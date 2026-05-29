# `debug.introspect`: KernelProvenance verification + symbol resolution

**Issue:** #53
**Epic:** #9
**Supersedes (in part):** #11
**Depends on:** #17 (KernelProvenance contract owner) — see "Dependency handling" below.
**Coordination:** `docs/specs/interface-contracts.md` §4.2 (fail-loud rule, `KernelProvenance` schema).

## Summary

Land the shared symbol-resolution + provenance-verification seam that both the
live drgn runner (#51) and the offline vmcore caller (#55) consume. Two
independent units — a **build_id verifier** and a **vmlinux/modules resolver** —
plus a thin local-qemu **boot-capture adapter** that records a `KernelProvenance`
into the manifest, and a re-point of the live runner so its expected `build_id`
flows from that authoritative record instead of the build step.

The §4.2 rule is the spine: consumers MUST verify `build_id` against the
live/crashed kernel before loading symbols and MUST fail loud on mismatch rather
than emitting garbage.

## Context: what exists today (after #51/#52)

- `kernel.build` extracts `build_id` from `vmlinux` via `readelf -n` and records
  it at `manifest.step_results["build"].details["build_id"]`, alongside
  `output_path` and `kernel_release`.
- `debug.introspect.run` (live SSH drgn) verifies provenance **on the target,
  inside the drgn wrapper**: it compares `prog.main_module().build_id` against
  `EXPECTED_BUILD_ID` (sourced from the *build* step) and emits
  `outcome.status="provenance_mismatch"` → `CONFIGURATION_ERROR`. Live drgn finds
  its own symbols on the target (`load_default_debug_info` over `/proc/kcore`),
  so there is no host-side vmlinux/modules path resolution on the live path.
- `KernelProvenance` (in `seams/target.py`) carries the full §4.2 shape
  (`build_id, release, vmlinux_ref, modules_ref, cmdline, config_ref`) but is
  **never constructed or populated anywhere**.

## Dependency handling (#17)

#53 is nominally blocked on #17, which owns the `KernelProvenance` schema and the
capture-at-boot wiring. #17 is still open and nothing populates a
`KernelProvenance` today. Rather than block, #53 ships **self-contained**: it
builds the seams against the existing `KernelProvenance` contract and adds a
**thin local-qemu boot-capture adapter** that synthesizes and records a
`KernelProvenance` from data already on the manifest. When #17 (and provisioning,
#39) land, they replace the adapter with provider-owned capture; the seams and
the manifest field they write are unchanged.

## Asymmetry that shapes the design

The two callers are not symmetric:

- **Live path** — the running kernel's `build_id` is observable only *from the
  target* (the wrapper's `prog.main_module().build_id`). drgn loads the target's
  own on-disk debuginfo, so symbols inherently match the running kernel; the
  build_id check is an **identity/provenance guard** ("is this the kernel this run
  booted?"). The live path does **not** use the host-side path resolver.
- **Offline/vmcore path** — the host supplies `vmlinux_ref`/`modules_ref`, and a
  build_id mismatch means **garbage symbols**. This is the load-bearing §4.2
  "fail loud" case; verification and path resolution are **host-side**.

Because the verification *locus* differs, the verifier and the resolver are
separate units. The verifier's comparison *rule* is shared; the resolver serves
the offline path (no live consumer today).

## Architecture & module layout

A new host-side package, a pure library with no manifest/IO knowledge:

```
src/linux_debug_mcp/symbols/
  __init__.py
  verify.py     # build_id verifier (shared by both callers)
  resolve.py    # vmlinux/modules locator (offline-facing today)
```

The boot-capture adapter lives next to the existing boot adapter
(`_publish_boot_ready_snapshot` in `server.py`, mirroring
`seams/target.py:publish_ready_snapshot`) — synthesizing a `KernelProvenance` is
provisioning's job, and keeping it out of `symbols/` lets #17 relocate it without
touching the library.

See ADR (below) for why a new package rather than `seams/` or `prereqs/`.

## 1. Verifier seam (`verify.py`)

A pure function over two opaque hex strings — no IO, trivially unit-testable:

```python
def verify_build_id(*, expected: str, observed: str) -> None:
    """Raise ProvenanceMismatch if observed != expected.

    Both MUST be the full canonical build-id: the complete lower-case hex of
    the ELF .note.gnu.build-id, never a prefix. The caller owns shape
    validation; this function only decides equality — the one rule both the
    live and offline callers share.
    """
```

- `ProvenanceMismatch(expected, observed)` — a typed exception carrying both ids
  (opaque hex, safe to surface).
- Handlers map it to `CONFIGURATION_ERROR` / code `provenance_mismatch`: the §4.2
  fail-loud rule, no fallback, no best-effort symbol load.
- **Representation, not just shape.** Exact string equality is correct only if
  both sides are the *same* representation, and a build-id has **no fixed length**
  (sha1 → 40 hex, md5 → 32, uuid → 32; the byte length depends on the linker's
  `--build-id` style). A regex therefore *cannot* assert "this is the complete id,
  not a prefix" — the existing `^[0-9a-f]{8,}$` only bounds charset and a minimum
  length. The real invariant is behavioral: **every caller extracts the complete
  build-id from an authoritative source and never truncates** —
  `readelf -n` on `vmlinux` (boot adapter), `prog.main_module().build_id.hex()`
  (live wrapper), and the vmcore's ELF notes (#55). Under that invariant exact
  equality is correct; a truncated id would only arise from a caller bug, not from
  normal data. `BUILD_ID_RE` (charset + min-length) is the boundary shape-check
  only. Callers normalize to lower-case hex before calling; the verifier assumes
  normalized input and decides equality, nothing else.
- **One constant, not three.** `BUILD_ID_RE` lives in `verify.py` and **replaces**
  the duplicate `_BUILD_ID_RE` definitions already in `local_drgn_introspect.py`
  (`:24`) and `server.py` (import the shared one; delete the copies — replace,
  don't deprecate), so the live wrapper's `EXPECTED_BUILD_ID` validation, the boot
  adapter, and the offline caller share one rule.
- Shape/normalization validation stays at the caller boundary; a malformed id is
  the caller's `provenance_corrupt`, never silently coerced inside the verifier.

## 2. Resolver seam (`resolve.py`)

Turns a `KernelProvenance` + the run root into concrete drgn-consumable paths,
confined to the run sandbox:

```python
@dataclass(frozen=True)
class ResolutionWarning:
    code: str        # e.g. "modules_debuginfo_missing"
    detail: str

@dataclass(frozen=True)
class ResolvedSymbols:
    vmlinux_path: Path
    modules_path: Path | None
    warnings: list[ResolutionWarning]

def resolve_symbols(
    provenance: KernelProvenance,
    *,
    run_dir: Path,
) -> ResolvedSymbols:
    ...
```

- **Confinement lives in `safety/paths.py`, not `server.py`.** No existing helper
  fits: `_require_run_debug_path` (`server.py:698-716`) confines under
  `<run>/debug` specifically and cannot guard a `build/`-relative ref — and it
  lives in `server.py`, which *imports* `symbols/` to wire the handlers. A pure
  leaf library cannot import back from the app module without an inversion/cycle.
  The canonical path-safety home is the existing leaf `safety/paths.py`
  (`PathSafetyError`, `_is_relative_to`, the `validate_*` family; imported by
  `server.py:124` and providers, importing `server` from nowhere). This design
  adds a public `confine_run_relative(ref, *, run_dir) -> Path` there, which
  resolves `(run_dir / ref)`, rejects any result not under `run_dir` (symlink
  escape, `..`, absolute override) with `PathSafetyError`. `resolve_symbols`
  imports it and wraps `PathSafetyError` as its own `SymbolResolutionError`
  (→ `CONFIGURATION_ERROR` / `symbol_resolution_failed`) so the resolver keeps one
  error vocabulary while reusing the single canonical guard; the boot adapter
  (§3) uses the same helper for its ref conversion. There is no injected `confine`
  callable.
- `vmlinux_ref` is **required**: run-relative, confined as above. Escaping /
  missing / not-a-regular-file → `SymbolResolutionError` → `CONFIGURATION_ERROR`
  / `symbol_resolution_failed`.
- `modules_ref` is **optional**: if `None` or the bundle is absent, that is **not
  fatal** — it yields a typed `ResolutionWarning(code="modules_debuginfo_missing")`
  in the returned list, never a silent drop. Today's local build emits no
  modules-debug bundle, so this is the default live-built case and the warning
  path gets real coverage immediately.
- The resolver does **not** re-verify `build_id` — that is `verify.py`. The
  offline caller composes them: `resolve_symbols` → read the vmcore's embedded
  `build_id` → `verify_build_id`.

## 3. Boot-capture adapter (synthesize + record `KernelProvenance`)

On the SUCCEEDED path of `target_boot_handler`, a new `_capture_kernel_provenance(...)`
helper builds a `KernelProvenance` and its result is **folded into the boot
`StepResult.details` dict at construction time**. Concretely it runs *before*
`server.py:1603` and feeds the dict literal there:
`details={**execution.details, "kernel_image_path": ..., "kernel_provenance": <model_dump>}`.
It must **not** run at the `_publish_boot_ready_snapshot` call site (`:1617`),
which is *after* `record_boot_attempt` (`:1616`) has already persisted the step —
writing there would require mutating a recorded StepResult and break the
write-once / immutable-manifest invariant. Folding it in at construction is the
single write, on the SUCCEEDED branch only.

Field sourcing (local-qemu adapter). Every source below is authoritative and
present on a successful build+boot — no "fallback" hand-waving:

| field | source | always present? |
|---|---|---|
| `build_id` | `step_results["build"].details["build_id"]` | yes — a SUCCEEDED build records it (else build fails at §7) |
| `release` | `step_results["build"].details["kernel_release"]`, which kbuild writes to `<build>/include/config/kernel.release` | yes on a successful kbuild |
| `vmlinux_ref` | run-relative path of the build's recorded `vmlinux` artifact (`_find_artifact(build, "vmlinux")`, `server.py:615`/`:3165`) | **no — vmlinux is optional** (see below) |
| `modules_ref` | `None` today — local build emits no modules-debug bundle | n/a |
| `cmdline` | `" ".join(boot details["kernel_args"])` — the **assembled** plan args the provider actually booted, with injected `root=`/`console=`/`nokaslr` (`libvirt_qemu.py:591-596,:665`), **not** the bare profile args | yes (recorded by the boot execution) |
| `config_ref` | run-relative `build/.config` (build's recorded `kernel-config` artifact) | yes — required build artifact (`server.py:370`) |

**Refs are stored absolute, recorded run-relative.** The build records artifact
paths as absolute strings under `<run>/build/`. The adapter converts each to the
run-relative ref it stores via `recorded_path.relative_to(run_dir)`; a recorded
path that is *not* under `run_dir` (relocated/symlinked artifact) is a
`kernel_provenance_capture_error` (code `artifact_path_unexpected`), not a
silently-fabricated ref. This applies to `vmlinux_ref` and `config_ref`.

**vmlinux is optional.** The codebase already guards a SUCCEEDED build that kept
no `vmlinux` artifact (`server.py:3165-3167`). The adapter therefore sources
`vmlinux_ref` from the *recorded* artifact rather than fabricating `build/vmlinux`:
if the artifact is present it records the real run-relative ref; if absent it
records the conventional `build/vmlinux` ref **plus** a capture note
`vmlinux_artifact_missing` so the offline path's eventual `symbol_resolution_failed`
traces back to "build did not retain vmlinux," not a phantom path. The live path
is unaffected either way (it never reads `vmlinux_ref`).

**Capture failure is typed and actionable, never a silent skip.** If a *required*
field genuinely can't be sourced (e.g. a SUCCEEDED build with no recorded
`build_id` or `kernel_release` — a real defect, not a normal degraded run), the
adapter does **not** silently omit the record. It writes
`kernel_provenance_capture_error` into the boot details with a specific code
(`build_id_unavailable` / `release_unavailable`) and message. Boot still succeeds
(provenance capture must not fail an otherwise-good boot), but the live re-point
(§4) then surfaces that captured reason verbatim instead of a bare
`provenance_missing` the agent can't act on. This replaces the original
"record nothing and log" path, which turned a server-side defect into an opaque
downstream failure.

## 4. Live re-point (`debug.introspect.run`)

The live handler's `EXPECTED_BUILD_ID` source moves from
`step_results["build"].details["build_id"]` to
`step_results["boot"].details["kernel_provenance"]["build_id"]`:

- Present + valid full hex → injected into the wrapper as today. The **in-wrapper
  guard is unchanged** — it still self-aborts before the user script on mismatch,
  the chosen fail-fast locus for live.
- `kernel_provenance` absent → `CONFIGURATION_ERROR` / `provenance_missing`. If a
  `kernel_provenance_capture_error` (§3) is recorded instead, the handler surfaces
  that captured code+message verbatim (still `provenance_missing` category) so the
  agent sees the actionable root cause, not a bare "missing."
- Present but malformed (fails the shared `BUILD_ID_RE`, §1) →
  `INFRASTRUCTURE_FAILURE` / `provenance_corrupt` (unchanged).

For local-qemu the boot-captured `build_id` equals the build step's, so behavior
is identical — but it now flows through the authoritative §4.2 record. The old
direct read of the build step is **removed** (replace, don't deprecate).

**Host-side verify and its precedence.** After the wrapper returns, the host calls
the shared `verify_build_id(expected=provenance.build_id, observed=wrapper_reported_id)`
before trusting results — this is what makes the verifier genuinely used by both
callers (one pure call on returned data, not a second mechanism). The two checks
have a **defined precedence: the host verdict is authoritative.** The wrapper's
in-target comparison is only a fast-fail optimization that avoids running the user
script against the wrong kernel. A wrapper *failure* already short-circuits in the
handler (the existing `outcome.status="provenance_mismatch"` path) before the host
verify runs, so the only divergence the host check can reach is **wrapper passed
but host `verify_build_id` disagrees** — itself a fault (it can only happen under a
truncation/normalization bug). The host treats it as a mismatch and fails loud
with `provenance_mismatch` (code detail `provenance_inconsistent`).

## 5. Error taxonomy (no new `ErrorCategory` values)

| condition | category | code | locus |
|---|---|---|---|
| build_id mismatch (live wrapper) | `CONFIGURATION_ERROR` | `provenance_mismatch` | wrapper (unchanged) |
| build_id mismatch (host verifier / offline) | `CONFIGURATION_ERROR` | `provenance_mismatch` | host |
| wrapper-pass / host-fail divergence (truncation/normalization bug) | `CONFIGURATION_ERROR` | `provenance_mismatch` (detail `provenance_inconsistent`) | host |
| no `kernel_provenance` in boot step | `CONFIGURATION_ERROR` | `provenance_missing` | pre-SSH |
| `kernel_provenance_capture_error` recorded at boot | `CONFIGURATION_ERROR` | `provenance_missing` (carries captured `build_id_unavailable` / `release_unavailable` / `artifact_path_unexpected`) | pre-SSH |
| `build_id` malformed (fails `BUILD_ID_RE`) | `INFRASTRUCTURE_FAILURE` | `provenance_corrupt` | pre-SSH |
| `vmlinux_ref` missing / escapes / not-a-file | `CONFIGURATION_ERROR` | `symbol_resolution_failed` | resolver |
| build kept no vmlinux artifact (capture-time note) | — (note) | `vmlinux_artifact_missing` | boot adapter (non-fatal) |
| `modules_ref` absent / missing bundle | — (warning) | `modules_debuginfo_missing` | resolver (non-fatal) |

`code` strings carry the introspect-specific distinctions; existing
`ErrorCategory` values cover every failure mode.

## 6. Testing

- **`verify.py`**: pure unit tests — match (no raise), mismatch (raises carrying
  both ids), and the representation trap: a full id vs a prefix of the *same*
  build raises (proving exact-equality catches the no-truncation contract), and
  `BUILD_ID_RE` rejects short/upper/non-hex input at the boundary. Property test
  over hex equality.
- **`resolve.py`**: unit tests with a tmp run dir — vmlinux resolves; missing
  vmlinux file → `symbol_resolution_failed`; path-escape attempt (`..`, symlink
  out, absolute override) → `CONFIGURATION_ERROR` via `confine_run_relative`;
  `modules_ref=None` and missing-bundle each → exactly one
  `modules_debuginfo_missing` warning with vmlinux still resolved.
- **Boot capture**: handler tests asserting (a) a SUCCEEDED boot records a
  well-formed `kernel_provenance` with run-relative refs and a `cmdline` built
  from `kernel_args`; (b) a build that kept no `vmlinux` artifact records the
  conventional ref **plus** the `vmlinux_artifact_missing` note (not a fabricated
  silent ref); (c) a build with no `build_id`/`kernel_release` records a typed
  `kernel_provenance_capture_error` and the boot still SUCCEEDS.
- **Live re-point**: existing introspect handler tests re-pointed to seed
  `kernel_provenance` in the boot step; add (a) `provenance_missing` when absent,
  (b) the capture-error code surfaced verbatim, (c) a host/wrapper divergence
  case asserting `provenance_inconsistent` fails loud. The gated real-drgn
  cross-check tests stay gated as-is.

## 7. Explicitly deferred

- The vmcore caller (`debug.introspect.from_vmcore`) that composes
  resolve+verify — **#55**. `resolve.py` ships unit-tested with no production
  caller yet; this is intentional.
- **Resolver confinement is run-relative only — a known boundary, not an
  accident.** `resolve_symbols` requires refs under the current `run_dir`. A
  vmcore analyzed by #55 may carry an externally-supplied `vmlinux`/modules
  outside any run; admitting an explicitly-allowed external symbol root is #55's
  call (it owns the trust decision for uploaded crash dumps). The seam is frozen
  narrow on purpose so the wider surface arrives with the caller that justifies
  it.
- Provisioning-owned provenance capture replacing the local-qemu adapter —
  **#17 / #39**.
- Real `modules_ref` population (a modules-debug bundle from the build) — out of
  scope; the warning path stands in until then.

## Acceptance criteria (from #53)

- [ ] A live target whose `build_id` matches the manifest's
  `KernelProvenance.build_id` (recorded at boot by the §3 adapter) resolves and
  runs; the host-side `verify_build_id` confirms the wrapper-reported id.
- [ ] A mismatched `build_id` fails with `CONFIGURATION_ERROR` /
  `provenance_mismatch` and no symbols are loaded (fail-loud, both loci).
- [ ] Missing module debuginfo is surfaced as a typed
  `modules_debuginfo_missing` warning, not silently dropped.

## ADR: a dedicated `symbols/` package

**Status:** proposed.

**Context:** #53 introduces host-side build_id verification and vmlinux/modules
path resolution consumed by #51 and #55.

**Decision:** Place both units in a new `src/linux_debug_mcp/symbols/` package as
pure functions; keep the boot-capture adapter in `server.py` next to the existing
boot snapshot adapter.

**Consequences:** Both callers import one library; the library has no IO/manifest
coupling and is unit-testable in isolation; #17 can relocate the boot adapter
without touching it.

**Considered & rejected:**

- *Build seam-only, consume the existing build-step `build_id`, no boot capture.*
  Rejected: the §4.2 acceptance criterion references a boot-recorded
  `KernelProvenance`; without capture the adapter would be untested in any real
  flow and the criterion deferred entirely.
- *One unified host-side verifier that the live wrapper also calls.* Rejected:
  the wrapper runs on the target and cannot import host code, so live enforcement
  is inevitably in-wrapper; a single host-only verifier would either drop the
  fail-fast guard or duplicate the rule. Separate units with one shared pure
  comparison is cleaner.
- *Belt-and-suspenders: keep both a full in-wrapper mechanism and a full
  host-side mechanism.* Rejected as redundant; the host call is a single pure
  `verify_build_id` on already-returned data, not a second mechanism.
- *Fold the seams into `seams/` or `prereqs/`.* Rejected: `seams/` is
  admission/transport snapshot territory and `prereqs/` is host-capability
  probing; symbol/provenance logic is a distinct concern.
- *Absolute host paths or opaque `file://` URIs for refs.* Rejected: absolute
  paths leak host layout into the manifest and are not portable; URIs are
  speculative (YAGNI) while local-only. Run-relative refs confined to the run
  sandbox extend the repo's path-safety leaf `safety/paths.py` with a new public
  `confine_run_relative` (§2) — the debug-scoped `_require_run_debug_path` cannot
  guard a `build/`-relative ref and lives in `server.py`, which the pure
  `symbols/` library must not import, so it is not reused directly.
