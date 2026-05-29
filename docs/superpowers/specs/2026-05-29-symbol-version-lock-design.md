# Symbol version-locking for the live gdb debug tier — design

**Issue:** #70 (epic #9, split from #17, consumed by #13/#14/#53) · **Status:** proposed
**Contract:** `docs/specs/interface-contracts.md` §4.2 (`KernelProvenance`) · **Owns:** the §4.2 version-lock contract
**ADR:** [0017](../../adr/0017-symbol-version-lock-gdb-tier.md)
**Reference:** ELF `NT_GNU_BUILD_ID`; `symbols/build_id.py`, `symbols/verify.py` (ADR 0008)

## 1. Purpose & scope

Before any symbol-using debug tool loads `vmlinux` DWARF against a kernel, the
symbols MUST be verified to match that kernel; a mismatch MUST fail loud rather
than emit silent garbage (interface-contracts §4.2: "Consumers MUST verify
`build_id` against the live/crashed kernel before loading symbols and MUST fail
loud on mismatch rather than emitting garbage").

Two of the three symbol-using tiers already do this:

- **#53 `debug.introspect` (live drgn over ssh):** reads the boot-recorded §4.2
  `KernelProvenance.build_id`, the drgn wrapper self-aborts on mismatch, and the
  host re-verifies with `verify_build_id` (`server.py` ~2628, ~3295). Mismatch →
  `CONFIGURATION_ERROR` / `provenance_mismatch`.
- **#14 `debug.introspect.from_vmcore` (postmortem):** compares the vmcore's
  embedded build-id against the host-parsed vmlinux ELF build-id (`server.py`
  ~3738). Mismatch → `provenance_mismatch`; absent embedded id →
  `provenance_unverifiable`.

The **third tier, #13 `debug.gdb` (QEMU gdbstub), is the gap.** Its
`start_session` validates `same_run_artifact_linkage` (the loaded vmlinux is the
same *path* the build recorded) and `live_banner_match` (the running kernel's
`linux_banner` **release string** equals the build's `kernel_release`), both gated
by `DebugProfile.symbol_identity_required` (default `True`). It **never compares
the build-id.** Two builds that share a release string (e.g. `6.9.0-test`) but
differ in content have different build-ids yet identical banners — they pass
today's checks and gdb loads mismatched symbols. This issue closes that hole and
makes the §4.2 build-id version-lock uniform across all three tiers.

### 1.1 In scope

- A shared verification primitive in `symbols/verify.py` that ties together
  "read the vmlinux ELF build-id, validate its shape, and compare it to an
  expected build-id", raising typed errors that map to the existing
  `CONFIGURATION_ERROR` codes (`vmlinux_build_id_unreadable`,
  `provenance_mismatch`). This is the single seam the tiers consume (§4.2 "expose
  verification for the symbol-using tiers").
- `debug.start_session` (#13) extracting the boot-recorded §4.2
  `KernelProvenance.build_id` and running the primitive against the on-disk
  vmlinux **before attaching gdb** — so a mismatch fails before the kernel is
  halted, with nothing acquired to tear down.
- Reusing the existing cross-tier error taxonomy and codes verbatim.

### 1.2 Out of scope

- **Reading the running kernel's build-id over the RSP/gdbstub channel.** That is
  arch-specific (locating the build-id note in live kernel memory), only testable
  through the gated gdb integration job, and redundant with the existing
  `live_banner_match` live cross-check. The architecture design already permits
  "the `vmlinux` build ID **or other available identity**" for the gdb tier
  (design §"QemuGdbstubProvider", line ~172). Banner-match stays as the live
  identity check; build-id covers symbol-source integrity. (ADR 0017, rejected A.)
- Refactoring the #53 live-wrapper verification path (its host check already calls
  `verify_build_id`; rewriting it earns no behavior and risks regression). The
  #14 vmcore path's inline read+verify is replaced by the new shared primitive
  because it is literally the same three lines (§3.3).
- Changing `DebugProfile.symbol_identity_required` semantics for banner/linkage.

## 2. Failure contract

All version-lock failures are `CONFIGURATION_ERROR` (the artifacts the caller
supplied are inconsistent — not infrastructure). The gdb tier runs the check
**pre-attach**, so every failure below returns before `transaction.open()` / the
gdb halt; nothing is acquired and no `debug` step is recorded SUCCEEDED.

| Condition (gdb tier) | `code` | category |
|---|---|---|
| boot recorded no `KernelProvenance` (or a capture error) | `provenance_missing` | `CONFIGURATION_ERROR` |
| recorded `build_id` is absent/malformed (fails `BUILD_ID_RE`) | `provenance_corrupt` | `CONFIGURATION_ERROR` (`INFRASTRUCTURE_FAILURE` if a previously-validated record is corrupt — see note) |
| vmlinux ELF carries no readable GNU build-id | `vmlinux_build_id_unreadable` | `CONFIGURATION_ERROR` |
| vmlinux build-id ≠ recorded build_id | `provenance_mismatch` | `CONFIGURATION_ERROR` |

Note: these are exactly the codes/categories the live (#53) and vmcore (#14)
tiers already emit, so an agent sees one version-lock vocabulary across tiers.
`provenance_missing`/`provenance_corrupt` mirror the live introspect handler
(`server.py` ~2632–2662): a missing record is `CONFIGURATION_ERROR`, a recorded
build_id that fails `BUILD_ID_RE` is `INFRASTRUCTURE_FAILURE` (`provenance_corrupt`)
because boot validated it on the way in.

The message on `provenance_mismatch` names both ids (opaque lower-case hex, safe
to surface — `ProvenanceMismatch` docstring) and the actionable fix ("rebuild or
re-boot so the booted kernel and the vmlinux on disk share a build-id").

## 3. Design

### 3.1 Shared primitive (`symbols/verify.py`)

```python
def verify_vmlinux_provenance(
    *, expected_build_id: str, vmlinux_path: Path,
    build_id_reader: Callable[[Path], str] = read_elf_build_id,
) -> str:
    """Read the vmlinux ELF build-id, validate its shape, and verify it equals
    expected_build_id. Returns the observed build-id on success.

    Raises BuildIdReadError (unreadable/non-ELF/no note → vmlinux_build_id_unreadable),
    ProvenanceMismatch (observed != expected → provenance_mismatch). The caller
    is responsible for having validated expected_build_id's shape (the recorded
    §4.2 value), exactly as the wrapper/vmcore callers do today.
    """
```

`build_id_reader` is injectable (default the real `read_elf_build_id`) so handler
tests drive it with a fake that returns a chosen build-id without minting a real
ELF — the same injection pattern the vmcore handler already exposes
(`debug_introspect_from_vmcore_handler(..., build_id_reader=...)`).

### 3.2 gdb tier consumption (`debug_start_session_handler`)

`debug_start_session_handler` gains a `build_id_reader` parameter (default
`read_elf_build_id`). After it has resolved the SUCCEEDED build's `vmlinux`
artifact and the SUCCEEDED debug boot, and before it acquires the debug lock /
opens the transport / attaches gdb, it:

1. Extracts the boot-recorded §4.2 `KernelProvenance` from
   `boot_result.details["kernel_provenance"]`, reusing the live-introspect
   extraction shape (`provenance_missing` on absent/capture-error,
   `provenance_corrupt` on a build_id failing `BUILD_ID_RE`).
2. Calls `verify_vmlinux_provenance(expected_build_id=…, vmlinux_path=vmlinux.path,
   build_id_reader=build_id_reader)`.
3. On `BuildIdReadError` → `CONFIGURATION_ERROR` / `vmlinux_build_id_unreadable`;
   on `ProvenanceMismatch` → `CONFIGURATION_ERROR` / `provenance_mismatch`. Both
   return before any acquisition, with `suggested_next_actions=["artifacts.get_manifest"]`.

The check is **unconditional** — independent of `symbol_identity_required`. A
positively-detected build-id mismatch is bogus-symbol territory and must always
fail; `symbol_identity_required` continues to govern only the stricter
"banner/linkage must be *confirmable*" stance inside the provider (a build-id
*match* does not weaken those checks). (ADR 0017, rejected E.)

Placement is a **direct pre-attach call in the handler**, not a registered
`SessionGuard.PreAttachPrecondition`: the facts it needs (the resolved vmlinux
path, the recorded build_id, and `artifact_root`) are per-call values in handler
scope, and `artifact_root` is a per-call tool parameter the singleton
`SessionGuard` (built once in `_build_transport_machinery`, without
`artifact_root`) cannot capture. This mirrors ADR 0016's decision that the
watchdog *relax* is a post-acquire direct call rather than a slot when data
placement requires it. The reserved pre/post-attach slots remain available for
future preconditions that key only on `SessionGuardContext`. (ADR 0017, rejected B/C.)

Covering both the transport-wired and the non-transport (legacy) handler paths:
the call sits before the `transport_enabled` branch, so a build-id mismatch is
rejected regardless of whether the transport machinery is wired.

### 3.3 vmcore tier (#14) re-point

The vmcore handler's inline "read vmlinux build-id, shape-check, then compare to
the vmcore-embedded id" becomes a call to `verify_vmlinux_provenance` with
`expected_build_id` = the vmcore-embedded id. Behavior and emitted codes are
unchanged; this is the "owns the contract / consume from the tiers" deliverable,
proven green by the existing vmcore tests.

### 3.4 What stays the same

- The #53 live wrapper path (self-abort + host `verify_build_id`) is untouched.
- The gdb provider's `same_run_artifact_linkage` / `live_banner_match` checks and
  `symbol_identity_required` gating are untouched; the build-id gate runs ahead of
  them in the handler.

## 4. Test plan (behavior, handlers called directly)

New, in `tests/test_symbols_verify.py` and a gdb-tier test module:

- `verify_vmlinux_provenance`: match returns observed id; mismatch raises
  `ProvenanceMismatch`; unreadable vmlinux raises `BuildIdReadError`; a prefix vs
  full id mismatches (no truncated-equality).
- gdb handler with a seeded debug-ready run (boot step carrying a
  `kernel_provenance` with build_id `B`):
  - injected reader returns `B` → attach proceeds (happy path).
  - injected reader returns `B' ≠ B` → `CONFIGURATION_ERROR` /
    `provenance_mismatch`, no `debug` step recorded, provider never attached.
  - injected reader raises `BuildIdReadError` → `vmlinux_build_id_unreadable`.
  - boot step with no `kernel_provenance` → `provenance_missing`.
  - boot step with a malformed recorded build_id → `provenance_corrupt`.
- vmcore tier: existing mismatch/unverifiable tests stay green after the
  re-point (no new behavior).

Shared fixtures gain a helper to seed a `kernel_provenance` into a boot step so
the existing gdb-handler tests (which now require it) stay green with an injected
matching reader. The gated gdb integration test is untouched (still skipped
without `gdb`/`qemu`).
