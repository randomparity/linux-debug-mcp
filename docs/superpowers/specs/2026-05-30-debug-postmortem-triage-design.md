# `debug.postmortem.triage` — composite triage report

**Date:** 2026-05-30
**Issue:** #93
**Epic:** #9 (Remote interactive kernel debugging for coding agents)
**Supersedes (in part):** #14
**Status:** Draft — pending adversarial review
**Depends on:** #92 (`debug.postmortem.crash` — `log`/`bt` → panic line + faulting backtrace; the `_crash_buildid_failloud` host gate; `DebugPostmortemCrashRequest`); #54/#55 (`debug.introspect.from_vmcore_helper` + the curated `dmesg`/`modules` drgn helpers)
**Design decisions:** [ADR 0027](../../adr/0027-postmortem-triage-composition.md) (handler-level composition via injectable seams; fixed helper set; single up-front build-id gate; per-section partial-vs-hard failure contract)

## 1. Background and scope

#92 shipped the `crash` offline tier and #54/#55 shipped the drgn offline tier. Both
answer *one question at a time*: an agent must know to call `bt`, then `log`, then the
`dmesg` helper, then `modules`, and stitch the four answers together. `debug.postmortem.triage`
is the **one call** that does that stitching: handed a crash, an agent calls
`triage(run_id, vmcore_ref, vmlinux_ref)` and gets back panic reason, faulting task +
backtrace, recent dmesg, and loaded modules as a single typed report. It is the
recommended first reaction to the `target.crashed` lifecycle event
(interface-contracts §5.5).

Triage introduces **no new analysis mechanism**. It composes the two existing tiers'
**handlers** (ADR 0027 decision 1) against a single `(vmcore, vmlinux)` pair, inheriting
their offline scoping (run-relative refs, no live target, no admission gate — §5.6 rule
3), build-id fail-loud, redaction, and manifest persistence wholesale. The only new
logic is: one up-front build-id gate, three sub-calls with a **fixed** command/helper
set, per-section assembly with a partial-failure contract, and one composed-report
artifact.

### In scope

- `debug.postmortem.triage(run_id, vmcore_ref, vmlinux_ref, modules_ref?, timeout_seconds) → ToolResponse` MCP tool, wired via `server.py`'s registration pattern.
- A fixed composition (ADR 0027 decision 2): one `debug.postmortem.crash` sub-call with `commands=["log","bt"]` (→ `panic_reason`, `faulting_task`, `backtrace`) and two `debug.introspect.from_vmcore_helper` sub-calls (`name="dmesg"` → `recent_dmesg`; `name="modules"` → `modules`).
- One typed `DebugPostmortemTriageReport` with five sections, each tagged `source` (`crash`|`drgn`) + `status` (`ok`|`failed`) + `reason?` (§3.3).
- Partial-report contract (ADR 0027 decision 3): a sub-call failure fails only its own sections; the report is returned `partial=True` as long as ≥1 section is `ok`. All five sections failed → hard `INFRASTRUCTURE_FAILURE` / `triage_all_sources_failed`.
- A single host-authoritative build-id fail-loud **up front**, before any sub-call (ADR 0027 decision 4), reusing #92's `_crash_buildid_failloud`. A mismatch is `CONFIGURATION_ERROR` and **no sub-call runs** (AC#3).
- `panic_reason` *selected* from the crash `log` parser's structured lines by panic-signature match (ADR 0027 decision 2a) — no new parser.
- No separate budget (ADR 0027 decision 5): the sub-calls tick the existing crash/introspect ceilings; the `postmortem.triage:<call_id>` step is a record only.
- Redaction at the composition boundary (ADR 0027 decision 6): the assembled report + the persisted `report.json` pass through `Redactor()`.
- `debug.postmortem.triage` added to `ALLOWED_DEBUG_OPERATIONS` (enumerability) and to the `local-crash-postmortem` capability's `operations`; **not** gated (§5.6 rule 3).
- Docs: a `triage` section in `docs/debug-postmortem.md`.
- An env-gated real-core integration test asserting crash- and drgn-sourced sections are mutually consistent on the same dump (AC#4).

### Out of scope

| Concern | Where it lives |
|---|---|
| New crash-output parsers | none — reuses #92's `bt`/`log` parsers |
| New drgn helpers | none — reuses #54's `dmesg`/`modules` |
| Caller-selectable commands/helpers | rejected (ADR 0027 decision 2 / rejected #2) — call the underlying tool |
| Cross-source reconciliation beyond side-by-side presentation | out of scope (issue) — both sources are presented, not merged |
| Compressed-kdump container support | inherited deferral from #92 (`vmcore_format_unsupported`) |

## 2. Architecture overview

```
agent ──MCP──▶ debug.postmortem.triage handler
                     │  (no admission, no SSH from triage itself, no target lifecycle)
                     ▼
       load manifest (missing run → run_not_found)
                     ├─ timeout_seconds ∈ [5,300]  (invalid_timeout)
                     ▼
       build-id fail-loud (HOST, ONCE, before any sub-call):  ← ADR 0027 decision 4
         read_vmcore_build_id(vmcore) vs read_elf_build_id(vmlinux)
         mismatch / unreadable / unverifiable  → CONFIGURATION_ERROR, NO sub-call
                     ▼
       crash sub-call:  debug_postmortem_crash_handler(commands=["log","bt"], …)
                     ▼
       drgn sub-call:   debug_introspect_from_vmcore_helper_handler(name="dmesg", …)
       drgn sub-call:   debug_introspect_from_vmcore_helper_handler(name="modules", …)
                     ▼
       assemble 5 sections (ok | failed+reason)  ← postmortem/triage.py
         panic_reason ← select panic line from results["log"].lines
         faulting_task, backtrace ← results["bt"]
         recent_dmesg ← dmesg result.entries/truncated
         modules ← modules result.modules/decode_errors
                     ▼
       all 5 failed?  ── yes → INFRASTRUCTURE_FAILURE / triage_all_sources_failed
                     │  no
                     ▼
       Redactor(report) → debug/postmortem/triage/<call-id>/report.json
                → postmortem.triage:<call_id> manifest step → ToolResponse.success(partial?)
```

New components:

1. **`debug_postmortem_triage_handler`** in `server.py` (the orchestrator) + the
   `debug.postmortem.triage` tool wrapper.
2. **`postmortem/triage.py`** — pure section-assembly: `assemble_report(crash_resp,
   dmesg_resp, modules_resp) -> DebugPostmortemTriageReport`-shaped dict, and
   `select_panic_reason(log_lines) -> str | None`. No I/O, no redaction (the handler
   redacts).
3. **`DebugPostmortemTriageRequest`** + **`DebugPostmortemTriageReport`** (+ section
   models) in `domain.py`.

Reused without change: `debug_postmortem_crash_handler`,
`debug_introspect_from_vmcore_helper_handler`, `_crash_buildid_failloud`,
`read_vmcore_build_id`, `read_elf_build_id`, `ArtifactStore`,
`_record_terminal_introspect_result`, `Redactor`, `confine`/`resolve` (transitively, in
the sub-handlers).

## 3. Tool surface

### 3.1 Request

```python
class DebugPostmortemTriageRequest(Model):        # extra="forbid"
    run_id: str
    vmcore_ref: str          # run-relative path to the captured vmcore file
    vmlinux_ref: str         # run-relative path to the uncompressed ELF vmlinux+symbols
    modules_ref: str | None = None   # optional run-relative directory of *.ko[.debug]
    timeout_seconds: int = 60        # handler-bounded to [5, 300]; applied to EACH sub-call
```

There is **no** `commands`/`helpers`/section field (fixed helper set, ADR 0027 decision
2) and **no** `target_ref`/`*_profile`/`debug_profile` (offline, never gated). The
manifest is consulted only for the run-directory layout — never for a target profile.

**`modules_ref` is threaded to the crash sub-call only.** Only the crash side uses it
(the server-injected `mod -S` symbol load). The drgn `dmesg`/`modules` helpers read the
ring buffer / `for_each_module(prog)` from the core itself and have **no** use for a
`*.ko` directory; passing `modules_ref` to them would only add a `resolve_symbols`
failure mode (an absent or non-directory `modules_ref` → `symbol_resolution_failed`)
that would knock out the drgn source for a reason unrelated to dmesg/module extraction.
So the two drgn sub-calls are invoked with `modules_ref=None`; `modules_ref` (when given)
is validated **up front** (§4 step 2) and passed only to the crash sub-call.

**Aggregate wall-clock and sequential ordering.** The three sub-calls run
**sequentially** (crash → dmesg → modules), each bounded by `timeout_seconds`, so a
triage call's worst-case wall-clock is **≈ 3 × `timeout_seconds`** (up to ~900 s at the
300 s cap). Sequential ordering is deliberate: each sub-call maps the multi-GB core, and
running them one at a time caps peak memory at a **single** core mapping (parallel
sub-calls would triple it for no latency win on a single-agent local server). The
response's `duration_ms` reports the real elapsed time so an agent sees the true cost;
the docs (§7) state the ≈3× relationship so agents budget `timeout_seconds` accordingly.

### 3.2 Operation gating

No `DebugProfile` in the path. `debug.postmortem.triage` is added to
`ALLOWED_DEBUG_OPERATIONS` for enumerability, but `_ensure_debug_operation_enabled` is
**not** invoked (no profile to resolve). §5.6-rule-3 "never gated": a triage call cannot
be blocked by target state or profile narrowing — proven by a handler test with no
admission service injected.

### 3.3 Response

`DebugPostmortemTriageReport` (all section payloads already redacted by the sub-handlers,
re-redacted at the boundary — ADR 0027 decision 6):

```python
class TriageSection(Model):
    source: Literal["crash", "drgn"]
    status: Literal["ok", "failed"]
    reason: str | None = None             # set iff status == "failed"

class PanicReasonSection(TriageSection):  # source="crash"
    text: str | None = None               # selected panic line; None when none matched (status may still be "ok")

class FaultingTaskSection(TriageSection): # source="crash"
    pid: int | None = None
    command: str | None = None

class BacktraceSection(TriageSection):    # source="crash"
    frames: list[dict[str, Any]] = []     # pass-through of the crash bt parser's frames

class RecentDmesgSection(TriageSection):  # source="drgn"
    entries: list[dict[str, Any]] = []    # pass-through of the dmesg helper's entries
    truncated: bool = False

class ModulesSection(TriageSection):      # source="drgn"
    modules: list[dict[str, Any]] = []    # pass-through of the modules helper's modules
    decode_errors: int = 0

class DebugPostmortemTriageReport(Model):
    vmcore_build_id: str
    panic_reason: PanicReasonSection
    faulting_task: FaultingTaskSection
    backtrace: BacktraceSection
    recent_dmesg: RecentDmesgSection
    modules: ModulesSection
```

Success `data` carries:

- `call_id` — the per-call UUIDv4-hex id (triage's own).
- `report` — the `DebugPostmortemTriageReport` (`model_dump(mode="json")`).
- `partial` — `true` when any section's `status == "failed"`.
- `vmcore_build_id` — the verified up-front id (also on the report).
- `sub_call_ids` — `{crash, dmesg, modules}` → each sub-call's `call_id`, read as
  `resp.data.get("call_id")` on a successful sub-call and `(resp.error.details or {}).get("call_id")`
  on a failed one (the crash/introspect handlers stamp the `call_id` into the failure
  `details`, not `data`), falling back to `null` only when the sub-call failed before
  minting an id (a config-level reject). This keeps a ran-but-failed sub-call's transcript
  reachable. The same map is carried in the `triage_all_sources_failed` hard-failure
  `details` (§3.4) so a sub-call that *ran* before the report came back empty stays
  reachable even when triage hard-fails.
- `artifacts` — an `ArtifactRef` to the redacted `report.json`.
- timing (`started_at`, `finished_at`, `duration_ms`). `duration_ms` is the true elapsed
  time across all three sequential sub-calls (≈ up to 3 × `timeout_seconds`, §3.1).

`suggested_next_actions`: `["debug.postmortem.crash", "debug.introspect.from_vmcore_helper", "artifacts.get_manifest"]`
on success; `["artifacts.get_manifest"]` on the build-id hard failure.

Section payloads are **pass-through** of the upstream typed-and-redacted shapes
(`list[dict[str, Any]]`), not re-modeled, to avoid a second source of truth that drifts
from the crash parsers / drgn helper output models (ADR 0027 decision 8).

### 3.4 Failure taxonomy

| Condition | `ErrorCategory` | `code` |
|---|---|---|
| run not found | `CONFIGURATION_ERROR` | `run_not_found` |
| `timeout_seconds ∉ [5,300]` | `CONFIGURATION_ERROR` | `invalid_timeout` |
| up-front vmcore build-id ≠ vmlinux build-id | `CONFIGURATION_ERROR` | `provenance_mismatch` |
| up-front vmlinux build-id unreadable | `CONFIGURATION_ERROR` | `vmlinux_build_id_unreadable` |
| up-front vmcore container not ELF | `CONFIGURATION_ERROR` | `vmcore_format_unsupported` |
| up-front vmcore truncated/unreadable | `CONFIGURATION_ERROR` | `vmcore_build_id_unreadable` |
| up-front vmcore carries no build-id | `CONFIGURATION_ERROR` | `provenance_unverifiable` |
| up-front vmcore ref missing/escaping | `CONFIGURATION_ERROR` | `vmcore_not_found` |
| up-front vmlinux/modules ref unsafe/missing | `CONFIGURATION_ERROR` | `symbol_resolution_failed` |
| up-front resolved `modules_path` charset-unsafe | `CONFIGURATION_ERROR` | `modules_path_unsafe` |
| **zero `ok` sections** (both sources produced nothing usable) | `INFRASTRUCTURE_FAILURE` | `triage_all_sources_failed` (details carry redacted `sub_call_ids` + `section_reasons`) |
| ≥1 `ok` section, ≥1 `failed` section | success, `partial=True`, failed sections carry `reason` (the sub-call `code`) | — |

The up-front gate (the `provenance_*` / `vmcore_*` / `vmlinux_*` / `symbol_resolution_failed`
/ `modules_path_unsafe` rows) reuses `_crash_buildid_failloud`, `confine_run_relative`,
`resolve_symbols`, and `validate_modules_path`, so the codes match #92 exactly. Those
rows are emitted **before any sub-call** (AC#3); the section-failure path (last row) is
reached only when the up-front gate passed.

## 4. Composition pipeline (`debug_postmortem_triage_handler`)

A linear orchestrator:

1. Resolve `ArtifactStore`; load manifest (missing → `run_not_found`). Validate
   `timeout_seconds ∈ [5,300]` (`invalid_timeout`). Triage runs **no** `sensitive/`
   preflight of its own: it writes only the redacted `report.json` under
   `debug/postmortem/triage/<call-id>/` (step 7) and never creates a sensitive call dir,
   so a `sensitive/`-mode check would be a phantom precondition. Each sub-handler still
   runs its own `sensitive/` preflight for the raw outputs *it* writes; a too-permissive
   `sensitive/` therefore surfaces as that sub-call's section failure (degraded report),
   not a triage-level reject.
2. **Up-front gate over the shared refs + build-id (ADR 0027 decision 4):** confine
   `vmcore_ref`, resolve `vmlinux_ref` **and `modules_ref`** via `resolve_symbols`, and
   — when `modules_ref` is given — run the crash handler's `validate_modules_path`
   charset check. All three shared-ref errors hard-fail **before any sub-call** and
   consistently (`vmcore_not_found` / `symbol_resolution_failed` / `modules_path_unsafe`),
   so a caller-input ref error is never a degraded partial report (the partial contract is
   reserved for genuine tier-unavailability). Then `_crash_buildid_failloud(...)`; on
   success, capture `vmcore_build_id`.
3. **crash sub-call:** `crash_handler(DebugPostmortemCrashRequest(run_id, vmcore_ref,
   vmlinux_ref, modules_ref, commands=["log","bt"], timeout_seconds), artifact_root=…,
   runner=…, vmcore_build_id_reader=…, vmlinux_build_id_reader=…, clock=…)`. `modules_ref`
   rides on this sub-call only.
4. **drgn sub-calls:** `drgn_helper_handler(DebugIntrospectFromVmcoreHelperRequest(...,
   modules_ref=None, name="dmesg", timeout_seconds), …)` then the same with
   `name="modules"`. `modules_ref` is **not** passed (§3.1). The drgn handler takes
   `build_id_reader=vmlinux_build_id_reader` and `runner=…`, `clock=…`.
5. **Assemble** the five sections from the three responses (`postmortem/triage.py`).
   A section's `reason` (when `failed`) is the sub-call's **stable error `code`**, read
   **defensively** as `(resp.error.details or {}).get("code") or "sub_call_failed"` — not
   every `ToolResponse.failure` carries `details` (e.g. a sub-handler's `ManifestStateError`
   branch returns a `details`-less failure), so a bare subscript would raise *inside*
   triage and defeat the partial-report design. The fallback constant keeps a detail-less
   failure a clean section failure. Codes seen here: `crash_timeout`,
   `helper_script_error`, `manifest_call_budget_exhausted`, … For the per-result
   (within-crash) failures the `reason` is the parser's `reason` token (`unknown_command`
   / `parse_failed` / `not_captured` / `output_truncated`).
   - crash `resp.ok` → `results = resp.data["results"]`:
     - `bt = results.get("bt")`; `parsed` truthy → `backtrace.status="ok"`,
       `frames=bt["frames"]`; `faulting_task.status="ok"`, `pid=bt.get("pid")`,
       `command=bt.get("command")`. Else both `failed` with `reason = bt.get("reason")`
       or `"bt_missing"`.
     - `log = results.get("log")`; `parsed` truthy → `panic_reason.status="ok"`,
       `text=select_panic_reason(log["lines"])` (may be `None`). Else `failed`
       (`reason = log.get("reason")` or `"log_missing"`).
   - crash `not resp.ok` → all three crash sections `failed`,
     `reason = resp.error.details["code"]`.
   - dmesg `resp.ok` (and `resp.data["result"]` present) → `recent_dmesg.status="ok"`,
     `entries=result["entries"]`, `truncated=result["truncated"]`. Else `failed`,
     `reason = resp.error.details["code"]`.
   - modules likewise → `modules.status="ok"`, `modules=result["modules"]`,
     `decode_errors=result["decode_errors"]`. Else `failed`.
6. If **all five** sections `failed` → `INFRASTRUCTURE_FAILURE` /
   `triage_all_sources_failed`. The failure `details` carry `sub_call_ids` (§3.3) and a
   `section_reasons` map (each section → its `reason`), **both passed through
   `Redactor()` before return** (ADR 0027 decision 6 / AC#5 — the hard-fail exit redacts
   too, not only the success path). No `report.json` is persisted (there is no usable
   report), but the sub-call ids keep any transcript a sub-call *did* persist reachable.
   Record a FAILED `postmortem.triage:<call_id>` step.

   **Hard-fail boundary vs the issue's "source" wording.** "All five sections failed"
   means **zero** `ok` sections; it can be reached even when a sub-call's `resp.ok` was
   `True` (e.g. crash ran but both `bt`/`log` were `not_captured`, and both drgn calls
   failed). This is the deliberate, simpler reading of the issue's "provided at least one
   source succeeded": the report is only worth returning when it has at least one `ok`
   section to show. Because `sub_call_ids` rides on the failure `details`, a sub-call that
   ran-but-produced-nothing is still discoverable (its raw transcript is on disk), so the
   stronger hard-fail rule loses no forensic reach.
7. Else: `report = Redactor().redact_value(report.model_dump(mode="json"))` (covers the
   composed payload **and** every section `reason`); mint triage `call_id`; create
   `<run>/debug/postmortem/triage/<call-id>/` (0700); write redacted `report.json`;
   record a SUCCEEDED `postmortem.triage:<call_id>` step with an `ArtifactRef`; return
   `ToolResponse.success(data={report, partial, call_id, …})`.

The crash sub-handler writes its own `postmortem.crash:<id>` step + artifacts; each drgn
sub-handler writes its own `introspect:<id>` step + artifacts; triage references them via
`sub_call_ids` (§3.3) but does not duplicate their artifacts.

### 4.1 Idempotency / step model

Like the sub-tiers, each triage call mints a fresh `call_id` and writes a distinct
`postmortem.triage:<call_id>` step; calls are **not** idempotent by a fixed step name.
No `force_*` flag. Manifest growth is bounded transitively by the sub-tier budgets (ADR
0027 decision 5).

### 4.2 `select_panic_reason` (ADR 0027 decision 2a)

```python
_PANIC_SIGNATURES = (  # ordered; first match wins
    "Kernel panic - not syncing",
    "Kernel panic",
    "Unable to handle kernel",
    "general protection fault",
    "kernel BUG at",
    "BUG:",
    "Oops",
)

def select_panic_reason(log_lines: list[dict]) -> str | None:
    for sig in _PANIC_SIGNATURES:
        for line in log_lines:
            text = line.get("text", "")
            if sig in text:
                return text
    return None
```

Pure, total, no raise. Operates on the `log` parser's already-redacted `text`. A
non-panic core returns `None` (a valid `ok` outcome — §3.3).

## 5. Build-id fail-loud (reused)

The up-front gate is exactly #92's: `read_vmcore_build_id(vmcore)` (the pure-Python ELF
VMCOREINFO reader) vs `read_elf_build_id(vmlinux)`, via `_crash_buildid_failloud`. Both
readers are injectable seams (`vmcore_build_id_reader=`, `vmlinux_build_id_reader=`,
defaults `read_vmcore_build_id`/`read_elf_build_id`) so handler tests inject fakes. The
distinct codes (`provenance_mismatch` / `provenance_unverifiable` /
`vmcore_format_unsupported` / `vmcore_build_id_unreadable` / `vmlinux_build_id_unreadable`)
are emitted before any sub-call. Because the crash sub-handler reuses the same readers,
its own gate is consistent by construction; the drgn wrapper's drgn-side id is verified
independently (a deep disagreement degrades the drgn sections to `failed`, not a hard
triage error — the up-front gate already proved the host-readable ids agree).

## 6. Concurrency (§5.6 rule 3)

Triage holds no admission handle, no `StopCapableGuard`, no console lease, no snapshot
read; it makes no SSH/subprocess call itself (the sub-handlers do, offline). Two triage
calls against the same run proceed in parallel; a call proceeds whether the target is
`READY`, `HALTED`, `CRASHED`, reclaimed, or never booted (AC: lifecycle-independent —
proven by a handler test with no admission service injected). The only shared mutable
state is the manifest, written by each sub-handler through the existing flock-retry
helper plus triage's own `postmortem.triage:<call_id>` step. The crash sub-call maps the
multi-GB core once; each drgn sub-call opens it once — resource posture identical to
running the sub-tools by hand (intentionally unbounded; the single local agent
self-limits, as in #92 §9).

## 7. Allowlist, capability & docs changes

- `config.py`: add `"debug.postmortem.triage"` to `ALLOWED_DEBUG_OPERATIONS`; add
  `TRIAGE_CRASH_COMMANDS = ("log", "bt")` and `TRIAGE_DMESG_HELPER = "dmesg"` /
  `TRIAGE_MODULES_HELPER = "modules"` constants so the fixed set is reviewable in one
  place.
- `providers/local_crash_postmortem.py`: add `"debug.postmortem.triage"` to the
  `operations` list (same capability — triage is offline, concurrent-safe, needs
  `crash` for its crash sub-call; the drgn sub-calls need drgn, advertised by
  `local-drgn-introspect`). The composite tool is advertised on the crash capability
  because it is offline/concurrent-safe like the rest of that capability.
- No new prereq check: triage's prerequisites are exactly the union of the crash and
  drgn tiers' existing checks; a missing tool degrades a source to a `failed` section
  (AC#2), so triage needs no admission-time gate of its own.
- Docs: a `triage` section in `docs/debug-postmortem.md` — what it composes, the
  partial-report semantics, the up-front build-id gate.

## 8. Testing strategy

Handler tests instantiate `debug_postmortem_triage_handler` directly with **injected
sub-handler seams** (`crash_handler=`, `drgn_helper_handler=`) returning canned
`ToolResponse`s, plus injected build-id readers — no real `crash`/drgn/vmcore, per repo
convention.

- **AC#1 happy path:** fake crash returns `results={"log": {parsed, lines:[…panic…]},
  "bt": {parsed, pid, command, frames:[…]}}`; fake dmesg returns
  `data={"result": {"entries":[…], "truncated":false}}`; fake modules returns
  `data={"result": {"modules":[…], "decode_errors":0}}` → `resp.ok`, all five sections
  `status="ok"`, `partial=False`, `report.panic_reason.text` is the panic line,
  `backtrace.frames`/`recent_dmesg.entries`/`modules.modules` populated, a
  `postmortem.triage:*` SUCCEEDED step + `report.json` under `debug/`.
- **AC#2 partial (crash source down):** fake crash returns
  `ToolResponse.failure(INFRASTRUCTURE_FAILURE, code="crash_open_failure")`; drgn fakes
  succeed → `resp.ok`, `partial=True`, the three crash sections `failed` with
  `reason == "crash_open_failure"` (the stable `code`, not prose), `recent_dmesg`/`modules`
  `ok`. Symmetric test: drgn down, crash up.
- **AC#2 within-source partial:** crash `ok` but `bt` is `{parsed:False,
  reason:"not_captured"}` and `log` parsed → `backtrace`/`faulting_task` `failed`
  (reason `not_captured`), `panic_reason` `ok`.
- **AC#3 build-id mismatch up front:** injected readers return different ids → hard
  `CONFIGURATION_ERROR` / `provenance_mismatch`, **and both sub-handler seams record zero
  calls** (assert call counters). Parametrize the other up-front codes
  (`provenance_unverifiable`, `vmcore_format_unsupported`, `vmlinux_build_id_unreadable`)
  via raising readers — each fails up front, no sub-call.
- **All-sources-down hard fail:** crash fails AND both drgn calls fail → hard
  `INFRASTRUCTURE_FAILURE` / `triage_all_sources_failed`; `details` carry `sub_call_ids`
  and a `section_reasons` map; no `report.json`; a FAILED `postmortem.triage:*` step.
- **Hard-fail still reachable when a sub-call ran:** crash `resp.ok=True` but `bt`/`log`
  both `not_captured` (3 crash sections fail) AND both drgn fail → hard
  `triage_all_sources_failed`, but `details["sub_call_ids"]["crash"]` is the crash
  sub-call id (its transcript stays reachable).
- **Hard-fail redaction:** a secret-shaped token in a sub-call's error `code`/reason is
  masked in the `triage_all_sources_failed` `details` (the hard-fail exit redacts, not
  only the success path).
- **Detail-less sub-call failure:** a sub-handler fake returns
  `ToolResponse.failure(category=…, message="…")` with **no `details`** → triage does not
  raise; the section is `failed` with `reason == "sub_call_failed"` (the fallback), and a
  detail-less *failed* crash sub-call still yields `sub_call_ids["crash"] is None` without
  error.
- **modules_ref up-front validation:** an unsafe/non-directory `modules_ref` →
  hard `symbol_resolution_failed` / `modules_path_unsafe` **before any sub-call** (both
  sub-handler seams record zero calls) — not a degraded partial report. A drgn sub-call
  fake asserts it received `modules_ref=None`.
- **`select_panic_reason` unit tests:** ordered signature precedence (`Kernel panic -
  not syncing` chosen over a later `BUG:`); no-match → `None`; empty list → `None`;
  a line missing `text` does not raise.
- **AC#5 redaction:** a secret-shaped token planted in a section payload (e.g. a crash
  `log` line, surfaced through the fake) is masked in `resp.data["report"]` **and** in
  the persisted `report.json`.
- **Lifecycle independence (§6):** handler succeeds with no admission service / no boot
  step injected (the signature has no admission parameter — calling it proves the gate
  is absent).
- **`partial` flag + `sub_call_ids`:** assert `partial` reflects any failed section and
  `sub_call_ids` maps each present sub-call id.
- **timeout/precondition edges:** `timeout_seconds=4` → `invalid_timeout` (no sub-call);
  missing run → `run_not_found`; missing/escaping `vmcore_ref` → `vmcore_not_found` (no
  sub-call).
- **Capability/config:** `local-crash-postmortem` advertises `debug.postmortem.triage`;
  the op is in `ALLOWED_DEBUG_OPERATIONS`; `TRIAGE_CRASH_COMMANDS == ("log","bt")`.

**AC#4 env-gated integration test** (`test_postmortem_triage_integration.py`): runs the
**real** crash + drgn against a fixture vmcore+vmlinux (skipped unless `crash` is on PATH,
drgn importable, and `LDM_VMCORE` points at a captured core + matching vmlinux — the same
gating the libvirt/gdb/drgn/crash suites use). The "crash and drgn runners produce
consistent results" AC is asserted as **deterministic, falsifiable invariants** the
fixture guarantees (not prose heuristics):

1. **Same-core provenance agreement** — the report's `vmcore_build_id` (the host VMCOREINFO
   id the up-front gate verified, fed to the crash side) equals the kernel build-id drgn
   reports for the *same* core. The fixture's drgn path exposes `main_module().build_id`;
   the test runs a one-line `from_vmcore` script (or reads the `modules`/`dmesg` sub-call's
   verified `build_id` field) and asserts byte-equality with `report["vmcore_build_id"]`.
   This is the strongest "same dump, consistent across runners" check and cannot pass
   vacuously.
2. **Crash side well-formed** — `report["faulting_task"]["status"] == "ok"` and
   `faulting_task["pid"]` is an `int >= 0`; `backtrace["frames"]` is non-empty (a panic
   core always has a faulting stack).
3. **Drgn side well-formed, fixture-agnostic** — `report["modules"]["status"]=="ok"`
   **and** `report["modules"]["decode_errors"]==0` (falsifiable — fails if the `modules`
   helper regresses on this kernel — without assuming the kernel is modular, which the
   shared `LDM_VMCORE` contract from #92/#55 does not promise: a valid monolithic core
   would otherwise spuriously fail a "non-empty modules" assertion), and
   `report["recent_dmesg"]["status"]=="ok"` with `recent_dmesg["entries"]` non-empty (a
   panic core always logged *something*). A non-empty *module list* is asserted only when
   the dedicated `LDM_VMCORE_MODULAR=1` signal is set (opt-in for a known-modular
   fixture), so the default path stays fixture-agnostic.

It is the **only** test exercising the real composition end-to-end; the unit suite proves
the assembly/partial/redaction logic with fakes.

## 9. Acceptance-criteria mapping

| Issue AC | Where satisfied |
|---|---|
| triage ⇒ one structured report: panic reason, faulting backtrace, recent dmesg, module list | §3.3, §4; AC#1 happy-path test (§8) |
| a failure in one source ⇒ partial report (section failed + reason), not a hard error, when the other succeeded | §3.3 (per-section status), ADR 0027 decision 3; AC#2 tests (§8) |
| build-id mismatch fails the whole triage loud **before** any sub-call | §4 step 2, §5, ADR 0027 decision 4; AC#3 test (sub-handlers never called) |
| crash- and drgn-sourced sections mutually consistent on the same dump | §8 env-gated integration test (AC#4) |
| all report fields + persisted artifacts through `Redactor()` | §4 step 7, ADR 0027 decision 6; AC#5 redaction test |
