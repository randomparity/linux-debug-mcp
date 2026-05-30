# ADR 0027 — `debug.postmortem.triage`: handler-level composition, single up-front build-id gate, per-section partial-failure contract

**Status:** Accepted (2026-05-30) · **Issue:** #93 · **Epic:** #9 · **Supersedes (in part):** #14 · **Depends on:** #92 (`debug.postmortem.crash`), #54/#55 (`debug.introspect.from_vmcore_helper` + curated drgn helpers) · **Affects:** `src/linux_debug_mcp/domain.py` (triage request + `DebugPostmortemTriageReport`), `src/linux_debug_mcp/postmortem/triage.py` (new: section assembly + panic-line selection), `src/linux_debug_mcp/server.py` (`debug_postmortem_triage_handler`, tool registration), `src/linux_debug_mcp/config.py` (`ALLOWED_DEBUG_OPERATIONS`, triage caps), `src/linux_debug_mcp/providers/local_crash_postmortem.py` (capability `operations`)

## Context

#93 adds `debug.postmortem.triage`: the single "first call for an agent handed a
crash" and the recommended reaction to the `target.crashed` lifecycle event
(interface-contracts §5.5). It does **not** introduce a new analysis mechanism. It
**composes** two already-shipped offline tiers into one structured report against a
single `(vmcore, vmlinux)` pair:

- the **crash** tier (#92, `debug.postmortem.crash`) supplies the *panic reason*,
  *faulting task*, and *faulting backtrace* (`log` + `bt`);
- the **drgn** tier (#54/#55, `debug.introspect.from_vmcore_helper`) supplies *recent
  dmesg* (`dmesg` helper) and *loaded modules* (`modules` helper).

Both tiers inherit ADR 0010's offline scoping (run-relative refs, no target, no
admission gate, host-authoritative build-id) and the mandatory redaction contract.
The issue calls out exactly four composition decisions the spec leaves open, recorded
here: (1) does triage invoke the sub-tiers' **handlers** or their **providers**;
(2) the **fixed helper set** (which commands/helpers, no caller choice); (3) the
**partial-vs-hard failure contract**; (4) where the single **build-id fail-loud**
runs. Everything else (run confinement, symbol resolution, per-sub-call redaction,
manifest persistence, the crash command allowlist) is inherited unchanged.

## Decision

### 1. Triage composes the sub-tier **handlers** in-process, via injectable seams

`debug_postmortem_triage_handler` calls `debug_postmortem_crash_handler` once and
`debug_introspect_from_vmcore_helper_handler` twice (`dmesg`, then `modules`) as
ordinary in-process function calls. The two sub-handlers are **injectable seams**
(`crash_handler=`, `drgn_helper_handler=`, defaulting to the real handlers), so
composition and partial-failure logic are unit-tested with fakes that return canned
`ToolResponse`s — no real `crash`/drgn/vmcore in unit tests, per repo convention.

The handlers — not the providers — are the composition unit because each handler
already owns the entire orchestration triage would otherwise duplicate: manifest load,
`resolve_symbols`/`confine_run_relative`, the per-sub-call build-id gate, the
`Redactor` pass over every returned/persisted field, the `sensitive/` vs `debug/`
artifact split, and the per-call manifest step. Re-driving the providers
(`SubprocessSshRunner` + `crash`/`python3` argv) from triage would re-implement all of
that and is exactly the duplication ADR 0026/0010 centralised. Triage's own job is
narrow: one build-id gate, three sub-calls, section assembly, one composed-report
artifact, one `postmortem.triage:<call_id>` manifest step.

The seam still threads the real I/O seams through to the real sub-handlers in
production: triage holds `runner`, `vmcore_build_id_reader`, `vmlinux_build_id_reader`,
and `clock`, uses the readers for its own up-front gate (decision 4), and forwards them
to the crash sub-handler (and `vmlinux_build_id_reader` → the drgn handler's
`build_id_reader`) so the up-front gate and the sub-calls read provenance identically.

### 2. The helper set is **fixed**, not caller-selectable

The triage request is `(run_id, vmcore_ref, vmlinux_ref, modules_ref?, timeout_seconds)`
— **no** `commands`/`helpers`/section-selection field. The composition is hard-coded:

| Report section | Source tier | Sub-call |
|---|---|---|
| `panic_reason` | crash | `debug.postmortem.crash` `commands=["log","bt"]` |
| `faulting_task` | crash | (same crash sub-call — `bt` header) |
| `backtrace` | crash | (same crash sub-call — `bt` frames) |
| `recent_dmesg` | drgn | `from_vmcore_helper name="dmesg"` |
| `modules` | drgn | `from_vmcore_helper name="modules"` |

This is the issue's "fixed helper set": one curated report, not a configurable
pipeline. An agent that wants a different command/helper calls the underlying tool
directly — triage is the *opinionated first look*, not a general composer (no
speculative configurability). The crash tier is invoked **once** with both `log` and
`bt` so the multi-GB core is opened once for both crash-sourced sections.

### 2a. `panic_reason` is **selected** from the crash `log` parser output, not newly parsed

The crash `log` parser (#92) already yields `{"lines": [{ts, text}]}`. Triage picks the
panic line by scanning those structured lines for a fixed, ordered set of kernel
panic-signature prefixes (`Kernel panic`, `BUG:`, `Oops`, `Unable to handle kernel`,
`general protection fault`, `kernel BUG at`, `WARNING:`-excluded, …) and taking the
first match. This is **selection over already-parsed, already-redacted data** — it adds
no new crash-output parser and stays within the issue's "reuses the crash runner's
parsers" scope. A core with no matching line (a deliberate `virsh dump`, not a panic)
yields `panic_reason.status="ok"` with `text=None` — successfully looked, found none —
mirroring the `modules` helper's "empty list is valid" stance. `status="failed"` is
reserved for when the underlying `log` command did not parse or the crash sub-call
failed.

### 3. Partial-vs-hard failure contract: per-section status; hard-fail only when **every** section failed

Each of the five sections is a typed object carrying `source` (`crash`|`drgn`),
`status` (`ok`|`failed`), and (when failed) a `reason`. A sub-call failure marks **its**
sections `failed` with the sub-call's redacted error message as the reason; the other
source's sections are unaffected. So `crash` not installed → the three crash sections
fail, `recent_dmesg`/`modules` still populate, and the call returns
`ToolResponse.success` with `partial=True` (AC#2). The composed report is returned
**partial**, never collapsed to a hard error, **as long as at least one section is
`ok`**.

The single hard-failure boundary inside the composition is: **zero `ok` sections** →
`ToolResponse.failure(INFRASTRUCTURE_FAILURE, code="triage_all_sources_failed")` whose
`details` carry the redacted `sub_call_ids` and a `section_reasons` map. "≥1 section
`ok` ⇒ partial success; 0 sections `ok` ⇒ hard failure" is the concrete reading of the
issue's "provided at least one source succeeded" — simpler than tracking
source-granularity success, and it can fire even when a sub-call's `resp.ok` was `True`
but produced no usable section (e.g. crash ran but `bt`/`log` were `not_captured`).
Carrying `sub_call_ids` on the failure keeps any transcript a sub-call *did* persist
reachable, so the stronger rule loses no forensic reach. The `reason` on a failed
section is the sub-call's **stable error `code`** (`details["code"]`), not the prose
`message`, so agents branch on a contract value. The up-front build-id gate (decision 4)
and triage's own input/precondition errors (run-not-found, bad timeout) are the **only**
other hard failures; every per-sub-call analysis failure degrades to a section.

### 4. A single build-id fail-loud runs **up front**, before any sub-call

Before invoking any sub-handler, triage runs the #92 host-authoritative gate **once**:
`read_vmcore_build_id(vmcore)` vs `read_elf_build_id(vmlinux)` (reusing the crash
handler's `_crash_buildid_failloud` helper). A mismatch / unreadable-vmlinux /
unverifiable-or-unsupported-vmcore is a `CONFIGURATION_ERROR` (`provenance_mismatch` /
`vmlinux_build_id_unreadable` / `vmcore_format_unsupported` / `provenance_unverifiable` /
`vmcore_build_id_unreadable`) returned **before any sub-call is made** — proven by a
test asserting both sub-handler seams saw zero invocations (AC#3). A build-id mismatch
is a *provenance* error the agent must fix (wrong vmlinux); degrading it to a per-section
failure would bury the one error that invalidates the entire report, so it is
deliberately outside the partial contract.

The sub-handlers re-run their own build-id gates (the crash handler via the same
readers; the drgn wrapper via drgn's `main_module().build_id`). This re-check is
intentional and cheap: `read_vmcore_build_id` is a seek-only PT_NOTE walk, and the drgn
path must open the core regardless. The up-front gate guarantees the *whole-report*
hard-fail semantics the issue requires; the sub-handler gates remain the per-tier
authority and are not weakened by a "skip" flag (which would be a phantom feature on
the standalone tools).

### 5. No separate budget; triage consumes the existing per-tier ceilings

Triage adds **no** new call-budget. Its one crash sub-call ticks the existing
`MAX_POSTMORTEM_CRASH_CALLS_PER_RUN`; its two drgn sub-calls tick the existing
`MAX_INTROSPECT_CALLS_PER_RUN`. A sub-call that trips its ceiling returns a
`CONFIGURATION_ERROR`, which triage treats as that source's section failure (degraded
report, decision 3) — not a triage-specific budget error. The `postmortem.triage:<call_id>`
manifest step triage writes is a record only; it is not itself budget-gated, matching
the issue's "the triage cost counts against the run's existing introspect/postmortem
call ceiling (no separate budget)."

### 6. The report is re-redacted at the composition boundary

Every field triage returns/persists already came from a sub-handler that redacted it.
Triage nonetheless passes the assembled report through `Redactor()` once more before
persisting `report.json` and returning it, so the contract ("all report fields +
persisted artifacts through `Redactor()`", AC#5) holds for the composed artifact as a
single chokepoint — and any field the composer itself synthesises (e.g. the selected
panic line) is covered without relying on the upstream pass. Re-redaction is idempotent
on already-redacted text. The **hard-fail exit** (`triage_all_sources_failed`) redacts
too: its `details` (`sub_call_ids` + `section_reasons`) pass through `Redactor()` before
return, so the chokepoint covers both the success and the all-sources-down paths — not
only the success path.

## Consequences

- Triage is thin: ~one gate + three calls + assembly. The heavy lifting (provenance,
  redaction, persistence, confinement) stays in the sub-handlers, single-sourced.
- A crash- or drgn-tier change (new parser field, new failure code) flows into triage
  automatically because triage consumes the handlers' typed responses, not re-derived
  provider output.
- The partial contract means an agent always gets *something* actionable from a
  half-broken host (crash missing, or drgn missing) — the `target.crashed` first-reaction
  stays useful when only one tier is installed.
- Re-checking the build-id per sub-call costs a few extra seek-only reads; accepted for
  the stronger whole-report fail-loud guarantee and to keep the sub-tools authoritative.
- Three manifest steps per triage (`postmortem.crash:*`, two `introspect:*`) plus the
  `postmortem.triage:*` record; manifest growth is bounded by the existing per-tier
  budgets, so no new bound is introduced.
- AC#4 (crash- and drgn-sourced sections mutually consistent on the same dump) is
  provable only against a real core; it is an env-gated integration test, like the
  sibling tiers' real-`crash`/real-drgn suites.

## Considered & rejected

1. **Invoke the providers (`SubprocessSshRunner` + `crash`/`python3`) directly from
   triage.** Rejected: re-implements manifest load, symbol resolution, the build-id
   gate, redaction, the sensitive/debug artifact split, and per-call step recording —
   the exact orchestration ADR 0026/0010 centralised in the handlers. Composition at the
   handler layer reuses all of it and inherits future fixes for free.

2. **A configurable section/command/helper set on the triage request.** Rejected: the
   issue specifies a *fixed* helper set and frames triage as the opinionated first call.
   A configurable pipeline is a speculative feature; an agent that wants a custom command
   already has `debug.postmortem.crash` / `debug.introspect.from_vmcore_helper`.

3. **Add a new "panic reason" crash-output parser.** Rejected: out of scope ("no new
   parsers"). The existing `log` parser's structured lines are sufficient; triage
   *selects* the panic line by signature match — composition logic, not a parser.

4. **Treat a build-id mismatch as just another per-section failure (fully partial
   report).** Rejected: a mismatch invalidates *every* section (wrong symbols → wrong
   backtrace, wrong modules), so a "partial report" would be confidently wrong on all
   five. AC#3 requires the mismatch to fail the whole triage loud, before any sub-call.

5. **Skip the sub-handlers' own build-id gates once triage has checked (a "trust me"
   flag).** Rejected: adds a phantom bypass flag to two standalone tools to save a
   seek-only read, and de-authoritative-ises tools that must stay correct when called
   directly. The redundant check is cheap and keeps each tier self-guarding.

6. **Hard-fail triage if *any* section fails (all-or-nothing).** Rejected: contradicts
   AC#2 (one source failing must still yield the other source's report). The partial
   contract is the whole point of the per-section status tagging.

7. **Run the crash `log` and `bt` as two separate `debug.postmortem.crash` calls.**
   Rejected: each call re-opens the multi-GB core (ADR 0026 rejected per-command crash
   invocations for the same reason). One batched crash call with `commands=["log","bt"]`
   opens the core once for both crash-sourced sections.

8. **Strongly re-type every inner item (frame/dmesg-entry/module) in the report.**
   Rejected: it duplicates the crash parsers' and drgn helpers' output shapes, creating a
   second source of truth that drifts (and, with `extra="forbid"`, would *reject* a new
   upstream field at the composition boundary). The section wrappers are typed
   (`source`/`status`/`reason` + payload); the payloads pass through the already-typed,
   already-redacted upstream shapes.

## References

spec `docs/superpowers/specs/2026-05-30-debug-postmortem-triage-design.md`;
interface contract `docs/specs/interface-contracts.md` §5.5 (`target.crashed`
first-reaction), §5.6 rule 3 (never gated), §4.2 (fail-loud);
ADR 0026 (`debug.postmortem.crash`: build-id reader, framing, parsers),
ADR 0010 (offline execution model, host-authoritative build-id, never-gated),
ADR 0009 (introspect helper layer), ADR 0008 (symbols package leaf);
`src/linux_debug_mcp/server.py` (`debug_postmortem_crash_handler`,
`debug_introspect_from_vmcore_helper_handler`, `_crash_buildid_failloud`).
