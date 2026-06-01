# 0039 — Introspect drgn provenance-failure taxonomy

Status: Accepted

## Context

Both introspect wrappers (`wrappers/live.py`, `wrappers/vmcore.py`) mapped **any**
exception raised while reading `prog.main_module().build_id` to a single
`drgn_version_skew` outcome with the message
*"drgn lacks main_module().build_id (version skew)"*.

In #139 the real cause was a drgn ≥ 0.2 behavioral change — the main module is not
created until module discovery runs, so `main_module()` raised
`LookupError: module not found` — **not** a missing `build_id` attribute and **not**
a build-id provenance mismatch. drgn *had* `build_id`; it just needed discovery
first. The message actively misled: an agent reading "drgn lacks
main_module().build_id" would suspect a too-old drgn when the opposite was true.

Two distinct defects sat behind one code:

1. The live wrapper read `prog.main_module().build_id.hex()` directly, so a `None`
   build-id raised `AttributeError` (`'NoneType' has no attribute 'hex'`) and was
   reported as version skew rather than "provenance unverifiable" — the vmcore
   wrapper already distinguished this case.
2. A resolution error (drgn raised while bringing up the module view) was
   indistinguishable from a genuine API/version gap.

## Decision

Split the build-id-resolution failure into precise outcome statuses. Both wrappers
resolve the module build-id in three ordered steps with distinct outcomes:

| Outcome status | Trigger | `ErrorCategory` | exit |
|---|---|---|---|
| `drgn_open_failure` | prelude `import drgn` / `set_kernel` / `set_core_dump` / `load_default_debug_info` raised | `INFRASTRUCTURE_FAILURE` | 3 |
| `drgn_version_skew` | `main_module().build_id` resolution raised `AttributeError` — drgn's module API genuinely lacks the attribute/shape | `INFRASTRUCTURE_FAILURE` | 3 |
| `drgn_api_incompatible` | `main_module().build_id` resolution raised any **other** exception (e.g. the #139 `LookupError`) — the program opened but its module/provenance API behaved unexpectedly | `INFRASTRUCTURE_FAILURE` | 3 |
| `provenance_unverifiable` | build-id resolved to `None` (no embedded build-id) | `CONFIGURATION_ERROR` | 4 |
| `provenance_mismatch` | build-id present but ≠ expected | `CONFIGURATION_ERROR` | 4 |

- The live wrapper now resolves the build-id (`_li_bid = prog.main_module().build_id`),
  then derives `_li_bid.hex() if _li_bid else None`, then checks
  `None → provenance_unverifiable` — matching the vmcore wrapper. A `None` build-id is
  no longer misreported as version skew.
- `drgn_open_failure` and `provenance_mismatch` are unchanged.
- The `drgn_version_skew`, `drgn_api_incompatible`, and `drgn_open_failure` outcomes
  carry `error_type` and the observed `drgn.__version__` (`drgn_version`, captured in
  the prelude, `None` if `import drgn` itself failed), so a version gap is diagnosable
  against the running drgn without a second round-trip.

## Consequences

- Agents can distinguish "drgn's API lacks build_id" (`drgn_version_skew`) from "drgn
  raised resolving the module" (`drgn_api_incompatible`) from "no build-id"
  (`provenance_unverifiable`) from "build-id mismatch" (`provenance_mismatch`). The
  #139 failure now surfaces as `drgn_api_incompatible` with `error_type="LookupError"`,
  not a misleading version-skew claim.
- `result.py` gains a `drgn_api_incompatible` mapping; the `drgn_version_skew` message
  is narrowed to the attribute-gap case; `provenance_unverifiable`'s message is made
  path-neutral (it is no longer vmcore-only).
- The golden live-wrapper snapshot (`tests/golden/live_wrapper_template.txt`) is
  regenerated. Wrapper tests gain coverage for `drgn_api_incompatible` and (live)
  `provenance_unverifiable`.
- #147 (active readiness self-test) builds on this taxonomy: a preflight that opens a
  target and confirms `main_module().build_id` resolves reports these same statuses.

## Considered & rejected

- **Reuse `drgn_open_failure` for resolution errors instead of adding
  `drgn_api_incompatible`.** Rejected: the prelude open already succeeded by the time
  the build-id read runs; collapsing both into one code destroys the "did the program
  open at all?" signal an agent needs to localize the fault.
- **Assert a hard numeric drgn version floor (e.g. `drgn >= 0.2`).** Rejected: no
  known-good minimum is declared anywhere in the repo (the prereq probe only reads
  `__version__` for forensics), so any floor is a guess that risks false-rejecting
  working setups. The behavioral `AttributeError` signal plus the recorded
  `drgn_version` pins the gap precisely without guessing. Active version confirmation
  (open a target, confirm resolution) belongs to #147.
- **Keep one code and only fix the message.** Rejected: the misleading message was a
  symptom; the conflation of four distinct causes into one code is the actual defect,
  and a single message cannot be accurate for all four.
