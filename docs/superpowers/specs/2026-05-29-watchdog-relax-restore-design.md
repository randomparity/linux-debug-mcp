# Watchdog relax/restore helper for interactive stops — design

**Issue:** #69 (epic #9, split from #17, consumed by #66) · **Status:** proposed
**Contract:** `docs/specs/interface-contracts.md` §5.5, §5.6 · **Plugs into:** `SessionGuard` (#66, `seams/guard.py`)
**ADR:** [0016](../../adr/0016-watchdog-relax-restore-helper.md)
**Reference:** kernel lockup detectors (`Documentation/admin-guide/lockup-watchdogs.rst`)

## 1. Purpose & scope

A naive interactive stop can wedge a target: while a CPU is held at a breakpoint,
the kernel's lockup detectors (and, on POWER, the platform/PHYP watchdog) keep
counting, so on resume — or on the other still-running CPUs — a softlockup/
hardlockup fires and the target panics or resets. This issue adds a **watchdog
relax/restore helper**: it relaxes the relevant watchdogs **before** an interactive
stop and restores their prior values **afterward**, including on error and timeout.

The helper is the first concrete `TeardownStep` (and paired enter-phase step) that
hangs off the `SessionGuard` seam #66 shipped with empty slots. #66 defined
**where** watchdog relax/restore hooks in; #69 defines **what it does** and proves
the relax→restore round-trip and the restore-on-error / restore-on-timeout
invariants by seam-level test.

### 1.1 In scope

- A `WatchdogPolicy` helper in a new `seams/watchdog.py`:
  - Architecture variants (`x86_64`, `ppc64le`) selecting an ordered list of
    `WatchdogKnob`s with their relaxed target values.
  - A stateful `relax(ctx)` / `restore(ctx)` pair keyed by `(target_key,
    generation)`: `relax` reads-then-captures each knob's current value and writes
    the relaxed value; `restore` is idempotent and writes the captured values back.
  - Execution through an injected `WatchdogControl` channel (`read_knob`/
    `write_knob`), so the mechanism is decoupled from any transport and unit-testable
    with a fake.
- Two thin `SessionGuard` adapters:
  - `WatchdogRelaxStep` — a `PreAttachPrecondition` (the **enter** slot) that calls
    `policy.relax`.
  - `WatchdogRestoreStep` — a `TeardownStep` (the **exit** slot) that calls
    `policy.restore`, run on the clean-end and attach-error teardown paths.
- Seam-level tests proving: capture-then-relax order; restore round-trips the
  captured values; restore is idempotent (double teardown); restore-on-error
  (`reason="attach_error"`); restore-on-timeout (an attach/operation timeout
  surfacing as a teardown); a failing channel write is non-fatal and aggregated
  into `TeardownReport.step_errors`; x86 vs ppc64le knob-list variance; the
  ppc64le out-of-band PHYP knob is recorded skipped, never executed; restore with
  no prior relax is a clean no-op.

### 1.2 Out of scope

- **Live wiring into the running debug handler.** Like #66's empty slots, #69 does
  **not** add the steps to the `SessionGuard()` constructed in `create_app`. The
  only implemented interactive tier today is the QEMU gdbstub, which **freezes the
  whole VM** while stopped (no guest time passes), so the lockup detectors cannot
  fire during a stop and there is nothing to relax. Wiring an inert ssh sysctl path
  into the gdbstub handler would be speculative dead code (and would introduce the
  open-failure leak of §4.2). The live consumer is the future KGDB / remote / POWER
  tier (epic #9), which owns the `WatchdogControl` backing and the correct
  placement (§4.2).
- The real `WatchdogControl` backing (ssh `sysctl`, or HMC/NovaLink for the POWER
  PHYP watchdog). #69 ships the Protocol and a fake; the live tier supplies the
  ssh/out-of-band implementation.
- Any change to `SessionGuard`, `TransportTransaction`, the admission protocol, or
  the lifecycle dispatcher. #69 adds only the new `seams/watchdog.py` module and its
  tests.
- Routing restore through the lifecycle-dispatcher invalidation path — see §5.

## 2. Background: what already exists

| Concern | Where | Status for #69 |
|---|---|---|
| Enter (`PreAttachPrecondition`) + exit (`TeardownStep`) slots | `seams/guard.py` `SessionGuard` | reused; #69 supplies one of each |
| Reverse-order, suppress+aggregate teardown-step execution | `SessionGuard.teardown` | reused unchanged; the restore step relies on its non-fatal contract |
| `SessionGuardContext` (`target_key`, `generation`, `session_id`, `reason`) | `seams/guard.py` | reused as the `relax`/`restore` key source |
| Bounded, cancelable command execution over ssh | `providers/local_ssh_tests.py` `SshRunner` | the live `WatchdogControl` backing (future tier); #69 depends only on the abstraction |
| Redaction of guest-derived text before persist/return | `safety/redaction.py` `Redactor` | applied to any captured knob text the helper surfaces |

The gap #69 fills: `SessionGuard` shipped the teardown slot empty with a comment
that "#69 adds a `TeardownStep`." There is no helper that knows **which** watchdogs
to relax, **captures** their prior state, and **restores** it idempotently across
the success/error/timeout exits.

## 3. Components (`seams/watchdog.py`)

### 3.1 `WatchdogArch` and `WatchdogKnob`

```python
class WatchdogArch(StrEnum):
    X86_64 = "x86_64"
    PPC64LE = "ppc64le"

@dataclass(frozen=True)
class WatchdogKnob:
    name: str                 # sysctl key, e.g. "kernel.nmi_watchdog"
    relaxed_value: str        # value written to relax it for an interactive stop
    out_of_band: bool = False # not reachable over the in-band (sysctl) channel
```

The relaxed value is what makes a stop safe; restore puts the captured prior value
back, so the relaxed value is only ever a transient override.

**x86_64 knobs** (sysctl / `/proc/sys/kernel`), in declared order:

| knob | relaxed | why |
|---|---|---|
| `kernel.nmi_watchdog` | `0` | stop the NMI/perf hardlockup detector counting while a CPU is held |
| `kernel.watchdog` | `0` | disable the soft+hard lockup detector threads |
| `kernel.watchdog_thresh` | `0` | belt-and-suspenders: a 0 threshold disables the period even if `watchdog` is re-armed |
| `kernel.softlockup_panic` | `0` | a softlockup observed across the stop must not panic |
| `kernel.hardlockup_panic` | `0` | a hardlockup observed across the stop must not panic |

**ppc64le knobs**: the same five generic lockup-detector knobs (the detectors are
arch-independent kernel infrastructure), **plus**:

| knob | relaxed | out_of_band |
|---|---|---|
| `phyp_partition_watchdog` | `disabled` | `True` |

The PHYP/PowerVM partition watchdog (and a PowerNV hardware watchdog) is controlled
out-of-band via the HMC/NovaLink/BMC, not by an in-band sysctl. With no out-of-band
`WatchdogControl` wired (future-stub territory, matching the repo's posture for
remote/console/power tools), an `out_of_band=True` knob is **recorded as skipped**
during relax and restore — never read, never written through the in-band channel.
This keeps the POWER variant honest: its generic detectors behave exactly like
x86's; its platform watchdog is declared and explicitly deferred.

### 3.2 `WatchdogControl` channel

```python
@dataclass(frozen=True)
class WriteOutcome:
    ok: bool
    detail: str = ""        # redacted; empty on success

@runtime_checkable
class WatchdogControl(Protocol):
    def read_knob(self, name: str) -> str | None:
        """Return the knob's current value, or None if it cannot be read
        (absent on this kernel / unreadable). Never raises for an absent knob."""
        ...
    def write_knob(self, name: str, value: str) -> WriteOutcome:
        """Set the knob. Returns WriteOutcome(ok=False, detail=...) on failure;
        MUST NOT raise — a failed write is data the policy aggregates, not control flow."""
        ...
```

The channel is **the only** thing that touches the target. #69 ships no concrete
backing; the live tier supplies one over `SshRunner` (in-band knobs) and/or an
out-of-band power-control channel. Tests inject a `FakeWatchdogControl` recording
the ordered `(op, name, value)` calls and returning scripted values/failures.

`detail` on a `WriteOutcome`, and any `read_knob` return surfaced into a report,
are passed through `Redactor` before they can reach a persisted/returned surface —
knob values are not secret, but the channel reads guest-side command output and the
repo contract requires redaction on every guest-output path.

### 3.3 `WatchdogPolicy` (stateful core)

```python
class WatchdogPolicy:
    def __init__(self, *, arch: WatchdogArch, channel: WatchdogControl,
                 knobs: Sequence[WatchdogKnob] | None = None) -> None: ...
    def relax(self, ctx: SessionGuardContext) -> RelaxReport: ...
    def restore(self, ctx: SessionGuardContext) -> RestoreReport: ...
```

State: a `dict[tuple[TargetKey, int], CapturedState]` keyed by `(ctx.target_key,
ctx.generation)`, guarded by a `threading.Lock` (the guard handlers can run
concurrently for distinct targets). `CapturedState` holds, per in-band knob, the
value read at relax time and a `relaxed: bool` recording whether the relax write
itself succeeded (a knob whose relax write failed is **not** restored — there is
nothing to put back, and writing the captured value would be a no-op write of a
value we never changed).

**`relax(ctx)`** — for each knob in declared order:
- `out_of_band` knob → record `skipped` (reason: no out-of-band channel), continue.
- in-band knob → `read_knob` (capture prior value; `None` ⇒ knob absent ⇒ record
  `absent`, skip the write), then `write_knob(relaxed_value)`; record the
  `WriteOutcome`. Store the captured map under the `(target_key, generation)` key,
  **replacing** any prior capture for that key (a re-`relax` of the same incarnation
  re-reads current state — see §4.1 idempotency).

Returns a `RelaxReport` (knob → outcome: `relaxed` / `absent` / `skipped` /
`write_failed`). `relax` never raises; a channel that itself raises is caught and
recorded as `write_failed` for that knob.

**`restore(ctx)`** — look up the captured map for `(target_key, generation)`:
- no entry (relax never ran for this incarnation, or restore already ran and cleared
  it) → return an empty `RestoreReport(restored={}, noop=True)`.
- entry present → for each knob that was actually `relaxed` (captured value known
  and the relax write succeeded), in **reverse** declared order, `write_knob(captured
  value)`; record the outcome. Then **delete** the captured map for the key (so a
  second restore is the no-op above). Knobs recorded `absent`/`skipped`/`write_failed`
  at relax are not restored.

Returns a `RestoreReport`. `restore` never raises (the `TeardownStep` contract); a
write that fails is recorded in the report and surfaces via the adapter into
`TeardownReport.step_errors`.

### 3.4 SessionGuard adapters

```python
class WatchdogRelaxStep:                  # PreAttachPrecondition
    name = "watchdog-relax"
    def __init__(self, policy: WatchdogPolicy) -> None: ...
    def check(self, ctx: SessionGuardContext) -> None:
        self._policy.relax(ctx)           # side-effecting; never raises to abort enter

class WatchdogRestoreStep:                # TeardownStep
    name = "watchdog-restore"
    def __init__(self, policy: WatchdogPolicy) -> None: ...
    def teardown(self, ctx: SessionGuardContext) -> None:
        report = self._policy.restore(ctx)
        if report.failures:               # any knob whose restore write failed
            raise WatchdogRestoreError(report)   # suppressed+aggregated by SessionGuard.teardown
```

`WatchdogRestoreStep.teardown` deliberately **raises** on a restore-write failure so
the failure lands in `TeardownReport.step_errors` (the §3.3a contract: a step that
fails records the failure; `SessionGuard.teardown` wraps each step in
suppress-with-logging). It does **not** raise on a `noop` restore (nothing was
relaxed). The resume + reap invariant is unaffected either way — `close` runs
regardless.

Both adapters share one `WatchdogPolicy` instance (the captured-state owner), so the
relax capture and the restore lookup address the same store.

## 4. Integration contract (how the live tier wires it)

### 4.1 Idempotency

A `debug.end_session` may be retried, so `SessionGuard.teardown` (and thus
`restore`) may run twice. `restore` is idempotent by construction: the first run
restores and deletes the captured map; the second finds no entry and returns a
`noop` report. `relax` is also re-entrant per incarnation: a re-`relax` re-reads the
live knobs and replaces the capture, so a relax that ran, then a stop that was
abandoned and re-entered, captures the **then-current** values rather than stacking
relaxed-over-relaxed.

### 4.2 Placement: relax must run in a guaranteed-teardown window

The enter slot #66 exposes is `pre_attach`, which runs **before**
`transaction.open()`. But the live `debug_start_session_handler` early-returns on an
`open()` failure (`GuardConflict`/`AdmissionError`) **without** calling
`teardown` — `open()` is a self-rolling-back write-ahead transaction with no
`sid` to tear down (session-guard spec §4, Finding 2). So a relax placed in the bare
`pre_attach` slot that ran before a failing `open()` would leave the watchdog
relaxed with **no** restore — a leak.

Therefore the **live** integration contract (recorded in ADR 0016) is: the relax
invocation must sit in the **post-acquire / pre-halt window** — after
`transaction.open()` commits (teardown is then guaranteed on every later failure)
and before `provider.start_session` performs the attach that halts the kernel (the
in-band channel is then still reachable). #66's `SessionGuard` has no slot in that
window; adding one enlarges the #66 seam, so it is deferred to the live KGDB/remote
tier that needs it (ADR 0016 rejected-alt 2).

Because #69 wires the steps **inert** (§1.2), this is a documented contract, not a
live bug: the seam tests construct a `SessionGuard(pre_attach=[relax],
teardown_steps=[restore])` to exercise the **mechanism** (enter → relax, teardown →
restore) with a fake channel, while the spec/ADR record the **placement** the live
tier must honor.

### 4.3 What the channel reaches, and when

`relax` runs while the kernel is **running** (pre-halt window) — `read_knob`/
`write_knob` over the in-band channel succeed. `restore` runs in `SessionGuard.
teardown`, which on the **clean-end** path executes after the provider detach has
already resumed the kernel (the channel is reachable). On the **attach-error** path
the kernel may still be parked at the durable `HALTED` record and the actual CPU
state is uncertain; the channel's bounded/cancelable contract (the live `SshRunner`
backing already enforces a per-command timeout) means a restore write against an
unreachable target fails fast and is recorded `write_failed` rather than hanging
teardown. The captured state is **not** cleared for a knob whose restore write
failed only if we choose to allow a later retry — for #69 the restore deletes the
whole map after one pass (idempotency §4.1); a live tier that wants post-resume
retry can re-`relax`/re-`restore`. This bounded-best-effort behavior is the same
posture `SessionGuard.teardown` already takes for `close`.

## 5. restore-on-error and restore-on-timeout

AC: watchdogs are restored "including on error/timeout." The two cases:

- **Error** — a post-`open()` failure (`provider.start_session` raises, or a
  post-attach precondition rejects) drives `teardown(reason="attach_error")`, which
  runs the `WatchdogRestoreStep`. Captured values are restored. Tested directly at
  the seam by driving `teardown` with a provider/step that raises.
- **Timeout** — an interactive-stop / attach **operation** timeout surfaces as a
  `ProviderDebugError` (a timeout `ErrorCategory`) from `provider.start_session`,
  taking the **same** `attach_error` teardown path → restore runs. Tested by a
  provider whose `start_session` raises a timeout-category error.

The **lifecycle-dispatcher invalidation path** (`resetting` / `crashed` /
`releasing` / `lease_expired`) is deliberately **not** a restore path, exactly as
ADR 0013 decided: every dispatcher invalidation is a target reboot/release, where
the kernel restarts with its configured watchdog defaults, so a restore would be
meaningless. #69 reaffirms this and adds a **conformance assertion** (not new
teardown code) that the dispatcher path leaves no watchdog obligation — i.e. the
restore step is correctly absent there — so reopening ADR 0013 is unnecessary. The
"times out" clause of AC1 for the *target* (no orphan, no live `HALTED`) is already
covered by #66's dispatcher conformance test; #69's timeout concern is the
*operation* timeout that lands on the synchronous teardown.

## 6. Error handling & failure contract

- `relax` and `restore` **never raise** — they return reports. A channel that
  raises is caught and recorded per-knob.
- `WatchdogRelaxStep.check` is side-effecting and must not abort the enter on a
  relax failure: a watchdog that could not be relaxed is a logged degradation, not a
  reason to refuse the session (refusing would strand the agent with no debug path
  for a non-safety-critical knob). It records the `RelaxReport` and returns. (A live
  tier that wants a hard refusal on a *specific* critical knob can add its own
  `PreAttachPrecondition`; that policy is out of scope for #69.)
- `WatchdogRestoreStep.teardown` raises `WatchdogRestoreError` only on a restore
  **write** failure, so the failure is captured into `TeardownReport.step_errors`
  and visible in the handler response details (`teardown_step_errors`) — it never
  flips a successful end to a failure and never blocks `close` (the resume + reap
  invariant holds regardless, per ADR 0013).
- All knob text surfaced into a report is redacted (§3.2).

## 7. Testing

Seam-level, injected `FakeWatchdogControl`, following the repo convention (no MCP):

- **relax order + capture**: `relax` reads each in-band knob then writes its relaxed
  value, in declared order; the captured map holds the read values.
- **x86 vs ppc64le variance**: the x86 policy drives exactly the five generic knobs;
  the ppc64le policy drives the five generic knobs **plus** records the
  `phyp_partition_watchdog` as `skipped` and never calls `read_knob`/`write_knob`
  for it.
- **restore round-trip**: after `relax` then `restore`, the channel saw each in-band
  knob written back to its captured value in reverse order; the captured map is
  cleared.
- **restore idempotency**: a second `restore` (double `teardown`) is a `noop` report
  with no further `write_knob` calls.
- **restore with no prior relax**: `restore` without a preceding `relax` is a `noop`,
  no writes.
- **restore-on-error**: a `SessionGuard` with the restore step + a `provider`/step
  that raises drives `teardown(reason="attach_error")`; assert each captured knob
  restored and `resume_ok` still holds (close still ran).
- **restore-on-timeout**: a `provider.start_session` raising a timeout-category
  `ProviderDebugError` drives the `attach_error` teardown → restore runs; assert
  restore happened.
- **restore-write failure is non-fatal**: a `FakeWatchdogControl` whose `write_knob`
  fails on restore for one knob → `WatchdogRestoreStep.teardown` raises, the error is
  aggregated into `TeardownReport.step_errors`, the **other** knobs are still
  restored, and `close` still ran (`resume_ok=True`).
- **absent knob**: `read_knob` returning `None` → that knob is recorded `absent`,
  not written at relax, and not restored.
- **relax write failure**: a knob whose relax `write_knob` fails is recorded
  `write_failed` and is **not** later restored (nothing was changed).
- **dispatcher path has no restore obligation** (conformance): emit a
  `target.resetting` event for a session and assert no watchdog restore is expected
  on that path (the step is not on the dispatcher) — documenting §5.
- **concurrency**: two distinct `(target_key, generation)` keys capture/restore
  independently (no cross-talk in the shared store).
- Integration tests touching real ssh/gdb stay env-gated and untouched.

## 8. Open questions

None. The wiring scope (inert, seam-tested), the relax placement contract
(post-acquire/pre-halt window, live tier owns it), and the restore-on-timeout
reconciliation (operation timeout via the synchronous teardown; dispatcher reboot
path a deliberate no-op) are settled in ADR 0016 with their rejected alternatives.
