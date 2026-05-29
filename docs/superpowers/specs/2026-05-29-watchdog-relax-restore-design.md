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
stop and restores their prior values **afterward** — attempted (and the outcome
recorded) on success, error, and timeout, bounded by the session window (§5).

The helper is the first concrete `TeardownStep` (the restore) that hangs off the
`SessionGuard` seam #66 shipped with empty slots, paired with a post-acquire
`relax` call (§3.4). #66 defined **where** watchdog restore hooks in; #69 defines
**what it does** and proves the relax→restore round-trip and the
restore-on-error / restore-on-timeout behavior by seam-level test.

### 1.1 In scope

- A `WatchdogPolicy` helper in a new `seams/watchdog.py`:
  - Architecture variants (`x86_64`, `ppc64le`) selecting an ordered list of
    `WatchdogKnob`s with their relaxed target values.
  - A stateful `relax(ctx)` / `restore(ctx)` pair keyed by `ctx.session_id`:
    `relax` reads-then-captures each knob's current value (once per session) and
    writes the relaxed value; `restore` is idempotent and writes the captured values
    back. `session_id` is the only `SessionGuardContext` field authoritative both
    where `relax` runs (post-acquire) and at teardown (§4.2) — `generation` is a 0
    placeholder at enter and even falls back to 0 at clean-end teardown when the
    record is already gone (`server.py:4845`), so it is unsafe as a key.
  - Execution through an injected `WatchdogControl` channel (`read_knob`/
    `write_knob`), so the mechanism is decoupled from any transport and unit-testable
    with a fake.
- `WatchdogRestoreStep` — a `TeardownStep` (the SessionGuard **exit** slot) that
  calls `policy.restore`, run on the clean-end and attach-error teardown paths.
- `policy.relax(ctx)` — invoked at session setup in the **post-acquire / pre-halt
  window** (§4.2). It is **not** a `pre_attach` precondition: at enter `session_id`
  is `None` and an `open()` failure skips teardown, so the literal enter slot is
  unsafe for relax. The issue's "hook into enter" maps to this post-acquire setup
  point; #69 ships it inert (§1.2) and the live tier invokes it there.
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
| Exit (`TeardownStep`) slot | `seams/guard.py` `SessionGuard` | reused; #69 supplies the restore step (the relax is a post-acquire call, not a slot — §3.4) |
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

State: a `dict[str, CapturedState]` keyed by `ctx.session_id`, guarded by a
`threading.Lock` (the guard handlers can run concurrently for distinct sessions).
`CapturedState` holds, per in-band knob, the value read at relax time and a
`relaxed: bool` recording whether the relax write itself succeeded (a knob whose
relax write failed is **not** restored — there is nothing to put back, and writing
the captured value would be a no-op write of a value we never changed).

**`relax(ctx)`** — **capture-once per session.** If a `CapturedState` already
exists for `ctx.session_id`, `relax` does **not** re-read (re-reading after a prior
relax would capture the already-*relaxed* value as the "prior" value and so destroy
the operator's true baseline — see §4.1); it re-issues the relax writes against the
existing capture and returns. On the first relax for the session, for each knob in
declared order:
- `out_of_band` knob → record `skipped` (reason: no out-of-band channel), continue.
- in-band knob → `read_knob` (capture prior value; `None` ⇒ knob absent ⇒ record
  `absent`, skip the write), then `write_knob(relaxed_value)`; record the
  `WriteOutcome`. Store the captured map under the `session_id` key.

`relax` requires a non-`None` `ctx.session_id` (it runs post-acquire, §4.2); a
`None` session_id is a programming error (relax invoked pre-acquire) and raises
`ValueError` rather than silently keying under a placeholder.

Returns a `RelaxReport` (knob → outcome: `relaxed` / `absent` / `skipped` /
`write_failed`). `relax` never raises; a channel that itself raises is caught and
recorded as `write_failed` for that knob.

**`restore(ctx)`** — look up the captured map for `ctx.session_id`:
- no entry (relax never ran for this session, or restore already ran and cleared
  it) → return an empty `RestoreReport(restored={}, noop=True)`.
- entry present → for each knob that was actually `relaxed` (captured value known
  and the relax write succeeded), in **reverse** declared order, `write_knob(captured
  value)`; record the outcome. Then **delete** the captured map for the session key,
  **unconditionally and regardless of per-knob write outcomes** (so a second restore
  is the no-op above; ADR 0016 rejected-alt 8 — a live tier wanting retry re-runs
  `relax`/`restore`). Knobs recorded `absent`/`skipped`/`write_failed` at relax are
  not restored.

Returns a `RestoreReport`. `restore` never raises (the `TeardownStep` contract); a
write that fails is recorded in the report and surfaces via the adapter into
`TeardownReport.step_errors`.

### 3.4 SessionGuard adapter + relax invocation

Only the **restore** is a `SessionGuard` Protocol adapter, because only the exit
(teardown) slot runs where its key field (`session_id`) is authoritative and a later
run is guaranteed. The **relax** is a direct `policy.relax(ctx)` call the live
integrator places in the post-acquire window (§4.2) — not a `pre_attach`
precondition (where `session_id` is `None` and an `open()` failure skips teardown).

```python
class WatchdogRestoreStep:                # TeardownStep (the SessionGuard exit slot)
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

The restore step and the live relax call share one `WatchdogPolicy` instance (the
captured-state owner) and pass contexts carrying the **same** `session_id`, so the
relax capture and the restore lookup address the same store entry.

## 4. Integration contract (how the live tier wires it)

### 4.1 Idempotency

A `debug.end_session` may be retried, so `SessionGuard.teardown` (and thus
`restore`) may run twice. `restore` is idempotent by construction: the first run
restores and deletes the captured map; the second finds no entry and returns a
`noop` report. `relax` is **capture-once per `session_id`**: a second `relax` for a
session that already has a capture re-issues the relax writes but does **not**
re-read into the capture. This is required for correctness, not just efficiency —
after the first relax the live knob values are the *relaxed* values, so a re-read
would capture (say) `nmi_watchdog=0` as the "prior" value and `restore` would then
write the relaxed value back, **destroying the operator's true baseline**. The
captured baseline survives any number of re-relaxes until a `restore` consumes and
clears it.

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
`transaction.open()` commits (teardown is then guaranteed on every later failure,
and `session_id` is now authoritative for the capture key) and before
`provider.start_session` performs the attach that halts the kernel (the in-band
channel is then still reachable). #66's `SessionGuard` has no slot in that window;
adding one enlarges the #66 seam, so it is deferred to the live KGDB/remote tier
that needs it (ADR 0016 rejected-alt 2). This is also why relax is a direct
`policy.relax(ctx)` call rather than a `pre_attach` precondition (§3.4): the
`pre_attach` slot runs at enter, where `session_id` is `None` and the open-failure
leak above applies.

Because #69 ships the helper **inert** (§1.2), this is a documented contract, not a
live bug: the seam tests call `policy.relax(ctx)` with a **post-acquire-shaped**
context (a real `session_id`, as the live tier produces) and then run
`SessionGuard(teardown_steps=[restore]).teardown(ctx)` with the **same**
`session_id`, exercising the relax→restore round-trip with a fake channel while the
spec/ADR record the **placement** the live tier must honor. The tests do **not**
drive relax through the `pre_attach` slot (that would mis-key under `session_id=None`
and mask the real skew).

### 4.3 What the channel reaches, and when

`relax` runs while the kernel is **running** (pre-halt window) — `read_knob`/
`write_knob` over the in-band channel succeed. `restore` runs in `SessionGuard.
teardown`, which on the **clean-end** path executes after the provider detach has
already resumed the kernel (the channel is reachable). On the **attach-error** path
the kernel may still be parked at the durable `HALTED` record and the actual CPU
state is uncertain; the channel's bounded/cancelable contract (the live `SshRunner`
backing already enforces a per-command timeout) means a restore write against an
unreachable target fails fast and is recorded `write_failed` rather than hanging
teardown. `restore` then **clears the whole capture after this one pass regardless
of per-knob write outcomes** (§3.3) — it does not retain failed knobs for an
auto-retry, so a second `teardown` is a clean `noop`; a live tier that wants
post-resume retry re-runs `relax`/`restore`. This bounded-best-effort behavior is the
same posture `SessionGuard.teardown` already takes for `close`.

## 5. restore-on-error and restore-on-timeout

AC: watchdogs are restored "including on error/timeout." The guarantee #69 makes is
precise and **best-effort, not unconditional**: on every error/timeout exit the
restore is **attempted** and any per-knob failure is **recorded** (into
`TeardownReport.step_errors`), never silently dropped. Actual restoration is
contingent on target reachability — on an error/timeout path the kernel may be
parked/wedged and the in-band channel unreachable (§4.3), in which case the restore
writes fail-fast and are recorded `write_failed`. The real safety property is the
pairing: **relax happens only in the pre-halt window (so the relaxed window is
bounded by the session), and restore is attempted-and-recorded on every synchronous
exit.** The two cases:

- **Error** — a post-`open()` failure (`provider.start_session` raises, or a
  post-attach precondition rejects) drives `teardown(reason="attach_error")`, which
  runs the `WatchdogRestoreStep`: restore is attempted against the (possibly
  unreachable) target and its outcome recorded. Tested both ways at the seam —
  a reachable channel (captured values written back) **and** an unreachable channel
  (writes fail, recorded in `step_errors`, capture still cleared).
- **Timeout** — an interactive-stop / attach **operation** timeout surfaces as a
  `ProviderDebugError` (a timeout `ErrorCategory`) from `provider.start_session`,
  taking the **same** `attach_error` teardown path → restore is attempted. A timeout
  is itself evidence the target may be unreachable, so this is the case most likely
  to record `write_failed`; the contract is attempt-and-record, not guaranteed write.

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
- The post-acquire `relax(ctx)` call records its `RelaxReport`; the live integrator
  must **not** abort the session on a relax failure — a watchdog that could not be
  relaxed is a logged degradation, not a reason to refuse the session (refusing would
  strand the agent with no debug path for a non-safety-critical knob). (A live tier
  that wants a hard refusal on a *specific* critical knob can add its own
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
- **capture-once (baseline preserved across re-relax)**: `relax`, then a second
  `relax` for the **same** `session_id` before any `restore`, then `restore` — assert
  each knob is written back to its **original** captured value (e.g. `1`), not the
  relaxed value (`0`); the second relax re-issued the relax writes but did not
  re-read into the capture.
- **session_id keying / pre-acquire guard**: `relax(ctx)` with `ctx.session_id=None`
  raises `ValueError` (relax was invoked pre-acquire); `relax` and `restore` keyed on
  the same real `session_id` round-trip even though the relax ctx and teardown ctx
  carry different `generation` values (proving the helper does not key on the
  non-authoritative `generation`).
- **restore-on-error (reachable)**: a `SessionGuard` with the restore step + a
  `provider`/step that raises drives `teardown(reason="attach_error")`; with a
  reachable channel assert each captured knob restored and `resume_ok` still holds
  (close still ran).
- **restore-on-error (unreachable channel)**: the same `attach_error` teardown but
  the channel's `write_knob` fails (target wedged/unreachable); assert the failure is
  recorded in `TeardownReport.step_errors`, the capture is still cleared (a retry is
  a clean `noop`), and `resume_ok` still holds — proving the degraded path is handled,
  not that restore magically succeeds.
- **restore-on-timeout**: a `provider.start_session` raising a timeout-category
  `ProviderDebugError` drives the `attach_error` teardown → restore is attempted;
  assert it runs (outcome recorded) on the same path as restore-on-error.
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
- **concurrency**: two distinct `session_id` keys capture/restore independently (no
  cross-talk in the shared store).
- Integration tests touching real ssh/gdb stay env-gated and untouched.

## 8. Open questions

None. The wiring scope (inert, seam-tested), the relax placement contract
(post-acquire/pre-halt window, live tier owns it), and the restore-on-timeout
reconciliation (operation timeout via the synchronous teardown; dispatcher reboot
path a deliberate no-op) are settled in ADR 0016 with their rejected alternatives.
