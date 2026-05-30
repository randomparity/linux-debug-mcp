# ADR 0023 — gdb/MI Phase D: RSP stall is detect-and-report with guaranteed resume, not a contained error

**Status:** Accepted (2026-05-29) · **Issue:** #82 (Phase D of #13; epic #9) · **ADR:** extends [0021](0021-gdb-mi-phase-c-session-registry-and-execution-state.md) (the guaranteed-resume teardown and the bounded interactive verbs) · **Affects:** `providers/gdb_mi.py` (`set remotetimeout` at attach, a bounded connect retry/backoff, and a distinguishable transport-stall signal on the timeout path), the per-op debug handlers in `server.py` (a stall reaps the session and runs the guaranteed-resume teardown rather than returning a retryable contained error).

## Context

Phase C bounded every interactive verb so a free-running kernel can never hang the tool call: each MI write carries `_MI_COMMAND_TIMEOUT_SEC` and each `*stopped` wait is deadline-bounded. But two robustness gaps remain for transports rougher than the clean QEMU gdbstub:

1. **gdb's own RSP read timeout is unset.** gdb defaults `remotetimeout` to 2s and, on some builds, retries indefinitely on a packet the stub never answers. Over a demuxed serial line the stub can be slow or momentarily silent; without an explicit, generous-but-finite `remotetimeout`, a single sluggish packet either spuriously drops the connection or stalls inside gdb below the MI timeout's visibility.
2. **A transport stall is currently indistinguishable from a benign command error.** When pygdbmi's `write` times out, the engine raises `GdbMiError(DEBUG_ATTACH_FAILURE)` — the same shape as a bad-symbol `^error`. The per-op handler treats a `GdbMiError` as a *contained* failure: it returns the error but **keeps the live session** so the agent can retry or `end_session`. That is correct for a bad symbol; it is wrong for a dead RSP link, where the target may be left HALTED behind a session that will never make progress. Phase D's acceptance is "an induced transport stall is **reported (not hung) and the target is resumed**" — which requires the stall to drive the guaranteed-resume teardown, not sit as a retryable error.

## Decision

### 1. Set `remotetimeout` explicitly at attach, before the RSP connect.

`attach()` issues `-gdb-set remotetimeout <RSP_REMOTE_TIMEOUT_SEC>` (a fixed, generous bound) immediately before `-target-select remote`, so every RSP packet gdb waits on is finite and the wait is owned by gdb (which can report a clean disconnect) rather than blocking opaquely under the MI write timeout. The value is a single module constant, set once.

### 2. Bound the RSP connect with a small retry/backoff for *transient* connect failures only.

`-target-select remote` is retried up to a fixed small count with a fixed backoff when it fails with a **transient** connect error (connection refused / reset — the stub or demux not yet listening). A non-transient failure (bad endpoint, auth, a `^error` that is not a connect race) is **not** retried — it fails immediately. The backoff sleeps are injectable (a `sleep` seam defaulting to `time.sleep`) so unit tests assert the retry count and ordering without wall-clock delay. The retry covers only the connect; it never re-issues a mutating or interactive verb (re-running `-exec-continue` after a partial stall would double-resume).

### 3. A timeout on an established session is a distinguishable transport stall that triggers guaranteed-resume teardown.

The engine's timeout path raises a `GdbMiError` carrying `details={"code": "transport_stall", ...}` and category `INFRASTRUCTURE_FAILURE` (not `DEBUG_ATTACH_FAILURE`), so the handler can tell "the link stalled" from "gdb rejected a command." The per-op handler inspects the raised `GdbMiError`: when its `details["code"] == "transport_stall"`, it **reaps the live attachment, runs `force_resume`, and tears down the transport** — the same guaranteed-resume path a raw (non-`GdbMiError`) fault already triggers — then returns an `INFRASTRUCTURE_FAILURE` report whose `suggested_next_actions` route the agent to `debug.start_session` (re-attach from scratch — never re-sync a stalled RSP, §5.4/§9.3), `debug.kdb`, and `debug.introspect.run`. Every other `GdbMiError` keeps the Phase-C contained-error behaviour (session stays live, agent may retry or `end_session`). The detect-and-report is bounded by the existing MI/interrupt timeouts, so the tool call returns within its ceiling and the target is provably resumed; it never hangs.

## Consequences

- An induced stall (a controller whose `write`/`read` times out mid-session) surfaces as a single `INFRASTRUCTURE_FAILURE` (`transport_stall`) response with the target resumed and the session reaped — re-attach starts clean, matching the "never re-sync RSP" contract.
- A benign command error (bad symbol, bad address) is unchanged: contained, session kept, retryable.
- `remotetimeout` and the connect retry make the clean QEMU path more tolerant of a slow first packet without changing its success behaviour; the retry seam keeps unit tests instant.
- The classification is a property of the engine's raised `GdbMiError.details["code"]`, so it is testable at the handler boundary with a fake controller that raises a stall vs a plain `^error`.

## Considered & rejected

- **Treat every `GdbMiError` timeout as a stall and always tear down.** Rejected: a transient command timeout on an otherwise-live session would needlessly destroy a recoverable session; only a stall on the *link* warrants teardown, and the `code="transport_stall"` marker draws that line.
- **Auto-reconnect/re-sync RSP after a stall and replay the breakpoint ledger.** Rejected by the interface contract (§5.4, §9.3): a stalled or reset link fully invalidates the session; re-syncing risks driving a half-dead stub. Re-attach from scratch is the only sound recovery, so the handler reaps and points the agent at `debug.start_session`.
- **Retry interactive verbs (continue/step) on timeout.** Rejected: `-exec-continue` already resumed the target before the stall; re-issuing it would double-resume or fight the interrupt fallback. Only the idempotent connect is retried.
- **Leave `remotetimeout` at gdb's default.** Rejected: the default is short and build-dependent; over a serial line it produces spurious drops or opaque stalls. An explicit generous-but-finite value makes the wait predictable and gdb-reported.
- **Add a new `TRANSPORT_STALL` `ErrorCategory`.** Rejected: `INFRASTRUCTURE_FAILURE` already denotes "the plumbing failed, not your input"; the `code="transport_stall"` detail gives the specific signal without growing the agent-facing taxonomy.
