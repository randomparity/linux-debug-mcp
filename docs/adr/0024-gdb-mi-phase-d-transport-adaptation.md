# ADR 0024 — gdb/MI Phase D: break-entry routes off the admitted plan, and a transport-quality warning for lossy out-of-band consoles

**Status:** Accepted (2026-05-29) · **Issue:** #82 (Phase D of #13; epic #9) · **ADR:** consumes [0018](0018-break-injection-policy-mapping.md) (the `BreakPolicy`/`BreakPlan` seam) and the §4.1/§5.6 interface contract · **Affects:** `server.py` (the `debug.interrupt` / break-entry path consults the session's recorded `break_plan`; `debug.start_session` computes and surfaces a transport-quality warning), `tests/test_gdb_mi_serial_kgdb_integration.py` (a new gated serial break/continue test), `docs/debug-gdb.md`.

## Context

Phase C's `debug.interrupt` issues `-exec-interrupt`, which is gdb sending an RSP interrupt packet. That is the correct break-entry **only** over a `gdbstub_native` transport (QEMU gdbstub), where gdb interrupts the stub directly. Over serial KGDB the target is free-running in the kernel and an RSP interrupt cannot reach it; entry into the debugger requires an out-of-band **break** — a UART BREAK, an `agent-proxy` break, or a `sysrq-g` write — chosen by topology. ADR 0018 already decided that choice belongs to an injectable `BreakPolicy` that maps the channel's `line_role` + `PlatformMetadata` to a `BreakMethod`, recorded as `TransportSession.break_plan` at `transaction.open()`. The issue is explicit that "the tier neither chooses nor hardcodes the method."

Two design points are open:

1. **Where the tier consults the admitted plan** so that break-entry uses `-exec-interrupt` for `gdbstub_native` and `transport.inject_break` otherwise — without the tier re-deriving the method.
2. **How to warn** when RSP is riding a lossy out-of-band console (IPMI SOL, HMC vterm) where the protocol may be unreliable, given `ToolResponse` has no `warnings` field.

A third, scoping point: the serial break/continue acceptance needs a producible PTY + `agent-proxy` demux fixture that does not exist yet.

## Decision

### 1. Break-entry routes off the recorded `break_plan.method`; it is never re-derived in the tier.

The break-entry path reads `TransportSession.break_plan.method` (already computed by `BreakPolicy` and persisted at open). `debug.interrupt` flows through `_debug_operation_response`, which loads the `qemu_gdbstub.DebugSession` (carrying `transport_session_id`), **not** the Layer-4 `TransportSession` that holds `break_plan`; so the break-entry path first resolves the `TransportSession` by `transport_session_id` from the `session_registry` to read `break_plan.method`, **defaulting to native `-exec-interrupt` when the record or the plan is absent** (the Phase-C behaviour, so a missing Layer-4 record never blocks an interrupt). The routing is then:

- `GDBSTUB_NATIVE` → the existing engine `interrupt()` (`-exec-interrupt`), unchanged.
- any other method (`UART_BREAK`, `AGENT_PROXY_BREAK`, `SYSRQ_G`) → `transport.break_inject.inject_break(method=..., break_plan=..., proxy=…, ssh_runner=…)`, then `wait_for_stop` for the resulting `*stopped`.

The decision of *which* method is entirely the recorded plan's; the tier only dispatches native-vs-inject on it. `inject_break` itself re-validates that the requested method equals the admitted plan's method, so a tier bug cannot smuggle a different method past the policy. A session whose `break_plan` is absent or `gdbstub_native` keeps Phase-C behaviour exactly.

**Scope of decision 1 in Phase D (the inject-execution seam).** The non-native injection needs the live `proxy`/`proxy_handle` (held inside the serial-local transport's `_proxy_handles`, keyed by backend pid + start-time) and the `ssh_argv_prefix` (derived from the rootfs profile) — **neither is a field on the `TransportSession`** the handler loads. Phase D therefore lands only the *routing decision* (native → `-exec-interrupt`; non-native → inject) as a pure, unit-tested function over `break_plan.method`, plus the `gdbstub_native` execution path that local CI fully covers. The seam that retrieves the live `proxy_handle` + ssh prefix for an already-open session (a `transaction.inject_break_for_session(session_id, requested_method)` lookup that resolves the handle from the owning transport) is **exercised by the gated serial integration test, not local-only CI** — it is named here so the routing decision does not imply the injection plumbing is complete. The router asserts at runtime that a non-native plan reaching a transport with no resolvable proxy handle fails `CONFIGURATION_ERROR` (`code="break_inject_unavailable"`), never silently no-ops the break.

### 2. A transport-quality warning is computed from the recorded topology and surfaced in `data` + `suggested_next_actions`.

`ToolResponse` has no `warnings` field, so `debug.start_session` surfaces a transport-quality warning in `data["transport_quality_warning"]` (a redacted string) and appends `debug.kdb` and `debug.introspect.run` to `suggested_next_actions`. The warning fires when the admitted RSP path rides a **lossy out-of-band console**, keyed on the **session-wide `PlatformMetadata.console_kind`** — `console_kind in {HVC, VIRTIO}` (the hvterm/SOL-style consoles whose BREAK semantics and packet integrity differ from a dedicated UART). It is **not** keyed on the debug channel's `line_role`: a demuxed RSP — exactly the SOL/HMC case the warning exists for — presents its channel as `line_role == RSP`/`DEDICATED_DEBUG`, never `SHARED_CONSOLE` (`_publish_boot_ready_snapshot` records the RSP channel as `LineRole.RSP`; the serial-local demux uses `DEDICATED_DEBUG`), so a `line_role == SHARED_CONSOLE` conjunct would make the warning dead code that never fires for any real RSP-bearing session. The clean QEMU gdbstub path publishes `console_kind == ConsoleKind.UART` (`server.py:1507`) and so emits **no** warning. The predicate is a single pure helper `is_lossy_out_of_band(console_kind) -> bool` so it is unit-testable without a transport, and it composes the same authoritative `PlatformMetadata` fact ADR 0018 already trusts — it never reads a free-text quality hint. A unit test asserts the helper fires on `HVC`/`VIRTIO` and is silent on `UART`, fed from a snapshot-shaped `PlatformMetadata`, not a hand-built channel ref.

### 3. The serial break/continue criterion ships gated, never as a false green.

Per the issue's challenge-review refinement, Phase D takes path (b): a new `tests/test_gdb_mi_serial_kgdb_integration.py` drives an actual RSP break/continue over the serial-local PTY `rsp_endpoint`, gated **exactly** like `test_serial_local_transport_integration.py` (skipped when `agent-proxy`/the PTY fixture is unavailable, requirable with `LDM_REQUIRE_AGENT_PROXY=1`). In local-only CI without the fixture the test is reported **skipped with the missing prerequisite named** — it is never counted as a passing gate. The QEMU-gdbstub criteria (module symbols, RSP-stall, the warning) ship as the unit-testable core and gate CI; the serial criterion holds only when the fixture is present.

## Consequences

- Over a serial KGDB transport the agent's break-entry uses the policy-admitted injection; over QEMU it uses the RSP interrupt — same `debug.interrupt` tool, transport-correct mechanism, no method hardcoded in the tier.
- An agent on a lossy SOL/HMC vterm is told at `start_session` that RSP may be unreliable and is pointed at `debug.kdb` / `debug.introspect` before it invests in a brittle RSP session.
- CI on a local-only runner stays green with the serial test **skipped** and the prerequisite named; the serial criterion is exercised only where `agent-proxy` + the PTY fixture exist.
- The warning predicate and the break-entry router are pure functions over recorded facts, so both are covered by unit tests that need no transport or guest.

## Considered & rejected

- **Hardcode `-exec-interrupt` and add a separate serial-break code path keyed on provider name.** Rejected: it re-derives the break method in the tier (the issue forbids it) and duplicates the `BreakPolicy` mapping ADR 0018 owns. Routing off the recorded `break_plan.method` keeps the policy the single authority.
- **Add a `warnings: list[str]` field to `ToolResponse`.** Rejected for this issue: it changes the wire contract for every tool and every committed response shape; the warning fits the existing `data` + `suggested_next_actions` channel, which is already the agent-facing "what next" surface. (A first-class warnings field is a defensible future cross-cutting change, out of Phase D scope.)
- **Infer transport quality from a free-text `break_hints` / quality string.** Rejected: ADR 0018 already deemed `break_hints` non-authoritative; deriving the warning from `(line_role, console_kind)` reuses the authoritative topology facts and stays consistent with the policy.
- **Build the full serial fixture now (path a) so the serial criterion gates CI unconditionally.** Rejected for Phase D: a self-contained kgdb-over-PTY RSP responder reproducible in local-only CI is a large, fragile build; the issue explicitly permits path (b), and the no-false-green gating keeps the criterion honest without it.
- **Suppress the warning whenever any RSP endpoint is present (trust the transport).** Rejected: a present `rsp_endpoint` over a lossy console is exactly the case the warning exists for; presence of an endpoint is not evidence of link quality.
