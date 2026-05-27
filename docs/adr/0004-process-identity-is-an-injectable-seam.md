# ADR 0004 — Process/listener identity is an injectable `ProcessIdentityProbe` seam (`/proc` default), shared with the qemu-gdbstub provider

**Status:** Accepted (2026-05-27) · **Issue:** #10 · **Affects:** Layer 3 (`AgentProxyBackend` reap + listener-identity verification), the existing `providers/qemu_gdbstub.py` controller-identity check

## Context

§6.1 requires two pid-based safety mechanisms in the agent-proxy backend: **reap-safety** — never `SIGKILL` a pid the backend did not spawn, guarded by a **start-time fingerprint** (pid + start-time) so pid reuse cannot cause a foreign kill (§4.7) — and **listener-identity verification** — a returned endpoint's listener must be the spawned child; a *foreign* listener on the intended port is abandoned + reallocated (and **never** killed).

The existing technique, `QemuGdbstubProvider._controller_identity` (qemu_gdbstub.py:1050), reads `/proc/<pid>/stat` field 19 for the start-time — **Linux-only**. The dev/unit-test host is macOS, which has no `/proc`: the start-time is absent and the check degrades to "unverified," which is the root cause of two failing tests (`test_end_session_terminates_recorded_live_controller_pid`, `test_end_session_rejects_live_pid_that_is_not_controller_process` — `alive_unverified` instead of `alive_not_controller`). agent-proxy itself runs **only on Linux**, and the integration tests that spawn it are already tool-gated/skipped without it.

## Decision

- Introduce a small injectable `ProcessIdentityProbe` Protocol: `identity(pid) -> ProcessIdentity | None` (`{pid, start_time, argv0}`, `None` if the pid is gone), `is_alive(pid) -> bool`, and `owns_listener(pid, host, port) -> bool | None` (does `pid` own the LISTEN socket on the **exact** `host:port`; `None` when indeterminable). The production default is a **single `/proc` implementation**, extracted from the existing `_controller_identity` logic so there is **one shared impl, not two diverging copies**. Unit tests inject a fake; the real-agent-proxy integration tests stay Linux/tool-gated.
- **Listener-identity verification differs by transport** (no single RSP-primary rule):
  - **qemu-gdbstub** uses a minimal **RSP-framing reachability probe** (the stub always answers the read-only `?`) — this is a *reachability/aliveness* check, not a listener-ownership check (QEMU owns the stub; we did not race-allocate it).
  - **agent-proxy** must **not** rely on RSP framing (a live kernel is not in kgdb until broken in, so its gdb port stays silent). Its load-bearing signal is **address-specific listener ownership** (`owns_listener(pid, "127.0.0.1", port)` for both ports), and it **fails closed**: ownership must be positively `True`; `False`/`None` rejects, `start` reaps our child and reallocates. A foreign listener is never signalled.
- The **reap-safety** property rests on the start-time fingerprint of the backend's *own spawned pid*, **not** on a listener→pid mapping: live closes use the owned `Popen` (`terminate/wait/kill/wait`), and crash reconciliation uses a stateless `stop_by_identity(pid, start_time)` that signals by pid **only** on a start-time match — so reaping stays safe even where pid-ownership cannot be observed and even after the in-memory handle is lost.
- The **qemu-gdbstub provider is refactored onto the same seam** (constructor injection; default = the `/proc` probe), and the two macOS failures are fixed by injecting a fake that returns a deterministic non-matching start-time (`alive_not_controller` on every OS) — removing the per-OS divergence rather than skipping it.
- **No new runtime dependency** (no `psutil`).

## Consequences

- The unit suite becomes **host-independent** — identical on macOS and Linux — because identity is injected; the production mechanism remains the proven `/proc` one on its only real platform.
- One shared identity implementation behind one Protocol; the qemu provider gains a constructor seam whose default preserves existing Linux behavior and makes the two tests deterministic everywhere.
- macOS gets no *real* process fingerprinting — acceptable, because nothing it would fingerprint (agent-proxy children, gdb controllers) runs on macOS in production.

## Considered & rejected

1. **Keep `/proc`-only; let macOS fail closed and mock ad hoc.** **Rejected:** perpetuates the per-OS behavioral divergence that already produces the two failures, forces inconsistent per-test mocking of `/proc`, and leaves the failures unfixed (skipped, not corrected).
2. **Add `psutil` for portable `create_time()` / `net_connections()`.** **Rejected:** a new runtime dependency is attack surface + maintenance burden (project policy: "justify new dependencies") for **zero production value** — agent-proxy never runs on macOS, so real macOS fingerprinting is unused; `/proc` already works on the deployment platform.
3. **Gate every identity-dependent unit test to Linux (skip on macOS).** **Rejected:** degrades the dev loop (the dev host cannot run them) and skipping is not fixing — the logic stays untested on the dev host and the divergence remains latent.

## References

design §6.1 (reap-safety + listener-identity verification), §4.7 (start-time fingerprint reuse); the existing `_controller_identity` in `src/linux_debug_mcp/providers/qemu_gdbstub.py`; the two failing tests in `tests/test_qemu_gdbstub_provider.py`.
