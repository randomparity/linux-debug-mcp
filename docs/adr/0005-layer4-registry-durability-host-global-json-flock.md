# ADR 0005 — Layer-4 durable registry: host-global runtime dir, JSON record per `TargetKey`, flock single-instance

**Status:** Accepted (2026-05-27) · **Issue:** #10 · **Affects:** Layer 4 (`coordination/registry.py`, the `open()`/`close()` transaction, reaper + reconciliation), `safety/runtime_locks.py` (new registry-dir resolver)

## Context

Layer 4 makes target ownership **durable** so the §10.2 crash-recovery invariants hold: a write-ahead ownership record must be found after a restart, a halted-target `recovery_required` tombstone must survive two restarts, an orphaned backend must be reaped *before* admission reopens, and a second server instance must fail loud rather than admit alongside the first. Layer 2's `AdmissionService` keeps this state **in memory only** (`_bindings`, `_closed_at`, `_recovery_required`, `_exec_epoch`); nothing of it survives a crash. Layer 4 must add the durable backing.

Three things are undecided and load-bearing:

1. **Location.** The single-stop-capable-holder guarantee and "second server fails loud" are **target-wide / host-wide** (`TargetKey = (provisioner, target_id)`, never `target_id` alone). The store therefore cannot be scoped to one artifact root — two server processes pointed at different `--artifact-root`s would not see each other's holders, silently breaking the host-wide single-holder.
2. **Format.** The record set is a small number of independent per-`TargetKey` records read/written one at a time, with the open() transaction needing **labeled crash points** between stages so a test seam can stop the write sequence at each and assert reconciliation. The repo already persists every durable artifact (`manifest.json`, gdbstub `DebugSession` JSON) as JSON written with atomic replace.
3. **Single-instance interlock.** The host-global serial-source lock and the existing `private_runtime_lock_dir` (`$XDG_RUNTIME_DIR/linux-debug-mcp/locks`, uid-isolated, `0700`, symlink/owner-validated — see `safety/runtime_locks.py`) already establish the host-global, uid-private runtime-dir precedent.

## Decision

- **Location — host-global runtime dir.** The durable registry lives in a new `registry/` sibling of the existing `locks/` dir, resolved by a new `private_runtime_registry_dir()` in `safety/runtime_locks.py` that reuses the same `_ensure_private` symlink/owner/`0700` validation. Default `$XDG_RUNTIME_DIR/linux-debug-mcp/registry/`, with the same `<tmp>/linux-debug-mcp-<uid>/registry` fallback as the lock dir. It is **not** under `--artifact-root`.
- **Format — one JSON file per `TargetKey`.** Ownership record `<provisioner>__<target_id>.json` and recovery tombstone `<provisioner>__<target_id>.tomb`, the `TargetKey` components hashed to a single safe path segment exactly as `device_lock_filename` already does (namespaced prefixes `owner-`/`tomb-` so they never collide with each other or with device locks). Every write is **write-tmp-then-`os.replace`** (atomic on the same filesystem); a record is `fsync`'d before the rename at each write-ahead stage. No SQLite, no shared DB.
- **Single-instance — flock.** A single `instance.lock` in the registry dir is held with a non-blocking `flock(LOCK_EX)` for the server's lifetime; a second instance that cannot acquire it **fails loud at startup** (maps to `INFRASTRUCTURE_FAILURE`), it does not wait.
- **Crash points are labeled stages.** The open()/close() write sequence is expressed as named stages (e.g. `record_written`, `guard_token_recorded`, `lease_token_recorded`, `promoted`), each its own atomic write, so an injected crash-point seam can stop after any stage and the reconciler is tested against every prefix.
- **Reconciliation on startup, before admission opens.** After acquiring `instance.lock`, the reaper scans `registry/`, reaps live orphans (via the Layer-3 start-time-fingerprinted `ProcessIdentityProbe`, ADR 0004 — never signalling a foreign pid), releases or tombstones stale records, and only then does `AdmissionService` accept its first admit. In-memory admission state is rebuilt from the durable records; the runtime execution epoch is a process-local fence reset on restart (the durable `execution_state` — `HALTED`/`unknown` — is what reconciliation reads, not the epoch counter).

## Consequences

- The host-wide single-holder and "second server fails loud" guarantees are **structural**: both the flock and every record key on the full `TargetKey` in a path that does not depend on the artifact root, so two servers with different roots still contend on the same `instance.lock` and see the same ownership files.
- The crash-point test seam is cheap: "restart" in a unit test is re-instantiating the registry against the same temp dir, and each write-ahead prefix is a real on-disk state. No process kill or DB recovery needed.
- Reusing `_ensure_private` means the registry inherits the audited symlink/owner/`0700` protections with no new safety surface; the only new code in `runtime_locks.py` is the leaf-name resolver.
- Records live in a tmpfs-backed `$XDG_RUNTIME_DIR` that is cleared on logout/reboot. That is **correct** for this state: a reboot destroys the QEMU domains and agent-proxy processes the records point at, so a stale post-reboot record would be meaningless. Durability is required across a *server restart within a session*, not across a host reboot.

## Considered & rejected

1. **Artifact-root-scoped store (`.linux-debug-mcp/registry/`).** Co-located with `runs/`, trivially inspectable, cleaned with the run tree. **Rejected:** ties the target-wide single-holder and crash-recovery to one artifact root, while `TargetKey` is host-scoped — two servers with different roots would each admit a stop-capable holder for the same target, and the "second server fails loud" flock would only fence within a root. A semantic mismatch with the contract's host-wide `TargetKey`.
2. **SQLite (WAL) at a host-global path.** ACID multi-row updates for free, one file. **Rejected:** adds a dependency and an idiom the repo does not use (all durable state today is JSON + atomic replace + flock); the write-ahead **crash-point** model — the thing the §10.2 rollback tests exercise at every stage — is harder to express and inject against a transactional DB than against labeled per-stage file writes; and the per-`TargetKey` records are independent, so cross-row transactions buy nothing here.
3. **Persist the execution epoch counter durably.** Would let a post-restart op match a pre-restart `ExecutionProof`. **Rejected:** the epoch is a *liveness* fence against stale in-process proofs, not a fact about the target; after a restart there are no in-flight proofs to fence, and the durable fact that matters (`HALTED`/`unknown`) is read from the ownership record by reconciliation, which is what gates recovery.

## References

design §4.3 (write-ahead transaction steps), §4.5 (lifecycle close ordering), §4.6 (execution state durability), §4.7 (durable ownership record + `recovery_required`), §9.1/§10.2 (crash-recovery conformance); roadmap Layer 4 row (`coordination/registry.py` = registry + reaper + reconciliation + tombstones + flock); `safety/runtime_locks.py` (`private_runtime_lock_dir`, `device_lock_filename`, `_ensure_private`); [ADR 0004](0004-process-identity-is-an-injectable-seam.md) (start-time-fingerprinted reap used by reconciliation).
