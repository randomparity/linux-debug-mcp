# ADR 0007 — local-qemu target identity (`TargetKey`, `generation`, `PlatformMetadata`) and the boot-to-READY snapshot producer

**Status:** Accepted (2026-05-27) · **Issue:** #10 · **Affects:** Layer 4 (`coordination/admission.py` snapshot binding, the `open()` transaction), `server.py` (`target_boot_handler`), `seams/target.py` (`publish_ready_snapshot`), `artifacts/manifest.py` (`BootAttempt`)

## Context

Layer 4's `AdmissionService._bind_snapshot` admits a `transport.open` / ssh-tier op only against an authoritative `TargetSnapshot` carrying the target's `generation`, the available `TransportRef`s, and its `PlatformMetadata`. The snapshot is produced by the provisioning layer in the eventual design (issue 08). For the local-qemu-only path that ships in #10 there is **no provisioner** — so without a local producer, `_bind_snapshot` raises `stale_handle` for every request and every Phase B admission gate fails closed (the Finding #3 / HIGH blocker).

Two identity facts are undecided and load-bearing for that producer:

1. **What is a local-qemu `TargetKey`?** `TargetKey = (provisioner, target_id)` is host-wide (ADR 0005). A local-qemu run is identified by its `run_id`, and `target.boot` already serialises per-VM on `target_lock(target_ref)`.
2. **What is a local-qemu `generation`?** Admission uses `generation` as the incarnation fence: a reboot must invalidate a prior-generation `OpenRequest` (`stale_handle`). The manifest already records a monotonic per-run boot counter, `BootAttempt.attempt` (`artifacts/manifest.py:13`), incremented on every (re)boot including `force_reboot`.

## Decision

- **TargetKey.** A local-qemu target is `TargetKey(provisioner="local-qemu", target_id=run_id)`. The `run_id` is the host-wide-unique identity; `provisioner="local-qemu"` distinguishes it from future remote provisioners sharing the host registry.
- **generation = `BootAttempt.attempt`.** The snapshot's `generation` is the current boot attempt's `attempt` counter. A reboot (`force_reboot`, attempt++) yields a higher generation, so a held `OpenRequest` minted against the prior attempt fails the generation fence as `stale_handle` — exactly the incarnation semantics admission expects. No new manifest field is introduced.
- **PlatformMetadata (documented local-qemu defaults).** `console_kind=ConsoleKind.UART`, `console_count=1`, `dedicated_debug_line=False`, `break_hints=[BreakHint.GDBSTUB_NATIVE]`; `ssh_reachable` is derived from whether the run's `RootfsProfile` carries `ssh_host`/`ssh_port` (`config.py:~258`). These describe the fixed shape of the libvirt/QEMU guest the local provider boots.
- **The producer is `target_boot_handler` on boot-to-READY.** When boot reaches `StepStatus.SUCCEEDED`, the handler builds the `TargetKey`, takes `generation = boot_attempt.attempt`, constructs the RSP `TransportRef` from the already-recorded `gdbstub_endpoint` boot detail (`server.py:~1234`), derives the `PlatformMetadata` above, and calls `publish_ready_snapshot(admission, …)` via the `_publish_boot_ready_snapshot` helper (`server.py:~1038`). Provisioning later owns this writer; the local-qemu path ships it now behind the same call.

## Consequences

- Phase B admission gates have an authoritative snapshot to bind against, so `_bind_snapshot` no longer fails closed — the Finding #3 blocker is removed without adding a manifest field or a provisioner.
- The reboot-invalidates-handle invariant is free: it rides the existing boot-attempt counter rather than a parallel generation field that could drift from it.
- The local-qemu `PlatformMetadata` defaults are a single documented source; `transport.open`/`debug.start_session`/`target.run_tests` all read the published snapshot rather than re-deriving platform facts, so B2/B3 reference B0's derivation instead of recomputing it.
- The producer couples `target_boot_handler` to the admission service. That coupling is injected (the handler already takes injectable dependencies), so handler tests pass a fake admission and assert the published snapshot.

## Considered & rejected

1. **A dedicated `generation` field on the manifest (or `TargetSnapshot` persisted under the run).** A first-class incarnation counter, conceptually clean. **Rejected:** it duplicates `BootAttempt.attempt` — every (re)boot already bumps that counter — and creates a second value that must be kept in sync with it on every boot/reboot/force-reboot path. Two counters that must agree are a latent divergence bug; reusing the boot-attempt counter has exactly the semantics admission needs.
2. **Synthesize `generation` from a hash/timestamp of the boot detail.** Avoids a field. **Rejected:** not guaranteed monotonic, so a slower reboot could mint a non-increasing generation and fail to invalidate a stale handle — defeating the fence.
3. **Derive `PlatformMetadata` lazily inside admission from the request.** **Rejected:** admission must bind against *trusted* facts, not request-supplied ones (the endpoint-safety / §8.4 trust boundary). The producer publishing authoritative platform metadata at boot is the trusted source; a request-derived platform would let a caller assert its own capabilities.

## References

design §4.1 (authoritative `TargetSnapshot` + binding), §4.6 (generation as incarnation fence), §8.4 (trusted capability metadata); roadmap Layer 4 (local-qemu-only, no provisioner ships in #10); `artifacts/manifest.py:13` (`BootAttempt.attempt`); `server.py` (`_publish_boot_ready_snapshot` ~1038, `target_boot_handler` ~1080, `gdbstub_endpoint` boot detail ~1234); `seams/target.py` (`PlatformMetadata`, `TargetKey`, `ConsoleKind`, `BreakHint`); `config.py` (`RootfsProfile.ssh_host`/`ssh_port` ~258); [ADR 0005](0005-layer4-registry-durability-host-global-json-flock.md) (host-wide `TargetKey`), [ADR 0003](0003-layer3-backend-attachment-vs-transport-session-ownership.md) (Layer 4 owns the snapshot/session).
