# Architecture Decision Records

Each ADR captures one non-trivial design decision — especially decisions the spec/roadmap leaves open. Format: Status · Context · Decision · Consequences · **Considered & rejected**. Supersede (never delete) an ADR when a decision changes. See `CLAUDE.md` → "Design decisions (ADRs)".

| ADR | Title | Status |
|---|---|---|
| [0001](0001-layer2-layer4-execution-state-gate-split.md) | Layer-2/Layer-4 split for the execution-state gate (ssh-tier admission) | Accepted |
| [0002](0002-stop-controller-execution-authority-is-the-guard-token.md) | Stop-controller execution-event authority is the guard token (a Layer-4 precondition) | Accepted |
| [0003](0003-layer3-backend-attachment-vs-transport-session-ownership.md) | Layer-3 backends return a `BackendAttachment`; Layer 4 owns the `TransportSession` | Accepted |
| [0004](0004-process-identity-is-an-injectable-seam.md) | Process/listener identity is an injectable `ProcessIdentityProbe` seam (`/proc` default) | Accepted |
| [0005](0005-layer4-registry-durability-host-global-json-flock.md) | Layer-4 durable registry: host-global runtime dir, JSON record per `TargetKey`, flock single-instance | Accepted |
| [0006](0006-layer4-unified-cancel-epoch-state-machine.md) | Layer-4 unifies the async-halt cancel/epoch protocol into one modelled state machine | Accepted |
| [0007](0007-local-qemu-target-identity-and-snapshot-producer.md) | local-qemu target identity (`TargetKey`, `generation=BootAttempt.attempt`, `PlatformMetadata`) + boot-to-READY snapshot producer | Accepted |
| [0008](0008-symbols-package.md) | Dedicated `symbols/` package for build_id verification + vmlinux/modules resolution | Accepted |
| [0009](0009-introspect-helper-layer.md) | Introspect helper layer: shared executor, typed-result convention, and `${ARGS_B64}` seam | Accepted |
| [0010](0010-introspect-from-vmcore-execution-model.md) | `debug.introspect.from_vmcore`: run-scoped offline execution, shared wrapper body, shared post-runner finalizer | Accepted |
| [0011](0011-introspect-write-mode-enforcement.md) | `debug.introspect` write mode: policy-gate enforcement + cooperative wrapper write-guard | Accepted |
| [0012](0012-secrets-store-backends-and-redaction.md) | Secrets store backends and global credential redaction | Accepted |
| [0013](0013-session-guard-precondition-teardown-seam.md) | SessionGuard: precondition/teardown seam composing existing primitives + guaranteed-resume invariant | Accepted |
| [0014](0014-ipmi-cipher-suite-policy.md) | IPMI cipher-suite policy: contract-layer enforcement + single chokepoint + CI tripwire | Accepted |
| [0015](0015-stop-capable-guard-revoke-retained-as-contract-primitive.md) | `StopCapableGuard.revoke()` retained as a contract primitive; §5.4 frees the guard by fenced release | Accepted |
| [0016](0016-watchdog-relax-restore-helper.md) | Watchdog relax/restore helper: stateful capture/restore behind the SessionGuard slots, wired inert with a post-acquire placement contract | Accepted |
| [0017](0017-symbol-version-lock-gdb-tier.md) | Symbol version-lock for the gdb tier: a shared build-id primitive verified pre-attach in the handler, not over RSP | Accepted |
| [0018](0018-break-injection-policy-mapping.md) | Break-injection policy: an injectable `BreakPolicy` seam mapping the selected channel's topology + platform facts to a break method | Accepted |
| [0019](0019-debug-gdb-mi-tier-decomposition.md) | `debug.gdb` KGDB/RSP tier: a persistent gdb/MI engine (replacing the batch text-scraper), delivered as a phased sub-issue series | Accepted |
| [0020](0020-gdb-mi-symbol-resolution-mechanism.md) | gdb/MI Phase B symbol resolution: address-of a validated symbol name via `-data-evaluate-expression`, provenance reused from ADR 0017 | Accepted |
| [0021](0021-gdb-mi-phase-c-session-registry-and-execution-state.md) | gdb/MI Phase C: an in-process live-session registry keyed by debug session id + a HALTED-for-the-window execution-state model; batch paths deleted | Accepted |
| [0022](0022-gdb-mi-phase-d-module-symbol-loading.md) | gdb/MI Phase D: module symbol loading via SSH-sourced sysfs section addresses + `add-symbol-file` | Accepted |
| [0023](0023-gdb-mi-phase-d-rsp-stall-detect-and-report.md) | gdb/MI Phase D: RSP stall is detect-and-report with guaranteed resume, not a contained error | Accepted |
| [0024](0024-gdb-mi-phase-d-transport-adaptation.md) | gdb/MI Phase D: break-entry routes off the admitted plan; transport-quality warning for lossy out-of-band consoles | Accepted |
| [0025](0025-gdb-mi-prereq-behavioral-primary-gate.md) | gdb/MI prerequisite: the mi3 `^done` behavioral probe is the primary gate; the version string is advisory | Accepted |
| [0026](0026-postmortem-crash-batch-runner.md) | `debug.postmortem.crash`: host-side pure-Python vmcore build-id reader, per-command output-redirection framing, best-effort raw-passthrough parsers | Accepted |
| [0027](0027-postmortem-triage-composition.md) | `debug.postmortem.triage`: handler-level composition, single up-front build-id gate, per-section partial-failure contract | Accepted |
| [0028](0028-postmortem-check-prereqs-kdump-readiness.md) | `debug.postmortem.check_prereqs`: live-target kdump readiness via the shared SSH probe, proof-only HALTED gate, mechanism-aware checks | Accepted |

**Layer-4 plan amendments (2026-05-27, addressing the `/challenge` review findings):** ADR 0002 amended with the in-process fenced guard token + post-restart `revoke()` soundness (Finding #4); ADR 0005 amended with the `on_partial` `backend_pid` write-through invariant (Finding #1) and the `recovery_required` single-source-of-truth / write-through-cache rule (Finding #5); ADR 0006 amended with the halt→runner cancel-bridge delivery mechanism + RUNNING-step terminalization (Finding #2).
