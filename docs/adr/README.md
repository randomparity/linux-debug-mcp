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
