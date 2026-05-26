# Transport provider abstraction — implementation roadmap

> **For agentic workers:** This is the *index* for a layered implementation of
> `docs/superpowers/specs/2026-05-26-transport-abstraction-design.md` (issue #10).
> It is not itself an executable plan — each layer below has (or will have) its own
> bite-sized plan document. Execute layers in order; each produces working, tested
> software and a reviewable PR on its own.

**Spec:** `docs/superpowers/specs/2026-05-26-transport-abstraction-design.md`
**Contract:** `docs/specs/interface-contracts.md` (settled; #10 implements 01's side)
**Branch:** `issue-10-transport-abstraction`
**Scope decision:** ship `transport.open` **with** the full §10.2 invariant set
(crash-recovery, execution-state, endpoint-safety). No fallback split.

---

## Why layered, and the one rule that orders the layers

The spec's §2 package layout already names the seam: `transport/` (01 core),
`coordination/` (01 cross-cutting), `seams/` (Protocols + minimal impls for
externally-owned pieces). The dependency arrows run strictly one way, so the layers
below are a topological sort of that graph. **Layer N may import only from layers
1..N-1 and existing code.** If a task in layer N needs a symbol that doesn't exist
yet, that symbol belongs in an earlier layer — fix the layering, don't forward-declare.

The single load-bearing principle that makes the split safe: **the durable
ownership record + admission service are the only authorities for "who owns this
target," and no *MCP-mediated* path may halt a kernel or return a live endpoint outside
an admitted session.** (A local out-of-band process connecting *directly* to a returned
loopback RSP endpoint and halting the kernel is the explicitly-documented spec §8.4
residual under the single-user local-dev threat model — not a supported control path;
see the endpoint-safety note below for exactly what the gate does and does not promise.) Lower layers define and test that authority in isolation; Layer 4 wires it
to real processes **and is where every §10.2 blocking invariant — crash-recovery,
execution-state gating, *and* endpoint-safety — must be green together**. The public
endpoint-returning, halting, recovery, and startup-validation paths (`transport.open`/
`close`, the migrated `debug.start_session`) therefore **ship in Layer 4**; Layer 5 adds
only the **observational** wrappers (`transport.status`/`health`) and `providers.list`
— the destructive `transport.inject_break` wrapper ships in Layer 4 with the other
halting paths. Two corollaries that the §10.2 merge bar forces (and that earlier
drafts of this roadmap got wrong):

- **Halting the kernel is a Layer-4 capability, not a Layer-3 one.** Layer 3 builds the
  `send_break` *mechanism* but exercises it only against fakes/PTY; the path that
  actually drops a real kernel into the debugger ships only once it runs inside an
  admitted stop session that holds the `StopCapableGuard` and has written durable
  execution state — otherwise a crash mid-break strands a halted kernel with no
  recovery marker. **This includes the *existing public* `debug.start_session` tool**,
  which already halts via the qemu gdbstub provider: it is migrated onto the `open()`
  transaction **in Layer 4** (not Layer 5), so a Layer-4 merge leaves **no** legacy
  ungated public halt path. If that migration slipped to Layer 5, a Layer-4 build would
  still let the old tool attach/halt/read without the durable record, `StopCapableGuard`,
  or recovery marker — silently invalidating the "§10.2 green at Layer 4" claim and
  blinding `target.run_tests`' halted-state gate to a halt taken through the old path.
- **Returning a live endpoint is a Layer-4 capability too.** The endpoint-safety gate
  (`endpoint_unsafe` default-deny, permissioned console) is enforced in Layer 4 — the
  `brokered_required` refusal happens **in admission, before any guard/lease/secret/
  attach** (it is a registry-metadata decision, not a post-attach discovery), with a
  return-path assertion that the bound address is loopback. So a known-unsafe request
  never transiently seizes a remote console or touches credentials.
- **Creating a `recovery_required` state implies shipping its clearance.** Because Layer 4
  migrates the public `debug.start_session` halt path and can therefore write a
  `recovery_required` tombstone on a crash or close-while-halted, Layer 4 **also** ships
  the agent-accessible recovery-clearance path (a `recovery=true` attach via the migrated
  debug tool or a minimal `transport.open(recovery=true)`/`close`). Otherwise a
  crashed-while-halted target is stuck: the probe clearance can't pass *because* the
  kernel is halted, and `reset` destroys the debug session — leaving no way to recover
  the parked kernel. No public path may create a halted/`recovery_required` state without
  a same-layer public path to clear it.

**Endpoint-safety: what the gate does and does NOT promise (spec §8.4).** The gate's
*hard* guarantees are: (1) a `brokered_required` (every remote/out-of-band) transport
can **never** return a raw TCP RSP — it must provide a brokered/`UnixSocketEndpoint`,
default-deny; (2) a `loopback_local` transport binds **loopback only** and its
listener identity is verified; (3) a permissioned `UnixSocketEndpoint` console enforces
access via mode-`0600` OS perms. What the gate **does not** promise: that a raw loopback
TCP RSP (qemu-gdbstub) is immune to a *hostile local process*. `127.0.0.1` is a
reachability boundary, not an access-control boundary, so another local uid/process can
in principle connect to the returned RSP and halt the kernel out-of-band. This is the
spec's **explicitly accepted residual for the single-user local-dev threat model**, and
it is bounded, not ignored: an out-of-band halt is **out of contract** and the
stop-capable controller records `execution_state=unknown` the moment it observes the
unexpected halt (§4.6 raw-endpoint caveat), so it can never masquerade as `EXECUTING`;
the multi-tenant fix is the **#08 brokered/tokenized endpoint**, shaped as an
endpoint-construction swap (replace `TcpEndpoint` in the `Endpoint` union), not a
contract change. So "endpoint-safety green at Layer 4" means *this gate + this caveat* —
**not** "raw loopback RSP is hardened against a local adversary." A reviewer must judge
the design against the single-user threat model it actually targets.

---

## Layer map

| # | Layer | New modules | Depends on | Produces (testable) | Plan doc |
|---|-------|-------------|------------|---------------------|----------|
| 1 | **Foundations** — pure data model + pure-function seams + taxonomy/gating | `seams/target.py`, `transport/base.py` (schemas only), `seams/secrets.py`, `seams/break_policy.py`; edits to `domain.py`, `config.py` | existing code | Pydantic wire schemas; `SecretsResolver` **Protocol** + an **env-only** minimal backend + a test fake (file/keyring/external are #08-owned — see the secrets-source invariant below); `BreakPolicy` topology+disproof decision (probes injected); two new `ErrorCategory` values; `TRANSPORT_OPERATIONS` allowlist | `…-layer-1-foundations.md` (written) |
| 2 | **Coordination primitives** — concurrency + admission | `coordination/lease.py`, `seams/guard.py`, `seams/lifecycle.py`, `coordination/admission.py` (SnapshotStore + admit/admit_recovery), `coordination/selection.py` | 1 | `ConsoleLease` CAS; the `StopCapableGuard`/`SessionGuard` **Protocol + a minimal in-process fenced-token impl** (the seam #08 later swaps — see the seam-ownership invariant below); `LifecycleDispatcher` awaited+bounded; `SnapshotStore`; admission freshness/snapshot-rebind/state-gate/near-expiry; break-plan-aware selection | TBD after L1 review |
| 3 | **Backends & transports** — bytes on the wire | `transport/proxy.py`, `transport/serial_local.py`, `transport/qemu_gdbstub.py`, `transport/break_inject.py`; edit `prereqs/checks.py` | 1 | `ProxyBackend`/`AgentProxyBackend` (argv, `-s003`, race-minimized ports + **listener identity verification that only ever signals the session's own start-time-fingerprinted child — a foreign listener is never killed, the attach is abandoned and ports reallocated**, cancellation-aware `start`/`on_partial`, start-time-fingerprinted reap); `serial-local` (incl. the mode-`0600` unix-socket console it *constructs*) and the qemu-gdbstub adapter (rsp passthrough) — both returning **internal, non-exported** session handles consumed only by Layer 3's in-process white-box tests and (later) Layer 4's transaction, never a caller-facing surface or MCP tool; the `inject_break` **executable primitive** (`send_break` mechanism), unit-tested against fakes — **no end-to-end kernel halt**, which is gated behind Layer 4's admitted session; agent-proxy prereq | TBD |
| 4 | **`open()` transaction + registry + recovery + endpoint-safety + ssh-tier gating** — the heart | `coordination/registry.py` (registry + reaper + reconciliation + tombstones + flock locks), the `open()`/`close()` transactions, the **endpoint-safety gate** (a **pre-attach admission refusal** of `brokered_required` exposure — decided from trusted registry metadata **before** any guard, lease, secret resolution, or provider attach — plus a return-path assertion that the bound address is actually loopback), execution-state gate, `seams/lifecycle.py` invalidation wiring, `seams/target.py` local-qemu SnapshotStore adapter, **edits to `server.py`** to route the **one** genuinely ssh-backed live handler — `target.run_tests` (local-ssh-tests) — through `admit()` + the execution-state gate **on the live-execution path** (a fresh or forced run that would actually drive ssh against the target), with a **cancellable live-op handle propagated into `LocalSshTestProvider`/`SshRunner`** so an in-flight `subprocess` is **killed** on halt rather than blocking under the tests lock until its timeout. A **terminal cached `SUCCEEDED`/`FAILED`** return stays a pure, ungated manifest read — retrievable even while `HALTED` (no compatibility regression, no live work, no hang); a cached **`RUNNING`** record encountered while `HALTED` is **cancelled/terminalized** (the admitted live-op record is closed and that state returned) rather than served as stale-running or left to hang. Plus a reusable ssh-live admission seam for the future `debug.introspect` tier; the existing **gdbstub `debug.*` reads stay under the stop-capable session model, NOT ssh-`EXECUTING` gating** (gdb reads registers/memory precisely while `HALTED`); **and the rewire of the existing public `debug.start_session` + its gdbstub `debug.*` stop-capable handlers onto the `open()` transaction** (so they acquire the `StopCapableGuard`, write durable execution state before any halt, and are crash-recoverable) — closing the legacy ungated public halt path **inside** Layer 4, not Layer 5; the public `transport.open`/`transport.close` wrappers; `create_app` endpoint-exposure + capability startup validation; and a legacy-`DebugSession` fence | 1,2,3 | the **full §10.2 invariant set**: write-ahead crash points, reconciliation, orphan reap, `recovery_required` gate + 3 clearance paths, generation idempotency, two-restart durability, abandoned-attach epoch fence, execution-state gate (incl. the **real** `target.run_tests` handler rejected while `HALTED` + in-flight cancel, with gdbstub `debug.*` reads explicitly exempt), close-while-halted, **endpoint-safety gate** (`loopback_local`→`TcpEndpoint`, `brokered_required`→`endpoint_unsafe`, permissioned-console refusal), redaction of console/transcript into the durable record, and **guarded** `inject_break` end-to-end (kernel halt only inside an admitted stop session); **plus the named public `transport.open` + `transport.close` + `transport.inject_break` wrappers, shipped in this same layer** (these `transport.*` tools land in Layer 4 — not Layer 5 — because they are the endpoint-returning, recovery, and halting surface): `transport.open(recovery=true)` routed through `admit_recovery` is the agent-accessible clearance, so no public path creates a `recovery_required` tombstone without a same-layer public path to clear it; the public `transport.inject_break` wrapper ships here because it halts the kernel, and its tests prove it enforces destructive-permission gating, write-ahead `HALTED`/`unknown` persistence **before** the break, timeout→`unknown` recovery, and no stale `EXECUTING` on crash; **the `create_app` endpoint-exposure + capability startup validation** (reject a remote family declaring `loopback_local` / an under-capable provisioner) lands here too, since Layer 4 is where the first public endpoint-returning paths appear; **and a legacy-session fence** — any pre-transport persisted gdbstub `DebugSession` lacking a bound transport-ownership record is refused on load (force-ended only after proving `EXECUTING`, else converted to a `recovery_required` tombstone), so an old session can never bypass the durable halt/recovery model | TBD |
| 5 | **Auxiliary tool surface, discovery, docs** | `server.py` (`transport.status`/`health` wrappers + handlers; `providers.list` merge), response-boundary redaction, `docs/transport-providers.md` | 1,2,3,4 | the **observational** `transport.status`/`health` MCP wrappers only (every endpoint-returning, halting — incl. `transport.inject_break` — recovery, and startup-validation path is **already shipped/enforced in Layer 4**); `providers.list` shows transports with capability flags; `secret_refs` never surfaced at the response boundary; qemu-gdbstub flow unchanged end-to-end | TBD |

---

## Conformance-test → layer mapping

The merge bar is spec §10.2 + contract §8. Each lands in the layer that owns the
mechanism it exercises. A test may be *written* against a fake in an earlier layer
and *re-run* end-to-end later; the row below is where it first becomes green.

**Layer 1**
- `extra="forbid"` rejection across every new schema; `Endpoint` discriminated-union
  parse/serialize; `OpenRequest` **requires** its `transport_ref` (admission needs the
  selected channel to re-bind/validate) and carries an `int` `generation` fence, and
  adds **no** `recovery` field — recovery is a `transport.open` tool arg, not a wire
  field (§3.2). (Admission-time rejection of a current-generation but foreign/edited
  `transport_ref` is a **Layer 2** conformance — see below.)
- `secret_refs` resolution is **env-only** in #10; `file`/`external` refs raise
  "deferred to #08" rather than being resolved, and resolved env values are **never**
  surfaced in output/logs nor persisted (§8, §9.1). The `SecretsResolver` Protocol +
  a test fake let transports be tested without #10 owning any credential storage — see
  the secrets-source invariant below.
- Break-plan policy: `line_role` determines `uart_break` vs `agent_proxy_break`;
  single shared-console + `ssh_reachable=false` + `supports_uart_break` **admits**
  `agent_proxy_break`; `no_break_plan` only when no topology predicate holds;
  `break_disproved` only when every topology candidate is positively disproved
  (probe results injected) (§4.1, §4.8).
- `TRANSPORT_OPERATIONS` allowlist gating; `inject_break` carries destructive perms (§7.3).

**Layer 2**
- Console-lease CAS race → exactly one `lease_conflict`; idempotent release;
  stale-token release no-op post-revoke (contract §8; spec §9.1).
- `StopCapableGuard` target-wide single-holder (gdb-on-RSP + kdb-on-console refused).
- Admission: freshness reject; snapshot re-binding (foreign/edited ref reject; stale
  `expires_at` reject **before** any acquisition); state gate; near-expiry reject.
- Selection: skip caps-sufficient-but-unbreakable channel, pick breakable; `transports[]`
  order authoritative; cross-provisioner isolation by `TargetKey`.
- `LifecycleDispatcher` awaited delivery bounded by `teardown_deadline`; force-reap
  still completes the transition; aggregates per-subscriber errors.

**Layer 3**
- Port identity verification: the backend **only signals processes it spawned**
  (start-time-fingerprinted child). When the intended port is occupied by a listener
  the backend did **not** spawn, that foreign listener is **never killed** — the
  backend abandons that attach attempt and reallocates on fresh ports, and the foreign
  port is never returned as a healthy endpoint. The conformance test proves an
  unrelated local listener occupying the port is **not** signaled and the attach
  retries elsewhere (§6.1). (A mismatched listener that *is* the backend's own child —
  e.g. it bound the wrong port — is reaped via the start-time fingerprint; pid reuse
  cannot cause a foreign kill.)
- Cancellable attach: `start` that never returns is force-reaped under
  `teardown_deadline`; registered partial pid/sockets killed; rolls back leaking nothing.
- Pre-`on_partial` hang abandoned at deadline; recovery not blocked behind stuck worker.
- agent-proxy reaped on close/shutdown (no orphans / port leaks).
- **Integration (gated, white-box / in-process):** the PTY-backed serial-local backend
  and the qemu-gdbstub adapter produce a `console_endpoint`/`rsp_endpoint` that the
  **test itself** connects to on loopback, asserts, and reaps within the test — they are
  **not** returned to any agent, persisted as an owned session, or exposed via an MCP
  tool (no public/MCP `transport.open` exists until Layer 4). No real kernel is
  attached, so there is nothing to halt; the `send_break` mechanism is exercised against
  the PTY/fake only. The consumer-facing `TransportSession` return — with durable
  ownership, `StopCapableGuard`, recovery marker, and the endpoint-safety gate — is
  **Layer 4**, where the end-to-end "`inject_break` drops a kgdb target into the
  debugger" test also lives.

**Layer 4** (the §10.2 keystone set)
- `open()` transaction rolls back at **every** step incl. write-ahead crash points,
  leaking no process/socket/fd/lease/guard/binding/record.
- Lifecycle invalidation cancels pending **and** promoted bindings; kexec full
  invalidation / no re-sync; `stale_handle` replay after generation bump.
- Crash recovery: write-ahead record found + released; live orphan reaped **before**
  admission opens; second server instance fails loud on `flock`.
- Halted-target `recovery_required` gate + its **three** clearance paths
  (probe→`EXECUTING`, `reset` advancing generation, `recovery=true` attach);
  two-restart durability; tombstone generation idempotency (fail-closed at bare startup).
- Abandoned-attach epoch fence + reconciliation.
- Execution-state gate: ssh-op-while-`HALTED` rejected; permitted while `EXECUTING`;
  async halt cancels in-flight ssh op; stale-`EXECUTING` → `probe_timeout`;
  failed `inject_break` → `unknown`; and an **out-of-band halt** taken via a
  directly-connected loopback RSP is recorded as `execution_state=unknown` when the
  controller next observes it — never silently left as `EXECUTING` (§4.6 raw-endpoint
  caveat; this is the mitigation for the §8.4 residual). **The one existing ssh-tier handler,
  `target.run_tests`, is exercised for real** (not a fake): routed through `admit()` it
  is rejected while `HALTED` and an admitted-then-halted run is cancelled, not hung; a
  reusable ssh-live admission seam is in place for the future `debug.introspect` tier.
  Three cases are covered by tests: (a) a fresh/forced `target.run_tests` that would
  drive ssh is rejected while `HALTED`; (b) a **terminal cached `SUCCEEDED`/`FAILED`**
  is still returned while `HALTED` — a pure manifest read, not a regression and not a
  hang; (c) a cached **`RUNNING`** under a now-`HALTED` target is cancelled/terminalized
  rather than served stale, and an in-flight admitted ssh `subprocess` is **killed** on
  halt, not left to time out holding the tests lock. (The gate is on *live SSH work*,
  not on manifest reads.)
  **Existing gdbstub `debug.*` register/memory reads are explicitly NOT ssh-`EXECUTING`
  gated** — they execute while the kernel is `HALTED` by design and remain governed by
  the stop-capable session / `StopCapableGuard`, not the ssh gate. (This corrects the
  spec §1.3 decision-7 wording, which loosely grouped "the current debug reads" with
  ssh ops; in this repo those reads are RSP/gdbstub, not ssh.)
- Close-while-halted: tombstone-then-revoke, never releases into false-`EXECUTING`.
- **Endpoint-safety *runtime* gate (moved here from a later layer — it is a §10.2
  blocking invariant):** at the `open()` return path, a `loopback_local` channel
  returns a `TcpEndpoint`; a `brokered_required` (remote) channel's RSP/stop-capable
  open is refused `endpoint_unsafe`; a permissioned `UnixSocketEndpoint` console refuses
  an unauthorized connect (§3.2, §8.4). The `brokered_required` refusal is a **pre-attach
  admission** decision: a conformance test asserts an `endpoint_unsafe` request leaves
  **no provider start, no secret resolution, and no acquired guard/lease** (it never
  reaches attach). The return path additionally asserts the bound address is loopback.
  The guarantee is **scoped per the endpoint-safety note above** — default-deny for
  remote families, loopback-only + identity-verified for local; the raw-loopback-RSP
  residual is the documented single-user-threat-model limitation, covered by the
  `execution_state=unknown` caveat, **not** a claim of hardening against a local adversary.
  (The *startup* structural check — rejecting a misconfigured registry where a remote
  family declares `loopback_local`, or an under-capable provisioner — is wired at
  `create_app` in **Layer 4**, the same layer that ships the first public
  endpoint-returning paths (`transport.open`/`close`, the migrated `debug.start_session`).
  It is belt-and-suspenders over the pre-attach admission refusal and has nothing to
  reject until remote transports exist, but it ships **with** the paths that can return
  endpoints — not a layer later.)
- Redaction of console/gdb-transcript content into the durable session record and any
  persisted snippet; raw captures stay on disk as `ArtifactRef(sensitive=True)` (§8.2).
- **Guarded end-to-end break (gated integration) + the public `transport.inject_break`
  wrapper:** `inject_break` drops a kgdb target into the debugger **only** inside an
  admitted stop session that holds the `StopCapableGuard` and has written durable
  execution state first (§4.6, §7.1). The public wrapper's own tests prove it enforces
  the `transport.inject_break` destructive-permission gate, writes `HALTED` (or
  `unknown` for an unconfirmable break) **before** issuing the break, recovers a
  mid-break timeout to `execution_state=unknown` (never stale `EXECUTING`), and leaves a
  reconcilable durable record on a crash mid-break.
- **No legacy ungated halt path after Layer 4:** the existing public `debug.start_session`
  flow is migrated onto the `open()` transaction — it acquires the same admitted stop
  session/`StopCapableGuard`, writes execution state **before** the halt, is found and
  cleared by crash reconciliation after a restart, and a halt taken through it makes
  `target.run_tests` reject while `HALTED` (so the old path cannot bypass the authority
  model). Conformance proves no public tool can halt the kernel outside an admitted,
  durable, recoverable session (spec §7.1).
- **Agent-recoverable after a crash-while-halted:** a simulated crash (or close-while-
  halted) that leaves a `recovery_required` tombstone is **clearable by an agent within
  this layer** — an ordinary open is rejected `recovery_required`, but the same-layer
  public `transport.open(recovery=true)` (routed through `admit_recovery`) is admitted,
  resumes/detaches, and clears the key; the agent is never left with only `reset` (which
  destroys the session) or a probe that cannot pass while halted (§4.7, §7.1).
- **Version-skew fence for pre-transport debug sessions:** a fixture with a pre-Layer-4
  persisted gdbstub `DebugSession` (raw `gdbstub_endpoint`, no transport-ownership
  record / generation / `StopCapableGuard` token) is **not** silently resumed after
  upgrade — the migrated `debug.*` handler refuses it, force-ends it only after proving
  `EXECUTING`, or converts it to a `recovery_required` tombstone — so an old session
  cannot bypass the durable model or leave `target.run_tests` blind to a kernel an old
  session already halted.

**Layer 5**
- The **observational** `transport.status`/`health` MCP wrappers behave as thin
  pass-throughs over the Layer-4-enforced transaction; `secret_refs` never surfaced at
  the response boundary. (The destructive `transport.inject_break` wrapper and its
  write-ahead/permission/timeout conformance ship in **Layer 4** with the halting paths.)
- `providers.list` shows transports with capability flags. (The endpoint-exposure +
  capability **startup** validation already shipped at `create_app` in Layer 4, with the
  first public endpoint-returning paths — it is not deferred here.)
- Existing local QEMU gdbstub debug flow passes **unchanged** on the new interface.

---

## Suggested PR boundaries

**Layer 0 — baseline doc-guard cleanup (prerequisite, before Layer 1).** `just
check-docs` currently exits non-zero on the **pre-existing committed docs** (other
planning artifacts under `docs/superpowers/` predate this work and contain the legacy
iteration-label word). The per-layer "leave `just check-docs` green" gate below is
therefore unattainable from today's baseline. Land a small cleanup PR first that scrubs
the forbidden term from the existing tracked docs (or otherwise makes the guard pass)
so the baseline is green; only then does the per-layer gate become a real, keepable
bar. This roadmap and the Layer 1 plan are already clear of the term (verified), so the
cleanup is confined to the other pre-existing docs.

One PR per layer thereafter, in order. Each PR must leave `just test` + `just lint` +
`just check-docs` green and add no new ruff warnings. Layers 1–2 are pure/no-tool
and fully unit-tested in CI; Layer 3 adds tool-gated integration tests (skipped
without `agent-proxy`/`gdb`/`virsh`); Layers 4–5 are unit-tested with injected
fakes plus the gated integration re-runs.

**Do not** return a live endpoint, halt a kernel, or advertise stop-capable debug
until **all** of Layer 4's invariants — crash-recovery, execution-state gating, *and*
endpoint-safety — are green together. That combined set is the §10.2 merge bar, and the
public paths that can return an endpoint, halt the kernel, or clear a `recovery_required`
state ship in Layer 4 alongside it; Layer 5 adds only the auxiliary observational
wrappers + `providers.list`. Layer 3 may merge its backends and the `send_break`
mechanism, but the path that actually drops a real kernel into the debugger is part of
the Layer 4 gate, not Layer 3.

---

## Cross-cutting invariants every layer must honor

These are not a layer; they are constraints checked in review of *each* PR.

- **Contract shapes are frozen.** No field is ever added to the settled-contract
  `TransportRef` or `OpenRequest` (spec §3.2). `endpoint_exposure` lives on the
  01-owned `TransportCapability`; `recovery` is a `transport.open` tool arg routing
  to the 01-internal `admit_recovery`, never a wire field.
- **`TargetKey` everywhere.** Every lease, guard, subscription, event, binding, and
  tombstone keys on the full `(provisioner, target_id)` tuple, never `target_id` alone.
- **Credential sources are #08-owned; #10 consumes an injected interface.** #10 ships
  only the `SecretsResolver` **Protocol**, an **env-only** minimal backend, and a test
  fake — it does **not** create a file/keyring/external credential source. `file` and
  `external` refs raise "deferred to #08" rather than reading anything; resolved env
  values are never persisted to session JSON, the manifest, logs, or tool output
  (leak-tested). This keeps the credential boundary where the ownership map puts it
  ("Secret resolution — Hardening (08)") and honors the #08 rule "sources are env /
  external store / OS keyring — never repo files": #10 reads no files at all. **This is
  a deliberate, flagged deviation from spec §3.4**, which lists "env + file" for the
  minimal resolver; the #08 hardening doc (the credential-policy owner) forbids repo
  files, so the env-only choice is the security-conservative reconciliation. #08 later
  drops in the real keyring/external-store backend behind the same Protocol with its own
  validation, audit, and leak tests; transports consume that implementation unchanged.
  The §3.4 wording should be reconciled to "env (file/keyring/external owned by #08)".
- **`extra="forbid"`** on every new model (inherit `Model`/`ConfigModel`).
- **Seam ownership is unambiguous: #10 owns the Protocol + a minimal impl; the bracketed
  owner swaps the *impl*, never the Protocol.** For every `seams/` piece the contract
  ownership map assigns elsewhere — `StopCapableGuard`/`SessionGuard` and `BreakPolicy`
  (#08), `LifecycleDispatcher` and the `TargetHandle`/`SnapshotStore` writer
  (provisioning) — #10 defines the stable Protocol **and ships a minimal in-process
  implementation now**, so #10's own conformance tests run without waiting on another
  issue. Conformance tests target the **Protocol**, so when #08 later replaces the
  `SessionGuard` impl it MUST pass the same target-wide single-holder / fenced-token /
  revoke-on-invalidation tests #10 wrote — there is no second guard and no divergence,
  and the Layer-2/Layer-4 bars are not blocked on #08. This is the spec's resolved
  decision (§1.3.1, §2, §5, §11); the contract's "owner = #08" means #08 owns the final
  impl + policy, not that #10 may ship without a working seam.
- **Redaction before both response and persistence** on any console/transcript path;
  raw captures stay on disk as `ArtifactRef(sensitive=True)`.
- **No shell.** agent-proxy and every subprocess use list argv; ports are ints;
  device/host strings are validated; endpoints pinned to `127.0.0.1`.
- **Bounded everything.** Every blocking IO / teardown / probe has an OS-level
  timeout; nothing is left to hang. A wedged operation is force-reaped, never awaited
  unbounded.
- **Doc terminology guard.** `just check-docs` forbids the legacy iteration-label word
  (the one this bullet deliberately does not spell) anywhere under `docs/` or
  `README.md`; keep every plan doc clear of it. The only sanctioned use is the existing
  code constant under `src/`, which the guard does not scan.
