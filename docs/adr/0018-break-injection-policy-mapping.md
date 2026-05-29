# ADR 0018 — Break-injection policy: an injectable `BreakPolicy` seam mapping the selected channel's topology + platform facts to a break method

**Status:** Accepted (2026-05-29) · **Issue:** #71 (epic #9, split from #17, facts from #10 `PlatformMetadata`, consumed by #12 `debug.kdb` / #13 `debug.gdb`) · **Affects:** `seams/break_policy.py` (`BreakPolicy` Protocol + `ReferenceBreakPolicy`); `coordination/selection.py` (`select_stop_capable_channel`, `BreakDisproof`); `coordination/transaction.py` (open transaction step 4 wiring + recorded `break_plan`); `transport/break_inject.py` (`inject_break` executes the recorded plan). No change to the executing mechanisms (`transport/proxy.py`, the ssh runner) — those are #10's, not this issue's.

## Context

interface-contracts §4.1 splits break injection three ways: provisioning supplies
**facts** (`PlatformMetadata`), this issue (the spec's placeholder "08") owns the
**policy** that maps facts → break method, and #10's transport layer **executes**
the chosen method. Provisioning MUST NOT hardcode a method.

The mapping seam already landed under #10's transport work
(`787d2ef feat: add reference break-plan policy seam (#10)`) because the Layer-4
`transport.open` transaction needs an executable break plan to admit a stop-capable
session (§4.8): `open()` MUST fail loud **before creating the session** if no
method's predicate holds. This ADR retroactively records the design #71 owns —
the predicates, the preference ordering, the disproof taxonomy and its scope, and
the deliberate non-consumption of `break_hints` — none of which any prior ADR
defines. ADR 0003 only notes that `break_plan` is "computed by `BreakPolicy` in
step 4"; ADR 0001/0006 cover the *post-break* RSP confirmation, not the *pre-attach*
mapping. There is no behavior change in this issue; the contribution is the decision
record plus tests for a previously-uncovered fact-set.

§4.1 fixes the normative per-method predicates and reference mappings:

| Break method        | Requires (ALL of)                                                      |
| ------------------- | ---------------------------------------------------------------------- |
| `gdbstub_native`    | selected channel `line_role=rsp` and `provides_rsp`                    |
| `uart_break`        | selected channel `line_role=dedicated_debug` and `supports_uart_break` |
| `agent_proxy_break` | selected channel `line_role=shared_console` and `supports_uart_break`  |
| `sysrq_g`           | `ssh_reachable=true` (issued in-guest over ssh; bound to no line)      |

`PlatformMetadata` (`transport/base.py:76`) carries `console_kind`,
`console_count`, `dedicated_debug_line`, `ssh_reachable`, and a
provider-suggested, **non-authoritative** `break_hints` list. `BreakMethod` /
`LineRole` are the enums at `transport/base.py:78,72`.

## Decision

1. **One injectable `BreakPolicy` Protocol seam; `ReferenceBreakPolicy` is the
   reference impl.** `plan(*, channel, platform, disproved) -> BreakPlan`
   (`seams/break_policy.py:30,45`). It is constructed once and injected into the
   open transaction (`server.py:6027` wires `ReferenceBreakPolicy()`;
   `coordination/transaction.py:160,245` holds and calls it). Provisioning supplies
   only facts; the executing mechanisms consume the recorded `BreakPlan`. This is
   the §4.1 facts → policy → execute split made concrete, with the policy as the
   single seam every stop-capable tier that *needs* a break shares, rather than
   per-tier logic. (A tier whose selected channel is `rsp`/`gdbstub_native` needs no
   injection — see Decision 7 — and the legacy non-transport gdb attach,
   `transport_enabled=false` at `server.py:4180`, is exactly that break-free case;
   it consults no policy by construction.)

2. **Topology-first: predicates key on the *selected channel's* `line_role` +
   `caps`, plus platform facts — never on the platform summary
   `dedicated_debug_line`.** A target may offer several break-capable serial
   channels (a shared console *and* a dedicated kgdb line); only the per-channel
   `line_role` + `caps` (§3.2, authoritative) disambiguates which line a break lands
   on (`_candidates`, `seams/break_policy.py:68`). The only *platform* facts the
   policy reads are `console_kind` and `ssh_reachable`; the summary facts
   `dedicated_debug_line` and `console_count` are intentionally unused — the
   "single shared console" boundary case (§4.1) is captured by the per-channel
   `line_role`/`caps` plus `ssh_reachable`, not by a count, so keying on
   `console_count` would add nothing the channel topology does not already say.

3. **Preference is candidate insertion order: line-native first, ssh `sysrq_g`
   last; `console_kind` *reorders* preference but never *excludes*
   `agent_proxy_break`.** For a `shared_console` line that `supports_uart_break`,
   `console_kind=uart` prefers the line-native `agent_proxy_break`; a non-UART
   console (`hvc`/`virtio`) prefers `sysrq_g` over ssh (hvterm BREAK semantics
   differ from UART) but keeps `agent_proxy_break` as a no-ssh fallback
   (`seams/break_policy.py:83,89-94`). The §4.1 boundary case — single shared
   console + `ssh_reachable=false` + `supports_uart_break` — therefore stays
   admissible via `agent_proxy_break` on every `console_kind`.

4. **The policy is pure: topology predicates plus a caller-injected `disproved`
   set; it never probes.** `plan()` is deterministic — its only dynamic input is
   the `disproved: set[BreakMethod]` the §4.8 admission layer passes for that
   channel. It raises `BreakPlanError` with one of two codes
   (`seams/break_policy.py:19,54,63`): `no_break_plan` (no method's topology
   predicate holds for the channel) and `break_disproved` (every
   topology-admissible candidate was positively disproved). The two are distinct
   because §4.8 distinguishes "never had a plan" from "had candidates, all proven
   unexecutable" — different operator remediation.

5. **Disproof scope is method-aware, resolved at selection.**
   `select_stop_capable_channel` (`coordination/selection.py:63`) iterates
   `transports[]` in authoritative order, skips a caps-sufficient but unbreakable
   channel, and resolves each channel's `disproved` set from a `set[BreakDisproof]`
   whose scope depends on the method (`coordination/selection.py:25,28-54`):
   `sysrq_g` is **target-wide** (its preconditions are a property of the running
   kernel / ssh, not of any one line), so a `sysrq_g` disproof prunes that method on
   *every* channel of the target; `gdbstub_native` / `uart_break` /
   `agent_proxy_break` are **line-bound** and prune only their own channel. Selection
   aggregates the taxonomy across capable channels: a positive `break_disproved` on
   any channel is never downgraded to `no_break_plan` by a later topology-less
   channel (`coordination/selection.py:94-100`).

6. **`break_hints` is deliberately not consumed by the policy.** §4.1 marks it
   provider-suggested and **non-authoritative**; the topology predicates are the
   sole authority. The field is carried on `PlatformMetadata` for forward-compatibility
   with the §4.1 contract and is currently unread by any code path
   (`coordination/admission.py:173` carries it immutably across admission but never
   inspects it); feeding it into the decision would let a provider's guess override
   the authoritative predicates.

7. **Execution rejects a requested method that is not the admitted plan, and
   `gdbstub_native` is not injectable.** `inject_break`
   (`transport/break_inject.py:28`) treats `gdbstub_native` as "needs no injection"
   (gdb interrupts the RSP channel directly) and rejects any requested method ≠ the
   recorded `BreakPlan.method` (`transport/break_inject.py:46-50`) rather than
   attempting it — the policy's decision is authoritative at execution time, not
   re-litigated by the caller.

## Consequences

- On the Layer-4 transport path (`transport_enabled`, `server.py:4180`), every
  stop-capable tier obtains its break method from the one `BreakPolicy` seam: #13
  `debug.gdb` already routes through `transaction.open` at `server.py:4205`, and #12
  `debug.kdb` will inherit the same path. No tier embeds per-platform selection
  logic, so the §4.1 mappings change in exactly one place. The legacy non-transport
  gdb attach consults no policy because it needs no break (RSP/`gdbstub_native`),
  not because it has its own mapping.
- A capable-but-unbreakable channel is skipped, and an attach with no executable
  break plan fails loud before any acquisition (no guard, lease, session, or halt to
  unwind), surfacing `no_break_plan` / `break_disproved` so an operator can tell a
  topology gap from a probe disproof.
- Because the policy is pure and disproof is injected, `ReferenceBreakPolicy.plan`
  is exhaustively unit-testable per fact-set without a live target
  (`tests/test_seams_break_policy.py`); the §4.8 probing that produces disproofs is
  tested separately at the selection layer (`tests/test_coordination_selection.py`).
- `break_hints` remains carried-but-unread. If a future need arises to use it (e.g.
  as a tiebreaker among equally-preferred candidates), that is a new decision that
  must supersede this point 6, not a silent change — the contract still says hints
  are non-authoritative.

## Considered & rejected

- **A. Let the provider hardcode the break method (treat `break_hints` as
  authoritative).** Rejected: §4.1 explicitly forbids provisioning hardcoding a
  method and marks hints non-authoritative. A provider also cannot see which channel
  the tier will *select*, so it cannot key on the per-channel `line_role` the
  predicates require; the method must be decided where the selected channel is known.

- **B. Key the predicates on the platform summary facts (`dedicated_debug_line`,
  `console_kind`) as a target-wide guess.** Rejected: a target can expose a shared
  console *and* a dedicated kgdb serial line where only the latter carries
  `supports_uart_break` (§3.2). A target-wide guess cannot say *which* line breaks,
  and `console_kind` (which describes the *primary* console) would wrongly gate a
  dedicated UART debug line behind an `hvc` primary console. Per-channel `line_role`
  + `caps` is the only unambiguous key (covered by
  `test_hvc_primary_console_still_allows_dedicated_uart_debug_line`).

- **C. Treat `console_kind` as a hard *gate* that excludes `agent_proxy_break` on
  non-UART consoles.** Rejected: the §4.1 boundary case (single shared console +
  `ssh_reachable=false` + `supports_uart_break`) MUST stay admissible via
  `agent_proxy_break`; gating it out would wrongly raise `no_break_plan` for a
  target that *can* break. `console_kind` is therefore a *preference* reorder only,
  not a predicate (covered by
  `test_hvc_shared_console_without_ssh_falls_back_to_agent_proxy_break`).

- **D. Fold disproof *discovery* into `plan()` — have the policy probe liveness
  itself.** Rejected: probing whether `gdbstub_native` / `sysrq_g` actually works is
  arch- and transport-specific and is §4.8 admission's job. Keeping `plan()` pure
  (topology + an injected disproof set) makes it deterministic and unit-testable, and
  lets `select_stop_capable_channel` aggregate disproofs across channels and apply
  method-aware scope — logic that would be duplicated per call site if the policy
  probed inline.

- **E. Collapse `no_break_plan` and `break_disproved` into a single error.**
  Rejected: §4.8 separates "no topology predicate ever held" (a static
  mis-provisioning the operator fixes by adding a break-capable line) from "a
  candidate existed but every one was positively disproved at probe time" (a runtime
  condition). Selection must not downgrade a positive disproof on one channel to
  `no_break_plan` because a later channel happens to be topology-less
  (`coordination/selection.py:94-100`), so the two codes are kept distinct and
  aggregated.

- **F. Use one disproof scope for all methods (all target-wide, or all
  line-bound).** Rejected: `sysrq_g`'s preconditions (`/proc/sys/kernel/sysrq`,
  `/proc/sysrq-trigger`) are a property of the running kernel reached over ssh, not
  of any one console/RSP line — so its disproof must prune the method on every
  channel of the target. The line-native methods are per-channel. A single scope
  either leaks an ssh disproof onto unrelated channels' line-native methods or fails
  to prune `sysrq_g` on a sibling channel; `BreakDisproof` enforces the split in
  `__post_init__` (`coordination/selection.py:42-47`).

- **G. Express the mapping as a declarative data table (a `dict` keyed on facts)
  rather than ordered predicates.** Tempting given the issue title ("mapping
  table"). Rejected: the decision is a conjunction of channel caps + platform facts +
  an injected disproof set, with a preference *ordering* and a `console_kind`
  reorder, plus the boundary case that must stay admissible. A flat dict cannot
  express the predicate conjunction or the preference reorder without a value side
  that is itself a function — at which point it is the same ordered-predicate code
  with worse locality. The single `_candidates` function, centralized in one module
  and consumed through the `BreakPolicy` seam, *is* the table the issue asks for.
