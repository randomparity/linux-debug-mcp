# ADR 0003 — Layer-3 backends return a `BackendAttachment`; Layer 4 owns the `TransportSession`

**Status:** Accepted (2026-05-27) · **Issue:** #10 · **Affects:** Layer 1 (`transport/base.py` — the internal `Transport` ABC), Layer 3 (`transport/proxy.py`, `serial_local.py`, `qemu_gdbstub.py` backends), Layer 4 (`open()` transaction / registry)

## Context

Layer 1 froze `transport/base.py` with `Transport.attach(request, *, cancel, deadline, on_partial) -> TransportSession` (base.py:328). But design §4.3 has **Layer 4** mint the `session_id` and write the write-ahead durable ownership record in **step 2** — *before* `attach` runs in **step 7** — and update it as the guard token (step 5) and lease token (step 6) appear. `attach` takes **no** `session_id` parameter, yet a `TransportSession` carries one, so a backend would mint a *second* identity Layer 4 must discard. `TransportSession` also carries fields whose authority lives in Layer 4 — `record_state`, `console_lease_token`, `stop_guard_token`, `attach_epoch`, `created_at`, `break_plan` (computed by `BreakPolicy` in step 4), `execution_state` (owned by the stop-capable controller, §4.6) — that a wire backend has no business setting.

The genuinely frozen contract is `TransportRef`/`OpenRequest` and `TransportSession` **as a persisted record schema** (§3.2). The `Transport` ABC is **01-internal** with **zero production callers** — only `tests/test_transport_base.py` references it (one abstract-instantiation check; `TransportSession` is constructed only in schema tests). The spec (§1.4) explicitly defers the Layer-3/Layer-4 ownership split to an ADR.

## Decision

- Backends return a frozen `BackendAttachment` carrying **only wire-discovered fields**: `console_endpoint`, `rsp_endpoint`, `backend_pid`, `backend_start_time`, and an optional `console_artifact: ArtifactRef | None`. The internal ABC becomes `Transport.attach(...) -> BackendAttachment`.
- **Layer 4 owns `TransportSession` end-to-end:** it mints `session_id` (step 2), persists/atomically updates the write-ahead record, acquires and records the guard/lease tokens, sets `record_state`/`attach_epoch`/`created_at`/`break_plan`/`execution_state`, and **assembles** the final `TransportSession` from its own record + the returned `BackendAttachment`.
- Partial resources continue to flow to Layer 4 via the `on_partial` callback the instant each is created (§4.3 step 7); `BackendAttachment` is the **terminal success value**, not the partial-resource channel.
- The persisted `TransportSession` **record schema is unchanged** — this ADR moves only what an internal method returns.

## Consequences

- The Layer-3/Layer-4 ownership boundary is **structural, not conventional**: a backend cannot mint identity, tokens, or `record_state` because those fields do not exist on `BackendAttachment`. There is no transient duplicate `session_id`, and `created_at` is unambiguously Layer 4's.
- `TransportSession` is constructed **only in Layer 4**; Layer 3 white-box tests assert a `BackendAttachment` (correct endpoints + a reapable pid/start-time), not a 17-field record. That round-trip assertion belongs in Layer 4, where the record is owned.
- `transport/base.py`'s internal `Transport` ABC return type changes; `new_session_id()` becomes a Layer-4-only caller. The abstract-instantiation test is unaffected and no production caller exists, so blast radius is nil.

## Considered & rejected

1. **Carrier + merge (no `base.py` edit):** `attach` keeps `-> TransportSession`, mints a throwaway `session_id`, fills only wire fields; Layer 4 copies those onto its step-2 record and ignores attach's id. **Rejected:** creates two sources of truth for identity — the exact smell [ADR 0002](0002-stop-controller-execution-authority-is-the-guard-token.md) rejected — and enforces the split only by convention (nothing stops a backend setting a token or `record_state=ready`); the backend must also fabricate a half-true full record with defaulted tokens.
2. **Thread `session_id` into `attach`, keep `-> TransportSession`:** Layer 4 passes its minted id down so the returned session carries the real identity; tokens/`record_state` left at defaults for Layer 4 to overwrite. **Rejected:** still returns a *partial* `TransportSession`, so "which fields are authoritative coming out of `attach`" remains a prose invariant rather than a typed one; the full return type invites a backend to over-populate; `created_at` ownership stays ambiguous.

## References

design §3.2 (frozen `TransportRef`/`OpenRequest`/`TransportSession` shapes), §4.3 (write-ahead transaction steps), §4.7 (durable ownership record); roadmap Layer 3 row ("internal, non-exported session handles consumed only by Layer 3's white-box tests and Layer 4's transaction"); [ADR 0002](0002-stop-controller-execution-authority-is-the-guard-token.md) (single-source authority over a parallel one).
