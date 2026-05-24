# Phase 5 Simplification Review Fixes

**Goal:** Apply low-risk simplification recommendations from the `main..HEAD`
subagent review while preserving the Phase 5 future-provider contract surface
and FastMCP schemas.

## Review Inputs

- Reuse reviewer: duplicate future operation mappings and repeated safe-label
  field declarations.
- Quality reviewer: duplicate future stub wrapper shape, unused stub response,
  provider-selection error rewrapping, repeated safe-label declarations, and
  test-only result-model complexity.
- Efficiency reviewer: repeated default-registry construction, avoidable
  registry list allocation, and unnecessary operation-capability copies.

## Accepted Changes

- [x] Add a small helper for contract safe-label field declarations.
- [x] Replace custom console byte-count validators with Pydantic bounds.
- [x] Delete the unused `stub_not_implemented_response`.
- [x] Return provider-selection failures directly from `_future_stub_handler`
  instead of unwrapping and rewrapping them.
- [x] Iterate registry provider values directly in operation/architecture
  lookup.
- [x] Avoid copying operation capabilities when all implementation states are
  already explicit.

## Deferred Changes

- Keep explicit FastMCP future-tool wrappers. Dynamic wrapper generation could
  change tool schemas, and schema stability is more important than removing this
  duplication in Phase 5.
- Keep future result models. They are part of the planned contract surface in
  the Phase 5 plan, even though runtime handlers currently return
  `ToolResponse`.
- Do not add a shared default-registry singleton yet. `ProviderRegistry` is
  mutable, so caching a live registry risks cross-test or cross-call mutation.

## Verification

```bash
pytest tests/test_provider_contracts.py tests/test_future_stub_handlers.py tests/test_providers.py tests/test_server.py -q
pytest -q
```
