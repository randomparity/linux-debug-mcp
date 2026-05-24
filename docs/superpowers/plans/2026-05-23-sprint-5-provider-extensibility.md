# Sprint 5 Provider Extensibility Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** Add a contract-first provider extensibility layer with richer capability metadata, static in-repo provider plugin declarations, safe future-facing stub providers, callable future MCP tools, and ppc64le design documentation without changing the implemented local x86_64 workflows.

**Architecture:** Keep Sprint 0-4 local handlers and concrete providers on their current paths. Extend provider metadata backward-compatibly, register built-in provider plugin specs from Python objects, and route only the new future-facing MCP tools through typed request validation, deterministic provider selection, and stub `not_implemented` responses. Stub operations must not create run workspaces, invoke subprocesses, open network or serial resources, read credentials, or mutate external systems.

**Tech Stack:** Python 3.11+, Pydantic v2, pytest, existing `ToolResponse`, `ErrorCategory`, `ProviderRegistry`, `ProviderCapability`, `OperationSemantics`, `TargetKind`, and `Redactor`.

---

## Current-Code Constraints

- `ProviderCapability` only has flat provider-level metadata: `operations`, `semantics`, host tools, permissions, and access methods.
- `ProviderRegistry.with_defaults()` directly registers local provider capabilities and has no plugin declaration boundary.
- There is no `providers/contracts.py` module for future provider request/result models.
- `server.py` currently has only implemented local Sprint 0-4 handlers plus the old generic `not_implemented_handler()`.
- `providers.list` returns raw capability dumps and currently only exposes the six implemented local providers.
- Future provider families, ppc64le metadata, and future MCP tools are not discoverable.
- Existing local workflows are x86_64-only and should not be refactored behind a new runtime dispatcher in this sprint.

## Files

- Modify: `src/linux_debug_mcp/domain.py` for `ImplementationState`, `ProviderOperationCapability`, richer `ProviderCapability` fields, and compatibility defaults.
- Modify: `src/linux_debug_mcp/providers/base.py` to populate operation capability metadata for existing local provider helpers.
- Modify: `src/linux_debug_mcp/providers/local_kernel_build.py`, `src/linux_debug_mcp/providers/libvirt_qemu.py`, `src/linux_debug_mcp/providers/local_ssh_tests.py`, and `src/linux_debug_mcp/providers/qemu_gdbstub.py` only as needed to add richer capability fields while preserving current operations.
- Create: `src/linux_debug_mcp/providers/plugins.py` for `ProviderPluginSpec`, built-in local plugin specs, and built-in stub plugin specs.
- Create: `src/linux_debug_mcp/providers/stubs.py` for future stub provider capability factories, provider selection helpers, and stable stub failure response helpers.
- Modify: `src/linux_debug_mcp/providers/registry.py` to load built-in plugin specs in `with_defaults()`, preserve provider-to-plugin documentation metadata, and support deterministic operation/architecture matching.
- Create: `src/linux_debug_mcp/providers/contracts.py` for future request/result Pydantic models and shared validators.
- Modify: `src/linux_debug_mcp/server.py` for future-facing handlers, validation failure mapping, redaction, and MCP tool registration.
- Modify: `tests/test_providers.py` for richer metadata, plugin spec loading, stub provider discoverability, and operation consistency.
- Create: `tests/test_provider_contracts.py` for contract validation and redaction-sensitive fields.
- Create: `tests/test_future_stub_handlers.py` for future MCP handler behavior, provider selection, error categories, and no-workspace safety.
- Modify: `tests/test_server.py` for `providers.list` payload shape and future tool registration.
- Modify: `README.md` for Sprint 5 status, implementation states, and future provider discoverability.
- Create: `docs/ppc64le-provider-spike.md` for the non-implementation ppc64le design spike.

## Task 1: Extend Provider Capability Metadata

**Files:**
- Modify: `src/linux_debug_mcp/domain.py`
- Modify: `src/linux_debug_mcp/providers/base.py`
- Modify: local provider capability factories as needed
- Modify: `tests/test_providers.py`
- Modify: `tests/test_server.py`

- [x] **Step 1: Write failing provider metadata tests**

Add tests proving:

- every default provider has `provider_family`, `implementation_state`, `transports`, `limitations`, and `operation_capabilities`
- operation capabilities expose `required_host_tools`, `destructive_permissions`, and `limitations` with empty-list defaults
- existing Sprint 0-4 providers have `implementation_state == "implemented"`
- local provider top-level `semantics` remain present for Sprint 0-4 compatibility
- `operations` and `[cap.operation for cap in operation_capabilities]` contain the same operation names
- each operation capability has operation-level `semantics`
- `providers.list` includes the new metadata fields while preserving the existing provider names

- [x] **Step 2: Run focused tests and confirm failure**

```bash
pytest tests/test_providers.py tests/test_server.py -q
```

Expected: FAIL because the richer metadata model does not exist.

- [x] **Step 3: Add backward-compatible domain models**

In `src/linux_debug_mcp/domain.py`:

- add `ImplementationState(StrEnum)` with `IMPLEMENTED`, `STUB`, and `EXTERNAL_RESERVED`
- add `ProviderOperationCapability`
- extend `ProviderCapability` with:
  - `provider_family: str = "local"`
  - `implementation_state: ImplementationState = ImplementationState.IMPLEMENTED`
  - `transports: list[str] = Field(default_factory=list)`
  - `limitations: list[str] = Field(default_factory=list)`
  - `operation_capabilities: list[ProviderOperationCapability] = Field(default_factory=list)`
- add a `model_validator(mode="after")` that fills missing `operation_capabilities` from `operations` using provider-level semantics, copies operation-level default state from the provider when omitted, and rejects mismatches when both are supplied

Keep existing field names and defaults so current constructors continue to work.

- [x] **Step 4: Populate local provider metadata**

Update `sprint0_capability()` and local provider capability factories to set sensible family and transport fields:

- `local-artifacts`: family `artifacts`, transports `["filesystem"]`
- `local-prereqs`: family `host`, transports `["subprocess", "filesystem"]`
- `local-kernel-build`: family `build`, transports `["subprocess", "filesystem"]`
- `local-libvirt-qemu`: family `boot`, transports `["libvirt", "serial-console", "filesystem"]`
- `local-ssh-tests`: family `test`, transports `["ssh", "filesystem"]`
- `local-qemu-gdbstub`: family `debug`, transports `["tcp", "gdb-remote", "filesystem"]`

- [x] **Step 5: Verify focused tests pass**

```bash
pytest tests/test_providers.py tests/test_server.py -q
```

Expected: PASS.

## Task 2: Add Static Built-In Provider Plugin Specs

**Files:**
- Create: `src/linux_debug_mcp/providers/plugins.py`
- Modify: `src/linux_debug_mcp/providers/registry.py`
- Modify: `tests/test_providers.py`

- [x] **Step 1: Write failing plugin-boundary tests**

Add tests proving:

- `ProviderPluginSpec` rejects empty plugin names and versions
- built-in plugin specs expose local provider capability factories
- `ProviderRegistry.with_defaults()` loads from built-in plugin specs
- the registry can return documentation paths for each registered provider based on the plugin spec that supplied it
- no dynamic entry point, manifest path, or string import loading is required for defaults
- duplicate provider names are still rejected

- [x] **Step 2: Implement `ProviderPluginSpec`**

Create `providers/plugins.py` with a Pydantic model:

```python
class ProviderPluginSpec(Model):
    plugin_name: str
    plugin_version: str
    implementation_state: ImplementationState
    provider_capability_factories: list[Callable[[], ProviderCapability]]
    documentation_paths: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
```

Use validators to reject unsafe empty labels. Define functions such as `local_provider_plugin_specs()` and later `stub_provider_plugin_specs()` that return static Python objects.

- [x] **Step 3: Route registry defaults through plugin specs and keep plugin metadata**

Change `ProviderRegistry.with_defaults()` to iterate built-in specs and register every capability returned by every factory. Store the originating plugin name, plugin version, documentation paths, and plugin limitations in a private metadata map keyed by provider name. Keep `register()`, `get()`, and `list_capabilities()` behavior stable, and add a read-only accessor such as `provider_plugin_metadata(provider_name)`.

- [x] **Step 4: Verify focused tests pass**

```bash
pytest tests/test_providers.py -q
```

Expected: PASS.

## Task 3: Add Future Stub Provider Capabilities

**Files:**
- Create: `src/linux_debug_mcp/providers/stubs.py`
- Modify: `src/linux_debug_mcp/providers/plugins.py`
- Modify: `src/linux_debug_mcp/providers/registry.py`
- Modify: `tests/test_providers.py`
- Modify: `tests/test_server.py`

- [x] **Step 1: Write failing stub discoverability tests**

Add tests proving default registry includes these stub provider names:

- `remote-build-stub`
- `remote-artifact-sync-stub`
- `reservation-stub`
- `provisioning-stub`
- `hardware-control-stub`
- `console-access-stub`
- `real-boot-stub`

For each stub, assert:

- `implementation_state == "stub"`
- `architectures` is exactly `["x86_64", "ppc64le"]` unless a narrower operation-specific reason is documented
- target kinds and transports match the family
- advertised operations match operation capabilities exactly
- advertised `required_host_tools` name future dependencies without requiring them to be installed in Sprint 5 tests
- operation-level destructive permissions are present for future provisioning, power, boot, and reserve/provision/boot operations
- limitations explain that no external side effects occur

- [x] **Step 2: Implement stub capability factories**

In `providers/stubs.py`, create one factory per stub provider. Advertise these operations:

- `remote-build-stub`: `remote.build_kernel`
- `remote-artifact-sync-stub`: `remote.sync_artifacts`
- `reservation-stub`: `reservation.request_host`, `reservation.release_host`
- `provisioning-stub`: `provision.prepare_target`
- `hardware-control-stub`: `hardware.power_control`
- `console-access-stub`: `console.open_session`, `console.read`, `console.write`
- `real-boot-stub`: `hardware.boot_kernel`, `workflow.reserve_provision_boot`

Use operation-level semantics. Mark destructive operations such as power control, provisioning, real boot, and reserve/provision/boot as destructive in operation metadata even though the stub performs no side effects.

- [x] **Step 3: Add stub plugin specs**

Expose the stub factories from `providers/plugins.py` as static built-in specs, including `docs/ppc64le-provider-spike.md` in `documentation_paths` for ppc64le-relevant specs. Ensure either `providers.list` or the registry metadata accessor can surface those documentation paths to clients; do not leave documentation paths only on private plugin objects.

- [x] **Step 4: Add registry selection helpers**

Add a deterministic helper such as:

```python
def find_by_operation_and_architecture(self, *, operation: str, architecture: str) -> list[ProviderCapability]:
    ...
```

It should match providers advertising both the operation and architecture. Do not perform fallback from an explicit provider name.

- [x] **Step 5: Verify focused tests pass**

```bash
pytest tests/test_providers.py tests/test_server.py -q
```

Expected: PASS.

## Task 4: Add Future Provider Contracts

**Files:**
- Create: `src/linux_debug_mcp/providers/contracts.py`
- Create: `tests/test_provider_contracts.py`

- [x] **Step 1: Write failing contract validation tests**

Cover valid minimal requests and malformed inputs for:

- `RemoteBuildRequest`
- `RemoteBuildResult`
- `RemoteArtifactSyncRequest`
- `RemoteArtifactSyncResult`
- `ReservationRequest`
- `ReservationResult`
- `ProvisioningRequest`
- `ProvisioningResult`
- `HardwareControlRequest`
- `HardwareControlResult`
- `ConsoleSessionRequest`
- `ConsoleReadRequest`
- `ConsoleReadResult`
- `ConsoleWriteRequest`
- `ConsoleWriteResult`
- `RealBootRequest`
- `RealBootResult`
- `ReserveProvisionBootRequest`

Tests should also prove every request model accepts the common safe selection and diagnostics fields required by the spec: optional `provider_name`, `architecture`, a request-scoped target/profile/pool label, `timeout_seconds`, `operation_label`, and optional `run_id` or artifact references where relevant.

Tests should reject empty provider names, unknown architectures, invalid timeouts, unsafe labels, missing required common fields, invalid power actions, invalid byte counts, empty console session IDs, raw credential or token fields, and empty or oversized console write payloads.

- [x] **Step 2: Implement shared validators**

In `providers/contracts.py`, define helpers for:

- known architectures: `x86_64`, `ppc64le`
- safe labels for provider names, profiles, targets, pools, session IDs, artifact refs, and operation labels
- timeout ranges such as `ge=1`, bounded upper limit
- no raw secret fields; allow only reference fields such as `credential_ref`, `ssh_key_ref`, `bmc_credential_ref`, and `reservation_token_ref`
- redaction-safe validation errors that report field names and categories rather than raw rejected values

- [x] **Step 3: Implement request/result models**

Keep models family-specific rather than one generic future operation request. Include fields required by the spec:

- `remote.build_kernel`: `architecture`, `source_ref`, `build_profile`
- `remote.sync_artifacts`: `architecture`, `external_artifact_ref`
- `reservation.request_host`: `architecture`, `reservation_pool`
- `reservation.release_host`: `architecture`, `reservation_id`
- `provision.prepare_target`: `architecture`, `target_name`, `provisioning_profile`
- `hardware.power_control`: `architecture`, `target_name`, `action`
- `hardware.boot_kernel`: `architecture`, `target_name`, `kernel_artifact_ref`
- `console.open_session`: `architecture`, `target_name`, `access_method`
- `console.read`: `architecture`, `console_session_id`, `max_bytes`
- `console.write`: `architecture`, `console_session_id`, `data`
- `workflow.reserve_provision_boot`: validate with `ReserveProvisionBootRequest` containing `architecture`, `reservation_pool`, `target_name`, `provisioning_profile`, `kernel_artifact_ref`

Add optional `provider_name`, `timeout_seconds`, `operation_label`, and relevant optional `run_id` or artifact reference fields to each request model. Add optional external ID fields on results but leave them unset by default.

- [x] **Step 4: Verify contract tests pass**

```bash
pytest tests/test_provider_contracts.py -q
```

Expected: PASS.

## Task 5: Implement Stub Handler Response Flow

**Files:**
- Modify: `src/linux_debug_mcp/providers/stubs.py`
- Modify: `src/linux_debug_mcp/server.py`
- Create: `tests/test_future_stub_handlers.py`

- [x] **Step 1: Write failing handler tests**

Use direct handler calls. Cover:

- valid requests for all new tools return `ErrorCategory.NOT_IMPLEMENTED`
- malformed requests return `ErrorCategory.CONFIGURATION_ERROR`
- unknown explicit provider returns `configuration_error`
- explicit provider that exists but does not advertise the requested operation or architecture returns `configuration_error`
- explicit provider never falls back to a different provider
- unsupported architecture returns `configuration_error`
- ambiguous implicit provider selection returns `configuration_error` and includes candidate names
- valid stub responses include provider name, operation, architecture, implementation state, and `providers.list` as a suggested next action
- ppc64le-relevant valid stub responses include `docs/ppc64le-provider-spike.md` in stable details
- redaction-sensitive request fields, especially `console.write` data and credential reference fields, are not echoed in errors
- no stub handler creates `.linux-debug-mcp/runs` under a temp artifact root
- monkeypatched guards prove stub handlers do not call `subprocess`, `socket`, credential file reads, serial device paths, libvirt providers, or artifact-store write APIs

- [x] **Step 2: Add provider selection and response helpers**

In `providers/stubs.py`, implement helpers such as:

- `select_future_provider(registry, operation, architecture, provider_name=None)`
- `future_not_implemented_response(provider, operation, architecture, documentation_paths=None)`
- `future_configuration_error_response(message, details=None)`

Keep details stable and machine-readable. Include documentation path details when relevant.

The selector should enforce the full explicit-provider rule: if `provider_name` is supplied, fetch exactly that provider, then verify that the same provider advertises the requested operation and architecture. Return `configuration_error` on any mismatch; never retry implicit selection.

- [x] **Step 3: Add server handler helpers**

In `server.py`, add a small common flow:

1. instantiate the right contract model
2. map `ValidationError` to `configuration_error`
3. select provider deterministically
4. return redacted `not_implemented`

The helper should accept the contract class and operation name. It should not create or read run manifests.

Validation failure responses should pass through `Redactor` and should not include `ValidationError.errors()` entries whose `input` values contain raw request payloads.

- [x] **Step 4: Add individual handlers**

Add:

- `remote_build_kernel_handler`
- `remote_sync_artifacts_handler`
- `reservation_request_host_handler`
- `reservation_release_host_handler`
- `provision_prepare_target_handler`
- `hardware_power_control_handler`
- `hardware_boot_kernel_handler`
- `console_open_session_handler`
- `console_read_handler`
- `console_write_handler`
- `workflow_reserve_provision_boot_handler`

`workflow_reserve_provision_boot_handler` should validate once and short-circuit to one `not_implemented` response. It must not call the individual reservation, provisioning, hardware, or boot handlers in sequence.

- [x] **Step 5: Verify focused tests pass**

```bash
pytest tests/test_future_stub_handlers.py -q
```

Expected: PASS.

## Task 6: Register Future MCP Tools

**Files:**
- Modify: `src/linux_debug_mcp/server.py`
- Modify: `tests/test_server.py`

- [x] **Step 1: Write failing tool registration tests**

Assert `create_app()` registers:

- `remote.build_kernel`
- `remote.sync_artifacts`
- `reservation.request_host`
- `reservation.release_host`
- `provision.prepare_target`
- `hardware.power_control`
- `hardware.boot_kernel`
- `console.open_session`
- `console.read`
- `console.write`
- `workflow.reserve_provision_boot`

Also assert each tool exposes the minimum request fields from the spec.

For tools with optional explicit selection, assert `provider_name`, `timeout_seconds`, and `operation_label` are also visible in the FastMCP schema.

- [x] **Step 2: Wire MCP tools**

Add `@app.tool(...)` wrappers that call the direct handlers and return `.model_dump(mode="json")`. Keep signatures explicit instead of accepting one untyped dict so FastMCP exposes useful schemas.

- [x] **Step 3: Verify registration tests pass**

```bash
pytest tests/test_server.py -q
```

Expected: PASS.

## Task 7: Add ppc64le Spike And README Updates

**Files:**
- Create: `docs/ppc64le-provider-spike.md`
- Modify: `README.md`
- Modify: `tests/test_providers.py` or `tests/test_server.py` if docs paths are asserted

- [x] **Step 1: Create ppc64le design spike**

Document that ppc64le is metadata and contract-only in Sprint 5. Cover:

- kernel image and build artifact differences
- remote build needs
- boot firmware and kernel argument differences
- PXE/NIM provisioning assumptions
- HMC/IPMI/BMC control expectations
- serial console expectations
- libvirt/QEMU versus real hardware boundaries
- debug limitations and differences from local x86_64 QEMU gdbstub
- artifact identity requirements for matching kernel, config, and symbols

- [x] **Step 2: Update README**

Add a concise Sprint 5 section explaining:

- local x86_64 remains the only implemented end-to-end workflow
- future providers are discoverable stubs
- implementation states: `implemented`, `stub`, `external_reserved`
- `providers.list` is the primary discovery tool
- ppc64le appears in stub metadata but is not executable

- [x] **Step 3: Verify docs references**

Run any doc-path tests added earlier and ensure provider metadata references `docs/ppc64le-provider-spike.md` where expected.

Also verify `providers.list` or an equivalent registry-backed response includes the documentation path for ppc64le-capable stub providers, so agents can discover why ppc64le appears without being executable.

## Task 8: Full Regression And Safety Audit

**Files:**
- No planned edits unless tests reveal defects

- [x] **Step 1: Run focused future-provider suite**

```bash
pytest tests/test_provider_contracts.py tests/test_future_stub_handlers.py tests/test_providers.py tests/test_server.py -q
```

Expected: PASS.

- [x] **Step 2: Run full test suite**

```bash
pytest -q
```

Expected: PASS. Existing Sprint 0-4 tests should pass unchanged or with only assertion updates for additive provider metadata and new provider names.

- [x] **Step 3: Manual side-effect check**

Review the stub code and tests for forbidden behavior:

- no `subprocess`
- no sockets
- no credential-file reads
- no serial device access
- no libvirt calls
- no artifact or run workspace writes
- no chaining workflow calls for `workflow.reserve_provision_boot`

- [x] **Step 4: Acceptance checklist**

Confirm:

- `providers.list` shows local implemented providers and Sprint 5 stubs with clear implementation states
- built-in provider plugin specs register local and stub capability factories without dynamic imports
- all future-facing MCP tools are callable
- valid future requests return stable `not_implemented`
- malformed future requests return stable `configuration_error`
- typed contracts exist for every future provider family
- ppc64le spike exists and is linked from metadata or README
- local build, boot, test, artifact, and debug behavior is unchanged
