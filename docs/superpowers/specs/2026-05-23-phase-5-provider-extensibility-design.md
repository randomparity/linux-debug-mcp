# Phase 5 Provider Extensibility Design

Date: 2026-05-23

## Purpose

Phase 5 turns the local x86_64 pilot into a project with explicit extension
boundaries. The phase should make future provider families visible and
testable without implementing remote build systems, lab reservation services,
PXE/NIM provisioning, HMC/IPMI control, serial hardware access, real hardware
boot, or ppc64le execution.

The goal is a contract-first in-repo extensibility layer: richer capability
metadata, typed provider contracts, callable future-facing MCP tools, and safe
stub providers that always fail before external side effects.

## Scope

Phase 5 includes:

- richer provider capability declarations
- static in-repo plugin declaration mechanics for provider bundles
- in-repo contract models for future provider families
- in-repo stub providers for remote build, reservation, provisioning, hardware
  control, serial console access, and real hardware boot
- callable MCP tools for those future paths
- stable `not_implemented` responses for valid future requests
- stable `configuration_error` responses for malformed future requests
- provider listing that distinguishes implemented local providers from in-repo
  stubs
- ppc64le design spike documentation
- unit tests proving stubs are callable, safe, and discoverable

Phase 5 does not include:

- dynamic external plugin package loading
- real remote build execution
- real artifact sync from remote systems
- real host reservation
- real PXE, NIM, or rootfs provisioning
- real HMC, IPMI, BMC, or power-control calls
- real serial-device or terminal sessions
- real hardware boot
- ppc64le build, boot, test, or debug execution
- refactoring the working Phase 0-4 local providers behind a new runtime
  dispatch system

## Recommended Approach

Use a contract-first in-repo stub layer.

The current local pilot paths should continue to use their existing concrete
providers and handlers. Phase 5 should not replace the working local
build/boot/test/debug orchestration with a new plugin runtime. Instead, it
should define the shapes that future providers must satisfy and expose those
future operations through MCP tools that return explicit, structured failures.

This gives agentic clients a discoverable roadmap and stable error behavior
while keeping the host safe. It also creates useful tests for provider metadata
and request validation before any real lab integration is added.

## Architecture

The existing `ProviderRegistry` should remain small and static in Phase 5, but
provider capabilities should describe more than a flat operation list.
The current `operations` list and top-level `semantics` field should remain for
backward compatibility with Phase 0-4 tests and clients. Phase 5 should add
the richer fields as backward-compatible model fields with defaults instead of
forcing every local provider call site to move in the same phase.

Capability metadata should support:

- provider name and version
- provider family or category
- implementation state: `implemented`, `stub`, or `external_reserved`
- supported architectures
- target kinds
- access methods and transports
- required dependencies
- destructive permissions
- operation-level semantics for every advertised operation
- human-readable limitations

Add a typed operation metadata model named `ProviderOperationCapability` with
these fields:

- `operation`: MCP tool or provider operation name
- `implementation_state`: `implemented`, `stub`, or `external_reserved`
- `semantics`: `OperationSemantics`
- `required_host_tools`: operation-specific host tools, defaulting to empty
- `destructive_permissions`: operation-specific permissions, defaulting to empty
- `limitations`: human-readable strings, defaulting to empty

`ProviderCapability` should gain:

- `provider_family`
- `implementation_state`
- `transports`
- `limitations`
- `operation_capabilities`

For Phase 5, `operations` should be derived from or kept consistent with
`operation_capabilities`. Tests should fail if a provider advertises an
operation in one field but not the other.

The registry should continue to list local implemented providers:

- `local-artifacts`
- `local-prereqs`
- `local-kernel-build`
- `local-libvirt-qemu`
- `local-ssh-tests`
- `local-qemu-gdbstub`

Phase 5 should add in-repo stub providers for future families with these
provider names:

- `remote-build-stub`
- `remote-artifact-sync-stub`
- `reservation-stub`
- `provisioning-stub`
- `hardware-control-stub`
- `console-access-stub`
- `real-boot-stub`

These providers should advertise future operations and dependencies, but their
implementation state must clearly mark them as stubs.

## Plugin Loading Boundary

The architecture spec calls for plugin loading mechanics. Phase 5 should
satisfy that requirement with a static in-repo declaration boundary, not dynamic
external package loading.

Add a small plugin declaration model named `ProviderPluginSpec` with:

- plugin name
- plugin version
- implementation state
- provider capability factories
- optional documentation paths
- limitations

`ProviderRegistry.with_defaults()` should load built-in provider plugin specs
from in-repo Python objects. It should not scan entry points, import modules by
string from user config, read plugin manifests from arbitrary paths, or execute
third-party package code.

This creates a migration path for later dynamic plugins while keeping Phase 5
safe and deterministic. Future dynamic loading can reuse the same declaration
shape after adding trust, versioning, and compatibility checks.

## Provider Contracts

Phase 5 should add typed request and result models for future provider
families in `src/linux_debug_mcp/providers/contracts.py`. If a later phase
adds real implementations and the module becomes too large, it can be split
without changing the public MCP tool surface.

Contracts should be separated by provider family rather than collapsed into one
large interface:

- `RemoteBuildRequest` and `RemoteBuildResult`
- `RemoteArtifactSyncRequest` and `RemoteArtifactSyncResult`
- `ReservationRequest` and `ReservationResult`
- `ProvisioningRequest` and `ProvisioningResult`
- `HardwareControlRequest` and `HardwareControlResult`
- `ConsoleSessionRequest`
- `ConsoleReadRequest` and `ConsoleReadResult`
- `ConsoleWriteRequest` and `ConsoleWriteResult`
- `RealBootRequest` and `RealBootResult`

Each request should include the common fields needed for provider selection and
safe diagnostics:

- provider name when explicitly selected
- architecture
- profile name or target name
- timeout
- safe operation label
- optional run ID or artifact references where relevant

Each result should allow future external IDs without requiring them in Phase
5. Examples include reservation IDs, remote build job IDs, provisioning task
IDs, power operation IDs, console session IDs, and external artifact bundle
IDs. Stub results should leave these unset.

The contract models should be Pydantic models, consistent with existing domain
and configuration models. Phase 5 should accept `x86_64` and `ppc64le` as
known architecture labels for future-facing contracts, while implemented local
workflows continue to support only their current x86_64 paths. The models
should reject empty provider names, unknown architecture strings, invalid
timeout values, unsafe labels, and malformed operation-specific inputs before a
provider is invoked.

Provider selection should be deterministic:

1. If a request includes `provider_name`, select exactly that provider or return
   `configuration_error`.
2. If a request omits `provider_name`, select the single stub provider that
   advertises the requested operation and architecture.
3. If zero or multiple providers match, return `configuration_error` with the
   candidate provider names when any exist.
4. Never fall back from an explicitly selected provider to a different provider.

Phase 5 should not add future provider profile models to the main server
configuration. The future-facing contracts should carry only request-scoped
profile labels such as `profile_name`, `target_name`, or `reservation_pool`.
Those labels are validated as safe identifiers but are not resolved to real
external systems until a later phase adds real providers.

## MCP Tool Surface

Phase 5 should add these callable MCP tools:

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

Each tool should return the existing `ToolResponse` shape. Valid future
requests should return `ErrorCategory.NOT_IMPLEMENTED`. Malformed requests,
unknown providers, unsupported architecture/profile combinations, or invalid
operation inputs should return `ErrorCategory.CONFIGURATION_ERROR`.

Stub tools should not create run workspaces. There is no real workflow evidence
to preserve yet, and creating failed run state for non-operational future paths
would make pilot runs harder to reason about.

`workflow.reserve_provision_boot` should validate its request and then
short-circuit to a single `not_implemented` response. It should not create a
run, request a reservation, prepare provisioning state, issue hardware control,
or call the individual stub handlers in sequence. This prevents a future-facing
workflow stub from producing confusing partial progress.

Minimum request fields should be explicit in the contract tests:

- `remote.build_kernel`: `architecture`, `source_ref`, `build_profile`
- `remote.sync_artifacts`: `architecture`, `external_artifact_ref`
- `reservation.request_host`: `architecture`, `reservation_pool`
- `reservation.release_host`: `architecture`, `reservation_id`
- `provision.prepare_target`: `architecture`, `target_name`,
  `provisioning_profile`
- `hardware.power_control`: `architecture`, `target_name`, `action`
- `hardware.boot_kernel`: `architecture`, `target_name`, `kernel_artifact_ref`
- `console.open_session`: `architecture`, `target_name`, `access_method`
- `console.read`: `architecture`, `console_session_id`, `max_bytes`
- `console.write`: `architecture`, `console_session_id`, `data`
- `workflow.reserve_provision_boot`: `architecture`, `reservation_pool`,
  `target_name`, `provisioning_profile`, `kernel_artifact_ref`

## Stub Provider Behavior

Stub providers must fail before external side effects.

They must not:

- read credential files
- open network sockets
- invoke subprocesses
- create or modify libvirt domains
- touch serial devices
- create reservation jobs
- create provisioning jobs
- power on, power off, or reboot hardware
- write runtime files or artifacts for stub-only tool calls

The allowed behavior is:

1. Validate request shape.
2. Select the advertised stub provider.
3. Return a stable `not_implemented` response for valid requests.

An example response is:

```json
{
  "ok": false,
  "status": "failed",
  "error": {
    "category": "not_implemented",
    "message": "provider remote-build-stub does not implement remote.build_kernel",
    "details": {
      "provider_name": "remote-build-stub",
      "operation": "remote.build_kernel",
      "architecture": "ppc64le",
      "implementation_state": "stub"
    }
  },
  "suggested_next_actions": ["providers.list"]
}
```

The exact wording may vary, but the category and details keys should remain
stable enough for agents to branch on.

## Secrets And Response Redaction

Future-facing requests should follow the existing secret-reference policy even
though providers are stubs. Contracts may include credential reference fields
such as `credential_ref`, `ssh_key_ref`, `bmc_credential_ref`, or
`reservation_token_ref`, but they must not accept raw secret values.

Stub responses and validation errors must not echo high-risk request payloads.
In particular, they should not include raw values for:

- console write data
- reservation tokens or credential material
- SSH private key paths when represented as secret references
- BMC, HMC, or IPMI credential values
- environment variables
- command text intended for future remote execution

Handlers should pass future-facing `ToolResponse` data through the existing
redaction path before returning it. Error details should prefer stable labels,
field names, provider names, operation names, architecture, and documentation
paths over raw request content.

## Data Flow

Future-facing stub operations should follow this flow:

```text
MCP tool request
  -> Pydantic request validation
  -> provider selection from capability metadata
  -> stub provider returns stable not_implemented
  -> MCP handler returns ToolResponse with suggested next actions
```

This is intentionally simpler than the local run flow. Stub operations do not
write manifests, collect artifacts, or mutate target state.

## ppc64le Design Spike

Phase 5 should add a ppc64le design spike document under `docs/`. The spike
should not promise implementation. It should identify the contract and
capability gaps that real ppc64le support will need.

The spike should cover:

- expected kernel image and build artifact differences
- likely remote build needs
- boot firmware and kernel argument differences
- PXE/NIM provisioning assumptions
- HMC/IPMI/BMC control expectations
- serial console expectations
- libvirt/QEMU versus real hardware boundaries
- debug limitations and likely differences from local x86_64 QEMU gdbstub
- artifact identity requirements for matching kernel, config, and symbols

The provider capability listing or README should point to this spike so agents
can understand why ppc64le appears in stub metadata but is not executable.

## Error Handling

Phase 5 should use existing error categories:

- `configuration_error` for malformed inputs, unknown profiles, unknown
  providers, unsupported request combinations, or unsafe values
- `not_implemented` for valid future operations that are intentionally stubbed

Stub errors should include:

- provider name
- operation
- architecture when provided
- implementation state
- reason the operation is unavailable

Suggested next actions should include `providers.list`. When the ppc64le spike
is relevant, responses should also include the documentation path.

## Testing Strategy

Tests should focus on contract and safety behavior:

- provider capability metadata includes implemented local providers and Phase
  5 stub providers
- `providers.list` exposes implementation state and future operation metadata
- all new MCP tools are registered
- malformed requests return `configuration_error`
- valid future requests return `not_implemented`
- stub tools do not create run workspaces
- stub providers do not invoke subprocesses, network calls, serial access, or
  filesystem writes outside normal test fixtures
- ppc64le appears only in future-facing metadata and documentation, not in
  implemented local workflow behavior
- existing Phase 0-4 tests continue to pass unchanged

Unit tests should use direct handler calls where possible. Tool registration
tests should verify FastMCP exposes the new names. No Phase 5 test should
require libvirt, QEMU, gdb, SSH, remote hosts, reservation services, serial
devices, HMC, IPMI, BMC, PXE, or NIM.

## Documentation

README updates should explain that Phase 5 adds discoverable future provider
surfaces, not operational remote or hardware support. The docs should make clear
that the local x86_64 pilot remains the only implemented end-to-end path.

`providers.list` documentation should explain implementation states so agents
can distinguish safe local workflows from future stubs.

## Acceptance Criteria

Phase 5 is complete when:

1. `providers.list` shows implemented local providers and in-repo stub
   providers with clear implementation states.
2. Built-in provider plugin specs register local and stub provider capability
   factories without dynamic external imports.
3. The new future-facing MCP tools are callable.
4. Valid future-facing tool requests return stable `not_implemented` responses.
5. Malformed future-facing tool requests return stable `configuration_error`
   responses.
6. Stub tools do not create run workspaces or perform external side effects.
7. Typed provider contracts exist for the future provider families.
8. A ppc64le design spike is documented.
9. Existing local build, boot, test, artifact, and debug tests continue to pass.
