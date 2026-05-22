# Sprint 0 Foundation Design

Date: 2026-05-22

## Purpose

Sprint 0 establishes the Python project foundation for the Linux Debug MCP
server. It creates testable contracts and a runnable, non-destructive MCP
skeleton before local kernel build, libvirt boot, smoke test, and live debug
providers are implemented in later sprints.

The sprint should make future work predictable: runs have durable state,
artifacts have a stable layout, providers register capabilities through a small
interface, host checks report actionable dependency gaps, and MCP responses use
the same structured shapes that later workflow tools will return.

## Scope

Sprint 0 includes:

- Python package and test harness.
- `pyproject.toml` with package metadata, console entry points, runtime
  dependencies, and test dependencies.
- MCP server entrypoint with foundational tools and explicit stubs for later
  workflow tools.
- Configuration and domain models for profiles, runs, artifacts, providers,
  steps, policies, and summaries.
- Static provider registry basics.
- Per-run artifact workspace creation and manifest persistence.
- Step state and idempotency policy for retrying completed steps.
- Secret-reference model and redaction helpers.
- Pilot host prerequisite checks.
- Structured logging setup.
- Initial developer and user-facing docs for the foundation.

Sprint 0 does not include:

- Running kernel builds.
- Applying kernel config fragments.
- Creating or modifying libvirt domains.
- Booting QEMU guests.
- Opening SSH or serial guest sessions.
- Attaching gdb to a QEMU gdbstub.
- Collecting real VM artifacts.

Later-sprint MCP tools may exist as explicit stubs, but they must return stable
`not_implemented` errors rather than fake success.

## Recommended Approach

Use a foundation library with MCP tool stubs.

This approach keeps Sprint 0 useful without overstating functionality. The MCP
server can start, create run workspaces, inspect host prerequisites, and expose
the public tool names, while implementation-sensitive operations return typed
errors until their providers exist. Domain, manifest, provider, safety, and
artifact contracts are tested as real behavior from the beginning.

## Architecture

### Technology Choices

Sprint 0 should make enough dependency choices for the implementation plan to be
directly executable:

- Python 3.11 or newer.
- `pyproject.toml` using `setuptools` package discovery with a `src/` layout.
- Pydantic v2 for configuration, domain, manifest, and response models.
- The Python MCP SDK package imported as `mcp` for the server implementation.
- `pytest` for unit tests.
- Standard-library `logging` with JSON-friendly structured fields; no external
  logging dependency in Sprint 0.

Dependency versions should be pinned with lower bounds in `pyproject.toml` and
kept narrow enough that a fresh editable install exercises the same dependency
families used during development. The implementation plan may choose exact
minimum versions, but it must not leave the MCP SDK, model framework, or test
runner implicit.

### Package Layout

The implementation should use a `src/` layout:

```text
pyproject.toml
README.md
src/linux_debug_mcp/
  __init__.py
  config.py
  domain.py
  server.py
  artifacts/
    __init__.py
    store.py
    manifest.py
  providers/
    __init__.py
    base.py
    registry.py
  safety/
    __init__.py
    paths.py
    redaction.py
    secrets.py
  prereqs/
    __init__.py
    checks.py
  logging.py
tests/
```

Tests should mirror these boundaries under `tests/`.

### Configuration Models

Configuration models describe the requested workflow without performing it.
They should be strict enough to reject ambiguous or unsafe inputs early.

Core models:

- `ServerConfig`: artifact root, default profiles, logging level, and safety
  defaults.
- `BuildProfile`: name, architecture, build output policy, optional config
  fragments, command timeout, and required tools.
- `RootfsProfile`: name, source reference, mutability policy, access method,
  credential references, readiness marker, and guest writable paths.
- `TargetProfile`: name, architecture, provider name, libvirt domain name or
  future target reference, kernel args, timeout policy, cleanup policy, and
  debug-gdbstub setting.
- `DebugProfile`: name, enabled operations, gdbstub endpoint, KASLR policy,
  symbol identity requirements, and evaluation mode.
- `ArtifactPolicy`: retention, raw-log sensitivity, redaction behavior, and
  failed-run preservation.

The first config loader may be small, but the model layer must not assume that
all providers are local or x86_64-only.

### Domain Models

Domain models form the stable vocabulary used by the orchestrator, providers,
artifacts, and MCP responses.

Core models:

- `KernelSource`
- `BuildArtifact`
- `RunRequest`
- `RunRecord`
- `RunStep`
- `StepResult`
- `ProviderCapability`
- `ProviderDependency`
- `ArtifactRef`
- `ArtifactBundle`
- `PrerequisiteCheck`
- `ToolResponse`

Run and step status values are:

- `pending`
- `running`
- `succeeded`
- `failed`
- `skipped`
- `canceled`

Error categories are:

- `configuration_error`
- `missing_dependency`
- `build_failure`
- `boot_timeout`
- `readiness_failure`
- `test_failure`
- `debug_attach_failure`
- `infrastructure_failure`
- `not_implemented`

### MCP Response Contract

Every MCP tool returns a JSON-serializable response envelope. Tool-specific
fields live under `data` so the common contract stays stable as tools are added.

Success responses include:

- `ok: true`
- `status`: `succeeded`, `skipped`, or another non-error step status when the
  operation is state-reporting rather than mutating.
- `run_id` when the operation is run-scoped.
- `summary`: a concise human-readable result.
- `data`: tool-specific structured data.
- `artifacts`: redacted artifact references relevant to the result.
- `suggested_next_actions`: concise next MCP calls or operator actions.

Error responses include:

- `ok: false`
- `status: failed`
- `run_id` when available.
- `error.category` using the domain error categories.
- `error.message`.
- `error.details` with redacted diagnostic data.
- `suggested_next_actions`.

All response envelopes must be serializable through the same Pydantic model
family used for manifests and domain objects. Long logs, raw command output, and
secret-bearing values stay on disk as artifacts and are represented by redacted
references or short redacted snippets.

### Provider Registry

Sprint 0 implements a static registry with named providers and declared
capabilities. Providers do not need to build, boot, test, or debug yet. They do
need to advertise enough metadata for validation and future selection.

Provider capability declarations include:

- Provider name and version.
- Supported architecture.
- Supported target kind: local, remote, virtual, or physical.
- Supported operations.
- Required host tools.
- Destructive permissions.
- Access methods.
- Whether operations are idempotent, retryable, cancelable, and safe to run
  concurrently.

The registry API should make later entry-point or module-based plugin loading
possible without changing the MCP tool surface.

### Artifact Store And Manifest

Every run gets a durable directory under the configured artifact root:

```text
<artifact-root>/<run-id>/
  manifest.json
  inputs/
  logs/
  build/
  target/
  tests/
  debug/
  summaries/
  sensitive/
```

`manifest.json` is the source of truth for run state. It records immutable
inputs, selected profiles, provider choices, step state, command metadata,
produced artifacts, cleanup state, and summary paths.

Sprint 0 only needs to create the layout, persist the manifest, reload it, and
record step results. The idempotency rule is:

- Retrying a completed step returns the recorded result.
- Retrying a failed or canceled step requires an explicit retry policy in later
  orchestration code.
- Retrying a `running` step returns the recorded in-progress state unless a
  stale-lock policy proves that the prior writer is gone. Sprint 0 only records
  the state and must not auto-recover stale running steps.
- Sprint 0 foundational tools must not silently overwrite a completed step
  result.

Manifest writes must be safe under duplicate MCP calls from the same agentic
session:

- Generate run IDs with enough entropy to avoid accidental collisions.
- Refuse caller-supplied run IDs that already exist unless the caller explicitly
  asks to read the existing run.
- Write manifest updates through a temporary file followed by an atomic rename.
- Use a per-run lock file for manifest mutation inside a single host filesystem.
- Record schema version and writer version in every manifest.
- Treat invalid JSON, unknown schema versions, and partial manifests as
  `infrastructure_failure` or `configuration_error` responses with the original
  file preserved for investigation.

### Secret References And Redaction

Secrets are represented by references, not values. A secret reference may point
to a local file path, environment variable name, or future external secret
manager key. Manifests and MCP responses record the reference type and label,
not the secret content.

The redaction layer should handle:

- Exact fake secret values supplied by tests.
- Key-value patterns such as passwords, tokens, and private key material.
- Command line and environment captures.
- Log snippets and MCP response snippets.

Raw secret-bearing artifacts are only allowed when an artifact policy explicitly
permits them. Such artifacts are stored under `sensitive/` and marked sensitive
in the manifest.

### Path Safety

Sprint 0 validates host and guest paths before a run is created. Validation is
conservative because later sprints will execute commands and write artifacts
based on these values.

Host path rules:

- Resolve `~`, relative segments, and symlinks before comparing paths.
- Require the artifact root to be an existing writable directory or a creatable
  child of an existing writable parent.
- Reject artifact roots that resolve to `/`, the user's home directory, a source
  checkout root, or another configured sensitive path.
- Create run directories only as direct children of the resolved artifact root.
- Reject run IDs containing path separators, `..`, shell metacharacters, control
  characters, or leading dots.
- Treat kernel source paths as read-only inputs in Sprint 0; `kernel.create_run`
  may verify tree markers but must not write into the source checkout.
- Validate file-based secret references for path shape and existence when
  requested, but never read or copy the secret value during prerequisite checks
  or manifest creation.

Guest path rules:

- Guest writable paths must be absolute POSIX paths.
- Reject guest paths containing `..`, empty components, shell metacharacters, or
  control characters.
- Guest paths are recorded as guest paths only; Sprint 0 must not map them to
  host paths.

Path validation failures use `configuration_error` with the rejected path
redacted when it falls under a secret reference.

### Prerequisite Checks

Sprint 0 includes host prerequisite checks for the pilot environment. Checks
report status and actionable details, but they do not install packages or modify
the host.

Initial checks:

- Python runtime version.
- Python package dependencies.
- Local command availability for `make`, `gcc` or `clang`, `bash`, `git`,
  `qemu-system-x86_64`, `virsh`, and `gdb`.
- Artifact root writability.
- Source checkout path existence and basic Linux tree markers when a source
  path is supplied.
- Libvirt client visibility through a non-destructive command if enabled by
  configuration.

Prerequisite results use statuses:

- `passed`
- `failed`
- `warning`
- `skipped`

Failures include a stable check ID, a concise message, and a suggested fix.

### MCP Tool Surface For Sprint 0

Implemented tools:

- `host.check_prerequisites`: runs non-destructive host checks and returns
  structured results.
- `kernel.create_run`: validates inputs, creates the run workspace, writes the
  manifest, and returns run metadata plus suggested next calls.
- `providers.list`: returns registered providers and capabilities.
- `artifacts.get_manifest`: returns a redacted view of a run manifest.

Stubbed tools:

- `kernel.build`
- `target.boot`
- `target.run_tests`
- `artifacts.collect`
- `workflow.build_boot_test`
- `workflow.build_boot_debug`
- All `debug.*` tools listed in the architecture specification.

Stubbed tools return a structured `not_implemented` error with the sprint that
will implement the tool when known.

### Logging

Logging should be structured and suitable for both command-line development and
MCP-server operation. Sprint 0 logs include run ID when available, tool name,
step name, provider name, status, and duration. Logs must pass through redaction
before being written to normal artifacts or returned in MCP responses.

## Data Flow

The Sprint 0 flow is:

```text
MCP request or CLI invocation
  -> config/domain validation
  -> safety and path checks
  -> provider registry lookup
  -> artifact workspace creation or manifest read
  -> redacted structured response
```

`kernel.create_run` is the first durable workflow boundary. It creates a
manifest with pending steps for later sprints but does not run those steps.

## Error Handling

All public operations return stable structured errors. Exceptions caused by
invalid input, missing host tools, unsafe paths, duplicate run IDs, invalid
manifest state, or unavailable providers should be normalized into the error
categories from the domain model.

Error responses include:

- `run_id` when available.
- `category`.
- `message`.
- `details` with redacted diagnostic data.
- `suggested_next_actions`.

No public response should include raw command output that may contain secrets.

## Testing Strategy

Sprint 0 uses unit tests only. Integration tests that require libvirt, QEMU, a
kernel checkout, or gdbstub access are deferred.

Required tests:

- Config model validation accepts valid pilot profiles and rejects unsafe or
  ambiguous inputs.
- Domain model serialization is stable for run, step, artifact, provider, and
  error objects.
- Provider registry registers providers, rejects duplicate names, and exposes
  capability metadata.
- Artifact store creates the expected directory layout.
- Manifest persistence can write, reload, and refuse silent overwrites of
  completed step results.
- Redaction removes fake secrets from command lines, environment maps, logs, and
  response snippets.
- Secret references serialize without exposing values.
- Path validation rejects unsafe artifact roots, run IDs, source paths, secret
  file references, and guest writable paths.
- Prerequisite checks can be tested with fake command runners.
- MCP tool handlers return the expected structured shapes for implemented and
  stubbed tools, including both success and error response envelopes.

## Acceptance Criteria

Sprint 0 is complete when:

1. The project installs in editable mode.
2. Unit tests pass without requiring libvirt, QEMU, a Linux checkout, or gdb.
3. The MCP server starts.
4. `host.check_prerequisites` returns structured pass/fail/warning/skipped
   checks without modifying the host.
5. `kernel.create_run` creates a durable run directory and manifest.
6. Re-reading a run manifest returns a redacted view.
7. Provider capabilities can be listed.
8. Later-sprint tools return structured `not_implemented` errors.
9. Docs explain how to run tests, start the server, create a run, inspect a
   manifest, and interpret prerequisite failures.

## Out Of Scope Decisions

These decisions remain deferred to later sprint planning:

- Exact kernel build commands and config-fragment application behavior.
- Libvirt domain XML generation strategy.
- Rootfs acquisition or composition.
- Guest readiness implementation.
- SSH and serial command execution.
- Gdb transport implementation.
- Plugin discovery mechanism beyond the static registry.
- CI environment for libvirt/QEMU integration tests.
