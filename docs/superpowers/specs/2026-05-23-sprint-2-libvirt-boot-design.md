# Sprint 2 Libvirt Boot Design

Date: 2026-05-23

## Purpose

Sprint 2 implements the first real target operation for the Linux Debug MCP
server: `target.boot`. The sprint boots a successfully built x86_64 kernel on a
configured local libvirt/QEMU development VM, captures serial console output,
waits for a configured readiness marker, records boot artifacts, and returns a
concise MCP response.

The implementation should be real enough for a configured pilot host to boot a
kernel through libvirt in this sprint. It should also remain testable without
libvirt by putting host command execution and console streaming behind fakeable
provider boundaries.

## Scope

Sprint 2 includes:

- Rootfs and target profile fields needed for local libvirt boot.
- `target.boot` handler and MCP tool implementation.
- A local `LibvirtQemuProvider` for x86_64 virtual targets.
- A host command runner abstraction whose default implementation uses real
  local tools such as `virsh`.
- Domain XML planning for a dedicated MCP-managed development domain.
- Kernel direct boot using the Sprint 1 `kernel-image` artifact.
- Rootfs validation and attachment according to `RootfsProfile`.
- Kernel command-line construction from `TargetProfile`.
- Serial console capture into the run workspace.
- Serial readiness marker detection.
- Boot timeout handling.
- Boot step manifest updates and artifact registration.
- `force_reboot=true` support for rerunning the boot step.
- Unit tests with fake runners and fake console streams.
- Gated local integration test documentation for real libvirt verification.

Sprint 2 does not include:

- SSH readiness.
- Guest command execution or smoke test suites.
- Artifact collection beyond boot artifacts.
- Live debug, gdbstub, or gdb integration.
- Rootfs image building, package injection, or guest customization.
- ppc64le.
- Physical hosts, PXE/NIM, HMC/IPMI, serial concentrators, or PCI passthrough.
- Broad libvirt inventory management.

## Recommended Approach

Use a real libvirt-backed target boot provider with fakeable process boundaries.

The `LibvirtQemuProvider` should plan and execute the local libvirt workflow,
but all host effects should go through narrow interfaces that tests can replace:
host tool lookup, command execution, domain lifecycle commands, and serial
console streaming. The default runner should use real local tools, initially
`virsh`, so Sprint 2 is not merely a planning exercise.

This approach keeps the default test suite deterministic while still delivering
a working pilot path on a configured host. It also matches the Sprint 1 provider
pattern: handlers coordinate manifest state and idempotency, while providers own
operation-specific planning and execution.

## Profile Model

Sprint 0 already introduced `RootfsProfile` and `TargetProfile`. Sprint 2 should
extend those models only where concrete boot behavior needs explicit policy.

`RootfsProfile` should support:

- `name`: stable profile key.
- `source`: host path to an existing root filesystem image or directory.
- `source_type`: `disk_image` for Sprint 2. Directory sources are rejected by
  the local libvirt provider until a later sprint defines a virtiofs, 9p, or
  initramfs-backed attachment contract.
- `mutability`: `read_only`, `copy_on_write`, or `mutable`.
- `access_method`: retained for future SSH/serial test execution.
- `credential_refs`: retained as secret references, not raw values.
- `readiness_marker`: serial marker that proves the guest reached the expected
  state.
- `guest_writable_paths`: retained for later smoke tests.

Sprint 2 should validate that the rootfs source exists and that the selected
mutability policy is supported by the local provider. The provider should
support `read_only` and `mutable` existing `disk_image` sources. It should
reject directory sources and `copy_on_write` with `configuration_error` until a
later sprint implements the required attachment mode or temporary overlay
creation. The provider should not build root filesystems or mutate a read-only
source in place.

For `disk_image` sources, the boot plan must define the guest-visible root block
device name used in both the domain XML and kernel command line, for example
`/dev/vda` for a virtio disk. The plan must fail before starting libvirt if the
profile kernel args already specify a conflicting `root=` value.

`TargetProfile` should support:

- `name`: stable profile key.
- `architecture`: initially `x86_64`.
- `provider_name`: defaulting to `local-libvirt-qemu`.
- `target_ref`: the dedicated libvirt domain name.
- `kernel_args`: profile-owned kernel command-line arguments.
- `timeout_seconds`: maximum time to wait for readiness.
- `cleanup_policy`: `preserve_on_failure` or `stop_on_failure`; controls the
  domain lifecycle after a failed boot attempt.
- `debug_gdbstub`: retained for Sprint 4 and rejected if enabled in Sprint 2.
- `libvirt_uri`: optional URI for the local libvirt connection. The boot plan
  must resolve this to either the profile value or an explicit server default
  before running host commands.
- `managed_domain`: explicit boolean that must be true before the provider
  defines, updates, starts, stops, or destroys the named domain.
- `managed_domain_prefix`: optional deployment-owned prefix. When configured,
  `target_ref` must start with this prefix.

The provider must reject target profiles that do not name a dedicated managed
domain. It must not inspect, redefine, stop, or destroy arbitrary libvirt
domains outside that explicit profile.

## Architecture

### MCP Handler

`target.boot` should follow the Sprint 1 handler pattern:

1. Validate `run_id` and load the manifest.
2. Validate that the manifest has a succeeded `build` step.
3. Locate the `kernel-image` artifact from the build result.
4. Resolve the immutable target and rootfs profiles requested when the run was
   created.
5. Reject profile override attempts for an existing run.
6. Return a recorded succeeded boot result when `force_reboot=false`.
7. Acquire an exclusive boot lock before mutating the target.
8. Record the `boot` step as `running`.
9. Ask the provider to execute the planned boot.
10. Record the terminal boot result.
11. Return a structured `ToolResponse`.

The handler should remain thin. It owns manifest loading, immutable profile
checks, idempotency, lock acquisition, and MCP response shaping. The provider
owns libvirt-specific planning and execution details.

### LibvirtQemuProvider

The local provider should expose small operations rather than one broad hook:

- Validate rootfs and target profile compatibility.
- Check required host tools.
- Build a boot plan.
- Render or generate domain XML for the dedicated domain.
- Define or update the domain.
- Stop or destroy the existing managed domain when `force_reboot=true`.
- Start the domain.
- Capture serial console output to the run workspace.
- Wait for the readiness marker.
- Return boot artifacts and structured metadata.

The default execution path may use `virsh` commands rather than Python libvirt
bindings. Command argv lists should be planned without shell expansion, include
the resolved libvirt connection URI, and be recorded in redacted metadata. The
provider must not rely on `virsh`'s process-default connection. A later
implementation can swap in Python libvirt bindings behind the same provider
boundary if that becomes useful.

Generated XML must include the serial device that the runner will read, the
rootfs disk attachment, and MCP ownership metadata. The ownership metadata should
include at least the provider name, managed domain name, and target profile name.
The current `run_id` may be recorded as diagnostic metadata, but it must not be
the ownership key because one dedicated managed domain can be reused across
multiple runs. If an existing domain with the same name lacks matching MCP
ownership metadata, the provider must fail with `configuration_error` instead of
redefining, starting, stopping, or destroying the domain.

The boot plan must make serial console wiring explicit. The provider should add
or validate kernel arguments for the selected serial device, such as
`console=ttyS0`, and reject conflicting console settings that would prevent the
configured readiness stream from observing boot output.

### Runner Boundary

The provider should use injectable interfaces for host effects:

- `which(command)`: host tool discovery.
- `run(argv, timeout, log_path=None)`: command execution.
- `stream_console(domain, output_path, timeout)`: serial console capture.

Tests can provide fake implementations that simulate success, missing tools,
command failures, timeouts, console output, and early domain exits. The default
runner should call real local tools.

### Artifact Layout

Sprint 2 should write boot artifacts under the existing run layout:

```text
<artifact-root>/<run-id>/
  target/
    domain.xml
    console.log
    boot-plan.json
  logs/
    boot.log
  summaries/
    boot-summary.json
```

The provider should register artifact references for files that exist after the
operation. Expected boot artifact kinds are:

- `domain-xml`
- `serial-console`
- `boot-log`
- `boot-plan`
- `boot-summary`

Console snippets returned through MCP responses must be bounded and redacted.
Full console logs stay on disk as artifacts.

## Data Flow

The normal Sprint 2 flow is:

```text
run manifest
  -> succeeded build result
  -> kernel-image artifact
  -> target/rootfs profile resolution
  -> boot plan
  -> libvirt domain define or update
  -> domain start
  -> serial console capture
  -> readiness marker detection
  -> boot artifacts and summary
```

`target.boot` accepts:

- `run_id`
- `artifact_root`, defaulting to the server default
- optional `target_profile`, which must match the immutable run request if
  supplied
- optional `rootfs_profile`, which must match the immutable run request if
  supplied
- `force_reboot`, default `false`

On success, the MCP response includes:

- `ok: true`
- `status: succeeded`
- `run_id`
- concise boot summary
- artifact references
- structured data with domain name, provider name, rootfs profile, target
  profile, kernel image path, readiness marker, timeout, started and ended
  timestamps, and elapsed time
- suggested next action: `artifacts.get_manifest` until Sprint 3 implements
  `target.run_tests`

On failure, the MCP response includes:

- stable error category
- redacted command and domain metadata
- boot log or serial console artifact references when available
- bounded diagnostic console snippet when available
- suggested fixes or next actions

## Idempotency And State

The `boot` step follows the durable run-state model from Sprint 0, with one
important addition: `force_reboot=true` should be supported in Sprint 2.

Behavior:

- If `force_reboot=false` and a succeeded boot result exists, return the
  recorded result without touching libvirt.
- If `force_reboot=false` and a running boot result exists, return an
  `infrastructure_failure` explaining that boot is already recorded as running
  unless the boot lock and recorded heartbeat prove the prior attempt is stale.
  A stale running step should be marked failed with diagnostic metadata before a
  retry starts.
- If `force_reboot=true`, acquire the boot lock, stop or destroy the dedicated
  managed domain if needed, rotate or preserve prior console evidence, redefine
  the domain, boot again, and record the new result.
- Failed boot results may be replaced by a later successful retry.
- Succeeded boot results are not overwritten unless `force_reboot=true`.

The artifact store should add a per-run boot lock. The initial implementation
may serialize boot operations per run. The design does not assume concurrent
mutation of the same libvirt domain is safe.

When rerunning a boot, prior console evidence should not be overwritten without
retention. A simple acceptable policy is to rename an existing `console.log` to
`console.<timestamp>.log` before writing the new console log and to record both
as artifacts when practical.

Failure cleanup must follow `cleanup_policy`. `preserve_on_failure` leaves a
started managed domain available for manual inspection and records that state in
the boot summary. `stop_on_failure` stops or destroys only the managed domain
after evidence collection. Successful boots should leave the domain running
unless a later sprint adds an explicit shutdown operation.

## Safety

Profiles must make host-affecting behavior explicit.

The provider must require:

- a target profile with an explicit domain name
- `managed_domain=true`
- matching MCP ownership metadata before mutating an existing domain
- a resolved libvirt connection URI from the target profile or server default
- a rootfs source that passes path validation
- a Sprint 2-supported rootfs source type
- a supported rootfs mutability policy
- a supported cleanup policy
- matching build and target architectures
- a successful build result with a `kernel-image` artifact
- non-conflicting `root=` and serial `console=` kernel arguments

The provider must not:

- manage domains that are not named by the target profile
- silently use or mutate unrelated libvirt domains
- mutate an existing domain that lacks matching MCP ownership metadata
- delete rootfs sources
- mutate read-only rootfs profiles in place
- enable gdbstub behavior in Sprint 2
- return unbounded console output through MCP responses

Command metadata, environment captures, and console snippets should pass through
the existing redaction helper before being returned in tool responses.

## Error Handling

Expected error categories:

- `configuration_error`: missing run, missing succeeded build, missing
  `kernel-image`, unsupported provider, unsupported architecture, unsafe rootfs
  path, missing managed domain declaration, unsupported mutability policy,
  unsupported rootfs source type, conflicting `root=` or serial `console=`
  kernel arguments, `copy_on_write` rootfs policy, profile override mismatch,
  missing resolved libvirt URI, existing domain ownership mismatch, unsupported
  cleanup policy, or `debug_gdbstub=true`.
- `missing_dependency`: required host tools such as `virsh` are unavailable.
- `boot_timeout`: the domain starts but the readiness marker does not appear
  before the configured timeout.
- `readiness_failure`: the console stream ends unexpectedly, the domain exits
  early, or the readiness signal is contradictory.
- `infrastructure_failure`: libvirt command failure, filesystem failure, lock
  failure, XML rendering failure, or unexpected runner error.

Provider failures should preserve enough evidence to diagnose the problem:
planned argv lists, redacted command output snippets, domain XML, console logs,
timeout values, timestamps, and selected profile names.

## Provider Capability

Sprint 2 should add a concrete provider capability such as
`local-libvirt-qemu`.

The capability should advertise:

- architecture: `x86_64`
- target kind: `virtual`
- operations: `target.boot`
- required host tools: `virsh`
- destructive permissions: domain define/update/start/stop for the configured
  managed domain with matching MCP ownership metadata
- access methods: `libvirt`, `serial-console`, `filesystem`
- semantics: idempotent when `force_reboot=false`, retryable, destructive only
  for the configured managed domain, not concurrent safe

The registry should replace `target.boot` in the stub provider listing with the
real local libvirt provider while leaving later-sprint tools as stubs.

## Testing Strategy

Default tests should not require libvirt, QEMU, a real rootfs, or a real kernel
build. They should use fake runners and fake console streams.

Required tests:

- Rootfs profile validation for existing paths and supported mutability.
- Directory rootfs sources return `configuration_error` in Sprint 2.
- `copy_on_write` rootfs policy returns `configuration_error`.
- Target profile validation for managed domain requirements.
- Existing domains without matching MCP ownership metadata are rejected before
  destructive operations.
- Ownership metadata allows the same managed domain to be reused by a later run
  with the same target profile.
- Unsupported cleanup policies return `configuration_error`.
- Failure when the run has no succeeded build result.
- Failure when the build result has no `kernel-image` artifact.
- Failure when build and target architectures do not match.
- Failure when `debug_gdbstub=true` is requested in Sprint 2.
- Boot plan generation with kernel image path, rootfs path, domain name, kernel
  args, root block device, serial device, resolved libvirt URI, XML path,
  console log path, timeout, readiness marker, and ownership metadata.
- Planned `virsh` argv includes the resolved libvirt URI instead of relying on
  host defaults.
- Conflicting `root=` or serial `console=` arguments return
  `configuration_error`.
- Missing `virsh` maps to `missing_dependency`.
- Successful fake domain define/start/readiness records artifacts, summary, and
  manifest step result.
- Boot timeout maps to `boot_timeout` and includes console artifacts.
- Console stream early exit maps to `readiness_failure`.
- Libvirt command failure maps to `infrastructure_failure`.
- Repeated successful `target.boot` returns the recorded result without invoking
  the provider again.
- `force_reboot=true` invokes stop or destroy policy, reruns boot, and preserves
  prior console evidence.
- Failure cleanup follows `preserve_on_failure` and `stop_on_failure`.
- Stale `running` boot state can be marked failed and retried after the prior
  lock is gone or expired.
- Concurrent boot calls for the same run use the boot lock so only one fake
  provider execution starts.
- Profile mismatch arguments return `configuration_error`.
- Provider registry lists the local libvirt/QEMU provider for `target.boot`.

Gated integration tests may run when explicitly enabled, for example:

```bash
LINUX_DEBUG_MCP_LIBVIRT_TEST=1 python -m pytest tests/test_libvirt_boot_integration.py
```

Those tests should skip with actionable messages unless the developer supplies
the required rootfs, source/build artifact setup, and libvirt permissions. They
should prove at least one real libvirt boot path without becoming part of the
default test suite.

## Documentation

README updates should explain:

- Sprint 2 can boot a built x86_64 kernel on a configured local libvirt host.
- The developer must provide a known-good rootfs and a dedicated managed domain
  profile, including the Sprint 2-supported rootfs disk image format.
- The server only manages the explicitly configured domain.
- Existing domains are only reused when their MCP ownership metadata matches the
  configured provider and run context.
- Readiness is serial-marker based in Sprint 2.
- SSH, smoke tests, artifact collection, and debug support remain later-sprint
  features.
- How to run the gated libvirt verification path.
- Required environment variables and profile fields for the gated integration
  test.
- How to configure the libvirt URI explicitly for the pilot host.

## Acceptance Criteria

Sprint 2 is complete when:

1. `kernel.create_run`, `kernel.build`, then `target.boot` can boot the built
   x86_64 kernel on a configured local libvirt host.
2. The boot provider only manages the explicitly configured dedicated domain.
3. The provider refuses to mutate existing domains without matching MCP
   ownership metadata.
4. The generated boot plan uses a supported rootfs disk attachment and
   non-conflicting `root=` kernel argument.
5. Host commands use an explicit resolved libvirt URI.
6. The provider captures serial console output into the run artifacts.
7. Readiness succeeds when the configured serial marker appears on the selected
   serial console.
8. Readiness failure and boot timeout produce stable MCP error responses.
9. The manifest records the boot step result and boot artifacts.
10. Repeated `target.boot` calls are idempotent unless `force_reboot=true`.
11. Unit tests cover planning, validation, idempotency, locking, timeout, and
   failure mapping without requiring libvirt.
12. A gated integration test or documented manual verification command proves the
   real libvirt path on an explicitly configured host.
