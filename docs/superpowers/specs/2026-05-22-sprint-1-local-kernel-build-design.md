# Sprint 1 Local Kernel Build Design

Date: 2026-05-22

## Purpose

Sprint 1 implements the first real workflow operation for the Linux Debug MCP
server: `kernel.build`. The sprint adds a local x86_64 kernel build provider
that builds a developer-prepared Linux checkout into the run workspace, records
the resulting build artifacts, and returns a concise MCP response that points to
the durable logs and outputs.

The sprint keeps kernel configuration developer-owned. The build provider
chooses how to execute and record the build; it does not silently choose kernel
features, run default configuration targets, or mutate configuration policy.

## Scope

Sprint 1 includes:

- A local kernel build provider for x86_64.
- `kernel.build` handler and MCP tool implementation.
- Per-run `O=` build output under `<artifact-root>/<run-id>/build/`.
- Build profile fields needed to plan local build commands.
- Config seeding from the developer-prepared source `.config` into the per-run
  build output when needed.
- Local build command planning and execution.
- Build log capture.
- Build artifact detection and registration.
- Manifest updates for the `build` step.
- Provider capability updates for the new local build operation.
- Unit tests and subprocess-fake tests that do not require a real kernel build.
- README updates for Sprint 1 behavior and expected developer setup.

Sprint 1 does not include:

- Libvirt or QEMU boot.
- Root filesystem provisioning.
- SSH, serial, or smoke test execution.
- Live debug or gdbstub support.
- Remote build hosts.
- ppc64le builds.
- Automatic kernel config generation.
- Default application of config fragments.
- Forced rebuild cleanup policy beyond preserving the current successful result.

## Recommended Approach

Use a local provider with per-run `O=` output and optional config seeding from
the source checkout.

This keeps every run isolated and makes build artifacts easy to collect while
preserving the developer's responsibility for kernel configuration. It also
matches the future provider model: a later remote build provider can implement
the same logical build operation by mapping the run workspace to a remote build
workspace and publishing artifacts back to the local artifact store.

## Build Configuration Ownership

The developer prepares the kernel configuration before calling `kernel.build`.
That configuration may match distro defaults, include task-specific changes, or
come from any other normal kernel development workflow.

The local build provider follows these rules:

1. If `<artifact-root>/<run-id>/build/.config` exists, use it.
2. If the per-run `.config` does not exist and `<source>/.config` exists, copy
   `<source>/.config` to `<artifact-root>/<run-id>/build/.config` before
   building.
3. If neither config exists, fail with `configuration_error`.
4. Do not run `defconfig`, `olddefconfig`, `menuconfig`, `localmodconfig`, or
   config fragment application unless a later explicit profile option enables
   that behavior.

The copied source `.config` is a seed. The resulting per-run `.config` is the
build artifact of record for the run.

## Build Profiles

Sprint 0 already has a `BuildProfile` model. Sprint 1 should extend it only as
needed for local build planning while keeping the model future-compatible with
remote providers.

Recommended fields:

- `name`: stable profile key.
- `architecture`: initially `x86_64`.
- `provider_name`: default `local-kernel-build`.
- `output_policy`: default `per_run`.
- `targets`: default pilot target list, initially `["bzImage"]`.
- `command_timeout_seconds`: build timeout.
- `required_tools`: host tools checked before execution.
- `jobs`: optional explicit parallelism.
- `make_variables`: safe string map for profile-owned make variables.
- `config_fragments`: retained as an explicit future option, disabled by
  default unless non-empty and intentionally supported.

The profile controls execution policy. It should not hide host-sensitive
behavior or ad hoc command fragments.

## Command Planning

The local provider plans commands as argv lists rather than shell strings.

The default command shape is:

```bash
make -C <source> O=<run>/build ARCH=x86_64 <targets>
```

If `jobs` is configured, the provider adds `-j<jobs>`. If no `jobs` value is
configured, Sprint 1 omits `-j`. Automatic CPU-count parallelism should be
explicit in the profile design, not hidden in the provider.

The command metadata recorded in the manifest should include:

- argv
- source path
- output path
- architecture
- targets
- selected profile
- start and end timestamps
- timeout
- exit status
- relevant environment overrides

## Artifact Layout

Sprint 1 writes build artifacts under the existing run layout:

```text
<artifact-root>/<run-id>/
  build/
    .config
    arch/x86/boot/bzImage
    vmlinux
  logs/
    build.log
  summaries/
    build-summary.json
```

The provider registers artifact references for the files that exist after a
successful build. The expected initial artifact kinds are:

- `build-log`
- `kernel-config`
- `kernel-image`
- `vmlinux`
- `build-summary`

Missing optional outputs should not make a successful build fail unless the
selected profile declares them required. For the x86_64 pilot profile, `bzImage`
and `.config` should be required. `vmlinux` should be recorded when present and
should become required before Sprint 4 live debug workflows depend on it.

## MCP Tool Behavior

`kernel.build` accepts:

- `run_id`
- `artifact_root`, defaulting to the server default
- optional `force_rebuild`, default `false`

Sprint 1 should implement `force_rebuild=false` behavior fully. If the manifest
already contains a succeeded `build` result and `force_rebuild` is false, the
handler returns the recorded result without rerunning `make`.

If `force_rebuild=true`, Sprint 1 returns `configuration_error` with a clear
message that rebuild cleanup policy is not implemented yet. The design leaves
room for a later explicit policy such as cleaning the per-run build directory,
preserving the prior build under a numbered output path, or requiring a new run.

On success, the MCP response includes:

- `ok: true`
- `status: succeeded`
- `run_id`
- concise build summary
- artifact references
- structured data with profile, architecture, targets, output path, source
  revision, and elapsed time
- suggested next action: `target.boot`

On failure, the MCP response includes:

- stable error category
- redacted command metadata
- log artifact reference when available
- short diagnostic snippet from the build log
- suggested fixes or next actions

## Error Handling

Expected error categories:

- `configuration_error`: missing run, missing profile, unsupported architecture,
  unsafe source path, missing developer-prepared `.config`, unsupported
  `force_rebuild`, or invalid profile settings.
- `missing_dependency`: required host tools are unavailable.
- `build_failure`: `make` exits non-zero.
- `infrastructure_failure`: artifact store, filesystem, timeout management, or
  subprocess execution fails unexpectedly.

Build output can contain secrets from environment or command output, so snippets
returned through MCP responses must pass through the existing redaction helper.
Full logs remain on disk as artifacts.

## Provider Boundary

Sprint 1 should introduce a concrete local provider module rather than putting
build execution directly in the MCP handler. The handler should coordinate:

1. Load manifest.
2. Resolve build profile.
3. Ask the provider to plan and execute the build.
4. Record the provider's `StepResult`.
5. Return a `ToolResponse`.

The provider interface should make future remote implementations possible. It
does not need plugin loading in Sprint 1, but the operation should be expressed
as "build this run with this profile" instead of "run this local shell command."

## Idempotency And State

The `build` step follows the Sprint 0 manifest idempotency rule.

- A succeeded build result is not overwritten on repeat calls.
- Failed build results may be replaced by a later successful retry.
- Running build state should not be auto-recovered in Sprint 1.
- Concurrent builds for the same run are rejected by the manifest lock or an
  equivalent per-run build lock.

Build execution should write enough state that an interrupted run leaves useful
evidence in `logs/build.log` and the manifest can still report the latest known
step result.

## Testing Strategy

Sprint 1 tests should avoid requiring a real Linux kernel build in the default
unit test suite.

Required tests:

- Build profile validation for new fields.
- Command planning for x86_64 per-run `O=` builds.
- Config seeding from source `.config`.
- Failure when no config exists.
- Use of existing per-run `.config` without overwriting it.
- Successful fake subprocess execution records logs, artifacts, summary, and
  manifest step result.
- Non-zero fake subprocess exit returns `build_failure`.
- Missing required host tools returns `missing_dependency`.
- Repeated successful `kernel.build` returns the recorded result without
  invoking subprocess again.
- `force_rebuild=true` returns the explicit unsupported `configuration_error`
  response.
- Provider registry lists the local build provider and no longer represents
  `kernel.build` only as a stub.

Optional gated integration tests may build a tiny prepared kernel tree or run
`make` against a developer-provided checkout when an environment variable opts
in. They must not run in the default test suite.

## Documentation

README updates should explain:

- Sprint 1 can build a prepared local Linux checkout.
- The developer must provide `.config` in the source tree or pre-populate the
  run build directory.
- The default output is `<artifact-root>/<run-id>/build`.
- The build log and summary locations.
- The tool still does not boot or debug kernels until later sprints.

## Acceptance Criteria

Sprint 1 is complete when:

1. `kernel.create_run` followed by `kernel.build` can run against a prepared
   local Linux checkout using the per-run `O=` directory.
2. The build provider preserves developer-owned config behavior and fails
   clearly when no config is available.
3. Build logs, config, kernel image, optional `vmlinux`, and build summary are
   recorded as artifacts.
4. The run manifest records the `build` step result.
5. Repeating `kernel.build` after success returns the recorded result without
   rerunning the build.
6. Unit tests cover command planning, config seeding, error handling,
   idempotency, and MCP response behavior without requiring libvirt or a real
   kernel build.
