# Phase 3 Smoke Tests And Artifacts Design

Date: 2026-05-23

## Purpose

Phase 3 completes the first non-debug pilot workflow after boot: run smoke
tests inside a booted guest, collect the important evidence from the run
workspace and guest, and expose a single `workflow.build_boot_test` tool that
performs the build, boot, test, and collection sequence.

The phase is SSH-first. Guest command execution uses SSH. Serial remains a
boot-readiness and evidence source in this phase, not an interactive command
transport. This avoids brittle serial login automation while still preserving
console output and readiness evidence for debugging failed runs.

## Scope

Phase 3 includes:

- `TestSuiteProfile` configuration for named smoke suites.
- SSH access fields on `RootfsProfile` needed for guest command execution.
- `target.run_tests` handler and MCP tool implementation.
- A local SSH test provider with injectable runner interfaces.
- Named smoke suite execution and ad hoc command execution.
- Per-command stdout, stderr, exit status, elapsed time, timeout, and summary
  capture.
- Guest `dmesg` collection through SSH after test execution.
- Bounded, redacted snippets in MCP responses.
- `artifacts.collect` handler and MCP tool implementation.
- Artifact bundle summary generation from manifest results and files already
  present in the run workspace.
- `workflow.build_boot_test` orchestration over the existing `kernel.build`,
  `target.boot`, new `target.run_tests`, and new `artifacts.collect` handlers.
- Manifest updates for `run_tests` and `collect_artifacts` steps.
- Idempotency for succeeded test and collection steps, with explicit rerun
  flags.
- Unit tests using fake SSH runners and existing fake providers.
- README/demo documentation for the pilot flow.

Phase 3 does not include:

- Serial command execution or serial login automation.
- Rootfs creation, package injection, or SSH key installation.
- Parallel or distributed test execution.
- Long-running test orchestration.
- Live debug, gdbstub, or gdb integration.
- vmcore or crash dump analysis.
- ppc64le, remote hosts, PXE/NIM, HMC/IPMI, or real hardware provisioning.

## Recommended Approach

Use a small SSH test provider and keep orchestration in handlers.

The `target.run_tests` handler should own run validation, immutable profile and
suite checks, idempotency, locking, and MCP response shaping. The SSH provider
should own guest command planning, SSH argv construction, timeout handling,
output capture, and test summary writing. This follows the Phase 1 and Phase
2 pattern: handlers coordinate durable run state, providers perform one concrete
operation behind fakeable boundaries.

`artifacts.collect` should not recrawl arbitrary host paths. It should collect
from known run subdirectories and from artifact references already recorded in
manifest step results. Guest-side collection in Phase 3 is limited to `dmesg`,
captured by the SSH test provider as part of `target.run_tests`.

## Profile Model

Phase 3 should add a small `TestSuiteProfile` model and a command model.

`TestCommand` should support:

- `name`: stable, filesystem-safe command label used in artifact paths.
- `argv`: non-empty ordered command arguments.
- `timeout_seconds`: optional per-command timeout override.
- `required`: whether a nonzero exit or timeout fails the `run_tests` step.

`TestSuiteProfile` should support:

- `name`: stable profile key.
- `commands`: ordered list of `TestCommand` entries.
- `timeout_seconds`: per-command timeout.
- `stop_on_failure`: whether to stop after the first failing command.
- `collect_dmesg`: whether to run `dmesg` after commands.

Commands should be represented as argv lists in configuration and MCP requests.
OpenSSH still executes the remote command through the user's login shell, so the
provider must not claim end-to-end shell-free execution. The provider should
construct a single remote command string by POSIX-quoting each argv element with
`shlex.quote()` and passing the local SSH invocation with `shell=False`:

```text
ssh <options> <user>@<host> -- '<quoted remote command>'
```

This keeps command intent structured, avoids local shell expansion, and makes
the remote-shell boundary explicit. If a suite needs shell semantics such as
pipes or redirection, it must use an explicit command such as
`["sh", "-lc", "..."]` in the profile.

`RootfsProfile` should grow the SSH fields needed by the local provider:

- `ssh_host`: host or address reachable from the MCP server.
- `ssh_port`: guest SSH port, default `22`.
- `ssh_user`: guest user name.
- `ssh_key_ref`: optional secret reference to a private key.
- `ssh_options`: validated additional SSH options, stored as key/value pairs.

The provider should reject SSH test execution when the selected rootfs profile
does not declare `access_method` as `ssh` or `ssh_and_serial`.

Phase 3 uses statically configured SSH reachability. It does not discover guest
IP addresses from libvirt leases, parse console output for addresses, or create
host port forwards. If `ssh_host` is absent, the provider fails with
`configuration_error` and points the caller to the rootfs profile.

Phase 3 should allow only these profile-owned SSH options:

- `ConnectTimeout`
- `IdentitiesOnly`
- `LogLevel`
- `StrictHostKeyChecking`

Allowed values are constrained:

- `ConnectTimeout`: integer seconds between 1 and the command timeout.
- `IdentitiesOnly`: `yes` or `no`.
- `LogLevel`: `ERROR`, `QUIET`, or `VERBOSE`.
- `StrictHostKeyChecking`: `accept-new` or `yes`.

The provider should always set these provider-owned options:

- `BatchMode=yes`
- `ConnectTimeout=<min(command timeout, 10)>` when the profile omits
  `ConnectTimeout`
- `StrictHostKeyChecking=accept-new` when the profile omits
  `StrictHostKeyChecking`
- `UserKnownHostsFile=<run>/target/known_hosts`

These defaults prevent password prompts, bound connection setup, avoid writing
to the developer's personal `known_hosts`, and still detect changed host keys
after the first connection for a run. `BatchMode` and `UserKnownHostsFile` are
not profile-overridable in Phase 3. Unknown options, invalid option values,
empty option names, and option names containing whitespace or control characters
are `configuration_error`.

## Default Smoke Suite

The default pilot smoke suite should be named `smoke-basic` and contain these
required commands:

1. `["uname", "-a"]`
2. `["test", "-r", "/proc/version"]`
3. `["cat", "/proc/cmdline"]`

The suite default timeout is 30 seconds per command, `stop_on_failure=true`, and
`collect_dmesg=true`. This suite proves that SSH command execution works, the
guest exposes normal procfs state, and the captured kernel command line can be
compared with the boot plan.

## SSH Test Provider

Add a provider, initially named `local-ssh-tests`, responsible for:

- validating rootfs SSH access settings
- checking required host tools, initially `ssh`
- planning suite and ad hoc command execution
- writing one output file per command
- recording command metadata without embedding secret values
- running optional `dmesg`
- writing `summaries/test-summary.json`
- returning a structured result with artifact references

The provider should use an injectable runner:

- `which(command)`: host tool discovery
- `run(argv, timeout, stdout_path, stderr_path)`: command execution

The default runner should use `subprocess.run()` with `shell=False`, bounded
timeouts, and separate stdout/stderr capture. Tests should use fake runners to
simulate success, failure, missing SSH, timeouts, and mixed command results.

SSH private keys and other credentials must be passed by reference. The provider
may include a key file path in argv only after redaction has a chance to mask it
from returned snippets and summaries. Raw key contents must never be read into
the manifest, summaries, or MCP responses.

`dmesg` collection is diagnostic, not a smoke-test assertion, in Phase 3. If
the configured suite has `collect_dmesg=true` and `dmesg` exits nonzero because
of guest permissions or kernel restrictions, `target.run_tests` should still use
the required smoke command results to decide pass/fail. The dmesg failure should
be recorded in the test summary with stdout, stderr, exit status, and an
artifact reference when output files were created.

## Test Execution Behavior

`target.run_tests` accepts:

- `run_id`
- `artifact_root`, defaulting to the server default
- optional `test_suite`, defaulting to the immutable run manifest request or a
  default smoke suite
- optional `commands`, an ad hoc ordered list of argv lists
- `force_rerun`, default `false`

The handler must validate:

1. the run exists
2. the boot step succeeded
3. the selected test suite matches the immutable run request when the run
   declared one
4. the rootfs profile supports SSH access
5. ad hoc commands are non-empty argv lists and contain no control characters

If both a named suite and ad hoc commands are provided, the handler should run
the named suite first and then the ad hoc commands. Ad hoc commands are treated
as required and get generated labels such as `adhoc-001`. If neither is provided
and the run has no suite, the handler should use the default pilot smoke suite.

Idempotency rules:

- A succeeded `run_tests` result is returned as recorded unless
  `force_rerun=true`.
- A failed `run_tests` result may be retried.
- A running `run_tests` result returns a structured running response while the
  test lock is held by another process.
- `force_rerun=true` replaces a succeeded `run_tests` result but does not delete
  prior test artifacts; new output files must be written under the next
  `tests/attempt-NNN/` directory.

The step succeeds only when all required commands exit zero. Optional commands
may fail and be reported in the summary without failing the step.

The artifact store should add a `tests_lock(run_id)` that follows the existing
build and boot lock pattern. Stale recorded `running` test steps may be converted
to failed only after the caller acquires the tests lock, because lock ownership
is the only Phase 3 evidence that no other local process is still writing test
artifacts.

## Artifact Layout

Phase 3 should write test and collection artifacts under the existing run
layout:

```text
<artifact-root>/<run-id>/
  tests/
    attempt-001/
      001-uname/
        stdout.txt
        stderr.txt
        command.json
      002-smoke/
        stdout.txt
        stderr.txt
        command.json
      dmesg.txt
  summaries/
    test-summary.json
    artifact-bundle.json
```

Expected test artifact kinds:

- `test-stdout`
- `test-stderr`
- `test-command-metadata`
- `dmesg`
- `test-summary`

Expected collection artifact kinds:

- `artifact-bundle`
- required build artifacts: `build-log`, `kernel-config`, `kernel-image`
- optional build artifacts: `vmlinux`
- required boot artifacts: `domain-xml`, `boot-plan`, `console-log`, `boot-log`
- existing test artifacts from the latest `run_tests` result

`artifacts.collect` should write a machine-readable bundle with:

- `run_id`
- collected timestamp
- selected profiles
- step statuses and summaries
- artifact references grouped by step
- missing expected artifacts
- optional expected artifacts that were absent
- cleanup state
- concise pass/fail rollup

It should not copy large artifacts in Phase 3. The bundle is an index over the
durable run workspace and manifest references.

Required artifact checks are step-aware. For each step that has a recorded
`succeeded` result, `artifacts.collect` should verify that every artifact
reference recorded by that step still exists. For each step that has a recorded
`failed` result, collection should include whatever artifacts the failed step
recorded and list missing references, but missing files from a failed step do
not make collection fail. Pending, skipped, and absent steps are listed by
status and do not create required artifact expectations. Missing required
artifacts from succeeded steps make `artifacts.collect` fail with
`infrastructure_failure` because the bundle cannot prove a previously successful
step. Missing optional artifacts are listed in the bundle but do not fail
collection.

Collection idempotency rules:

- A succeeded `collect_artifacts` result is returned as recorded unless
  `force_recollect=true`.
- `force_recollect=true` rewrites `summaries/artifact-bundle.json` from the
  current manifest and current filesystem evidence.
- A failed `collect_artifacts` result may be retried.
- Collection uses a `collect_lock(run_id)` so two callers cannot write the
  bundle concurrently.

## Workflow Behavior

`workflow.build_boot_test` accepts:

- `source_path`
- `build_profile`
- `target_profile`
- `rootfs_profile`
- optional `run_id`
- optional `test_suite`
- optional ad hoc `commands`
- `artifact_root`
- `force_rebuild`, initially passed through to `kernel.build`
- `force_reboot`, passed through to `target.boot`
- `force_rerun_tests`
- `force_recollect`

The workflow should:

1. create a run when `run_id` is omitted or the run does not exist
2. load an existing run when `run_id` is supplied and exists
3. call `kernel.build`
4. call `artifacts.collect` and return the build failure if build fails
5. call `target.boot`
6. call `artifacts.collect` and return the boot failure if boot fails
7. call `target.run_tests`
8. call `artifacts.collect` even when tests fail, so failed-run evidence is
   indexed
9. return a concise workflow summary with artifact bundle path

When `run_id` is supplied and already exists, the workflow must compare the
existing manifest request with the supplied source path, build profile, target
profile, rootfs profile, and test suite. Any mismatch is a
`configuration_error`; the workflow must not reinterpret an existing run ID as a
new request. When `run_id` is supplied and does not exist, creation uses that
exact run ID after the normal run ID validation.

The workflow should not hide intermediate failure details. The final response
should include the failing step, its error category, the latest successful step,
and suggested next actions.

## MCP Responses

Successful `target.run_tests` responses include:

- `ok: true`
- `status: succeeded`
- `run_id`
- concise test summary
- command result counts
- bounded stdout/stderr snippets
- artifact references
- suggested next action: `artifacts.collect`

Failed `target.run_tests` responses include:

- `ok: false`
- `status: failed`
- `error.category` as `test_failure`, `missing_dependency`,
  `configuration_error`, or `infrastructure_failure`
- failing command metadata
- bounded output snippets
- artifact references
- suggested next action: `artifacts.collect`

`artifacts.collect` responses include the artifact bundle reference and a
pass/fail rollup. Long logs remain on disk.

## Safety And Redaction

Phase 3 must preserve the existing safety posture:

- local SSH argv lists are planned without shell expansion
- remote SSH commands are POSIX-quoted from argv lists before crossing the
  remote shell boundary
- SSH options are validated as simple option names and values
- only the explicitly listed SSH options are accepted
- credential references are recorded by reference, never by value
- returned snippets are redacted before entering MCP responses
- summaries avoid raw secret-bearing values
- full stdout/stderr artifacts are treated as normal artifacts unless a profile
  marks them sensitive in a later phase

The first redaction tests should include fake SSH key paths, fake tokens in
command output, and environment-like strings in stdout/stderr.

## Testing Strategy

Unit tests should cover:

- `TestSuiteProfile` validation
- rootfs SSH profile validation
- SSH argv planning with and without key references
- rejection of unknown SSH options
- missing `ssh`
- successful command execution
- command failure with `stop_on_failure=true`
- command failure with optional commands
- timeout behavior
- dmesg collection success and failure
- default `smoke-basic` suite behavior
- test artifact layout
- `target.run_tests` idempotency and `force_rerun`
- `artifacts.collect` bundle contents
- `workflow.build_boot_test` success and each failure boundary
- redaction of snippets and summaries

No default test should require libvirt, QEMU, SSH connectivity, or a Linux
guest. Any real guest smoke test should be opt-in and skipped unless explicit
environment variables identify the guest access settings.

## Documentation

The README and Fedora user guide should document:

- required guest SSH expectations
- how to choose or prepare a rootfs that allows SSH login
- default smoke suite behavior
- sample `kernel.create_run`, `kernel.build`, `target.boot`,
  `target.run_tests`, `artifacts.collect`, and `workflow.build_boot_test`
  calls
- where to find test output, dmesg, console logs, and bundle summaries

The docs should state clearly that Phase 3 does not install SSH keys or mutate
the rootfs to enable login.
