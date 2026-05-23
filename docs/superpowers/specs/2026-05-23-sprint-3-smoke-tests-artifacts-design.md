# Sprint 3 Smoke Tests And Artifacts Design

Date: 2026-05-23

## Purpose

Sprint 3 completes the first non-debug pilot workflow after boot: run smoke
tests inside a booted guest, collect the important evidence from the run
workspace and guest, and expose a single `workflow.build_boot_test` tool that
performs the build, boot, test, and collection sequence.

The sprint is SSH-first. Guest command execution uses SSH. Serial remains a
boot-readiness and evidence source in this sprint, not an interactive command
transport. This avoids brittle serial login automation while still preserving
console output and readiness evidence for debugging failed runs.

## Scope

Sprint 3 includes:

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

Sprint 3 does not include:

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
output capture, and test summary writing. This follows the Sprint 1 and Sprint
2 pattern: handlers coordinate durable run state, providers perform one concrete
operation behind fakeable boundaries.

`artifacts.collect` should not recrawl arbitrary host paths. It should collect
from known run subdirectories and from artifact references already recorded in
manifest step results. Guest-side collection in Sprint 3 is limited to `dmesg`,
captured by the SSH test provider as part of `target.run_tests`.

## Profile Model

Sprint 3 should add a small `TestSuiteProfile` model:

- `name`: stable profile key.
- `commands`: ordered list of smoke commands.
- `timeout_seconds`: per-command timeout.
- `stop_on_failure`: whether to stop after the first failing command.
- `collect_dmesg`: whether to run `dmesg` after commands.
- `required`: whether a failed command makes the step fail.

Commands should be represented as argv lists, not shell strings. The first
implementation may run commands through SSH as:

```text
ssh <options> <user>@<host> -- <command argv...>
```

This keeps command planning explicit and avoids local shell expansion. If a
future suite needs shell semantics, it should use an explicit command such as
`["sh", "-lc", "..."]` in the profile.

`RootfsProfile` should grow the SSH fields needed by the local provider:

- `ssh_host`: host or address reachable from the MCP server.
- `ssh_port`: guest SSH port, default `22`.
- `ssh_user`: guest user name.
- `ssh_key_ref`: optional secret reference to a private key.
- `ssh_options`: validated additional SSH options, stored as key/value pairs.

The provider should reject SSH test execution when the selected rootfs profile
does not declare `access_method` as `ssh` or `ssh_and_serial`.

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
the named suite first and then the ad hoc commands. If neither is provided and
the run has no suite, the handler should use the default pilot smoke suite.

Idempotency rules:

- A succeeded `run_tests` result is returned as recorded unless
  `force_rerun=true`.
- A failed `run_tests` result may be retried.
- A running `run_tests` result returns a structured running response while the
  test lock is held by another process.
- `force_rerun=true` replaces a succeeded `run_tests` result but does not delete
  prior test artifacts; new output files should include stable sequence numbers
  or a rerun attempt directory.

The step succeeds only when all required commands exit zero. Optional commands
may fail and be reported in the summary without failing the step.

## Artifact Layout

Sprint 3 should write test and collection artifacts under the existing run
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
- existing `build-log`, `kernel-config`, `kernel-image`, `vmlinux`
- existing `domain-xml`, `boot-plan`, `console-log`, `boot-log`
- existing test artifacts

`artifacts.collect` should write a machine-readable bundle with:

- `run_id`
- collected timestamp
- selected profiles
- step statuses and summaries
- artifact references grouped by step
- missing expected artifacts
- cleanup state
- concise pass/fail rollup

It should not copy large artifacts in Sprint 3. The bundle is an index over the
durable run workspace and manifest references.

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
4. stop and return the build failure if build fails
5. call `target.boot`
6. stop and return the boot failure if boot fails
7. call `target.run_tests`
8. call `artifacts.collect` even when tests fail, so failed-run evidence is
   indexed
9. return a concise workflow summary with artifact bundle path

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

Sprint 3 must preserve the existing safety posture:

- command argv lists are planned without shell expansion
- SSH options are validated as simple option names and values
- credential references are recorded by reference, never by value
- returned snippets are redacted before entering MCP responses
- summaries avoid raw secret-bearing values
- full stdout/stderr artifacts are treated as normal artifacts unless a profile
  marks them sensitive in a later sprint

The first redaction tests should include fake SSH key paths, fake tokens in
command output, and environment-like strings in stdout/stderr.

## Testing Strategy

Unit tests should cover:

- `TestSuiteProfile` validation
- rootfs SSH profile validation
- SSH argv planning with and without key references
- missing `ssh`
- successful command execution
- command failure with `stop_on_failure=true`
- command failure with optional commands
- timeout behavior
- dmesg collection success and failure
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

The docs should state clearly that Sprint 3 does not install SSH keys or mutate
the rootfs to enable login.
