# Dynamic per-run profile overrides

**Date:** 2026-05-25
**Branch:** `feat/dynamic-profiles`
**Status:** Design approved, pending spec review

## Problem

An agent driving the pipeline can only pick from four hardcoded profiles. There
is no way to inject a kernel command-line argument (e.g. `dhash_entries=1`), add
a `CONFIG_*` option, or select a different root filesystem without editing
`server.py` and restarting the server.

The capability already exists in the data model but is unreachable at runtime:

- `BuildProfile.config_fragments` + `make_variables` — kernel config.
- `TargetProfile.kernel_args` — kernel command line.
- `RootfsProfile.source` — root filesystem selection.

The gaps:

1. `create_app()` / `main()` never load a `ServerConfig`. Handlers read the
   hardcoded module globals `DEFAULT_BUILD_PROFILES`, `DEFAULT_TARGET_PROFILES`,
   `DEFAULT_ROOTFS_PROFILES`.
2. The `kernel.create_run` tool accepts only profile *names* (strings),
   resolved against those globals.
3. Every later step (`build`, `boot`) re-resolves the profile *by name* and
   rejects anything differing from the immutable manifest `request`.
4. The local build provider explicitly rejects config fragments
   (`local_kernel_build.py`: *"config fragments are not supported by the local
   Sprint 1 provider"*).

## Decisions

Settled during brainstorming:

| Question | Decision |
|----------|----------|
| Mechanism | **Inline per-run overrides** layered on a required named base profile. |
| Safety posture | **Validated free-form** (structural validators, not an allow-list). |
| Kernel-config representation | **Inline config-fragment lines + `make_variables`**. |
| Persistence / resolution | **Approach A** — freeze resolved profiles into the manifest; steps resolve from the manifest, not module globals. |
| Mid-session value changes | A run's config is immutable. Changing a value = a new run. **Boot-time** values (cmdline, rootfs) may additionally vary per **boot attempt** against an existing build, without rebuilding. |

### Why mid-session changes split build-time vs boot-time

Neither persistence approach permits mutating a value in an existing run in
place — `RunManifest.request` is immutable and profile drift is a
`configuration_error` at every step. To change a value, the agent creates a new
run.

But values divide by blast radius:

- **Build-time** (`config_lines`, `make_variables`) — changing these
  invalidates the kernel build. A new run with a rebuild is the only honest
  model.
- **Boot-time** (`kernel_args`, rootfs `source`) — changing these does *not*
  require a rebuild. The same `bzImage`/`vmlinux` can boot repeatedly with
  different command lines.

The motivating use case (`dhash_entries=1`) is a boot-time value, and the
iterative loop is build-once → boot(args=X) → test → boot(args=Y) → test. So
the design supports re-booting an already-built run with new boot-time values as
a new **boot attempt**, while keeping the build immutable.

## Architecture

### 1. Override inputs — split by lifecycle (`config.py`)

Two small models, separated because they have different lifecycles:

- **`BuildOverrides`** — `config_lines: list[str]`, `make_variables: dict[str, str]`.
  Fixed for the life of a run.
- **`BootOverrides`** — `kernel_args: list[str]`, `rootfs_source: str | None`.
  May vary per boot attempt.

The named base profile stays **required**; overrides layer on top. Scalar
overrides win over the base; list overrides (`kernel_args`, `config_lines`)
append to the base profile's values.

### 2. Safety / validators (validated free-form)

- **`kernel_args` tokens** — each token matches
  `^[A-Za-z0-9_][A-Za-z0-9_.:=,/-]*$`. Rejects whitespace, shell metacharacters
  (`;`, `|`, `&`, `` ` ``, `$`, `<`, `>`), quotes, and control characters.
  Accepts `dhash_entries=1`, `nokaslr`, `console=ttyS0,115200`. This validator
  is also applied to `TargetProfile.kernel_args`, which has no content
  validation today.
- **`config_lines`** — kconfig assignment grammar:
  `^CONFIG_[A-Z0-9_]+=(y|m|n|-?\d+|0x[0-9A-Fa-f]+|"[^"\n]*")$`
  or `^# CONFIG_[A-Z0-9_]+ is not set$`.
- **`rootfs_source`** — a new check in `safety/paths.py` mirroring
  `validate_source_path`: the path must exist and must not overlap the source
  tree, sensitive paths, `$HOME`, or `/`.

Validation runs in the handler at `create_run` / `boot` and returns
`configuration_error` with the offending value **before** any run or attempt
directory is created.

### 3. Persistence — Approach A, frozen into the manifest

- `RunRequest` gains optional `build_overrides` / `boot_overrides` — the
  recorded *intent*.
- `RunManifest` gains:
  - a frozen `resolved_build_profile`, and
  - a list of **boot attempts**, each carrying
    `{attempt, resolved_target_profile, resolved_rootfs_profile, status}`,
  - a `latest_boot_attempt` pointer.

  This resolved state is the *computed truth* that steps consume, replacing the
  `DEFAULT_*` global lookups in `kernel_build_handler` and
  `target_boot_handler`.
- Existing drift-checks continue to compare base profile *names*, so they keep
  working unchanged.

### 4. Boot-attempt model

Mirrors the existing test-attempt precedent (`tests/attempt-N`,
`_next_test_attempt`, `server.py`).

- New `boot/attempt-N` directories.
- `target.boot` against a `SUCCEEDED` build **with new boot overrides** opens a
  *new attempt*: it resolves a fresh target/rootfs profile, reuses the build
  artifact, and updates `latest_boot_attempt`.
- The `latest_boot_attempt` pointer satisfies the existing prerequisite checks
  ("tests require a `SUCCEEDED` boot"; "debug requires a debug boot with a
  recorded gdbstub endpoint").
- **Build-time** overrides remain strictly immutable — changing `config_lines`
  or `make_variables` after a `SUCCEEDED` build is a `configuration_error` that
  directs the agent to create a new run.

### 5. Build-provider config-fragment support (`local_kernel_build.py`)

- Remove the "config fragments are not supported by the local Sprint 1
  provider" guard.
- When `config_lines` are present: write them to
  `run_dir/inputs/override.config`, merge into the base `.config` via
  `scripts/kconfig/merge_config.sh`, then `make O=… olddefconfig`, through the
  existing injectable runner. `make_variables` already flow through to the make
  argv.

### 6. Tool surface (`server.py:create_app`)

- `kernel.create_run` gains optional `config_lines`, `make_variables`,
  `kernel_args`, `rootfs_source`.
- `target.boot` gains optional `kernel_args`, `rootfs_source`, opening a new
  boot attempt when a build has already succeeded.
- Merge + validate happens in the handler.

## Data flow

```
create_run(base names + build_overrides + boot_overrides)
  → resolve base profiles from registry
  → merge overrides, validate
  → freeze resolved_build_profile + boot attempt 1 (resolved target/rootfs)
    into manifest
  → build      reads resolved_build_profile     → applies fragments + make vars
  → boot       reads boot attempt's resolved profiles → cmdline + rootfs
  → run_tests  runs against the boot attempt

re-boot(boot_overrides) against a SUCCEEDED build
  → validate
  → new boot attempt N (reuses build artifact)
  → run_tests against attempt N
```

## Error handling

- Validation failures → `configuration_error` at the handler, before any side
  effects; the response carries the offending value.
- Build-time override change after a `SUCCEEDED` build → `configuration_error`
  directing to a new run.
- Boot-time override against an existing build → new attempt (allowed).
- Unknown base profile → `configuration_error`.
- Conflicting `root=` / `console=` kernel args still caught at the boot
  provider.

## Testing

- **Validators** including malicious/edge inputs: `kernel_args` like
  `foo; rm -rf /`, embedded control characters, whitespace; `config_lines` that
  violate the grammar; `rootfs_source` pointing at `$HOME` / sensitive paths /
  the source tree.
- **Merge precedence** — overrides win over / append to base correctly.
- **Manifest freezing** — resolved profiles are written at `create_run`; build
  and boot read from the manifest, not the module globals (verify by mutating a
  global mid-run and confirming no effect).
- **Build provider** — `config_lines` produce a `merge_config.sh` invocation;
  fake runner asserts the argv and fragment-file contents.
- **Boot-attempt** — a second `target.boot` with new `kernel_args` produces
  `attempt-2`, reuses the build artifact, and `run_tests` targets attempt 2.
- **Fail-fast** — `create_run` with a bad override does not create a run
  directory.
- **Integration** — full override flow through `create_run → build → boot →
  run_tests` with fake providers and runners.

## Open items to confirm during planning

- The `prepare_config` integration point for the fragment merge (where in the
  config-prep stage `merge_config.sh` runs relative to defconfig).
- Exact `step_results` keying for boot attempts vs. the `latest_boot_attempt`
  pointer, and how `target_lock` / `boot_lock` scope to an attempt.

## Out of scope

- Loading a `ServerConfig` from a file or environment (Approach C from
  brainstorming). Profiles remain code-defined; overrides are the dynamic path.
- Defining a brand-new profile inline with no named base.
- Overriding rootfs fields beyond `source` (mutability, SSH settings).
- Remote / provisioning / hardware paths — still discoverable stubs.
