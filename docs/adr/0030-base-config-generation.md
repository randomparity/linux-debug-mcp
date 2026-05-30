# ADR 0030 — base kernel config generation for a clean source tree

**Status:** Accepted (2026-05-30) · **Issue:** #101 · **Epic:** #100 · **Affects:**
`src/kdive/config.py` (`validate_make_targets` helper, `BuildProfile.base_config`,
`BuildOverrides.base_config`), `src/kdive/providers/local_kernel_build.py` (`BuildPlan.base_config`,
`plan_build`, `ConfigGenerationError`, `MissingConfigError`, `_generate_base_config`, `prepare_config`
precedence ladder, `execute_build` error mapping), `src/kdive/server.py`
(`DEFAULT_BUILD_PROFILES` — `x86_64-default` gains `base_config`, new `x86_64-debug`; `_resolve_initial_profiles`
override replacement). Spec: [2026-05-30-base-kernel-config-generation.md](../specs/2026-05-30-base-kernel-config-generation.md).

## Context

`kernel.build` cannot build a freshly cloned kernel tree: the config step only merges `config_lines`
onto an existing `.config`, and `prepare_config` raises a bare `ValueError` when no `.config` exists in
either the run output dir or the source tree. #101 (child of the first-run-readiness epic #100) adds a
config-generation path so a plain `git clone` builds, and a debug profile yields a DWARF `vmlinux` that
boots under the gdbstub tier. The decisions below are the ones #101 leaves open and that have viable
alternatives.

## Decision

### 1. `base_config` is an ordered list of make config targets

`BuildProfile`/`BuildOverrides` gain `base_config: list[str]`, validated by the same make-target rule as
`targets`. When generation is needed, each target runs in order as `make -C <src> O=<out> ARCH=x86_64
<target>`. This is extensible (a profile can compose `["defconfig", "kvm_guest.config"]`) and matches the
issue's framing of ordered config targets.

### 2. `base_config` runs only as the last rung of a precedence ladder

`prepare_config` resolves the base `.config` in fixed order: (1) output-dir `.config` (idempotent
rebuild), (2) source-tree `.config` (developer-prepared, copied — unchanged behavior), (3) `base_config`
generation, (4) `CONFIGURATION_ERROR` with a `suggested_fix`. A developer-prepared `.config` therefore
wins over `base_config` — generation is the last resort before failure, preserving backward
compatibility for existing developer-config workflows.

### 3. `build_overrides.base_config` replaces the profile list (does not merge)

`config_lines` merge last-wins by `CONFIG_*` symbol because each line has a symbol identity. Make config
targets are an ordered sequence of operations with no such identity, so a positional merge would be
ill-defined. An override therefore replaces the profile's `base_config` wholesale, recorded in the frozen
manifest `BuildProfile` like the other build fields.

### 4. The debug config is delivered as explicit `config_lines`, not a fragment file

`x86_64-debug` carries its debug/virtio/console symbols as explicit `config_lines` rather than appending
an upstream fragment target (e.g. `kvm_guest.config`) to `base_config`. Explicit lines make the produced
config deterministic and independent of the checked-out tree's fragment contents, which vary across
kernel versions.

### 5. DWARF via `CONFIG_DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT=y`, not bare `CONFIG_DEBUG_INFO=y`

In modern kconfig `DEBUG_INFO` is not directly user-selectable; it is `select`ed by a `DEBUG_INFO_*`
choice. A bare `CONFIG_DEBUG_INFO=y` would be dropped by `olddefconfig`. Selecting the toolchain-default
DWARF choice pulls in `DEBUG_INFO` and clears `DEBUG_INFO_NONE`, so vmlinux reliably carries DWARF for the
gdbstub tier.

### 6. `suggested_fix` rides `BuildExecutionResult.details`

`ErrorInfo` has no dedicated remedy field, and the build handler already spreads `execution.details` into
the failure response. The no-config-no-base_config failure puts `suggested_fix` in `details` rather than
inventing a new schema field.

### 7. A failing generation target attaches its log as an artifact

A nonzero `base_config` target returns the redacted log *tail* in `diagnostic` **and** attaches the
failing target's per-target log as an `ArtifactRef` (kind `config-log`) on the FAILED result. This
mirrors the `ReadelfUnavailable`/`BuildIdMissing` paths, which already attach produced artifacts so an
operator can inspect a failure through the manifest without re-running the build, rather than being
limited to the truncated tail.

## Consequences

- A clean checkout builds with `kernel.create_run` + `kernel.build` and no developer config.
- The bare `ValueError` becomes an actionable `CONFIGURATION_ERROR` with a `suggested_fix`.
- `prepare_config`'s signature changes from `(source_path, output_path)` to `(plan, log_dir)` so it can
  reach `base_config`, the environment, and a per-target log dir; provider unit tests adapt to the new
  signature.
- A new `x86_64-debug` default profile gives agents a one-name path to a DWARF, KASLR-disabled,
  virtio/serial-enabled guest kernel.
- Existing frozen manifests are unaffected (immutable `RunRequest`/`BuildProfile`); only new runs pick up
  the `x86_64-default` `base_config`.

## Considered & rejected

1. **A single `defconfig: bool` flag instead of an ordered list.** Rejected: a boolean cannot express
   `defconfig` followed by a fragment target, and the issue explicitly frames config generation as an
   ordered set of make targets. The list is the extensible shape. (decision 1)
2. **`base_config` overrides *merge* with the profile list.** Rejected: make targets have no symbol
   identity to merge on (unlike `config_lines`), so any merge rule (append? positional replace?) is
   arbitrary. Wholesale replacement is the only well-defined override semantics. (decision 3)
3. **`base_config` wins over a developer-prepared source `.config`.** Rejected: it would silently
   discard a config a developer deliberately placed in the tree, breaking the existing workflow. Source
   `.config` stays ahead of generation in the ladder. (decision 2)
4. **Deliver the debug config by appending `kvm_guest.config` to `base_config`.** Rejected: the fragment's
   contents vary by kernel version, making the produced config non-deterministic and the debug guarantee
   tree-dependent. Explicit `config_lines` are deterministic. (decision 4)
5. **Enable DWARF with a bare `CONFIG_DEBUG_INFO=y`.** Rejected: `DEBUG_INFO` is not user-selectable in
   modern kconfig and `olddefconfig` drops the bare assignment, so vmlinux would ship without DWARF.
   Selecting a `DEBUG_INFO_DWARF_*` choice is the correct mechanism. (decision 5)
6. **Add a dedicated `suggested_fix` field to `ErrorInfo`.** Rejected as out-of-scope schema churn: the
   `details` channel already reaches the failure response and is the established place for structured
   failure context. (decision 6)
