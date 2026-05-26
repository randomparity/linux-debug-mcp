# Dynamic per-run profile overrides

**Date:** 2026-05-25
**Branch:** `feat/dynamic-profiles`
**Status:** Design under adversarial review

## Problem

An agent driving the pipeline can only pick from four hardcoded profiles. There
is no way to inject a kernel command-line argument (e.g. `dhash_entries=1`), add
a `CONFIG_*` option, or select a different root filesystem without editing
`server.py` and restarting the server.

The capability partly exists in the data model but is unreachable at runtime:

- `BuildProfile.config_fragments` + `make_variables` — kernel config.
- `TargetProfile.kernel_args` — kernel command line.
- `RootfsProfile.source` — root filesystem selection.

The gaps:

1. `create_app()` / `main()` never load a `ServerConfig`. Handlers read the
   hardcoded module globals `DEFAULT_BUILD_PROFILES`, `DEFAULT_TARGET_PROFILES`,
   `DEFAULT_ROOTFS_PROFILES`.
2. The `kernel.create_run` tool accepts only profile *names* (strings),
   resolved against those globals.
3. Every later step re-resolves the profile *by name* and rejects anything
   differing from the immutable manifest `request` — `build` via
   `_build_profile_from_manifest` (`server.py:147`, reading
   `DEFAULT_BUILD_PROFILES`), `run_tests` via
   `rootfs_profiles[manifest.request.rootfs_profile]` (`:1027`).
4. The local build provider explicitly rejects config fragments
   (`local_kernel_build.py:88`), and it has no defconfig step — `prepare_config`
   (`:107`) copies a developer-prepared `.config` or fails. So there is no
   in-tree base config to merge into unless the developer supplied one.

## Decisions

Settled during brainstorming:

| Question | Decision |
|----------|----------|
| Mechanism | **Inline per-run overrides** layered on a required named base profile. |
| Safety posture | **Validated free-form** (structural validators, not an allow-list). |
| Kernel-config representation | **Inline config-fragment lines + `make_variables`**. |
| Persistence / resolution | Freeze resolved profiles into the manifest; steps resolve from the manifest, not module globals. |
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

## Phasing

The work decomposes into two independently shippable phases of differing risk.
Each phase is a separate implementation plan; Phase 1 lands first.

- **Phase 1 — boot-time overrides + `make_variables`** (lower risk, plumbing).
  `kernel_args` and `rootfs_source` boot-time overrides, the `make_variables`
  build-time override (already wired through `plan_build`, no new mechanism),
  the resolved-profile freezing infrastructure, and the boot-attempt model.
- **Phase 2 — config-fragment merge** (contentious build-config change).
  `config_lines` fragment application, which activates the explicit carve-out in
  the Phase-1 local-build design and requires the `merge_config.sh` mechanism
  plus a user-doc correction. Deferred behind Phase 1 because it carries the
  hardest open questions; the design records them here so the boundary is clear.

The two phases share one mechanism: **freezing the resolved profiles into the
manifest** (below). Phase 1 builds it; Phase 2 reuses it.

## Architecture

### 1. Override inputs — split by lifecycle (`config.py`)

Two small models, separated because they have different lifecycles:

- **`BuildOverrides`** — `config_lines: list[str]` (Phase 2),
  `make_variables: dict[str, str]` (Phase 1). Fixed for the life of a run.
- **`BootOverrides`** — `kernel_args: list[str]`, `rootfs_source: str | None`.
  May vary per boot attempt.

The named base profile stays **required**; overrides layer on top.

**Merge semantics.** Scalar overrides replace the base value. For
`kernel_args`, the merge de-duplicates by key: a `key=value` override replaces
any base token with the same `key=`, and a bare flag (e.g. `nokaslr`) replaces a
matching base flag; remaining overrides append. This avoids the duplicate /
silently-conflicting tokens that a naive append would leave on the
`" ".join(...)` cmdline (`libvirt_qemu.py:512`), whose only existing guard is
the `root=`/`console=` conflict check (`:623`). For `config_lines`, later lines
for the same `CONFIG_` symbol win (matching `merge_config.sh -m` behavior).

### 2. Safety / validators (validated free-form)

- **`kernel_args` tokens** — each token matches
  `^[A-Za-z0-9_][A-Za-z0-9_.:=,/-]*$`. Rejects whitespace, shell metacharacters
  (`;`, `|`, `&`, `` ` ``, `$`, `<`, `>`), quotes, and control characters.
  Accepts `dhash_entries=1`, `nokaslr`, `console=ttyS0,115200`. The same
  validator is added to `TargetProfile.kernel_args`, which has no content
  validation today.

  This is a **syntactic** guard, not a semantic allow-list. Because the cmdline
  is composed into libvirt domain XML (`libvirt_qemu.py:512`) and not a shell,
  the regex closes host-side injection. It deliberately still permits
  guest-affecting args such as `init=…` / `rdinit=…`; that matches the existing
  trust model (the agent already controls the guest it boots) and the readiness
  marker fails the boot if the guest is broken. The charset excludes quotes,
  `+`, `%`, `@`; an arg needing those is an explicit follow-up, not a silent
  gap.

- **`config_lines`** (Phase 2) — kconfig assignment grammar:
  `^CONFIG_[A-Z0-9_]+=(y|m|n|-?\d+|0x[0-9A-Fa-f]+|"[^"\n]*")$`
  or `^# CONFIG_[A-Z0-9_]+ is not set$`.

- **`make_variables`** — keys are already validated
  (`config.py:70`: reserved-name and name-pattern checks; values rejected only
  for control characters). Values are otherwise **syntactically
  unconstrained**. This is the intended trust boundary: values are appended as
  `f"{key}={value}"` to a no-shell `subprocess.run` argv
  (`local_kernel_build.py:93`), so there is no host shell to inject into. We do
  not add a value allow-list; the design states this explicitly rather than
  implying the existing validation covers value semantics.

- **`rootfs_source`** — a new `validate_rootfs_source` in `safety/paths.py`
  modeled on `validate_artifact_root`'s overlap logic (`paths.py:39`), **not**
  on `validate_source_path` (which requires `Kconfig`+`Makefile` markers,
  `:81`). It must: resolve to an existing regular file, contain no shell
  metacharacters, and not overlap the source tree, configured sensitive paths,
  `$HOME`, or `/`.

### 3. Persistence — resolved profiles frozen into the manifest

The crux of both phases. Today the manifest's `RunRequest` stores only profile
*names* and steps re-resolve them from module globals. We store the resolved
profile bodies and have steps read those.

- `RunRequest` gains optional `build_overrides` and an **initial**
  `boot_overrides` — the recorded *intent* for attempt 1. It stays immutable;
  per-attempt boot overrides do **not** live here (see boot attempts below).
- `RunManifest` (`schema_version` bumped `1 → 2`) gains:
  - `resolved_build_profile: BuildProfile | None` — the base `BuildProfile`
    merged with `build_overrides`, frozen at `create_run`. This requires the
    manifest model to import the `config` profile models, and adding
    `build_overrides`/`boot_overrides` to `RunRequest` adds a `domain → config`
    edge too. Both are acyclic: `config.py` imports only `safety.secrets`, which
    has no internal imports, so neither `manifest → config` nor `domain → config`
    closes a cycle.
  - `boot_attempts: list[BootAttempt]`, where
    `BootAttempt = {attempt: int, boot_overrides, resolved_target_profile,
    resolved_rootfs_profile, status, started_at}`. Appended to, never mutated.
  - A new `with_boot_attempt(...)` model method (append-only; mirrors the
    immutability discipline of `with_step_result`).
- **Atomic persistence.** `record_step_result` (`store.py:84`) is today the only
  atomic manifest writer — it takes `_manifest_lock`, applies `with_step_result`,
  and writes. It touches `step_results` only. Appending a `BootAttempt` and
  updating `step_results["boot"]` to that attempt **must happen in one locked
  write**, or the two can disagree on the latest attempt — the exact consistency
  the `run_tests` binding (§5) depends on. The design adds a single store method
  (e.g. `record_boot_attempt`) that, under `_manifest_lock`, applies both
  `with_boot_attempt(...)` and `with_step_result(..., replace_succeeded=True)`
  to the loaded manifest and writes once. Ordering within that write: append the
  attempt, then point `step_results["boot"]` at it.
- `_build_profile_from_manifest` (`server.py:147`) is replaced: it returns
  `manifest.resolved_build_profile` when present, and **falls back to
  `DEFAULT_BUILD_PROFILES[name]`** when it is `None`. `kernel_build_handler`
  (which today takes no injectable profile map) reads the resolved profile from
  the manifest. The fallback path intentionally stays global-resolved — it fires
  only for pre-v2 manifests — so the "mutate a global mid-run, confirm no effect"
  test applies to the resolved-profile-present path, not the fallback.
- Existing per-name drift-checks continue to compare the recorded base profile
  *name*, so they keep working unchanged.

**Migration.** All new fields (`build_overrides`, `boot_overrides`,
`resolved_build_profile`, `boot_attempts`) are optional/defaulted, so a
`schema_version` 1 manifest still validates under `extra="forbid"`
(`store.py:80` does a plain `model_validate_json`). The `resolved_build_profile
is None` fallback above is what keeps a pre-upgrade run buildable; without it an
old run would have no profile to return. No data rewrite of existing manifests
is performed — the version bump is purely additive.

The existing `step_results` dict (`manifest.py:18`, keyed by step name) is left
as-is: `step_results["boot"]`/`["run_tests"]` continue to reflect the **latest**
attempt for the prerequisite checks ("tests require a `SUCCEEDED` boot"; "debug
requires a debug boot with a gdbstub endpoint"). The per-attempt history lives
in `boot_attempts`. This is the relationship the previous draft left ambiguous.

### 4. Boot-attempt model

The `tests/attempt-N` precedent (`_next_test_attempt`, `server.py:353`) is
**only** a filesystem directory counter — `run_tests` still records a single
`step_results["run_tests"]`. So we borrow only the `boot/attempt-N` *directory*
layout from it; the per-attempt **manifest records** in `boot_attempts` (§3) are
new and are what make boot iteration first-class.

- A new `boot/attempt-N` directory per attempt (counter mirrors
  `_next_test_attempt`). **This requires a `plan_boot` change the test-attempt
  precedent already has but boot lacks.** `plan_tests` receives `attempt=…`
  (`server.py:1067`), but `plan_boot` (`libvirt_qemu.py:311`) has no `attempt`
  parameter and writes five fixed paths — `target/domain.xml`,
  `logs/console.log`, `logs/boot.log`, `target/boot-plan.json`,
  `summaries/boot-summary.json` (`:344-348`) — so a second attempt would
  overwrite attempt 1's artifacts. Phase 1 must thread an `attempt` (or
  attempt-dir) parameter through `plan_boot` and relocate those five paths plus
  `_ensure_artifact_dirs`/`_artifact_refs` under `boot/attempt-N/`. This is named
  Phase-1 scope.
- `target.boot` against a `SUCCEEDED` build **with new boot overrides** opens a
  new attempt: resolve a fresh target/rootfs profile from the base profile +
  the call's boot overrides, append a `BootAttempt`, reuse the build artifact,
  and update `step_results["boot"]` to the new attempt's result. Without new
  overrides, the existing `force_reboot` semantics are unchanged.
- **This is a code change to the SUCCEEDED-guard, not an invariant.**
  `with_step_result` refuses to overwrite a `SUCCEEDED` step unless
  `replace_succeeded=True` (`manifest.py:36`), and the boot handler early-returns
  the recorded boot when `step_results["boot"]` is `SUCCEEDED and not
  force_reboot` (`server.py:823`, `:925`). The new-attempt trigger must be added
  to those guard conditions (`… and not force_reboot and not
  opening_new_attempt`) and must record the new attempt's result with
  `replace_succeeded=True`. The handler already computes a `replace_succeeded`
  flag for the SUCCEEDED case (`server.py:928`) and records with it (`:970`), so
  the machinery exists; the design only widens the trigger.
- **Concurrency.** Boot attempts are **not** concurrent. They share the single
  managed domain, so they serialize on `boot_lock(run_id)` plus the cross-run
  `target_lock(target_ref)` (`store.py:147`). A new attempt destroys and
  redefines the managed domain through the existing ownership validation
  (`libvirt_qemu.py`), which is keyed by `target_ref`, not by attempt. The
  design states this rather than deferring it.
- **Build-time** overrides remain strictly immutable — changing `config_lines`
  or `make_variables` after a `SUCCEEDED` build is a `configuration_error` that
  directs the agent to create a new run.

### 5. `run_tests` binds to the boot attempt (`target_run_tests_handler`)

`target_run_tests_handler` currently resolves rootfs by name from
`DEFAULT_ROOTFS_PROFILES` (`server.py:1027`). It is added to the set of handlers
that read resolved state: a test run binds to the **latest** boot attempt and
uses that attempt's `resolved_rootfs_profile` for the SSH connection details —
otherwise a boot attempt that swapped `rootfs_source` would be invisible to the
tests. (Phase 1 binds to the latest attempt only; an explicit `attempt` selector
is deferred — the iterate-and-test loop always targets the most recent boot.)

### 6. Redaction of override values

Override values are agent-supplied *inputs*, not command output, so they are not
secrets by construction — but the manifest and responses echo them, and an agent
could pass a secret-shaped value. The accurate picture against the current
`Redactor` (`redaction.py:33`, which redacts a mapping member only when the
mapping carries `sensitive: true` and the key is literally `"path"`, or when the
key matches `password|token|api_key|secret`; and `redact_text` scrubs
`key=value` secret patterns and registered secret values from any string):

- **Manifest view is already covered.** `get_manifest_handler`
  (`server.py:428`) runs the entire manifest through `Redactor().redact_value`,
  so the new fields (`resolved_*`, overrides) inherit that pass to the extent the
  Redactor matches secret-shaped content. No new wiring needed there.
- **The real gap is boot responses — all of them, not just the recorded path.**
  Unlike `_recorded_test_success_response` / `_recorded_collect_success_response`
  (`:184`, `:202`), which already use `Redactor`, none of the boot handler's
  return points redact. These echo freshly merged `kernel_args` / rootfs detail
  and must all route through `Redactor`:
  - the **fresh-boot success** return (`server.py:905`, `data=terminal.details`)
    — the primary path for a new attempt;
  - the recorded-success path `_recorded_boot_success_response` (`:174`);
  - the failure returns that echo `details` (`:866`, `:888`, `:912`).

  Rather than enumerate paths an implementer might miss, the rule is: **every
  boot handler return point routes through `Redactor`.** The in-lock
  `ProviderBootError` return (`:956`) and the RUNNING `_running_boot_response`
  (`:213`, used at `:979`) carry only endpoint/profile-name detail today, not
  merged override values, so they are not live leaks — but they are covered by
  the blanket rule so a future change that adds override detail cannot regress.
- **`rootfs_source` is not special-cased as a secret.** It is a host path
  comparable to `source_path`, which the manifest already surfaces unredacted.
  The previous draft's claim that it is "treated as `sensitive`" was not
  implementable against the current redactor (a `RootfsProfile` serializes its
  path under key `source`, with no `sensitive` flag, so neither redactor branch
  fires) and is dropped rather than asserted.

### 7. Build-provider config-fragment support (Phase 2, `local_kernel_build.py`)

This activates the explicit carve-out in the Phase-1 local-build design
(`2026-05-22-phase-1-local-kernel-build-design.md`: *"Do not run … config
fragment application unless a later explicit profile option enables that
behavior"*). `config_lines` is that option.

- Remove the `config_fragments` rejection guard (`:88`).
- `config_lines` **augment a developer-prepared base `.config`**. There is no
  defconfig step; if `prepare_config` (`:107`) finds no base `.config`, the
  build fails with the same `configuration_error` as today. `config_lines`
  cannot bootstrap a config from nothing — the Problem statement's "add a
  `CONFIG_*` option" means "add to an existing base config."
- Merge insertion point: inside `execute_build`, **after** `prepare_config`
  returns the base `.config` (`:158`) and **before** `runner.run(plan.argv)`.
  The provider writes the merged lines to `run_dir/inputs/override.config`, then
  runs `<source>/scripts/kconfig/merge_config.sh -m -O <build-dir>
  <base.config> <override.config>` followed by `make O=<build-dir> olddefconfig`,
  through the injectable runner. The main `make` argv from `plan_build` is
  unchanged.
- **Planning prerequisites** (must be resolved before Phase 2 implementation):
  confirm `scripts/kconfig/merge_config.sh` exists in the supported source trees
  and that `-O <output>` writes the merged `.config` into the build output dir;
  pin the exact argv; and update the user-facing claim in
  `docs/fedora-libvirt-user-guide.md` ("does not run `defconfig` or generate
  kernel configs") to reflect fragment application.

### 8. Tool surface (`server.py:create_app`)

- `kernel.create_run` gains optional `kernel_args`, `rootfs_source`,
  `make_variables` (Phase 1) and `config_lines` (Phase 2).
- `target.boot` gains optional `kernel_args`, `rootfs_source`, opening a new
  boot attempt. `target.run_tests` automatically binds to the latest boot
  attempt (no `attempt` selector in Phase 1 — deferred).
- Merge + validate happens in the handler.

## Data flow

```
create_run(base names + build_overrides + boot_overrides)
  → resolve base profiles from registry
  → merge overrides, validate
  → freeze resolved_build_profile + boot_attempts[1] (resolved target/rootfs)
    into manifest (schema_version 2)
  → build      reads resolved_build_profile     → make vars (+ fragments, Ph2)
  → boot       reads boot_attempts[latest]       → cmdline + rootfs
  → run_tests  binds to boot_attempts[latest]    → rootfs conn details

re-boot(boot_overrides) against a SUCCEEDED build
  → validate
  → append boot_attempts[N] (reuses build artifact; serialized on boot/target lock)
  → run_tests binds to attempt N
```

## Error handling

- Validation failures → `configuration_error` at the handler, before any side
  effects; the response carries the offending value (redacted if secret-shaped).
- Build-time override change after a `SUCCEEDED` build → `configuration_error`
  directing to a new run.
- Boot-time override against an existing build → new attempt (allowed).
- `config_lines` supplied but no developer-prepared base `.config` →
  `configuration_error` from `prepare_config` (Phase 2).
- Unknown base profile → `configuration_error`.
- Conflicting `root=` / `console=` kernel args still caught at the boot
  provider after the de-dup merge. **Ordering note for implementers:** the
  handler de-dups overrides against the *base profile's* `kernel_args` only. The
  provider injects `root=`/`console=` defaults later, at plan time, and only if
  absent (`libvirt_qemu.py:588`); a surviving user `console=` suppresses the
  default and is then validated by `_validate_kernel_args` (`:623`). Do not
  attempt to de-dup against the injected defaults — they are not visible to the
  handler.

## Testing

Phase 1 unless noted.

- **Validators**, including malicious/edge inputs: `kernel_args` like
  `foo; rm -rf /`, embedded control characters, whitespace, quotes;
  `rootfs_source` pointing at `$HOME` / a sensitive path / the source tree / a
  non-file; `config_lines` grammar violations (Phase 2).
- **Merge precedence** — `kernel_args` de-dup by key (override replaces base
  `key=`; bare-flag replace); `config_lines` last-wins (Phase 2).
- **Manifest freezing & migration** — resolved profiles written at `create_run`
  round-trip through `schema_version` 2; build/boot/run_tests read from the
  manifest, not module globals (verify by mutating a global mid-run and
  confirming no effect); a `schema_version` 1 manifest still loads.
- **`run_tests` binding** — a boot attempt that swapped `rootfs_source` is the
  rootfs the test step connects to.
- **Build provider** (Phase 2) — `config_lines` produce a `merge_config.sh`
  invocation between `prepare_config` and the main `make`; fake runner asserts
  the argv and `override.config` contents; the no-base-`.config` path fails with
  `configuration_error`.
- **Boot-attempt** — a second `target.boot` with new `kernel_args` appends
  `boot_attempts[2]`, reuses the build artifact, updates `step_results["boot"]`,
  and `run_tests` targets attempt 2; attempts serialize on the locks.
- **Redaction** — a value the `Redactor` actually matches (a `make_variables`
  value containing a `token=…`-shaped substring, or a registered secret string)
  is redacted across **every** boot return point (fresh success `:905`, recorded
  `:174`, the `details`-echoing failures) and the manifest view. A bare
  `rootfs_source` path is *not* expected to be redacted (it is surfaced like
  `source_path`); the test asserts that, so the behavior is intentional, not an
  accidental leak.
- **Fail-fast** — `create_run` with a bad override creates no run directory.
- **Integration** — full override flow through `create_run → build → boot →
  run_tests` with fake providers and runners.

## Out of scope

- Loading a `ServerConfig` from a file or environment. Profiles remain
  code-defined; overrides are the dynamic path.
- Defining a brand-new profile inline with no named base.
- Overriding rootfs fields beyond `source` (mutability, SSH settings).
- `kernel_args` values needing quotes / `+` / `%` / `@` (deliberate follow-up).
- Concurrent boot attempts against one run (attempts serialize by design).
- Remote / provisioning / hardware paths — still discoverable stubs.
