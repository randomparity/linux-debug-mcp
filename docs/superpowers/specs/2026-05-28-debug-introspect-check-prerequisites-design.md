# `debug.introspect.check_prerequisites` — target-side drgn prerequisite probe

**Date:** 2026-05-28
**Issue:** #52
**Epic:** #9 (Remote interactive kernel debugging for coding agents)
**Supersedes (in part):** #11
**Status:** Draft — pending user review
**Depends on:** `debug.introspect.run` (#51, merged in `providers/local_drgn_introspect.py`); reuses its SSH transport, profile resolution, and `build_id` recording. Independent of the runner's admission seam.

## 1. Background and scope

Epic #9's default debug tier is `debug.introspect.run` — drgn over SSH, JSON out, no stop-the-world. That tier only works when the target actually has drgn, a usable `python3`, and kernel debuginfo where drgn's default search looks. Today an agent discovers a missing prerequisite the hard way: it calls `debug.introspect.run`, the on-target wrapper fails in `prog.load_default_debug_info()`, and the agent gets a `drgn_open_failure` outcome with no actionable guidance about what to install.

This spec adds an up-front probe so an agent learns whether introspection is usable on a target — and what is missing if not — **before** attempting it.

### In scope

- The `debug.introspect.check_prerequisites(run_id, target_ref, …)` MCP tool: a run-scoped, read-only probe that SSHes into a booted target and reports drgn/python/debuginfo status.
- A single on-target `python3` probe script (no drgn-to-kernel attach) that gathers facts in one round-trip and emits one JSON object.
- Host-side handler that resolves profiles from the manifest (reusing `debug.introspect.run`'s path), parses the probe JSON, and returns a `PrerequisiteCheck` list plus an `introspect_usable` verdict.
- Distro-specific remediation strings derived from the target's `/etc/os-release`.
- A provenance hint: compare the running kernel's build-id against the host build's recorded `build_id`.
- Adding `debug.introspect.check_prerequisites` to the `local-drgn-introspect` capability's advertised `operations`.

### Out of scope

| Concern | Where it lives |
|---|---|
| Installing debuginfo or drgn packages on the target | Out — document remediation only, never act (issue #52) |
| Running any introspection script against the live kernel | #51 (`debug.introspect.run`) |
| Full `KernelProvenance` resolution + module debuginfo locator | #53 |
| Curated drgn helper library | #54 |
| vmcore / offline execution | #55 |
| Gating the probe behind `DebugProfile.enabled_operations` | Out — see §3 (the probe touches none of the constrained debug surface) |

## 2. Architecture overview

```
agent ──MCP──▶ check_prerequisites handler ──▶ load manifest (read-only)
                       │                              │ resolve target/rootfs/debug profiles
                       │                              │ enforce manifest-immutability
                       │                              │ pull build_id from build step
                       │
                       ▼
              render on-target probe (python3, no drgn attach)
                       │
                       ▼
       build_ssh_argv() + SubprocessSshRunner.run(stdin=probe) ──SSH──▶ python3 -
                       │                                                     │
                       │  ◀────────────────── one JSON object on stdout ─────┘
                       ▼
              parse JSON → PrerequisiteCheck[] + introspect_usable
                       │  apply distro→install-hint map
                       │  Redactor over request echo / stderr / payload
                       │  persist raw stdout+stderr to <run>/sensitive/debug/checkprereq/<probe_id>/ (0600), ArtifactRef
                       ▼
              ToolResponse.success(data={introspect_usable, checks})
```

No admission gate (`AdmissionService`) is taken: the probe never attaches drgn to the live kernel, so it is not an ssh-live debug operation. It is not step-recorded in the manifest: prerequisite state is mutable (drgn may be installed between calls), so a cached SUCCEEDED result would be wrong by construction. The handler reads the manifest but does not mutate it.

## 3. Tool surface

New run-scoped tool registered in `create_app()`, sibling to `debug.introspect.run`:

```python
@app.tool(name="debug.introspect.check_prerequisites")
def debug_introspect_check_prerequisites(
    run_id: str,
    target_ref: str,
    artifact_root: str = str(DEFAULT_ARTIFACT_ROOT),
    timeout_seconds: int = 20,           # bounded 5–60
    debug_profile: str | None = None,
    target_profile: str | None = None,
    rootfs_profile: str | None = None,
) -> dict[str, Any]:
    return debug_introspect_check_prerequisites_handler(...).model_dump(mode="json")
```

The request model `DebugIntrospectCheckPrerequisitesRequest` (in `domain.py`) carries the same fields and is validated `extra="forbid"`. `timeout_seconds` is bounded to 5–60 (a probe should be fast; out-of-range → `CONFIGURATION_ERROR`).

**Why run-scoped, not stateless.** Unlike `host.check_prerequisites` (local, stateless), this probe must SSH into a *booted* target. The SSH endpoint comes from the run's resolved rootfs profile, and the provenance hint needs the build step's `build_id`. Both live in the manifest, so the tool takes `run_id` + `target_ref` and resolves exactly as `debug.introspect.run` does.

**Profile resolution & immutability.** The handler resolves `target_profile`/`rootfs_profile`/`debug_profile` from the manifest. Any explicitly passed profile field must be omitted or identical to the recorded value (the manifest-immutability invariant); a divergent value returns `CONFIGURATION_ERROR`. This reuses the existing helper path from `debug_introspect_run_handler`.

**Not gated by `enabled_operations`.** `_ensure_debug_operation_enabled` guards operations that read kernel memory/registers/symbols (the `ALLOWED_DEBUG_OPERATIONS` surface). The probe reads none of those — it checks tooling presence over SSH — so it is a diagnostic like `host.check_prerequisites` and is intentionally callable even when `debug.introspect.run` itself is disabled. (That is the point: you probe to find out whether you *can* enable/use introspection.)

## 4. On-target probe script

A self-contained `python3` script piped over SSH stdin to `python3 -` (the same transport `debug.introspect.run` uses via `build_ssh_argv()` and `SubprocessSshRunner.run(stdin=…)`). It assumes only a stdlib `python3` on the target — no `drgn`, no `readelf`, no extra tooling. It **never** imports drgn to open the kernel; it only imports drgn to read its version.

**Shared-interpreter invariant.** The probe and `debug.introspect.run` MUST issue a byte-identical SSH + interpreter invocation, because the probe's `target.drgn` result is only predictive of the runner if both import drgn under the same interpreter. The interpreter command (`python3 -`) is factored into one shared module-level constant (`TARGET_PYTHON_ARGV`) consumed by both the runner and the probe; neither hard-codes it independently. A consequence (see #3, EL `python3.NN-drgn`): drgn installed for an interpreter *other* than the one `TARGET_PYTHON_ARGV` selects is reported **missing by design** — which is correct, because the runner would equally fail to import it. The probe records `sys.executable` so an agent can see exactly which interpreter was checked.

The script collects, in one pass, and emits a single JSON object on stdout:

| Field | How |
|---|---|
| `python_version` | `".".join(map(str, sys.version_info[:3]))` |
| `python_executable` | `sys.executable` (which interpreter the probe — and therefore the runner — uses) |
| `drgn_present` / `drgn_version` | `import drgn; drgn.__version__`, catching `ImportError` |
| `distro_id` / `distro_version` | parse `ID=` / `VERSION_ID=` from `/etc/os-release` |
| `kernel_release` | `os.uname().release` |
| `running_build_id` | parse `NT_GNU_BUILD_ID` ELF note from `/sys/kernel/notes`; on `EPERM`/absent, `null` (see §5 — not a WARNING) |
| `vmlinux_debuginfo` | see "debuginfo search" below — records `{found, candidates, path, file_build_id, build_id_verified, file_matches_host}` over the candidate set |
| `module_debuginfo` | `/usr/lib/debug/lib/modules/<rel>/kernel/` exists and is non-empty |
| `btf` | `os.path.exists("/sys/kernel/btf/vmlinux")` — surfaced as `target.vmlinux_debuginfo.details.btf`; consulted by §5 only as a *fallback* (DWARF-absent + BTF-present → `unknown`, not `unusable`), since the pinned drgn may attach to the core kernel via BTF with reduced type coverage |

**Debuginfo search — must track drgn, not a subset, and select by build-id (not first-existing).** drgn's `load_default_debug_info()` does not take the first vmlinux that exists on disk; it selects the candidate whose build-id matches the running kernel. The probe must do the same, or a stale vmlinux at an earlier path (common after a rebuild that left an old `/boot/vmlinux-<rel>`) plus the correct copy at a later path would make the probe report a mismatch while the runner succeeds — a false `unusable`. So the probe **enumerates every candidate that exists**, in drgn's default order, and resolves over the *set*:

1. build-id-indexed: `/usr/lib/debug/.build-id/<bid[:2]>/<bid[2:]>.debug` (where `<bid>` is `running_build_id`)
2. `/usr/lib/debug/boot/vmlinux-<rel>`
3. `/usr/lib/debug/lib/modules/<rel>/vmlinux`
4. `/lib/modules/<rel>/build/vmlinux`
5. `/lib/modules/<rel>/vmlinux`
6. `/boot/vmlinux-<rel>`

This list is pinned to the drgn version recorded for the runner and is reviewed when that pin changes; a comment in the probe source cites the drgn search-path source.

**Build-id verification across the candidate set.** Let `R` = `running_build_id` (target's live kernel), `H` = host `build_id` (manifest), and for each existing candidate `Fᵢ` = the build-id parsed from that ELF — seeking to the `PT_NOTE` program header rather than reading the whole (potentially large) file, the same note-parsing routine used for `/sys/kernel/notes`. The `vmlinux_debuginfo` record carries `{found, candidates: [{path, file_build_id: Fᵢ|null}], path, file_build_id, build_id_verified, file_matches_host}` where:

- `found` = at least one candidate exists.
- **`build_id_verified` = (`R` known and **some** candidate has `Fᵢ == R`)** — the found debuginfo provably matches the *running* kernel, exactly what drgn keys on. `path`/`file_build_id` then report that matching candidate. Hit #1 matches by construction and is still cross-parsed as a guard.
- When `R` is `null` (non-root, `/sys/kernel/notes` unreadable) the probe cannot confirm `Fᵢ == R`, so `build_id_verified=false`; it instead reports `file_matches_host = (some candidate has Fᵢ == H)` so the agent has a weaker signal.
- A candidate's `Fᵢ` is `null` only when its parse genuinely fails (unreadable/non-ELF/compressed/no note); such candidates simply don't contribute a match.

"Wrong debuginfo" (a fatal signal in §5) means: `R` known, at least one candidate parsed, and **no** candidate has `Fᵢ == R`. This is what §5's verdict consumes — file presence alone never asserts a match, but a parse-and-match (`Fᵢ == R`) by *any* candidate does.

Each probe sub-step is wrapped so one failure (e.g. unreadable `/sys/kernel/notes`) degrades that field to `null`/`false` rather than aborting the whole probe. The script writes the JSON and exits 0 whenever it ran to completion; a non-zero exit means the interpreter never started (see §6).

## 5. Output — `PrerequisiteCheck` list + verdict

`ToolResponse.success` with `data`:

- `introspect_usable: "usable" | "unknown" | "unusable"` — a **tri-state** verdict, not a bool, because a two-valued flag cannot distinguish "confirmed ready" from "nothing blocks it but the match is unconfirmable," and collapsing the latter to `true` re-introduces the "discover failure the hard way" outcome §1 exists to prevent. Using the §4 symbols `R` (running build-id), `H` (host build-id), `F` (matched-debuginfo build-id):
  - **`unusable`** — drgn not importable, **or** neither DWARF nor BTF available (no DWARF `found` in drgn's default search **and** `btf` absent), **or** a *proven* contradiction: provenance mismatch (`R` and `H` both known and `R != H`) or wrong-debuginfo (`R` known, ≥1 candidate parsed, and **no** candidate has `Fᵢ == R`). These are exactly the cases where `debug.introspect.run` would fail (`drgn_open_failure`/`provenance_mismatch`).
  - **`usable`** — drgn importable, DWARF `found`, debuginfo provably matches the running kernel (`build_id_verified`, i.e. `F == R`), **and** provenance confirmed (`R == H`). All three of `R`/`H`/`F` are known and agree — the strongest signal, equivalent to what the runner verifies.
  - **`unknown`** — drgn importable and *some* debug source plausibly usable, but the full chain cannot be confirmed. Covers: DWARF `found` with no proven contradiction but the build-id chain unconfirmable (`R` is `null`, `H` is absent, or `F` could not be parsed); **or** no DWARF found but `btf` present (the pinned drgn may attach to the core kernel via `/sys/kernel/btf/vmlinux` with reduced type coverage — not asserting it will). drgn may succeed at load time; the agent may proceed-and-handle, but must not treat this as a guarantee. `details` surface whatever partial signal exists (`file_matches_host`, `btf`).

  Module debuginfo absence never moves the verdict toward `unusable` (core-kernel introspection still works). Rationale: a false `unusable` makes the agent abandon a working tier, so uncertainty maps to `unknown` (not `unusable`), and only a *proven* mismatch or hard-missing prerequisite is `unusable`.

  **Host `build_id` (`H`) absent.** A run can have no recorded `H` (externally-supplied/prebuilt kernel image, a build step predating #51's `build_id` recording, or failed `build_id` extraction). When `H` is `null`: `target.kernel_buildid` is SKIPPED ("host build-id unknown — provenance not checked"); the verdict cannot reach `usable` (provenance unconfirmable) and is `unknown` unless drgn/DWARF are outright missing (`unusable`).

- `checks: list[PrerequisiteCheck]` — the same model `host.check_prerequisites` returns (`check_id`, `status`, `message`, `details`, `suggested_fix`):

| check_id | PASSED | FAILED / WARNING | details / suggested_fix |
|---|---|---|---|
| `target.python3` | python3 ran, version captured | FAILED if interpreter absent | `details.version`, `details.executable` |
| `target.drgn` | importable | FAILED if missing | `details.version`, `details.executable`; `suggested_fix` = distro install hint |
| `target.kernel_buildid` | read and matches host `build_id` | WARNING on proven mismatch; SKIPPED (not WARNING) when `running_build_id` is `null` (e.g. `/sys/kernel/notes` EPERM under non-root SSH) **or** host `build_id` is absent | `details.running`, `details.expected` |
| `target.vmlinux_debuginfo` | `found` **and** `build_id_verified` (`F == R`) | WARNING if `found` but unverified, **or** not found but `btf` present (BTF fallback may attach); FAILED only if neither DWARF nor BTF | `details.path`, `details.file_build_id`, `details.build_id_verified`, `details.file_matches_host`, `details.btf`; remediation hint |
| `target.module_debuginfo` | present | WARNING if absent (core works) | `details.path` |

Note `target.kernel_buildid` SKIPPED (rather than WARNING) when the running build-id is simply unreadable: an unprivileged SSH user commonly cannot read `/sys/kernel/notes`, and that is a property of the access method, not a defect in the target — flagging it WARNING would train agents to ignore the check.

**Distro → install-hint map**, built from `distro_id`:

| distro_id family | drgn install hint |
|---|---|
| `fedora` | `sudo dnf install drgn` |
| `rhel` / `centos` / `rocky` / `almalinux` | `sudo dnf install python3-drgn` (requires EPEL) |
| `debian` / `ubuntu` | `sudo apt install python3-drgn` (or the drgn PPA) |
| unknown / unset | `python3 -m pip install drgn` |

`suggested_next_actions`: `["debug.introspect.run"]` when the verdict is `usable` or `unknown` (in `unknown` the agent may proceed-and-handle), otherwise `["host.check_prerequisites"]`.

**Build-id normalization.** All build-ids — `running_build_id` parsed from `NT_GNU_BUILD_ID`, the `<bid>` used to build the index path (§4 #1), any id parsed out of a matched ELF, and the host `build_id` from the manifest — are normalized to lowercase hex with no separators or whitespace before any comparison or path construction. Without this, a case or whitespace difference produces a spurious `unusable`/mismatch or a missed index hit.

A drgn-missing or debuginfo-absent target is a **successful probe** (a report with FAILED/WARNING checks), not a tool failure — mirroring `host.check_prerequisites`, which always returns success even when individual checks fail.

## 6. Error handling

Tool-level `ToolResponse.failure` is reserved for conditions that prevent producing a report at all:

| Condition | `ErrorCategory` |
|---|---|
| `run_id`/`target_ref` not in manifest | `CONFIGURATION_ERROR` |
| no SUCCEEDED boot step for `target_ref` (target never booted) | `READINESS_FAILURE`, `suggested_next_actions: ["target.boot"]` |
| rootfs `access_method` not `ssh`/`ssh_and_serial` | `CONFIGURATION_ERROR` |
| `access_method` is ssh but a required field (`ssh_host`/`ssh_user`/`ssh_key_ref`) is unset | `CONFIGURATION_ERROR` naming the absent field |
| passed profile field diverges from manifest | `CONFIGURATION_ERROR` |
| `timeout_seconds` out of 5–60 | `CONFIGURATION_ERROR` |
| SSH connection failure / probe timeout | `INFRASTRUCTURE_FAILURE` |
| captured stdout exceeds the read cap (256 KiB) before parse | `INFRASTRUCTURE_FAILURE` (oversized output — do not `json.loads`) |
| ssh succeeded but stdout is not parseable JSON | `INFRASTRUCTURE_FAILURE` (with redacted snippet) |

The not-booted check runs **before** the SSH attempt: probing a target whose boot step never SUCCEEDED would otherwise time out into a generic `INFRASTRUCTURE_FAILURE` ("retry infra"), when the actionable signal is "boot the target first." This mirrors how `debug.introspect.run` depends on a booted target.

The captured stdout is bounded to a 256 KiB read cap before any `json.loads`, so a buggy interpreter, a noisy shell profile prepending output, or a hostile target cannot balloon handler memory with unbounded output — mirroring the on-target output caps in `debug.introspect.run`.

**`python3` missing on the target** is special: ssh exits non-zero (127) with no JSON, but this is a legitimate, actionable finding, not infrastructure breakage. The handler distinguishes it (exit 127 / "command not found" on stderr) and synthesizes a **success** report: `target.python3` FAILED, `target.drgn` and the debuginfo checks SKIPPED, `introspect_usable="unusable"`, with a python3-install remediation hint. Any other non-zero exit with no JSON is treated as `INFRASTRUCTURE_FAILURE`.

## 7. Redaction & artifacts

- `Redactor(secret_values=[ssh_key_ref])` is applied to the request echo, the stderr snippet, and the final response payload before return — the same pattern as `debug_introspect_run_handler`.
- Raw probe stdout and stderr are persisted **only on disk**, never returned inline (per issue #52: "never a raw command transcript"). Because this transcript is deliberately *un-redacted*, it is stored under `<run>/sensitive/debug/checkprereq/<probe_id>/` — matching `debug.introspect.run`, which keeps raw transcripts under `sensitive/`. `ArtifactStore.create_run` hardens only the `sensitive/` subtree to `0700`; storing the leaf files `0600` *under* that `0700` parent is what makes the mode load-bearing (a `0600` leaf under the umask-default `0755` `debug/` parent would be weaker). Files are referenced by `ArtifactRef`.
- **Per-invocation isolation.** The probe is not step-recorded (§2), so there is no `call_id` to key artifacts on. Each invocation instead generates a unique `<probe_id>` (host-side, from the manifest-lock-free `ArtifactStore` id source — not `random`/`Date.now`, which are unavailable in some execution contexts; reuse the run's existing id generator) for its artifact subdir. This prevents two concurrent `check_prerequisites` calls for the same `run_id`+`target_ref` (plausible when an agent polls readiness in a loop) from clobbering or interleaving each other's transcript, and guarantees a response never references a file another call is mid-write on.

## 8. Capability wiring

Add `debug.introspect.check_prerequisites` to the `local-drgn-introspect` capability's `operations` list (in `built_in_provider_plugin_specs()` / the capability factory) so `providers.list` advertises it alongside `debug.introspect.run`. No new provider class is required; the probe-render and parse logic live beside the runner, and `LocalDrgnIntrospectProvider` remains the owning capability.

## 9. Testing

Handler tests inject a fake `SshRunner` returning canned `SshCommandResult`s; no live SSH in unit tests (live integration stays gated like `test_qemu_gdbstub_integration.py`).

Verdict values below are the tri-state `introspect_usable` (`usable`/`unknown`/`unusable`).

| Scenario | Assertion |
|---|---|
| drgn present, build-id-indexed DWARF (path #1), `R==H` | verdict `usable`, all checks PASSED, `details.build_id_verified=true` |
| drgn present, DWARF at `/boot/vmlinux-<rel>` (path #6), ELF note parses `F==R==H` | `build_id_verified=true`, verdict `usable` (non-#1 paths reach `usable` when parse+match succeed) |
| drgn present, DWARF found at path #6, `running_build_id=null` (non-root), `F==H` proxy only | `target.vmlinux_debuginfo` WARNING, `details.file_matches_host=true`, verdict **`unknown`** (not `usable`) |
| stale vmlinux at path #2 (`F₂≠R`) **and** correct vmlinux at path #4 (`F₄==R`) | set-based match wins → `build_id_verified=true`, `details.path`=#4, verdict `usable` (no false `unusable`) |
| drgn present, DWARF found only via build-id index for a *different* build, `btf` absent | proven mismatch → verdict `unusable`, `target.vmlinux_debuginfo`/`target.kernel_buildid` reflect it |
| DWARF build-id mismatches running (`F≠R`) **and** `btf` present | unconfirmable (drgn may fall back to BTF) → verdict `unknown`, no false `unusable` |
| host `build_id` absent, drgn + DWARF found | `target.kernel_buildid` SKIPPED ("provenance not checked"), verdict `unknown` |
| drgn missing, `distro_id=fedora` | `target.drgn` FAILED, `suggested_fix` = dnf hint, verdict `unusable`, `details.executable` populated |
| drgn missing, `distro_id=ubuntu` | `suggested_fix` = apt/PPA hint |
| drgn missing, unknown distro | `suggested_fix` = pip hint |
| python3 missing (ssh exit 127, no JSON) | success report, `target.python3` FAILED, drgn/debuginfo SKIPPED, verdict `unusable` |
| running build-id ≠ host build_id (proven) | `target.kernel_buildid` WARNING with both ids; verdict `unusable` |
| `/sys/kernel/notes` unreadable (`running_build_id=null`, non-root) | `target.kernel_buildid` **SKIPPED** (not WARNING) |
| no DWARF in any search path, `btf` absent | `target.vmlinux_debuginfo` FAILED, verdict `unusable` |
| no DWARF in any search path, `btf` present | `target.vmlinux_debuginfo` WARNING (`details.btf=true`), verdict `unknown` (BTF fallback) |
| module debuginfo absent only | `target.module_debuginfo` WARNING, verdict not moved to `unusable` |
| build-id case/whitespace differs between sources | normalized before compare → match, no spurious mismatch |
| target never booted (no SUCCEEDED boot step) | `READINESS_FAILURE`, `suggested_next_actions=["target.boot"]`, no SSH attempted |
| SSH connection failure (booted target unreachable) | `INFRASTRUCTURE_FAILURE` |
| ssh OK but garbage stdout | `INFRASTRUCTURE_FAILURE`, redacted snippet |
| stdout exceeds 256 KiB read cap | `INFRASTRUCTURE_FAILURE`, no `json.loads` attempted |
| rootfs `access_method != ssh` | `CONFIGURATION_ERROR` |
| `access_method=ssh` but `ssh_host` unset | `CONFIGURATION_ERROR` naming the field |
| profile field diverges from manifest | `CONFIGURATION_ERROR` |
| two concurrent probes (same run+target) | distinct `<probe_id>` artifact subdirs; neither transcript clobbered |
| redaction | `ssh_key_ref` absent from every response field |
| shared-interpreter invariant | probe and runner resolve the same `TARGET_PYTHON_ARGV` constant (asserted by a unit test referencing both) |

**Gated integration test (real drgn).** The handler tests above use canned JSON and therefore cannot catch the §4 path list drifting from drgn's real search behavior — the single most load-bearing correctness claim. A gated test (skipped without `drgn` + a readable kernel, like `test_qemu_gdbstub_integration.py`) runs the probe **and** a real `drgn` on the same host/kernel and asserts they agree on (a) debuginfo-found and (b) `running_build_id`. The probe source carries a comment citing the exact drgn version and search-path source the §4 list was copied from; the integration test fails loudly when the installed drgn disagrees, flagging that the pin needs review.

## 10. Acceptance criteria mapping (issue #52)

- *Target without drgn → clean "drgn missing" report with distro install hint* → §5 (`target.drgn` FAILED + distro map), §9.
- *Target with drgn → drgn + Python versions plus debuginfo hint* → §5 (`target.drgn`/`target.python3` details, debuginfo checks).
- *Failures categorized via `ErrorCategory`, not raw strings* → §6.
- *Output is `Redactor`-safe* → §7, §9 redaction test.
