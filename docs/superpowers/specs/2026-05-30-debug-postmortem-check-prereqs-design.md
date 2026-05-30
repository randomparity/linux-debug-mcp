# `debug.postmortem.check_prereqs` — kdump readiness checks

**Date:** 2026-05-30
**Issue:** #94
**Epic:** #9 (Remote interactive kernel debugging for coding agents)
**Supersedes (in part):** #14
**Status:** Draft — pending adversarial review
**Depends on:** #51 (`debug.introspect.run` foundation: `SshRunner`/`SubprocessSshRunner`, `build_ssh_argv`, known_hosts handling, `Redactor`, profile gating, ssh-tier admission); the shared on-target probe machinery added in #84 (`_target_python_remote_argv`, `_resolve_probe_context`, `_prepare_probe_dirs`, `_read_capped`, `PROBE_STDOUT_CAP`)
**Design decisions:** [ADR 0028](../../adr/0028-postmortem-check-prereqs-kdump-readiness.md)

## 1. Background and scope

The `debug.postmortem` tier analyzes a `vmcore` captured by kdump after a panic.
That analysis is worthless if the target was never configured to *produce* a
vmcore: no crashkernel memory reserved, the kdump service inactive, or the dump
directory unwritable all mean "on the next panic, there will be nothing to fetch."
`debug.postmortem.check_prereqs` is the **diagnostic** that an agent runs against a
live, booted target *before* relying on kdump — it detects and asserts readiness
and returns actionable fixes. It is the live-target sibling of the offline crash
(#92) and triage (#93) tools and the readiness counterpart to
`debug.introspect.check_prerequisites` (#84).

It is **diagnostic only**: it never enables, configures, starts, or restarts
kdump/fadump (configuration is out of scope per #14) and never modifies the kdump
service or target configuration. It does perform one **transient, self-cleaning
write probe** of the dump directory (create + immediately unlink a uniquely named
temp file) — the only way to assert the dump dir is genuinely writable by the
capture identity (see §3.2 / ADR 0028 decision 5); the service state is *reported*,
never changed.

### In scope

- `debug.postmortem.check_prereqs(run_id, target_ref, …) → ToolResponse` MCP tool,
  wired via `server.py`'s registration pattern, returning a list of
  `PrerequisiteCheck` (the existing `domain.PrerequisiteCheck` model).
- Three **independent** SSH probes (all read-only except the transient dump-dir
  write probe of §3.2), each emitting one `PrerequisiteCheck`:
  - `kdump.crashkernel_reserved` — kexec/kdump path: `/proc/cmdline` carries
    `crashkernel=` **and** `/sys/kernel/kexec_crash_size > 0`. POWER fadump path:
    `/sys/kernel/fadump_enabled == 1` (the reservation is firmware-assisted, so
    `kexec_crash_size` is 0 by design and is *not* a failure — AC#3).
  - `kdump.service_active` — `systemctl is-active <unit>` over a fixed candidate
    unit list (`kdump`, `kdump-tools`); **reported, never started** (AC: inactive
    service FAILs with a fix).
  - `kdump.dump_path_writable` — the configured dump dir (default `/var/crash`,
    overridden by an `/etc/kdump.conf` `path` directive when readable) exists and
    is writable.
- Independence invariant: the on-target probe gathers **all** facts unconditionally
  in one round-trip and emits them as one JSON object; the host builds all three
  checks from that object, so one probe's failure never masks another (AC#2).
- POWER fadump detection: the probe reads `/sys/kernel/fadump_enabled` /
  `/sys/kernel/fadump_registered` and reports which mechanism is active; an
  active-fadump target is reported as fadump, never a false kdump failure (AC#3).
  x86_64 `/var/crash` kdump is the **tested** path; fadump is detected-and-reported
  but unvalidated (no POWER hardware), documented as such.
- ssh-tier lifecycle gating: a `HALTED` target is **fast-rejected** before any SSH
  is attempted (§5.6 rule 2), never left to hang (AC#4).
- Bounded SSH execution (per-call `timeout_seconds` + a stdout byte cap) and
  redaction of all captured output before it is returned **and** before it is
  persisted (AC#5).
- `debug.postmortem.check_prereqs` added to `ALLOWED_DEBUG_OPERATIONS`
  (enumerability) and to the `local-drgn-introspect` capability's `operations`
  (the live-ssh capability — `local-crash-postmortem` is filesystem-only).
- Docs: a readiness section in `docs/debug-postmortem.md`, including the ppc64le
  fadump note.
- An **env-gated** live-target integration test (skipped without a reachable
  kdump-capable guest), plus host-side unit tests of the pure check builder (AC#6).

### Out of scope

| Concern | Where it lives |
|---|---|
| Enabling/configuring/starting kdump or fadump | document-only (#14); this tool never mutates target state |
| Listing or fetching vmcores | sibling #95 (`list_dumps` + `fetch`) |
| Validating that a *captured* dump is well-formed | #92/#95 |
| Resolving a kdump dump target on a separate device / NFS / SSH | not resolved; the probe reports the local dir it checked and documents the limitation (x86_64 local `/var/crash` is the tested path) |
| Full admission promotion / cancel-fence around the probe | rejected (ADR 0028 decision 3) — a bounded read-only probe needs only the HALTED fast-reject |
| Gating the tool on `DebugProfile.enabled_operations` | not gated — a read-only diagnostic, like `debug.introspect.check_prerequisites` (ADR 0028 decision 7) |

## 2. Architecture overview

```
agent ──MCP──▶ debug.postmortem.check_prereqs handler
                     │
                     ▼
  _resolve_probe_context(request)            # reused from #84 (introspect prereq)
     ├─ run not found / manifest error       → CONFIGURATION_ERROR / ManifestStateError
     ├─ profile / target_ref ≠ manifest       → CONFIGURATION_ERROR (manifest_profile_mismatch)
     ├─ timeout_seconds ∉ [5,60]              → CONFIGURATION_ERROR (invalid_timeout)
     ├─ boot step not SUCCEEDED               → READINESS_FAILURE (target_not_booted)
     └─ rootfs access_method ≠ ssh / no host  → CONFIGURATION_ERROR
                     │  (context resolved: store, run_id, rootfs, redactor)
                     ▼
  _reject_if_target_halted(run_id, admission, session_registry)   # NEW, §3.3
     ├─ admission or registry absent          → inert (ungated; legacy/test callers)
     ├─ no authoritative snapshot             → READINESS_FAILURE (snapshot_missing)
     └─ execution_state == HALTED             → READINESS_FAILURE (target_halted)  ← AC#4
                     │  (EXECUTING / UNKNOWN proceed)
                     ▼
  run KDUMP_PROBE_SCRIPT over SSH             # reuses _target_python_remote_argv,
     │  (stdin=script, stdout/stderr → sensitive/, capped, bounded timeout)   build_ssh_argv, runner.run
     ▼
  parse JSON  ──▶ build_kdump_checks(probe)   # NEW pure host-side module, §3.2
     │              (3 independent PrerequisiteChecks + mechanism report)
     ▼
  ToolResponse.success(checks, mechanism, probe artifacts)   # redacted
```

Everything except the probe **script** and the **check builder** is shared with the
introspect prerequisite probe (#84): context resolution, dir layout, the bounded
capped SSH round-trip, JSON parsing, oversize/timeout/cancel handling, and redaction.

## 3. Detailed design

### 3.0 Generalizing `_resolve_probe_context` (shared resolver)

`_resolve_probe_context` (`server.py:2131`) is annotated
`request: DebugIntrospectCheckPrerequisitesRequest`. Since `ty` (hard-gating in CI)
does not structurally duck-type Pydantic models, passing the new request model is a
type error. The resolver is generalized to accept a `Protocol` over the six fields it
reads (`run_id`, `target_ref`, `timeout_seconds`, `debug_profile`, `target_profile`,
`rootfs_profile`):

```python
class _SupportsProbeRequest(Protocol):
    run_id: str
    target_ref: str
    timeout_seconds: int
    debug_profile: str | None
    target_profile: str | None
    rootfs_profile: str | None
```

The introspect call site is unaffected (`DebugIntrospectCheckPrerequisitesRequest`
satisfies the Protocol). The resolver's introspect-specific `host_build_id`
computation (`server.py:2209-2210`) stays — it is unused on the kdump path but
harmless (a build step may or may not exist; the field is just ignored by the kdump
handler). If `ty` rejects the Protocol on attribute variance, the fallback is a shared
base model both requests inherit; the Protocol is preferred for lower blast radius
(ADR 0028 decision 8).

### 3.1 Request / response contract

A new `DebugPostmortemCheckPrereqsRequest` (in `domain.py`), field-identical to
`DebugIntrospectCheckPrerequisitesRequest` (a distinct tool gets a distinct model
per the repo's model-per-tool convention):

| Field | Type | Notes |
|---|---|---|
| `run_id` | str | Existing run (`kernel.create_run`); must have a SUCCEEDED `boot` step. |
| `target_ref` | str | Must equal the manifest's `target_profile`. |
| `timeout_seconds` | int | Handler-bounded to `[5, 60]` (default 20). |
| `debug_profile` / `target_profile` / `rootfs_profile` | str \| null | When non-null, must match the immutable manifest request. |

Success `data`:

| Key | Meaning |
|---|---|
| `kdump_ready` | bool — true iff **no** check is `FAILED` (a `WARNING`, e.g. an unassessed non-local dump target, is non-blocking; §3.2). |
| `mechanism` | `"kdump"` \| `"fadump"` \| `"none"` — the detected active crash-capture mechanism. |
| `probe_id` | the per-call probe id (also the sensitive-artifact subdir). |
| `checks` | list of redacted `PrerequisiteCheck` JSON (3 entries, stable order). |

`artifacts`: `probe-stdout` / `probe-stderr` (sensitive, under `sensitive/`),
`probe-report` (`probe.json`, redacted, non-sensitive).
`suggested_next_actions`: `["artifacts.get_manifest"]` (the readiness verdict is
terminal for this tool; dump listing/fetch is the #95 sibling, not yet registered).

### 3.2 `prereqs/kdump_probe.py` — pure host-side check builder + on-target script

Mirrors `prereqs/drgn_probe.py`'s split: a stdlib-only `KDUMP_PROBE_SCRIPT` that
emits one JSON object of raw facts, and a pure `build_kdump_checks(probe) ->
tuple[list[PrerequisiteCheck], str]` returning the three checks plus the mechanism
string. The builder is the unit-test surface; it never touches SSH.

Raw facts the script gathers (all unconditional, each guarded so one read failing
never aborts the others). The script makes **exactly one** subprocess call —
`systemctl is-active kdump kdump-tools` (one invocation, one state line per unit) —
bounded by **a single in-script timeout `T = max(2, timeout_seconds // 2)`**, which is
templated into the script (`string.Template`, the introspect-wrapper mechanism). Since
there is one call and `T ≤ timeout_seconds // 2 < timeout_seconds`, the subprocess is
provably under the outer `timeout {timeout_seconds}s` bound across the whole `[5, 60]`
range (at the `=5` minimum, `T=2`). A stalled `systemctl` thus yields
`service_active=None` — a `FAILED` service check — instead of overrunning the budget,
getting the whole interpreter killed, and masking the other two facts (independence
invariant). Running both unit names in one call (rather than two sequential calls)
removes the worst-case `2×T` overrun.

| Fact | Source | Used by |
|---|---|---|
| `cmdline_has_crashkernel` | `crashkernel=` substring of `/proc/cmdline` | crashkernel check |
| `kexec_crash_size` | int of `/sys/kernel/kexec_crash_size` (or null) | crashkernel check |
| `fadump_enabled` / `fadump_registered` | int of `/sys/kernel/fadump_{enabled,registered}` (or null) | mechanism + crashkernel check |
| `service_active` | `True` if any unit line from the single `systemctl is-active kdump kdump-tools` call is `active`; `null` if `systemctl` is absent/errors/times out | service check |
| `service_units` | per-unit raw states parsed from that one call's stdout (or an error marker) | service check details |
| `dump_target_directive` | the dump-target directive in `/etc/kdump.conf` if present — a line beginning `raw`/`ext2`/`ext3`/`ext4`/`xfs`/`btrfs`/`minix`/`nfs`/`ssh`/`nvme`/`virtiofs` (the makedumpfile target types); `null` if none/file unreadable | dump-path check (non-local guard) |
| `dump_dir` | the `/etc/kdump.conf` `path` directive when readable, else `/var/crash` | dump-path check |
| `dump_dir_exists` | `os.path.isdir(dump_dir)` | dump-path check |
| `dump_dir_writable` | **transient write probe**: `tempfile.mkstemp(dir=dump_dir, prefix=".ldm-writecheck-")` then `unlink` in a `finally` (returns `False` on any `OSError`; `null` if the dir is absent). NOT `os.access(W_OK)` — the probe runs as root and root bypasses mode bits, so `os.access` returns `True` for any existing dir on a writable mount and could never detect a genuinely unwritable target (ADR 0028 decision 5). Self-cleaning on every path **except** an outer-`timeout` SIGKILL mid-probe, which may leave one small uniquely-named `.ldm-writecheck-*` file; the recognizable prefix lets an operator/agent identify the stray (ADR 0028 decision 5). | dump-path check |
| `dump_dir_write_error` | the `OSError` class/errno when the write probe failed (e.g. `ENOSPC`, `EROFS`, `EACCES`) | dump-path check fix text |
| `arch` | `os.uname().machine` | mechanism reporting |

Mechanism resolution (host-side): `fadump` if `fadump_enabled == 1`; else `kdump`
if (`cmdline_has_crashkernel` and `kexec_crash_size > 0`); else `none`.

Check verdicts:

- **`kdump.crashkernel_reserved`** — `PASSED` if `mechanism == "fadump"` (message
  names fadump as the active POWER mechanism) **or** (`cmdline_has_crashkernel` and
  `kexec_crash_size > 0`). Otherwise `FAILED` with a fix that distinguishes the two
  causes: no `crashkernel=` on the cmdline → "add `crashkernel=` and reboot";
  present but `kexec_crash_size == 0` → "crashkernel reserved 0 bytes; the
  `crashkernel=` value did not reserve memory (too large for available RAM, or
  bad syntax)".
- **`kdump.service_active`** — `PASSED` if any candidate unit is `active`; `FAILED`
  otherwise, fix: "enable and start the kdump service (`systemctl enable --now
  kdump`); this tool reports state only and never starts it." `details` carry the
  per-unit states so an agent sees which unit name applies.
- **`kdump.dump_path_writable`** — when `dump_target_directive` is **non-null**, the
  dump target is a separate device / NFS / SSH whose `path` is relative to that
  target's mount, **not** the rootfs, so a local write-probe would be meaningless;
  the check is `WARNING` ("dump target is a separate `<directive>` device/share; local
  writability not assessed — x86_64 local `/var/crash` is the tested path") and is
  **not** treated as a blocker. Otherwise (local dump dir): `PASSED` if `dump_dir_exists`
  and the write probe succeeded; `FAILED` if missing ("create `<dir>`") or
  present-but-the-write-failed ("`<dir>` is not writable by the capture kernel:
  `<errno>`; fix the mount (read-only?), free space (`ENOSPC`), or
  ownership/permissions"). The fix text is driven by `dump_dir_write_error` so an agent
  gets the specific cause. `details` carry the resolved `dump_dir`, its source
  (`/etc/kdump.conf` vs default), and any `dump_target_directive`. The write probe is
  transient and self-cleaning (§3.0 / scope note) — it is the only oracle that reflects
  what the capture kernel will actually be able to do for a local target.

`kdump_ready = not any(c.status == FAILED for c in checks)` — i.e. no *detected*
blocker. A `WARNING` (e.g. an unassessed non-local dump target) is non-blocking, so a
correctly-configured separate-dump-device target is not falsely reported not-ready; an
agent distinguishes "ready" from "ready-but-something-unassessed" via the per-check
statuses. A fully-local kdump-ready target has all three `PASSED` (AC#1); any genuine
fault is a `FAILED` check (AC#2).

### 3.3 HALTED fast-reject (`_reject_if_target_halted`)

A new module-level helper, the front half of `_admit_run_tests_ssh_tier` without the
`admit_ssh_tier` promotion:

```python
def _reject_if_target_halted(*, run_id, admission, session_registry) -> ToolResponse | None:
    if admission is None or session_registry is None:
        return None                      # inert gate: legacy/handler-test callers run ungated
    target_key = TargetKey(provisioner="local-qemu", target_id=run_id)
    snapshot = _require_snapshot(admission, target_key)        # may raise snapshot_missing
    proof = probe_execution_state(registry=session_registry, admission=admission,
                                  target_key=target_key, generation=snapshot.generation)
    if proof.state is ExecutionState.HALTED:
        return <READINESS_FAILURE / target_halted, suggested target.run_tests? no — resume/detach>
    return None
```

`AdmissionError` (e.g. `snapshot_missing`) is caught at the handler and mapped to its
carried `category`/`code`. The handler calls this **after** `_resolve_probe_context`
(so config errors precede lifecycle errors) and **before** building the SSH argv.

Why proof-only, not full `admit_ssh_tier` promotion: see ADR 0028 decision 3. The
probe is bounded by the SSH command timeout, so a target that halts *between* the
proof read and the SSH attempt cannot hang forever — it fails with the bounded
`INFRASTRUCTURE_FAILURE` path, never an unbounded stall. The fast-reject satisfies
§5.6 rule 2 ("rejected immediately … never left to hang").

### 3.4 Failure contract

| Condition | Category | `details.code` |
|---|---|---|
| run dir / manifest missing | CONFIGURATION_ERROR | (message: `run not found`) |
| profile or `target_ref` ≠ manifest | CONFIGURATION_ERROR | `manifest_profile_mismatch` |
| `timeout_seconds` ∉ [5,60] | CONFIGURATION_ERROR | `invalid_timeout` |
| boot step not SUCCEEDED | READINESS_FAILURE | `target_not_booted` |
| rootfs not ssh / missing ssh fields | CONFIGURATION_ERROR | `unsupported_access_method` / `missing_ssh_field` |
| no authoritative snapshot (gate active) | READINESS_FAILURE | `snapshot_missing` |
| target HALTED | READINESS_FAILURE | `target_halted` |
| ssh transport failed (exit 255 / raised) | INFRASTRUCTURE_FAILURE | `ssh_connect_failure` / `ssh_failure` |
| probe timed out / cancelled / stdin failed | INFRASTRUCTURE_FAILURE | `ssh_failure` |
| stdout over cap | INFRASTRUCTURE_FAILURE | `oversized_output` |
| no python3 on target (exit 127) | INFRASTRUCTURE_FAILURE | `probe_no_python` |
| probe ran but emitted no parseable JSON dict | INFRASTRUCTURE_FAILURE | `probe_unparseable` |

The probe returning JSON always yields a `success` response (the three checks carry
the PASS/FAIL verdicts); only an *infrastructure* failure to obtain facts is a
`ToolResponse.failure`. python3-absent is an infrastructure failure (not synthesized
checks) because, unlike the introspect probe, none of the three kdump facts can be
established without it — a fail-closed verdict, never a false PASS.

### 3.5 Redaction

Raw `stdout.raw` / `stderr.raw` stay under
`<run>/sensitive/debug/postmortem/check_prereqs/<probe_id>/` (0o600, chmod-fixed
dirs). Only `redactor.redact_value([check.model_dump() …])` is returned, and the
persisted `probe.json` is `redactor.redact_value(parsed)`. The redactor is seeded
with the rootfs `ssh_key_ref` (matching the introspect probe). `/proc/cmdline` can
carry secrets (e.g. a root password injected via boot args); redaction before
return and before persist covers that.

## 4. Acceptance-criteria traceability

| AC | Satisfied by |
|---|---|
| kdump-ready target → all three PASS | §3.2 verdicts; env-gated integration test on a kdump-ready guest |
| missing crashkernel / inactive service / unwritable path each FAIL independently, with a fix | §3.2 (independence invariant: all facts gathered before any check); host-side unit tests with synthesized probe dicts |
| fadump POWER target reported as fadump, not a false kdump failure | §3.2 mechanism resolution + crashkernel check; unit test with `fadump_enabled=1`, `kexec_crash_size=0` |
| HALTED target fast-rejected, never hangs | §3.3; handler test injecting a HALTED session record |
| captured output redacted | §3.5; unit test that a seeded secret in probe stdout is absent from the response |
| live test env-gated | integration test guarded on an env var + reachable guest, like `test_drgn_probe_integration.py` |

## 5. Testing strategy

- **`tests/test_prereqs_kdump_probe.py`** (pure, no SSH): `build_kdump_checks` over
  synthesized probe dicts — ready, missing-crashkernel, reserved-0-bytes, inactive
  service, missing dir, write-failed dir (with `dump_dir_write_error` → cause-specific
  fix text), fadump-enabled, mechanism=none. Assert independence (a probe with all
  three faults yields three FAILs) **and** the service-fact-missing case
  (`service_active=null` from a stalled/absent `systemctl` → `kdump.service_active`
  FAILED while the crashkernel and dump-path checks still produce their own verdicts)
  **and** the non-local-dump case (`dump_target_directive` set → `kdump.dump_path_writable`
  WARNING, not a false FAIL, and `kdump_ready` stays true when the other two PASS).
- **Handler tests** (`tests/test_postmortem_check_prereqs.py`): a fake `SshRunner`
  returning canned JSON → success with three checks; HALTED fast-reject via an
  injected session registry; config errors (run-not-found, profile mismatch, bad
  timeout, non-ssh rootfs); python3-absent (exit 127); unparseable stdout;
  redaction of a seeded secret. Handlers called directly with injected
  `ssh_runner=`, `admission=`, `session_registry=`, `rootfs_profiles=`.
- **Capability / config tests**: `debug.postmortem.check_prereqs` in
  `ALLOWED_DEBUG_OPERATIONS` and in `local_drgn_introspect_capability().operations`.
- **Env-gated integration** (`tests/test_kdump_prereqs_integration.py`): real SSH to
  a kdump-capable guest, skipped without the guest env var; never un-gated in CI.

## 6. Open questions

None blocking. The dump-target resolution for non-local devices and POWER fadump
validation are explicitly deferred and documented, not silently claimed.
