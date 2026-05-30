# ADR 0028 — `debug.postmortem.check_prereqs`: live-target kdump readiness via the shared SSH probe, proof-only HALTED gate, mechanism-aware checks

**Status:** Accepted (2026-05-30) · **Issue:** #94 · **Epic:** #9 · **Affects:** `src/linux_debug_mcp/prereqs/kdump_probe.py` (new: `KDUMP_PROBE_SCRIPT` + `build_kdump_checks`), `src/linux_debug_mcp/domain.py` (`DebugPostmortemCheckPrereqsRequest`), `src/linux_debug_mcp/server.py` (`_reject_if_target_halted`, `debug_postmortem_check_prereqs_handler`, tool registration; `_resolve_probe_context` parameter generalized to a `Protocol`; `_prepare_probe_dirs` parametrized), `src/linux_debug_mcp/config.py` (`ALLOWED_DEBUG_OPERATIONS`), `src/linux_debug_mcp/providers/local_drgn_introspect.py` (capability `operations`)

## Context

#94 adds the first **live-target** `debug.postmortem` tool. Where #92/#93 analyze a
captured vmcore offline (no target, never gated — ADR 0010/0026/0027), this tool
probes a booted target over SSH to assert kdump readiness *before* a panic, so an
agent learns "this target will not produce a dump" while it can still act, not after.

It is the readiness sibling of `debug.introspect.check_prerequisites` (#84): same
shape (resolve run/manifest, run a stdlib python3 probe over SSH, parse JSON, build
`PrerequisiteCheck`s). The introspect prereq probe already factored the reusable
machinery (`_target_python_remote_argv`, `_resolve_probe_context`,
`_prepare_probe_dirs`, `_read_capped`, the capped/bounded SSH round-trip). The
decisions below are the ones #94 leaves open and that have viable alternatives;
everything else is inherited from #84 unchanged.

## Decision

### 1. Reuse the #84 SSH-probe machinery with a kdump-specific script + check builder

The handler reuses `_resolve_probe_context`, `_target_python_remote_argv`,
`build_ssh_argv`, the `SshRunner` round-trip, `_read_capped`, and the
oversize/timeout/cancel handling verbatim. Only two things are new: a kdump
`KDUMP_PROBE_SCRIPT` (stdlib-only python3 emitting one JSON facts object) and a pure
`build_kdump_checks(probe) -> (checks, mechanism)` in a new `prereqs/kdump_probe.py`,
mirroring `prereqs/drgn_probe.py`'s script/builder split. The builder is the
unit-test surface and never touches SSH.

### 2. The on-target script gathers facts; the host decides verdicts

The script reads raw facts only (`/proc/cmdline`, `/sys/kernel/kexec_crash_size`,
`/sys/kernel/fadump_*`, `systemctl is-active`, dump-dir existence/writability) and
emits them as one JSON object. All reads are independently guarded so one failing
read never aborts the others, and **all** facts are gathered in a single round-trip
before any verdict — that is what makes the three checks independent (AC#2): one
probe's failure cannot mask another because the host builds all three from the same
already-collected object. Trust boundary: the target emits data, the host emits the
contract objects (same rule as ADR 0026 decision-mirroring; the target never decides
PASS/FAIL).

The script makes exactly one subprocess call — `systemctl is-active kdump kdump-tools`
(both unit names in one invocation, one state line per unit) — bounded by a single
in-script timeout `T = max(2, timeout_seconds // 2)`, templated into the script via
`string.Template` (the introspect-wrapper mechanism). One call at `T ≤ timeout_seconds
// 2 < timeout_seconds` is provably under the outer `timeout {timeout_seconds}s`
interpreter bound for the whole `[5, 60]` range — including the `=5` minimum, where a
fixed "≤5 s" timeout run twice would have overrun the budget and got the interpreter
killed (→ no JSON → a total `INFRASTRUCTURE_FAILURE` masking the crashkernel and
dump-path facts, the cross-check the independence invariant forbids). With this bound,
a stalled/blocked `systemctl` yields `service_active=null` → a `FAILED` service check
while the file-read facts still return their own verdicts.

### 3. HALTED is a proof-only fast-reject, not a full admission promotion

The handler calls a new `_reject_if_target_halted` — the front half of
`_admit_run_tests_ssh_tier`: read the authoritative snapshot, take a fresh
`probe_execution_state` proof, and return `READINESS_FAILURE / target_halted` when
`HALTED`. It does **not** call `admit_ssh_tier` (no tier promotion, no
`complete()/rollback()` handle, no cancel-fence thread). When `admission` or
`session_registry` is absent (handler tests, legacy callers) the gate is inert.

Rationale: §5.6 rule 2 requires that an ssh-tier op against a HALTED target be
"rejected immediately … never left to hang." The proof-only pre-check delivers the
immediate rejection; the existing SSH command timeout bounds the residual
TOCTOU window (a target that halts *after* the proof but *before*/*during* the SSH
attempt fails on the bounded `INFRASTRUCTURE_FAILURE` path, never an unbounded
stall). A bounded, read-only, single-shot probe does not need the promotion +
cancel-fence machinery that `target.run_tests` needs for a long-running, multi-command
execution that must be cancelled mid-flight on a halt.

### 4. Mechanism-aware crashkernel check (fadump is not a kdump failure)

The host resolves the active mechanism: `fadump` if `/sys/kernel/fadump_enabled ==
1`, else `kdump` if (`crashkernel=` present **and** `kexec_crash_size > 0`), else
`none`. The `kdump.crashkernel_reserved` check PASSES on an active-fadump target and
names fadump as the POWER mechanism, rather than FAILing because `kexec_crash_size`
is 0 (firmware-assisted dump reserves memory differently — AC#3). x86_64 `/var/crash`
kdump is the tested path; fadump is detected-and-reported but unvalidated (no POWER
hardware) and documented as such, consistent with #14's "documented, not silently
claimed" stance.

### 5. Writability is a transient write probe, not `os.access(W_OK)`; dump-dir resolution is local-only

The probe runs as root (`_target_python_remote_argv` prefixes `sudo` for a non-root
login; a root login is already root). Root bypasses DAC mode-bit checks, so
`os.access(dump_dir, W_OK)` returns `True` for *any* existing directory on a writable
mount regardless of owner/mode — it could never detect a genuinely unwritable target
and AC#2's "unwritable dump path FAILs" would be unreachable. Instead the script
performs a **transient write probe**: create a uniquely named temp file in `dump_dir`,
then `unlink` it in a `finally`. `dump_dir_writable` is the success of that probe; on
`OSError` the errno (`EROFS`, `ENOSPC`, `EACCES`, …) is captured into
`dump_dir_write_error` and drives a cause-specific fix message. This is the only
oracle that reflects what the kdump capture kernel (also root) will actually
experience. It uses `tempfile.mkstemp(dir=dump_dir, prefix=".ldm-writecheck-")` and
`unlink`s in a `finally`; it changes no kdump configuration or service state, so the
tool remains diagnostic and "read-only" is narrowed to "does not modify kdump
config/service state" (the spec scope note). Cleanup runs on every path **except** an
outer-`timeout --kill-after` SIGKILL mid-probe (SIGKILL skips `finally`), which may
leave one small uniquely-named `.ldm-writecheck-*` file in the dump dir; the
recognizable prefix lets an operator/agent identify the stray. This residual is
benign (tiny, self-identifying) and accepted rather than guarded with a signal
handler.

The dump dir itself is the `path` directive of `/etc/kdump.conf` when that file is
readable, else the `/var/crash` default; the resolved dir and its source are in
`details`. A dump target on a separate block device / NFS / SSH (where `path` is
relative to that target's mount, not the rootfs) is **not** resolved; the limitation
is documented. This matches the issue's "default `/var/crash`" and keeps the probe a
diagnostic, not a kdump.conf interpreter.

### 6. python3-absent is a fail-closed infrastructure failure, not synthesized checks

Unlike the introspect probe (which synthesizes a partial check set on exit 127
because its `python3`/`drgn` checks are *about* the interpreter), none of the three
kdump facts can be established without python3 on the target. Exit 127 therefore
returns `INFRASTRUCTURE_FAILURE / probe_no_python` — a fail-closed verdict that never
emits a false PASS for a readiness the probe could not measure.

### 7. Listed for enumerability; capability on the ssh side; not enabled-operations-gated

`debug.postmortem.check_prereqs` is added to `ALLOWED_DEBUG_OPERATIONS` (so
`providers.list` and the default `DebugProfile` enumerate it) and to the
`local-drgn-introspect` capability's `operations` (the ssh-capable capability;
`local-crash-postmortem` is `transports=["filesystem"]` and cannot host an ssh op).
Like `debug.introspect.check_prerequisites`, it is a read-only diagnostic and is
**not** gated through `_ensure_debug_operation_enabled` / `DebugProfile.enabled_operations`
— the only lifecycle gate is the §5.6 HALTED fast-reject (decision 3).

### 8. `_resolve_probe_context` is generalized to a `Protocol`

`_resolve_probe_context` is annotated for `DebugIntrospectCheckPrerequisitesRequest`;
`ty` (hard-gating) does not structurally accept a different Pydantic model, so the
"reused verbatim" claim does not hold without a change. The parameter is generalized
to a `Protocol` (`_SupportsProbeRequest`) over the six fields the resolver reads
(`run_id`, `target_ref`, `timeout_seconds`, `debug_profile`, `target_profile`,
`rootfs_profile`); both request models satisfy it and the introspect call site is
unchanged. The resolver's introspect-specific `host_build_id` computation stays —
unused on the kdump path but harmless (the kdump handler ignores it). If `ty` rejects
the Protocol on attribute variance, the fallback is a shared base model both requests
inherit (equivalent, higher blast radius — see rejected #8).

## Consequences

- One new pure module (`prereqs/kdump_probe.py`) and one new handler; the rest is
  reuse, plus a one-line generalization of `_resolve_probe_context`'s parameter type.
  The pure builder gives full branch coverage of the verdict matrix without a target.
- The three checks are guaranteed independent because the host builds them from a
  single pre-collected facts object.
- A HALTED target is rejected without the promotion machinery; the residual
  TOCTOU window is bounded by the SSH timeout, not unbounded.
- fadump targets get a correct, non-false-negative readiness report, but fadump
  remains an untested code path until POWER hardware exists.
- `_prepare_probe_dirs` gains a `category` parameter (default unchanged) so the
  introspect path keeps `debug/checkprereq/<id>` while postmortem uses
  `debug/postmortem/check_prereqs/<id>`. Behavior for existing callers is identical.

## Considered & rejected

1. **Full `admit_ssh_tier` promotion + cancel-fence (mirror `target.run_tests`
   exactly).** Rejected: heavier than a bounded, read-only, single-shot probe
   warrants — it adds a promotion handle, `complete()/rollback()` lifecycle, and a
   daemon cancel-watcher thread to defend against a mid-op halt that the SSH timeout
   already bounds. `debug.introspect.check_prerequisites` set the precedent of a
   bounded probe; #94 only adds the HALTED *fast-reject*, which the proof-only check
   delivers. (decision 3)
2. **No lifecycle gating at all (copy `debug.introspect.check_prerequisites`
   verbatim).** Rejected: #94 AC#4 explicitly requires HALTED fast-reject; an ungated
   probe against a HALTED kernel hangs on a dead network stack until the SSH timeout —
   the exact "never left to hang" failure §5.6 rule 2 forbids surfacing late.
3. **Build the `PrerequisiteCheck`s inside the on-target script.** Rejected: the
   verdict logic would be untestable without a live target and would trust
   target-emitted contract objects across the SSH trust boundary. The script emits
   facts; the host decides — matching `drgn_probe.py`. (decision 2)
4. **A pure-shell on-target probe (avoid the python3 dependency).** Rejected:
   emitting well-formed, redaction-safe JSON from shell is fragile (quoting,
   locale, `set -e` interactions). python3-stdlib is the established probe substrate
   (#84) and is present on every kdump-capable distro the tested path targets; its
   absence is a clean fail-closed `probe_no_python` (decision 6).
5. **A new `local-kdump-prereqs` provider capability.** Rejected: needless surface.
   The op rides the existing ssh-probe capability (`local-drgn-introspect`), which
   already advertises `debug.introspect.check_prerequisites` and requires ssh.
   (decision 7)
6. **Synthesize a partial check set when python3 is absent (like the introspect
   probe's exit-127 path).** Rejected: the introspect checks are *about* the
   interpreter, so a partial set is meaningful there; the kdump checks are about
   crashkernel/service/path facts that python3 absence makes wholly unmeasurable, so a
   synthesized PASS/SKIP set would misrepresent readiness. Fail closed instead.
   (decision 6)
7. **Parse `/etc/kdump.conf` fully (dump device, NFS, raw, ssh targets).** Rejected
   for this issue: the dump-target filesystem semantics (path relative to a mounted
   dump device) are out of scope; the probe resolves the local dir and documents the
   limitation. A future issue can extend it when a non-local dump target is in scope.
   (decision 5)
8. **Generalize `_resolve_probe_context` via a shared base model instead of a
   `Protocol`.** Equivalent for `ty`, but it changes the class hierarchy of the
   already-shipped `DebugIntrospectCheckPrerequisitesRequest` (higher blast radius for
   no benefit). The `Protocol` leaves both concrete models untouched. Kept as the
   fallback only if `ty` rejects the Protocol. (decision 8)
9. **`os.access(dump_dir, W_OK)` for the writability fact.** Rejected: the probe runs
   as root and root bypasses DAC mode bits, so `os.access(W_OK)` returns `True` for any
   existing dir on a writable mount — it can detect only a missing dir or a read-only
   mount, never a genuinely misconfigured (wrong owner/mode/full) target, leaving AC#2
   unreachable. The transient write probe is the faithful oracle. (decision 5)
10. **Narrow the dump-path check to "exists + on a writable mount" and drop the
    permission fix text (the reviewer's alternative b).** Rejected: it would weaken
    AC#2 to something the root probe can technically satisfy while still missing
    `ENOSPC`/`EROFS` distinctions an agent needs. The write probe is barely more code,
    self-cleaning, and yields the specific errno. (decision 5)
