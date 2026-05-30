# `debug.postmortem.crash` — host-side crash batch runner

`debug.postmortem.crash` runs a validated batch of [`crash`](https://crash-utility.github.io/)
commands against a captured vmcore + matching vmlinux **on the agent host** and
returns parsed JSON keyed by command plus a preserved, redacted transcript. It is the
`crash`-utility analogue of the offline drgn path (`debug.introspect.from_vmcore`):
offline, host-side, and **always concurrent-safe** — no live target, no admission gate,
never gated by a `DebugProfile`.

Design: [spec](superpowers/specs/2026-05-30-debug-postmortem-crash-design.md) ·
[ADR 0026](adr/0026-postmortem-crash-batch-runner.md).

## Request

| Field | Type | Notes |
|---|---|---|
| `run_id` | str | Existing run (`kernel.create_run`). |
| `vmcore_ref` | str | Run-relative path to the captured vmcore, confined to `<run_dir>`. |
| `vmlinux_ref` | str | Run-relative path to the uncompressed ELF vmlinux with symbols. |
| `modules_ref` | str \| null | Optional run-relative directory of `*.ko[.debug]`. |
| `commands` | list[str] | crash command lines (validated — see below). |
| `timeout_seconds` | int | Handler-bounded to `[5, 300]` (default 60). |

`vmcore_ref`/`vmlinux_ref`/`modules_ref` are **run-relative** and confined to the run
directory. A vmcore captured elsewhere (kdump, or a `virsh dump`) must be staged into
the run directory first; an out-of-sandbox ref is a `configuration_error`.

## Command validation (security)

The path is offline and never gated, so command-content validation is the only trust
boundary. `crash`'s command interpreter is **not** a sandbox: `!` runs a host shell
command, `cmd | prog` pipes to a host shell, and `cmd > file` redirects to a host file.
Each command is therefore checked before any crash invocation:

- **Denied:** a leading `!`, any of `|`, `>`, `<`, `` ` ``, `$(`, `;`, `&`, and any
  newline/control character. A violation is `configuration_error` / `command_not_permitted`.
- **Allowlisted leading verb:** the first token must be a read-only analysis verb
  (`bt`, `ps`, `log`, `kmem`, `sys`, `mod`, `struct`, `union`, `p`, `rd`, `vtop`,
  `task`, `files`, `vm`, `net`, `dev`, `irq`, `mach`, `runq`, `mount`, `swap`, `timer`,
  `dis`, `sym`, `list`, `tree`, `search`, `foreach`, `help`).

Commands are stripped before validation, dedup, and use as the response key; `"bt"` and
`"bt "` are the same command and rejected as a duplicate.

## Response

Success `data`:

- `call_id` — the per-call id.
- `vmcore_build_id` — the verified vmcore build-id.
- `results` — an object keyed by the (stripped) command string. Each value is either a
  typed parsed object (for `bt`/`ps`/`log`/`kmem -i`/`sys`) or a raw-passthrough object
  `{"parsed": false, "reason": ..., "raw": ...}`. Reasons: `unknown_command` (no
  parser), `parse_failed` (parser raised), `output_truncated` (hit the output cap),
  `not_captured` (crash aborted before this command ran). A command is **never** silently
  dropped.
- `module_symbols` — present only when `modules_ref` was supplied:
  `{requested, status: "loaded" | "load_failed", detail}` from the server-injected
  `mod -S` load (best-effort, never fatal).
- `truncated` — `true` when the aggregate output hit the cap.
- `artifacts` — `ArtifactRef`s to the redacted transcript and parsed JSON under
  `<run>/debug/postmortem/crash/<call-id>/`.

### Parsed shapes

| Command | Parsed shape |
|---|---|
| `bt` | `{pid?, command?, frames: [{level, symbol, pc_addr}]}` |
| `ps` | `{processes: [{pid, ppid, cpu, task_addr, st, comm}]}` |
| `log` | `{lines: [{ts, text}]}` |
| `kmem -i` | `{memory: {<label>: {pages, detail}}}` |
| `sys` | `{system: {<KEY>: <value>}}` |

## Build-id fail-loud

Before crash runs, the host compares two build-ids:

- `read_vmcore_build_id(vmcore)` — the vmcore's embedded `VMCOREINFO BUILD-ID` (the
  same value drgn exposes as `main_module().build_id`); and
- `read_elf_build_id(vmlinux)` — the vmlinux's ELF GNU build-id.

A mismatch is `configuration_error` / `provenance_mismatch` and **no crash runs**.
Distinct fail-closed codes:

| Condition | Code |
|---|---|
| vmcore build-id ≠ vmlinux build-id | `provenance_mismatch` |
| vmlinux ELF build-id unreadable (non-ELF / compressed / stripped) | `vmlinux_build_id_unreadable` |
| vmcore is not an ELF container (e.g. compressed-kdump) | `vmcore_format_unsupported` |
| vmcore ELF is truncated / unreadable | `vmcore_build_id_unreadable` |
| vmcore carries no `VMCOREINFO BUILD-ID` (cannot verify) | `provenance_unverifiable` |

The vmcore must be an ELF container from a `CONFIG_BUILD_ID` kernel that registered
VMCOREINFO (kdump `/proc/vmcore`, or a QEMU `dump-guest-memory` with VMCOREINFO).
Compressed-kdump containers are not parsed in this release; they fail loud with
`vmcore_format_unsupported` rather than silently skipping the check.

## Bounds and concurrency

- One `crash` session opens the vmcore once; each command's output is redirected to its
  own file (`cmd-NNNN.out`), so per-command framing is race-free.
- crash runs under `prlimit --fsize` so no single command's output file can exceed the
  per-command cap on disk; the aggregate is bounded by the per-run command limit.
- A timeout (`timeout --kill-after`) cuts the crash child cleanly → `crash_timeout`.
  Runner-level failures always win over partial output.
- No admission gate, no SSH, no target snapshot read: two calls against the same run
  proceed in parallel, regardless of target lifecycle. Each call writes a unique
  `postmortem.crash:<call_id>` manifest step.

## Redaction

Every command output (typed or raw), the persisted `parsed.json`, and the redacted
`transcript.txt` pass through `Redactor()` before being returned or persisted. The
unredacted crash stdout/stderr stays under `<run>/sensitive/…` (mode 0600) and is never
returned.

---

# `debug.postmortem.triage` — composite triage report

`debug.postmortem.triage` is the **one call** for an agent handed a crash, and the
recommended first reaction to the `target.crashed` lifecycle event. It composes the
crash and drgn offline tiers into a single typed report against one `(vmcore, vmlinux)`
pair. It is offline and **never gated**, like the rest of this tier.

Design: [spec](superpowers/specs/2026-05-30-debug-postmortem-triage-design.md) ·
[ADR 0027](adr/0027-postmortem-triage-composition.md).

## Request

| Field | Type | Notes |
|---|---|---|
| `run_id` | str | Existing run (`kernel.create_run`). |
| `vmcore_ref` | str | Run-relative path to the captured vmcore. |
| `vmlinux_ref` | str | Run-relative path to the uncompressed ELF vmlinux with symbols. |
| `modules_ref` | str \| null | Optional run-relative `*.ko[.debug]` dir; used by the crash sub-call only. |
| `timeout_seconds` | int | Handler-bounded to `[5, 300]` (default 60), applied to **each** sub-call. |

The three sub-calls run **sequentially**, so worst-case wall-clock is ≈ 3 ×
`timeout_seconds`; `duration_ms` reports the true elapsed time.

## What it composes

| Report section | Source | Sub-call |
|---|---|---|
| `panic_reason` | crash | `debug.postmortem.crash` `log` (panic line selected from the parsed log) |
| `faulting_task` | crash | `debug.postmortem.crash` `bt` (header pid/command) |
| `backtrace` | crash | `debug.postmortem.crash` `bt` (frames) |
| `recent_dmesg` | drgn | `debug.introspect.from_vmcore_helper` `dmesg` |
| `modules` | drgn | `debug.introspect.from_vmcore_helper` `modules` |

## Partial-report semantics

Each section is tagged `source` (`crash`/`drgn`), `status` (`ok`/`failed`), and — when
failed — a `reason` (the sub-call's stable error code). A failure in **one** source
fails only its sections; the report is returned with `partial: true` as long as at least
one section is `ok`. Only when **every** section failed does triage hard-fail with
`triage_all_sources_failed` (whose `details` carry `sub_call_ids` so a sub-call that
*ran* stays reachable). `sub_call_ids` also lets an agent pull a sub-call's own
transcript/artifacts.

## Build-id fail-loud

Before any sub-call, triage runs the host-authoritative build-id gate **once**
(`read_vmcore_build_id` vs `read_elf_build_id`). A mismatch / unreadable vmlinux /
unverifiable-or-unsupported vmcore is a `configuration_error` and **no sub-call runs** —
the whole triage fails loud, never a degraded report.

## Redaction

The composed report and the persisted `report.json` under
`<run>/debug/postmortem/triage/<call-id>/` pass through `Redactor()`; the
`triage_all_sources_failed` failure `details` are redacted too. Each sub-call's own raw
outputs stay under its own `sensitive/` tree (the sub-tiers' contract).

# `debug.postmortem.check_prereqs` — kdump readiness

`debug.postmortem.check_prereqs` probes a **live, booted** target over SSH and reports
whether it is configured to capture a vmcore on the next panic. It is **diagnostic
only**: it detects and asserts readiness and never enables, configures, starts, or
restarts kdump (configuration is out of scope per #14 — the service state is
*reported*, never changed). The one write it performs is a transient, self-cleaning
write probe of the dump dir (create + immediately remove a temp file) to assert the
dir is genuinely writable by the capture kernel; it modifies no kdump configuration or
service state. Unlike the offline crash/triage tools, it touches a live target, so it
is an ssh-tier op gated on the target lifecycle: a `HALTED` target is fast-rejected
(interface-contracts §5.6 rule 2), never left to hang.

Design: [spec](superpowers/specs/2026-05-30-debug-postmortem-check-prereqs-design.md) ·
[ADR 0028](adr/0028-postmortem-check-prereqs-kdump-readiness.md).

## Request

| Field | Type | Notes |
|---|---|---|
| `run_id` | str | Existing run with a SUCCEEDED `boot` step. |
| `target_ref` | str | Must equal the manifest's `target_profile`. |
| `timeout_seconds` | int | Handler-bounded to `[5, 60]` (default 20). |
| `debug_profile` / `target_profile` / `rootfs_profile` | str \| null | When non-null, must match the immutable manifest request. |

## The three independent checks

The on-target probe gathers **all** facts in one round-trip; the host builds the three
checks from that one object, so one failing probe never masks another.

| `check_id` | PASS when | On FAIL, `suggested_fix` |
|---|---|---|
| `kdump.crashkernel_reserved` | kexec/kdump: `/proc/cmdline` has `crashkernel=` **and** `/sys/kernel/kexec_crash_size > 0`. POWER: `/sys/kernel/fadump_enabled == 1`. | add `crashkernel=` and reboot, or fix a value that reserved 0 bytes. |
| `kdump.service_active` | `systemctl is-active` reports `active` for `kdump` or `kdump-tools`. | enable and start the service (`systemctl enable --now kdump`) — reported only, never started by this tool. |
| `kdump.dump_path_writable` | the configured dump dir (default `/var/crash`, or an `/etc/kdump.conf` `path`) exists and a transient write probe succeeds. | create the dir, or fix the read-only mount / free space (`ENOSPC`) / ownership. |

Success `data` carries `kdump_ready` (true iff all three PASS), `mechanism`
(`kdump`/`fadump`/`none`), `probe_id`, and the redacted `checks`.

## ppc64le / fadump

On POWER, firmware-assisted dump (fadump) replaces kexec-based kdump: it reserves
memory through firmware, so `/sys/kernel/kexec_crash_size` is 0 by design. When
`/sys/kernel/fadump_enabled == 1` the tool reports `mechanism: "fadump"` and the
crashkernel check PASSES — a fadump target is **not** a false kdump failure. x86_64
`/var/crash` kdump is the tested path; fadump detection is documented but unvalidated
(no POWER hardware in this environment). A dump target on a separate device / NFS / SSH
is not resolved — the probe reports the local dir it checked.

## Redaction

Raw probe `stdout`/`stderr` stay under
`<run>/sensitive/debug/postmortem/check_prereqs/<probe_id>/`; only the redacted checks
are returned and the persisted `probe.json` is redacted. `/proc/cmdline` can carry
secrets injected as boot args, so redaction runs before the response **and** before
persistence.
