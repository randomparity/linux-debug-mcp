# ADR 0029 — `debug.postmortem.list_dumps` + `.fetch`: SSH enumeration, scp staging, size-based truncation detection, host-side-only analysis

**Status:** Accepted (2026-05-30) · **Issue:** #95 · **Epic:** #9 · **Supersedes (in part):** #14 · **Affects:** `src/kdive/postmortem/dumps.py` (new: enumeration script + pure `parse_dump_listing` / `derive_dump_id` / `plan_fetch`), `src/kdive/domain.py` (`DebugPostmortemListDumpsRequest`, `DebugPostmortemFetchRequest`, `DumpEntry`, `FetchedFile`), `src/kdive/server.py` (`debug_postmortem_list_dumps_handler`, `debug_postmortem_fetch_handler`, `build_scp_argv`, `_resolve_probe_context` timeout-band generalization, `_reject_if_target_halted` message generalization, tool registration), `src/kdive/config.py` (`ALLOWED_DEBUG_OPERATIONS`, fetch timeout band + size constants), `src/kdive/providers/local_vmcore_retrieval.py` (new capability), `src/kdive/providers/plugins.py`, `src/kdive/artifacts/store.py` (`postmortem_fetch_lock`)

## Context

#95 adds the two live-target tools that move a kdump-captured `vmcore` from a
booted target to the host run directory so the offline analyzers
(`debug.postmortem.crash` #92, `debug.introspect.from_vmcore` #55) can consume it.
`list_dumps` enumerates captured dumps over SSH; `fetch` copies a selected dump
(plus co-located symbols) into the run dir with integrity reporting. #55 explicitly
deferred remote vmcore retrieval to this issue.

Both are ssh-tier live ops, so they inherit the #84/#94 probe machinery
(`_resolve_probe_context`, `_target_python_remote_argv`, `build_ssh_argv`, the capped
SSH round-trip, `_reject_if_target_halted`, redaction). The decisions below are the
ones #95 leaves open and that have viable alternatives; everything else is inherited.

## Decision

### 1. `list_dumps` is an SSH python3 enumeration probe (reuse #84/#94 machinery)

`list_dumps` reuses the probe path verbatim: resolve run/manifest, render a
stdlib-only python3 script, run it over SSH bounded by `timeout {timeout_seconds}s`,
parse one JSON facts object, and let the host build the response. The on-target
script walks the configured dump dir's immediate subdirectories and, for each that
contains a `vmcore` (or `vmcore.flat`/`vmcore-incomplete`), emits one record:
`{dir, vmcore_name, size, mtime, kernel, present}` where `kernel` is the kernel
version parsed from the first line of a readable `vmcore-dmesg.txt` (else null),
`mtime` is the vmcore's `st_mtime` epoch, and `present` lists which co-located files
exist (`vmcore-dmesg.txt`, `vmlinux`, `vmcoreinfo`). The host's pure
`parse_dump_listing(probe) -> list[DumpEntry]` turns the facts into the
contract objects (the same target-emits-facts / host-decides trust boundary as ADR
0028 decision 2). An empty dump dir yields an **empty list and a success response**,
never an error (AC#1).

### 2. `fetch` re-enumerates and matches `dump_ref` against the target's own listing

`fetch(dump_ref)` does **not** scp a caller-supplied path directly. It first re-runs
the same enumeration probe, then requires `dump_ref` to equal one of the dump dirs the
target itself enumerated; a non-match is `CONFIGURATION_ERROR / dump_not_found`. This
makes `fetch` transfer only a dump the target authoritatively reported — eliminating
path-injection (an agent cannot coax scp into pulling `/etc/shadow` or a path with
shell metacharacters) and giving an authoritative, fresh manifest of which co-located
symbol files actually exist to transfer. The extra round-trip is cheap relative to a
multi-GB scp and is the security boundary for the bulk-transfer op.

### 3. Transfer uses `scp`, not `ssh … cat`, because the SSH runner is text-mode

`SubprocessSshRunner.run` opens its stdout file in text mode (`encoding="utf-8"`) and
spawns the subprocess with `text=True`; streaming a binary vmcore through that pipe
would corrupt it (invalid-UTF-8 replacement). `scp` writes the destination file
itself, so the runner only captures scp's textual stdout/stderr — binary integrity is
scp's concern, not the pipe's. A new `build_scp_argv` mirrors `build_ssh_argv` (same
`-o BatchMode/UserKnownHostsFile/ConnectTimeout/StrictHostKeyChecking` options and key
selection) with scp's spellings: uppercase `-P` for the port and a
`user@host:remote_path` source plus a local dest path. scp is driven through the
existing `SshRunner.run` (it is just another bounded, cancelable subprocess). Because
scp's `host:remote_path` is expanded by a **remote** shell (unlike `build_ssh_argv`,
which `shlex.quote`s the whole remote command) and default kdump dirs contain `:` while
hostnames can carry spaces, `build_scp_argv` passes `scp -T` and `shlex.quote`s the
remote path after the `user@host:` prefix so the remote shell receives it literally.

### 4. Truncation detection is a remote-size vs local-size comparison; sha256 is reported

The integrity oracle that AC#3 requires ("a truncated/partial transfer is detected and
reported, not silently accepted") is: record the **expected remote size** for **every**
file the enumeration lists (the script reports `file_sizes` for the core file and each
co-located symbol file, not just the vmcore), transfer via scp, then require scp exit 0
**and** `local_size == expected_size` for each staged file. A short file (dropped
connection mid-transfer, ENOSPC on the host) fails the size check →
`INFRASTRUCTURE_FAILURE / incomplete_transfer`, the partial dest dir is removed, and
**no** SUCCEEDED step is recorded. Each retrieved file additionally reports its local
`sha256` + `size_bytes` (for provenance and the agent's own end-to-end verification);
the local hash is a local-disk-bound re-read whose cost the decision-7 size ceiling
bounds (it is not covered by the scp `timeout_seconds`, which bounds only the transfer
subprocess). A full **remote** sha256 is *not* computed by default: hashing a multi-GB
vmcore on the target reads the whole file an extra time, and size + scp's own exit
status already detect truncation. (A future opt-in remote-hash verification — and a
future opt-out of the local hash for very large cores — are noted as rejected-for-now
alternatives.)

### 5. Staging layout and a deterministic `dump_id`

Fetched files land under `<run>/debug/postmortem/dumps/<dump_id>/`, returning
**run-relative refs** (`debug/postmortem/dumps/<dump_id>/vmcore`, …) that
`debug.postmortem.crash` and `debug.introspect.from_vmcore` accept directly (they
`confine_run_relative` such refs against the run dir). `dump_id` is derived
deterministically from the remote dump dir so a re-fetch maps to the same staging dir:
`dump_id = <sanitized-basename>-<sha256(remote_dir_path)[:8]>`, where the basename is
slugged to `[A-Za-z0-9._-]` (other chars → `_`). The 8-hex suffix disambiguates two
distinct remote dirs whose basenames slug identically. `vmcore` is always staged;
`vmcore-dmesg.txt`, `vmlinux`, `vmcoreinfo` are staged when decision 2's listing shows
them co-located; their refs are null when absent. Module debuginfo is not co-located
in the tested `/var/crash` layout, so `modules_ref` is null on the tested path and the
field is reserved for a future layout that ships it.

### 6. Idempotency: a SUCCEEDED `postmortem.fetch:<dump_id>` step short-circuits; `force` re-transfers

`fetch` is idempotent by `run_id` + `dump_id`, mirroring the repo's step contract
(CLAUDE.md "idempotent by run_id + step name"). The step name is
`postmortem.fetch:<dump_id>`. Under a per-run `postmortem_fetch_lock`: load the
manifest; if a SUCCEEDED `postmortem.fetch:<dump_id>` exists and `force` is false,
return the recorded refs unchanged with `already_fetched=true` and **no** re-transfer
(this is what "refuse to overwrite an already-fetched dump unless force" means — the
existing staged dump is returned, never silently re-pulled). With `force=true`, the
dest dir is cleared and the dump re-transferred, replacing the step
(`replace_succeeded=True`). A prior **non-SUCCEEDED** attempt (a crashed transfer that
left a partial dir but no SUCCEEDED step) does not short-circuit: the dest dir is
cleared and re-fetched. The manifest step — not dir existence — is the source of truth.

### 7. `fetch` is bounded three ways before a byte moves: timeout band, size ceiling, free-space precheck

A bulk multi-GB scp cannot complete inside the probe's `[5, 60]` band. `fetch`'s
`timeout_seconds` defaults to 300 and is bounded `[5, 3600]`; `list_dumps` keeps the
probe `[5, 60]` (default 20). `_resolve_probe_context`'s hard-coded `[5, 60]` check is
generalized to a `(min, max)` parameter (default `(5, 60)`), so the shared resolver
serves both ops — the same low-blast-radius generalization #94 applied to the request
type (ADR 0028 decision 8).

"Bounded transfer" is an explicit issue-scope item, so the size bound is **not** opt-in.
Because the enumeration (decision 2) stat'd the exact total fetch size before any
transfer, `fetch` enforces, before taking the lock: (a) a **default ceiling**
`DEFAULT_FETCH_MAX_BYTES` (a config constant), which the request's `max_bytes` overrides
when set — a dump whose total exceeds the effective ceiling is refused
`CONFIGURATION_ERROR / dump_too_large`; and (b) a **free-space precheck** —
`shutil.disk_usage(dest).free` below the total plus a headroom margin is refused
`INFRASTRUCTURE_FAILURE / insufficient_disk`. The host is therefore never filled by a
transfer it could have predicted would not fit, and the unbounded-by-default
disk-consumption failure mode is closed.

`fetch` also refuses a non-finished core. A `vmcore.flat` (makedumpfile flat format) is
refused `READINESS_FAILURE / dump_flat_format` **even with** `force`: crash/drgn cannot
read it without a `makedumpfile -R` rebuild on the target (out of scope), so staging it
as `vmcore` would hand the agent an unusable ref. An in-progress `vmcore-incomplete`
core is refused `dump_incomplete` unless `force` — it is a partial of the *same* format
the finished `vmcore` would have, so a forced fetch stages the partial as `vmcore`; its
size races a still-writing file, which is why `force` is the explicit override.

### 8. HALTED fast-reject on both ops (reuse #94, generalized message)

Both ops call `_reject_if_target_halted` (ADR 0028 decision 3) after
`_resolve_probe_context` and before any SSH — a HALTED target is fast-rejected with
`READINESS_FAILURE / target_halted`, never left to hang (§5.6 rule 2). The helper's
kdump-specific message is generalized to take an `action` phrase so each op names its
own action ("enumerating dumps" / "fetching a dump"). The proof-only fast-reject (not a
full `admit_ssh_tier` promotion) is sufficient for the same reason as #94: the SSH/scp
command timeout bounds the residual TOCTOU window.

### 9. Host-side-only analysis this phase; target-side deferred and documented

#95 pulls the vmcore to the host for offline analysis. Running `crash`/drgn **on** the
target ("target-side analysis", the large-dump alternative from #14's design) is out
of scope and documented as the deferred large-dump path — for a vmcore too large to
transfer economically, target-side analysis avoids the move, but it is not implemented
here. `list_dumps` reports sizes so an agent can choose before committing to a fetch;
the docs carry the host-side vs target-side tradeoff.

### 10. A new `local-vmcore-retrieval` capability (not the introspect capability)

`fetch` requires `scp` in addition to `ssh`. Adding `scp` to `local-drgn-introspect`'s
`required_host_tools` would over-declare scp for the pure introspect/probe ops that
never transfer files. A new `local-vmcore-retrieval` capability (`transports=["ssh"]`,
`required_host_tools=["ssh", "scp"]`, `operations=["debug.postmortem.list_dumps",
"debug.postmortem.fetch"]`) advertises the real requirement honestly. This is the
opposite of ADR 0028 decision 5 (which rode the existing capability) precisely because
#94 added **no** new host tool while #95 does. `list_dumps` rides the same capability
even though it needs only ssh — a conservative single-capability advertisement; its
handler never invokes scp, so an scp-absent host still serves `list_dumps` at runtime.

### 11. Redaction of listings and file metadata

Dump paths, kernel-version strings, and dmesg-derived metadata can carry secrets, so
every listing/metadata object is `redactor.redact_value`'d before it is returned **and**
before the `probe.json` / `fetch.json` artifacts are persisted. The redactor is seeded
with the rootfs `ssh_key_ref` (the resolver already does this). Raw scp/ssh
stdout/stderr stay under `<run>/sensitive/…` at 0o600.

### 12. ppc64le / fadump layout note

The enumeration is layout-based (any dump-dir subdir holding a `vmcore`), so it is not
x86_64-specific by construction, but x86_64 `/var/crash` is the only **tested** path.
POWER fadump may write a different path/capture layout; this is documented, not
silently claimed, consistent with #14 and ADR 0028 decision 4.

## Consequences

- One new pure module (`postmortem/dumps.py`: enumeration script + pure
  `parse_dump_listing` / `derive_dump_id` / `plan_fetch`), two handlers, one new
  capability, `build_scp_argv`, and small generalizations of `_resolve_probe_context`
  (timeout band) and `_reject_if_target_halted` (message). The pure functions give full
  branch coverage of enumeration parsing and fetch planning without a target.
- `fetch` transfers only target-enumerated dumps, closing the path-injection surface
  the bulk-transfer op would otherwise open.
- Truncation is caught by a deterministic size comparison; the partial dir is cleaned
  and no success is recorded, so a downstream analyzer never reads a short vmcore.
- A re-fetch without `force` returns the staged refs without re-pulling; `force`
  replaces — the established idempotency contract.
- scp is a new host-tool dependency, advertised on a dedicated capability so the
  introspect ops are unaffected.

## Considered & rejected

1. **Stream the vmcore over the existing `ssh … cat` channel (no scp dependency).**
   Rejected: `SubprocessSshRunner` is text-mode (`text=True`, utf-8 stdout file), so a
   binary vmcore would be corrupted by the pipe; making the runner binary-aware is a
   larger, riskier change than adding scp, and scp also gives transfer semantics
   (resume-nothing but a clean exit status) for free. (decision 3)
2. **Trust the caller-supplied `dump_ref` after lexical/shell-quote validation.**
   Rejected: even shlex-quoted, a lexically-confined path can be a symlink or a
   non-dump file, and the op would then transfer arbitrary target content. Re-enumerating
   and matching against the target's own listing is the only check that guarantees fetch
   moves a real dump. (decision 2)
3. **Always compute a remote sha256 and compare to the local hash.** Rejected as the
   default: it reads the whole multi-GB vmcore an extra time on the target and doubles
   the transfer-time cost for a guarantee that size + scp's exit status already deliver
   for the truncation case AC#3 names. Noted as a future opt-in for callers who need
   end-to-end content verification of a small dump. (decision 4)
4. **Hard-code one timeout band for probes and transfers.** Rejected: `[5, 60]` cannot
   fit a multi-GB scp and `[5, 3600]` is absurd for a read-only probe; parameterizing the
   resolver's band is one argument and keeps both ops on the shared resolver. (decision 7)
5. **A filesystem completion sentinel (dir-exists) for idempotency instead of a manifest
   step.** Rejected: a crashed transfer leaves a dir with no sentinel-vs-complete
   distinction, and the repo's idempotency contract is manifest-step-based. Keying on a
   SUCCEEDED `postmortem.fetch:<dump_id>` step matches build/boot/tests/crash and
   correctly treats a partial prior dir as "not fetched". (decision 6)
6. **Ride the `local-drgn-introspect` capability (as #94's check_prereqs did).**
   Rejected: #94 added no host tool, so riding was honest; #95 needs `scp`, and folding
   it into the introspect capability would falsely require scp for `debug.introspect.run`
   and the probes. A dedicated `local-vmcore-retrieval` capability advertises the real
   dependency. (decision 10)
7. **Stage under a caller-named or random `dump_id`.** Rejected: a random id breaks
   re-fetch idempotency (decision 6 needs a stable key) and a caller-named id reopens a
   path-injection/collision surface. A deterministic `slug-hash` derivation is stable and
   collision-resistant. (decision 5)
8. **Fetch every file in the dump dir.** Rejected: a dump dir can hold operator junk; we
   stage only the known kdump artifacts (`vmcore`, `vmcore-dmesg.txt`, `vmlinux`,
   `vmcoreinfo`) that the analyzers consume, keeping the transfer bounded and the staged
   set predictable. (decision 5)
