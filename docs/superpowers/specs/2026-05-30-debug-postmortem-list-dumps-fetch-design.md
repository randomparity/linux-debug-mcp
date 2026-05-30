# `debug.postmortem.list_dumps` + `.fetch` — vmcore retrieval to host

**Date:** 2026-05-30
**Issue:** #95
**Epic:** #9 (Remote interactive kernel debugging for coding agents)
**Supersedes (in part):** #14
**Status:** Draft — pending adversarial review
**Depends on:** #51 (`debug.introspect.run` foundation: `SshRunner`/`SubprocessSshRunner`, `build_ssh_argv`, known_hosts handling, `Redactor`, profile gating); the shared probe machinery from #84/#94 (`_resolve_probe_context`, `_target_python_remote_argv`, `_prepare_probe_dirs`, `_read_capped`, `PROBE_STDOUT_CAP`, `_reject_if_target_halted`)
**Design decisions:** [ADR 0029](../../adr/0029-postmortem-list-dumps-fetch.md)

## 1. Background and scope

`debug.postmortem.crash` (#92) and `debug.introspect.from_vmcore` (#55) analyze a
captured `vmcore` **offline, on the host**. Before they can run, the vmcore that kdump
captured on the target has to be moved to the host run directory. #55 explicitly
deferred remote vmcore retrieval to this issue. #95 adds the two live-target SSH tools
that do the move:

- **`debug.postmortem.list_dumps(run_id, target_ref, …) → ToolResponse`** — enumerate
  captured dumps under the configured dump dir over SSH; return one entry per dump
  (`path`, `kernel`, `time`, `size`); an **empty list** (not an error) when none exist.
- **`debug.postmortem.fetch(run_id, target_ref, dump_ref, …) → ToolResponse`** — copy
  the selected dump's `vmcore` plus co-located `vmcoreinfo`/`vmlinux` (where present)
  into `<run>/debug/postmortem/dumps/<dump_id>/`, returning **run-relative refs** that
  the crash/from_vmcore analyzers accept directly; report `sha256` + size per file;
  detect a truncated transfer; refuse to re-fetch without `force`.

Both are ssh-tier live ops: they require a booted target and are gated by the §5.6
HALTED fast-reject. Neither analyzes the dump — they only enumerate and stage it.

### In scope

- Two MCP tools wired via `server.py`'s registration pattern, each calling a handler
  that is the unit of testing (called directly with injected `ssh_runner=`,
  `admission=`, `session_registry=`, `rootfs_profiles=`).
- `list_dumps`: an SSH python3 enumeration probe over the configured dump dir
  (default `/var/crash`; the `vmcore` + `vmcore-dmesg.txt` layout), reusing the
  #84/#94 probe path. Empty dir → empty list, success (AC#1).
- `fetch`: re-enumerate, match `dump_ref` against the target's own listing
  (path-injection guard, ADR 0029 decision 2), scp the vmcore + co-located symbols
  into the run dir, report per-file `sha256` + size, detect truncation by remote-size
  vs local-size comparison (AC#3), refuse re-fetch without `force` (AC#4), return
  run-relative refs (AC#2).
- HALTED fast-reject on both ops (§5.6 rule 2 / AC#5).
- Redaction of all listing/metadata before return **and** before persist (AC#5).
- New `local-vmcore-retrieval` capability (`required_host_tools=["ssh", "scp"]`).
- `debug.postmortem.list_dumps` / `debug.postmortem.fetch` added to
  `ALLOWED_DEBUG_OPERATIONS` (enumerability).
- Docs: a retrieval section in `docs/debug-postmortem.md`, including the host-side vs
  target-side tradeoff and the ppc64le/fadump layout note.
- An **env-gated** live-target integration test (skipped without a reachable guest with
  a captured dump); pure-function unit tests of enumeration parsing + fetch planning;
  handler tests with a fake `SshRunner` covering success/error/edge paths.

### Out of scope

| Concern | Where it lives |
|---|---|
| Analyzing the dump (running `crash`/drgn) | #92 / #55 (the analyzers this feeds) |
| Triggering/capturing the dump (kdump does that on panic) | target-side, not this tool |
| Target-side analysis (run `crash`/drgn **on** the target) | deferred; documented as the large-dump alternative (ADR 0029 decision 9) |
| Resolving a dump target on a separate device / NFS / SSH | the enumeration walks the resolved local dump dir; non-local dump targets are documented, x86_64 `/var/crash` is the tested path |
| Default remote sha256 content verification | rejected default (ADR 0029 decision 4 / rejected #3); size + scp exit status is the truncation oracle |
| Gating on `DebugProfile.enabled_operations` | not gated — like the other read/stage live diagnostics; the lifecycle gate is the HALTED fast-reject |

## 2. Architecture overview

```
agent ──MCP──▶ list_dumps handler                     fetch handler
                  │                                       │
   _resolve_probe_context(req, band=(5,60))   _resolve_probe_context(req, band=(5,3600))
                  │                                       │
   _reject_if_target_halted(action="enumerating dumps")  _reject_if_target_halted("fetching a dump")
                  │                                       │
   run DUMP_LIST_SCRIPT over SSH                 run DUMP_LIST_SCRIPT over SSH (re-enumerate)
                  │                                       │  match dump_ref → DumpEntry (else dump_not_found)
   parse_dump_listing(probe) → [DumpEntry]               │  max_bytes guard → dump_too_large
                  ▼                                       │  postmortem_fetch_lock(run_id):
   ToolResponse.success(dumps=[…])                        │    SUCCEEDED postmortem.fetch:<id> & !force → cached
                                                          │    plan_fetch(entry) → files to scp
                                                          │    for each: build_scp_argv → runner.run
                                                          │    size match? sha256? else incomplete_transfer
                                                          │    record SUCCEEDED step
                                                          ▼
                                            ToolResponse.success(vmcore_ref, …, files=[…])
```

Everything except the enumeration **script**, the pure host parsers
(`parse_dump_listing` / `derive_dump_id` / `plan_fetch`), `build_scp_argv`, and the
fetch staging/idempotency loop is shared with the #84/#94 probe path.

## 3. Detailed design

### 3.0 Shared-resolver generalization (timeout band)

`_resolve_probe_context` hard-codes the `[5, 60]` timeout check. It is generalized to
take `timeout_band: tuple[int, int] = (5, 60)`; `list_dumps` passes the default,
`fetch` passes `(5, 3600)` (ADR 0029 decision 7). The introspect/kdump call sites are
unchanged (they take the default). Everything else the resolver does (run/manifest
existence, profile-immutability match, boot-SUCCEEDED, rootfs-is-ssh, redactor seed) is
reused verbatim — both new request models satisfy the existing `_SupportsProbeRequest`
Protocol (`run_id`, `target_ref`, `timeout_seconds`, `*_profile`).

### 3.1 Request / response contracts

`DebugPostmortemListDumpsRequest` (in `domain.py`):

| Field | Type | Notes |
|---|---|---|
| `run_id` | str | Existing run with a SUCCEEDED `boot` step. |
| `target_ref` | str | Must equal the manifest `target_profile`. |
| `dump_dir` | str \| null | Override the default `/var/crash`; absolute path, validated by the handler. |
| `timeout_seconds` | int | Handler-bounded `[5, 60]` (default 20). |
| `debug_profile` / `target_profile` / `rootfs_profile` | str \| null | When non-null, must match the immutable manifest request. |

`list_dumps` success `data`: `{"dump_dir": str, "dumps": [DumpEntry…], "probe_id": str}`.
`suggested_next_actions`: `["debug.postmortem.fetch"]`.

`DumpEntry` (domain Model): `path` (remote dump dir, the `dump_ref` for fetch),
`kernel` (str|None), `capture_time` (ISO-8601 str|None — derived host-side from the
vmcore mtime), `size_bytes` (int — the vmcore's size), `incomplete` (bool — a
`vmcore-incomplete`/`vmcore.flat`-only dir), `available_files` (list[str] — which of
`vmcore-dmesg.txt`/`vmlinux`/`vmcoreinfo` are co-located).

`DebugPostmortemFetchRequest` (in `domain.py`):

| Field | Type | Notes |
|---|---|---|
| `run_id` | str | As above. |
| `target_ref` | str | As above. |
| `dump_ref` | str | A `path` from `list_dumps`; re-validated against a fresh enumeration (decision 2). |
| `force` | bool | Default false; true re-transfers and replaces (decision 6) **and** overrides the `incomplete`-dump refusal (§3.4 step 2.5). |
| `dump_dir` | str \| null | Same override as `list_dumps`; the re-enumeration uses it. |
| `max_bytes` | int \| null | Per-call override of the default ceiling `DEFAULT_FETCH_MAX_BYTES`; refuse a dump whose total fetch size exceeds the effective ceiling (`dump_too_large`) before any transfer. `null` ⇒ the default ceiling still applies. |
| `timeout_seconds` | int | Handler-bounded `[5, 3600]` (default 300). |
| `debug_profile` / `target_profile` / `rootfs_profile` | str \| null | As above. |

`fetch` success `data`: `{"dump_id": str, "vmcore_ref": str, "vmlinux_ref": str|None,
"vmcoreinfo_ref": str|None, "vmcore_dmesg_ref": str|None, "modules_ref": str|None,
"files": [FetchedFile…], "total_bytes": int, "already_fetched": bool}`.
`suggested_next_actions`: `["debug.postmortem.crash", "debug.postmortem.triage",
"debug.introspect.from_vmcore"]`.

`FetchedFile` (domain Model): `name` (e.g. `vmcore`), `ref` (run-relative), `sha256`
(hex), `size_bytes` (int).

### 3.2 `postmortem/dumps.py` — enumeration script + pure host functions

Mirrors `prereqs/kdump_probe.py`'s split.

**`DUMP_LIST_SCRIPT_TEMPLATE`** (stdlib python3, `$dump_dir` substituted via
`string.Template`): walk the immediate subdirs of `dump_dir`; for each holding a
`vmcore` / `vmcore.flat` / `vmcore-incomplete`, emit one record:

| Key | Source |
|---|---|
| `dir` | absolute path of the dump subdir |
| `vmcore_name` | the matched core file name |
| `size` | `st_size` of the core file |
| `mtime` | `st_mtime` (epoch float) of the core file |
| `kernel` | first-line kernel version from a readable `vmcore-dmesg.txt`, else null |
| `incomplete` | true when only `vmcore-incomplete`/`vmcore.flat` is present (no finished `vmcore`) |
| `present` | which of `vmcore-dmesg.txt`/`vmlinux`/`vmcoreinfo` exist in the dir |
| `file_sizes` | `{name: st_size}` for the core file **and** every co-located file in `present` — the per-file expected size used by the §3.4 truncation guard (review finding 3) |

Emits one JSON object `{"dump_dir": str, "exists": bool, "dumps": [record…]}`. A missing
or empty dir → `dumps: []`. Each read is guarded so one unreadable dir never aborts the
walk. The `incomplete`/`vmcore.flat` distinction: `vmcore-incomplete` is makedumpfile's
in-progress/failed marker (renamed to `vmcore` only on success), and `vmcore.flat` is the
flattened format crash cannot read directly; both make a dir not directly fetchable, so
both set `incomplete=true`.

**`parse_dump_listing(probe) -> list[DumpEntry]`** (pure): turn each record into a
`DumpEntry`. `capture_time` is `datetime.fromtimestamp(mtime, UTC).isoformat()` when
mtime is a number, else null. Stable sort by `capture_time` desc then `path`. The unit
of testing for the AC#1 empty-list and metadata-shape behavior.

**`derive_dump_id(remote_dir: str) -> str`** (pure): `<slug(basename)>-<sha256(remote_dir)[:8]>`
where slug maps non-`[A-Za-z0-9._-]` to `_` (decision 5). Deterministic; tested for
stability and collision-resistance.

**`plan_fetch(entry: DumpEntry) -> list[FetchSpec]`** (pure): the ordered list of files
to scp — always the core file; plus `vmcore-dmesg.txt`/`vmlinux`/`vmcoreinfo` when in
`entry.available_files`. Each `FetchSpec` carries the remote path, the local name, the
result-ref key (`vmcore_ref`/`vmlinux_ref`/…), and the **expected size** for that file
(from `entry.file_sizes`), so **every** staged file — not just the vmcore — gets the
§3.4 size-match truncation guard (review finding 3). The unit of testing for which files
map to which refs.

### 3.3 `build_scp_argv` (server.py)

Mirrors `build_ssh_argv` for the `-o` option shape (single source of truth) with scp's
spellings: same `-o BatchMode=yes / UserKnownHostsFile / ConnectTimeout /
StrictHostKeyChecking` plus any extra `ssh_options`, uppercase `-P {port}`, `-i {key}`
when set, then the `user@host:remote_path` source and the local dest path. The same
`ConnectTimeout ≤ command_timeout` guard applies. Driven through `SshRunner.run` like any
bounded subprocess.

**Remote-path quoting (review finding 4).** Unlike `build_ssh_argv` (which `shlex.quote`s
the whole remote command), scp's `host:remote_path` argument is expanded by a **remote**
shell, and default kdump dirs contain `:` (`<host>-YYYY-MM-DD-HH:MM:SS`) — and hostnames
can carry spaces/metacharacters. `build_scp_argv` therefore passes `scp -T` (disable the
remote-side wildcard/strict filename check) **and** `shlex.quote`s the remote path
*after* the `user@host:` prefix, so the remote shell receives the path literally. A test
fetches from a dump dir containing `:` and a space to lock this in.

### 3.4 Fetch staging + idempotency loop

The pre-transfer admission checks (run after `dump_ref` is matched in §3, **before** the
lock):

- **`incomplete` refusal (review finding 2):** if the matched `entry.incomplete` is true,
  refuse with `READINESS_FAILURE / dump_incomplete` unless `force` — an
  in-progress/`vmcore.flat` dir is not a directly-analyzable core, and its size races a
  still-writing file so the size guard below would be unreliable.
- **Size ceiling (review finding 1):** the effective ceiling is `max_bytes` when set,
  else `DEFAULT_FETCH_MAX_BYTES` (a config constant). Refuse with `CONFIGURATION_ERROR /
  dump_too_large` when `sum(entry.file_sizes.values())` exceeds it.
- **Free-space precheck (review finding 1):** refuse with `INFRASTRUCTURE_FAILURE /
  insufficient_disk` when `shutil.disk_usage(dest_parent).free` is below the total fetch
  size plus a headroom margin. The total is known from `entry.file_sizes`, so the host is
  never filled by a transfer it could have predicted would not fit.

Then, under `store.postmortem_fetch_lock(run_id)` (a new per-run file lock):

1. Load manifest; `step = step_results.get(f"postmortem.fetch:{dump_id}")`.
2. If `step` is SUCCEEDED and not `force`: return the recorded refs/files unchanged
   (read from the step's `details`), `already_fetched=true`, **no** re-transfer (AC#4
   "refuse to overwrite").
3. Else: clear the dest dir (`<run>/debug/postmortem/dumps/<dump_id>/`) if present
   (a partial prior attempt), recreate it 0o700.
4. For each `FetchSpec`: build scp argv, `runner.run(..., timeout=timeout_seconds)`;
   on non-zero exit / timeout / cancel → `incomplete_transfer` failure (clean dest,
   no success step). For **every** file, require `local_size == spec.expected_size`
   (decision 4 / review finding 3); a mismatch is `incomplete_transfer`.
5. Compute `sha256` + size of each staged file (`FetchedFile`).
6. Persist a redacted `fetch.json` manifest in the dest dir; record a SUCCEEDED
   `postmortem.fetch:<dump_id>` `StepResult` whose `details` carry the refs + `files`
   (so step 2 can return them) (replace when `force`). Return refs.

The lock + load-under-lock + re-check mirrors the build/boot step pattern (CLAUDE.md).
A `ManifestStateError` on record uses the `_record_terminal_*` retry-with-backoff
pattern.

**Latency budget note (review finding 3).** `timeout_seconds` bounds each scp subprocess
(step 4). The post-transfer local `sha256` (step 5) is a full re-read of each staged file
on local disk and is **not** covered by that timeout; for a multi-GB vmcore it adds a
local-disk-bound pass whose cost the `DEFAULT_FETCH_MAX_BYTES` ceiling caps. This is
local I/O (fast, predictable) rather than network, and the size ceiling bounds it; a
future opt-in could skip the local hash for very large cores (ADR 0029 decision 4).

### 3.5 Failure contract

| Condition | Category | `details.code` |
|---|---|---|
| run dir / manifest missing | CONFIGURATION_ERROR | (message: `run not found`) |
| profile or `target_ref` ≠ manifest | CONFIGURATION_ERROR | `manifest_profile_mismatch` |
| `timeout_seconds` out of band | CONFIGURATION_ERROR | `invalid_timeout` |
| `dump_dir` not absolute | CONFIGURATION_ERROR | `invalid_dump_dir` |
| boot step not SUCCEEDED | READINESS_FAILURE | `target_not_booted` |
| rootfs not ssh / missing ssh fields | CONFIGURATION_ERROR | `unsupported_access_method` / `missing_ssh_field` |
| target HALTED | READINESS_FAILURE | `target_halted` |
| ssh/scp transport failed (exit 255 / raised / timeout / cancel) | INFRASTRUCTURE_FAILURE | `ssh_connect_failure` / `ssh_failure` |
| stdout over cap (enumeration) | INFRASTRUCTURE_FAILURE | `oversized_output` |
| no python3 on target (enumeration, exit 127) | INFRASTRUCTURE_FAILURE | `probe_no_python` |
| enumeration emitted no parseable JSON dict | INFRASTRUCTURE_FAILURE | `probe_unparseable` |
| `dump_ref` not in the fresh listing (fetch) | CONFIGURATION_ERROR | `dump_not_found` |
| matched dump is `incomplete` and not `force` (fetch) | READINESS_FAILURE | `dump_incomplete` |
| total fetch size exceeds the effective ceiling (fetch) | CONFIGURATION_ERROR | `dump_too_large` |
| host free space below total fetch size + headroom (fetch) | INFRASTRUCTURE_FAILURE | `insufficient_disk` |
| scp transferred a short/partial file (fetch) | INFRASTRUCTURE_FAILURE | `incomplete_transfer` |

`list_dumps` returning JSON (including an empty `dumps`) is always a `success`. Only an
infrastructure failure to obtain the listing is a `failure`.

### 3.6 Redaction

Raw enumeration stdout/stderr and scp stdout/stderr stay under
`<run>/sensitive/debug/postmortem/{list_dumps,fetch}/<id>/` (0o600). The returned
`dumps`/`files`/refs and the persisted `probe.json` / `fetch.json` are
`redactor.redact_value`'d; the redactor is seeded with the rootfs `ssh_key_ref`.

## 4. Acceptance-criteria traceability

| AC | Satisfied by |
|---|---|
| `list_dumps` per-dump `path`/`kernel`/`time`/`size`; empty list when none | §3.2 `parse_dump_listing`; pure unit tests (empty, one, many, incomplete-only) + env-gated integration |
| `fetch` stages vmcore (+ symbols) and returns run-relative refs the analyzers accept | §3.4 staging; handler test asserts refs resolve under the run dir and feed `confine_run_relative` |
| each retrieved file reports `sha256` + size; truncation detected, not silently accepted | §3.4 step 4–5 (per-file size match) + ADR 0029 decision 4; handler tests: a short vmcore **and** a short symbol file each → `incomplete_transfer` |
| bounded transfer (issue scope) | §3.4 pre-transfer `dump_too_large` (ceiling) + `insufficient_disk` (free-space precheck) + `dump_incomplete` refusal; handler tests for each |
| re-fetch without `force` refused; with `force` replaces | §3.4 step 2 idempotency; handler test (second call cached `already_fetched=true`; `force` re-transfers) |
| captured metadata redacted; HALTED fast-rejected | §3.6 + §3.0/§3.1 HALTED reject; handler tests (seeded secret absent; injected HALTED session record) |
| live-target test env-gated | integration test guarded on an env var + reachable guest with a captured dump, like `test_kdump_prereqs_integration.py`; never un-gated in CI |

## 5. Testing strategy

- **`tests/test_postmortem_dumps.py`** (pure, no SSH): `parse_dump_listing` over
  synthesized probe dicts (empty, one dump, many dumps sort order, incomplete-only,
  missing kernel, dir not existing); `derive_dump_id` stability + collision-resistance +
  slugging; `plan_fetch` file→ref mapping with/without co-located symbols.
- **Handler tests** (`tests/test_postmortem_list_dumps.py`,
  `tests/test_postmortem_fetch.py`): fake `SshRunner` returning canned enumeration JSON
  and writing staged files; list success (incl. empty); fetch success with refs +
  sha256 + size; truncated vmcore **and** truncated symbol file → `incomplete_transfer`;
  `dump_not_found`; `dump_incomplete` (and `force` override); `dump_too_large`;
  `insufficient_disk`; remote path with `:`/space (scp quoting); idempotent re-fetch
  (cached) and `force` re-transfer; HALTED fast-reject; config errors (run-not-found,
  profile mismatch, bad timeout, bad dump_dir, non-ssh rootfs); python3-absent (exit
  127); unparseable stdout; redaction of a seeded secret. Handlers called directly with
  injected providers/profiles.
- **Capability / config tests**: both ops in `ALLOWED_DEBUG_OPERATIONS` and in
  `local_vmcore_retrieval_capability().operations`; `required_host_tools` includes scp.
- **Env-gated integration** (`tests/test_postmortem_fetch_integration.py`): real SSH/scp
  to a guest with a captured dump, skipped without the guest env var.

## 6. Open questions

None blocking. Target-side analysis, default remote-hash verification, and non-local
dump-target resolution are explicitly deferred and documented, not silently claimed.
