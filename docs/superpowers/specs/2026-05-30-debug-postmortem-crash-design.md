# `debug.postmortem.crash` — host-side crash batch runner + parsers

**Date:** 2026-05-30
**Issue:** #92
**Epic:** #9 (Remote interactive kernel debugging for coding agents)
**Supersedes (in part):** #14
**Status:** Draft — pending adversarial review
**Depends on:** #55 (host-authoritative `build_id` via `symbols/build_id.py:read_elf_build_id`; run-relative confinement via `confine_run_relative`; the shared local-subprocess runner + manifest/redaction step pattern in `_execute_vmcore_introspect_call`)
**Design decisions:** [ADR 0026](../../adr/0026-postmortem-crash-batch-runner.md) (pure-Python ELF vmcore build-id reader, batch-via-stdin with `!echo` sentinel framing, parser-failure = raw passthrough, parser/runner ownership)

## 1. Background and scope

#55 shipped the **drgn** offline tier (`debug.introspect.from_vmcore`): a user
drgn script run against a captured vmcore on the agent host, with no live target
and no admission gate. This spec adds the **`crash`-utility** analogue:
`debug.postmortem.crash`, which runs a *fixed batch of `crash` commands* against a
captured vmcore + matching vmlinux on the agent host and returns parsed JSON keyed
by command plus a preserved transcript. Per `interface-contracts.md` §5.6 rule 3,
vmcore analysis has no live dependency and is **always concurrent-safe** — never
gated.

The two offline tiers are siblings, not substitutes: drgn runs arbitrary
Python/drgn against the core; `crash` runs the curated `crash` command vocabulary
(`bt`, `ps`, `log`, `kmem`, `sys`, …) whose output this tool parses into typed
JSON. An agent picks whichever matches its question.

The scoping, manifest persistence, redaction discipline, run-relative confinement,
and build-id fail-loud contract are inherited from #55 / ADR 0010. The crash path
differs in four ways, each settled by [ADR 0026](../../adr/0026-postmortem-crash-batch-runner.md):
how the host reads the vmcore's embedded build-id (drgn handed it to us inside its
wrapper; `crash` does not, so the host must read it *before* analysis), how `crash`
is driven non-interactively and its output framed per command, what happens when a
command does not parse, and where the parsers and batch driver live.

### In scope

- `debug.postmortem.crash(run_id, vmcore_ref, vmlinux_ref, modules_ref?, commands[], timeout_seconds) → ToolResponse` MCP tool, wired via `server.py`'s tool-registration pattern.
- Run-scoped, run-relative refs confined to `<run_dir>` via #53's `confine_run_relative` / `resolve_symbols`. **No** `target_ref`, no `*_profile`, no admission gate, no SSH — identical scoping to #55.
- Driving `crash` non-interactively (batch commands fed on stdin), with each command's output framed by a server-minted sentinel so the parser can split the transcript reliably (ADR 0026 §2).
- Best-effort parsers → typed JSON for `bt`, `ps`, `log`, `kmem -i`, `sys`. An unknown or unparseable command returns its **raw text** under the command key — parsing never silently drops a command.
- Host-side `build_id` fail-loud: the vmcore's embedded build-id (`symbols/vmcore_build_id.py:read_vmcore_build_id`) vs the host-parsed `read_elf_build_id(vmlinux)` (#55's reader). Mismatch → `CONFIGURATION_ERROR` / `provenance_mismatch`, **no crash run**. Distinct codes for an unreadable vmlinux, a vmcore with no build-id, and an unsupported vmcore container — matching ADR 0010.
- Bounded execution: handler-bounded `commands` count and `timeout_seconds`; raw-transcript and parsed-JSON output caps; the `crash` child killed on timeout (`timeout --kill-after`), no strand.
- Raw transcript preserved on disk; only redacted snippets in the response (`ArtifactRef` to a redacted transcript). All persisted artifacts + response fields pass through `Redactor()`.
- `debug.postmortem.crash` added to `ALLOWED_DEBUG_OPERATIONS` for enumerability; **not** gated (§5.6 rule 3 / ADR 0010 item 7 — no profile in the request, no admission tier to narrow).
- A `crash` tool prerequisite check in `prereqs/checks.py`.
- A new `local-crash-postmortem` provider capability advertising the operation (`concurrent_safe=True`, `required_host_tools=["crash"]`).
- Docs: `docs/debug-postmortem.md` (usage, parsed fields, the `build_id` contract).

### Out of scope

| Concern | Where it lives |
|---|---|
| drgn vmcore analysis | #55 (shipped; `debug.introspect.from_vmcore`) — #14's "wire drgn vmcore to introspect" is satisfied there |
| `triage` composite | sibling issue (#93) |
| vmcore / symbol retrieval from a target | sibling issue (#94) |
| kdump readiness checks | sibling issue (#95) |
| makedumpfile filter-level tuning | not planned |
| **Compressed-kdump (`makedumpfile -c`) container** build-id extraction | deferred (§5.3); a non-ELF container fails loud with `vmcore_format_unsupported`, never a silent skip |

## 2. Architecture overview

```
agent ──MCP──▶ debug.postmortem.crash handler
                     │  (no admission, no SSH, no sudo, no target lifecycle)
                     ▼
       load manifest ─┬─ commands/timeout invariants
                      ├─ per-run call-budget (MAX_POSTMORTEM_CRASH_CALLS_PER_RUN)
                      ├─ sensitive/ mode 0700 preflight
                      ▼
       resolve_symbols(KernelProvenance(vmlinux_ref, modules_ref), run_dir)
                      │   → confined vmlinux_path, modules_path
                      ▼
       confine vmcore_ref to run_dir (confine_run_relative)   ← #53 leaf
                      │
                      ▼
       build_id fail-loud (HOST, before crash runs):
         observed = read_vmcore_build_id(vmcore)   ← new pure-Python ELF reader
         expected = read_elf_build_id(vmlinux)     ← #55 reader
         observed != expected  → provenance_mismatch (no crash run)
                      │
                      ▼
       render command script (build_command_script: !echo sentinels per command)
                      ▼
       runner.run(["timeout","--kill-after=2s","<t>s","crash","-s",vmlinux,vmcore],
                      │          stdin=cmd_script, stdout→sensitive/stdout.raw, cap)
                      ▼
       split_transcript → per-command segments → parse_command (typed | raw)
                      ▼
       Redactor → debug/postmortem/crash/<call-id>/{transcript.txt, parsed.json}
                → postmortem.crash:<call_id> manifest step → ToolResponse
```

New components:

1. **One tool handler** (`debug_postmortem_crash_handler`) plus a private
   `_execute_postmortem_crash_call` orchestrator in `server.py`.
2. **`symbols/vmcore_build_id.py`** — `read_vmcore_build_id(path)`, the host-side
   reader for the vmcore's embedded build-id (ELF container).
3. **`postmortem/` package** — `crash_batch.py` (pure command-script build +
   transcript split) and `crash_parsers.py` (per-command parsers + dispatch).
4. **`providers/local_crash_postmortem.py`** — the capability factory.

Reused without change: `resolve_symbols` / `confine_run_relative` (#53),
`read_elf_build_id` (#55), `SubprocessSshRunner`, `Redactor`, `ArtifactStore`,
`_record_terminal_*` flock-retry persistence pattern, `_redact_and_truncate`,
`RUN_STDOUT_CAP`.

## 3. Tool surface

### 3.1 Request

```python
class DebugPostmortemCrashRequest(Model):       # extra="forbid"
    run_id: str
    vmcore_ref: str          # run-relative path to the captured vmcore file
    vmlinux_ref: str         # run-relative path to the uncompressed ELF vmlinux+symbols
    modules_ref: str | None = None   # optional run-relative directory of *.ko[.debug]
    commands: list[str]      # crash command lines; handler-bounded (§6 step 2)
    timeout_seconds: int = 60        # handler-bounded to [5, 300]
```

There is **no** `target_ref`/`*_profile`/`debug_profile` field: the crash path does
not name, boot, reach, or gate a live target. The manifest is consulted only for the
run-directory layout, the call budget, and the `sensitive/` mode preflight — never
for a target profile, boot snapshot, or recorded `KernelProvenance`. A vmcore may be
analysed against a run whose boot failed, or whose target was reclaimed.

**Refs are run-relative.** `vmcore_ref`, `vmlinux_ref`, `modules_ref` are confined to
`<run_dir>` via `confine_run_relative` / `resolve_symbols`. An out-of-sandbox ref is a
`CONFIGURATION_ERROR`. A vmcore captured elsewhere (kdump, #95) must be staged into
the run directory first.

### 3.2 Operation gating

No `DebugProfile` in the call path (no `debug_profile` field). The operation is added
to `ALLOWED_DEBUG_OPERATIONS` (the static allowlist) for enumerability, but
`_ensure_debug_operation_enabled` (which takes a resolved `DebugProfile`) is **not**
invoked — there is no profile to resolve and no admission tier to narrow. This is the
§5.6-rule-3 "never gated" property made concrete: a crash call cannot be blocked by
target state or by a profile's `enabled_operations`.

### 3.3 Response

Success `data` carries:

- `call_id` — the per-call UUIDv4-hex id.
- `vmcore_build_id` — the vmcore's embedded build-id (the verified value).
- `results` — an object keyed by the **exact command string** the caller supplied;
  each value is either a typed parsed object (`bt`/`ps`/`log`/`kmem -i`/`sys`) or a
  raw string (unknown/unparseable command, or a command whose output was truncated
  or not captured). Each value also carries `parsed: bool` and, when not parsed, a
  `reason` (`unknown_command` / `parse_failed` / `output_truncated` / `not_captured`).
- `truncated` — `true` when the raw transcript hit the output cap.
- `artifacts` — `ArtifactRef`s to the **redacted** transcript and parsed JSON under
  `<run>/debug/postmortem/crash/<call-id>/`.
- timing (`started_at`, `finished_at`, `duration_ms`), `crash_exit_code`.

`suggested_next_actions` is `["artifacts.get_manifest", "debug.postmortem.crash"]`.

Duplicate command strings: if the caller supplies the same command twice, the keyed
`results` object would collide. The handler rejects a `commands` list with duplicate
entries (`invalid_commands` / `duplicate_command`) so the keyed response is
unambiguous; an agent that wants the same command twice issues two calls.

## 4. Driving `crash` non-interactively (ADR 0026 §2)

`crash` is invoked once per call with the vmlinux + vmcore as positional arguments
and the command batch on **stdin** (mirroring how the drgn wrapper is fed on stdin),
under `timeout(1)` for kill-after defence-in-depth:

```
timeout --kill-after=2s <t>s crash -s <vmlinux_path> <vmcore_path>
```

`-s` (silent) suppresses the version banner, the `crash> ` prompt, and runtime
scrolling messages, leaving a clean stream to parse. The stdin script is built by
`build_command_script(commands, sentinel_token)`:

```
!echo <token>-0
<command 0>
!echo <token>-1
<command 1>
...
!echo <token>-N
exit
```

`<token>` is a server-minted UUIDv4 hex (not caller input — no injection surface).
`!echo` is `crash`'s shell escape; it prints the sentinel line to the same stdout
stream, immediately *before* each command's output. The trailing `exit` ends the
session deterministically.

`split_transcript(raw, token, commands)` splits the captured stdout on the sentinel
lines. The segment after sentinel `i` (up to sentinel `i+1` or EOF) is command `i`'s
output. **Missing-sentinel handling:** if `crash` aborts mid-batch (e.g. a command
faults the session), the trailing sentinels never appear; every command whose
sentinel is absent is recorded with `parsed: false`, `reason: not_captured` — never
silently dropped (AC: unknown/unparseable command never dropped, generalised to
not-captured). The sentinel carries the command index so a gap is detectable rather
than mis-attributing one command's output to another.

**Why not one `crash` per command:** re-opening a multi-GB vmcore N times is the cost
the issue's "batch runner" framing rejects (ADR 0026 §2, rejected alternative). **Why
not prompt-parsing:** `crash> ` prompt formatting is fragile and a command's own
output can contain the prompt string (ADR 0026 §2, rejected alternative).

## 5. Host-side build-id fail-loud

### 5.1 The two readers

Both ids are read on the **host, before `crash` runs** (the §4.2 / ADR 0010 fail-loud
guarantee — "no analysis runs" on mismatch):

- `expected = read_elf_build_id(vmlinux_path)` — #55's pure-Python ELF reader,
  unchanged. A non-ELF / compressed / stripped / truncated vmlinux raises
  `BuildIdReadError` → `CONFIGURATION_ERROR` / `vmlinux_build_id_unreadable` (caller
  supplied the wrong file).
- `observed = read_vmcore_build_id(vmcore_path)` — new reader (§5.2).

`observed != expected` → `CONFIGURATION_ERROR` / `provenance_mismatch`, no crash run
(matches #55 / §4.2 / AC: "build_id mismatch fails loud; no crash run"). The host is
authoritative for both sides; `crash` is never trusted to self-report provenance.

### 5.2 `symbols/vmcore_build_id.py:read_vmcore_build_id`

```python
def read_vmcore_build_id(path: Path) -> str:
    """Return the lower-case hex kernel build-id embedded in an ELF vmcore.

    Parses the ELF header → program headers → PT_NOTE segments and reads the
    kernel build-id from the VMCOREINFO note's ``BUILD-ID=<hex>`` line (the
    source drgn and crash use), falling back to an ``NT_GNU_BUILD_ID`` note if
    one is present. Pure-Python struct parse — no drgn/crash/pyelftools
    dependency. Reuses the seek-only PT_NOTE walk from ``build_id.py`` (notes
    live in early segments; the file is never slurped).
    """
```

Lives in `symbols/` beside `build_id.py` (ADR 0008 keeps symbol/provenance logic in
one leaf). It is the **host-authoritative** observed build-id.

Failure modes (distinct, fail-closed — never a silent skip):

- **Non-ELF container** (e.g. the compressed-kdump `makedumpfile` magic, or any
  unrecognised format) → `VmcoreFormatUnsupported` → `CONFIGURATION_ERROR` /
  `vmcore_format_unsupported`. ELF is the format this repo's QEMU world produces
  (`virsh dump` / `dump-guest-memory`); compressed-kdump support is a documented
  follow-on (§5.3). The agent can re-capture as ELF.
- **ELF but truncated / unreadable** → `VmcoreBuildIdError` → `CONFIGURATION_ERROR` /
  `vmcore_build_id_unreadable`.
- **ELF, readable, but no build-id present** (no `BUILD-ID=` in VMCOREINFO and no
  `NT_GNU_BUILD_ID`) → `VmcoreBuildIdAbsent` → `CONFIGURATION_ERROR` /
  `provenance_unverifiable` (distinct from a *mismatch*: the agent cannot fix it by
  hunting for a different vmlinux; it must capture from a `CONFIG_BUILD_ID` kernel).
  This mirrors ADR 0010's "core carries no embedded build-id" decision.

The reader is injectable as a `vmcore_build_id_reader: Callable[[Path], str]` seam
(default `read_vmcore_build_id`), alongside `vmlinux_build_id_reader`
(default `read_elf_build_id`), so handler tests inject fakes without synthesising
vmcore/vmlinux ELF bytes, while `read_vmcore_build_id` gets focused unit tests against
crafted ELF/VMCOREINFO blobs.

### 5.3 Deferred: compressed-kdump container

The `makedumpfile -c` compressed-kdump format (magic `KDUMP   `) is **not** parsed in
this PR. Its header embeds VMCOREINFO at an offset, parseable in principle, but the
struct layout is larger than the ELF case and this repo produces ELF cores. A
compressed container fails loud with `vmcore_format_unsupported` (never a silent skip
of the build-id check). Adding compressed support is a clean follow-on: a new branch
in `read_vmcore_build_id` keyed on the magic, with the rest of the path unchanged.

## 6. Execution pipeline (`_execute_postmortem_crash_call`)

A linear orchestrator mirroring `_execute_vmcore_introspect_call`. Steps:

1. Resolve `ArtifactStore`; load manifest (missing run → `CONFIGURATION_ERROR`,
   `run_not_found`).
2. Request invariants: `commands` non-empty, `len(commands) ≤ MAX_CRASH_COMMANDS`,
   each command non-empty after strip, no duplicates, combined script `≤
   CRASH_SCRIPT_BYTE_CAP` (`invalid_commands` with a `reason`); `timeout_seconds` in
   `[5, 300]` (`invalid_timeout`).
3. Per-run call-budget: count `postmortem.crash:` steps; `≥
   MAX_POSTMORTEM_CRASH_CALLS_PER_RUN` → `CONFIGURATION_ERROR`
   (`manifest_call_budget_exhausted`). Soft cap (non-atomic read-then-write), matching
   the introspect budget's stance.
4. `sensitive/` mode-0700 preflight (`sensitive_dir_missing` /
   `sensitive_dir_too_permissive`) — identical to #55.
5. Resolve symbols: `KernelProvenance(build_id="", release="", vmlinux_ref=...,
   modules_ref=..., cmdline="", config_ref=None)` shell → `resolve_symbols` confines
   `vmlinux_path` / `modules_path` to `run_dir`. `SymbolResolutionError` →
   `CONFIGURATION_ERROR` (`symbol_resolution_failed`, carrying the resolver `code`).
   Separately `confine_run_relative(vmcore_ref)`; missing/escaping vmcore →
   `CONFIGURATION_ERROR` (`vmcore_not_found`).
6. Build-id fail-loud (§5): `read_vmcore_build_id(vmcore)` vs
   `read_elf_build_id(vmlinux)`. The distinct failure codes of §5.2 are emitted here;
   on mismatch, **return before any crash invocation**.
7. Mint `call_id`; create `<run>/debug/postmortem/crash/<call-id>/` (0700) and
   `<run>/sensitive/debug/postmortem/crash/<call-id>/` (0700); build the command
   script (`build_command_script`); write the redacted `request.json` (with the
   resolved paths recorded as their run-relative refs).
8. Run locally: `runner.run(["timeout","--kill-after=2s", f"{t}s","crash","-s",
   vmlinux_path, vmcore_path], timeout=t+10, stdin=cmd_script,
   stdout_path=sensitive/stdout.raw, stderr_path=sensitive/stderr.raw,
   cancel=<unused event>, max_stdout_bytes=CRASH_STDOUT_CAP)`. No sudo, no SSH argv,
   no admission watcher — `cancel` is an event that never fires (the runner timeout +
   `timeout(1)` bound the call). `modules_ref`, when given, is loaded via the crash
   command stream (`mod -S <modules_path>` prepended to the batch) **best-effort**: a
   failed module load is a non-fatal note in `results`, never a hard failure, matching
   `resolve_symbols`'s non-fatal modules stance. chmod 0600 the raw files.
9. Triage the runner result (mirrors `_finalize_introspect_call`'s
   `oversized_output` / `cancelled` / `stdin_failed` / `timed_out` / `exit==124`
   branches). On a clean run, `split_transcript` + `parse_command` per segment,
   redact, persist, write the `postmortem.crash:<call_id>` step, return.

`Redactor` is seeded with no secret values (no `ssh_key_ref`); the refs are
run-relative and carry no secrets, but **all** returned/persisted text still passes
through `Redactor` (the generic pattern set) to satisfy the redaction acceptance
criterion — `crash log` (dmesg) and `bt` can surface guest strings.

### 6.1 Idempotency / step model

Like the introspect path (and unlike `build`/`boot`), each call mints a fresh
`call_id` and writes a distinct `postmortem.crash:<call_id>` step; calls are **not**
idempotent by a fixed step name. The per-run `MAX_POSTMORTEM_CRASH_CALLS_PER_RUN`
budget bounds the manifest growth. No `force_*` flag exists or is needed.

## 7. Parsers (`postmortem/crash_parsers.py`)

`parse_command(command: str, raw_text: str) -> ParsedCommand` dispatches on the
leading token(s) of the command (normalised: `kmem -i` matched as `kmem` + `-i`
flag). Best-effort and total: any parser that raises, or any command without a
parser, yields `{"parsed": False, "reason": ..., "raw": <text>}`. Typed parsers:

| Command | Parsed shape (typed dict) |
|---|---|
| `bt` | `frames: [{level, pc_addr?, symbol?, offset?, module?, raw}]`, plus `pid`/`command`/`task_addr` from the header line when present |
| `ps` | `processes: [{pid, ppid, cpu?, task_addr?, st, mem_pct?, vsz?, rss?, comm}]` |
| `log` | `lines: [{ts?, level?, text}]` (dmesg ring buffer; timestamp + facility best-effort) |
| `kmem -i` | `memory: {<field>: {pages?, total?, percent?}}` keyed by the report's row labels (`TOTAL MEM`, `FREE`, `USED`, `CACHED`, `SLAB`, …) |
| `sys` | `system: {<key>: <value>}` from the `KEY: value` block (`KERNEL`, `DUMPFILE`, `CPUS`, `DATE`, `UPTIME`, `RELEASE`, `MACHINE`, `MEMORY`, `PANIC`, …) |

Parsers operate purely on text (no crash dependency) and are unit-tested against
captured-output fixtures. They never raise out of `parse_command`; a parse exception
is caught and converted to the raw-passthrough form. Each parsed value is redacted by
the handler before it is returned/persisted (the parser does not redact — redaction
is the handler's single responsibility, applied uniformly to typed and raw values).

## 8. Failure taxonomy

| Condition | `ErrorCategory` | `code` |
|---|---|---|
| run not found | `CONFIGURATION_ERROR` | `run_not_found` |
| empty/oversized/duplicate/blank command list; bad timeout | `CONFIGURATION_ERROR` | `invalid_commands` (+ `reason`) / `invalid_timeout` |
| budget exhausted | `CONFIGURATION_ERROR` | `manifest_call_budget_exhausted` |
| `sensitive/` missing/too-permissive | `CONFIGURATION_ERROR` | `sensitive_dir_missing` / `sensitive_dir_too_permissive` |
| vmcore ref missing/escaping | `CONFIGURATION_ERROR` | `vmcore_not_found` |
| vmlinux/modules ref unsafe/missing | `CONFIGURATION_ERROR` | `symbol_resolution_failed` (+ resolver `code`) |
| vmlinux ELF build-id unreadable (non-ELF/compressed/stripped/truncated) | `CONFIGURATION_ERROR` | `vmlinux_build_id_unreadable` |
| vmcore container not ELF (e.g. compressed-kdump) | `CONFIGURATION_ERROR` | `vmcore_format_unsupported` |
| vmcore ELF truncated/unreadable | `CONFIGURATION_ERROR` | `vmcore_build_id_unreadable` |
| vmcore carries no embedded build-id (cannot verify) | `CONFIGURATION_ERROR` | `provenance_unverifiable` |
| **vmcore build_id ≠ vmlinux build_id** | `CONFIGURATION_ERROR` | `provenance_mismatch` |
| crash cannot open the core / load the vmlinux (nonzero exit, no usable transcript) | `INFRASTRUCTURE_FAILURE` | `crash_open_failure` |
| timeout / oversized transcript | `INFRASTRUCTURE_FAILURE` | `crash_timeout` / `oversized_output` |
| crash ran; a command did not parse / was not captured | success; that key is `parsed:false` + `reason` | — |
| module bundle present but `mod -S` failed | success + non-fatal note in `results` | `modules_load_failed` |

A nonzero `crash` exit with a usable transcript (some commands ran before a later one
faulted) is **success** with per-command `not_captured` markers for the unrun tail —
not a blanket `crash_open_failure`. `crash_open_failure` is reserved for the case
where `crash` produced no parseable transcript at all (it could not open the pair).

## 9. Concurrency (§5.6 rule 3)

No admission handle, no `StopCapableGuard`, no console lease, no snapshot read. Two
`debug.postmortem.crash` calls against the same run proceed in parallel; a call
proceeds whether the run's target is `READY`, `HALTED`, `CRASHED`, reclaimed, or never
booted (AC: lifecycle-independent — proven by a handler test with no admission service
injected). The only shared mutable state is the manifest, written through the existing
flock-retry helper (each call appends a unique `postmortem.crash:<call_id>` step).

**Resource posture (intentionally unbounded, stated explicitly).** As with the drgn
vmcore path (ADR 0010 item 10), "concurrent-safe" means *free of state corruption*,
not resource-bounded. Each in-flight call maps the multi-GB vmcore in the `crash`
child; K parallel calls cost ≈ K× that. `MAX_POSTMORTEM_CRASH_CALLS_PER_RUN` bounds
the per-run lifetime total, not in-flight parallelism. This server is local,
single-agent: the sole caller controls its own fan-out, so no host-wide semaphore is
added (no speculative multi-tenant feature). Documented so the agent can self-limit.

## 10. Allowlist, capability & prereq changes

- `config.py`: add `"debug.postmortem.crash"` to `ALLOWED_DEBUG_OPERATIONS`; add
  `MAX_POSTMORTEM_CRASH_CALLS_PER_RUN`, `MAX_CRASH_COMMANDS`, `CRASH_SCRIPT_BYTE_CAP`,
  `CRASH_STDOUT_CAP`.
- `providers/local_crash_postmortem.py`: `local_crash_postmortem_capability()` →
  `ProviderCapability(provider_name="local-crash-postmortem", provider_family="debug",
  operations=["debug.postmortem.crash"], required_host_tools=["crash"],
  transports=["filesystem"], access_methods=["subprocess","filesystem"],
  semantics=OperationSemantics(concurrent_safe=True, idempotent=False, retryable=True,
  destructive=False, cancelable=True))`. Registered in `local_provider_plugin_specs`.
  A separate capability (not folded into `local-drgn-introspect`) because that one is
  `required_host_tools=["ssh"]` + drgn; crash is offline and needs neither.
- `prereqs/checks.py`: `_crash_check(runner)` — `which("crash")` PASSED with the
  path, else FAILED with an install hint. Added to `check_prerequisites`'s tool loop
  (a presence check, like `make`/`gdb`; no behavioural probe — `crash` cannot run
  without a core).

## 11. Testing strategy

Handler tests instantiate the handler directly with injected fakes (`runner=`,
`vmlinux_build_id_reader=`, `vmcore_build_id_reader=`), per repo convention. No real
`crash`/vmcore in unit tests.

- `read_vmcore_build_id`: ELF little/big-endian with `BUILD-ID=` in VMCOREINFO; ELF
  with `NT_GNU_BUILD_ID` fallback and no VMCOREINFO; ELF with neither →
  `VmcoreBuildIdAbsent`; truncated ELF → `VmcoreBuildIdError`; non-ELF
  (compressed-kdump magic / random bytes) → `VmcoreFormatUnsupported`.
- `crash_batch`: `build_command_script` interleaves sentinels and a trailing `exit`;
  `split_transcript` maps clean output to the right command; a transcript missing the
  last two sentinels marks those commands `not_captured`; a command whose output
  *contains* a sentinel-shaped substring is still split correctly (sentinel is a
  full-line UUID match, not a substring).
- `crash_parsers`: each typed parser against a captured-output fixture (happy path) and
  against a malformed/empty fixture (falls back to raw passthrough, never raises);
  `parse_command` dispatch (`kmem -i` vs bare `kmem`); unknown command → raw.
- Handler happy path: a fake runner returns a framed multi-command transcript →
  `ToolResponse.success`, `results` keyed by command with the right typed/raw split,
  `postmortem.crash:<call_id>` SUCCEEDED, redacted `transcript.txt`/`parsed.json` under
  `debug/`, raw under `sensitive/` (AC: one JSON object keyed by command + ArtifactRef).
- Build-id fail-loud: injected readers returning different ids → `provenance_mismatch`,
  **runner never called** (assert the fake runner saw no invocation); a separate
  `provenance_unverifiable` (vmcore reader raises `VmcoreBuildIdAbsent`),
  `vmcore_format_unsupported`, and `vmlinux_build_id_unreadable` (AC: mismatch fails
  loud, no crash run).
- Unknown/unparseable command not dropped: a command with no parser and a command
  whose parser raises both appear in `results` as `parsed:false` (AC).
- Timeout/oversized: fake runner reports `exit 124` → `crash_timeout`; oversized output
  → `oversized_output` + `truncated:true` indicator (AC: timeout cuts cleanly, oversize
  truncated with an explicit indicator).
- Lifecycle independence: handler succeeds with **no** boot step / no snapshot / no
  admission service injected (AC).
- Redaction: a secret-shaped token in a command's output is masked in the response and
  in the persisted `transcript.txt`/`parsed.json` (AC: all persisted + response through
  Redactor).
- Edges: missing run; missing/escaping vmcore; unsafe vmlinux ref; empty/duplicate/
  oversized command list; bad timeout; budget exhausted; sensitive-dir too permissive.

**AC: the real-crash test is env-gated.** `test_postmortem_crash_integration.py` runs
the real `crash` binary against a fixture vmcore+vmlinux, skipped unless `crash` is on
PATH and `LDM_VMCORE` points at a captured core + matching vmlinux — exactly the
gating the libvirt/gdb/drgn integration suites use. It is the only test that exercises
the real batch framing and parsers end-to-end.

## 12. Acceptance-criteria mapping

| Issue AC | Where satisfied |
|---|---|
| batch of crash commands ⇒ one JSON keyed by command, `bt`/`ps`/`log`/`kmem -i`/`sys` typed, transcript by `ArtifactRef` | §3.3, §7; handler happy-path + parser tests (§11) |
| unknown/unparseable command returns raw text, never dropped | §4 (not-captured), §7 (raw passthrough); §11 not-dropped test |
| build_id mismatch fails loud (`CONFIGURATION_ERROR`), no crash run | §5; §11 fail-loud test (runner never called) |
| timeout cuts the crash child cleanly; oversize truncated with an explicit indicator | §6 step 8 (`timeout --kill-after`), §8; §11 timeout/oversized test |
| unaffected by target lifecycle (no admission gate in path) | §3.2, §6, §9; §11 lifecycle-independence test |
| all persisted artifacts + response fields through `Redactor()` | §6, §7; §11 redaction test |
| real-crash test env-gated | §11 integration test |
