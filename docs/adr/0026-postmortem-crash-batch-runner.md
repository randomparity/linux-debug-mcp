# ADR 0026 — `debug.postmortem.crash`: host-side build-id reader, batch `!echo` framing, raw-passthrough parsers

**Status:** Accepted (2026-05-30) · **Issue:** #92 · **Epic:** #9 · **Affects:** `src/linux_debug_mcp/symbols/vmcore_build_id.py` (new), `src/linux_debug_mcp/postmortem/` (new package: `crash_batch.py`, `crash_parsers.py`), `src/linux_debug_mcp/providers/local_crash_postmortem.py` (new), `src/linux_debug_mcp/server.py` (`_execute_postmortem_crash_call`, `debug_postmortem_crash_handler`, tool registration), `src/linux_debug_mcp/config.py` (`ALLOWED_DEBUG_OPERATIONS` + caps), `src/linux_debug_mcp/prereqs/checks.py` (`crash` check)

## Context

#92 adds the `crash`-utility offline tier alongside #55's drgn offline tier
(`debug.introspect.from_vmcore`). It reuses #55 / ADR 0010 wholesale for scoping
(run-relative refs, no target, no admission gate), manifest persistence, redaction,
and the local-subprocess runner. Four decisions are crash-specific and were left open
by the spec — the issue names exactly these as requiring a new ADR: how the host
obtains the vmcore's embedded build-id (drgn handed it to us *inside* its wrapper;
`crash` does not), how `crash` is driven non-interactively and its output framed per
command, what happens when a command does not parse, and where the parsers and batch
driver live. ADR 0010 (offline execution model, host-authoritative build-id,
never-gated property) and ADR 0011 (write-mode N/A to an immutable core) are inherited
unchanged; this ADR records only the deltas.

## Decision

### 1. The host reads the vmcore's embedded build-id with a pure-Python ELF reader

A new `symbols/vmcore_build_id.py:read_vmcore_build_id(path) -> str` parses the ELF
vmcore's PT_NOTE segments for the kernel build-id: the `VMCOREINFO` note's
`BUILD-ID=<hex>` line (the same source drgn and crash use), falling back to an
`NT_GNU_BUILD_ID` note. It reuses the seek-only PT_NOTE walk from #55's `build_id.py`
(notes live in early segments; the multi-GB file is never slurped). It is **pure
Python** — no drgn, crash, or pyelftools dependency.

This makes both sides of the §4.2 fail-loud check **host-authoritative and computed
before `crash` runs** (matching ADR 0010's "no analysis runs on mismatch"):
`observed = read_vmcore_build_id(vmcore)` vs `expected = read_elf_build_id(vmlinux)`.
A mismatch is `CONFIGURATION_ERROR` / `provenance_mismatch`, no crash invocation.

Three distinct, **fail-closed** failure codes follow (a build-id that cannot be
established never silently passes the gate):

- non-ELF container (compressed-kdump magic / unrecognised) → `VmcoreFormatUnsupported`
  → `vmcore_format_unsupported`;
- ELF but truncated/unreadable → `VmcoreBuildIdError` → `vmcore_build_id_unreadable`;
- ELF, readable, no build-id present → `VmcoreBuildIdAbsent` → `provenance_unverifiable`
  (distinct from a mismatch — the agent cannot fix it by swapping vmlinux; it must
  capture from a `CONFIG_BUILD_ID` kernel), mirroring ADR 0010's "core carries no
  embedded build-id" decision.

The reader is injectable (`vmcore_build_id_reader` seam), so handler tests need no
synthesised vmcore. ELF is the format this repo's QEMU world produces (`virsh dump` /
`dump-guest-memory`); the compressed-kdump container is a documented follow-on (spec
§5.3) that adds one magic-keyed branch — until then it fails loud, never silently
skips the check.

### 2. `crash` is driven in one batch session over stdin, framed by `!echo` sentinels

`crash -s <vmlinux> <vmcore>` is invoked **once per call** with the command batch on
stdin (mirroring the drgn-wrapper-on-stdin pattern), under
`timeout --kill-after=2s <t>s`. `build_command_script(commands, token)` interleaves a
server-minted UUIDv4-hex sentinel before each command via `crash`'s `!echo
<token>-<i>` shell escape, ending with `exit`. `split_transcript(raw, token, commands)`
splits the captured stdout on full-line sentinel matches; the segment after sentinel
`i` is command `i`'s output. A sentinel that never appears (crash aborted mid-batch)
marks that command `parsed:false`, `reason:not_captured` — never silently dropped. The
index in the sentinel makes a gap detectable rather than mis-attributing output.

The token is server-generated, not caller input, so `!echo` carries no injection
surface. `-s` (silent) suppresses the banner/prompt/scroll noise for a clean stream.

### 3. Parsing is best-effort and total; failure is raw passthrough

`parse_command(command, raw_text)` dispatches on the command's leading token(s) to
typed parsers for `bt`, `ps`, `log`, `kmem -i`, `sys`. Any command without a parser,
or whose parser raises, yields `{"parsed": False, "reason": ..., "raw": <text>}` —
parsing never drops a command and never raises out of the dispatcher. Parsers are pure
text functions (no `crash` dependency), unit-tested against captured-output fixtures.
Redaction is **not** the parser's job: the handler redacts every value (typed or raw)
uniformly before returning/persisting, keeping redaction a single responsibility.

### 4. Parsers and batch driver live in a new `postmortem/` package; the build-id reader in `symbols/`

`crash_batch.py` (command-script build + transcript split) and `crash_parsers.py`
(parsers + dispatch) are pure, side-effect-free modules in a new
`src/linux_debug_mcp/postmortem/` package — the home for this and the sibling
postmortem tools (#93–#95). The build-id reader lives in `symbols/` beside
`build_id.py` because ADR 0008 keeps all symbol/provenance logic in that one leaf. The
`server.py` orchestrator (`_execute_postmortem_crash_call`) and the capability factory
(`providers/local_crash_postmortem.py`) follow the established server/provider split.

### 5. Raw transcript under `sensitive/`, redacted transcript under `debug/`

The issue's wording ("raw transcript under `<run>/debug/postmortem/crash/<call-id>/`")
is reconciled with the mandatory-redaction contract (CLAUDE.md; "all persisted
artifacts + response fields through `Redactor()`"): the **unredacted** `crash` stdout/
stderr is written under `<run>/sensitive/debug/postmortem/crash/<call-id>/` (0600,
never returned), and a **redacted** transcript + parsed JSON under
`<run>/debug/postmortem/crash/<call-id>/` is what the response's `ArtifactRef`s point
at — exactly the split #55 uses (`sensitive/stdout.raw` vs `debug/.../stdout.json`).

## Consequences

- The §5.6-rule-3 "never gated" property is structural: the gate code is simply not in
  `_execute_postmortem_crash_call`; a lifecycle-independence test (no boot, no
  admission injected) proves it.
- One pure-Python ELF reader is the host-authoritative observed build-id; the host
  never trusts `crash` to self-report provenance, and the check runs before any
  multi-GB core is mapped by `crash`.
- The crash tier has **no drgn dependency** and its own `crash` prereq check — the two
  offline tiers are installable independently.
- Best-effort raw passthrough means a parser bug degrades one command to raw text, not
  the whole call; new commands work (as raw) the day they are issued, before a parser
  exists.
- A compressed-kdump core fails loud today; adding support is one magic-keyed branch in
  `read_vmcore_build_id` with the rest of the path unchanged.

## Considered & rejected

1. **Delegate vmcore build-id extraction to drgn** (reuse #55's
   `main_module().build_id`). Rejected: couples the crash tool to a drgn install,
   contradicting the issue's framing of crash as a standalone tier with its own
   prereq and "no live dependency." The ELF VMCOREINFO note is trivially parseable on
   the host without a heavyweight runtime.

2. **Let `crash` self-check the vmlinux/vmcore match** (rely on its built-in mismatch
   warning). Rejected: `crash`'s check is OSRELEASE/version-based, not build-id; it
   runs *during* analysis (violating "no analysis runs on mismatch"); and it yields a
   coarse pass/fail, not ADR 0010's distinct `provenance_mismatch` /
   `provenance_unverifiable` / `vmcore_format_unsupported` codes the agent needs to
   choose a remediation.

3. **One `crash` invocation per command** (trivial per-command framing). Rejected: each
   invocation re-opens and re-maps the multi-GB vmcore — the cost the issue's "batch
   runner" framing exists to avoid. The `!echo`-sentinel batch opens the core once.

4. **Frame by parsing `crash`'s `crash> ` prompt.** Rejected: prompt formatting is
   fragile and version-dependent, and a command's own output can contain the literal
   `crash> ` string, mis-splitting the transcript. A full-line server-minted UUID
   sentinel cannot be forged by command output.

5. **Make parsers strict (fail the call on an unparseable command).** Rejected: the
   issue requires "never silently drops a command" and "unknown ⇒ raw text." A strict
   parser would make the tool brittle against `crash` version drift and new commands;
   best-effort + raw passthrough degrades gracefully and is what an agent can still act
   on.

6. **Redact inside each parser.** Rejected: scatters the redaction responsibility
   across N parsers (each an easy place to forget a field). Redacting once in the
   handler, uniformly over typed and raw values, is the single chokepoint the
   CLAUDE.md redaction contract wants.

7. **Fold the crash op into the `local-drgn-introspect` capability.** Rejected: that
   capability is `required_host_tools=["ssh"]` + drgn (the live tier shares it). Crash
   is offline, needs neither ssh nor drgn, and is `concurrent_safe=True`. A separate
   `local-crash-postmortem` capability advertises its true host-tool requirement
   (`crash`) and concurrency property to `providers.list`.

8. **Add a `DebugProfile`/`enabled_operations` gate to the crash path.** Rejected (as
   ADR 0010 item 7): §5.6 rule 3 says vmcore analysis is never gated. The operation is
   listed in `ALLOWED_DEBUG_OPERATIONS` for enumerability, but
   `_ensure_debug_operation_enabled` is not called — no profile in the request, no
   admission tier to narrow.

9. **Write the raw transcript under `debug/` as the issue's text literally says.**
   Rejected: `crash log`/`bt` surface guest memory and strings; the CLAUDE.md contract
   requires every persisted artifact through `Redactor()`. Raw goes to `sensitive/`
   (0600, never returned) and a redacted transcript under `debug/` carries the
   `ArtifactRef` — the same split #55 uses. The issue's intent (preserve the
   transcript, reference it by `ArtifactRef`) is honoured; only the directory of the
   *unredacted* copy changes, to keep secrets out of the returnable tree.

## References

spec `docs/superpowers/specs/2026-05-30-debug-postmortem-crash-design.md`;
interface contract `docs/specs/interface-contracts.md` §4.2, §5.6 rule 3, §3.3;
ADR 0010 (offline execution model, host-authoritative build-id, never-gated),
ADR 0008 (symbols package leaf), ADR 0011 (write-mode N/A to a core);
`src/linux_debug_mcp/symbols/build_id.py` (`read_elf_build_id`),
`src/linux_debug_mcp/server.py` (`_execute_vmcore_introspect_call`).
