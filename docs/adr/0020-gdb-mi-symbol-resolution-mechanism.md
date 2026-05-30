# ADR 0020 — gdb/MI Phase B symbol resolution: address-of a validated symbol name via `-data-evaluate-expression`, with provenance version-lock reused from ADR 0017

**Status:** Accepted (2026-05-29) · **Issue:** #80 (Phase B of #13; epic #9; consumes ADR [0017](0017-symbol-version-lock-gdb-tier.md) symbol version-lock and is constrained by ADR [0019](0019-debug-gdb-mi-tier-decomposition.md) decision 4) · **Affects:** `providers/gdb_mi.py` (new `GdbMiEngine.resolve_symbol` + `ResolvedSymbol` model); the Phase-A attach probe `_run_mi_attach_probe` in `server.py` (resolve one canonical symbol after `^connected`, before detach, and surface it under `mi_probe.symbol`). No new agent-facing `debug.*` operation, no change to `ALLOWED_DEBUG_OPERATIONS`, no change to the transport/guard/version-lock seams.

## Context

Issue #80 is Phase B of the gdb/MI tier (#13): load `vmlinux` symbols into the
MI engine and version-lock them to the booted kernel before attach. Two of its
three acceptance criteria are already satisfied by merged work and are **not**
re-implemented here:

- **Provenance mismatch / missing** (AC1, AC3) are enforced by ADR 0017 / #70's
  `_verify_gdb_symbol_version_lock`, called in `debug_start_session_handler`
  *before* any acquisition or attach (before `session_guard.enter`,
  `transaction.open`, and the MI probe). It returns `CONFIGURATION_ERROR` with
  `provenance_mismatch` / `provenance_missing` / `vmlinux_build_id_unreadable`
  (and `provenance_corrupt` for a malformed recorded id). That gate is generic
  to the handler, so it already covers the MI path — what is missing is *test
  evidence* that a mismatch blocks the MI engine specifically (the engine's
  `attach()` is never reached), not new gate code.

- **Symbol load** is already performed by Phase A's `attach()`, which runs
  `-file-exec-and-symbols <vmlinux>` before `-target-select remote`. Symbols are
  loaded into the MI session; what Phase A never does is *prove they resolve*.

The genuine Phase B delta is **AC2: "a matching `vmlinux` attaches and resolves a
symbol by name."** The Phase-A probe (`probe_read`) only returns the `^connected`
record. Phase B must resolve a symbol by name through the MI interface and surface
the typed result.

The open question is **which MI mechanism resolves a name to an address**, given:
(a) the tier pins a minimum gdb of **9.1** (`MIN_GDB_VERSION`, ADR 0019 / #79);
(b) ADR 0019 decision 4 scopes `-data-evaluate-expression` to Phase C **as the
internal implementation of the named inspectors** and rejects exposing arbitrary
expression evaluation as an agent-facing operation; (c) the constrained-debug
surface (CLAUDE.md, `ALLOWED_DEBUG_OPERATIONS`) must stay intact — Phase B adds no
agent-facing operation.

## Decision

1. **Resolve a name to an address with `-data-evaluate-expression "&<name>"`.**
   `GdbMiEngine.resolve_symbol(attachment, symbol_name) -> ResolvedSymbol` issues
   that one MI command and reads the `value` field from the parsed `^done` record
   verbatim (no substring/address extraction). `ResolvedSymbol` is a frozen wire
   model carrying the requested `name` and the observed `value` string
   (e.g. `"0x... <linux_banner>"`).
   A `^error` (symbol absent / not yet loaded) raises `GdbMiError` with
   `DEBUG_ATTACH_FAILURE` — symbols were supposed to be loaded, so an unresolvable
   canonical symbol is an attach-level failure, not a soft miss. The observed
   `value` is the **link-time** address from the loaded ELF symbol table
   (`&<name>` reads the symbol table, not target memory), so it proves
   symbol-table presence and resolvability — **not** the relocated running
   address, which on a KASLR kernel differs. Runtime/module relocation addressing
   is a Phase D concern; Phase B's `ResolvedSymbol` is proof-of-resolution only and
   the value is stored as the raw gdb string (no fragile address re-parse).

2. **Validate the symbol name to a bare C identifier before interpolation.**
   `symbol_name` must match `^[A-Za-z_][A-Za-z0-9_]*$`; anything else raises
   `CONFIGURATION_ERROR` without touching gdb. This keeps the command an
   *address-of a name*, never an arbitrary expression: the `&` operator plus an
   identifier cannot smuggle a second expression, a call, or shell/MI control
   characters. The check is the boundary that makes decision 1 consistent with
   ADR 0019's "no raw-expression escape hatch."

3. **The probe resolves one fixed canonical symbol: `linux_banner`.** After the
   `^connected` proof and before resume/detach, `_run_mi_attach_probe` calls
   `resolve_symbol(attachment, "linux_banner")` and merges the typed result under
   `mi_probe.symbol` (redacted like every other probe field). `linux_banner` is
   present in every Linux kernel image (it is the `/proc/version` string) and is
   already the anchor of the live banner cross-check (`live_banner_match`,
   ADR 0017 context), so it needs no kernel-config gating. The probe does **not**
   accept a caller-supplied symbol; the name is a fixed constant, so no agent-facing
   surface is added.

4. **A resolution fault is subject to the same guaranteed-resume invariant.**
   Because `resolve_symbol` runs inside the existing `_run_mi_attach_probe`
   try-block, a `GdbMiError` (or any exception) from it triggers the unchanged
   best-effort `force_resume` + transport teardown: the target is never left
   `HALTED`, the guard is released, and the failure is reported. No new teardown
   path is introduced.

## Consequences

- The MI probe now proves not just *attach* but *usable symbols*: the response
  `mi_probe.symbol` carries a typed name→address resolution as evidence for AC2,
  alongside the Phase-A `mi_probe.record`.
- `-data-evaluate-expression` enters the engine in Phase B rather than Phase C.
  Its use here is strictly internal and single-purpose (address-of a fixed,
  validated canonical symbol); the agent-facing `debug.evaluate` inspector
  allowlist and its Phase-C MI migration are unaffected, and no new operation is
  reachable. The name-shape gate (decision 2) is what keeps this from being the
  arbitrary-expression surface ADR 0019 rejected.
- The version floor stays at gdb 9.1: `-data-evaluate-expression` predates it,
  so no probe-capability or `MIN_GDB_VERSION` change is needed (unlike the
  `-symbol-info-*` verbs — see rejected B).
- Provenance behavior is unchanged; Phase B adds MI-path test coverage asserting
  the ADR 0017 gate blocks before `attach()`, but introduces no new gate logic
  and no new error codes.

## Considered & rejected

- **A. Re-resolve over the `-symbol-info-symbol` (address→name) verb.** Rejected:
  that verb answers the inverse question (given an address, name it); AC2 is
  name→address. It cannot satisfy the criterion without first knowing the address.

- **B. Use `-symbol-info-functions` / `-symbol-info-variables --name <regex>`.**
  These are the "structured" symbol-table MI verbs and would avoid `-data-evaluate-
  expression` entirely. Rejected: they were introduced in **gdb 10.1**, below which
  they are unavailable — but the tier's documented floor is gdb **9.1** (ADR 0019).
  Adopting them would force raising `MIN_GDB_VERSION` to 10.1 (a scope change owned
  by ADR 0019, narrowing supported hosts) or carrying a version-branch fallback.
  `-data-evaluate-expression "&name"` works unchanged from 9.1 up, so it holds the
  floor with no capability branch.

- **C. Parse `info address <name>` console-stream text via `-interpreter-exec
  console`.** Rejected: it returns free-form console-stream records ("Symbol
  \"linux_banner\" is static storage at address 0x..."), the exact human-text
  scraping #13/ADR 0019 exists to eliminate. Eval returns a structured `^done`
  value record instead.

- **D. Expose `resolve_symbol` as an agent-facing `debug.*` operation taking an
  arbitrary symbol name.** Rejected: it would add surface to the constrained debug
  contract (CLAUDE.md, `ALLOWED_DEBUG_OPERATIONS`) and, with an arbitrary name,
  edge toward the raw-expression hatch ADR 0019 forbids. Phase B's need is an
  internal proof that loaded symbols resolve; a fixed canonical symbol inside the
  existing probe meets the acceptance without new agent surface. Per-symbol
  agent-facing resolution, if ever needed, belongs to a later phase behind an
  allowlist.

- **E. Skip symbol resolution; treat Phase A's `-file-exec-and-symbols` ^done as
  sufficient "symbols loaded" evidence.** Rejected: a successful
  `-file-exec-and-symbols` proves gdb opened the file, not that a symbol resolves
  against the attached target; AC2 explicitly requires resolving a symbol *by
  name*. The probe must demonstrate resolution, not just file load.

- **F. Verify the running kernel's build-id over RSP post-attach as the Phase B
  provenance check.** Rejected here as in ADR 0017 (rejected A): provenance is
  verified pre-attach against the artifact store, deterministically and
  unit-testably; reading the running build-id over RSP is arch-specific, only
  testable through the gated integration job, and redundant with `live_banner_match`.
  Phase B consumes the existing pre-attach primitive unchanged.
