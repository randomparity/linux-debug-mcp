# gdb/MI Phase D — module symbols, RSP-stall robustness, serial transport + docs

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the gdb/MI tier robust beyond the clean QEMU gdbstub path: load loadable-module symbols at runtime addresses so module breakpoints resolve; detect-and-report an RSP transport stall instead of hanging, with guaranteed resume; route break-entry off the admitted `break_plan` (never re-derived in the tier); warn when RSP rides a lossy out-of-band console; and ship `docs/debug-gdb.md`. The serial-KGDB break/continue criterion ships as a gated integration test (no false green).

**Architecture:** Engine-layer additions live in `providers/gdb_mi.py` (RSP `remotetimeout` + connect retry, `transport_stall` tagging, `load_module_symbols`). Guest-side facts (sysfs section addresses) are sourced in a bespoke `server.py` handler over the existing injectable `SshRunner` seam; the `.ko` is resolved by an injectable finder confined to the build tree. The transport-quality warning and the break-entry router are pure functions over recorded `PlatformMetadata`/`TransportSession.break_plan` facts. Per-op stall handling runs the full `start_session`-style teardown **inside `debug_lock`**.

**Tech Stack:** Python 3.11+, `pygdbmi`, Pydantic v2 (`Model`/`ConfigModel`, `extra="forbid"`), pytest with injected `FakeController`/fake `SshRunner`, ruff + ty.

**Spec:** `docs/superpowers/specs/2026-05-29-debug-gdb-mi-tier-design.md` (Phase D) · **ADRs:** [0022](../../adr/0022-gdb-mi-phase-d-module-symbol-loading.md), [0023](../../adr/0023-gdb-mi-phase-d-rsp-stall-detect-and-report.md), [0024](../../adr/0024-gdb-mi-phase-d-transport-adaptation.md) · consumes [0018](../../adr/0018-break-injection-policy-mapping.md), [0021](../../adr/0021-gdb-mi-phase-c-session-registry-and-execution-state.md)

**Conventions every task follows:**
- TDD: write the failing test first, run it red, implement, run it green, commit.
- Guardrails green at every commit: `uv run ruff check && uv run ruff format --check && uv run ty check src && uv run python -m pytest -q`.
- Engine tests use the `FakeController` pattern from `tests/test_gdb_mi_core_ops.py`. Handler tests inject fakes (`ssh_runner=`, `module_ko_finder=`, `gdb_mi_engine=`, `gdb_mi_sessions=`, profile dicts) per the repo contract — never through MCP.
- Redact every returned/persisted record. Keep env-gated integration tests gated.
- Commit trailer: `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`.

**Delivery order is A→B→C→D (C merged); within Phase D the tasks are independently committable. Recommended order: 1→2→3 (stall), 4→5 (module symbols), 6 (warning), 7 (break routing), 8 (serial gated test), 9 (docs), 10 (sweep).**

---

## File Structure

- **Modify** `src/linux_debug_mcp/providers/gdb_mi.py` — constants `RSP_REMOTE_TIMEOUT_SEC`, `_CONNECT_RETRY_COUNT`, `_CONNECT_RETRY_BACKOFF_SEC`; `attach()` sets `remotetimeout` + retries the connect via an injectable `sleep` seam + re-tags connect-phase timeouts as `DEBUG_ATTACH_FAILURE`; a `transport_stall` tag on post-attach write timeouts; silence-path stall in `resume()`; new `LoadedModule` record + `load_module_symbols()`.
- **Modify** `src/linux_debug_mcp/config.py` — add `debug.load_module_symbols` to `ALLOWED_DEBUG_OPERATIONS`.
- **Modify** `src/linux_debug_mcp/server.py` — `_read_module_sections` (SSH-sysfs) + `_default_module_ko_finder` + `debug_load_module_symbols_handler` (gated by the literal op string, **not** via `DEBUG_METHOD_OPERATIONS`) + tool wrapper; `is_lossy_out_of_band` + wire warning into `debug_start_session_handler`; `_break_entry_method` router consulting `TransportSession.break_plan`; per-op + read-path `transport_stall` teardown (threads `transaction`/`session_guard` through the debug handlers); `transport_quality_warning` redaction.
- **Modify** `src/linux_debug_mcp/coordination/transaction.py` — add `inject_break_for_session(session_id, requested_method)` resolving the live proxy handle/ssh prefix and delegating to `transport.break_inject.inject_break`, raising `break_inject_unavailable` when no handle.
- **Modify** `src/linux_debug_mcp/providers/qemu_gdbstub.py` — `DebugSession` gains `loaded_modules: dict[str, dict[str, object]]`.
- **Create** `tests/test_gdb_mi_rsp_stall.py` — engine stall + retry unit tests.
- **Create** `tests/test_gdb_mi_module_symbols.py` — engine `load_module_symbols` unit tests.
- **Create** `tests/test_server_load_module_symbols.py` — handler tests (fake ssh_runner + finder).
- **Create** `tests/test_server_transport_quality_warning.py` — warning predicate + start_session wiring.
- **Create** `tests/test_server_break_entry_routing.py` — native-vs-inject router.
- **Create** `tests/test_gdb_mi_serial_kgdb_integration.py` — gated serial break/continue.
- **Create** `docs/debug-gdb.md`.

---

## Task 1: RSP `remotetimeout` + bounded connect retry (injectable sleep)

ADR 0023 decisions 1–2. Set `remotetimeout` before connect; retry any idempotent pre-`^connected` connect error a fixed small number of times.

**Files:** Modify `src/linux_debug_mcp/providers/gdb_mi.py`; Test `tests/test_gdb_mi_rsp_stall.py`.

- [ ] **Step 1 — failing tests.** Using the `FakeController` pattern:
  - `test_attach_sets_remotetimeout_before_target_select`: assert the command sequence includes `-gdb-set remotetimeout <N>` and that its index precedes `-target-select remote ...`.
  - `test_connect_retries_transient_error_then_succeeds`: script the first `-target-select remote` write as a `^error`, the retry as `^connected`; inject a recording `sleep` seam; assert the connect was issued twice, one backoff sleep occurred, attach succeeds.
  - `test_connect_exhausts_retries_then_fails_attach`: all connect attempts `^error`; assert `GdbMiError(DEBUG_ATTACH_FAILURE)` after `_CONNECT_RETRY_COUNT` attempts, sleeps == count-1, engine `exit()` called.
- [ ] **Step 2 — run red.**
- [ ] **Step 3 — implement.** Add constants; thread an injectable `sleep: Callable[[float], None] = time.sleep` through `GdbMiEngine.__init__`. In `attach()`, issue `-gdb-set remotetimeout {RSP_REMOTE_TIMEOUT_SEC}` before `-target-select remote`. Wrap the connect in a bounded loop: on a connect `^error` (or a connect-phase write timeout), `sleep(backoff)` and retry up to `_CONNECT_RETRY_COUNT`; re-tag any connect-phase timeout as `DEBUG_ATTACH_FAILURE`. On exhaustion, `controller.exit()` and raise `DEBUG_ATTACH_FAILURE`. Keep the connect idempotent (only the connect is retried — never a later verb).
- [ ] **Step 3b — update the shared attach test fixture (REQUIRED, or the whole engine suite goes red).** `attach()` now issues **six** commands, not five, so the shared `_ATTACH_OK = [_DONE, _DONE, _DONE, _DONE, _CONNECTED]` (`tests/test_gdb_mi_core_ops.py:53`) — consumed by `_attached()` in every engine test — is one write short and `FakeController` will run out mid-attach across the **entire** engine suite. Bump it to `_ATTACH_OK = [_DONE, _DONE, _DONE, _DONE, _DONE, _CONNECTED]` and audit every command-index assertion in `tests/test_gdb_mi_core_ops.py` and `tests/test_gdb_mi_engine.py` (any `commands[i]`/`commands.index(...)` that assumed the old offset). Re-run the **full** engine suite green, not just the new file.
- [ ] **Step 4 — run green** (`uv run python -m pytest tests/test_gdb_mi_core_ops.py tests/test_gdb_mi_engine.py tests/test_gdb_mi_rsp_stall.py -q` — all green after the fixture bump).
- [ ] **Step 5 — commit:** `feat(gdb-mi): set remotetimeout and bound the RSP connect with retry/backoff`.

---

## Task 2: `transport_stall` tagging — write-path + silence-path

ADR 0023 decision 3. A post-attach write timeout, and a silence-during-`resume` (interrupt accepted, no `*stopped`), both raise `code="transport_stall"` / `INFRASTRUCTURE_FAILURE`.

**Files:** Modify `src/linux_debug_mcp/providers/gdb_mi.py`; Test `tests/test_gdb_mi_rsp_stall.py`.

- [ ] **Step 1 — failing tests.**
  - `test_write_timeout_on_established_session_tags_transport_stall`: after a successful attach, script the next per-op write to raise the controller timeout; assert the raised `GdbMiError.category == INFRASTRUCTURE_FAILURE` and `details["code"] == "transport_stall"`.
  - `test_attach_phase_timeout_is_attach_failure_not_stall`: script a connect-phase write timeout (after retries exhausted); assert category `DEBUG_ATTACH_FAILURE`, **not** `transport_stall` (established = per-op path only).
  - `test_resume_silence_after_accepted_interrupt_is_transport_stall`: `-exec-continue` → `^running`; `read()` returns `[]` for the budget; `-exec-interrupt` write accepted (`^done`/`^error`-benign) but no `*stopped` ever arrives → `resume()` raises `transport_stall`.
  - `test_resume_timeout_with_sigint_stop_is_benign_timed_out`: same but the interrupt yields a `*stopped (signal-received)` → returns `StopRecord(timed_out=True)`, **no** raise (Phase-C behaviour preserved).
- [ ] **Step 2 — run red.**
- [ ] **Step 3 — implement.** Give the controller-timeout → `GdbMiError` path a way to carry `transport_stall`: the per-op `_run`/`write` wrapper tags timeouts reached after attach as `transport_stall`/`INFRASTRUCTURE_FAILURE`, while `attach()`'s own connect-phase writes re-tag to `DEBUG_ATTACH_FAILURE` (Task 1). In `resume()`, after the wait times out, call `interrupt()`; if the interrupt write succeeded but `wait_for_stop` returns `None` (no SIGINT stop), raise `GdbMiError(transport_stall)` instead of returning `timed_out=True`. A delivered SIGINT that yields a stop stays benign.
- [ ] **Step 4 — run green.**
- [ ] **Step 5 — commit:** `feat(gdb-mi): tag write-path and silence-path RSP stalls as transport_stall`.

---

## Task 3: Per-op `transport_stall` teardown inside `debug_lock`

ADR 0023 decision 3. The stall runs the full `start_session`-style teardown (`force_resume` + `_resume_debug_transport` + `_teardown_debug_transport`) **inside** the lock; benign `GdbMiError`s keep Phase-C contained behaviour.

**Files:** Modify `src/linux_debug_mcp/server.py` (`_debug_operation_response`, the inner `try` at ~4832-4855); Test `tests/test_server_debug_core_ops.py` (extend) or a new `tests/test_server_debug_stall.py`.

**Plumbing scope (do this first — it is broad).** `_debug_operation_response` today carries only `admission`, `session_registry`, `gdb_mi_engine`, `gdb_mi_sessions` — **not** `transaction`/`session_guard`, which `_teardown_debug_transport` needs — and the read handlers route through it **without even `admission`**. So the teardown requires threading `transaction` + `session_guard` through `_debug_operation_response`, `_debug_stateful_response`, `_debug_read_response`, every per-op handler (the ~12 stateful + the ~4 read handlers), and every matching `@app.tool` wrapper in `create_app` (pass the same `transport_transaction`/`session_guard` already wired into `debug.start_session`). Enumerate them from the existing wrapper block and change them in one commit so no half-wired handler ships.

**Read-path stalls.** A `read_memory`/`read_registers`/`read_symbol`/`evaluate` over a dead link can stall too. Decision: read ops get the **same** `transport_stall` teardown (a stalled read means the link is dead regardless of op kind), so the read handlers gain `transaction`/`session_guard` as well; a read-stall test mirrors the stateful one.

- [ ] **Step 1 — failing tests** (handler-level, inject a `gdb_mi_engine` whose op raises `GdbMiError(transport_stall)` and a fake transaction/admission/session_guard/registry):
  - `test_transport_stall_reaps_resumes_and_tears_down`: a stateful op stall → response `INFRASTRUCTURE_FAILURE` with `details["code"]=="transport_stall"`, `suggested_next_actions` contains `debug.start_session`, `debug.kdb`, `debug.introspect.run`; assert the attachment was reaped, `force_resume` called, the durable record written EXECUTING, and the guard released (via fakes recording calls).
  - `test_read_op_transport_stall_also_tears_down`: a `read_memory` stall runs the identical teardown (proves the read path is wired, not just the stateful path).
  - `test_benign_gdbmi_error_keeps_session`: a `GdbMiError(DEBUG_ATTACH_FAILURE)` (bad symbol) returns contained failure, attachment **not** reaped, no transport teardown (Phase-C unchanged).
- [ ] **Step 2 — run red.**
- [ ] **Step 3 — implement.** Thread the params per the plumbing-scope note above. Inside the inner `try` (where the raw-fault branch already reaps), catch `GdbMiError` whose `details.get("code") == "transport_stall"` and run the same teardown sequence `_run_mi_attach_probe`'s failure path uses (`server.py:4111-4130`): `force_resume(reaped)` → `_resume_debug_transport(...)` (best-effort) → `_teardown_debug_transport(...)`, then return the structured `INFRASTRUCTURE_FAILURE`. All teardown happens before the `with store.debug_lock` block exits.
- [ ] **Step 4 — run green** (and the full `tests/test_server_debug_*` + `tests/test_server_debug_reads_while_halted.py` to confirm no regression from the new params).
- [ ] **Step 5 — commit:** `feat(server): tear down the transport on an RSP stall, inside debug_lock`.

---

## Task 4: Engine `load_module_symbols` + `LoadedModule` record (idempotent via ledger)

ADR 0022 decision 3. `-interpreter-exec console "add-symbol-file <ko> <text> -s .data <addr> …"`, hex-re-validated, ledger-deduped.

**Files:** Modify `src/linux_debug_mcp/providers/gdb_mi.py`; Test `tests/test_gdb_mi_module_symbols.py`.

- [ ] **Step 1 — failing tests.**
  - `test_load_module_symbols_issues_add_symbol_file`: `sections={".text":"0xffffffffc0000000",".data":"0xffffffffc0010000"}`, `ko_path=tmp/foo.ko`; assert the console command is `-interpreter-exec console "add-symbol-file <escaped-ko> 0xffffffffc0000000 -s .data 0xffffffffc0010000"` (text positional first, others as `-s name addr`), and a typed `LoadedModule(name=..., sections=...)` is returned (redacted).
  - `test_load_module_symbols_rejects_non_hex_address`: a section value `"0xZZ"` or `"; quit"` raises `CONFIGURATION_ERROR` before any write.
  - `test_load_module_symbols_rejects_ko_with_control_whitespace`: a `ko_path` containing a newline raises `CONFIGURATION_ERROR` (reuse `_mi_path`).
  - `test_load_module_symbols_error_record_is_attach_failure`: console `^error` → `DEBUG_ATTACH_FAILURE`.
- [ ] **Step 2 — run red.**
- [ ] **Step 3 — implement.** Add `LoadedModule(Model)` (`name: str`, `sections: dict[str,str]`). `load_module_symbols(attachment, *, name, ko_path, sections)`: re-validate each address as `0x`-hex; build `add-symbol-file {escaped_ko} {text} -s {sec} {addr} …` (sorted/deterministic order, `.text` first), issue via `-interpreter-exec console`, classify via `_run`. Return a redacted `LoadedModule`. (Ledger dedup lives in the handler, Task 5, since the engine is stateless.)
- [ ] **Step 4 — run green.**
- [ ] **Step 5 — commit:** `feat(gdb-mi): load_module_symbols via add-symbol-file console command`.

---

## Task 5: `debug.load_module_symbols` handler + SSH-sysfs sourcing + finder + ledger

ADR 0022 decisions 1–3. New op end-to-end.

**Files:** Modify `src/linux_debug_mcp/config.py` (allowlist), `src/linux_debug_mcp/server.py` (helpers, handler, tool wrapper — gated by the literal op string, **not** `DEBUG_METHOD_OPERATIONS`), `src/linux_debug_mcp/providers/qemu_gdbstub.py` (`DebugSession.loaded_modules`); Test `tests/test_server_load_module_symbols.py`.

- [ ] **Step 1 — failing tests** (inject a fake `SshRunner`, a fake `module_ko_finder`, a fake engine):
  - `test_reads_sysfs_sections_and_loads`: fake ssh returns `0x...` for `.text`/`.data`; finder returns a `.ko`; assert the engine got the parsed sections and the response is success with a `loaded_modules` ledger entry persisted.
  - `test_text_unreadable_reports_section_addresses_unreadable`: ssh returns non-zero/empty for `.text`; assert `CONFIGURATION_ERROR` / `code="section_addresses_unreadable"`, engine **not** called.
  - `test_module_not_loaded_when_sysfs_dir_absent`: ssh reports the `/sys/module/<name>` dir absent → `module_not_loaded`.
  - `test_ko_not_found_reports_with_spellings`: finder returns `None` → `module_object_not_found` naming the `-`/`_` spellings tried.
  - `test_explicit_sections_override_skips_ssh`: caller passes `sections=` → ssh_runner not called; validated identically.
  - `test_ssh_unreachable_without_explicit_sections`: no ssh path + no explicit map → `ssh_unreachable`.
  - `test_idempotent_reload_same_address_is_noop`: a module already in `loaded_modules` at the same `.text` → success no-op, engine `load_module_symbols` **not** re-called.
  - `test_reload_changed_address_is_error`: same module, different discovered `.text` → `module_address_changed`.
  - `test_op_gated_by_enabled_operations`: a profile narrowing out `debug.load_module_symbols` → refused before SSH/gdb.
  - `test_module_name_rejects_non_identifier`: a name with `;`/`/` → `CONFIGURATION_ERROR` before SSH.
- [ ] **Step 2 — run red.**
- [ ] **Step 3 — implement.**
  - `config.py`: add `"debug.load_module_symbols"` to `ALLOWED_DEBUG_OPERATIONS`.
  - `qemu_gdbstub.py`: add `loaded_modules: dict[str, dict[str, object]] = Field(default_factory=dict)` to `DebugSession`.
  - `server.py`: the bespoke handler gates with the **literal** op string `_ensure_debug_operation_enabled(profile, "debug.load_module_symbols")` — do **not** add it to `DEBUG_METHOD_OPERATIONS` (whose entries are all `_engine_op_data`-dispatchable; this op routes through its own handler, so an entry there would be dead/misleading). `_read_module_sections(ssh_runner, rootfs_profile, module_name) -> dict[str,str]` (validate name; one SSH read per allowlisted section file under `/sys/module/<name>/sections/`; `.text` mandatory → `section_addresses_unreadable` on miss; distinguish dir-absent → `module_not_loaded`; validate each value `0x`-hex); `_default_module_ko_finder(build_tree, name)` (try `<name>.ko[.debug]` and the `-`/`_` swap, confine via `safety/paths.py`); `debug_load_module_symbols_handler(*, ... ssh_runner=None, module_ko_finder=None, sections=None, ko_path=None, gdb_mi_engine, gdb_mi_sessions, admission, session_registry, ...)` running under `store.debug_lock`, fence-then-lookup, `_ensure_debug_operation_enabled`, ledger dedup, engine call, persist `loaded_modules`, redact, guaranteed-resume on raw fault; the `@app.tool(name="debug.load_module_symbols")` wrapper.
- [ ] **Step 4 — run green** (+ regenerate any committed schema snapshot if `DebugSession` is snapshotted — check `introspect_helpers/schemas/`; `DebugSession` is not a helper model, so likely none).
- [ ] **Step 5 — commit:** `feat(server): add debug.load_module_symbols (sysfs sections + add-symbol-file)`.

---

## Task 6: Transport-quality warning

ADR 0024 decision 2. `is_lossy_out_of_band(console_kind)` pure helper; wired into `debug.start_session` success data.

**Files:** Modify `src/linux_debug_mcp/server.py`; Test `tests/test_server_transport_quality_warning.py`.

- [ ] **Step 1 — failing tests.**
  - `test_is_lossy_out_of_band_predicate`: `HVC`/`VIRTIO` → True; `UART` → False (fed a snapshot-shaped `PlatformMetadata`).
  - `test_start_session_over_hvc_emits_warning`: a start_session whose snapshot platform has `console_kind=HVC` → success `data["transport_quality_warning"]` non-empty (redacted) and `suggested_next_actions` includes `debug.kdb`, `debug.introspect.run`.
  - `test_start_session_over_qemu_uart_no_warning`: the existing local-qemu `UART` path → no `transport_quality_warning` key; `suggested_next_actions` unchanged.
- [ ] **Step 2 — run red.**
- [ ] **Step 3 — implement.** Add `is_lossy_out_of_band(console_kind: ConsoleKind) -> bool` (`console_kind in {HVC, VIRTIO}`). In `debug_start_session_handler`, after a successful attach, read `snapshot.platform.console_kind` (already available via the OpenRequest/admission snapshot) and, when lossy, set `data["transport_quality_warning"]` (redacted) and extend `suggested_next_actions`.
- [ ] **Step 4 — run green.**
- [ ] **Step 5 — commit:** `feat(server): warn when gdb/MI RSP rides a lossy out-of-band console`.

---

## Task 7: Break-entry routing off `break_plan`

ADR 0024 decision 1. `debug.interrupt` resolves the `TransportSession` and routes native-vs-inject, defaulting to native.

**Files:** Modify `src/linux_debug_mcp/server.py`; Test `tests/test_server_break_entry_routing.py`.

**Prerequisite — `inject_break_for_session` does not exist yet.** The router's non-native branch calls `transaction.inject_break_for_session(session_id, requested_method)`, but `TransportTransaction` has no such method today (repo-wide search confirms). This task creates it, or Task 7's router will not `ty check`. The method resolves the owning transport's live `proxy`/`proxy_handle` (from the serial-local transport's `_proxy_handles`) + the `ssh_argv_prefix`, then calls `transport.break_inject.inject_break(...)`; when no handle resolves (e.g. a `gdbstub-qemu` transport, or the handle is gone), it raises `InjectBreakError`/`CONFIGURATION_ERROR` with `code="break_inject_unavailable"` — never a silent no-op. Its `gdbstub_native`-guard already exists in `inject_break`.

- [ ] **Step 1 — failing tests** (pure router + the new seam, with a fake transaction/transport):
  - `test_router_native_for_gdbstub_native`: a `break_plan.method == GDBSTUB_NATIVE` (or absent record) routes to the engine `interrupt()` path; inject not called.
  - `test_router_inject_for_serial_method`: a `break_plan.method == AGENT_PROXY_BREAK` routes to `inject_break_for_session`; assert it is called with the admitted method.
  - `test_inject_break_for_session_missing_handle_raises_unavailable`: the new seam with a transport that has no resolvable proxy handle → `break_inject_unavailable`, never a silent no-op.
- [ ] **Step 2 — run red.**
- [ ] **Step 3 — implement.** (a) Add `TransportTransaction.inject_break_for_session(session_id, requested_method)` resolving the handle + ssh prefix and delegating to `inject_break`, raising `break_inject_unavailable` when no handle. (b) A pure `_break_entry_method(transport_session) -> BreakMethod` (load `TransportSession` by `transport_session_id` from `session_registry`; default `GDBSTUB_NATIVE` when record/plan absent). (c) In the interrupt path, branch: native → engine `interrupt()`; else → `transaction.inject_break_for_session(session_id, method)` then `wait_for_stop`. Local CI covers (b)+(c)'s routing and the `break_inject_unavailable` guard against a `gdbstub-qemu` transport (no handle); the **real** handle-resolution success path runs only in Task 8's gated serial test.
- [ ] **Step 4 — run green** (`ty check src` must pass — the seam now exists).
- [ ] **Step 5 — commit:** `feat(server): route break-entry off the admitted break_plan, native by default`.

---

## Task 8: Serial-KGDB gated integration test (no false green)

ADR 0024 decision 3.

**Files:** Create `tests/test_gdb_mi_serial_kgdb_integration.py`.

Depends on Task 7's `inject_break_for_session` (the real handle-resolution path this test exercises).

- [ ] **Step 1 — write the gated test.** Mirror `tests/test_serial_local_transport_integration.py`'s `pytestmark = pytest.mark.skipif(shutil.which("agent-proxy") is None and os.environ.get("LDM_REQUIRE_AGENT_PROXY") != "1", reason="agent-proxy not installed (set LDM_REQUIRE_AGENT_PROXY=1 to require it in CI) — serial-KGDB break/continue prerequisite")`. Build the PTY-backed `serial-local` demux to get an `rsp_endpoint`, attach the MI engine over it, set a breakpoint, inject a break via `inject_break_for_session` (the admitted plan), continue, and assert a `*stopped`. The skip reason **names the missing prerequisite** so a local-only run shows it skipped, never passing.
- [ ] **Step 2 — run.** Locally without `agent-proxy`: assert it reports `skipped` (the prerequisite named). Do not un-gate.
- [ ] **Step 3 — commit:** `test(gdb-mi): gated serial-KGDB break/continue integration (skipped without agent-proxy)`.

---

## Task 9: `docs/debug-gdb.md`

Issue scope + ADR 0024.

**Files:** Create `docs/debug-gdb.md`.

- [ ] **Step 1 — write the doc.** Sections: the gdb/MI tier overview; the agent flow (`start_session → load_module_symbols → set_breakpoint → continue`); **transport-quality guidance** (QEMU gdbstub is the clean path; SOL/HMC vterm RSP may be unreliable → prefer `debug.kdb`/`debug.introspect`; the warning the tool emits); RSP-stall behaviour (re-attach, never re-sync); **ppc64le caveats** (hvc0 + kgdb roughness; prefer drgn/KDB on POWER where practical). No the word "sprint" anywhere.
- [ ] **Step 2 — run `just check-docs`** (must pass; the doc is user-facing, not under `docs/superpowers/`).
- [ ] **Step 3 — commit:** `docs: add debug-gdb.md transport-quality + ppc64le guidance`.

---

## Task 10: Guardrails sweep + capability operations advertisement

- [ ] **Step 1** — confirm the `local-qemu-gdbstub` capability's `operations` list advertises `debug.load_module_symbols` (so `providers.list` surfaces it); add a test asserting it.
- [ ] **Step 2** — full guardrails: `uv run ruff check && uv run ruff format --check && uv run ty check src && uv run python -m pytest -q`. Fix every warning.
- [ ] **Step 3** — `just check-docs`.
- [ ] **Step 4 — commit** any residual wiring: `chore(gdb-mi): advertise load_module_symbols + Phase D guardrail sweep`.

---

## Acceptance mapping

| Issue criterion | Verified by |
|---|---|
| Module symbols load at runtime addresses; module breakpoint resolves & is hit | Tasks 4–5 unit (command shape, sysfs parse, ledger); the **hit** in the gated integration test (Task 8) |
| Basic break/continue over a demuxed serial line | Task 8 gated test (skipped without `agent-proxy`, never a false green) |
| Induced transport stall reported (not hung) and target resumed | Tasks 2–3 (write-path + silence-path stall → `transport_stall` → full teardown, durable EXECUTING, guard released) |
| Lossy out-of-band console emits the transport-quality warning | Task 6 (`is_lossy_out_of_band` + start_session wiring) |
| Break entry executes `inject_break` using `BreakPolicy`, not hardcoded | Task 7 (routing off `break_plan.method`) |
| `docs/debug-gdb.md` transport-quality + ppc64le caveats | Task 9 |

## Rollback / cleanup

Each task is an independent commit; reverting any one leaves the gate behind `ALLOWED_DEBUG_OPERATIONS` (new op unreachable until merged) and the warning/stall paths are additive. No durable schema migration: `DebugSession.loaded_modules` defaults to `{}`, so old manifests load unchanged.
