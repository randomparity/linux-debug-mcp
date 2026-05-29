# `debug.introspect` write-mode (`allow_write`) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the `allow_write=true` hard-reject in `debug.introspect.run` with a two-factor policy gate (DebugProfile capability + per-call destructive-permission ack), a cooperative `drgn.Program`-subclass write-guard in the wrapper, and an audit trail; reclassify the vmcore reject as not-applicable.

**Architecture:** The host-side policy gate is the security boundary. The wrapper guard is a `drgn.Program` subclass whose `write()` raises a sentinel (caught → `write_mode_disabled` outcome → `CONFIGURATION_ERROR`), giving a clean rejection without breaking read-only scripts (`isinstance` still passes). `allow_write` and the satisfied required permissions are recorded on every manifest write path and one WARNING audit log line.

**Tech Stack:** Python 3.11+, Pydantic v2, FastMCP, pytest, `uv`, `ruff`, `ty`. Spec: `docs/superpowers/specs/2026-05-29-debug-introspect-write-mode-design.md`. ADR: `docs/adr/0011-introspect-write-mode-enforcement.md`.

**Conventions:** Tests call handlers directly with injected providers/profiles. `ToolResponse.success/failure` with the most specific `ErrorCategory`. Run `uv run ruff check && uv run ruff format && uv run ty check src && uv run python -m pytest -q` green before each commit. Commit trailer: `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`.

---

## File map

- `src/linux_debug_mcp/config.py` — add `debug.introspect.write` to `ALLOWED_DEBUG_OPERATIONS`; add `INTROSPECT_DESTRUCTIVE_PERMISSIONS`; generalise `missing_destructive_permissions` with a `registry` kwarg.
- `src/linux_debug_mcp/domain.py` — add `acknowledged_permissions` to `DebugIntrospectRunRequest`.
- `src/linux_debug_mcp/providers/local_drgn_introspect.py` — `${ALLOW_WRITE_SETUP}` in `_WRAPPER_PROLOGUE_LIVE`; sentinel + `except` arm in `_WRAPPER_BODY`; `render_wrapper(allow_write=…)` and `render_wrapper_skeleton` substitution.
- `src/linux_debug_mcp/server.py` — write-mode gate in `_execute_introspect_call`; thread `allow_write` to `render_wrapper`, `_finalize_introspect_call`, `_record_introspect_failure`, and the `WrapperRenderError` `StepResult`; audit log at call_id mint; `write_mode_disabled` branch in `_finalize_introspect_call`; vmcore reclassify; expose `acknowledged_permissions` on the MCP tool.
- `tests/golden/live_wrapper_template.txt` — regenerate after the prologue/body edits.
- Tests: `tests/test_config.py`, `tests/test_domain.py`, `tests/test_introspect_wrapper.py`, `tests/test_debug_introspect_run.py`, `tests/test_debug_introspect_from_vmcore.py`, `tests/test_drgn_introspect_integration.py`.

---

## Task 1: config — write op, destructive-permission registry, generalised checker

**Files:**
- Modify: `src/linux_debug_mcp/config.py:95-119` (`ALLOWED_DEBUG_OPERATIONS`), `:135-153` (constants + `missing_destructive_permissions`)
- Test: `tests/test_config.py`

- [ ] **Step 1: Write failing tests**

Add to `tests/test_config.py` (extend the import on line 5 to add `INTROSPECT_DESTRUCTIVE_PERMISSIONS, missing_destructive_permissions`):

```python
def test_allowed_debug_operations_includes_introspect_write() -> None:
    assert "debug.introspect.write" in ALLOWED_DEBUG_OPERATIONS


def test_introspect_destructive_permissions_has_run_entry() -> None:
    assert INTROSPECT_DESTRUCTIVE_PERMISSIONS["debug.introspect.run"] == [
        "mutate live kernel state via drgn write APIs"
    ]


def test_missing_destructive_permissions_introspect_registry() -> None:
    required = INTROSPECT_DESTRUCTIVE_PERMISSIONS["debug.introspect.run"]
    assert (
        missing_destructive_permissions(
            "debug.introspect.run", [], registry=INTROSPECT_DESTRUCTIVE_PERMISSIONS
        )
        == required
    )
    assert (
        missing_destructive_permissions(
            "debug.introspect.run", required, registry=INTROSPECT_DESTRUCTIVE_PERMISSIONS
        )
        == []
    )
    # Superset acknowledgement satisfies the gate.
    assert (
        missing_destructive_permissions(
            "debug.introspect.run", [*required, "extra"], registry=INTROSPECT_DESTRUCTIVE_PERMISSIONS
        )
        == []
    )


def test_missing_destructive_permissions_defaults_to_transport_registry() -> None:
    # Default registry is unchanged for the transport call site.
    assert missing_destructive_permissions("transport.inject_break", []) == [
        "drop target kernel into the debugger"
    ]
```

> `test_config.py:130-147` is the **only** snapshot affected by the new op: it is the sole test asserting the default `enabled_operations` list. Other `enabled_operations` references construct explicit subsets, and `debug.introspect.write` is a capability token (not an MCP tool and not in any `ProviderCapability.operations` list), so `providers.list` / `_tool_manager._tools` snapshots are unchanged.

Also update the default-profile snapshot at `tests/test_config.py:130-147` — append one entry to the expected list:

```python
        "debug.introspect.from_vmcore_helper",
        "debug.introspect.write",
    ]
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run python -m pytest tests/test_config.py -q`
Expected: FAIL — `ImportError`/`KeyError` for `INTROSPECT_DESTRUCTIVE_PERMISSIONS`, and the snapshot mismatch.

- [ ] **Step 3: Implement config changes**

In `src/linux_debug_mcp/config.py`, append to `ALLOWED_DEBUG_OPERATIONS` (after `"debug.introspect.from_vmcore_helper",` at line 118):

```python
    # ADR 0011 / #56: capability token (NOT an MCP tool) gating allow_write=true
    # on the live introspect path. Only ever passed to _ensure_debug_operation_enabled.
    "debug.introspect.write",
```

After `TRANSPORT_DESTRUCTIVE_PERMISSIONS = {...}` (line 137) add:

```python
INTROSPECT_DESTRUCTIVE_PERMISSIONS = {
    "debug.introspect.run": ["mutate live kernel state via drgn write APIs"],
}
```

Replace `missing_destructive_permissions` (lines 146-153) with:

```python
def missing_destructive_permissions(
    operation: str,
    acknowledged: list[str],
    *,
    registry: dict[str, list[str]] | None = None,
) -> list[str]:
    """Return the destructive permissions an operation requires that the caller has not
    acknowledged. A non-destructive (or unknown) operation requires nothing, so the list is
    empty. The tool layer refuses the call when this is non-empty so an agent never performs a
    destructive operation without explicit acknowledgement. ``registry`` selects the
    permission table (defaults to ``TRANSPORT_DESTRUCTIVE_PERMISSIONS`` for the transport ops;
    introspect passes ``INTROSPECT_DESTRUCTIVE_PERMISSIONS``)."""
    table = registry if registry is not None else TRANSPORT_DESTRUCTIVE_PERMISSIONS
    required = table.get(operation, [])
    acknowledged_set = set(acknowledged)
    return [permission for permission in required if permission not in acknowledged_set]
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run python -m pytest -q`
Expected: PASS — full suite green at this commit (the transport call site stays green via the default registry; `test_config:130` is the only snapshot touched).

- [ ] **Step 5: Commit**

```bash
git add src/linux_debug_mcp/config.py tests/test_config.py
git commit -m "feat(introspect): add write-capability op + destructive-permission registry (#56)"
```

---

## Task 2: domain — `acknowledged_permissions` on the run request

**Files:**
- Modify: `src/linux_debug_mcp/domain.py:108-116` (`DebugIntrospectRunRequest`)
- Test: `tests/test_domain.py`

- [ ] **Step 1: Write failing test**

Add to `tests/test_domain.py`:

```python
def test_introspect_run_request_acknowledged_permissions_default_empty() -> None:
    from linux_debug_mcp.domain import DebugIntrospectRunRequest

    req = DebugIntrospectRunRequest(run_id="r1", target_ref="local-qemu", script="pass")
    assert req.acknowledged_permissions == []
    req2 = DebugIntrospectRunRequest(
        run_id="r1", target_ref="local-qemu", script="pass", acknowledged_permissions=["x"]
    )
    assert req2.acknowledged_permissions == ["x"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run python -m pytest tests/test_domain.py::test_introspect_run_request_acknowledged_permissions_default_empty -q`
Expected: FAIL — `ValidationError` (extra field forbidden).

- [ ] **Step 3: Implement field**

In `src/linux_debug_mcp/domain.py`, add to `DebugIntrospectRunRequest` after `allow_write: bool = False` (line 112):

```python
    acknowledged_permissions: list[str] = Field(default_factory=list)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run python -m pytest tests/test_domain.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/linux_debug_mcp/domain.py tests/test_domain.py
git commit -m "feat(introspect): add acknowledged_permissions to run request (#56)"
```

---

## Task 3: wrapper — `drgn.Program`-subclass write-guard

**Files:**
- Modify: `src/linux_debug_mcp/providers/local_drgn_introspect.py` (`_WRAPPER_PROLOGUE_LIVE`, `_WRAPPER_BODY`, `render_wrapper`, `render_wrapper_skeleton`)
- Regenerate: `tests/golden/live_wrapper_template.txt`
- Test: `tests/test_introspect_wrapper.py`

- [ ] **Step 1: Write failing tests**

Add to `tests/test_introspect_wrapper.py`. First a class-based stub drgn (the existing `_install_stub_drgn` uses a *function* for `Program`, which cannot be subclassed), then the two guard tests:

```python
def _install_classbased_stub_drgn(monkeypatch: pytest.MonkeyPatch) -> None:
    """Stub drgn whose Program is a subclassable class with a base write()."""
    drgn_module = types.ModuleType("drgn")

    class _StubProgram:
        def set_kernel(self) -> None: ...

        def load_default_debug_info(self) -> None: ...

        def main_module(self):
            return SimpleNamespace(build_id=bytes.fromhex(EXPECTED_BUILD_ID))

        def write(self, *_a: Any, **_k: Any) -> None:
            return None

    drgn_module.Program = _StubProgram  # type: ignore[attr-defined]
    helpers_pkg = types.ModuleType("drgn.helpers")
    helpers_linux = types.ModuleType("drgn.helpers.linux")
    helpers_linux.__all__ = []  # type: ignore[attr-defined]
    helpers_pkg.linux = helpers_linux  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "drgn", drgn_module)
    monkeypatch.setitem(sys.modules, "drgn.helpers", helpers_pkg)
    monkeypatch.setitem(sys.modules, "drgn.helpers.linux", helpers_linux)


def test_wrapper_write_guard_blocks_write_when_allow_write_false(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_classbased_stub_drgn(monkeypatch)
    rendered = render_wrapper(
        user_script="prog.write(0, b'x')",
        expected_build_id=EXPECTED_BUILD_ID,
        call_id=CALL_ID,
        allow_write=False,
    )
    buf = StringIO()
    code = 0
    ns: dict[str, Any] = {"__name__": "__wrapper__", "__builtins__": builtins}
    with redirect_stdout(buf):
        try:
            exec(compile(rendered, "<wrapper>", "exec"), ns)
        except SystemExit as exc:
            code = int(exc.code) if exc.code is not None else 0
    assert code == 6
    payload = json.loads(buf.getvalue())
    assert payload["outcome"]["status"] == "write_mode_disabled"


def test_wrapper_write_allowed_when_allow_write_true(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_classbased_stub_drgn(monkeypatch)
    rendered = render_wrapper(
        user_script="prog.write(0, b'x'); emit({'wrote': True})",
        expected_build_id=EXPECTED_BUILD_ID,
        call_id=CALL_ID,
        allow_write=True,
    )
    buf = StringIO()
    code = 0
    ns: dict[str, Any] = {"__name__": "__wrapper__", "__builtins__": builtins}
    with redirect_stdout(buf):
        try:
            exec(compile(rendered, "<wrapper>", "exec"), ns)
        except SystemExit as exc:
            code = int(exc.code) if exc.code is not None else 0
    assert code == 6
    payload = json.loads(buf.getvalue())
    assert payload["outcome"] == {"status": "ok"}
    assert payload["emits"] == [{"wrote": True}]


def test_render_wrapper_threads_allow_write_setup() -> None:
    guarded = render_wrapper(
        user_script="pass", expected_build_id=EXPECTED_BUILD_ID, call_id=CALL_ID, allow_write=False
    )
    plain = render_wrapper(
        user_script="pass", expected_build_id=EXPECTED_BUILD_ID, call_id=CALL_ID, allow_write=True
    )
    assert "_li_GuardedProgram" in guarded
    assert "_li_GuardedProgram" not in plain
    assert "_li_program_class = drgn.Program" in plain
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run python -m pytest tests/test_introspect_wrapper.py -q`
Expected: FAIL — `render_wrapper()` has no `allow_write` kwarg (`TypeError`).

- [ ] **Step 3: Implement the wrapper changes**

In `src/linux_debug_mcp/providers/local_drgn_introspect.py`:

(a) In `_WRAPPER_PROLOGUE_LIVE`, replace the three lines (currently `prog = drgn.Program()` / `prog.set_kernel()` / `prog.load_default_debug_info()` at lines 107-109) with the `${ALLOW_WRITE_SETUP}` block placed *after* the `_li_drgn_helper_names = ...` line and the program instantiation switched to the factory:

```python
    _li_drgn_helper_names = set(globals().keys()) - _li_pre_helpers

${ALLOW_WRITE_SETUP}
    prog = _li_program_class()
    prog.set_kernel()
    prog.load_default_debug_info()
```

> Ordering constraint (spec §6): `${ALLOW_WRITE_SETUP}` is emitted *after* the `_li_drgn_helper_names` snapshot so the guard names are never captured as drgn helpers, and it is inside the existing `try:` that maps drgn-open failures to `drgn_open_failure`. Indent the substituted block to match (4 spaces inside the `try`).

(b) At the top of `_WRAPPER_BODY` (before `_li_emit_buffer = []`), define the sentinel unconditionally:

```python
class _li_WriteModeDisabled(Exception):
    pass

```

(c) In `_WRAPPER_BODY`, add an `except` arm before the generic `except BaseException as exc:` in the user-script exec block:

```python
    except _li_WriteModeDisabled as exc:
        msg, msg_trunc = _li_truncate(str(exc), _li_caps["error_message"])
        _li_result["outcome"] = {"status": "write_mode_disabled",
                                 "error_message": msg}
        _li_result["truncated"]["error_message"] = msg_trunc
```

(d) Update `render_wrapper` (line 480) signature and substitution. Add `allow_write: bool = False` after `caps`, and add the `ALLOW_WRITE_SETUP` substitution. Define the two block strings as module constants near the templates:

```python
_ALLOW_WRITE_SETUP_GUARDED = (
    "    class _li_GuardedProgram(drgn.Program):\n"
    "        def write(self, *_li_a, **_li_k):\n"
    "            raise _li_WriteModeDisabled('allow_write is false; drgn write APIs are disabled')\n"
    "    _li_program_class = _li_GuardedProgram"
)
_ALLOW_WRITE_SETUP_PLAIN = "    _li_program_class = drgn.Program"


def _allow_write_setup(allow_write: bool) -> str:
    return _ALLOW_WRITE_SETUP_PLAIN if allow_write else _ALLOW_WRITE_SETUP_GUARDED
```

In `render_wrapper`'s `WRAPPER_TEMPLATE.substitute(...)` call add `ALLOW_WRITE_SETUP=_allow_write_setup(allow_write),`. In `render_wrapper_skeleton`'s `substitute(...)` add `ALLOW_WRITE_SETUP=_allow_write_setup(False),` (skeleton mirrors the default read-only render).

> `Template.substitute` raises `KeyError` on any unfilled placeholder, so both render functions MUST pass `ALLOW_WRITE_SETUP`. `render_vmcore_wrapper*` use `VMCORE_WRAPPER_TEMPLATE`, which has no `${ALLOW_WRITE_SETUP}` placeholder, so they are unchanged.

- [ ] **Step 4: Regenerate the golden template and run wrapper tests**

```bash
uv run python -c "from linux_debug_mcp.providers.local_drgn_introspect import WRAPPER_TEMPLATE; open('tests/golden/live_wrapper_template.txt','w').write(WRAPPER_TEMPLATE.template)"
uv run python -m pytest tests/test_introspect_wrapper.py tests/test_vmcore_wrapper.py -q
```
Expected: PASS — including `test_live_wrapper_template_byte_identical_after_split` (now matches the regenerated golden) and `test_vmcore_wrapper_shares_body_with_live` (the shared body, now with the sentinel, is still a substring of both templates).

- [ ] **Step 5: Commit**

```bash
git add src/linux_debug_mcp/providers/local_drgn_introspect.py tests/test_introspect_wrapper.py tests/golden/live_wrapper_template.txt
git commit -m "feat(introspect): drgn.Program-subclass write-guard in wrapper (#56)"
```

---

## Task 4: handler — write-mode gate, audit, manifest recording, finalize branch

**Files:**
- Modify: `src/linux_debug_mcp/server.py` — imports; `_execute_introspect_call` (gate ~2550, audit ~2760, render call ~2772, WrapperRenderError details ~2805, admission-fail record ~2951, finalize call ~2972); `_finalize_introspect_call` (~3012 signature, ~3178 new branch, ~3287 success details, `_fail` closure ~3054); `_record_introspect_failure` (~378 signature, ~434 details)
- Test: `tests/test_debug_introspect_run.py`

- [ ] **Step 1: Write failing handler tests**

In `tests/test_debug_introspect_run.py`, extend the `linux_debug_mcp.config` import to include `INTROSPECT_DESTRUCTIVE_PERMISSIONS`, and replace `test_allow_write_rejected` (lines 276-291) with the gated-behaviour tests plus the audit/recording tests:

```python
_WRITE_PERMS = ["mutate live kernel state via drgn write APIs"]


def test_allow_write_requires_profile_op(tmp_path: Path) -> None:
    _, run_id, _ = _bootstrap_run_with_build(tmp_path)
    targets, rootfs, _ = _profiles()
    # Profile enables run but NOT debug.introspect.write.
    profile = DebugProfile(
        name="qemu-gdbstub-default",
        enabled_operations=["debug.introspect.run"],
    )
    response = debug_introspect_run_handler(
        _make_request(run_id, allow_write=True, acknowledged_permissions=_WRITE_PERMS),
        artifact_root=tmp_path,
        target_profiles=targets,
        rootfs_profiles=rootfs,
        debug_profiles={"qemu-gdbstub-default": profile},
        ssh_runner=FakeSshRunner(),
        admission=FakeAdmissionService(snapshot=_make_snapshot(run_id)),
        session_registry=FakeSessionRegistry(),
    )
    assert response.ok is False
    assert response.error.details["code"] == "operation_disabled"


def test_allow_write_requires_ack(tmp_path: Path) -> None:
    _, run_id, _ = _bootstrap_run_with_build(tmp_path)
    targets, rootfs, debug = _profiles()
    response = debug_introspect_run_handler(
        _make_request(run_id, allow_write=True, acknowledged_permissions=[]),
        artifact_root=tmp_path,
        target_profiles=targets,
        rootfs_profiles=rootfs,
        debug_profiles=debug,
        ssh_runner=FakeSshRunner(),
        admission=FakeAdmissionService(snapshot=_make_snapshot(run_id)),
        session_registry=FakeSessionRegistry(),
    )
    assert response.ok is False
    assert response.error.details["code"] == "permission_required"
    assert response.error.details["required_permissions"] == _WRITE_PERMS


def test_allow_write_admitted_records_flag_and_perms(tmp_path: Path) -> None:
    store, run_id, _ = _bootstrap_run_with_build(tmp_path)
    targets, rootfs, debug = _profiles()
    ssh = FakeSshRunner(results=[_happy_ssh_result()])
    response = debug_introspect_run_handler(
        _make_request(run_id, allow_write=True, acknowledged_permissions=[*_WRITE_PERMS, "extra"]),
        artifact_root=tmp_path,
        target_profiles=targets,
        rootfs_profiles=rootfs,
        debug_profiles=debug,
        ssh_runner=ssh,
        admission=FakeAdmissionService(snapshot=_make_snapshot(run_id)),
        session_registry=FakeSessionRegistry(),
    )
    assert response.ok is True
    manifest = store.load_manifest(run_id)
    step = next(v for k, v in manifest.step_results.items() if k.startswith("introspect:"))
    assert step.details["allow_write"] is True
    # Only the satisfied required perms are recorded, not the caller's "extra".
    assert step.details["acknowledged_permissions"] == _WRITE_PERMS


def test_read_only_call_skips_gates_and_ignores_ack(tmp_path: Path) -> None:
    store, run_id, _ = _bootstrap_run_with_build(tmp_path)
    targets, rootfs, _ = _profiles()
    # Profile lacks debug.introspect.write; a read-only call must still succeed.
    profile = DebugProfile(
        name="qemu-gdbstub-default",
        enabled_operations=["debug.introspect.run"],
    )
    ssh = FakeSshRunner(results=[_happy_ssh_result()])
    response = debug_introspect_run_handler(
        _make_request(run_id, allow_write=False, acknowledged_permissions=["ignored"]),
        artifact_root=tmp_path,
        target_profiles=targets,
        rootfs_profiles=rootfs,
        debug_profiles={"qemu-gdbstub-default": profile},
        ssh_runner=ssh,
        admission=FakeAdmissionService(snapshot=_make_snapshot(run_id)),
        session_registry=FakeSessionRegistry(),
    )
    assert response.ok is True
    manifest = store.load_manifest(run_id)
    step = next(v for k, v in manifest.step_results.items() if k.startswith("introspect:"))
    assert step.details["allow_write"] is False
    assert "acknowledged_permissions" not in step.details


def test_write_mode_audit_log_line(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    _, run_id, _ = _bootstrap_run_with_build(tmp_path)
    targets, rootfs, debug = _profiles()
    ssh = FakeSshRunner(results=[_happy_ssh_result()])
    with caplog.at_level("WARNING"):
        debug_introspect_run_handler(
            _make_request(run_id, allow_write=True, acknowledged_permissions=_WRITE_PERMS),
            artifact_root=tmp_path,
            target_profiles=targets,
            rootfs_profiles=rootfs,
            debug_profiles=debug,
            ssh_runner=ssh,
            admission=FakeAdmissionService(snapshot=_make_snapshot(run_id)),
            session_registry=FakeSessionRegistry(),
        )
    audit_lines = [r for r in caplog.records if "write-mode invocation" in r.getMessage()]
    assert len(audit_lines) == 1


def test_read_only_call_emits_no_audit_line(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    _, run_id, _ = _bootstrap_run_with_build(tmp_path)
    targets, rootfs, debug = _profiles()
    ssh = FakeSshRunner(results=[_happy_ssh_result()])
    with caplog.at_level("WARNING"):
        debug_introspect_run_handler(
            _make_request(run_id),
            artifact_root=tmp_path,
            target_profiles=targets,
            rootfs_profiles=rootfs,
            debug_profiles=debug,
            ssh_runner=ssh,
            admission=FakeAdmissionService(snapshot=_make_snapshot(run_id)),
            session_registry=FakeSessionRegistry(),
        )
    assert not [r for r in caplog.records if "write-mode invocation" in r.getMessage()]


def test_allow_write_failed_call_records_flag_via_failure_recorder(tmp_path: Path) -> None:
    store, run_id, _ = _bootstrap_run_with_build(tmp_path)
    targets, rootfs, debug = _profiles()
    # A drgn_open_failure outcome routes through _fail -> _record_introspect_failure
    # (a genuinely FAILED step), exercising the failure recorder's allow_write path.
    # NB: outcome.status="error" would NOT work here — it is the SUCCESS path
    # (status="script_error", SUCCEEDED step) and never reaches _record_introspect_failure.
    body = {
        "call_id": "0" * 32,
        "build_id": None,
        "outcome": {"status": "drgn_open_failure", "error_type": "OSError", "error_message": "x"},
        "emits": [],
        "user_stdout": "",
        "prelude_ms": 1,
        "truncated": {k: False for k in ("emits", "user_stdout", "traceback", "total_json", "per_emit_size", "error_message")},
    }
    ssh = FakeSshRunner(results=[SshCommandResult(exit_status=3, stdout=json.dumps(body), stderr="")])
    debug_introspect_run_handler(
        _make_request(run_id, allow_write=True, acknowledged_permissions=_WRITE_PERMS),
        artifact_root=tmp_path,
        target_profiles=targets,
        rootfs_profiles=rootfs,
        debug_profiles=debug,
        ssh_runner=ssh,
        admission=FakeAdmissionService(snapshot=_make_snapshot(run_id)),
        session_registry=FakeSessionRegistry(),
    )
    manifest = store.load_manifest(run_id)
    step = next(v for k, v in manifest.step_results.items() if k.startswith("introspect:"))
    assert step.status == StepStatus.FAILED
    assert step.details["allow_write"] is True
    assert step.details["acknowledged_permissions"] == _WRITE_PERMS


def test_write_mode_disabled_outcome_rejected(tmp_path: Path) -> None:
    store, run_id, _ = _bootstrap_run_with_build(tmp_path)
    targets, rootfs, debug = _profiles()
    body = {
        "call_id": "0" * 32,
        "build_id": VALID_BUILD_ID,
        "outcome": {"status": "write_mode_disabled", "error_message": "blocked"},
        "emits": [],
        "user_stdout": "",
        "prelude_ms": 1,
        "truncated": {k: False for k in ("emits", "user_stdout", "traceback", "total_json", "per_emit_size", "error_message")},
    }
    ssh = FakeSshRunner(results=[SshCommandResult(exit_status=6, stdout=json.dumps(body), stderr="")])
    response = debug_introspect_run_handler(
        _make_request(run_id),
        artifact_root=tmp_path,
        target_profiles=targets,
        rootfs_profiles=rootfs,
        debug_profiles=debug,
        ssh_runner=ssh,
        admission=FakeAdmissionService(snapshot=_make_snapshot(run_id)),
        session_registry=FakeSessionRegistry(),
    )
    assert response.ok is False
    assert response.error.category == ErrorCategory.CONFIGURATION_ERROR
    assert response.error.details["code"] == "write_mode_disabled"
    manifest = store.load_manifest(run_id)
    step = next(v for k, v in manifest.step_results.items() if k.startswith("introspect:"))
    assert step.status == StepStatus.FAILED
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run python -m pytest tests/test_debug_introspect_run.py -q`
Expected: FAIL — old `allow_write_not_supported` path gone; new gate/branch/recording not implemented.

- [ ] **Step 3: Implement the gate + audit + recording**

In `src/linux_debug_mcp/server.py`:

(a) Extend the `linux_debug_mcp.config` import (near line 25/40) to add `INTROSPECT_DESTRUCTIVE_PERMISSIONS`.

(b) Replace the `allow_write` reject block (lines 2549-2556) with the two-factor gate:

```python
    # Spec §5.2 step 3 / ADR 0011: write-mode policy gate (live path only).
    if request.allow_write:
        try:
            _ensure_debug_operation_enabled(resolved_debug, "debug.introspect.write")
        except ProviderDebugError as exc:
            return ToolResponse.failure(
                category=exc.category,
                message=str(exc),
                run_id=run_id,
                details={**exc.details, "code": "operation_disabled"},
            )
        missing = missing_destructive_permissions(
            operation_name,
            request.acknowledged_permissions,
            registry=INTROSPECT_DESTRUCTIVE_PERMISSIONS,
        )
        if missing:
            return ToolResponse.failure(
                category=ErrorCategory.CONFIGURATION_ERROR,
                run_id=run_id,
                message=(
                    "debug.introspect.run write mode is destructive; "
                    "acknowledge its required permissions to proceed"
                ),
                details={"code": "permission_required", "required_permissions": missing},
            )
    # The satisfied required permissions for audit/recording (gate guarantees all are acked).
    write_mode_permissions = (
        list(INTROSPECT_DESTRUCTIVE_PERMISSIONS.get(operation_name, [])) if request.allow_write else []
    )
```

(c) Immediately after the call_id mkdir block (after line 2768, before `args_json = _introspect_args_json(request)`), emit the audit line:

```python
        if request.allow_write:
            logger.warning(
                "audit: %s write-mode invocation run_id=%s call_id=%s permissions=%s",
                operation_name,
                run_id,
                call_id,
                write_mode_permissions,
            )
```

(d) Thread `allow_write` into the `render_wrapper` call (line 2772) — add `allow_write=request.allow_write,`.

(e) In the `WrapperRenderError` `StepResult.details` (line 2805-2813) add:

```python
                    "allow_write": request.allow_write,
```

(f) In the admission-complete-failure `_record_introspect_failure` call (line 2951) add:

```python
                allow_write=request.allow_write,
                acknowledged_permissions=write_mode_permissions,
```

(g) In the live `_finalize_introspect_call` call (line 2972) add:

```python
            allow_write=request.allow_write,
            acknowledged_permissions=write_mode_permissions,
```

(h) `_record_introspect_failure` (line 378): add params and details. Add to the signature after `redacted_payload`:

```python
    allow_write: bool = False,
    acknowledged_permissions: list[str] | None = None,
```

After the `details` dict is built (after line 441) add:

```python
    details["allow_write"] = allow_write
    if allow_write:
        details["acknowledged_permissions"] = list(acknowledged_permissions or [])
```

(i) `_finalize_introspect_call` (line 3012): add the same two params to the signature (after `post_validator`). In the `_fail` inner closure (line 3054), forward them to `_record_introspect_failure`:

```python
            allow_write=allow_write,
            acknowledged_permissions=acknowledged_permissions,
```

In the success `step_details` dict (after line 3296, `"outcome_status": outcome_status,`) add:

```python
        "allow_write": allow_write,
```

and after the `exec_principal` block (after line 3300) add:

```python
    if allow_write:
        step_details["acknowledged_permissions"] = list(acknowledged_permissions or [])
```

(j) Add the `write_mode_disabled` discrimination branch among the outcome branches (after the `script_compile_error` branch, before line 3187 `wrapper_internal_error`):

```python
    if outcome_status == "write_mode_disabled":
        return _fail(
            category=ErrorCategory.CONFIGURATION_ERROR,
            code="write_mode_disabled",
            message="script attempted a drgn write API but allow_write is false",
            outcome_status_for_forensics=outcome_status,
            include_stdout_json=True,
            redacted_payload=rp,
        )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run python -m pytest tests/test_debug_introspect_run.py -q`
Expected: PASS (all new tests + the unchanged matrix).

- [ ] **Step 5: Commit**

```bash
git add src/linux_debug_mcp/server.py tests/test_debug_introspect_run.py
git commit -m "feat(introspect): write-mode gate, audit, manifest recording (#56)"
```

---

## Task 5: vmcore — reclassify `allow_write` reject as not-applicable

**Files:**
- Modify: `src/linux_debug_mcp/server.py:3556-3562` (`_execute_vmcore_introspect_call`)
- Test: `tests/test_debug_introspect_from_vmcore.py:227-232`

- [ ] **Step 1: Update the failing test**

Replace `test_allow_write_rejected` in `tests/test_debug_introspect_from_vmcore.py` (lines 227-232):

```python
def test_allow_write_not_applicable(tmp_path: Path) -> None:
    _run(tmp_path)
    resp = debug_introspect_from_vmcore_handler(
        _req(allow_write=True), artifact_root=tmp_path, runner=FakeRunner(), build_id_reader=lambda p: VALID
    )
    assert resp.error.category == ErrorCategory.CONFIGURATION_ERROR
    assert resp.error.details["code"] == "write_mode_not_applicable"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run python -m pytest tests/test_debug_introspect_from_vmcore.py::test_allow_write_not_applicable -q`
Expected: FAIL — code is still `allow_write_not_supported`.

- [ ] **Step 3: Implement the reclassification**

In `src/linux_debug_mcp/server.py`, replace the vmcore `allow_write` reject (lines 3556-3562):

```python
    if request.allow_write:
        return ToolResponse.failure(
            category=ErrorCategory.CONFIGURATION_ERROR,
            run_id=run_id,
            message=(
                "write mode is not applicable to offline vmcore analysis; "
                "the core file is immutable"
            ),
            details={"code": "write_mode_not_applicable"},
        )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run python -m pytest tests/test_debug_introspect_from_vmcore.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/linux_debug_mcp/server.py tests/test_debug_introspect_from_vmcore.py
git commit -m "feat(introspect): vmcore allow_write is not-applicable, not unsupported (#56)"
```

---

## Task 6: MCP tool — expose `acknowledged_permissions`

**Files:**
- Modify: `src/linux_debug_mcp/server.py:6195-6222` (`debug.introspect.run` tool)
- Test: `tests/test_debug_introspect_run.py`

- [ ] **Step 1: Write failing test**

Add to `tests/test_debug_introspect_run.py` (import `create_app` if not already; otherwise assert via the tool signature):

```python
def test_run_tool_exposes_acknowledged_permissions() -> None:
    import inspect

    from linux_debug_mcp.server import create_app

    app = create_app()
    tool = app._tool_manager._tools["debug.introspect.run"]
    params = inspect.signature(tool.fn).parameters
    assert "acknowledged_permissions" in params
```

> If `app._tool_manager._tools` differs in this FastMCP version, inspect `create_app` for the registry accessor and adjust; the assertion is that the registered `debug.introspect.run` callable accepts `acknowledged_permissions`.

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run python -m pytest tests/test_debug_introspect_run.py::test_run_tool_exposes_acknowledged_permissions -q`
Expected: FAIL — parameter absent.

- [ ] **Step 3: Implement the tool param**

In `src/linux_debug_mcp/server.py`, add to the `debug_introspect_run` tool signature (after `allow_write: bool = False,` line 6202):

```python
        acknowledged_permissions: list[str] | None = None,
```

and pass it into the request (after `allow_write=allow_write,` line 6212):

```python
            acknowledged_permissions=acknowledged_permissions or [],
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run python -m pytest tests/test_debug_introspect_run.py::test_run_tool_exposes_acknowledged_permissions -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/linux_debug_mcp/server.py tests/test_debug_introspect_run.py
git commit -m "feat(introspect): expose acknowledged_permissions on the MCP run tool (#56)"
```

---

## Task 7: env-gated live integration coverage (kept gated)

**Files:**
- Modify: `tests/test_drgn_introspect_integration.py`

These mirror `test_introspect_emit_roundtrip` (lines 226-245) exactly: `_require_integration_env()` first (keeps them gated), `_bootstrap_booted_run(tmp_path)` for the context, `target_ref="pilot-libvirt"`, `artifact_root=tmp_path / "runs"`. The default debug profile (unset) already enables `debug.introspect.write`, so the `allow_write=True` call passes the gate on the ack alone.

- [ ] **Step 1: Add the two gated tests**

Append to `tests/test_drgn_introspect_integration.py`:

```python
_WRITE_PERM = "mutate live kernel state via drgn write APIs"


def test_introspect_allow_write_false_blocks_prog_write(tmp_path) -> None:
    _require_integration_env()
    ctx = _bootstrap_booted_run(tmp_path)
    request = DebugIntrospectRunRequest(
        run_id=ctx.run_id,
        target_ref="pilot-libvirt",
        script='prog.write(0, b"\\x00")',
        timeout_seconds=30,
        allow_write=False,
    )
    response = debug_introspect_run_handler(
        request,
        artifact_root=tmp_path / "runs",
        target_profiles=ctx.target_profiles,
        rootfs_profiles=ctx.rootfs_profiles,
        admission=ctx.admission,
        session_registry=ctx.session_registry,
    )
    assert response.ok is False
    assert response.error.category == ErrorCategory.CONFIGURATION_ERROR
    assert response.error.details["code"] == "write_mode_disabled"


def test_introspect_allow_write_true_reaches_drgn(tmp_path) -> None:
    _require_integration_env()
    ctx = _bootstrap_booted_run(tmp_path)
    request = DebugIntrospectRunRequest(
        run_id=ctx.run_id,
        target_ref="pilot-libvirt",
        script='prog.write(0, b"\\x00"); emit({"reached": True})',
        timeout_seconds=30,
        allow_write=True,
        acknowledged_permissions=[_WRITE_PERM],
    )
    response = debug_introspect_run_handler(
        request,
        artifact_root=tmp_path / "runs",
        target_profiles=ctx.target_profiles,
        rootfs_profiles=ctx.rootfs_profiles,
        admission=ctx.admission,
        session_registry=ctx.session_registry,
    )
    # Under write mode the guard is absent, so prog.write reaches drgn, which
    # fails on today's read-only live target (no writable target exists yet).
    # The contract being asserted: the call is NOT rejected as
    # write_mode_disabled — proving the guard is not installed under write mode.
    # A drgn-level write failure surfaces as a script `error` outcome (ok=True
    # response, outcome.status="error"), not write_mode_disabled.
    if response.ok:
        assert response.data["status"] in {"ok", "script_error"}
    else:
        assert response.error.details.get("code") != "write_mode_disabled"
```

> Do NOT remove or weaken `_require_integration_env()` (CLAUDE.md: keep integration tests gated).

- [ ] **Step 2: Verify the tests skip without drgn/target**

Run: `uv run python -m pytest tests/test_drgn_introspect_integration.py -q`
Expected: SKIPPED (no drgn / no live target on this host or in CI).

- [ ] **Step 3: Commit**

```bash
git add tests/test_drgn_introspect_integration.py
git commit -m "test(introspect): env-gated write-mode round trips (#56)"
```

---

## Task 8: full guardrails sweep

- [ ] **Step 1: Run the complete suite + linters + types**

```bash
uv run ruff check && uv run ruff format && uv run ty check src && uv run python -m pytest -q
```
Expected: all green, zero warnings. Fix any fallout (e.g. other tests that asserted `allow_write_not_supported`, or `providers.list`/capability snapshots affected by the new op) before proceeding.

- [ ] **Step 2: Commit any fixups**

```bash
git add -A
git commit -m "chore(introspect): guardrail fixups for write-mode (#56)"
```

---

## Self-review notes

- **Spec coverage:** §2 gate → Task 4(b); §3.1 request field → Task 2; §3.2 failure codes → Tasks 4/5; §4 vmcore → Task 5; §5 config → Task 1; §6 wrapper subclass guard + ordering + finalize branch → Tasks 3 & 4(j); §7 audit (both paths + log) → Task 4(c,e,f,g,h,i); §8 tests → Tasks 1-7; §9 risks → covered by Task 7 gated tests + Task 3/4 unit tests.
- **Two regression anchors (review-surfaced):** `test_write_mode_disabled_outcome_rejected` (silent-success default) and `test_allow_write_failed_call_records_flag_via_failure_recorder` (failure-path recording — uses a `drgn_open_failure` outcome that genuinely routes through `_record_introspect_failure`, since `outcome.status="error"` is the success path) are both in Task 4.
- **Naming consistency:** `_li_program_class`, `_li_GuardedProgram`, `_li_WriteModeDisabled`, `write_mode_permissions`, code `write_mode_disabled` / `write_mode_not_applicable` / `permission_required` / `operation_disabled` are used identically across tasks.
