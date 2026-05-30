# gdb/MI Phase B — vmlinux symbol resolution + provenance lock Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prove the gdb/MI engine's loaded `vmlinux` symbols resolve by name (`linux_banner`), surfaced as typed JSON in the attach probe, and add MI-path test evidence that the merged #70 provenance gate blocks before the MI engine attaches.

**Architecture:** Phase A already loads symbols (`-file-exec-and-symbols`) and #70 already verifies `KernelProvenance.build_id` pre-attach in `debug_start_session_handler`. This change adds one engine method — `GdbMiEngine.resolve_symbol`, issuing `-data-evaluate-expression "&<name>"` for a name validated to a bare C identifier — and calls it for the fixed canonical symbol `linux_banner` inside the existing `_run_mi_attach_probe`, between the `^connected` proof and resume/detach. A resolution fault rides the unchanged guaranteed-resume teardown. No new agent-facing operation; ADR [0020](../../adr/0020-gdb-mi-symbol-resolution-mechanism.md).

**Tech Stack:** Python 3.11+, pydantic (`Model`/`extra="forbid"`), pygdbmi, pytest. Lint `uv run ruff check` / `ruff format`; types `uv run ty check src`; tests `uv run python -m pytest -q`.

---

## File Structure

- `src/linux_debug_mcp/providers/gdb_mi.py` — add `ResolvedSymbol` model, `CANONICAL_PROBE_SYMBOL` constant, `_SYMBOL_NAME_RE`, `GdbMiEngine.resolve_symbol`; change the private `_run` to return the records it parsed (callers that ignore the value are unaffected).
- `src/linux_debug_mcp/server.py` — in `_run_mi_attach_probe`, resolve `CANONICAL_PROBE_SYMBOL` after `probe_read` and before `resume_and_detach`, merging the redacted typed result under `mi_probe.symbol`.
- `tests/test_gdb_mi_engine.py` — unit tests for `resolve_symbol` (success, bad-name reject, `^error`, missing-value).
- `tests/test_server_debug_mi_probe.py` — extend `FakeEngine` with `resolve_symbol` + `fail_on="resolve"`; add probe-surfaces-symbol, resolve-fault-resumes, and provenance-mismatch-blocks-MI-attach tests.
- `tests/test_gdb_mi_integration.py` — extend the gated live test to assert the probe surfaced `mi_probe.symbol` and to drive `engine.resolve_symbol` directly.

---

## Task 1: `ResolvedSymbol` model + name validator + `_run` returns records

**Files:**
- Modify: `src/linux_debug_mcp/providers/gdb_mi.py`
- Test: `tests/test_gdb_mi_engine.py`

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_gdb_mi_engine.py` (the `FakeController`, `_engine`, `_endpoint`, `_ATTACH_OK`, `_DONE` helpers already exist):

```python
from linux_debug_mcp.providers.gdb_mi import CANONICAL_PROBE_SYMBOL, ResolvedSymbol


# A -data-evaluate-expression "&linux_banner" success: ^done with a value field.
_EVAL_OK: list[dict[str, object]] = [
    {"type": "result", "message": "done", "payload": {"value": "0x1234 <linux_banner>"}, "token": None}
]


def test_resolve_symbol_returns_typed_value(tmp_path: Path) -> None:
    vmlinux = tmp_path / "vmlinux"
    vmlinux.write_text("elf", encoding="utf-8")
    controller = FakeController([*_ATTACH_OK, _EVAL_OK])
    engine = _engine(controller)
    attachment = engine.attach(rsp_endpoint=_endpoint(), vmlinux_path=vmlinux, transcript_path=tmp_path / "mi.log")
    resolved = engine.resolve_symbol(attachment, CANONICAL_PROBE_SYMBOL)
    assert isinstance(resolved, ResolvedSymbol)
    assert resolved.name == CANONICAL_PROBE_SYMBOL
    assert resolved.value == "0x1234 <linux_banner>"
    # the address-of a bare identifier is sent, quoted, as a single MI argument
    assert controller.commands[-1] == '-data-evaluate-expression "&linux_banner"'


def test_resolve_symbol_rejects_non_identifier_name_without_touching_gdb(tmp_path: Path) -> None:
    vmlinux = tmp_path / "vmlinux"
    vmlinux.write_text("elf", encoding="utf-8")
    controller = FakeController(list(_ATTACH_OK))  # no eval response scripted
    engine = _engine(controller)
    attachment = engine.attach(rsp_endpoint=_endpoint(), vmlinux_path=vmlinux, transcript_path=tmp_path / "mi.log")
    commands_before = list(controller.commands)
    with pytest.raises(GdbMiError) as exc:
        engine.resolve_symbol(attachment, "linux_banner; call system")
    assert exc.value.category == ErrorCategory.CONFIGURATION_ERROR
    assert controller.commands == commands_before  # gdb was never asked


def test_resolve_symbol_raises_debug_attach_failure_on_error_record(tmp_path: Path) -> None:
    vmlinux = tmp_path / "vmlinux"
    vmlinux.write_text("elf", encoding="utf-8")
    error = [{"type": "result", "message": "error", "payload": {"msg": "No symbol \"linux_banner\""}, "token": None}]
    controller = FakeController([*_ATTACH_OK, error])
    engine = _engine(controller)
    attachment = engine.attach(rsp_endpoint=_endpoint(), vmlinux_path=vmlinux, transcript_path=tmp_path / "mi.log")
    with pytest.raises(GdbMiError) as exc:
        engine.resolve_symbol(attachment, CANONICAL_PROBE_SYMBOL)
    assert exc.value.category == ErrorCategory.DEBUG_ATTACH_FAILURE


def test_resolve_symbol_raises_when_done_has_no_value(tmp_path: Path) -> None:
    vmlinux = tmp_path / "vmlinux"
    vmlinux.write_text("elf", encoding="utf-8")
    no_value = [{"type": "result", "message": "done", "payload": None, "token": None}]
    controller = FakeController([*_ATTACH_OK, no_value])
    engine = _engine(controller)
    attachment = engine.attach(rsp_endpoint=_endpoint(), vmlinux_path=vmlinux, transcript_path=tmp_path / "mi.log")
    with pytest.raises(GdbMiError) as exc:
        engine.resolve_symbol(attachment, CANONICAL_PROBE_SYMBOL)
    assert exc.value.category == ErrorCategory.DEBUG_ATTACH_FAILURE
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run python -m pytest tests/test_gdb_mi_engine.py -q -k resolve_symbol`
Expected: FAIL — `ImportError: cannot import name 'CANONICAL_PROBE_SYMBOL'` / `ResolvedSymbol`.

- [ ] **Step 3: Add the model, constant, regex, and validator**

In `src/linux_debug_mcp/providers/gdb_mi.py`, after the `import re`-needs and near the top constants add `import re` to the imports (it is not yet imported) and below `_KNOWN_KEYS`:

```python
# A bare C identifier. The name-shape gate (ADR 0020 decision 2) keeps resolve_symbol's
# `-data-evaluate-expression "&<name>"` an address-of-a-name, never an arbitrary expression.
_SYMBOL_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
# The fixed canonical symbol the Phase-B attach probe resolves: present in every kernel image
# (the /proc/version string), so it needs no kernel-config gating (ADR 0020 decision 3).
CANONICAL_PROBE_SYMBOL = "linux_banner"
```

Add the model after `MiRecord` (before `parse_mi_records`):

```python
class ResolvedSymbol(Model):
    """One name->address resolution via gdb/MI ``-data-evaluate-expression "&<name>"``. ``value`` is
    the gdb-rendered link-time address string (e.g. ``"0x... <linux_banner>"``) stored verbatim --
    proof the symbol resolves in the loaded symbol table, NOT the relocated runtime address
    (ADR 0020). Frozen wire shape (``Model`` => extra="forbid")."""

    name: str
    value: str
```

- [ ] **Step 4: Change `_run` to return the records it parsed**

In `src/linux_debug_mcp/providers/gdb_mi.py`, change the `_run` signature and add a return; existing callers in `attach()` ignore the value, so they are unaffected:

```python
    def _run(self, attachment: GdbMiAttachment, command: str) -> list[MiRecord]:
        records = self._records_from(attachment.controller.write(command, timeout_sec=_MI_COMMAND_TIMEOUT_SEC))
        attachment.records.extend(records)
        self._append_transcript(attachment.transcript_path, command, records)
        result = MiRecord.first_result(records)
        if result is not None and result.message == "error":
            raise GdbMiError(
                f"gdb/MI command failed: {command}",
                category=ErrorCategory.DEBUG_ATTACH_FAILURE,
                details={"command": command, "payload": self._redactor.redact_value(result.payload)},
            )
        return records
```

- [ ] **Step 5: Implement `resolve_symbol`**

Add this method to `GdbMiEngine`, placed after `probe_read`:

```python
    def resolve_symbol(self, attachment: GdbMiAttachment, symbol_name: str) -> ResolvedSymbol:
        """Resolve *symbol_name* to its address via ``-data-evaluate-expression "&<name>"`` and return
        the typed result (ADR 0020). *symbol_name* must be a bare C identifier; anything else is a
        CONFIGURATION_ERROR raised before gdb is touched. An MI ``^error`` (symbol absent / not loaded)
        or a ``^done`` with no ``value`` is a DEBUG_ATTACH_FAILURE -- symbols were supposed to be
        loaded, so an unresolvable canonical symbol is an attach-level failure, not a soft miss."""
        if not _SYMBOL_NAME_RE.match(symbol_name):
            raise GdbMiError(
                f"symbol name must be a bare C identifier, got {symbol_name!r}",
                category=ErrorCategory.CONFIGURATION_ERROR,
                details={"symbol": symbol_name},
            )
        records = self._run(attachment, f'-data-evaluate-expression "&{symbol_name}"')
        result = MiRecord.first_result(records)
        value = result.payload.get("value") if result is not None and isinstance(result.payload, dict) else None
        if not isinstance(value, str):
            raise GdbMiError(
                f"gdb/MI returned no value resolving symbol {symbol_name!r}",
                category=ErrorCategory.DEBUG_ATTACH_FAILURE,
                details={"symbol": symbol_name},
            )
        return ResolvedSymbol(name=symbol_name, value=value)
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `uv run python -m pytest tests/test_gdb_mi_engine.py -q`
Expected: PASS (all, including the pre-existing attach/probe/resume tests — `_run`'s new return value does not change their behavior).

- [ ] **Step 7: Lint, format, type-check**

Run: `uv run ruff check src tests && uv run ruff format src tests && uv run ty check src`
Expected: no errors.

- [ ] **Step 8: Commit**

```bash
git add src/linux_debug_mcp/providers/gdb_mi.py tests/test_gdb_mi_engine.py
git commit -m "feat(gdb-mi): resolve a symbol by name via -data-evaluate-expression"
```

---

## Task 2: Probe resolves `linux_banner` and surfaces it under `mi_probe.symbol`

**Files:**
- Modify: `src/linux_debug_mcp/server.py` (`_run_mi_attach_probe`, ~`server.py:4076-4089`; import)
- Test: `tests/test_server_debug_mi_probe.py`

- [ ] **Step 1: Extend `FakeEngine` and write the failing tests**

In `tests/test_server_debug_mi_probe.py`, replace the `FakeEngine` class so it also models `resolve_symbol` and a `"resolve"` fault, and import the model + constant. Add `from linux_debug_mcp.providers.gdb_mi import CANONICAL_PROBE_SYMBOL, GdbMiError, MiRecord, ResolvedSymbol` (extend the existing import line). Replace the class body:

```python
class FakeEngine:
    """A GdbMiEngine-shaped fake. ``fail_on`` selects which step raises (``attach``/``probe``/``resolve``
    raise GdbMiError; ``probe_crash`` raises an unwrapped RuntimeError)."""

    def __init__(self, *, fail_on: str | None = None, resume_confirmed: bool = True) -> None:
        self.fail_on = fail_on
        self._resume_confirmed = resume_confirmed
        self.attached = False
        self.resolved: str | None = None
        self.resumed = False
        self.forced = False

    def attach(self, *, rsp_endpoint, vmlinux_path, transcript_path):
        if self.fail_on == "attach":
            raise GdbMiError("attach blew up", category=ErrorCategory.DEBUG_ATTACH_FAILURE)
        self.attached = True
        return object()  # opaque attachment handle

    def probe_read(self, attachment) -> MiRecord:
        if self.fail_on == "probe":
            raise GdbMiError("rsp timeout", category=ErrorCategory.DEBUG_ATTACH_FAILURE)
        if self.fail_on == "probe_crash":
            raise RuntimeError("unexpected non-GdbMiError engine crash")  # an unwrapped tool exception
        return MiRecord(type="result", message="connected", payload=None)  # the ^connected attach proof

    def resolve_symbol(self, attachment, symbol_name: str) -> ResolvedSymbol:
        if self.fail_on == "resolve":
            raise GdbMiError("no such symbol", category=ErrorCategory.DEBUG_ATTACH_FAILURE)
        self.resolved = symbol_name
        return ResolvedSymbol(name=symbol_name, value="0x1234 <linux_banner>")

    def resume_and_detach(self, attachment) -> bool:
        self.resumed = True
        return True

    def force_resume(self, attachment) -> bool:
        self.forced = True
        return self._resume_confirmed
```

Add these tests:

```python
def test_probe_surfaces_resolved_symbol(tmp_path: Path) -> None:
    artifact_root = _create_debug_ready_run(tmp_path)
    registry = _make_registry(tmp_path / "reg")
    txn, admission = _build_transaction(registry=registry)
    engine = FakeEngine()
    resp = debug_start_session_handler(
        artifact_root=artifact_root,
        run_id=RUN_ID,
        provider=FakeDebugProvider(),
        debug_profiles=_profiles(),
        transaction=txn,
        admission=admission,
        session_registry=registry,
        gdb_mi_engine=engine,
    )
    assert resp.ok is True
    assert engine.resolved == CANONICAL_PROBE_SYMBOL
    # AC2: the probe surfaced a typed name->address resolution.
    assert resp.data["mi_probe"]["symbol"]["name"] == CANONICAL_PROBE_SYMBOL
    assert resp.data["mi_probe"]["symbol"]["value"] == "0x1234 <linux_banner>"


def test_resolve_fault_resumes_and_frees_guard(tmp_path: Path) -> None:
    artifact_root = _create_debug_ready_run(tmp_path)
    registry = _make_registry(tmp_path / "reg")
    txn, admission = _build_transaction(registry=registry)
    engine = FakeEngine(fail_on="resolve", resume_confirmed=True)
    resp = debug_start_session_handler(
        artifact_root=artifact_root,
        run_id=RUN_ID,
        provider=FakeDebugProvider(),
        debug_profiles=_profiles(),
        transaction=txn,
        admission=admission,
        session_registry=registry,
        gdb_mi_engine=engine,
    )
    assert resp.ok is False
    assert resp.error.category == ErrorCategory.DEBUG_ATTACH_FAILURE
    # guaranteed resume + teardown: a resolution fault is the same fault path as a probe fault.
    assert engine.forced is True
    assert registry.read_record(KEY) is None
    assert registry.read_tombstone(KEY) is None
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run python -m pytest tests/test_server_debug_mi_probe.py -q -k "resolved_symbol or resolve_fault"`
Expected: FAIL — `KeyError: 'symbol'` in the success test (probe does not yet resolve), and the resolve-fault test sees `resp.ok is True` (no resolve step yet).

- [ ] **Step 3: Wire resolution into the probe**

In `src/linux_debug_mcp/server.py`, extend the import on line 95:

```python
from linux_debug_mcp.providers.gdb_mi import CANONICAL_PROBE_SYMBOL, GdbMiEngine, GdbMiError
```

In `_run_mi_attach_probe`, between the `probe_read` and `resume_and_detach` calls, resolve the canonical symbol and add it to the surfaced dict (replace the `record = ... return None, mi_probe` block):

```python
        attachment = engine.attach(
            rsp_endpoint=transport_session.rsp_endpoint, vmlinux_path=vmlinux_path, transcript_path=transcript_path
        )
        record = engine.probe_read(attachment)
        symbol = engine.resolve_symbol(attachment, CANONICAL_PROBE_SYMBOL)
        engine.resume_and_detach(attachment)
        mi_probe: dict[str, object] = {
            "mi_probe": redactor.redact_value(
                {
                    "record": record.model_dump(mode="json"),
                    "symbol": symbol.model_dump(mode="json"),
                    "transcript_path": str(transcript_path),
                }
            )
        }
        return None, mi_probe
```

(The broad `except Exception` below already covers a `resolve_symbol` fault: it runs `force_resume` + teardown and returns the failure — no new fault path is needed.)

- [ ] **Step 4: Run the tests to verify they pass**

Run: `uv run python -m pytest tests/test_server_debug_mi_probe.py -q`
Expected: PASS (new tests plus the pre-existing probe/guard/fault tests).

- [ ] **Step 5: Lint, format, type-check**

Run: `uv run ruff check src tests && uv run ruff format src tests && uv run ty check src`
Expected: no errors.

- [ ] **Step 6: Commit**

```bash
git add src/linux_debug_mcp/server.py tests/test_server_debug_mi_probe.py
git commit -m "feat(gdb-mi): probe resolves linux_banner and surfaces it as typed JSON"
```

---

## Task 3: MI-path evidence that the provenance gate blocks before `attach()`

**Files:**
- Test: `tests/test_server_debug_mi_probe.py`

- [ ] **Step 1: Write the failing tests**

The #70 gate (`_verify_gdb_symbol_version_lock`) runs before `transaction.open` and the probe, so a mismatch / missing provenance must abort with the MI engine's `attach()` never reached. Add to `tests/test_server_debug_mi_probe.py`:

```python
_OTHER_BUILD_ID = "ffffffffffffffffffffffffffffffffffffffff"  # pragma: allowlist secret


def test_provenance_mismatch_blocks_mi_attach(tmp_path: Path) -> None:
    artifact_root = _create_debug_ready_run(tmp_path)
    registry = _make_registry(tmp_path / "reg")
    txn, admission = _build_transaction(registry=registry)
    engine = FakeEngine()
    resp = debug_start_session_handler(
        artifact_root=artifact_root,
        run_id=RUN_ID,
        provider=FakeDebugProvider(),
        debug_profiles=_profiles(),
        transaction=txn,
        admission=admission,
        session_registry=registry,
        gdb_mi_engine=engine,
        build_id_reader=lambda _p: _OTHER_BUILD_ID,
    )
    assert resp.ok is False
    assert resp.error.category == ErrorCategory.CONFIGURATION_ERROR
    assert resp.error.details["code"] == "provenance_mismatch"
    # the gate fires before any acquisition or attach: the MI engine was never reached.
    assert engine.attached is False
    assert registry.read_record(KEY) is None


def test_missing_provenance_blocks_mi_attach(tmp_path: Path) -> None:
    artifact_root = _create_debug_ready_run(tmp_path)
    store = ArtifactStore(artifact_root, create_root=False)
    boot = store.load_manifest(RUN_ID).step_results["boot"]
    store.record_step_result(
        RUN_ID,
        StepResult(
            step_name="boot",
            status=StepStatus.SUCCEEDED,
            summary=boot.summary,
            details={k: v for k, v in boot.details.items() if k != "kernel_provenance"},
        ),
        replace_succeeded=True,
    )
    registry = _make_registry(tmp_path / "reg")
    txn, admission = _build_transaction(registry=registry)
    engine = FakeEngine()
    resp = debug_start_session_handler(
        artifact_root=artifact_root,
        run_id=RUN_ID,
        provider=FakeDebugProvider(),
        debug_profiles=_profiles(),
        transaction=txn,
        admission=admission,
        session_registry=registry,
        gdb_mi_engine=engine,
    )
    assert resp.ok is False
    assert resp.error.details["code"] == "provenance_missing"
    assert engine.attached is False
```

- [ ] **Step 2: Run the tests to verify they pass immediately**

Run: `uv run python -m pytest tests/test_server_debug_mi_probe.py -q -k "blocks_mi_attach"`
Expected: PASS. These tests assert pre-existing #70 behavior on the MI path (no new production code), so they pass on first run — this is the AC1/AC3 evidence for the MI engine. (If either fails, the #70 gate is not ordered before the probe and that is a real regression to fix, not a test bug.)

- [ ] **Step 3: Commit**

```bash
git add tests/test_server_debug_mi_probe.py
git commit -m "test(gdb-mi): provenance gate blocks before the MI engine attaches"
```

---

## Task 4: Extend the gated live integration test to assert symbol resolution

**Files:**
- Modify: `tests/test_gdb_mi_integration.py`

- [ ] **Step 1: Add the resolution assertions (gated — runs only with live env)**

In `tests/test_gdb_mi_integration.py`, extend the import and add assertions. Change the import line to:

```python
    from linux_debug_mcp.providers.gdb_mi import CANONICAL_PROBE_SYMBOL, GdbMiEngine, MiRecord
```

After the existing `assert debug_resp.data["mi_probe"]["record"]["message"] == "connected"` line, add:

```python
    # AC2: the wired probe resolved the canonical symbol by name against the loaded vmlinux symbols.
    assert debug_resp.data["mi_probe"]["symbol"]["name"] == CANONICAL_PROBE_SYMBOL
    assert debug_resp.data["mi_probe"]["symbol"]["value"]  # a non-empty gdb-rendered address string
```

After the existing direct-engine `mi_record = engine.probe_read(attachment)` / `assert ... == "connected"` block, add (before the resume timing block):

```python
    resolved = engine.resolve_symbol(attachment, CANONICAL_PROBE_SYMBOL)
    assert resolved.name == CANONICAL_PROBE_SYMBOL and resolved.value, "linux_banner must resolve by name"
```

- [ ] **Step 2: Verify the test still collects and skips cleanly without live env**

Run: `uv run python -m pytest tests/test_gdb_mi_integration.py -q`
Expected: 1 skipped (the live gate is unset locally) — the file must still import and collect.

- [ ] **Step 3: Commit**

```bash
git add tests/test_gdb_mi_integration.py
git commit -m "test(gdb-mi): assert live probe resolves linux_banner by name"
```

---

## Task 5: Full guardrail sweep

**Files:** none (verification only)

- [ ] **Step 1: Run the full suite**

Run: `uv run python -m pytest -q`
Expected: PASS (live gdbstub/libvirt/drgn integration tests skipped, as in CI).

- [ ] **Step 2: Lint, format-check, type-check, docs guard**

Run: `uv run ruff check src tests && uv run ruff format --check src tests && uv run ty check src && just check-docs`
Expected: all clean, zero warnings.

- [ ] **Step 3: Confirm no uncommitted changes remain**

Run: `git status --short`
Expected: empty.

---

## Self-Review

**Spec coverage (ADR 0020 + spec Phase B delta):**
- Decision 1 (`-data-evaluate-expression "&<name>"`, raw value, `^error`→DEBUG_ATTACH_FAILURE) → Task 1.
- Decision 2 (bare-identifier name gate → CONFIGURATION_ERROR before gdb) → Task 1.
- Decision 3 (fixed `linux_banner`, surfaced under `mi_probe.symbol`, redacted) → Task 2.
- Decision 4 (resolution fault rides the existing guaranteed-resume teardown) → Task 2 step 3 note + Task 2 resolve-fault test.
- AC1/AC3 (provenance gate blocks before MI attach) → Task 3.
- AC2 live evidence → Task 4.

**Placeholder scan:** none — every code/test step shows the actual content and exact command.

**Type consistency:** `ResolvedSymbol(name, value)`, `CANONICAL_PROBE_SYMBOL`, and `resolve_symbol(attachment, symbol_name)` are used identically in the engine, the probe, the unit tests, the handler tests, and the integration test. `_run` returns `list[MiRecord]` and `MiRecord.first_result` is the existing classmethod.
