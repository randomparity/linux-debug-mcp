# Wait-for-debugger frozen boot Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `wait_for_debugger` option that boots a `debug_gdbstub` target with QEMU gdbstub `wait=on`, freezing the vCPU at reset so `debug.start_session` attaches and sets breakpoints before early init, and `debug.continue` releases.

**Architecture:** A new `wait_for_debugger` flag on `TargetProfile` (overridable per-run via `BootOverrides`) flows into `BootPlan`; `render_domain_xml` selects `wait=on`/`wait=off` from it; `execute_boot` branches on it to skip the readiness wait and guest-IP discovery and return `SUCCEEDED`-frozen. The handler's existing `SUCCEEDED`-gated provenance capture + admission snapshot are reused unchanged, so `debug.start_session` works against a frozen boot with no debug-tier change.

**Tech Stack:** Python 3.11+, Pydantic v2 (`Model`/`ConfigModel`, `extra="forbid"`), pytest, libvirt/QEMU (`virsh`), gdb/MI engine. Spec: `docs/specs/2026-05-30-wait-for-debugger.md`. ADR: `docs/adr/0033-wait-for-debugger-frozen-boot.md`.

---

## File Structure

- `src/linux_debug_mcp/config.py` — `TargetProfile.wait_for_debugger` (+ model validator), `BootOverrides.wait_for_debugger`.
- `src/linux_debug_mcp/providers/libvirt_qemu.py` — `BootPlan.wait_for_debugger`, `plan_boot` (set field + cross-field validation), `render_domain_xml` (`wait=` token), `execute_boot` (frozen branch).
- `src/linux_debug_mcp/server.py` — `target_boot_handler` effective-`wait_for_debugger` merge, `has_new_boot_overrides`, frozen `suggested_next_actions`.
- Tests: `tests/test_config.py` (or the existing config-validation test module), `tests/test_libvirt_qemu_provider.py`, `tests/test_target_boot_handler.py`, `tests/test_qemu_gdbstub_integration.py` (gated).

---

## Task 1: `wait_for_debugger` config fields + model validator

**Files:**
- Modify: `src/linux_debug_mcp/config.py` (`TargetProfile` ~402-419, `BootOverrides` ~481-499)
- Test: `tests/test_config.py`

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_config.py`. `tests/test_config.py` does **not** currently import the config models, so add the imports at the top of the file:

```python
import pytest
from pydantic import ValidationError

from linux_debug_mcp.config import BootOverrides, TargetProfile
```

Then add the tests:

```python
def test_target_profile_wait_for_debugger_defaults_false() -> None:
    profile = TargetProfile(name="t", architecture="x86_64")
    assert profile.wait_for_debugger is False


def test_target_profile_wait_for_debugger_requires_debug_gdbstub() -> None:
    with pytest.raises(ValidationError, match="wait_for_debugger requires debug_gdbstub"):
        TargetProfile(name="t", architecture="x86_64", wait_for_debugger=True)


def test_target_profile_wait_for_debugger_accepts_with_gdbstub() -> None:
    profile = TargetProfile(
        name="t", architecture="x86_64", debug_gdbstub=True, wait_for_debugger=True
    )
    assert profile.wait_for_debugger is True


def test_boot_overrides_wait_for_debugger_is_tristate() -> None:
    assert BootOverrides().wait_for_debugger is None
    assert BootOverrides(wait_for_debugger=True).wait_for_debugger is True
    assert BootOverrides(wait_for_debugger=False).wait_for_debugger is False
```

- [ ] **Step 2: Run to verify they fail**

Run: `uv run python -m pytest tests/test_config.py -k wait_for_debugger -q`
Expected: FAIL (`wait_for_debugger` is not a field of `TargetProfile` → `ValidationError: extra fields not permitted`, and the model validator does not exist).

- [ ] **Step 3: Add the fields and validator**

In `config.py`, add to `TargetProfile` (after `gdbstub_endpoint: str = "127.0.0.1:1234"`, line ~411):

```python
    wait_for_debugger: bool = False
```

Add `model_validator` to the imports at the top (`from pydantic import BaseModel, ConfigDict, Field, ValidationInfo, field_validator, model_validator`), and add this method to `TargetProfile` (after the existing `validate_kernel_args` validator):

```python
    @model_validator(mode="after")
    def validate_wait_for_debugger(self) -> "TargetProfile":
        if self.wait_for_debugger and not self.debug_gdbstub:
            raise ValueError("wait_for_debugger requires debug_gdbstub")
        return self
```

Add to `BootOverrides` (after `rootfs: RootfsOverrides | None = None`, line ~484):

```python
    wait_for_debugger: bool | None = None
```

- [ ] **Step 4: Run to verify they pass**

Run: `uv run python -m pytest tests/test_config.py -k wait_for_debugger -q`
Expected: PASS (4 tests).

- [ ] **Step 5: Guardrails + commit**

Run: `uv run ruff check src tests && uv run ruff format src tests && uv run ty check src`
Expected: clean.

```bash
git add src/linux_debug_mcp/config.py tests/test_config.py
git commit -m "feat(config): add wait_for_debugger to TargetProfile and BootOverrides"
```

---

## Task 2: `BootPlan.wait_for_debugger` + plan-time validation

**Files:**
- Modify: `src/linux_debug_mcp/providers/libvirt_qemu.py` (`BootPlan` ~99-103, `plan_boot` ~378-384 and the `return BootPlan(...)` ~420-460)
- Test: `tests/test_libvirt_qemu_provider.py`

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_libvirt_qemu_provider.py` (helpers `make_inputs`, `target_profile`, `rootfs_profile`, `assert_configuration_error` already exist):

```python
def test_plan_boot_sets_wait_for_debugger_when_enabled(tmp_path: Path) -> None:
    kernel, rootfs, run_dir = make_inputs(tmp_path)
    provider = LibvirtQemuProvider()

    plan = provider.plan_boot(
        run_id="run-abc123",
        run_dir=run_dir,
        kernel_image_path=kernel,
        target_profile=target_profile(
            debug_gdbstub=True, gdbstub_endpoint="127.0.0.1:1234", wait_for_debugger=True
        ),
        rootfs_profile=rootfs_profile(rootfs),
    )

    assert plan.wait_for_debugger is True


def test_plan_boot_wait_for_debugger_defaults_false(tmp_path: Path) -> None:
    plan = make_plan(tmp_path)
    assert plan.wait_for_debugger is False
```

- [ ] **Step 2: Run to verify they fail**

Run: `uv run python -m pytest tests/test_libvirt_qemu_provider.py -k wait_for_debugger -q`
Expected: FAIL (`BootPlan` has no `wait_for_debugger` field → `TypeError` on construction).

- [ ] **Step 3: Add the field and wire `plan_boot`**

In `libvirt_qemu.py`, add to the `BootPlan` dataclass (after `discover_guest_ip: bool`, line ~103):

```python
    wait_for_debugger: bool
```

In `plan_boot`, after the gdbstub-endpoint block (after line ~384, before `domain_name = target_profile.target_ref`), add the cross-field gate:

```python
        if target_profile.wait_for_debugger and not target_profile.debug_gdbstub:
            raise self._configuration_error("wait_for_debugger requires debug_gdbstub")
```

In the `return BootPlan(...)` constructor, add (next to `discover_guest_ip=...`):

```python
            wait_for_debugger=target_profile.wait_for_debugger,
```

- [ ] **Step 4: Run to verify they pass**

Run: `uv run python -m pytest tests/test_libvirt_qemu_provider.py -k wait_for_debugger -q`
Expected: PASS (2 tests).

- [ ] **Step 5: Guardrails + commit**

Run: `uv run ruff check src tests && uv run ruff format src tests && uv run ty check src`
Expected: clean.

```bash
git add src/linux_debug_mcp/providers/libvirt_qemu.py tests/test_libvirt_qemu_provider.py
git commit -m "feat(boot): carry wait_for_debugger on BootPlan with plan-time gdbstub gate"
```

---

## Task 3: `render_domain_xml` selects the `wait=` token

**Files:**
- Modify: `src/linux_debug_mcp/providers/libvirt_qemu.py` (`render_domain_xml` gdbstub block ~664-671)
- Test: `tests/test_libvirt_qemu_provider.py`

- [ ] **Step 1: Write the failing tests**

```python
def test_render_domain_xml_emits_wait_on_for_frozen_boot(tmp_path: Path) -> None:
    kernel, rootfs, run_dir = make_inputs(tmp_path)
    provider = LibvirtQemuProvider()
    plan = provider.plan_boot(
        run_id="run-abc123",
        run_dir=run_dir,
        kernel_image_path=kernel,
        target_profile=target_profile(
            debug_gdbstub=True, gdbstub_endpoint="127.0.0.1:1234", wait_for_debugger=True
        ),
        rootfs_profile=rootfs_profile(rootfs),
    )

    xml_text = provider.render_domain_xml(plan)

    assert "server=on,wait=on" in xml_text
    assert "wait=off" not in xml_text


def test_render_domain_xml_emits_wait_off_for_non_frozen_debug_boot(tmp_path: Path) -> None:
    kernel, rootfs, run_dir = make_inputs(tmp_path)
    provider = LibvirtQemuProvider()
    plan = provider.plan_boot(
        run_id="run-abc123",
        run_dir=run_dir,
        kernel_image_path=kernel,
        target_profile=target_profile(debug_gdbstub=True, gdbstub_endpoint="127.0.0.1:1234"),
        rootfs_profile=rootfs_profile(rootfs),
    )

    xml_text = provider.render_domain_xml(plan)

    assert "server=on,wait=off" in xml_text
```

- [ ] **Step 2: Run to verify they fail**

Run: `uv run python -m pytest tests/test_libvirt_qemu_provider.py -k "wait_on or wait_off" -q`
Expected: FAIL on the `wait=on` test (the string is hardcoded `wait=off`).

- [ ] **Step 3: Select the token from the plan**

In `render_domain_xml`, replace the hardcoded gdbstub arg (lines ~664-671):

```python
        if plan.debug_gdbstub and plan.gdbstub_endpoint is not None:
            wait = "on" if plan.wait_for_debugger else "off"
            qemu_commandline = ElementTree.SubElement(domain, f"{{{QEMU_NS}}}commandline")
            ElementTree.SubElement(qemu_commandline, f"{{{QEMU_NS}}}arg", {"value": "-gdb"})
            ElementTree.SubElement(
                qemu_commandline,
                f"{{{QEMU_NS}}}arg",
                {"value": f"tcp:{plan.gdbstub_endpoint.host}:{plan.gdbstub_endpoint.port},server=on,wait={wait}"},
            )
```

- [ ] **Step 4: Run to verify they pass**

Run: `uv run python -m pytest tests/test_libvirt_qemu_provider.py -k "wait_on or wait_off" -q`
Expected: PASS (2 tests).

- [ ] **Step 5: Guardrails + commit**

Run: `uv run ruff check src tests && uv run ruff format src tests && uv run ty check src`
Expected: clean.

```bash
git add src/linux_debug_mcp/providers/libvirt_qemu.py tests/test_libvirt_qemu_provider.py
git commit -m "feat(boot): render gdbstub wait=on when wait_for_debugger is set"
```

---

## Task 4: `execute_boot` frozen branch

**Files:**
- Modify: `src/linux_debug_mcp/providers/libvirt_qemu.py` (`execute_boot`, after the `start` success check ~537, before `stream_console` ~539)
- Test: `tests/test_libvirt_qemu_provider.py`

- [ ] **Step 1: Write the failing tests**

```python
def _frozen_plan(tmp_path: Path):
    kernel, rootfs, run_dir = make_inputs(tmp_path)
    provider = LibvirtQemuProvider()
    return provider.plan_boot(
        run_id="run-abc123",
        run_dir=run_dir,
        kernel_image_path=kernel,
        target_profile=target_profile(
            debug_gdbstub=True, gdbstub_endpoint="127.0.0.1:1234", wait_for_debugger=True
        ),
        rootfs_profile=rootfs_profile(rootfs),
    )


def test_execute_boot_frozen_returns_succeeded_without_streaming(tmp_path: Path) -> None:
    plan = _frozen_plan(tmp_path)
    runner = FakeLibvirtRunner()
    provider = LibvirtQemuProvider(runner=runner)

    result = provider.execute_boot(plan)

    assert result.status == StepStatus.SUCCEEDED
    assert result.details["console_status"] == "frozen"
    assert result.details["wait_for_debugger"] is True
    assert result.details["debug_boot"] is True
    assert result.details["gdbstub_endpoint"] == {"host": "127.0.0.1", "port": 1234}
    assert result.details["guest_ip"] is None
    assert result.details["guest_ip_discovery"]["status"] == "skipped"
    assert result.details["guest_ip_discovery"]["reason"] == "wait_for_debugger"
    assert runner.console_calls == []
    assert runner.domifaddr_calls == []


def test_execute_boot_frozen_still_fails_on_start_error(tmp_path: Path) -> None:
    plan = _frozen_plan(tmp_path)
    runner = FakeLibvirtRunner(start=CommandResult(["virsh", "start"], 1, stderr="boom\n"))
    provider = LibvirtQemuProvider(runner=runner)

    result = provider.execute_boot(plan)

    assert result.status == StepStatus.FAILED
    assert runner.console_calls == []
```

- [ ] **Step 2: Run to verify they fail**

Run: `uv run python -m pytest tests/test_libvirt_qemu_provider.py -k "frozen" -q`
Expected: FAIL on the first test (`execute_boot` streams the console and returns `console_status="ready"`, and `console_calls` is non-empty).

- [ ] **Step 3: Add the frozen branch**

In `execute_boot`, immediately after the `start` success check (after the `if start.exit_status != 0 or start.timed_out:` block ends, line ~537) and before `console = self.runner.stream_console(...)`, insert:

```python
        if plan.wait_for_debugger:
            frozen_details: dict[str, object] = {
                "domain": plan.domain_name,
                "console_status": "frozen",
                "wait_for_debugger": True,
                "matched_marker": None,
                "console_snippet": "",
                "kernel_args": plan.kernel_args,
                "guest_ip": None,
                "guest_ip_discovery": {
                    "status": "skipped",
                    "source": "lease",
                    "reason": "wait_for_debugger",
                },
            }
            return self._boot_result(
                plan=plan,
                status=StepStatus.SUCCEEDED,
                summary="target booted frozen, waiting for debugger attach",
                details=frozen_details,
                artifacts=self._existing_artifacts(artifacts),
            )
```

Note: `_boot_result` merges `self._debug_details(plan)` (which sets `debug_boot`, `gdbstub_endpoint`, `nokaslr_source`) and appends the `boot-summary` artifact, so those keys are present without being repeated here.

- [ ] **Step 4: Run to verify they pass**

Run: `uv run python -m pytest tests/test_libvirt_qemu_provider.py -k "frozen" -q`
Expected: PASS (2 tests).

- [ ] **Step 5: Run the whole provider suite (no regression on the normal path)**

Run: `uv run python -m pytest tests/test_libvirt_qemu_provider.py -q`
Expected: PASS (all existing tests, including the `wait=off`/ready path, unchanged).

- [ ] **Step 6: Guardrails + commit**

Run: `uv run ruff check src tests && uv run ruff format src tests && uv run ty check src`
Expected: clean.

```bash
git add src/linux_debug_mcp/providers/libvirt_qemu.py tests/test_libvirt_qemu_provider.py
git commit -m "feat(boot): return SUCCEEDED-frozen and skip readiness wait when frozen"
```

---

## Task 5: handler — effective `wait_for_debugger` merge, new-override gate, frozen next-action

**Files:**
- Modify: `tests/conftest.py` (`FakeBootProvider`, ~110-205) — add a `details` injection hook
- Modify: `src/linux_debug_mcp/server.py` (`target_boot_handler`: override merge ~1741-1768, `has_new_boot_overrides` ~1787-1790, success `ToolResponse` ~1924-1931)
- Test: `tests/test_target_boot_handler.py`

**Harness facts (verified):** `tests/test_target_boot_handler.py` imports shared fixtures from `tests/conftest.py` — `FakeBootProvider`, `create_run`, `record_build`, `profiles`, `target_profile`, `rootfs_profile` — and a local `boot(artifact_root, tmp_path, *, provider=None, target=None, **kwargs)` helper. `ToolResponse` fields are `response.ok` (bool), `response.data` (dict), `response.suggested_next_actions` (list), `response.error` (ErrorInfo|None) — there is **no** `response.status`. A debug target is `target_profile().model_copy(update={"debug_gdbstub": True})`. The seeding sequence is `artifact_root = create_run(tmp_path)` then `record_build(artifact_root)`.

- [ ] **Step 1a: Extend `conftest.FakeBootProvider` to inject details (prerequisite)**

`conftest.FakeBootProvider.execute_boot` returns a **fixed** details dict with no `console_status` key, so a frozen handler result cannot be simulated without this change. Add a `details` param that is merged into the returned dict. In `tests/conftest.py`, change the `__init__` signature to add (after `raise_on_execute`):

```python
        details: dict[str, object] | None = None,
```
and store it:
```python
        self.extra_details = details or {}
```
Then in `execute_boot`, merge it into the returned `details=` dict (spread `**self.extra_details` last so a test can set `console_status`):

```python
            details={
                "domain": plan.domain_name,
                "provider_call": len(self.executions),
                "debug_boot": plan.debug_gdbstub,
                "gdbstub_endpoint": plan.gdbstub_endpoint,
                "nokaslr_source": plan.nokaslr_source,
                **self.extra_details,
            },
```

Run the existing suites to confirm the additive change is non-breaking:
Run: `uv run python -m pytest tests/test_target_boot_handler.py tests/test_server_boot_snapshot_producer.py -q`
Expected: PASS (no behavior change when `details` is unset).

- [ ] **Step 1b: Write the failing handler test**

Add to `tests/test_target_boot_handler.py` (it already imports `BootOverrides`, `create_run`, `record_build`, `profiles`, `target_profile`, `FakeBootProvider` via the `conftest` import and module imports):

```python
def test_target_boot_frozen_override_yields_debug_next_action(tmp_path: Path) -> None:
    artifact_root = create_run(tmp_path)
    record_build(artifact_root)
    debug_target = target_profile().model_copy(update={"debug_gdbstub": True})
    provider = FakeBootProvider(details={"console_status": "frozen"})

    response = boot(
        artifact_root,
        tmp_path,
        provider=provider,
        target=debug_target,
        boot_overrides=BootOverrides(wait_for_debugger=True),
    )

    assert response.ok is True
    assert response.data["console_status"] == "frozen"
    assert response.suggested_next_actions == ["debug.start_session"]
    # the override reached the provider's plan_boot:
    assert provider.plans[-1]["target_profile"].wait_for_debugger is True
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run python -m pytest tests/test_target_boot_handler.py -k frozen -q`
Expected: FAIL — `suggested_next_actions` is the default `["artifacts.get_manifest"]` and/or the override is not applied so `provider.plans[-1]["target_profile"].wait_for_debugger` is `False`.

- [ ] **Step 3a: Apply the effective override**

In `target_boot_handler`, inside the `if effective_boot_overrides is not None:` block (after the `kernel_args` copy, before the `rootfs_update` block, ~line 1751), add:

```python
            if effective_boot_overrides.wait_for_debugger is not None:
                resolved_target_profile = resolved_target_profile.model_copy(
                    update={"wait_for_debugger": effective_boot_overrides.wait_for_debugger}
                )
```

- [ ] **Step 3b: Count `wait_for_debugger` as a new boot override**

Extend `has_new_boot_overrides` (line ~1787):

```python
    has_new_boot_overrides = boot_overrides is not None and (
        bool(boot_overrides.kernel_args)
        or boot_overrides.rootfs_source is not None
        or boot_overrides.has_rootfs_field_overrides()
        or boot_overrides.wait_for_debugger is not None
    )
```

- [ ] **Step 3c: Frozen `suggested_next_actions`**

In the success `ToolResponse.success(...)` inside `execute_boot` (the inner function, ~line 1924), select the next action from the recorded details:

```python
        if execution.status == StepStatus.SUCCEEDED:
            next_actions = (
                ["debug.start_session"]
                if terminal.details.get("console_status") == "frozen"
                else ["artifacts.get_manifest"]
            )
            return ToolResponse.success(
                summary=execution.summary,
                run_id=run_id,
                data=_redacted_boot_data(terminal.details),
                artifacts=execution.artifacts,
                suggested_next_actions=next_actions,
            )
```

- [ ] **Step 4: Run to verify it passes**

Run: `uv run python -m pytest tests/test_target_boot_handler.py -k frozen -q`
Expected: PASS.

- [ ] **Step 5: Run the full boot-handler suite**

Run: `uv run python -m pytest tests/test_target_boot_handler.py -q`
Expected: PASS (existing non-frozen tests still assert `["artifacts.get_manifest"]`).

- [ ] **Step 6: Guardrails + commit**

Run: `uv run ruff check src tests && uv run ruff format src tests && uv run ty check src`
Expected: clean.

```bash
git add src/linux_debug_mcp/server.py tests/conftest.py tests/test_target_boot_handler.py
git commit -m "feat(server): apply wait_for_debugger override and steer to debug.start_session"
```

---

## Task 6: version-lock + admission-snapshot regression guards (frozen path)

**Files:**
- Test: `tests/test_target_boot_handler.py`

These guard the §4 spec dependencies: a frozen `SUCCEEDED` boot must stay on the handler's `SUCCEEDED` path so the **provenance capture** runs (`server.py:1884`) and the **admission snapshot** is published (`server.py:1916`) — both gated on status, **not** on `console_status`. If a refactor ever gates the frozen branch on `console_status == "ready"`, these guards fail and flag that `debug.start_session` would reject frozen boots.

**Harness facts (verified):** the admission-snapshot pattern is established in `tests/test_server_boot_snapshot_producer.py:49-58` — seed with `create_run` + `record_build`, build `AdmissionService(SnapshotStore())` (imported from `linux_debug_mcp.coordination.admission`), pass `admission=` to the handler, then prove publication by binding an RSP request: `admission.admit(key, request)` returns a non-None handle. **Provenance caveat:** `conftest.record_build` records build details with **no `build_id`**, so `_capture_kernel_provenance` records `kernel_provenance_capture_error` (code `build_id_unavailable`) rather than `kernel_provenance`. The regression guard therefore asserts the capture **ran** (one of the two keys is present), which is exactly what distinguishes "frozen boot stayed on the SUCCEEDED path" from "frozen branch skipped capture". The unambiguous proof that the SUCCEEDED path executed is the snapshot test.

- [ ] **Step 1: Write the failing/guard tests**

Add to `tests/test_target_boot_handler.py`. Add the admission imports at the top if absent:

```python
from linux_debug_mcp.coordination.admission import AdmissionService, SnapshotStore
from linux_debug_mcp.seams.target import TargetKey
```

```python
def test_frozen_boot_stays_on_success_path_for_provenance_capture(tmp_path: Path) -> None:
    artifact_root = create_run(tmp_path)
    record_build(artifact_root)
    debug_target = target_profile().model_copy(update={"debug_gdbstub": True})
    provider = FakeBootProvider(details={"console_status": "frozen"})

    boot(
        artifact_root,
        tmp_path,
        provider=provider,
        target=debug_target,
        boot_overrides=BootOverrides(wait_for_debugger=True),
    )

    manifest = ArtifactStore(artifact_root, create_root=False).load_manifest("run-abc123")
    boot_details = manifest.step_results["boot"].details
    # record_build records no build_id, so capture records the error variant — but it RAN,
    # which proves the frozen boot stayed on the handler's SUCCEEDED path (server.py:1884).
    assert "kernel_provenance" in boot_details or "kernel_provenance_capture_error" in boot_details


def test_frozen_boot_publishes_admission_snapshot(tmp_path: Path) -> None:
    artifact_root = create_run(tmp_path)
    record_build(artifact_root)
    debug_target = target_profile().model_copy(update={"debug_gdbstub": True})
    admission = AdmissionService(SnapshotStore())
    provider = FakeBootProvider(details={"console_status": "frozen"})

    response = boot(
        artifact_root,
        tmp_path,
        provider=provider,
        target=debug_target,
        boot_overrides=BootOverrides(wait_for_debugger=True),
        admission=admission,
    )
    assert response.ok is True
    # The published snapshot is what debug.start_session/run_tests resolve via _require_snapshot.
    # SnapshotStore.get(target_key) is the verified read API (admission.py:233).
    target_key = TargetKey(provisioner="local-qemu", target_id="run-abc123")
    assert admission.snapshot_store.get(target_key) is not None
```

The snapshot store is reachable as `admission.snapshot_store` (the `AdmissionService` is constructed with `AdmissionService(SnapshotStore())`); if the attribute name differs, grep `self._store`/`snapshot_store` in `coordination/admission.py` and adjust — the contract under test is "a `TargetSnapshot` for `run-abc123` exists after the frozen boot". `TargetKey` is imported from `linux_debug_mcp.seams.target` (see `tests/test_server_boot_snapshot_producer.py:6`).

- [ ] **Step 2: Run the guards honestly**

Run: `uv run python -m pytest tests/test_target_boot_handler.py -k "provenance or snapshot" -q`
Expected: both PASS — the handler captures provenance and publishes the snapshot on the `SUCCEEDED` branch regardless of `console_status` (Tasks 4–5 route the frozen boot through that branch). They are **regression guards** that lock the behavior so a later refactor cannot gate those steps on `console_status == "ready"` and silently break `debug.start_session` for frozen boots. If either FAILS, the frozen branch is not on the handler's `SUCCEEDED` path; fix Task 4/5 before proceeding.

- [ ] **Step 3: No implementation change expected**

These are guards over behavior Tasks 4–5 already produce; no new source change. If Step 2 failed, return to Task 4 (frozen branch must return `SUCCEEDED`) / Task 5, not here.

- [ ] **Step 4: Guardrails + commit**

Run: `uv run ruff check src tests && uv run ruff format src tests && uv run ty check src`
Expected: clean.

```bash
git add tests/test_target_boot_handler.py
git commit -m "test(server): guard frozen-boot provenance + admission snapshot for debug.start_session"
```

---

## Task 7: gated end-to-end acceptance integration test

**Files:**
- Modify: `tests/test_qemu_gdbstub_integration.py` (add one test behind the existing tool/env gate)

- [ ] **Step 1: Inspect the existing gate**

Run: `grep -n "skipif\|pytest.mark\|which\|getenv\|RUN_.*INTEGRATION" tests/test_qemu_gdbstub_integration.py | head`
Note the exact skip decorator/marker the module already uses (tool presence + env opt-in). The new test MUST reuse that same gate — do not introduce a new always-on path.

- [ ] **Step 2: Add the gated acceptance test**

Mirroring the module's existing fixtures (real `virsh` + `gdb`, real build/boot), add:

```python
@<existing_integration_gate>
def test_frozen_boot_hits_early_breakpoint_deterministically(<existing fixtures>) -> None:
    # 1. Boot a debug_gdbstub target with wait_for_debugger=True.
    boot_resp = target_boot_handler(..., boot_overrides=BootOverrides(wait_for_debugger=True))
    assert boot_resp.ok is True
    assert boot_resp.data["console_status"] == "frozen"
    # virsh start returned promptly while the vCPU is frozen (the §4 load-bearing assumption):
    # the handler returned without spending the readiness timeout.

    # 2. Attach to the reset-vector CPU.
    session = debug_start_session_handler(...)
    assert session.ok is True

    # 3. Break at an early-init symbol, continue, assert the stop + inspectability.
    debug_set_breakpoint_handler(..., symbol="dcache_init")  # or "start_kernel"
    cont = debug_continue_handler(...)
    assert cont.ok is True
    # assert the session reports HALTED at the breakpoint and an early symbol reads back,
    # using whatever read/inspect handler the module already exercises.
```

The `ToolResponse` API is `.ok`/`.data`/`.suggested_next_actions`/`.error` (`domain.py:470-478`) — there is no `.status`. Match the exact `debug_*` handler signatures the module already calls.

Keep this test behind the gate; it needs a real QEMU+KVM guest and a real kernel build and MUST stay skipped in CI. It is the only place the headline acceptance criterion is proven.

- [ ] **Step 3: Verify it is collected-but-skipped in CI conditions**

Run: `uv run python -m pytest tests/test_qemu_gdbstub_integration.py -q`
Expected: the new test is SKIPPED (no `virsh`/`gdb`/env), not collected-error. Confirm with `-rs` that the skip reason is the existing gate.

- [ ] **Step 4: Guardrails + commit**

Run: `uv run ruff check tests && uv run ruff format tests`
Expected: clean.

```bash
git add tests/test_qemu_gdbstub_integration.py
git commit -m "test(debug): gated end-to-end frozen-boot early-breakpoint acceptance"
```

---

## Task 8: final full-suite + lint gate

- [ ] **Step 1: Full guardrail sweep**

Run: `uv run ruff check src tests && uv run ruff format --check src tests && uv run ty check src && uv run python -m pytest -q`
Expected: all green; integration tests skipped.

- [ ] **Step 2: Confirm no schema snapshot drift**

Run: `git status --porcelain` — expect no unexpected modifications under `src/linux_debug_mcp/introspect_helpers/schemas/`. `TargetProfile`/`BootOverrides` are config models, not introspect-helper wire schemas, so no snapshot regeneration is expected. If any snapshot changed, investigate before committing.

---

## Self-Review

- **Spec coverage:**
  - Decision 1 (flag placement + override) → Task 1, Task 5 (effective merge + new-override gate).
  - Decision 2 (`wait=` token) → Task 3.
  - Decision 3 (plan-time + model validation) → Task 1 (model), Task 2 (plan-time).
  - Decision 4 (frozen branch: skip stream, skip discovery, `SUCCEEDED`-frozen, details) → Task 4; success-path dependencies (`kernel_provenance` + admission snapshot) → Task 6; `virsh start` returns + early breakpoint → Task 7.
  - Decision 5 (idempotency / new-override re-plan) → Task 5 Step 3b.
  - Decision 6 (frozen-domain lifetime) → reuses existing destroy-on-reboot path; no new code, exercised by Task 5/7.
  - Failure contract rows → Task 1 (validation), Task 4 (frozen success, start-fail), Task 7 (e2e).
  - Verification list → Tasks 2,3,4,5,6,7 map 1:1.
- **Placeholder scan:** Tasks 5–6 now use the real `conftest` harness (`create_run`, `record_build`, `profiles`, `boot()`, `FakeBootProvider(details=...)`, `AdmissionService(SnapshotStore())`, `response.ok`/`.data`) verified against `tests/conftest.py` and `tests/test_server_boot_snapshot_producer.py`. Task 7 is the only remaining placeholdered task — it defers the integration gate decorator and the exact `debug_*` handler call signatures to the existing `tests/test_qemu_gdbstub_integration.py`, because that test must run against a real QEMU+KVM guest and reuse the module's established fixtures rather than invent them; its behavior asserts (`console_status == "frozen"`, breakpoint hit) are concrete.
- **Type consistency:** `wait_for_debugger` is `bool` on `TargetProfile`/`BootPlan` and `bool | None` on `BootOverrides` throughout; `console_status == "frozen"` string used identically in provider (Task 4) and handler next-action (Task 5) and tests.
