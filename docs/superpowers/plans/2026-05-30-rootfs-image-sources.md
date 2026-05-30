# Rootfs Image Sources (Phase 1 local builder) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the default rootfs bootable out of the box via a `source_kind` image-source abstraction, a `copy_on_write` libvirt overlay, and a one-command Fedora builder.

**Architecture:** A new pure resolver (`rootfs/sources.py`) gates `source_kind` at boot time in the handler before `plan_boot`; the libvirt provider gains a `copy_on_write` mutability that creates a per-boot `qemu-img` overlay over a pristine base; a `scripts/build-rootfs.sh` + `just rootfs` recipe produces the default image. Spec: `docs/specs/2026-05-30-rootfs-image-sources.md`; ADR: `docs/adr/0031-rootfs-image-source-abstraction.md`.

**Tech Stack:** Python 3.11+, Pydantic models, pytest, libvirt/qemu-img CLIs (faked in unit tests), bash.

---

## File Structure

- `src/linux_debug_mcp/config.py` — `RootfsProfile.source_kind` field (modify).
- `src/linux_debug_mcp/rootfs/__init__.py` — new package marker (create).
- `src/linux_debug_mcp/rootfs/sources.py` — `resolve_rootfs_source`, `RootfsSourceError` (create).
- `src/linux_debug_mcp/providers/libvirt_qemu.py` — `BootPlan` overlay fields, `plan_boot`, `execute_boot`, `render_domain_xml`, `_validate_profiles`, capability `required_host_tools` (modify).
- `src/linux_debug_mcp/server.py` — `target_boot_handler` resolver wiring; `DEFAULT_ROOTFS_PROFILES["minimal"]` flip (modify).
- `scripts/build-rootfs.sh` — Fedora image builder (create).
- `justfile` — `rootfs` recipe (modify).
- `docs/fedora-libvirt-user-guide.md` — §5 leads with `just rootfs` (modify).
- `tests/conftest.py` — shared test harness (`create_run`, `record_build`, `profiles`, `rootfs_profile`, `target_profile`, `FakeBootProvider`); reused, not modified.
- Tests: `tests/test_rootfs_sources.py` (create), `tests/test_config.py`, `tests/test_libvirt_qemu_provider.py`, `tests/test_target_boot_handler.py` (existing — extend) (modify/extend).

---

## Task 1: `RootfsProfile.source_kind` field

**Files:**
- Modify: `src/linux_debug_mcp/config.py` (`RootfsProfile`, ~line 375-388)
- Test: `tests/test_config.py`

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_config.py`:

```python
def test_rootfs_profile_source_kind_defaults_to_local_path():
    from linux_debug_mcp.config import RootfsProfile

    profile = RootfsProfile(name="minimal", source="/img.qcow2")
    assert profile.source_kind == "local_path"


def test_rootfs_profile_accepts_each_source_kind():
    from linux_debug_mcp.config import RootfsProfile

    for kind in ("local_path", "builder", "prebuilt", "url"):
        profile = RootfsProfile(name="m", source="/img.qcow2", source_kind=kind)
        assert profile.source_kind == kind


def test_rootfs_profile_rejects_unknown_source_kind():
    import pytest
    from pydantic import ValidationError

    from linux_debug_mcp.config import RootfsProfile

    with pytest.raises(ValidationError):
        RootfsProfile(name="m", source="/img.qcow2", source_kind="nfs")
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run python -m pytest tests/test_config.py -k source_kind -q`
Expected: FAIL (`source_kind` is an unexpected field → `extra="forbid"` ValidationError, and the default test errors).

- [ ] **Step 3: Add the field**

In `src/linux_debug_mcp/config.py`, in `class RootfsProfile`, add immediately after the `source_type` line:

```python
    source_kind: Literal["local_path", "builder", "prebuilt", "url"] = "local_path"
```

(`Literal` is already imported in `config.py`.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run python -m pytest tests/test_config.py -k source_kind -q`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add src/linux_debug_mcp/config.py tests/test_config.py
git commit -m "feat(config): add RootfsProfile.source_kind discriminator"
```

---

## Task 2: rootfs source resolver

**Files:**
- Create: `src/linux_debug_mcp/rootfs/__init__.py`
- Create: `src/linux_debug_mcp/rootfs/sources.py`
- Test: `tests/test_rootfs_sources.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_rootfs_sources.py`:

```python
from pathlib import Path

import pytest

from linux_debug_mcp.config import RootfsProfile
from linux_debug_mcp.domain import ErrorCategory
from linux_debug_mcp.rootfs.sources import RootfsSourceError, resolve_rootfs_source


def _profile(tmp_path: Path, *, source_kind: str, exists: bool = True) -> RootfsProfile:
    image = tmp_path / "minimal.qcow2"
    if exists:
        image.write_bytes(b"qcow2")
    return RootfsProfile(name="minimal", source=str(image), source_kind=source_kind)


def test_local_path_returns_source_without_existence_check(tmp_path: Path):
    profile = _profile(tmp_path, source_kind="local_path", exists=False)
    assert resolve_rootfs_source(profile) == Path(profile.source)


def test_builder_present_returns_path(tmp_path: Path):
    profile = _profile(tmp_path, source_kind="builder", exists=True)
    assert resolve_rootfs_source(profile) == Path(profile.source)


def test_builder_missing_raises_configuration_error_with_just_rootfs(tmp_path: Path):
    profile = _profile(tmp_path, source_kind="builder", exists=False)
    with pytest.raises(RootfsSourceError) as exc:
        resolve_rootfs_source(profile)
    assert exc.value.category == ErrorCategory.CONFIGURATION_ERROR
    assert "just rootfs" in exc.value.suggested_fix


@pytest.mark.parametrize(("kind", "issue"), [("prebuilt", "#106"), ("url", "#107")])
def test_unimplemented_kinds_raise_not_implemented(tmp_path: Path, kind: str, issue: str):
    profile = _profile(tmp_path, source_kind=kind, exists=True)
    with pytest.raises(RootfsSourceError) as exc:
        resolve_rootfs_source(profile)
    assert exc.value.category == ErrorCategory.NOT_IMPLEMENTED
    assert issue in str(exc.value)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run python -m pytest tests/test_rootfs_sources.py -q`
Expected: FAIL with `ModuleNotFoundError: linux_debug_mcp.rootfs.sources`.

- [ ] **Step 3: Create the package + resolver**

Create `src/linux_debug_mcp/rootfs/__init__.py`:

```python
"""Rootfs image-source acquisition (resolution, builder dispatch)."""
```

Create `src/linux_debug_mcp/rootfs/sources.py`:

```python
"""Resolve a RootfsProfile's source_kind to a concrete on-disk image path.

Phase 1 (issue #102) implements ``local_path`` and ``builder``. ``prebuilt`` (#106)
and ``url`` (#107) are accepted by the model but report ``NOT_IMPLEMENTED`` here. The
resolver performs no privileged provisioning: the only filesystem access is a
``Path.exists()`` check for the ``builder`` kind.
"""

from pathlib import Path

from linux_debug_mcp.config import RootfsProfile
from linux_debug_mcp.domain import ErrorCategory

_BUILDER_FIX = (
    "Run `just rootfs` to build the default rootfs image at the configured path, "
    "or set the rootfs profile's source to an existing disk image."
)
_UNIMPLEMENTED_ISSUE = {"prebuilt": "#106", "url": "#107"}


class RootfsSourceError(Exception):
    """A rootfs source_kind could not be resolved to a usable image."""

    def __init__(self, message: str, *, category: ErrorCategory, suggested_fix: str = "") -> None:
        super().__init__(message)
        self.category = category
        self.suggested_fix = suggested_fix


def resolve_rootfs_source(profile: RootfsProfile) -> Path:
    """Map ``profile.source_kind`` to a concrete image path or raise RootfsSourceError.

    For ``local_path`` the path is returned without an existence check (the provider's
    own resolution reports the generic missing-path error). For ``builder`` a missing
    image raises a CONFIGURATION_ERROR naming ``just rootfs``. ``prebuilt``/``url``
    raise NOT_IMPLEMENTED naming their tracking issue.
    """
    source = Path(profile.source)
    kind = profile.source_kind
    if kind == "local_path":
        return source
    if kind == "builder":
        if source.exists():
            return source
        raise RootfsSourceError(
            f"builder rootfs image not found: {source}",
            category=ErrorCategory.CONFIGURATION_ERROR,
            suggested_fix=_BUILDER_FIX,
        )
    issue = _UNIMPLEMENTED_ISSUE[kind]
    raise RootfsSourceError(
        f"rootfs source_kind '{kind}' is not implemented yet (tracked in {issue})",
        category=ErrorCategory.NOT_IMPLEMENTED,
    )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run python -m pytest tests/test_rootfs_sources.py -q`
Expected: PASS (5 tests).

- [ ] **Step 5: Commit**

```bash
git add src/linux_debug_mcp/rootfs/__init__.py src/linux_debug_mcp/rootfs/sources.py tests/test_rootfs_sources.py
git commit -m "feat(rootfs): add source_kind resolver with builder gate"
```

---

## Task 3: `copy_on_write` overlay in the libvirt provider

**Files:**
- Modify: `src/linux_debug_mcp/providers/libvirt_qemu.py` (`BootPlan` ~line 41-70; `plan_boot` ~line 311-388; `execute_boot` ~line 390-498; `render_domain_xml` ~line 500-539; `_validate_profiles` ~line 565-590; `local_libvirt_qemu_capability` ~line 808-826)
- Test: `tests/test_libvirt_qemu_provider.py`

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_libvirt_qemu_provider.py`. First extend the test `FakeLibvirtRunner.run` so it tolerates a `qemu-img` command (it currently indexes `argv[3]` assuming a virsh argv). Add this guard as the **first** statement in `FakeLibvirtRunner.run`, after `self.commands.append(argv)` and the `log_path` block:

```python
        if argv[0] == "qemu-img":
            return CommandResult(argv, 0, stdout="Formatting...\n")
```

Also add `qemu-img` to the default tools so the dependency check passes: change the `tools` default line in `FakeLibvirtRunner.__init__` to:

```python
        self.tools = {"virsh": "/usr/bin/virsh", "qemu-img": "/usr/bin/qemu-img"} if tools is None else tools
```

Then add these tests at the end of the file:

```python
def test_validate_profiles_accepts_copy_on_write(tmp_path: Path) -> None:
    kernel, rootfs, run_dir = make_inputs(tmp_path)
    provider = LibvirtQemuProvider(runner=PortCheckingRunner())
    plan = provider.plan_boot(
        run_id="run-cow",
        run_dir=run_dir,
        kernel_image_path=kernel,
        target_profile=target_profile(),
        rootfs_profile=rootfs_profile(rootfs, mutability="copy_on_write"),
    )
    assert plan.rootfs_mutability == "copy_on_write"


def test_plan_boot_copy_on_write_computes_overlay_and_backing(tmp_path: Path) -> None:
    kernel, rootfs, run_dir = make_inputs(tmp_path)
    provider = LibvirtQemuProvider(runner=PortCheckingRunner())
    plan = provider.plan_boot(
        run_id="run-cow",
        run_dir=run_dir,
        kernel_image_path=kernel,
        target_profile=target_profile(),
        rootfs_profile=rootfs_profile(rootfs, mutability="copy_on_write"),
        attempt=1,
    )
    assert plan.rootfs_backing_path == rootfs.resolve()
    assert plan.rootfs_path == run_dir.resolve() / "boot" / "attempt-1" / "rootfs-overlay.qcow2"
    assert plan.overlay_create_argv == [
        "qemu-img",
        "create",
        "-f",
        "qcow2",
        "-F",
        "qcow2",
        "-b",
        str(rootfs.resolve()),
        str(plan.rootfs_path),
    ]


def test_plan_boot_non_cow_has_no_overlay(tmp_path: Path) -> None:
    kernel, rootfs, run_dir = make_inputs(tmp_path)
    provider = LibvirtQemuProvider(runner=PortCheckingRunner())
    plan = provider.plan_boot(
        run_id="run-ro",
        run_dir=run_dir,
        kernel_image_path=kernel,
        target_profile=target_profile(),
        rootfs_profile=rootfs_profile(rootfs, mutability="read_only"),
    )
    assert plan.rootfs_backing_path is None
    assert plan.overlay_create_argv is None
    assert plan.rootfs_path == rootfs.resolve()


def test_execute_boot_runs_qemu_img_create_before_define(tmp_path: Path) -> None:
    kernel, rootfs, run_dir = make_inputs(tmp_path)
    provider = LibvirtQemuProvider(runner=PortCheckingRunner())
    plan = provider.plan_boot(
        run_id="run-cow",
        run_dir=run_dir,
        kernel_image_path=kernel,
        target_profile=target_profile(),
        rootfs_profile=rootfs_profile(rootfs, mutability="copy_on_write"),
    )
    runner = FakeLibvirtRunner()
    result = LibvirtQemuProvider(runner=runner).execute_boot(plan)
    assert result.status == StepStatus.SUCCEEDED
    commands = [c[0] if c[0] == "qemu-img" else c[3] for c in runner.commands]
    assert "qemu-img" in commands
    assert commands.index("qemu-img") < commands.index("define")


def test_execute_boot_copy_on_write_missing_qemu_img_is_missing_dependency(tmp_path: Path) -> None:
    kernel, rootfs, run_dir = make_inputs(tmp_path)
    provider = LibvirtQemuProvider(runner=PortCheckingRunner())
    plan = provider.plan_boot(
        run_id="run-cow",
        run_dir=run_dir,
        kernel_image_path=kernel,
        target_profile=target_profile(),
        rootfs_profile=rootfs_profile(rootfs, mutability="copy_on_write"),
    )
    runner = FakeLibvirtRunner(tools={"virsh": "/usr/bin/virsh"})
    result = LibvirtQemuProvider(runner=runner).execute_boot(plan)
    assert result.status == StepStatus.FAILED
    assert result.error_category == ErrorCategory.MISSING_DEPENDENCY
    assert "qemu-img" in result.details["missing_tools"]


def test_execute_boot_qemu_img_failure_is_infrastructure_failure(tmp_path: Path) -> None:
    kernel, rootfs, run_dir = make_inputs(tmp_path)
    provider = LibvirtQemuProvider(runner=PortCheckingRunner())
    plan = provider.plan_boot(
        run_id="run-cow",
        run_dir=run_dir,
        kernel_image_path=kernel,
        target_profile=target_profile(),
        rootfs_profile=rootfs_profile(rootfs, mutability="copy_on_write"),
    )

    class FailingQemuImgRunner(FakeLibvirtRunner):
        def run(self, argv, *, timeout, log_path=None):
            self.commands.append(argv)
            if argv[0] == "qemu-img":
                return CommandResult(argv, 1, stderr="qemu-img: boom\n")
            return super().run(argv, timeout=timeout, log_path=log_path)

    result = LibvirtQemuProvider(runner=FailingQemuImgRunner()).execute_boot(plan)
    assert result.status == StepStatus.FAILED
    assert result.error_category == ErrorCategory.INFRASTRUCTURE_FAILURE


def test_render_domain_xml_copy_on_write_points_at_overlay_and_is_writable(tmp_path: Path) -> None:
    kernel, rootfs, run_dir = make_inputs(tmp_path)
    provider = LibvirtQemuProvider(runner=PortCheckingRunner())
    plan = provider.plan_boot(
        run_id="run-cow",
        run_dir=run_dir,
        kernel_image_path=kernel,
        target_profile=target_profile(),
        rootfs_profile=rootfs_profile(rootfs, mutability="copy_on_write"),
    )
    xml = ElementTree.fromstring(provider.render_domain_xml(plan))
    disk = xml.find("devices/disk")
    assert disk.find("source").attrib["file"] == str(plan.rootfs_path)
    assert disk.find("readonly") is None


def test_capability_advertises_qemu_img() -> None:
    from linux_debug_mcp.providers.libvirt_qemu import local_libvirt_qemu_capability

    capability = local_libvirt_qemu_capability()
    assert "qemu-img" in capability.required_host_tools
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run python -m pytest tests/test_libvirt_qemu_provider.py -k "copy_on_write or overlay or qemu_img" -q`
Expected: FAIL (`copy_on_write` rejected by `_validate_profiles`; `BootPlan` has no `rootfs_backing_path`/`overlay_create_argv`; capability lacks `qemu-img`).

- [ ] **Step 3: Add `BootPlan` fields**

In `src/linux_debug_mcp/providers/libvirt_qemu.py`, in `class BootPlan`, add after the `rootfs_mutability: str` line:

```python
    rootfs_backing_path: Path | None
    overlay_create_argv: list[str] | None
```

- [ ] **Step 4: Accept `copy_on_write` in validation**

In `_validate_profiles`, replace:

```python
        if rootfs_profile.mutability not in {"read_only", "mutable"}:
            raise self._configuration_error(f"{rootfs_profile.mutability} rootfs mutability is not supported")
```

with:

```python
        if rootfs_profile.mutability not in {"read_only", "mutable", "copy_on_write"}:
            raise self._configuration_error(f"{rootfs_profile.mutability} rootfs mutability is not supported")
```

- [ ] **Step 5: Compute overlay paths in `plan_boot`**

In `plan_boot`, the line `rootfs_path = self._resolve_existing_path(rootfs_profile.source, description="rootfs source path")` resolves the base. After the `attempt_dir = resolved_run_dir / "boot" / f"attempt-{attempt}"` line, add:

```python
        rootfs_backing_path: Path | None = None
        overlay_create_argv: list[str] | None = None
        if rootfs_profile.mutability == "copy_on_write":
            rootfs_backing_path = rootfs_path
            overlay_path = attempt_dir / "rootfs-overlay.qcow2"
            overlay_create_argv = [
                "qemu-img",
                "create",
                "-f",
                "qcow2",
                "-F",
                "qcow2",
                "-b",
                str(rootfs_backing_path),
                str(overlay_path),
            ]
            rootfs_path = overlay_path
```

Then in the `return BootPlan(...)` call, add the two new fields (next to `rootfs_mutability=rootfs_profile.mutability,`):

```python
            rootfs_backing_path=rootfs_backing_path,
            overlay_create_argv=overlay_create_argv,
```

- [ ] **Step 6: Create the overlay in `execute_boot` before `define`**

In `execute_boot`, replace the existing virsh dependency check:

```python
        if self.runner.which("virsh") is None:
            return self._boot_result(
                plan=plan,
                status=StepStatus.FAILED,
                summary="missing required libvirt tools",
                error_category=ErrorCategory.MISSING_DEPENDENCY,
                details={"missing_tools": ["virsh"]},
                artifacts=[],
            )
```

with:

```python
        required_tools = ["virsh"]
        if plan.overlay_create_argv is not None:
            required_tools.append("qemu-img")
        missing_tools = [tool for tool in required_tools if self.runner.which(tool) is None]
        if missing_tools:
            return self._boot_result(
                plan=plan,
                status=StepStatus.FAILED,
                summary="missing required libvirt tools",
                error_category=ErrorCategory.MISSING_DEPENDENCY,
                details={"missing_tools": missing_tools},
                artifacts=[],
            )
```

Then, immediately before the `define = self.runner.run(plan.define_argv, ...)` line, add the overlay-create step (the attempt dir already exists because `_ensure_artifact_dirs(plan)` ran at the top of `execute_boot`):

```python
        if plan.overlay_create_argv is not None:
            overlay = self.runner.run(
                plan.overlay_create_argv, timeout=plan.timeout_seconds, log_path=plan.boot_log_path
            )
            if overlay.exit_status != 0 or overlay.timed_out:
                return self._command_failure_result(
                    plan=plan, command="qemu-img create", result=overlay, artifacts=artifacts
                )
```

- [ ] **Step 7: (No code) `_command_failure_result` already returns INFRASTRUCTURE_FAILURE**

`_command_failure_result` (`libvirt_qemu.py`) unconditionally passes `error_category=ErrorCategory.INFRASTRUCTURE_FAILURE` (including the timed-out case), so the qemu-img failure test's assertion holds with no change. Nothing to do here.

- [ ] **Step 8: Advertise `qemu-img` in the capability**

In `local_libvirt_qemu_capability()`, change:

```python
        required_host_tools=["virsh"],
```

to:

```python
        required_host_tools=["virsh", "qemu-img"],
```

- [ ] **Step 9: Run the provider tests**

Run: `uv run python -m pytest tests/test_libvirt_qemu_provider.py -q`
Expected: PASS (existing tests still pass; new `copy_on_write`/overlay/qemu-img/capability tests pass). `render_domain_xml` for `read_only`/`mutable` is unchanged because `rootfs_path` equals the base for those modes.

- [ ] **Step 10: Commit**

```bash
git add src/linux_debug_mcp/providers/libvirt_qemu.py tests/test_libvirt_qemu_provider.py
git commit -m "feat(libvirt): copy_on_write rootfs via per-boot qemu-img overlay"
```

---

## Task 4: wire the resolver into `target_boot_handler`

**Files:**
- Modify: `src/linux_debug_mcp/server.py` (`target_boot_handler`, the `try` around `plan_boot` ~line 1971-1998; imports ~line 170-180)
- Test: `tests/test_target_boot_handler.py` (**exists**) using the shared harness in `tests/conftest.py`.

**Harness note:** `tests/conftest.py` already provides `create_run(tmp_path) -> artifact_root` (run id `"run-abc123"`, target `local-qemu`, rootfs `minimal`), `record_build(artifact_root)` (records a SUCCEEDED build with a kernel-image artifact + `architecture="x86_64"`), `target_profile()`, and `FakeBootProvider`. The resolver runs in the handler **before** `provider.plan_boot`, so `FakeBootProvider` is sufficient — no real libvirt. Do **not** call `create_run_handler` directly with profile registries (it takes profile *names*, not `target_profiles`/`rootfs_profiles` dicts). Do **not** route through the file's `boot()` helper for these tests — it already passes `**profiles(...)`, so adding `rootfs_profiles=` would collide on that keyword.

- [ ] **Step 1: Write the failing tests**

Append to the existing `tests/test_target_boot_handler.py` (it already imports `create_run`, `record_build`, `FakeBootProvider` from `conftest`, and `RootfsProfile`, `ErrorCategory`, `StepStatus` are imported there; add `target_profile` to the `conftest` import list and `ArtifactStore` is already imported):

```python
def _booted_run_with_rootfs(tmp_path: Path, rootfs: RootfsProfile):
    artifact_root = create_run(tmp_path)
    record_build(artifact_root)
    return target_boot_handler(
        artifact_root=artifact_root,
        run_id="run-abc123",
        provider=FakeBootProvider(),
        target_profiles={"local-qemu": target_profile()},
        rootfs_profiles={"minimal": rootfs},
    ), artifact_root


def test_boot_builder_missing_image_returns_configuration_error(tmp_path: Path) -> None:
    rootfs = RootfsProfile(
        name="minimal",
        source=str(tmp_path / "absent.qcow2"),
        source_kind="builder",
        mutability="copy_on_write",
        readiness_marker="ready",
    )
    response, artifact_root = _booted_run_with_rootfs(tmp_path, rootfs)
    assert response.ok is False
    assert response.error.category == ErrorCategory.CONFIGURATION_ERROR
    assert "just rootfs" in response.error.details["suggested_fix"]
    manifest = ArtifactStore(artifact_root, create_root=False).load_manifest("run-abc123")
    assert manifest.step_results["boot"].status == StepStatus.FAILED


def test_boot_prebuilt_kind_returns_not_implemented(tmp_path: Path) -> None:
    image = tmp_path / "minimal.qcow2"
    image.write_text("qcow2\n", encoding="utf-8")
    rootfs = RootfsProfile(
        name="minimal",
        source=str(image),
        source_kind="prebuilt",
        mutability="read_only",
        readiness_marker="ready",
    )
    response, _ = _booted_run_with_rootfs(tmp_path, rootfs)
    assert response.ok is False
    assert response.error.category == ErrorCategory.NOT_IMPLEMENTED
    assert "#106" in response.error.message
```

If `target_profile` is not yet in the file's `from conftest import (...)` block, add it. `create_run` records `manifest.request.rootfs_profile = "minimal"`, which matches the injected `rootfs_profiles={"minimal": ...}` so the manifest-immutability check passes.

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run python -m pytest tests/test_target_boot_handler.py -k "builder_missing or prebuilt" -q`
Expected: FAIL — without the resolver, a `builder`-missing profile falls through to `FakeBootProvider.plan_boot` (no `suggested_fix`/CONFIGURATION_ERROR from the resolver), and `prebuilt` is treated as a normal path (no NOT_IMPLEMENTED).

- [ ] **Step 3: Import the resolver in `server.py`**

In `src/linux_debug_mcp/server.py`, add to the imports near the other `linux_debug_mcp` imports:

```python
from linux_debug_mcp.rootfs.sources import RootfsSourceError, resolve_rootfs_source
```

- [ ] **Step 4: Resolve under the lock before `plan_boot`**

In `target_boot_handler`, inside the `with store.target_lock(target_ref):` block, in the `try:` that wraps `plan = provider.plan_boot(...)`, add the resolver call as the **first** statement of the `try`, before `plan = provider.plan_boot(`:

```python
                try:
                    resolve_rootfs_source(resolved_rootfs_profile)
                    plan = provider.plan_boot(
                        run_id=run_id,
                        run_dir=store.run_dir(run_id),
                        kernel_image_path=Path(kernel_image.path),
                        target_profile=resolved_target_profile,
                        rootfs_profile=resolved_rootfs_profile,
                        attempt=next_attempt,
                    )
                except RootfsSourceError as exc:
                    failed = StepResult(
                        step_name="boot",
                        status=StepStatus.FAILED,
                        summary=str(exc),
                        details={"suggested_fix": exc.suggested_fix} if exc.suggested_fix else {},
                    )
                    store.record_step_result(run_id, failed, replace_succeeded=replace_succeeded or force_reboot)
                    return ToolResponse.failure(
                        category=exc.category,
                        message=str(exc),
                        run_id=run_id,
                        details={"suggested_fix": exc.suggested_fix} if exc.suggested_fix else {},
                        suggested_next_actions=["artifacts.get_manifest"],
                    )
                except ProviderBootError as exc:
```

(The `except ProviderBootError as exc:` line already exists immediately after the `plan_boot` call — you are inserting the `resolve_rootfs_source(...)` line and the new `except RootfsSourceError` arm before it. Keep the existing `except ProviderBootError` and `except (ManifestStateError, OSError, ValueError)` arms intact.)

- [ ] **Step 5: Run tests to verify they pass**

Run: `uv run python -m pytest tests/test_target_boot_handler.py -q`
Expected: PASS (2 tests). `prebuilt` is rejected before `plan_boot` with NOT_IMPLEMENTED; `builder`-missing records a FAILED boot with the `suggested_fix`.

- [ ] **Step 6: Commit**

```bash
git add src/linux_debug_mcp/server.py tests/test_target_boot_handler.py
git commit -m "feat(server): gate boot on rootfs source_kind resolution"
```

---

## Task 5: flip the default `minimal` profile

**Files:**
- Modify: `src/linux_debug_mcp/server.py` (`DEFAULT_ROOTFS_PROFILES["minimal"]` ~line 286-296)
- Test: `tests/test_server.py` (or wherever default profiles are asserted) + any test that breaks from the flip.

- [ ] **Step 1: Write the failing test**

Add to `tests/test_server.py` (or the module that imports `DEFAULT_ROOTFS_PROFILES`):

```python
def test_default_minimal_rootfs_is_builder_copy_on_write():
    from linux_debug_mcp.server import DEFAULT_ROOTFS_PROFILES

    minimal = DEFAULT_ROOTFS_PROFILES["minimal"]
    assert minimal.source_kind == "builder"
    assert minimal.mutability == "copy_on_write"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run python -m pytest tests/test_server.py -k default_minimal_rootfs -q`
Expected: FAIL (current default is implicit `local_path` + `read_only`).

- [ ] **Step 3: Flip the default**

In `src/linux_debug_mcp/server.py`, in `DEFAULT_ROOTFS_PROFILES`, change the `minimal` profile to:

```python
    "minimal": RootfsProfile(
        name="minimal",
        source="/var/lib/linux-debug-mcp/rootfs/minimal.qcow2",
        source_kind="builder",
        mutability="copy_on_write",
        readiness_marker="linux-debug-mcp-ready",
        ssh_host="127.0.0.1",
        ssh_port=22,
        ssh_user="root",
    ),
```

- [ ] **Step 4: Run test to verify it passes; then run the full suite to catch fallout**

Run: `uv run python -m pytest tests/test_server.py -k default_minimal_rootfs -q`
Expected: PASS.

Run: `uv run python -m pytest -q`
Expected: Most pass. Any test that asserted the default `minimal` is `read_only` or that injected the default into the provider expecting `read_only` will fail. For each failure, fix the assertion to match the new default (`copy_on_write` / `source_kind="builder"`). Do **not** change provider behavior to accommodate a stale assertion — update the test expectation. Tests that inject their own `RootfsProfile` (most handler tests) are unaffected.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat(server): default minimal rootfs to builder + copy_on_write"
```

---

## Task 6: the Fedora image builder script + `just rootfs`

**Files:**
- Create: `scripts/build-rootfs.sh`
- Modify: `justfile` (add a `rootfs` recipe)

- [ ] **Step 1: Write the builder script**

Create `scripts/build-rootfs.sh`:

```bash
#!/usr/bin/env bash
# Build a minimal, bootable Fedora rootfs qcow2 for linux-debug-mcp.
#
# Produces a whole-disk ext4 qcow2 that boots as /dev/vda, prints the readiness
# marker on ttyS0, runs sshd, and carries an authorized public key. This is a
# host-prep convenience: the MCP server never builds images at tool-call time.
#
# Run unprivileged; the script elevates only the commands that need root.
set -euo pipefail

ROOTFS_PATH="${LINUX_DEBUG_MCP_ROOTFS:-/var/lib/linux-debug-mcp/rootfs/minimal.qcow2}"
RELEASEVER="${LINUX_DEBUG_MCP_ROOTFS_RELEASEVER:-43}"
IMAGE_SIZE="${LINUX_DEBUG_MCP_ROOTFS_SIZE:-2G}"
SSH_USER="${LINUX_DEBUG_MCP_ROOTFS_SSH_USER:-root}"
MARKER="linux-debug-mcp-ready"

# Resolve the invoking user's home even when launched via sudo, so the default
# authorized key is the human's, not root's.
invoking_user="${SUDO_USER:-${USER:-$(id -un)}}"
invoking_home="$(getent passwd "${invoking_user}" | cut -d: -f6)"
: "${invoking_home:=${HOME:-}}"

resolve_authorized_key() {
  if [[ -n "${LINUX_DEBUG_MCP_ROOTFS_AUTHORIZED_KEY:-}" ]]; then
    printf '%s\n' "${LINUX_DEBUG_MCP_ROOTFS_AUTHORIZED_KEY}"
    return
  fi
  local candidate
  for candidate in "${invoking_home}/.ssh/id_ed25519.pub" "${invoking_home}/.ssh/id_rsa.pub"; do
    if [[ -f "${candidate}" ]]; then
      printf '%s\n' "${candidate}"
      return
    fi
  done
}

require() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "error: required command '$1' not found on PATH" >&2
    exit 1
  }
}

require dnf
require virt-make-fs

authorized_key="$(resolve_authorized_key)"
if [[ -z "${authorized_key}" || ! -f "${authorized_key}" ]]; then
  echo "error: no SSH public key found. Set LINUX_DEBUG_MCP_ROOTFS_AUTHORIZED_KEY" >&2
  echo "       to a .pub file, or create ${invoking_home}/.ssh/id_ed25519.pub" >&2
  exit 1
fi

if [[ "${SSH_USER}" == "root" ]]; then
  ssh_home="/root"
else
  ssh_home="/home/${SSH_USER}"
fi

work="$(mktemp -d)"
cleanup() { sudo rm -rf "${work}"; }
trap cleanup EXIT

echo "Installing Fedora ${RELEASEVER} into ${work} ..."
sudo dnf --installroot="${work}" \
  --releasever="${RELEASEVER}" \
  --setopt=install_weak_deps=False \
  --setopt=tsflags=nodocs \
  install -y systemd fedora-release passwd openssh-server

sudo tee "${work}/etc/fstab" >/dev/null <<'EOF'
/dev/vda / ext4 defaults 0 1
EOF

sudo tee "${work}/etc/systemd/system/${MARKER}.service" >/dev/null <<EOF
[Unit]
Description=Signal linux-debug-mcp serial readiness
After=dev-ttyS0.device
Wants=dev-ttyS0.device

[Service]
Type=oneshot
ExecStart=/bin/sh -c 'echo ${MARKER} > /dev/ttyS0'
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

sudo mkdir -p "${work}/etc/systemd/system/multi-user.target.wants"
sudo ln -sf "../${MARKER}.service" \
  "${work}/etc/systemd/system/multi-user.target.wants/${MARKER}.service"
sudo ln -sf /usr/lib/systemd/system/sshd.service \
  "${work}/etc/systemd/system/multi-user.target.wants/sshd.service"

sudo mkdir -p "${work}${ssh_home}/.ssh"
sudo cp "${authorized_key}" "${work}${ssh_home}/.ssh/authorized_keys"
sudo chmod 700 "${work}${ssh_home}/.ssh"
sudo chmod 600 "${work}${ssh_home}/.ssh/authorized_keys"
sudo chown -R "${SSH_USER}:${SSH_USER}" "${work}${ssh_home}/.ssh" 2>/dev/null || true

# If a SELinux policy is ever pulled in transitively, relabel on first boot so the
# host-written authorized_keys gets the correct context before sshd matters.
sudo touch "${work}/.autorelabel"

echo "Packing ${ROOTFS_PATH} ..."
sudo mkdir -p "$(dirname "${ROOTFS_PATH}")"
sudo virt-make-fs --format=qcow2 --type=ext4 --size="${IMAGE_SIZE}" "${work}" "${ROOTFS_PATH}"
sudo chown "${invoking_user}:${invoking_user}" "${ROOTFS_PATH}"

echo "Done: ${ROOTFS_PATH}"
qemu-img info "${ROOTFS_PATH}" 2>/dev/null || true
```

- [ ] **Step 2: Make it executable and lint it**

Run:

```bash
chmod +x scripts/build-rootfs.sh
shellcheck scripts/build-rootfs.sh
shfmt -i 2 -d scripts/build-rootfs.sh
```

Expected: `shellcheck` reports nothing; `shfmt -d` shows no diff. Fix any finding (e.g., quoting) until both are clean.

- [ ] **Step 3: Add the `just rootfs` recipe**

In `justfile`, add after the `check-host` recipe:

```just
rootfs:
    ./scripts/build-rootfs.sh
```

- [ ] **Step 4: Verify the recipe is listed**

Run: `just --list | grep rootfs`
Expected: `rootfs` appears in the list.

- [ ] **Step 5: Commit**

```bash
git add scripts/build-rootfs.sh justfile
git commit -m "feat(build): just rootfs Fedora image builder (sshd + key + marker)"
```

---

## Task 7: update the user guide §5

**Files:**
- Modify: `docs/fedora-libvirt-user-guide.md` (§5)

- [ ] **Step 1: Lead §5 with the one-command path**

In `docs/fedora-libvirt-user-guide.md`, at the start of §5 (after the intro paragraph, before the manual `dnf --installroot` recipe), insert:

```markdown
### One command: `just rootfs`

The fastest path is the bundled builder, which produces the marker + sshd +
authorized-key image at the default path:

```bash
sudo mkdir -p /var/lib/linux-debug-mcp/rootfs
sudo chown "$USER":"$USER" /var/lib/linux-debug-mcp/rootfs
just rootfs
```

Override defaults via environment: `LINUX_DEBUG_MCP_ROOTFS` (output path),
`LINUX_DEBUG_MCP_ROOTFS_RELEASEVER`, `LINUX_DEBUG_MCP_ROOTFS_SIZE`,
`LINUX_DEBUG_MCP_ROOTFS_SSH_USER`, `LINUX_DEBUG_MCP_ROOTFS_AUTHORIZED_KEY`.

The default `minimal` rootfs profile is `source_kind="builder"` and
`mutability="copy_on_write"`: a missing image makes `target.boot` fail with a
`configuration_error` whose `suggested_fix` names `just rootfs`, and each boot runs
from a throwaway qcow2 overlay so the base image stays pristine. `copy_on_write`
requires `qemu-img` on the host and a qcow2 base image.

Under `qemu:///system`, the libvirt qemu user must be able to read the kernel image,
the rootfs base image, and the per-run overlay (under the artifact root). This is the
same access the kernel image already requires; place the artifact root and source tree
on a libvirt-readable, correctly-labeled path, or use `qemu:///session`. SSH login
additionally requires that the guest not mislabel `authorized_keys` — the builder image
has no SELinux policy and carries `.autorelabel`, so this holds without action.

The manual recipe below remains valid as an explanation of what the script does.
```

- [ ] **Step 2: Verify the doc guard passes**

Run: `just check-docs`
Expected: passes (no "sprint" tokens introduced).

- [ ] **Step 3: Commit**

```bash
git add docs/fedora-libvirt-user-guide.md
git commit -m "docs(guide): lead rootfs §5 with just rootfs one-command path"
```

---

## Task 8: full guardrails

- [ ] **Step 1: Lint + format**

Run: `uv run ruff check . && uv run ruff format --check .`
Expected: clean. If `ruff format --check` reports diffs, run `uv run ruff format .` and re-commit.

- [ ] **Step 2: Types**

Run: `uv run ty check src`
Expected: no errors. The new `BootPlan` fields are `Path | None` / `list[str] | None`; ensure the `plan_boot` locals are annotated (`rootfs_backing_path: Path | None = None`, `overlay_create_argv: list[str] | None = None`) so `ty` sees consistent types.

- [ ] **Step 3: Full test suite**

Run: `uv run python -m pytest -q`
Expected: all pass.

- [ ] **Step 4: Final commit if any fixups**

```bash
git add -A
git commit -m "chore: guardrail fixups for rootfs image sources"
```

(Skip if the tree is already clean.)

---

## Self-Review notes (spec coverage)

- `source_kind` field → Task 1. Resolver (`local_path`/`builder`/`prebuilt`/`url`) → Task 2. Resolver wired under the boot lock with the `except RootfsSourceError` arm + recorded FAILED StepResult → Task 4. `copy_on_write` overlay (validation, `plan_boot` paths, `execute_boot` create-before-define, `render_domain_xml`, `qemu-img` MISSING_DEPENDENCY, INFRASTRUCTURE_FAILURE) + capability `qemu-img` → Task 3. Default `minimal` flip → Task 5. Builder script (sshd + key + marker + `.autorelabel`, sudo-only-on-privileged-commands, invoking-user key discovery) + `just rootfs` → Task 6. §5 doc + host requirements → Task 7. qcow2-base precondition → documented in Task 3 (`-F qcow2`) and Task 7. Guardrails → Task 8.
- Type consistency: `rootfs_backing_path` and `overlay_create_argv` are named identically across `BootPlan`, `plan_boot`, `execute_boot`, and the tests. `resolve_rootfs_source` / `RootfsSourceError` (with `.category`, `.suggested_fix`) are consistent across `sources.py`, the handler, and the tests.
