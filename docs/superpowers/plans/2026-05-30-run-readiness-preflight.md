# Run-readiness preflight Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend `host.check_prerequisites` so that, given the build/target/rootfs profile names a caller intends to use, it names the three roundtrip-blocking gaps up front — a missing/unresolvable rootfs image, a kernel `.config` that is neither present nor derivable, and a gdbstub endpoint port that is not free — each as a `PrerequisiteCheck` with a concrete `suggested_fix`.

**Architecture:** Three new pure functions in `prereqs/checks.py` (`check_kernel_config`, `check_rootfs_image`, `check_gdbstub_port`) each take a resolved profile object (or `None`) and return one `PrerequisiteCheck`. `check_rootfs_image` delegates to the existing `resolve_rootfs_source` (#102) plus an explicit `Path.exists()`. `check_gdbstub_port` takes an injected `port_probe` returning a 3-way `PortProbeResult` (`free`/`in_use`/`error`); the default probe is a plain TCP `bind` that distinguishes `EADDRINUSE` from other `OSError`s. `prerequisites_handler` (in `server.py`) resolves the three profile names against the default registries (test-injectable), emits a `FAILED` check for an unknown name, and appends the three readiness checks to the existing host/toolchain checks. The `host.check_prerequisites` tool gains three optional name parameters.

**Tech Stack:** Python 3.11+, Pydantic v2 (`Model`/`ConfigModel`, `extra="forbid"`), pytest, stdlib `socket`/`errno`. Spec: `docs/specs/2026-05-30-run-readiness-preflight.md`. ADR: `docs/adr/0034-run-readiness-preflight.md`.

---

## File Structure

- `src/linux_debug_mcp/prereqs/checks.py` — new: `PortProbeResult` dataclass, `_default_port_probe`, `_parse_gdbstub_endpoint`, `check_kernel_config`, `check_rootfs_image`, `check_gdbstub_port`. New imports of `config` profile models and `rootfs.sources`. `check_prerequisites` itself is **unchanged**.
- `src/linux_debug_mcp/server.py` — `prerequisites_handler` gains `build_profile`/`target_profile`/`rootfs_profile` name params + `*_profiles` registry injection; new `_resolve_readiness_profile` + `_readiness_checks` helpers; `host.check_prerequisites` tool gains the three name params.
- `docs/tool-reference.md` — document the three new parameters.
- Tests: `tests/test_prereqs.py` (pure check functions), `tests/test_server.py` (handler wiring).

---

## Task 1: Three pure readiness check functions + port probe

**Files:**
- Modify: `src/linux_debug_mcp/prereqs/checks.py`
- Test: `tests/test_prereqs.py`

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_prereqs.py`. New imports at the top:

```python
from linux_debug_mcp.config import BuildProfile, RootfsProfile, TargetProfile
from linux_debug_mcp.prereqs.checks import (
    PortProbeResult,
    check_gdbstub_port,
    check_kernel_config,
    check_rootfs_image,
)
```

Tests (behavior + edges):

```python
# --- check_kernel_config ---
def test_kernel_config_skipped_without_build_profile() -> None:
    check = check_kernel_config(None, None)
    assert check.check_id == "kernel.config"
    assert check.status == "skipped"


def test_kernel_config_passes_when_base_config_derivable() -> None:
    build = BuildProfile(name="b", architecture="x86_64", base_config=["defconfig"])
    check = check_kernel_config(None, build)
    assert check.status == "passed"
    assert "defconfig" in check.message


def test_kernel_config_skipped_when_empty_base_config_and_no_source() -> None:
    build = BuildProfile(name="b", architecture="x86_64")  # base_config defaults to []
    check = check_kernel_config(None, build)
    assert check.status == "skipped"


def test_kernel_config_passes_when_source_config_present(tmp_path: Path) -> None:
    (tmp_path / ".config").write_text("CONFIG_X=y\n", encoding="utf-8")
    build = BuildProfile(name="b", architecture="x86_64")
    check = check_kernel_config(tmp_path, build)
    assert check.status == "passed"
    assert "present" in check.message


def test_kernel_config_fails_when_no_config_and_no_base_config(tmp_path: Path) -> None:
    build = BuildProfile(name="b", architecture="x86_64")
    check = check_kernel_config(tmp_path, build)
    assert check.status == "failed"
    assert check.suggested_fix is not None
    assert "base_config" in check.suggested_fix


# --- check_rootfs_image ---
def test_rootfs_image_skipped_without_profile() -> None:
    check = check_rootfs_image(None)
    assert check.check_id == "rootfs.image"
    assert check.status == "skipped"


def test_rootfs_image_passes_when_local_path_exists(tmp_path: Path) -> None:
    image = tmp_path / "disk.qcow2"
    image.write_bytes(b"qcow")
    profile = RootfsProfile(name="r", source=str(image), source_kind="local_path")
    check = check_rootfs_image(profile)
    assert check.status == "passed"
    assert check.details["path"] == str(image)


def test_rootfs_image_fails_when_local_path_missing(tmp_path: Path) -> None:
    profile = RootfsProfile(name="r", source=str(tmp_path / "absent.qcow2"), source_kind="local_path")
    check = check_rootfs_image(profile)
    assert check.status == "failed"
    assert "not found" in check.message


def test_rootfs_image_fails_with_builder_fix_when_builder_image_missing(tmp_path: Path) -> None:
    profile = RootfsProfile(name="r", source=str(tmp_path / "minimal.qcow2"), source_kind="builder")
    check = check_rootfs_image(profile)
    assert check.status == "failed"
    assert "just rootfs" in (check.suggested_fix or "")


def test_rootfs_image_fails_for_not_implemented_kind() -> None:
    profile = RootfsProfile(name="r", source="catalog-name", source_kind="prebuilt")
    check = check_rootfs_image(profile)
    assert check.status == "failed"
    assert "local_path" in (check.suggested_fix or "")


# --- check_gdbstub_port ---
def test_gdbstub_port_skipped_without_profile() -> None:
    check = check_gdbstub_port(None)
    assert check.check_id == "gdbstub.port"
    assert check.status == "skipped"


def test_gdbstub_port_skipped_when_not_debug_gdbstub() -> None:
    target = TargetProfile(name="t", architecture="x86_64")  # debug_gdbstub defaults False
    check = check_gdbstub_port(target)
    assert check.status == "skipped"


def test_gdbstub_port_passes_when_free() -> None:
    target = TargetProfile(name="t", architecture="x86_64", debug_gdbstub=True)
    check = check_gdbstub_port(target, port_probe=lambda h, p: PortProbeResult("free"))
    assert check.status == "passed"
    assert check.details == {"host": "127.0.0.1", "port": 1234}


def test_gdbstub_port_fails_when_in_use() -> None:
    target = TargetProfile(name="t", architecture="x86_64", debug_gdbstub=True)
    check = check_gdbstub_port(target, port_probe=lambda h, p: PortProbeResult("in_use"))
    assert check.status == "failed"
    assert "in use" in check.message
    assert "127.0.0.1:1234" in check.message


def test_gdbstub_port_fails_with_bind_error_detail() -> None:
    target = TargetProfile(name="t", architecture="x86_64", debug_gdbstub=True)
    check = check_gdbstub_port(
        target, port_probe=lambda h, p: PortProbeResult("error", "Permission denied")
    )
    assert check.status == "failed"
    assert "could not bind" in check.message
    assert "Permission denied" in check.message


def test_gdbstub_port_fails_on_unparseable_endpoint() -> None:
    target = TargetProfile(
        name="t", architecture="x86_64", debug_gdbstub=True, gdbstub_endpoint="garbage"
    )
    probed: list[tuple[str, int]] = []
    check = check_gdbstub_port(
        target, port_probe=lambda h, p: probed.append((h, p)) or PortProbeResult("free")
    )
    assert check.status == "failed"
    assert "could not parse" in check.message
    assert probed == []  # never probes a malformed endpoint
```

- [ ] **Step 2: Run to verify they fail**

Run: `uv run python -m pytest tests/test_prereqs.py -q`
Expected: ImportError / failures — the new symbols do not exist yet.

- [ ] **Step 3: Implement the functions in `prereqs/checks.py`**

Add imports near the top:

```python
import errno
import socket
from dataclasses import dataclass

from linux_debug_mcp.config import BuildProfile, RootfsProfile, TargetProfile
from linux_debug_mcp.rootfs.sources import RootfsSourceError, resolve_rootfs_source
```

Add the probe result + default probe:

```python
@dataclass(frozen=True)
class PortProbeResult:
    """Outcome of a single gdbstub-port bind probe. `state` is free/in_use/error;
    `detail` carries the OS error string for the `error` state."""

    state: Literal["free", "in_use", "error"]
    detail: str = ""


def _default_port_probe(host: str, port: int) -> PortProbeResult:
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    try:
        with socket.socket(family, socket.SOCK_STREAM) as sock:
            sock.bind((host, port))
    except OSError as exc:
        if exc.errno == errno.EADDRINUSE:
            return PortProbeResult("in_use")
        return PortProbeResult("error", str(exc))
    return PortProbeResult("free")
```

(`Literal` is already imported via `typing`? check — add `from typing import Literal` if absent; `Protocol` is imported from `typing`, so extend that import.)

Add `check_kernel_config`:

```python
def check_kernel_config(source_path: Path | None, build_profile: BuildProfile | None) -> PrerequisiteCheck:
    if build_profile is None:
        return PrerequisiteCheck(
            check_id="kernel.config", status=PrerequisiteStatus.SKIPPED, message="no build profile selected"
        )
    if build_profile.base_config:
        targets = " ".join(build_profile.base_config)
        return PrerequisiteCheck(
            check_id="kernel.config",
            status=PrerequisiteStatus.PASSED,
            message=f"kernel .config is derivable via `make {targets}`",
            details={"base_config": list(build_profile.base_config)},
        )
    if source_path is None:
        return PrerequisiteCheck(
            check_id="kernel.config",
            status=PrerequisiteStatus.SKIPPED,
            message="no source path supplied; cannot verify .config presence",
        )
    if (source_path / ".config").is_file():
        return PrerequisiteCheck(
            check_id="kernel.config", status=PrerequisiteStatus.PASSED, message="source .config is present"
        )
    return PrerequisiteCheck(
        check_id="kernel.config",
        status=PrerequisiteStatus.FAILED,
        message="no .config in the source tree and the build profile has an empty base_config",
        suggested_fix=(
            "Provide a .config in the source tree (e.g. run `make defconfig`) or select a build "
            "profile with a base_config such as x86_64-default."
        ),
    )
```

Add `check_rootfs_image`:

```python
_ROOTFS_LOCAL_FIX = "Select a rootfs profile whose source_kind is local_path or builder, or build the image."


def check_rootfs_image(rootfs_profile: RootfsProfile | None) -> PrerequisiteCheck:
    if rootfs_profile is None:
        return PrerequisiteCheck(
            check_id="rootfs.image", status=PrerequisiteStatus.SKIPPED, message="no rootfs profile selected"
        )
    try:
        path = resolve_rootfs_source(rootfs_profile)
    except RootfsSourceError as exc:
        return PrerequisiteCheck(
            check_id="rootfs.image",
            status=PrerequisiteStatus.FAILED,
            message=str(exc),
            suggested_fix=exc.suggested_fix or _ROOTFS_LOCAL_FIX,
        )
    if not path.exists():
        return PrerequisiteCheck(
            check_id="rootfs.image",
            status=PrerequisiteStatus.FAILED,
            message=f"rootfs image not found: {path}",
            suggested_fix=_ROOTFS_LOCAL_FIX,
        )
    return PrerequisiteCheck(
        check_id="rootfs.image",
        status=PrerequisiteStatus.PASSED,
        message="rootfs image is present",
        details={"path": str(path)},
    )
```

Add the endpoint parser + `check_gdbstub_port`:

```python
def _parse_gdbstub_endpoint(endpoint: str) -> tuple[str, int] | None:
    host, sep, port_text = endpoint.rpartition(":")
    if not sep or not host or not port_text:
        return None
    try:
        port = int(port_text)
    except ValueError:
        return None
    if not 1 <= port <= 65535:
        return None
    return host, port


def check_gdbstub_port(
    target_profile: TargetProfile | None,
    *,
    port_probe: Callable[[str, int], PortProbeResult] | None = None,
) -> PrerequisiteCheck:
    if target_profile is None:
        return PrerequisiteCheck(
            check_id="gdbstub.port", status=PrerequisiteStatus.SKIPPED, message="no target profile selected"
        )
    if not target_profile.debug_gdbstub:
        return PrerequisiteCheck(
            check_id="gdbstub.port",
            status=PrerequisiteStatus.SKIPPED,
            message="target profile does not enable gdbstub",
        )
    parsed = _parse_gdbstub_endpoint(target_profile.gdbstub_endpoint)
    if parsed is None:
        return PrerequisiteCheck(
            check_id="gdbstub.port",
            status=PrerequisiteStatus.FAILED,
            message=f"could not parse gdbstub_endpoint: {target_profile.gdbstub_endpoint}",
            suggested_fix="Set gdbstub_endpoint to host:port, e.g. 127.0.0.1:1234.",
        )
    host, port = parsed
    endpoint = f"{host}:{port}"
    result = (port_probe or _default_port_probe)(host, port)
    if result.state == "in_use":
        return PrerequisiteCheck(
            check_id="gdbstub.port",
            status=PrerequisiteStatus.FAILED,
            message=f"gdbstub endpoint {endpoint} is already in use",
            suggested_fix="Stop the process holding it or set a different gdbstub_endpoint.",
        )
    if result.state == "error":
        return PrerequisiteCheck(
            check_id="gdbstub.port",
            status=PrerequisiteStatus.FAILED,
            message=f"could not bind gdbstub endpoint {endpoint}: {result.detail}",
            suggested_fix=(
                "For a privileged port (<1024) run with the needed capability or choose a port >=1024; "
                "for a non-local host confirm the address is configured on this machine."
            ),
        )
    return PrerequisiteCheck(
        check_id="gdbstub.port",
        status=PrerequisiteStatus.PASSED,
        message=f"gdbstub endpoint {endpoint} is free",
        details={"host": host, "port": port},
    )
```

Ensure `Callable` is imported (`from typing import Callable` or `from collections.abc import Callable`; prefer `collections.abc`).

- [ ] **Step 4: Run the tests, confirm green**

Run: `uv run python -m pytest tests/test_prereqs.py -q`
Then: `uv run ruff check src tests && uv run ruff format --check src tests && uv run ty check src`

---

## Task 2: Handler wiring + tool parameters

**Files:**
- Modify: `src/linux_debug_mcp/server.py` (`prerequisites_handler` ~1232-1248, `host.check_prerequisites` tool ~8706-8716, `check_prerequisites` import ~111)
- Test: `tests/test_server.py`

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_server.py` (it already imports `prerequisites_handler`):

```python
def test_prerequisites_handler_readiness_skipped_without_profiles(tmp_path: Path) -> None:
    response = prerequisites_handler(artifact_root=tmp_path / "runs", source_path=None)
    by_id = {c["check_id"]: c for c in response.data["checks"]}
    assert by_id["kernel.config"]["status"] == "skipped"
    assert by_id["rootfs.image"]["status"] == "skipped"
    assert by_id["gdbstub.port"]["status"] == "skipped"


def test_prerequisites_handler_names_missing_rootfs_and_passes_config(tmp_path: Path) -> None:
    response = prerequisites_handler(
        artifact_root=tmp_path / "runs",
        source_path=None,
        build_profile="x86_64-debug",
        target_profile="local-qemu-debug",
        rootfs_profile="minimal",
        port_probe=lambda h, p: PortProbeResult("free"),  # never bind a real port in a unit test
    )
    by_id = {c["check_id"]: c for c in response.data["checks"]}
    assert by_id["kernel.config"]["status"] == "passed"
    assert by_id["rootfs.image"]["status"] == "failed"
    assert "just rootfs" in by_id["rootfs.image"]["suggested_fix"]
    assert by_id["gdbstub.port"]["status"] == "passed"


def test_prerequisites_handler_unknown_profile_is_failed_check(tmp_path: Path) -> None:
    response = prerequisites_handler(
        artifact_root=tmp_path / "runs", source_path=None, build_profile="does-not-exist"
    )
    by_id = {c["check_id"]: c for c in response.data["checks"]}
    assert by_id["kernel.config"]["status"] == "failed"
    assert "unknown build profile" in by_id["kernel.config"]["message"]
    # the other readiness checks still ran
    assert by_id["rootfs.image"]["status"] == "skipped"
```

Import `PortProbeResult` from `linux_debug_mcp.prereqs.checks` in the test module. The handler exposes a
`port_probe` injection seam (Task 2 Step 3) so handler-level tests of the port path never bind a real
socket — consistent with the repo's "handlers are tested with injected dependencies" rule.

- [ ] **Step 2: Run to verify they fail**

Run: `uv run python -m pytest tests/test_server.py -k prerequisites -q`
Expected: FAIL — the handler does not accept the new parameters yet.

- [ ] **Step 3: Implement the handler + helpers**

Extend the `check_prerequisites` import line to also import the three readiness functions:

```python
from linux_debug_mcp.prereqs.checks import (
    PortProbeResult,
    check_gdbstub_port,
    check_kernel_config,
    check_prerequisites,
    check_rootfs_image,
)
```

Ensure `Callable` is importable in `server.py` (it already imports from `collections.abc`/`typing`; add
`Callable` to the existing `collections.abc` import if absent).

Add helpers above `prerequisites_handler`:

```python
_READINESS_CHECK_IDS = {"build": "kernel.config", "target": "gdbstub.port", "rootfs": "rootfs.image"}


def _resolve_readiness_profile(
    kind: str, name: str | None, registry: dict[str, Any]
) -> tuple[Any, PrerequisiteCheck | None]:
    if name is None:
        return None, None
    if name not in registry:
        known = ", ".join(sorted(registry)) or "(none configured)"
        return None, PrerequisiteCheck(
            check_id=_READINESS_CHECK_IDS[kind],
            status=PrerequisiteStatus.FAILED,
            message=f"unknown {kind} profile: {name}",
            suggested_fix=f"Select a known {kind} profile: {known}.",
        )
    return registry[name], None
```

Rewrite `prerequisites_handler`:

```python
def prerequisites_handler(
    *,
    artifact_root: Path,
    source_path: str | None,
    enable_libvirt_check: bool = False,
    build_profile: str | None = None,
    target_profile: str | None = None,
    rootfs_profile: str | None = None,
    build_profiles: dict[str, BuildProfile] | None = None,
    target_profiles: dict[str, TargetProfile] | None = None,
    rootfs_profiles: dict[str, RootfsProfile] | None = None,
    port_probe: Callable[[str, int], PortProbeResult] | None = None,
) -> ToolResponse:
    build_profiles = build_profiles if build_profiles is not None else DEFAULT_BUILD_PROFILES
    target_profiles = target_profiles if target_profiles is not None else DEFAULT_TARGET_PROFILES
    rootfs_profiles = rootfs_profiles if rootfs_profiles is not None else DEFAULT_ROOTFS_PROFILES
    source = Path(source_path) if source_path else None
    checks = check_prerequisites(
        artifact_root=artifact_root, source_path=source, enable_libvirt_check=enable_libvirt_check
    )
    build_obj, build_err = _resolve_readiness_profile("build", build_profile, build_profiles)
    rootfs_obj, rootfs_err = _resolve_readiness_profile("rootfs", rootfs_profile, rootfs_profiles)
    target_obj, target_err = _resolve_readiness_profile("target", target_profile, target_profiles)
    checks.append(build_err or check_kernel_config(source, build_obj))
    checks.append(rootfs_err or check_rootfs_image(rootfs_obj))
    checks.append(target_err or check_gdbstub_port(target_obj, port_probe=port_probe))
    failed = [check for check in checks if check.status == "failed"]
    return ToolResponse.success(
        summary=f"{len(failed)} prerequisite checks failed",
        data={"checks": [check.model_dump(mode="json") for check in checks]},
        suggested_next_actions=["Fix failed checks", "kernel.create_run"],
    )
```

Ensure `PrerequisiteCheck`, `PrerequisiteStatus`, `BuildProfile`, `RootfsProfile`, `TargetProfile` are imported in `server.py` (the profile models already are; add `PrerequisiteCheck`/`PrerequisiteStatus` from `domain` if not present).

Update the tool registration:

```python
@app.tool(name="host.check_prerequisites")
def host_check_prerequisites(
    artifact_root: str = str(DEFAULT_ARTIFACT_ROOT),
    source_path: str | None = None,
    enable_libvirt_check: bool = False,
    build_profile: str | None = None,
    target_profile: str | None = None,
    rootfs_profile: str | None = None,
) -> dict[str, Any]:
    return prerequisites_handler(
        artifact_root=Path(artifact_root),
        source_path=source_path,
        enable_libvirt_check=enable_libvirt_check,
        build_profile=build_profile,
        target_profile=target_profile,
        rootfs_profile=rootfs_profile,
    ).model_dump(mode="json")
```

- [ ] **Step 4: Run the tests + guardrails**

Run: `uv run python -m pytest tests/test_server.py tests/test_prereqs.py tests/test_setup_tooling.py -q`
Then full guardrails: `uv run ruff check src tests && uv run ruff format --check src tests && uv run ty check src && uv run python -m pytest -q`

Verify `dev_setup.check_host` still works (no profiles → three SKIPPED checks appended; `format_prerequisite_checks` renders them). `test_setup_tooling.py` mocks `prerequisites_handler`, so it is unaffected.

---

## Task 3: Document the new parameters

**Files:**
- Modify: `docs/tool-reference.md` (`host.check_prerequisites` section ~20-34)

- [ ] **Step 1: Update the tool-reference entry**

Extend the description to mention the optional `build_profile`/`target_profile`/`rootfs_profile` readiness checks (rootfs image resolvable, `.config` present-or-derivable, gdbstub port free) and add them to the example arguments. Keep it factual.

- [ ] **Step 2: Doc guard**

Run: `just check-docs` (must pass — no "sprint" tokens).

---

## Verification (whole feature)

- [ ] `uv run ruff check src tests` — clean
- [ ] `uv run ruff format --check src tests` — clean
- [ ] `uv run ty check src` — clean (hard-gating)
- [ ] `uv run python -m pytest -q` — green
- [ ] `just check-docs` — pass
- [ ] Manual acceptance trace (spec §Acceptance): `prerequisites_handler` with `build_profile="x86_64-debug"`, `target_profile="local-qemu-debug"`, `rootfs_profile="minimal"` on a machine without `minimal.qcow2` → `kernel.config` PASSED, `rootfs.image` FAILED naming `just rootfs`, `gdbstub.port` PASSED/FAILED per port state; no names → all three SKIPPED.

## Rollback / cleanup

Each task is additive and independently revertible. `check_prerequisites` is untouched, so reverting Task 2's handler change restores the prior response shape exactly (the three new params default to `None`). No migrations, no persisted-state changes, no manifest format change.
