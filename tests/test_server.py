from pathlib import Path

from linux_debug_mcp.server import (
    create_app,
    create_run_handler,
    get_manifest_handler,
    list_providers_handler,
    not_implemented_handler,
    prerequisites_handler,
)


def test_create_run_handler_creates_manifest(tmp_path: Path) -> None:
    source = tmp_path / "linux"
    source.mkdir()
    (source / "Kconfig").write_text("mainmenu\n", encoding="utf-8")
    (source / "Makefile").write_text("VERSION = 6\n", encoding="utf-8")

    response = create_run_handler(
        artifact_root=tmp_path,
        source_path=str(source),
        build_profile="x86_64-default",
        target_profile="local-qemu",
        rootfs_profile="minimal",
        run_id="run-abc123",
    )

    assert response.ok is True
    assert response.run_id == "run-abc123"
    assert (tmp_path / "run-abc123" / "manifest.json").exists()
    assert response.suggested_next_actions == ["kernel.build"]


def test_create_run_handler_rejects_source_checkout_as_artifact_root(tmp_path: Path) -> None:
    source = tmp_path / "linux"
    source.mkdir()
    (source / "Kconfig").write_text("mainmenu\n", encoding="utf-8")
    (source / "Makefile").write_text("VERSION = 6\n", encoding="utf-8")

    response = create_run_handler(
        artifact_root=source,
        source_path=str(source),
        build_profile="x86_64-default",
        target_profile="local-qemu",
        rootfs_profile="minimal",
        run_id="run-abc123",
    )

    assert response.ok is False
    assert response.error is not None
    assert response.error.category == "configuration_error"


def test_create_run_handler_rejects_unsafe_run_id(tmp_path: Path) -> None:
    source = tmp_path / "linux"
    source.mkdir()
    (source / "Kconfig").write_text("mainmenu\n", encoding="utf-8")
    (source / "Makefile").write_text("VERSION = 6\n", encoding="utf-8")

    response = create_run_handler(
        artifact_root=tmp_path,
        source_path=str(source),
        build_profile="x86_64-default",
        target_profile="local-qemu",
        rootfs_profile="minimal",
        run_id="../run-abc123",
    )

    assert response.ok is False
    assert response.error is not None
    assert response.error.category == "configuration_error"


def test_get_manifest_handler_returns_redacted_manifest(tmp_path: Path) -> None:
    source = tmp_path / "linux"
    source.mkdir()
    (source / "Kconfig").write_text("mainmenu\n", encoding="utf-8")
    (source / "Makefile").write_text("VERSION = 6\n", encoding="utf-8")

    create_run_handler(
        artifact_root=tmp_path,
        source_path=str(source),
        build_profile="x86_64-default",
        target_profile="local-qemu",
        rootfs_profile="minimal",
        run_id="run-abc123",
    )

    response = get_manifest_handler(artifact_root=tmp_path, run_id="run-abc123")

    assert response.ok is True
    assert response.data["manifest"]["run_id"] == "run-abc123"


def test_get_manifest_handler_rejects_unsafe_run_id(tmp_path: Path) -> None:
    response = get_manifest_handler(artifact_root=tmp_path, run_id="../run-abc123")

    assert response.ok is False
    assert response.error is not None
    assert response.error.category == "configuration_error"


def test_prerequisites_handler_returns_checks(tmp_path: Path) -> None:
    response = prerequisites_handler(
        artifact_root=tmp_path,
        source_path=None,
        enable_libvirt_check=False,
    )

    assert response.ok is True
    assert "checks" in response.data
    assert any(check["check_id"] == "python.version" for check in response.data["checks"])


def test_list_providers_handler_returns_default_capabilities() -> None:
    response = list_providers_handler()

    assert response.ok is True
    assert {provider["provider_name"] for provider in response.data["providers"]} == {
        "local-artifacts",
        "local-prereqs",
        "stub-workflows",
    }


def test_not_implemented_handler_returns_structured_error() -> None:
    response = not_implemented_handler("kernel.build")

    assert response.ok is False
    assert response.error is not None
    assert response.error.category == "not_implemented"
    assert response.error.details["tool"] == "kernel.build"


def test_create_app_constructs_fastmcp_server() -> None:
    assert type(create_app()).__name__ == "FastMCP"
