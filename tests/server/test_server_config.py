import json
from pathlib import Path

import pytest
from conftest import make_source_tree

from kdive import server
from kdive.config import BootOverrides, ServerConfig
from kdive.server import (
    SERVER_CONFIG_ENV_VAR,
    create_app,
    create_run_handler,
    load_server_config,
)


def make_sensitive_rootfs(tmp_path: Path) -> tuple[Path, Path]:
    """Return (sensitive_dir, rootfs_file) where rootfs_file lives inside sensitive_dir."""
    sensitive_dir = tmp_path / "secrets"
    sensitive_dir.mkdir()
    rootfs = sensitive_dir / "rootfs.qcow2"
    rootfs.write_text("disk image", encoding="utf-8")
    return sensitive_dir, rootfs


def test_load_server_config_returns_none_when_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(SERVER_CONFIG_ENV_VAR, raising=False)
    assert load_server_config() is None


def test_load_server_config_loads_sensitive_paths_from_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config_path = tmp_path / "config.json"
    config_path.write_text(
        json.dumps({"artifact_root": str(tmp_path / "runs"), "sensitive_paths": ["/etc/secret-rootfs"]}),
        encoding="utf-8",
    )
    monkeypatch.setenv(SERVER_CONFIG_ENV_VAR, str(config_path))

    config = load_server_config()

    assert config is not None
    assert config.sensitive_paths == [Path("/etc/secret-rootfs")]


def test_load_server_config_raises_on_missing_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(SERVER_CONFIG_ENV_VAR, str(tmp_path / "does-not-exist.json"))
    with pytest.raises(ValueError, match="failed to read server config"):
        load_server_config()


def test_load_server_config_raises_on_invalid_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config_path = tmp_path / "config.json"
    config_path.write_text("{not valid json", encoding="utf-8")
    monkeypatch.setenv(SERVER_CONFIG_ENV_VAR, str(config_path))
    with pytest.raises(ValueError, match="invalid server config"):
        load_server_config()


def test_create_run_rejects_rootfs_source_overlapping_sensitive_path(tmp_path: Path) -> None:
    source = make_source_tree(tmp_path)
    sensitive_dir, rootfs = make_sensitive_rootfs(tmp_path)

    response = create_run_handler(
        artifact_root=tmp_path / "runs",
        source_path=str(source),
        build_profile="x86_64-default",
        target_profile="local-qemu",
        rootfs_profile="minimal",
        boot_overrides=BootOverrides(rootfs_source=str(rootfs)),
        sensitive_paths=[sensitive_dir],
    )

    assert response.ok is False
    assert response.error is not None
    assert response.error.category == "configuration_error"
    assert "sensitive" in response.error.message


def test_create_run_allows_rootfs_source_when_no_sensitive_paths(tmp_path: Path) -> None:
    source = make_source_tree(tmp_path)
    _sensitive_dir, rootfs = make_sensitive_rootfs(tmp_path)

    response = create_run_handler(
        artifact_root=tmp_path / "runs",
        source_path=str(source),
        build_profile="x86_64-default",
        target_profile="local-qemu",
        rootfs_profile="minimal",
        boot_overrides=BootOverrides(rootfs_source=str(rootfs)),
        sensitive_paths=[],
    )

    assert response.ok is True


def test_create_app_threads_configured_sensitive_paths_into_create_run(tmp_path: Path) -> None:
    source = make_source_tree(tmp_path)
    sensitive_dir, rootfs = make_sensitive_rootfs(tmp_path)
    config = ServerConfig(artifact_root=tmp_path / "runs", sensitive_paths=[sensitive_dir])
    app = create_app(config)
    create_run_fn = app._tool_manager._tools["kernel.create_run"].fn

    result = create_run_fn(
        profiles=server.CreateRunProfiles(
            source_path=str(source),
            build_profile="x86_64-default",
            target_profile="local-qemu",
            rootfs_profile="minimal",
        ),
        context=server.CreateRunContext(artifact_root=str(tmp_path / "runs")),
        options=server.CreateRunOptions(boot_overrides={"rootfs_source": str(rootfs)}),
    )

    assert result["ok"] is False
    assert result["error"]["category"] == "configuration_error"
    assert "sensitive" in result["error"]["message"]


def test_create_app_without_config_allows_nonsensitive_rootfs(tmp_path: Path) -> None:
    source = make_source_tree(tmp_path)
    _sensitive_dir, rootfs = make_sensitive_rootfs(tmp_path)
    app = create_app()
    create_run_fn = app._tool_manager._tools["kernel.create_run"].fn

    result = create_run_fn(
        profiles=server.CreateRunProfiles(
            source_path=str(source),
            build_profile="x86_64-default",
            target_profile="local-qemu",
            rootfs_profile="minimal",
        ),
        context=server.CreateRunContext(artifact_root=str(tmp_path / "runs")),
        options=server.CreateRunOptions(boot_overrides={"rootfs_source": str(rootfs)}),
    )

    assert result["ok"] is True
