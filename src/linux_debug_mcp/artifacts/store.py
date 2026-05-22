from __future__ import annotations

import json
import os
import shutil
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from pydantic import ValidationError

from linux_debug_mcp.artifacts.manifest import RunManifest
from linux_debug_mcp.domain import ErrorCategory, RunRequest, StepResult
from linux_debug_mcp.safety.paths import PathSafetyError, validate_artifact_root, validate_run_id


class ManifestStateError(RuntimeError):
    def __init__(self, message: str, category: ErrorCategory = ErrorCategory.INFRASTRUCTURE_FAILURE) -> None:
        super().__init__(message)
        self.category = category


class ArtifactStore:
    SUBDIRS = ("inputs", "logs", "build", "target", "tests", "debug", "summaries", "sensitive")

    def __init__(
        self,
        artifact_root: Path,
        *,
        source_paths: list[Path] | None = None,
        sensitive_paths: list[Path] | None = None,
    ) -> None:
        try:
            self.artifact_root = validate_artifact_root(
                artifact_root,
                source_paths=source_paths or [],
                sensitive_paths=sensitive_paths or [],
            )
        except PathSafetyError as exc:
            raise ManifestStateError(str(exc), ErrorCategory.CONFIGURATION_ERROR) from exc
        try:
            self.artifact_root.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise ManifestStateError(f"failed to create artifact root: {exc}") from exc

    def create_run(self, request: RunRequest) -> RunManifest:
        run_id = self._validate_run_id(request.run_id or self._generate_run_id())
        run_dir = self._run_dir(run_id)
        if run_dir.exists():
            raise ManifestStateError(f"run already exists: {run_id}", ErrorCategory.CONFIGURATION_ERROR)

        created_run_dir = False
        try:
            run_dir.mkdir(parents=False)
            created_run_dir = True
            for subdir in self.SUBDIRS:
                (run_dir / subdir).mkdir()

            manifest = RunManifest.create(run_id=run_id, request=request.model_copy(update={"run_id": run_id}))
            self._write_manifest(run_dir, manifest)
        except FileExistsError as exc:
            if created_run_dir:
                shutil.rmtree(run_dir, ignore_errors=True)
            raise ManifestStateError(f"run already exists: {run_id}", ErrorCategory.CONFIGURATION_ERROR) from exc
        except OSError as exc:
            if created_run_dir:
                shutil.rmtree(run_dir, ignore_errors=True)
            raise ManifestStateError(f"failed to create run {run_id}: {exc}") from exc
        return manifest

    def load_manifest(self, run_id: str) -> RunManifest:
        run_dir = self._run_dir(run_id)
        manifest_path = run_dir / "manifest.json"
        try:
            return RunManifest.model_validate_json(manifest_path.read_text(encoding="utf-8"))
        except (OSError, ValidationError, json.JSONDecodeError) as exc:
            raise ManifestStateError(f"failed to read manifest for {run_id}: {exc}") from exc

    def record_step_result(self, run_id: str, result: StepResult) -> RunManifest:
        run_id = self._validate_run_id(run_id)
        run_dir = self._run_dir(run_id)
        with self._manifest_lock(run_dir):
            manifest = self.load_manifest(run_id)
            updated = manifest.with_step_result(result)
            if updated != manifest:
                self._write_manifest(run_dir, updated)
            return updated

    def _run_dir(self, run_id: str) -> Path:
        safe_run_id = self._validate_run_id(run_id)
        return self.artifact_root / safe_run_id

    def _validate_run_id(self, run_id: str) -> str:
        try:
            return validate_run_id(run_id)
        except PathSafetyError as exc:
            raise ManifestStateError(str(exc), ErrorCategory.CONFIGURATION_ERROR) from exc

    def _write_manifest(self, run_dir: Path, manifest: RunManifest) -> None:
        manifest_path = run_dir / "manifest.json"
        temp_path = run_dir / ".manifest.json.tmp"
        temp_path.write_text(manifest.model_dump_json(indent=2), encoding="utf-8")
        os.replace(temp_path, manifest_path)

    def _generate_run_id(self) -> str:
        return f"run-{uuid.uuid4().hex[:16]}"

    @contextmanager
    def _manifest_lock(self, run_dir: Path) -> Iterator[None]:
        lock_path = run_dir / ".manifest.lock"
        try:
            fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError as exc:
            raise ManifestStateError("manifest is locked", ErrorCategory.INFRASTRUCTURE_FAILURE) from exc
        try:
            os.write(fd, str(os.getpid()).encode("ascii"))
            yield
        finally:
            os.close(fd)
            try:
                lock_path.unlink()
            except FileNotFoundError:
                pass
