from __future__ import annotations

import json
import os
import shutil
import tempfile
import uuid
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from hashlib import sha256
from pathlib import Path

from pydantic import ValidationError

from linux_debug_mcp.artifacts.manifest import BootAttempt, RunManifest
from linux_debug_mcp.config import BuildProfile, RootfsProfile, TargetProfile
from linux_debug_mcp.domain import ErrorCategory, RunRequest, StepResult
from linux_debug_mcp.safety.paths import PathSafetyError, validate_artifact_root, validate_run_id
from linux_debug_mcp.safety.runtime_locks import RuntimeLockError, private_runtime_lock_dir


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
        create_root: bool = True,
    ) -> None:
        try:
            self.artifact_root = validate_artifact_root(
                artifact_root,
                source_paths=source_paths or [],
                sensitive_paths=sensitive_paths or [],
            )
        except PathSafetyError as exc:
            raise ManifestStateError(str(exc), ErrorCategory.CONFIGURATION_ERROR) from exc
        if create_root:
            try:
                self.artifact_root.mkdir(parents=True, exist_ok=True)
            except OSError as exc:
                raise ManifestStateError(f"failed to create artifact root: {exc}") from exc

    def create_run(
        self,
        request: RunRequest,
        *,
        resolved_build_profile: BuildProfile | None = None,
        resolved_target_profile: TargetProfile | None = None,
        resolved_rootfs_profile: RootfsProfile | None = None,
    ) -> RunManifest:
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
            # Spec §6.1 R2-F4: <run>/sensitive/ must be 0700 so the 0600 file
            # mode on wrapper.py (spec §6.1) is load-bearing against other
            # local users. mkdir's `mode=` arg is masked by umask on POSIX; an
            # explicit chmod after the fact is the only portable guarantee.
            (run_dir / "sensitive").chmod(0o700)

            manifest = RunManifest.create(
                run_id=run_id,
                request=request.model_copy(update={"run_id": run_id}),
                resolved_build_profile=resolved_build_profile,
                resolved_target_profile=resolved_target_profile,
                resolved_rootfs_profile=resolved_rootfs_profile,
            )
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

    def record_step_result(
        self,
        run_id: str,
        result: StepResult,
        *,
        replace_succeeded: bool = False,
        append: bool = False,
    ) -> RunManifest:
        """Record ``result`` into the manifest under the manifest lock.

        ``append=False`` (default): ``replace_succeeded`` controls the
        ``with_step_result`` semantics — used by the singleton named steps
        (``build``, ``boot``, ``run_tests``, ``debug``) where a re-invocation
        after ``force_*`` overwrites a SUCCEEDED entry.

        ``append=True`` (spec §5.2 step 13): uses
        ``RunManifest.append_step_result``, which never replaces and raises on
        ``step_name`` collision. Used for ``introspect:<call_id>`` records.
        ``replace_succeeded`` is rejected when combined with ``append=True``
        to surface caller bugs early.
        """
        if append and replace_succeeded:
            raise ValueError("append=True is incompatible with replace_succeeded=True")
        run_id = self._validate_run_id(run_id)
        run_dir = self._run_dir(run_id)
        with self._manifest_lock(run_dir):
            manifest = self.load_manifest(run_id)
            if append:
                try:
                    updated = manifest.append_step_result(result)
                except ValueError as exc:
                    raise ManifestStateError(str(exc), ErrorCategory.INFRASTRUCTURE_FAILURE) from exc
            else:
                updated = manifest.with_step_result(result, replace_succeeded=replace_succeeded)
            if updated != manifest:
                self._write_manifest(run_dir, updated)
            return updated

    def record_boot_attempt(
        self,
        run_id: str,
        *,
        attempt: BootAttempt,
        boot_result: StepResult,
    ) -> RunManifest:
        run_id = self._validate_run_id(run_id)
        run_dir = self._run_dir(run_id)
        with self._manifest_lock(run_dir):
            manifest = self.load_manifest(run_id)
            updated = manifest.with_boot_attempt(attempt)
            updated = updated.with_step_result(boot_result, replace_succeeded=True)
            self._write_manifest(run_dir, updated)
            return updated

    def run_dir(self, run_id: str) -> Path:
        return self._run_dir(run_id)

    @contextmanager
    def build_lock(self, run_id: str) -> Iterator[None]:
        run_dir = self._run_dir(run_id)
        with self._file_lock(
            run_dir / ".build.lock",
            locked_message="build is locked",
            failure_prefix="failed to lock build",
        ):
            yield

    @contextmanager
    def boot_lock(self, run_id: str) -> Iterator[None]:
        run_dir = self._run_dir(run_id)
        with self._file_lock(
            run_dir / ".boot.lock",
            locked_message="boot is locked",
            failure_prefix="failed to lock boot",
        ):
            yield

    @contextmanager
    def tests_lock(self, run_id: str) -> Iterator[None]:
        run_dir = self._run_dir(run_id)
        with self._file_lock(
            run_dir / ".tests.lock",
            locked_message="tests are locked",
            failure_prefix="failed to lock tests",
        ):
            yield

    @contextmanager
    def collect_lock(self, run_id: str) -> Iterator[None]:
        run_dir = self._run_dir(run_id)
        with self._file_lock(
            run_dir / ".collect.lock",
            locked_message="artifact collection is locked",
            failure_prefix="failed to lock artifact collection",
        ):
            yield

    @contextmanager
    def debug_lock(self, run_id: str) -> Iterator[None]:
        run_dir = self._run_dir(run_id)
        with self._file_lock(
            run_dir / ".debug.lock",
            locked_message="debug is locked",
            failure_prefix="failed to lock debug",
        ):
            yield

    @contextmanager
    def target_lock(self, target_ref: str) -> Iterator[None]:
        lock_dir = self._target_lock_dir()
        lock_name = self._safe_lock_name(target_ref)
        lock_path = lock_dir / f"target-{lock_name}.lock"
        with self._file_lock(
            lock_path,
            locked_message="target domain is locked",
            failure_prefix="failed to lock target domain",
        ):
            yield

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

    def _target_lock_dir(self) -> Path:
        # Resolve the base via this module's tempfile so tests that monkeypatch
        # store.tempfile.gettempdir still steer the fallback path. The shared helper
        # raises with a "runtime lock directory" noun; rewrite it to the historical
        # "target lock directory" wording so this taxonomy's messages are unchanged.
        try:
            return private_runtime_lock_dir(base=Path(tempfile.gettempdir()))
        except RuntimeLockError as exc:
            message = str(exc).replace("runtime lock directory", "target lock directory")
            raise ManifestStateError(message) from exc

    def _safe_lock_name(self, value: str) -> str:
        safe_chars = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-")
        if value and all(char in safe_chars for char in value):
            return value
        return sha256(value.encode("utf-8")).hexdigest()

    @contextmanager
    def _manifest_lock(self, run_dir: Path) -> Iterator[None]:
        with self._file_lock(
            run_dir / ".manifest.lock",
            locked_message="manifest is locked",
            failure_prefix="failed to lock manifest",
        ):
            yield

    @contextmanager
    def _file_lock(self, lock_path: Path, *, locked_message: str, failure_prefix: str) -> Iterator[None]:
        try:
            fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError as exc:
            raise ManifestStateError(locked_message, ErrorCategory.INFRASTRUCTURE_FAILURE) from exc
        except OSError as exc:
            raise ManifestStateError(f"{failure_prefix}: {exc}") from exc
        try:
            os.write(fd, str(os.getpid()).encode("ascii"))
            yield
        finally:
            os.close(fd)
            with suppress(FileNotFoundError):
                lock_path.unlink()
