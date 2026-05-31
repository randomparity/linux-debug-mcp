from __future__ import annotations

import contextlib
import ipaddress
import logging
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TypeVar

from kdive.artifacts.handlers import _redacted_artifacts
from kdive.artifacts.manifest import BootAttempt, RunManifest
from kdive.artifacts.store import ArtifactStore, ManifestStateError
from kdive.config import RootfsProfile, TestCommand, TestSuiteProfile
from kdive.coordination.admission import AdmissionError, AdmissionHandle, AdmissionService
from kdive.coordination.exec_probe import probe_execution_state
from kdive.coordination.registry import SessionRegistry
from kdive.default_profiles import DEFAULT_ROOTFS_PROFILES
from kdive.domain import ArtifactRef, ErrorCategory, StepResult, StepStatus, ToolResponse
from kdive.providers.local.local_ssh_tests import LocalSshTestProvider, TestPlan
from kdive.providers.ssh import TestExecutionResult
from kdive.safety.redaction import Redactor
from kdive.seams.target import TargetKey
from kdive.transport.base import ExecutionState
from kdive.transport.handlers import _require_snapshot

logger = logging.getLogger(__name__)
_RequiredT = TypeVar("_RequiredT")

RUNNING_TESTS_MESSAGE = "previous test run is still recorded as running"
DEFAULT_TEST_SUITES = {
    "smoke-basic": TestSuiteProfile(
        name="smoke-basic",
        timeout_seconds=30,
        stop_on_failure=True,
        collect_dmesg=True,
        commands=[
            TestCommand(name="uname", argv=["uname", "-a"]),
            TestCommand(name="proc-version", argv=["test", "-r", "/proc/version"]),
            TestCommand(name="proc-cmdline", argv=["cat", "/proc/cmdline"]),
        ],
    )
}


def _require_value(value: _RequiredT | None, message: str) -> _RequiredT:
    if value is None:
        raise RuntimeError(message)
    return value


def _configuration_failure(*, run_id: str, message: str, details: dict[str, Any] | None = None) -> ToolResponse:
    return ToolResponse.failure(
        category=ErrorCategory.CONFIGURATION_ERROR,
        message=message,
        run_id=run_id,
        details=details,
    )


def _recorded_test_success_response(*, run_id: str, result: StepResult) -> ToolResponse:
    redactor = Redactor()
    return ToolResponse.success(
        summary=redactor.redact_text(result.summary),
        run_id=run_id,
        data=redactor.redact_value(result.details),
        artifacts=result.artifacts,
        suggested_next_actions=["artifacts.collect"],
    )


def _recorded_test_failure_response(*, run_id: str, result: StepResult) -> ToolResponse:
    redactor = Redactor()
    return ToolResponse.failure(
        category=ErrorCategory.TEST_FAILURE,
        message=redactor.redact_text(result.summary),
        run_id=run_id,
        details=redactor.redact_value(result.details),
        artifacts=result.artifacts,
        suggested_next_actions=["artifacts.collect"],
    )


def _running_tests_response(*, run_id: str, result: StepResult) -> ToolResponse:
    return ToolResponse.failure(
        category=ErrorCategory.INFRASTRUCTURE_FAILURE,
        message=RUNNING_TESTS_MESSAGE,
        run_id=run_id,
        details=Redactor().redact_value(result.details),
        artifacts=result.artifacts,
        suggested_next_actions=["artifacts.get_manifest"],
    )


def _admit_run_tests_ssh_tier(
    *,
    run_id: str,
    admission: AdmissionService | None,
    session_registry: SessionRegistry | None,
) -> AdmissionHandle | None:
    if admission is None or session_registry is None:
        return None
    target_key = TargetKey(provisioner="local-qemu", target_id=run_id)
    snapshot = _require_snapshot(admission, target_key)
    proof = probe_execution_state(
        registry=session_registry, admission=admission, target_key=target_key, generation=snapshot.generation
    )
    if proof.state is ExecutionState.HALTED:
        raise AdmissionError(
            "target halted in debugger; resume or detach before running tests",
            category=ErrorCategory.READINESS_FAILURE,
            code="target_halted",
        )
    return admission.admit_ssh_tier(target_key, snapshot.generation, snapshot.platform, execution_proof=proof)


def _execute_tests_under_gate(
    *,
    provider: LocalSshTestProvider,
    plan: TestPlan,
    admission: AdmissionService | None,
    handle: AdmissionHandle | None,
) -> TestExecutionResult:
    if handle is None or admission is None:
        return provider.execute_tests(plan)

    runner_cancel = threading.Event()
    watch_done = threading.Event()

    def _watch() -> None:
        while not watch_done.is_set():
            if handle.wait_cancelled(0.1):
                runner_cancel.set()
                return

    watcher = threading.Thread(target=_watch, daemon=True)
    watcher.start()
    try:
        result = provider.execute_tests(plan, cancel=runner_cancel)
        admission.complete(handle)
        return result
    finally:
        watch_done.set()
        watcher.join(timeout=2)


def _next_test_attempt(run_dir: Path) -> int:
    attempts = []
    tests_dir = run_dir / "tests"
    if tests_dir.exists():
        for path in tests_dir.glob("attempt-*"):
            try:
                attempts.append(int(path.name.removeprefix("attempt-")))
            except ValueError:
                continue
    return max(attempts, default=0) + 1


def _validate_adhoc_commands(commands: list[list[str]] | None) -> list[TestCommand]:
    validated: list[TestCommand] = []
    for index, argv in enumerate(commands or [], start=1):
        validated.append(TestCommand(name=f"adhoc-{index:03d}", argv=argv, required=True))
    return validated


def _select_boot_attempt(boot_attempts: list[BootAttempt], attempt: int | None) -> BootAttempt:
    if attempt is None:
        return boot_attempts[-1]
    selected = next((record for record in boot_attempts if record.attempt == attempt), None)
    if selected is None:
        available = sorted(record.attempt for record in boot_attempts)
        raise ValueError(f"boot attempt {attempt} not found; recorded attempts: {available}")
    if selected.status != StepStatus.SUCCEEDED:
        raise ValueError(f"boot attempt {attempt} did not succeed (status: {selected.status})")
    return selected


def _ssh_host_is_unset_or_loopback(host: str | None) -> bool:
    if host is None or not host.strip():
        return True
    normalized = host.strip()
    if normalized.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(normalized).is_loopback
    except ValueError:
        return False


def _validated_guest_ip(value: object) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = ipaddress.ip_address(value.strip())
    except ValueError:
        return None
    if parsed.is_loopback or parsed.is_link_local or parsed.is_unspecified:
        return None
    return str(parsed)


@dataclass(frozen=True)
class _RunTestsInputs:
    provider: LocalSshTestProvider
    rootfs_profile: RootfsProfile
    suite_profile: TestSuiteProfile | None
    adhoc_commands: list[TestCommand]
    existing: StepResult | None


@dataclass(frozen=True)
class _CompletedRunTests:
    execution: TestExecutionResult
    summary: str
    details: dict[str, Any]
    diagnostic: str
    artifacts: list[ArtifactRef]


def _resolve_run_tests_inputs(
    *,
    run_id: str,
    manifest: RunManifest,
    boot_result: StepResult,
    test_suite: str | None,
    commands: list[list[str]] | None,
    force_rerun: bool,
    attempt: int | None,
    provider: LocalSshTestProvider | None,
    rootfs_profiles: dict[str, RootfsProfile] | None,
    test_suites: dict[str, TestSuiteProfile] | None,
) -> tuple[_RunTestsInputs | None, ToolResponse | None]:
    try:
        adhoc_commands = _validate_adhoc_commands(commands)
    except ValueError as exc:
        return None, _configuration_failure(run_id=run_id, message=str(exc))

    requested_suite = test_suite or manifest.request.test_suite
    if manifest.request.test_suite is not None and requested_suite != manifest.request.test_suite:
        return None, _configuration_failure(
            run_id=run_id,
            message="test_suite must match the immutable run manifest request",
            details={"requested_suite": requested_suite, "manifest_suite": manifest.request.test_suite},
        )
    if requested_suite is None and not adhoc_commands:
        requested_suite = "smoke-basic"

    rootfs_profiles = rootfs_profiles if rootfs_profiles is not None else DEFAULT_ROOTFS_PROFILES
    test_suites = test_suites if test_suites is not None else DEFAULT_TEST_SUITES
    if manifest.boot_attempts:
        try:
            resolved_rootfs_profile = _select_boot_attempt(manifest.boot_attempts, attempt).resolved_rootfs_profile
        except ValueError as exc:
            return None, _configuration_failure(run_id=run_id, message=str(exc))
    elif attempt is not None:
        return None, _configuration_failure(
            run_id=run_id, message=f"boot attempt {attempt} not found: no boot attempts recorded for this run"
        )
    else:
        try:
            resolved_rootfs_profile = rootfs_profiles[manifest.request.rootfs_profile]
        except KeyError:
            return None, _configuration_failure(
                run_id=run_id,
                message=f"unknown rootfs profile: {manifest.request.rootfs_profile}",
            )

    boot_details = boot_result.details if isinstance(boot_result.details, dict) else {}
    guest_ip = _validated_guest_ip(boot_details.get("guest_ip"))
    if guest_ip is not None and _ssh_host_is_unset_or_loopback(resolved_rootfs_profile.ssh_host):
        resolved_rootfs_profile = resolved_rootfs_profile.model_copy(update={"ssh_host": guest_ip})
    elif boot_details.get("guest_ip") is not None and guest_ip is None:
        logger.warning(
            "run %s: discarding invalid persisted guest_ip %r; using configured ssh_host",
            run_id,
            boot_details.get("guest_ip"),
        )

    try:
        suite_profile = test_suites[requested_suite] if requested_suite is not None else None
    except KeyError:
        return None, _configuration_failure(run_id=run_id, message=f"unknown test suite: {requested_suite}")

    existing = manifest.step_results.get("run_tests")
    if existing and existing.status == StepStatus.SUCCEEDED and not force_rerun:
        return None, _recorded_test_success_response(run_id=run_id, result=existing)
    if existing and existing.status == StepStatus.FAILED and not force_rerun:
        return None, _recorded_test_failure_response(run_id=run_id, result=existing)

    return (
        _RunTestsInputs(
            provider=provider or LocalSshTestProvider(),
            rootfs_profile=resolved_rootfs_profile,
            suite_profile=suite_profile,
            adhoc_commands=adhoc_commands,
            existing=existing,
        ),
        None,
    )


def _record_run_tests_post_admission_failure(
    *,
    store: ArtifactStore,
    run_id: str,
    provider_name: str,
    force_rerun: bool,
    summary: str,
    details: dict[str, Any],
    category: ErrorCategory,
    message: str,
) -> ToolResponse:
    terminal = StepResult(
        step_name="run_tests",
        status=StepStatus.FAILED,
        summary=summary,
        details={"provider": provider_name, **details},
    )
    store.record_step_result(run_id, terminal, replace_succeeded=force_rerun)
    return ToolResponse.failure(
        category=category,
        message=message,
        run_id=run_id,
        details=Redactor().redact_value(terminal.details),
        suggested_next_actions=["artifacts.collect"],
    )


def _locked_run_tests_execution(
    *,
    store: ArtifactStore,
    run_id: str,
    inputs: _RunTestsInputs,
    force_rerun: bool,
    admission: AdmissionService | None,
    session_registry: SessionRegistry | None,
) -> _CompletedRunTests | ToolResponse:
    with store.tests_lock(run_id):
        locked_manifest = store.load_manifest(run_id)
        existing = locked_manifest.step_results.get("run_tests")
        if existing and existing.status == StepStatus.SUCCEEDED and not force_rerun:
            return _recorded_test_success_response(run_id=run_id, result=existing)
        if existing and existing.status == StepStatus.FAILED and not force_rerun:
            return _recorded_test_failure_response(run_id=run_id, result=existing)
        if existing and existing.status == StepStatus.RUNNING:
            stale_failed = StepResult(
                step_name="run_tests",
                status=StepStatus.FAILED,
                summary=existing.summary,
                artifacts=existing.artifacts,
                details={**existing.details, "stale_running_recovered": True},
            )
            store.record_step_result(run_id, stale_failed)

        attempt = _next_test_attempt(store.run_dir(run_id))
        try:
            plan = inputs.provider.plan_tests(
                run_id=run_id,
                run_dir=store.run_dir(run_id),
                rootfs_profile=inputs.rootfs_profile,
                suite=inputs.suite_profile,
                adhoc_commands=inputs.adhoc_commands,
                attempt=attempt,
            )
        except ValueError as exc:
            return _configuration_failure(run_id=run_id, message=str(exc))
        try:
            handle = _admit_run_tests_ssh_tier(run_id=run_id, admission=admission, session_registry=session_registry)
        except AdmissionError as exc:
            return ToolResponse.failure(
                category=exc.category,
                message=str(exc),
                run_id=run_id,
                details={"code": exc.code},
                suggested_next_actions=["artifacts.collect"],
            )
        running = StepResult(
            step_name="run_tests",
            status=StepStatus.RUNNING,
            summary="target tests running",
            details={
                "provider": inputs.provider.name,
                "suite": inputs.suite_profile.name if inputs.suite_profile is not None else "adhoc",
                "attempt": attempt,
            },
        )
        store.record_step_result(run_id, running, replace_succeeded=force_rerun)
        try:
            execution = _execute_tests_under_gate(
                provider=inputs.provider, plan=plan, admission=admission, handle=handle
            )
        except AdmissionError as exc:
            if handle is not None and admission is not None:
                with contextlib.suppress(Exception):
                    admission.rollback(handle)
            return _record_run_tests_post_admission_failure(
                store=store,
                run_id=run_id,
                provider_name=inputs.provider.name,
                force_rerun=force_rerun,
                summary="test run spanned an execution-state transition (target halted)",
                details={"code": exc.code, "error": str(exc)},
                category=exc.category,
                message=str(exc),
            )
        except Exception as exc:
            if handle is not None and admission is not None:
                with contextlib.suppress(Exception):
                    admission.rollback(handle)
            return _record_run_tests_post_admission_failure(
                store=store,
                run_id=run_id,
                provider_name=inputs.provider.name,
                force_rerun=force_rerun,
                summary="unexpected test provider failure",
                details={"exception_type": type(exc).__name__, "error": str(exc)},
                category=ErrorCategory.INFRASTRUCTURE_FAILURE,
                message="unexpected test provider failure",
            )
        redactor = Redactor()
        safe_details = redactor.redact_value(execution.details)
        safe_summary = redactor.redact_text(execution.summary)
        safe_diagnostic = redactor.redact_text(execution.diagnostic or "")
        safe_artifacts = _redacted_artifacts(execution.artifacts, redactor)
        terminal = StepResult(
            step_name="run_tests",
            status=execution.status,
            summary=safe_summary,
            artifacts=safe_artifacts,
            details=safe_details,
        )
        store.record_step_result(run_id, terminal, replace_succeeded=force_rerun)
    return _CompletedRunTests(
        execution=execution,
        summary=safe_summary,
        details=safe_details,
        diagnostic=safe_diagnostic,
        artifacts=safe_artifacts,
    )


def target_run_tests_handler(
    *,
    artifact_root: Path,
    run_id: str,
    test_suite: str | None = None,
    commands: list[list[str]] | None = None,
    force_rerun: bool = False,
    attempt: int | None = None,
    provider: LocalSshTestProvider | None = None,
    rootfs_profiles: dict[str, RootfsProfile] | None = None,
    test_suites: dict[str, TestSuiteProfile] | None = None,
    admission: AdmissionService | None = None,
    session_registry: SessionRegistry | None = None,
) -> ToolResponse:
    try:
        store = ArtifactStore(artifact_root, create_root=False)
        manifest_path = store.run_dir(run_id) / "manifest.json"
        if not manifest_path.is_file():
            return _configuration_failure(run_id=run_id, message=f"run not found: {run_id}")
        manifest = store.load_manifest(run_id)
    except ManifestStateError as exc:
        return ToolResponse.failure(category=exc.category, message=str(exc), run_id=run_id)

    boot_result = manifest.step_results.get("boot")
    if boot_result is None or boot_result.status != StepStatus.SUCCEEDED:
        return _configuration_failure(run_id=run_id, message="target run tests requires a succeeded boot")

    inputs, input_failure = _resolve_run_tests_inputs(
        run_id=run_id,
        manifest=manifest,
        boot_result=boot_result,
        test_suite=test_suite,
        commands=commands,
        force_rerun=force_rerun,
        attempt=attempt,
        provider=provider,
        rootfs_profiles=rootfs_profiles,
        test_suites=test_suites,
    )
    if input_failure is not None:
        return input_failure
    inputs = _require_value(inputs, "run tests inputs missing after successful resolution")

    try:
        completed = _locked_run_tests_execution(
            store=store,
            run_id=run_id,
            inputs=inputs,
            force_rerun=force_rerun,
            admission=admission,
            session_registry=session_registry,
        )
        if isinstance(completed, ToolResponse):
            return completed
    except ManifestStateError as exc:
        if "tests are locked" in str(exc):
            try:
                refreshed = store.load_manifest(run_id).step_results.get("run_tests")
            except ManifestStateError:
                refreshed = None
            if refreshed and refreshed.status == StepStatus.RUNNING:
                return _running_tests_response(run_id=run_id, result=refreshed)
            if inputs.existing and inputs.existing.status == StepStatus.RUNNING:
                return _running_tests_response(run_id=run_id, result=inputs.existing)
        return ToolResponse.failure(category=exc.category, message=str(exc), run_id=run_id)

    if completed.execution.status == StepStatus.SUCCEEDED:
        return ToolResponse.success(
            summary=completed.summary,
            run_id=run_id,
            data=completed.details,
            artifacts=completed.artifacts,
            suggested_next_actions=["artifacts.collect"],
        )
    return ToolResponse.failure(
        category=completed.execution.error_category or ErrorCategory.TEST_FAILURE,
        message=completed.summary,
        run_id=run_id,
        details={
            **completed.details,
            "diagnostic": completed.diagnostic,
        },
        artifacts=completed.artifacts,
        suggested_next_actions=["artifacts.collect"],
    )
