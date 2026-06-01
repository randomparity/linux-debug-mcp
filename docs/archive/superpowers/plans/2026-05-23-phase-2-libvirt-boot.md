# Phase 2 Libvirt Boot Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement `target.boot` for local x86_64 libvirt/QEMU targets with serial readiness detection, durable boot artifacts, idempotency, and fakeable tests.

**Architecture:** Keep the MCP handler responsible for run validation, immutable profile checks, step state, locking, and response shaping. Put libvirt planning, XML rendering, command execution, console capture, ownership checks, cleanup policy, and boot summary writing behind `LibvirtQemuProvider` with injectable runner interfaces.

**Tech Stack:** Python 3.11+, Pydantic v2, pytest, stdlib `subprocess`, stdlib XML rendering/parsing, existing `ArtifactStore`, `RunManifest`, `ToolResponse`, and provider registry.

---

## Current-Code Constraints To Resolve First

- `RunManifest.with_step_result()` currently refuses to replace any succeeded step, so `force_reboot=true` cannot overwrite a succeeded `boot` result until the manifest API supports explicit replacement for selected calls.
- `RootfsProfile` does not have `source_type`; `TargetProfile` does not have `libvirt_uri`, `managed_domain`, or `managed_domain_prefix`; `cleanup_policy` values currently differ from the Phase 2 design.
- There is no runtime config loader for `ServerConfig`; handlers currently use module-level default build profiles only. Phase 2 needs either explicit profile maps injected into `target_boot_handler()` or a config-loading task before the public MCP tool can resolve real target/rootfs profiles.
- `ArtifactStore` only exposes `build_lock()`. Phase 2 needs `boot_lock()` with the same nonblocking file-lock pattern and a host-wide domain-scoped lock so two runs cannot mutate the same libvirt domain concurrently, even if callers use different artifact roots.
- `StepResult` has no heartbeat field. Phase 2 must implement a minimal stale-running rule based on acquiring the boot lock, or the handler will leave crashed `boot` attempts permanently unretryable.
- `virsh dumpxml <domain>` returns a nonzero exit when the domain does not exist. The provider must distinguish "domain not found" from real command failure so first boot can define the dedicated managed domain.
- Libvirt disk XML must enforce rootfs mutability. A `read_only` profile attached as a writable disk can corrupt the configured golden image.
- The runner protocol is not enough for the pilot-host path. Phase 2 must include a default subprocess-backed runner with bounded command execution and console streaming.
- A failed boot using `preserve_on_failure` can leave the managed domain running. A later retry must stop the matching managed domain before `start`, otherwise retries can fail with an already-active domain instead of replacing the failed boot result.

## Files

- Modify: `src/linux_debug_mcp/config.py` for Phase 2 profile fields and validators.
- Modify: `src/linux_debug_mcp/artifacts/manifest.py` for controlled step-result replacement.
- Modify: `src/linux_debug_mcp/artifacts/store.py` for `boot_lock()` and host-wide domain-scoped locking.
- Create: `src/linux_debug_mcp/providers/libvirt_qemu.py` for boot plan, runner protocol, execution result, provider implementation, XML helpers, and capability.
- Modify: `src/linux_debug_mcp/providers/registry.py` to register `local-libvirt-qemu` and remove `target.boot` from `stub-workflows`.
- Modify: `src/linux_debug_mcp/server.py` for default pilot profiles, `target_boot_handler()`, and MCP tool wiring.
- Create: `tests/test_libvirt_qemu_provider.py` for provider planning, validation, ownership, runner, timeout, cleanup, and artifact behavior.
- Create: `tests/test_target_boot_handler.py` for manifest validation, idempotency, locking, profile mismatch, failure mapping, and `force_reboot`.
- Modify: `tests/test_config.py`, `tests/test_artifacts.py`, `tests/test_providers.py`, and `tests/test_server.py` for changed profile fields and provider listing.
- Create: `tests/test_libvirt_boot_integration.py` as an opt-in real-host integration test.
- Modify: `README.md` for pilot-host configuration and gated verification.

## Task 1: Align Phase 2 Profile Models

**Files:**
- Modify: `src/linux_debug_mcp/config.py`
- Modify: `tests/test_config.py`

- [ ] **Step 1: Write failing config tests**

Add tests that prove the Phase 2 profile shape is accepted and invalid policy is rejected:

```python
def test_phase_2_profiles_accept_libvirt_boot_fields(tmp_path: Path) -> None:
    rootfs = RootfsProfile(
        name="minimal",
        source=str(tmp_path / "rootfs.qcow2"),
        source_type="disk_image",
        mutability="read_only",
        access_method="serial",
        readiness_marker="linux-debug-ready",
    )
    target = TargetProfile(
        name="local-qemu",
        architecture="x86_64",
        provider_name="local-libvirt-qemu",
        target_ref="mcp-linux-debug-dev",
        kernel_args=["nokaslr"],
        timeout_seconds=120,
        cleanup_policy="preserve_on_failure",
        libvirt_uri="qemu:///system",
        managed_domain=True,
        managed_domain_prefix="mcp-",
    )

    assert rootfs.source_type == "disk_image"
    assert target.libvirt_uri == "qemu:///system"
    assert target.managed_domain is True
```

```python
@pytest.mark.parametrize("cleanup_policy", ["preserve_all", "preserve_failed", "stop_failed", "remove_temporary"])
def test_phase_2_target_profile_rejects_old_cleanup_policy_values(cleanup_policy: str) -> None:
    with pytest.raises(ValidationError):
        TargetProfile(
            name="local-qemu",
            architecture="x86_64",
            provider_name="local-libvirt-qemu",
            cleanup_policy=cleanup_policy,
        )
```

- [ ] **Step 2: Run tests and confirm failure**

Run:

```bash
pytest tests/test_config.py -q
```

Expected: FAIL because `source_type`, `libvirt_uri`, `managed_domain`, `managed_domain_prefix`, and Phase 2 cleanup policy values are not implemented.

- [ ] **Step 3: Update models**

Change `RootfsProfile` and `TargetProfile` in `src/linux_debug_mcp/config.py` to include:

```python
class RootfsProfile(ConfigModel):
    name: str
    source: str
    source_type: Literal["disk_image", "directory"] = "disk_image"
    mutability: Literal["read_only", "copy_on_write", "mutable"] = "copy_on_write"
    access_method: Literal["ssh", "serial", "ssh_and_serial", "none"] = "ssh"
    credential_refs: list[SecretReference] = Field(default_factory=list)
    readiness_marker: str | None = None
    guest_writable_paths: list[str] = Field(default_factory=list)
```

```python
class TargetProfile(ConfigModel):
    name: str
    architecture: str
    provider_name: str = "local-libvirt-qemu"
    target_ref: str | None = None
    kernel_args: list[str] = Field(default_factory=list)
    timeout_seconds: int = Field(default=300, ge=1)
    cleanup_policy: Literal["preserve_on_failure", "stop_on_failure"] = "preserve_on_failure"
    debug_gdbstub: bool = False
    libvirt_uri: str | None = None
    managed_domain: bool = False
    managed_domain_prefix: str | None = None
```

- [ ] **Step 4: Run tests**

Run:

```bash
pytest tests/test_config.py -q
```

Expected: PASS after updating existing fixture expectations to the new cleanup policy and provider name.

## Task 2: Add Boot/Domain Locks And Controlled Step Replacement

**Files:**
- Modify: `src/linux_debug_mcp/artifacts/store.py`
- Modify: `src/linux_debug_mcp/artifacts/manifest.py`
- Modify: `tests/test_artifacts.py`

- [ ] **Step 1: Write failing artifact tests**

Add:

```python
def test_boot_lock_excludes_concurrent_boots(tmp_path: Path) -> None:
    source = make_source_tree(tmp_path)
    store = ArtifactStore(tmp_path / "runs", source_paths=[source])
    store.create_run(request(run_id="run-abc123"))

    with (
        store.boot_lock("run-abc123"),
        pytest.raises(ManifestStateError, match="boot is locked"),
        store.boot_lock("run-abc123"),
    ):
        pass
```

```python
def test_succeeded_boot_result_can_be_replaced_when_explicit(tmp_path: Path) -> None:
    source = make_source_tree(tmp_path)
    store = ArtifactStore(tmp_path / "runs", source_paths=[source])
    store.create_run(request(run_id="run-abc123"))

    store.record_step_result("run-abc123", StepResult(step_name="boot", status=StepStatus.SUCCEEDED, summary="old"))
    manifest = store.record_step_result(
        "run-abc123",
        StepResult(step_name="boot", status=StepStatus.SUCCEEDED, summary="new"),
        replace_succeeded=True,
    )

    assert manifest.step_results["boot"].summary == "new"
```

```python
def test_target_lock_excludes_concurrent_domain_mutation(tmp_path: Path) -> None:
    source = make_source_tree(tmp_path)
    store_a = ArtifactStore(tmp_path / "runs-a", source_paths=[source])
    store_b = ArtifactStore(tmp_path / "runs-b", source_paths=[source])

    with (
        store_a.target_lock("mcp-linux-debug-dev"),
        pytest.raises(ManifestStateError, match="target domain is locked"),
        store_b.target_lock("mcp-linux-debug-dev"),
    ):
        pass
```

- [ ] **Step 2: Run tests and confirm failure**

Run:

```bash
pytest tests/test_artifacts.py::test_boot_lock_excludes_concurrent_boots tests/test_artifacts.py::test_succeeded_boot_result_can_be_replaced_when_explicit tests/test_artifacts.py::test_target_lock_excludes_concurrent_domain_mutation -q
```

Expected: FAIL because `boot_lock()`, `target_lock()`, and `replace_succeeded` do not exist.

- [ ] **Step 3: Implement store and manifest changes**

Add `replace_succeeded` to `ArtifactStore.record_step_result()` and `RunManifest.with_step_result()`. Add:

```python
@contextmanager
def boot_lock(self, run_id: str) -> Iterator[None]:
    run_dir = self._run_dir(run_id)
    with self._file_lock(
        run_dir / ".boot.lock",
        locked_message="boot is locked",
        failure_prefix="failed to lock boot",
    ):
        yield
```

Add:

```python
@contextmanager
def target_lock(self, target_ref: str) -> Iterator[None]:
    lock_name = _safe_lock_name(target_ref)
    lock_dir = self._target_lock_dir()
    lock_dir.mkdir(parents=True, exist_ok=True)
    with self._file_lock(
        lock_dir / f"target-{lock_name}.lock",
        locked_message="target domain is locked",
        failure_prefix="failed to lock target domain",
    ):
        yield
```

Implement `_safe_lock_name()` with a deterministic hash or strict character whitelist so arbitrary libvirt domain names cannot escape the lock directory. Implement `_target_lock_dir()` as a host-wide per-user lock directory, for example `${XDG_RUNTIME_DIR}/linux-debug-mcp/locks` when available and otherwise a deterministic directory under `tempfile.gettempdir()` namespaced by UID. Do not place target locks under the per-run artifact root.

- [ ] **Step 4: Run tests**

Run:

```bash
pytest tests/test_artifacts.py -q
```

Expected: PASS.

## Task 3: Implement Provider Planning And Validation

**Files:**
- Create: `src/linux_debug_mcp/providers/libvirt_qemu.py`
- Create: `tests/test_libvirt_qemu_provider.py`

- [ ] **Step 1: Write failing provider planning tests**

Cover:
- existing disk image with `read_only` and `mutable` succeeds
- directory source returns `configuration_error`
- `copy_on_write` returns `configuration_error`
- missing `target_ref`, `managed_domain=False`, bad prefix, `debug_gdbstub=True`, missing libvirt URI, unsupported cleanup policy, unsupported architecture, conflicting `root=`, and conflicting `console=` return `configuration_error`
- generated plan contains `kernel_image_path`, `rootfs_path`, `domain_name`, `kernel_args`, `root_device="/dev/vda"`, `serial_device="ttyS0"`, explicit `libvirt_uri`, artifact paths, timeout, readiness marker, ownership metadata, and `virsh -c <uri>` argv lists

- [ ] **Step 2: Run tests and confirm failure**

Run:

```bash
pytest tests/test_libvirt_qemu_provider.py -q
```

Expected: FAIL because the module does not exist.

- [ ] **Step 3: Add provider skeleton**

Create dataclasses/protocols:

```python
@dataclass(frozen=True)
class BootPlan:
    run_id: str
    provider_name: str
    target_profile_name: str
    rootfs_profile_name: str
    domain_name: str
    libvirt_uri: str
    kernel_image_path: Path
    rootfs_path: Path
    rootfs_mutability: str
    root_device: str
    serial_device: str
    kernel_args: list[str]
    timeout_seconds: int
    readiness_marker: str
    domain_xml_path: Path
    console_log_path: Path
    boot_log_path: Path
    boot_plan_path: Path
    boot_summary_path: Path
    ownership: dict[str, str]
    define_argv: list[str]
    start_argv: list[str]
    destroy_argv: list[str]
    dumpxml_argv: list[str]
```

```python
@dataclass(frozen=True)
class CommandResult:
    argv: list[str]
    exit_status: int
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
```

```python
@dataclass(frozen=True)
class ConsoleResult:
    status: Literal["ready", "timeout", "exited"]
    matched_marker: str | None
    snippet: str
    started_at: datetime
    ended_at: datetime
```

```python
@dataclass(frozen=True)
class BootExecutionResult:
    status: StepStatus
    summary: str
    artifacts: list[ArtifactRef]
    details: dict[str, object]
    error_category: ErrorCategory | None = None
    diagnostic: str | None = None
```

```python
class ProviderBootError(Exception):
    def __init__(
        self,
        message: str,
        *,
        category: ErrorCategory,
        details: dict[str, object] | None = None,
        artifacts: list[ArtifactRef] | None = None,
    ) -> None: ...
```

```python
class LibvirtRunner(Protocol):
    def which(self, command: str) -> str | None: ...
    def run(self, argv: list[str], *, timeout: int, log_path: Path | None = None) -> CommandResult: ...
    def stream_console(self, domain: str, *, libvirt_uri: str, output_path: Path, timeout: int, readiness_marker: str) -> ConsoleResult: ...
```

- [ ] **Step 4: Implement `LibvirtQemuProvider.plan_boot()`**

Use explicit validation before any host mutation. Resolve paths with `Path(...).expanduser().resolve(strict=True)`. Reject all unsupported policies with `ProviderBootError(category=ErrorCategory.CONFIGURATION_ERROR, ...)`. Build kernel args by appending `root=/dev/vda` and `console=ttyS0` only when non-conflicting values are not already present. Carry `rootfs_mutability` into the boot plan so XML rendering can enforce `read_only` versus `mutable`.

- [ ] **Step 5: Run provider planning tests**

Run:

```bash
pytest tests/test_libvirt_qemu_provider.py -q
```

Expected: planning tests PASS; execution tests still fail until later tasks add execution.

## Task 4: Render Domain XML And Check Ownership

**Files:**
- Modify: `src/linux_debug_mcp/providers/libvirt_qemu.py`
- Modify: `tests/test_libvirt_qemu_provider.py`

- [ ] **Step 1: Write failing XML ownership tests**

Cover:
- XML includes direct kernel boot loader, rootfs disk target `vda`, serial/console PTY, and metadata entries for provider, domain, and target profile.
- XML for `read_only` rootfs profiles includes a libvirt readonly disk marker and XML for `mutable` rootfs profiles omits it.
- fake existing domain XML without matching MCP ownership causes `configuration_error` and no define/start/destroy command.
- fake existing domain XML with matching ownership permits reuse across a different run id.

- [ ] **Step 2: Implement XML helpers**

Use `xml.etree.ElementTree` to generate and inspect XML. Keep run id diagnostic-only and match ownership on provider name, managed domain name, and target profile name. Render `<readonly/>` under the disk device when `plan.rootfs_mutability == "read_only"` so the guest cannot write to a read-only profile's backing image.

- [ ] **Step 3: Run XML tests**

Run:

```bash
pytest tests/test_libvirt_qemu_provider.py -q
```

Expected: PASS for planning and XML ownership tests.

## Task 5: Implement Provider Execution

**Files:**
- Modify: `src/linux_debug_mcp/providers/libvirt_qemu.py`
- Modify: `tests/test_libvirt_qemu_provider.py`

- [ ] **Step 1: Write failing execution tests**

Cover:
- missing `virsh` maps to `missing_dependency`
- default runner `which()` and `run()` use subprocess without shell expansion, capture stdout/stderr, append output to `log_path`, and map timeout to `CommandResult(timed_out=True)`
- default runner `stream_console()` starts `virsh -c <uri> console --force <domain>`, writes full console output to `console.log`, returns bounded snippets, returns `ready` when the marker appears, and terminates the subprocess on timeout or early exit
- first boot treats `virsh -c <uri> dumpxml <domain>` "domain not found" as an absent domain and proceeds to define/start
- `dumpxml` command failures other than "domain not found" map to `infrastructure_failure`
- retry after a previous failed boot with a preserved running domain stops the matching managed domain before define/start
- fake define/start/readiness writes `domain.xml`, `boot-plan.json`, `console.log`, `boot.log`, `boot-summary.json`
- timeout maps to `boot_timeout` and keeps console artifacts
- early console exit maps to `readiness_failure`
- command failure maps to `infrastructure_failure`
- `stop_on_failure` destroys only after evidence collection
- `preserve_on_failure` leaves the fake domain running
- rerun rotates existing `console.log` to `console.<timestamp>.log`

- [ ] **Step 2: Implement `execute_boot()`**

Use an explicit signature such as `execute_boot(plan: BootPlan, *, force_reboot: bool = False, retrying_after_failure: bool = False) -> BootExecutionResult` so lifecycle cleanup is driven by handler state instead of inferred from libvirt errors.

Sequence:
1. Create artifact directories.
2. Check `virsh` with runner `which`.
3. Write `boot-plan.json`.
4. Inspect existing domain ownership with `virsh -c <uri> dumpxml <domain>`. Treat the runner's explicit "domain not found" result as an absent domain, not as infrastructure failure; all other nonzero `dumpxml` failures remain `infrastructure_failure`.
5. Render and write `domain.xml`.
6. Stop/destroy the managed domain before define/start when `force_reboot=true` or `retrying_after_failure=true`. Do this only after ownership has been validated and prior console/domain evidence has been retained.
7. Define/update using `virsh -c <uri> define <domain.xml>`.
8. Start using `virsh -c <uri> start <domain>`.
9. Stream console until readiness marker or terminal failure.
10. Write summary and return `BootExecutionResult`.

Implement `SubprocessLibvirtRunner` as the provider default. It must invoke commands with argv lists only, never `shell=True`; include the resolved `libvirt_uri` in console commands; write command output to the requested log path; cap returned snippets; and reliably terminate child processes on timeout. Tests should monkeypatch `subprocess.run` and `subprocess.Popen` rather than requiring real libvirt.

- [ ] **Step 3: Run provider tests**

Run:

```bash
pytest tests/test_libvirt_qemu_provider.py -q
```

Expected: PASS.

## Task 6: Add `target_boot_handler()`

**Files:**
- Modify: `src/linux_debug_mcp/server.py`
- Create: `tests/test_target_boot_handler.py`

- [ ] **Step 1: Write failing handler tests**

Cover:
- missing run is `configuration_error`
- no succeeded build is `configuration_error`
- succeeded build without `kernel-image` is `configuration_error`
- build/target architecture mismatch is `configuration_error`
- profile mismatch arguments are `configuration_error`
- repeated successful boot returns recorded result without invoking provider
- running boot returns `infrastructure_failure` while lock/state are active
- `force_reboot=true` invokes provider and records replacement result
- existing failed boot invokes provider with `retrying_after_failure=True` so preserved domains are stopped before the retry starts
- concurrent calls use `boot_lock()`
- concurrent calls for different runs that resolve to the same `target_ref` use `target_lock()` so only one provider execution mutates the domain
- stale recorded `RUNNING` boot is marked failed and retried only when `boot_lock()` is available and the domain lock can also be acquired

- [ ] **Step 2: Implement handler**

Add `target_boot_handler()` with injectable `provider`, `target_profiles`, `rootfs_profiles`, and `default_libvirt_uri` parameters. Use module defaults for the public tool until a broader config loader exists.

Add module-level `DEFAULT_TARGET_PROFILES` and `DEFAULT_ROOTFS_PROFILES` only as pilot placeholders. They must be overrideable by tests and by the public tool path, and the README must state which environment/profile values a real pilot host must provide. The public MCP tool must fail with `configuration_error` when the immutable run request names a target or rootfs profile that is not present in the resolved maps.

For `RUNNING` boot results:
- If `boot_lock(run_id)` cannot be acquired, return `infrastructure_failure` with the recorded running details.
- If `boot_lock(run_id)` can be acquired and no provider execution is active, mark the old running result as failed with `details["stale_running_recovered"] = True`, then continue with a retry under the same lock.
- Do not mark a running result stale while `target_lock(target_ref)` is unavailable; report that the target domain is locked instead.

Acquire locks in this order for every boot execution path:
1. `boot_lock(run_id)`
2. `target_lock(target_ref)`

This prevents both duplicate boots for one run and concurrent mutation of the same libvirt domain by different runs.

- [ ] **Step 3: Wire MCP tool**

Replace only the `target.boot` stub registration with a real FastMCP tool accepting `run_id`, `artifact_root`, optional `target_profile`, optional `rootfs_profile`, and `force_reboot`.

- [ ] **Step 4: Run handler tests**

Run:

```bash
pytest tests/test_target_boot_handler.py tests/test_server.py -q
```

Expected: PASS after updating the `target.boot` not-implemented test to a later-phase tool.

## Task 7: Register Provider Capability

**Files:**
- Modify: `src/linux_debug_mcp/providers/registry.py`
- Modify: `tests/test_providers.py`

- [ ] **Step 1: Write failing registry test**

Assert defaults contain `local-libvirt-qemu`, that it advertises `target.boot`, `virsh`, `TargetKind.VIRTUAL`, and that `stub-workflows` no longer advertises `target.boot`.

- [ ] **Step 2: Implement capability function**

Add `local_libvirt_qemu_capability()` in `providers/libvirt_qemu.py` and register it in `ProviderRegistry.with_defaults()`.

- [ ] **Step 3: Run registry tests**

Run:

```bash
pytest tests/test_providers.py tests/test_server.py::test_list_providers_handler_returns_default_capabilities -q
```

Expected: PASS.

## Task 8: Add Gated Integration Test And README

**Files:**
- Create: `tests/test_libvirt_boot_integration.py`
- Modify: `README.md`

- [ ] **Step 1: Add skipped-by-default integration test**

Use `pytest.skip()` unless `LINUX_DEBUG_MCP_LIBVIRT_TEST=1`, `LINUX_DEBUG_MCP_ROOTFS`, `LINUX_DEBUG_MCP_SOURCE`, `LINUX_DEBUG_MCP_DOMAIN`, `LINUX_DEBUG_MCP_LIBVIRT_URI`, and `LINUX_DEBUG_MCP_READINESS_MARKER` are set.

- [ ] **Step 2: Document pilot-host setup**

Document the dedicated managed domain requirement, disk-image rootfs support, explicit libvirt URI, required serial readiness marker, opt-in integration command, and later-phase exclusions.

- [ ] **Step 3: Run docs/integration smoke checks**

Run:

```bash
pytest tests/test_libvirt_boot_integration.py -q
```

Expected without environment: SKIPPED with actionable missing-variable message.

## Task 9: Final Verification

**Files:**
- All changed files

- [ ] **Step 1: Run unit suite**

Run:

```bash
pytest -q
```

Expected: PASS.

- [ ] **Step 2: Run lint**

Run:

```bash
ruff check .
```

Expected: PASS.

- [ ] **Step 3: Run optional real libvirt verification**

Run only on a configured pilot host:

```bash
LINUX_DEBUG_MCP_LIBVIRT_TEST=1 \
LINUX_DEBUG_MCP_SOURCE=/path/to/linux \
LINUX_DEBUG_MCP_ROOTFS=/var/lib/linux-debug/rootfs.qcow2 \
LINUX_DEBUG_MCP_DOMAIN=mcp-linux-debug-dev \
LINUX_DEBUG_MCP_LIBVIRT_URI=qemu:///system \
LINUX_DEBUG_MCP_READINESS_MARKER=linux-debug-ready \
pytest tests/test_libvirt_boot_integration.py -q
```

Expected: PASS and artifacts under the configured test artifact root.

## Self-Review Notes

- Spec coverage: plan covers profile model, handler, provider, runner boundary, artifact layout, idempotency, safety, error mapping, capability registration, tests, integration gate, and README.
- Review hardening: the plan now requires a target/domain lock in addition to the per-run boot lock, first-boot handling for missing `dumpxml` domains, explicit provider result/error dataclasses, and a concrete stale-running recovery rule based on lock ownership.
- Placeholder scan: no task is left unresolved; each task has concrete files, tests, commands, and implementation shape.
