# Guest-IP lease discovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** After a successful default-NAT boot, `target.run_tests` SSHes to the guest's DHCP-leased IP with no hand-set address, by discovering it in the boot provider and overriding a loopback/unset `ssh_host` in the run_tests handler.

**Architecture:** The `LibvirtQemuProvider` polls `virsh domifaddr --source lease` on the success branch (gated on an SSH-relevant rootfs profile), parses the first routable IPv4 with a pure total function, and surfaces `guest_ip` + `guest_ip_discovery` on the boot result `details`. `target_run_tests_handler` reads the persisted `guest_ip`, re-validates it, and substitutes it for `ssh_host` only when the configured host is unset or loopback. The override is in-memory; the manifest stays immutable.

**Tech Stack:** Python 3.11+, Pydantic v2 (`RootfsProfile.model_copy`), `ipaddress` stdlib, pytest. Spec: `docs/specs/2026-05-30-guest-ip-lease-discovery.md`. ADR: `docs/adr/0032-guest-ip-lease-discovery.md`.

---

## File Structure

- `src/linux_debug_mcp/providers/libvirt_qemu.py` — add `parse_domifaddr_ipv4` (module fn), extend the `LibvirtRunner` Protocol docs only via `run()` reuse (no new method), add `BootPlan.domifaddr_argv` + `BootPlan.discover_guest_ip`, add poll/sleep params to `LibvirtQemuProvider.__init__`, add `_discover_guest_ip` helper called from `execute_boot`'s success branch.
- `src/linux_debug_mcp/server.py` — add `_ssh_host_is_unset_or_loopback` + `_validated_guest_ip` module helpers, apply the override in `target_run_tests_handler` after `resolved_rootfs_profile` resolution.
- `tests/test_libvirt_qemu_provider.py` — parser unit tests + `execute_boot` discovery tests (extend `FakeLibvirtRunner` to answer `domifaddr`).
- `tests/test_target_run_tests_handler.py` — handler override tests.
- `tests/test_server_ssh_host_override.py` (new) — `_ssh_host_is_unset_or_loopback` / `_validated_guest_ip` truth-table unit tests.

---

## Task 1: `parse_domifaddr_ipv4` pure parser

**Files:**
- Modify: `src/linux_debug_mcp/providers/libvirt_qemu.py` (add module-level function after the imports / constants, before `GdbstubEndpoint`)
- Test: `tests/test_libvirt_qemu_provider.py`

- [ ] **Step 1: Write the failing tests**

Add at the end of `tests/test_libvirt_qemu_provider.py`:

```python
from linux_debug_mcp.providers.libvirt_qemu import parse_domifaddr_ipv4

_DOMIFADDR_SINGLE = """\
 Name       MAC address          Protocol     Address
-------------------------------------------------------------------------------
 vnet0      52:54:00:1a:2b:3c    ipv4         192.168.122.45/24
"""

_DOMIFADDR_IPV6_THEN_IPV4 = """\
 Name       MAC address          Protocol     Address
-------------------------------------------------------------------------------
 vnet0      52:54:00:1a:2b:3c    ipv6         fe80::5054:ff:fe1a:2b3c/64
 vnet0      52:54:00:1a:2b:3c    ipv4         192.168.122.50/24
"""

_DOMIFADDR_HEADERS_ONLY = """\
 Name       MAC address          Protocol     Address
-------------------------------------------------------------------------------
"""

_DOMIFADDR_LOOPBACK_ONLY = """\
 Name       MAC address          Protocol     Address
-------------------------------------------------------------------------------
 lo         00:00:00:00:00:00    ipv4         127.0.0.1/8
"""

_DOMIFADDR_LINKLOCAL_THEN_ROUTABLE = """\
 Name       MAC address          Protocol     Address
-------------------------------------------------------------------------------
 vnet0      52:54:00:1a:2b:3c    ipv4         169.254.3.4/16
 vnet1      52:54:00:1a:2b:3d    ipv4         192.168.122.77/24
"""


def test_parse_domifaddr_single_ipv4() -> None:
    assert parse_domifaddr_ipv4(_DOMIFADDR_SINGLE) == "192.168.122.45"


def test_parse_domifaddr_prefers_ipv4_over_ipv6() -> None:
    assert parse_domifaddr_ipv4(_DOMIFADDR_IPV6_THEN_IPV4) == "192.168.122.50"


def test_parse_domifaddr_headers_only_returns_none() -> None:
    assert parse_domifaddr_ipv4(_DOMIFADDR_HEADERS_ONLY) is None


def test_parse_domifaddr_empty_returns_none() -> None:
    assert parse_domifaddr_ipv4("") is None


def test_parse_domifaddr_skips_loopback() -> None:
    assert parse_domifaddr_ipv4(_DOMIFADDR_LOOPBACK_ONLY) is None


def test_parse_domifaddr_skips_linklocal_takes_routable() -> None:
    assert parse_domifaddr_ipv4(_DOMIFADDR_LINKLOCAL_THEN_ROUTABLE) == "192.168.122.77"


def test_parse_domifaddr_malformed_rows_are_skipped() -> None:
    assert parse_domifaddr_ipv4("garbage\nipv4 not-an-ip\n   \n") is None
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run python -m pytest tests/test_libvirt_qemu_provider.py -k parse_domifaddr -q`
Expected: FAIL with `ImportError: cannot import name 'parse_domifaddr_ipv4'`.

- [ ] **Step 3: Write the implementation**

Add to `src/linux_debug_mcp/providers/libvirt_qemu.py` after the `import` block / namespace registration and before `class GdbstubEndpoint`:

```python
import ipaddress


def parse_domifaddr_ipv4(output: str) -> str | None:
    """Return the first routable IPv4 address from ``virsh domifaddr`` output.

    Scans the tabular rows, keeps rows whose protocol column is ``ipv4``, strips the
    ``/prefix`` from the address, and returns the first address that is not loopback,
    link-local, or unspecified. Total: malformed/short rows are skipped, never raised.
    Returns ``None`` when no routable IPv4 row is present.
    """
    for line in output.splitlines():
        columns = line.split()
        if len(columns) < 4:
            continue
        protocol, address_field = columns[2], columns[3]
        if protocol != "ipv4":
            continue
        candidate = address_field.split("/", maxsplit=1)[0]
        try:
            parsed = ipaddress.IPv4Address(candidate)
        except ipaddress.AddressValueError:
            continue
        if parsed.is_loopback or parsed.is_link_local or parsed.is_unspecified:
            continue
        return str(parsed)
    return None
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run python -m pytest tests/test_libvirt_qemu_provider.py -k parse_domifaddr -q`
Expected: PASS (7 tests).

- [ ] **Step 5: Commit**

```bash
git add src/linux_debug_mcp/providers/libvirt_qemu.py tests/test_libvirt_qemu_provider.py
git commit -m "feat(boot): add parse_domifaddr_ipv4 lease parser

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 2: `BootPlan` carries `domifaddr_argv` + `discover_guest_ip`

**Files:**
- Modify: `src/linux_debug_mcp/providers/libvirt_qemu.py` (`BootPlan` dataclass fields; `plan_boot` to set them)
- Test: `tests/test_libvirt_qemu_provider.py`

- [ ] **Step 1: Write the failing test**

Add to `tests/test_libvirt_qemu_provider.py`:

```python
def test_plan_boot_sets_domifaddr_argv_and_discovery_gate(tmp_path: Path) -> None:
    kernel, rootfs, run_dir = make_inputs(tmp_path)
    provider = LibvirtQemuProvider()

    plan = provider.plan_boot(
        run_id="run-abc123",
        run_dir=run_dir,
        kernel_image_path=kernel,
        target_profile=target_profile(),
        rootfs_profile=rootfs_profile(rootfs),  # default access_method="ssh"
    )

    assert plan.domifaddr_argv == [
        "virsh", "-c", "qemu:///system", "domifaddr", "debug-vm", "--source", "lease",
    ]
    assert plan.discover_guest_ip is True


def test_plan_boot_disables_discovery_for_serial_only_profile(tmp_path: Path) -> None:
    kernel, rootfs, run_dir = make_inputs(tmp_path)
    provider = LibvirtQemuProvider()
    profile = RootfsProfile(
        name="minimal",
        source=str(rootfs),
        access_method="serial",
        readiness_marker="linux-debug-mcp-ready",
    )

    plan = provider.plan_boot(
        run_id="run-abc123",
        run_dir=run_dir,
        kernel_image_path=kernel,
        target_profile=target_profile(),
        rootfs_profile=profile,
    )

    assert plan.discover_guest_ip is False
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run python -m pytest tests/test_libvirt_qemu_provider.py -k "domifaddr_argv or serial_only_profile" -q`
Expected: FAIL with `AttributeError: 'BootPlan' object has no attribute 'domifaddr_argv'`.

- [ ] **Step 3: Implement**

In `BootPlan` (the `@dataclass(frozen=True)`), add two fields at the end of the field list:

```python
    domifaddr_argv: list[str]
    discover_guest_ip: bool
```

In `plan_boot`, just before `return BootPlan(`, the `virsh_prefix` is already computed. Add to the `BootPlan(...)` constructor call (alongside the other `*_argv` entries):

```python
            domifaddr_argv=[*virsh_prefix, "domifaddr", domain_name, "--source", "lease"],
            discover_guest_ip=rootfs_profile.access_method in {"ssh", "ssh_and_serial"},
```

- [ ] **Step 4: Run to verify it passes**

Run: `uv run python -m pytest tests/test_libvirt_qemu_provider.py -k "domifaddr_argv or serial_only_profile" -q`
Expected: PASS (2 tests).

- [ ] **Step 5: Run the full provider test module (no regressions)**

Run: `uv run python -m pytest tests/test_libvirt_qemu_provider.py -q`
Expected: PASS (existing tests that build a `BootPlan` directly, if any, are via `plan_boot`, so they pick up the new fields automatically). If any test constructs `BootPlan(...)` literally, add the two new fields there.

- [ ] **Step 6: Commit**

```bash
git add src/linux_debug_mcp/providers/libvirt_qemu.py tests/test_libvirt_qemu_provider.py
git commit -m "feat(boot): plan domifaddr argv and SSH-gated discovery flag

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 3: Provider poll + surface `guest_ip` on success

**Files:**
- Modify: `src/linux_debug_mcp/providers/libvirt_qemu.py` (`LibvirtQemuProvider.__init__`, new `_discover_guest_ip`, call site in `execute_boot` success branch)
- Test: `tests/test_libvirt_qemu_provider.py` (extend `FakeLibvirtRunner` to answer `domifaddr`)

- [ ] **Step 1: Extend `FakeLibvirtRunner` and write the failing tests**

In `tests/test_libvirt_qemu_provider.py`, extend `FakeLibvirtRunner.__init__` to accept a `domifaddr` queue and dispatch it in `run`. Add to `__init__` params: `domifaddr: list[CommandResult] | None = None`. In `__init__` body:

```python
        self.domifaddr_results = list(domifaddr) if domifaddr is not None else [
            CommandResult(
                ["virsh", "domifaddr"],
                0,
                stdout=(
                    " Name   MAC address          Protocol     Address\n"
                    "----------------------------------------------------\n"
                    " vnet0  52:54:00:1a:2b:3c    ipv4         192.168.122.45/24\n"
                ),
            )
        ]
        self.domifaddr_calls: list[dict[str, object]] = []
```

In `run`, before the final `raise AssertionError`, add an `action == "domifaddr"` branch:

```python
        if action == "domifaddr":
            self.domifaddr_calls.append({"argv": argv, "timeout": timeout})
            if self.domifaddr_results:
                return self.domifaddr_results.pop(0)
            return CommandResult(argv, 0, stdout="")
```

Add a fake sleep recorder used by the new tests:

```python
class SleepRecorder:
    def __init__(self) -> None:
        self.calls: list[float] = []

    def __call__(self, seconds: float) -> None:
        self.calls.append(seconds)
```

Now the tests:

```python
def test_execute_boot_surfaces_guest_ip_on_success(tmp_path: Path) -> None:
    plan = make_plan(tmp_path)  # default rootfs access_method="ssh" -> discover_guest_ip True
    runner = FakeLibvirtRunner()
    provider = LibvirtQemuProvider(runner=runner, sleep=SleepRecorder())

    result = provider.execute_boot(plan)

    assert result.status == StepStatus.SUCCEEDED
    assert result.details["guest_ip"] == "192.168.122.45"
    assert result.details["guest_ip_discovery"]["status"] == "found"
    assert any(call["argv"] == plan.domifaddr_argv for call in runner.domifaddr_calls)


def test_execute_boot_uses_call_timeout_not_boot_timeout(tmp_path: Path) -> None:
    plan = make_plan(tmp_path)
    runner = FakeLibvirtRunner()
    provider = LibvirtQemuProvider(runner=runner, sleep=SleepRecorder(), lease_discovery_call_timeout=5)

    provider.execute_boot(plan)

    domifaddr_call = next(c for c in runner.domifaddr_calls if c["argv"] == plan.domifaddr_argv)
    assert domifaddr_call["timeout"] == 5
    assert domifaddr_call["timeout"] != plan.timeout_seconds


def test_execute_boot_polls_until_lease_found(tmp_path: Path) -> None:
    plan = make_plan(tmp_path)
    empty = CommandResult(["virsh", "domifaddr"], 0, stdout="")
    found = CommandResult(
        ["virsh", "domifaddr"], 0,
        stdout=" vnet0  52:54:00:1a:2b:3c    ipv4    192.168.122.9/24\n",
    )
    runner = FakeLibvirtRunner(domifaddr=[empty, empty, found])
    sleeper = SleepRecorder()
    provider = LibvirtQemuProvider(
        runner=runner, sleep=sleeper, lease_discovery_attempts=8, lease_discovery_interval=1.0
    )

    result = provider.execute_boot(plan)

    assert result.details["guest_ip"] == "192.168.122.9"
    assert len(runner.domifaddr_calls) == 3
    assert sleeper.calls == [1.0, 1.0]  # slept between the 3 attempts, not after the success


def test_execute_boot_no_lease_after_poll(tmp_path: Path) -> None:
    plan = make_plan(tmp_path)
    empty = CommandResult(["virsh", "domifaddr"], 0, stdout="")
    runner = FakeLibvirtRunner(domifaddr=[empty, empty])
    sleeper = SleepRecorder()
    provider = LibvirtQemuProvider(
        runner=runner, sleep=sleeper, lease_discovery_attempts=2, lease_discovery_interval=0.5
    )

    result = provider.execute_boot(plan)

    assert result.status == StepStatus.SUCCEEDED
    assert result.details["guest_ip"] is None
    assert result.details["guest_ip_discovery"]["status"] == "no_lease"
    assert len(runner.domifaddr_calls) == 2
    assert sleeper.calls == [0.5]  # attempts-1 sleeps


def test_execute_boot_domifaddr_failure_is_unavailable(tmp_path: Path) -> None:
    plan = make_plan(tmp_path)
    failure = CommandResult(["virsh", "domifaddr"], 1, stderr="error: Domain not found\n")
    runner = FakeLibvirtRunner(domifaddr=[failure])
    provider = LibvirtQemuProvider(runner=runner, sleep=SleepRecorder(), lease_discovery_attempts=8)

    result = provider.execute_boot(plan)

    assert result.status == StepStatus.SUCCEEDED
    assert result.details["guest_ip"] is None
    assert result.details["guest_ip_discovery"]["status"] == "unavailable"
    assert len(runner.domifaddr_calls) == 1  # non-zero exit stops the poll immediately


def test_execute_boot_skips_discovery_for_serial_profile(tmp_path: Path) -> None:
    plan = make_plan(tmp_path)
    plan = replace(plan, discover_guest_ip=False)
    runner = FakeLibvirtRunner()
    provider = LibvirtQemuProvider(runner=runner, sleep=SleepRecorder())

    result = provider.execute_boot(plan)

    assert result.status == StepStatus.SUCCEEDED
    assert result.details["guest_ip"] is None
    assert result.details["guest_ip_discovery"]["status"] == "skipped"
    assert runner.domifaddr_calls == []


def test_execute_boot_timeout_skips_discovery(tmp_path: Path) -> None:
    plan = make_plan(tmp_path)
    timeout_console = ConsoleResult(
        status="timeout", matched_marker=None, snippet="...",
        started_at=datetime(2026, 1, 1, tzinfo=UTC), ended_at=datetime(2026, 1, 1, tzinfo=UTC),
    )
    runner = FakeLibvirtRunner(console=timeout_console)
    provider = LibvirtQemuProvider(runner=runner, sleep=SleepRecorder())

    result = provider.execute_boot(plan)

    assert result.status == StepStatus.FAILED
    assert "guest_ip" not in result.details
    assert runner.domifaddr_calls == []
```

Add `from dataclasses import replace` to the test imports (top of file).

- [ ] **Step 2: Run to verify they fail**

Run: `uv run python -m pytest tests/test_libvirt_qemu_provider.py -k "guest_ip or call_timeout or polls_until or no_lease or unavailable or skips_discovery or timeout_skips" -q`
Expected: FAIL — `LibvirtQemuProvider.__init__` rejects `sleep=` (unexpected kwarg) / `guest_ip` not in details.

- [ ] **Step 3: Implement the provider changes**

Update `LibvirtQemuProvider.__init__` (currently `def __init__(self, *, runner=None)`):

```python
    def __init__(
        self,
        *,
        runner: LibvirtRunner | None = None,
        sleep: Callable[[float], None] = time.sleep,
        lease_discovery_attempts: int = 8,
        lease_discovery_interval: float = 1.0,
        lease_discovery_call_timeout: int = 5,
    ) -> None:
        self.runner = runner or SubprocessLibvirtRunner()
        self._sleep = sleep
        self._lease_discovery_attempts = lease_discovery_attempts
        self._lease_discovery_interval = lease_discovery_interval
        self._lease_discovery_call_timeout = lease_discovery_call_timeout
```

Add `from collections.abc import Callable` to the imports (top of `libvirt_qemu.py`); `time` is already imported.

Add the discovery helper to the class:

```python
    def _discover_guest_ip(self, plan: BootPlan) -> dict[str, object]:
        """Best-effort guest-IP discovery from the libvirt lease (ADR 0032).

        Never raises: any failure resolves to a typed status. Polls
        ``virsh domifaddr --source lease`` up to ``lease_discovery_attempts`` times,
        sleeping ``lease_discovery_interval`` between attempts, stopping at the first
        routable IPv4. A non-zero ``domifaddr`` exit stops the poll immediately.
        """
        if not plan.discover_guest_ip:
            return {"guest_ip": None, "guest_ip_discovery": {"status": "skipped", "source": "lease"}}
        for attempt in range(self._lease_discovery_attempts):
            result = self.runner.run(
                plan.domifaddr_argv,
                timeout=self._lease_discovery_call_timeout,
                log_path=plan.boot_log_path,
            )
            if result.exit_status != 0 or result.timed_out:
                detail = (result.stderr or result.stdout or "").strip()[:512]
                return {
                    "guest_ip": None,
                    "guest_ip_discovery": {"status": "unavailable", "source": "lease", "detail": detail},
                }
            guest_ip = parse_domifaddr_ipv4(result.stdout)
            if guest_ip is not None:
                return {
                    "guest_ip": guest_ip,
                    "guest_ip_discovery": {"status": "found", "source": "lease"},
                }
            if attempt < self._lease_discovery_attempts - 1:
                self._sleep(self._lease_discovery_interval)
        return {"guest_ip": None, "guest_ip_discovery": {"status": "no_lease", "source": "lease"}}
```

In `execute_boot`, the success branch is the `if console.status == "ready":` block (libvirt_qemu.py ~511). Merge discovery into `details` before the success return. Replace:

```python
        if console.status == "ready":
            return self._boot_result(
                plan=plan,
                status=StepStatus.SUCCEEDED,
                summary="target booted and reported readiness",
                details=details,
                artifacts=self._existing_artifacts(artifacts),
            )
```

with:

```python
        if console.status == "ready":
            details.update(self._discover_guest_ip(plan))
            return self._boot_result(
                plan=plan,
                status=StepStatus.SUCCEEDED,
                summary="target booted and reported readiness",
                details=details,
                artifacts=self._existing_artifacts(artifacts),
            )
```

(The failure branches below do not call `_discover_guest_ip`, satisfying "discovery skipped on timeout/readiness-failure".)

- [ ] **Step 4: Run the new tests**

Run: `uv run python -m pytest tests/test_libvirt_qemu_provider.py -k "guest_ip or call_timeout or polls_until or no_lease or unavailable or skips_discovery or timeout_skips" -q`
Expected: PASS (7 tests).

- [ ] **Step 5: Run the full provider module**

Run: `uv run python -m pytest tests/test_libvirt_qemu_provider.py -q`
Expected: PASS. The existing `test_execute_boot_success_*` tests now also exercise `_discover_guest_ip` via the default `FakeLibvirtRunner` (returns a lease), and they assert on `kernel_args`/artifacts which are unaffected. If any pre-existing success test asserts an exact `details` dict equality, relax it to subset checks (it will now also carry `guest_ip`).

- [ ] **Step 6: Commit**

```bash
git add src/linux_debug_mcp/providers/libvirt_qemu.py tests/test_libvirt_qemu_provider.py
git commit -m "feat(boot): discover guest IP from libvirt lease on success

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 4: `_ssh_host_is_unset_or_loopback` + `_validated_guest_ip` helpers

**Files:**
- Modify: `src/linux_debug_mcp/server.py` (two module-level helpers near the other `_`-prefixed helpers)
- Test: `tests/test_server_ssh_host_override.py` (new)

- [ ] **Step 1: Write the failing tests**

Create `tests/test_server_ssh_host_override.py`:

```python
import pytest

from linux_debug_mcp.server import _ssh_host_is_unset_or_loopback, _validated_guest_ip


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        (None, True),
        ("", True),
        ("   ", True),
        ("127.0.0.1", True),
        ("127.0.0.2", True),
        ("::1", True),
        ("localhost", True),
        ("LocalHost", True),
        ("192.168.122.45", False),
        ("10.0.0.5", False),
        ("bastion.example", False),
    ],
)
def test_ssh_host_is_unset_or_loopback(host: str | None, expected: bool) -> None:
    assert _ssh_host_is_unset_or_loopback(host) is expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("192.168.122.45", "192.168.122.45"),
        ("10.0.0.5", "10.0.0.5"),
        (None, None),
        ("", None),
        ("127.0.0.1", None),       # loopback rejected
        ("169.254.1.2", None),     # link-local rejected
        ("not-an-ip", None),       # non-IP rejected
        ("192.168.122.45; rm -rf", None),  # injected token rejected
        (12345, None),             # non-str rejected
    ],
)
def test_validated_guest_ip(value: object, expected: str | None) -> None:
    assert _validated_guest_ip(value) == expected
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run python -m pytest tests/test_server_ssh_host_override.py -q`
Expected: FAIL with `ImportError: cannot import name '_ssh_host_is_unset_or_loopback'`.

- [ ] **Step 3: Implement the helpers**

In `src/linux_debug_mcp/server.py`, ensure `import ipaddress` is present (add to the stdlib import group if missing). Add near the other module-level `_`-helpers (e.g. just above `target_run_tests_handler`):

```python
def _ssh_host_is_unset_or_loopback(host: str | None) -> bool:
    """True when ``host`` is unset/empty, ``localhost``, or a loopback IP (ADR 0032 d6).

    Any other value — a routable IP or a non-IP DNS name — is a deliberate operator
    override and returns False so it is preserved.
    """
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
    """Return a routable IP string from an untrusted persisted ``guest_ip`` or None (ADR 0032 d7).

    Re-validates the on-disk value before it can reach an SSH argv: rejects non-strings,
    non-IP text, and loopback/link-local/unspecified addresses, keeping the SSH target
    injection-free even if the manifest was corrupted between boot and test.
    """
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = ipaddress.ip_address(value.strip())
    except ValueError:
        return None
    if parsed.is_loopback or parsed.is_link_local or parsed.is_unspecified:
        return None
    return str(parsed)
```

- [ ] **Step 4: Run to verify it passes**

Run: `uv run python -m pytest tests/test_server_ssh_host_override.py -q`
Expected: PASS (20 parametrized cases).

- [ ] **Step 5: Commit**

```bash
git add src/linux_debug_mcp/server.py tests/test_server_ssh_host_override.py
git commit -m "feat(server): add ssh_host loopback + guest_ip validation helpers

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 5: Apply the override in `target_run_tests_handler`

**Files:**
- Modify: `src/linux_debug_mcp/server.py` (`target_run_tests_handler`, after `resolved_rootfs_profile` is resolved and before `provider.plan_tests`)
- Test: `tests/test_target_run_tests_handler.py`

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_target_run_tests_handler.py`. Use a helper that records a boot StepResult carrying `guest_ip` details (the `create_booted_run` helper records boot with no details, so overwrite it):

```python
from linux_debug_mcp.providers.local_ssh_tests import TestExecutionResult


def _set_boot_guest_ip(artifact_root: Path, guest_ip: str | None, *, run_id: str = "run-abc123") -> None:
    store = ArtifactStore(artifact_root, create_root=False)
    store.record_step_result(
        run_id,
        StepResult(
            step_name="boot",
            status=StepStatus.SUCCEEDED,
            summary="boot ok",
            details={"guest_ip": guest_ip, "guest_ip_discovery": {"status": "found"}},
        ),
        replace_succeeded=True,
    )


def test_run_tests_overrides_loopback_ssh_host_with_guest_ip(tmp_path: Path) -> None:
    artifact_root = create_booted_run(tmp_path)
    _set_boot_guest_ip(artifact_root, "192.168.122.45")
    provider = FakeTestProvider()

    response = target_run_tests_handler(
        artifact_root=artifact_root,
        run_id="run-abc123",
        provider=provider,
        rootfs_profiles={"minimal": rootfs(tmp_path)},  # ssh_host="127.0.0.1"
        test_suites=suites(),
    )

    assert response.ok is True
    assert provider.planned_rootfs.ssh_host == "192.168.122.45"


def test_run_tests_preserves_explicit_non_loopback_ssh_host(tmp_path: Path) -> None:
    artifact_root = create_booted_run(tmp_path)
    _set_boot_guest_ip(artifact_root, "192.168.122.45")
    provider = FakeTestProvider()
    explicit = RootfsProfile(
        name="minimal", source=str(tmp_path / "rootfs.qcow2"),
        access_method="ssh", ssh_host="203.0.113.7", ssh_user="root",
    )

    response = target_run_tests_handler(
        artifact_root=artifact_root,
        run_id="run-abc123",
        provider=provider,
        rootfs_profiles={"minimal": explicit},
        test_suites=suites(),
    )

    assert response.ok is True
    assert provider.planned_rootfs.ssh_host == "203.0.113.7"


def test_run_tests_ignores_invalid_persisted_guest_ip(tmp_path: Path) -> None:
    artifact_root = create_booted_run(tmp_path)
    _set_boot_guest_ip(artifact_root, "127.0.0.1")  # fails re-validation
    provider = FakeTestProvider()

    response = target_run_tests_handler(
        artifact_root=artifact_root,
        run_id="run-abc123",
        provider=provider,
        rootfs_profiles={"minimal": rootfs(tmp_path)},  # ssh_host="127.0.0.1"
        test_suites=suites(),
    )

    assert response.ok is True
    assert provider.planned_rootfs.ssh_host == "127.0.0.1"  # original preserved


def test_run_tests_no_guest_ip_is_noop(tmp_path: Path) -> None:
    artifact_root = create_booted_run(tmp_path)
    _set_boot_guest_ip(artifact_root, None)
    provider = FakeTestProvider()

    response = target_run_tests_handler(
        artifact_root=artifact_root,
        run_id="run-abc123",
        provider=provider,
        rootfs_profiles={"minimal": rootfs(tmp_path)},
        test_suites=suites(),
    )

    assert response.ok is True
    assert provider.planned_rootfs.ssh_host == "127.0.0.1"
```

- [ ] **Step 2: Run to verify they fail**

Run: `uv run python -m pytest tests/test_target_run_tests_handler.py -k "guest_ip or explicit_non_loopback or invalid_persisted" -q`
Expected: FAIL — `test_run_tests_overrides_loopback_ssh_host_with_guest_ip` asserts `192.168.122.45` but gets `127.0.0.1` (override not yet wired).

- [ ] **Step 3: Implement the override**

In `target_run_tests_handler`, locate the block that resolves `resolved_rootfs_profile` (the `if manifest.boot_attempts: ... elif ... else:` chain, server.py ~2082-2098) and the following `try: suite_profile = ...`. Immediately after `resolved_rootfs_profile` is fully resolved (after that if/elif/else, before `suite_profile` resolution), insert:

```python
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
```

(`boot_result` is already bound earlier in the handler at server.py:2061; `logger` is the module logger already used in this file.)

- [ ] **Step 4: Run to verify they pass**

Run: `uv run python -m pytest tests/test_target_run_tests_handler.py -k "guest_ip or explicit_non_loopback or invalid_persisted" -q`
Expected: PASS (5 tests).

- [ ] **Step 5: Run the full handler module (no regressions)**

Run: `uv run python -m pytest tests/test_target_run_tests_handler.py -q`
Expected: PASS. Existing tests use `rootfs(tmp_path)` (ssh_host="127.0.0.1") and a boot StepResult with no details, so `boot_details.get("guest_ip")` is None → the override is a no-op and behavior is unchanged.

- [ ] **Step 6: Commit**

```bash
git add src/linux_debug_mcp/server.py tests/test_target_run_tests_handler.py
git commit -m "feat(server): override loopback ssh_host with discovered guest IP

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 6: Full guardrails + workflow regression sweep

**Files:** none (verification only)

- [ ] **Step 1: Lint + format**

Run: `uv run ruff check && uv run ruff format --check`
Expected: no errors. If `ruff format --check` reports diffs, run `uv run ruff format` and re-stage.

- [ ] **Step 2: Type check (hard-gating)**

Run: `uv run ty check src`
Expected: no errors. Common fixes: ensure `Callable` import, `dict[str, object]` return annotations on the new helpers, and that `_discover_guest_ip` returns the exact dict shape.

- [ ] **Step 3: Full test suite**

Run: `uv run python -m pytest -q`
Expected: PASS (the env-gated `test_libvirt_boot_integration.py` / `test_qemu_gdbstub_integration.py` skip without `virsh`/`gdb` — that is expected). Pay attention to `tests/test_workflow_build_boot_test_handler.py` and `tests/test_server_boot_snapshot_producer.py`: they drive boot → run_tests end to end with a `FakeLibvirtRunner`; the default fake now returns a lease so boot details gain `guest_ip`. If a workflow test asserts an exact boot `details` equality, relax to a subset/`>=` check.

- [ ] **Step 4: Final commit if any fixups were needed**

```bash
git add -A
git commit -m "test: stabilize boot/run_tests suites for guest_ip details

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

(Skip if Steps 1-3 produced no changes.)

---

## Self-review notes

- **Spec coverage:** parser (Task 1, spec §1), plan argv + SSH gate (Task 2, spec §1/§3), poll + statuses found/no_lease/unavailable/skipped + call-timeout + sleep seam (Task 3, spec §1-§3 + failure contract), loopback/unset helper + re-validation (Task 4, spec §4/§4a), run_tests override + preserve-explicit + ignore-invalid + no-op (Task 5, spec §4/§4a + failure contract), guardrails + workflow regressions (Task 6, spec Verification).
- **No wire-model change:** `guest_ip`/`guest_ip_discovery` ride `StepResult.details`; no `domain.py` edit, no JSON-schema snapshot regeneration (spec "Affected code").
- **Type consistency:** `parse_domifaddr_ipv4(str) -> str | None`, `_validated_guest_ip(object) -> str | None`, `_ssh_host_is_unset_or_loopback(str | None) -> bool`, `_discover_guest_ip(BootPlan) -> dict[str, object]`, `BootPlan.domifaddr_argv: list[str]`, `BootPlan.discover_guest_ip: bool` — names match across tasks.
- **Lease staleness** is documented in the spec; no code path trusts freshness — the override is best-effort and the connect failure is the recovery signal (no task needed; behavioral, covered by the no-op/preserve tests).
