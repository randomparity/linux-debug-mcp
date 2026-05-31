# Unprivileged Tooling Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `just rootfs` and the permission preflight run as a regular user with no host-side privilege escalation, producing a bootable whole-disk-ext4 rootfs and reporting real KVM/libvirt/build-toolchain capability.

**Architecture:** Rewrite `scripts/build-rootfs.sh` into two unprivileged libguestfs stages (`virt-builder` customize → `virt-tar-out` + `virt-make-fs --type=ext4` repack, with `/etc/fstab` normalization and a `chmod 0644`). Add three pure capability checks to `prereqs/checks.py` wired through the existing `host.check_prerequisites` handler. Add a static `check-no-sudo` guard (just recipe + pytest + CI job). Add a two-tier env-gated integration test. Rewrite the user guide §5.

**Tech Stack:** Bash (shellcheck/shfmt), Python 3.11+ (pytest, ruff, ty), libguestfs (`virt-builder`/`virt-tar-out`/`virt-make-fs`/`guestfish`), just, GitHub Actions.

**Source of truth:** `docs/superpowers/specs/2026-05-30-unprivileged-tooling-design.md` and `docs/adr/0037-unprivileged-tooling.md`. Read both before starting.

**Ground-truth references (verify still current before editing):**
- Boot provider whole-disk contract: `src/kdive/providers/libvirt_qemu.py:321` (`root_device = "/dev/vda"`), `:744` (appends `root=`), `:778` (rejects other `root=`), `:667` (whole-disk `vda`), `:658-661` (no `<initrd>`), `:645-688` (`render_domain_xml`, no base seclabel/chown).
- Default rootfs profile: `src/kdive/server.py:294-305` (`minimal.source = /var/lib/kdive/rootfs/minimal.qcow2`).
- Debug build pins virtio-blk: `src/kdive/server.py:255-273`.
- Preflight patterns to mirror: `src/kdive/prereqs/checks.py` (`check_gdbstub_port` advisory + injected probe `:450-504`; `check_rootfs_image` SKIPPED pattern `:377-409`; `_libvirt_check` `:278-321`).
- Handler wiring: `src/kdive/server.py:1263-1296` (`prerequisites_handler`), `:8757-8773` (tool wrapper).
- Test conventions: `tests/test_prereqs.py` (`FakeRunner`, no `conftest.py`); `tests/test_libvirt_boot_integration.py:1-60` (env-gated skip pattern).
- CI guard job pattern: `.github/workflows/ci.yml:86-106` (`docs` / `ipmi-policy` jobs).

---

## File Structure

- `src/kdive/prereqs/checks.py` — **modify**: add `DEFAULT_LIBVIRT_URI`, `_default_kvm_probe`, `check_kvm_access`, `check_libvirt_connect`, `check_rootfs_builder`.
- `src/kdive/server.py` — **modify**: import the three checks + `SubprocessPrerequisiteRunner`; thread `runner`/`kvm_probe` through `prerequisites_handler` and append the three checks.
- `tests/test_prereqs.py` — **modify**: add unit tests for the three checks and the handler wiring.
- `scripts/build-rootfs.sh` — **rewrite**: two-stage unprivileged build, no sudo, fstab normalization, `chmod 0644`.
- `justfile` — **modify**: add `check-no-sudo` recipe.
- `tests/test_no_privilege_escalation.py` — **create**: mirror the guard as pytest.
- `.github/workflows/ci.yml` — **modify**: add a `no-sudo` job.
- `tests/test_unprivileged_build_integration.py` — **create**: Tier 1 (layout, no KVM) + Tier 2 (full boot).
- `docs/fedora-libvirt-user-guide.md` — **modify**: rewrite §5 to the sudo-free flow + document the 0644 + `virt_image_t` base-image requirement.

---

## Task 1: `check_rootfs_builder` — verify the unprivileged toolchain

**Files:**
- Modify: `src/kdive/prereqs/checks.py`
- Test: `tests/test_prereqs.py`

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_prereqs.py` (it already imports from `kdive.prereqs.checks` and defines `FakeRunner`):

```python
def test_rootfs_builder_passes_when_toolchain_present() -> None:
    from kdive.prereqs.checks import check_rootfs_builder

    check = check_rootfs_builder(runner=FakeRunner({"virt-builder", "qemu-img"}))
    assert check.check_id == "rootfs.builder"
    assert check.status == "passed"


def test_rootfs_builder_fails_naming_libguestfs_tools_when_virt_builder_missing() -> None:
    from kdive.prereqs.checks import check_rootfs_builder

    check = check_rootfs_builder(runner=FakeRunner({"qemu-img"}))
    assert check.status == "failed"
    assert "libguestfs-tools" in (check.suggested_fix or "")


def test_rootfs_builder_fails_when_qemu_img_missing() -> None:
    from kdive.prereqs.checks import check_rootfs_builder

    check = check_rootfs_builder(runner=FakeRunner({"virt-builder"}))
    assert check.status == "failed"
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run python -m pytest tests/test_prereqs.py -k rootfs_builder -q`
Expected: FAIL with `ImportError: cannot import name 'check_rootfs_builder'`.

- [ ] **Step 3: Implement `check_rootfs_builder`**

Append to `src/kdive/prereqs/checks.py` (after `check_gdbstub_port`):

```python
def check_rootfs_builder(*, runner: PrerequisiteRunner | None = None) -> PrerequisiteCheck:
    """Report whether the unprivileged rootfs build toolchain is present.

    The rewritten ``scripts/build-rootfs.sh`` builds entirely inside libguestfs, so it needs
    ``virt-builder`` and ``qemu-img`` and explicitly does not need ``dnf`` or ``sudo``.
    """
    runner = runner or SubprocessPrerequisiteRunner()
    missing = [tool for tool in ("virt-builder", "qemu-img") if runner.which(tool) is None]
    if missing:
        return PrerequisiteCheck(
            check_id="rootfs.builder",
            status=PrerequisiteStatus.FAILED,
            message=f"unprivileged build toolchain incomplete: missing {', '.join(missing)}",
            suggested_fix="Install libguestfs-tools (provides virt-builder, virt-make-fs, qemu-img).",
        )
    return PrerequisiteCheck(
        check_id="rootfs.builder",
        status=PrerequisiteStatus.PASSED,
        message="virt-builder and qemu-img are present",
    )
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `uv run python -m pytest tests/test_prereqs.py -k rootfs_builder -q`
Expected: 3 passed.

- [ ] **Step 5: Commit**

```bash
git add src/kdive/prereqs/checks.py tests/test_prereqs.py
git commit -m "feat(prereqs): add rootfs.builder capability check"
```

---

## Task 2: `check_kvm_access` — test the device, WARNING when unusable

**Files:**
- Modify: `src/kdive/prereqs/checks.py`
- Test: `tests/test_prereqs.py`

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_prereqs.py`:

```python
def test_kvm_access_passes_when_device_usable() -> None:
    from kdive.prereqs.checks import check_kvm_access

    check = check_kvm_access(kvm_probe=lambda: True)
    assert check.check_id == "kvm.access"
    assert check.status == "passed"


def test_kvm_access_warns_when_device_unusable() -> None:
    from kdive.prereqs.checks import check_kvm_access

    check = check_kvm_access(kvm_probe=lambda: False)
    assert check.status == "warning"
    assert "kvm" in (check.suggested_fix or "").lower()
    assert "TCG" in (check.message or "")
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run python -m pytest tests/test_prereqs.py -k kvm_access -q`
Expected: FAIL with `ImportError: cannot import name 'check_kvm_access'`.

- [ ] **Step 3: Implement `_default_kvm_probe` and `check_kvm_access`**

Add `import os` to the top of `src/kdive/prereqs/checks.py` (with the other stdlib imports), then append:

```python
def _default_kvm_probe() -> bool:
    return os.access("/dev/kvm", os.R_OK | os.W_OK)


def check_kvm_access(*, kvm_probe: Callable[[], bool] | None = None) -> PrerequisiteCheck:
    """Report whether ``/dev/kvm`` is usable by the running user.

    Tests the real capability with ``os.access`` rather than ``kvm`` group membership. WARNING (not
    FAILED) when unusable: the workflow still runs under TCG (slow). The ``suggested_fix`` recommends
    ``kvm`` group membership because the stock-Fedora ``uaccess`` seat ACL is interactive-login-only
    and does not follow into the server's service/cron/non-login-SSH context.
    """
    usable = (kvm_probe or _default_kvm_probe)()
    if usable:
        return PrerequisiteCheck(
            check_id="kvm.access",
            status=PrerequisiteStatus.PASSED,
            message="/dev/kvm is readable and writable",
        )
    return PrerequisiteCheck(
        check_id="kvm.access",
        status=PrerequisiteStatus.WARNING,
        message="/dev/kvm is not usable; libguestfs/qemu fall back to TCG (functional but slow)",
        suggested_fix=(
            "Add your user to the 'kvm' group for durable access across login/service/cron contexts "
            "(the interactive uaccess seat ACL does not follow into non-login contexts)."
        ),
    )
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `uv run python -m pytest tests/test_prereqs.py -k kvm_access -q`
Expected: 2 passed.

- [ ] **Step 5: Commit**

```bash
git add src/kdive/prereqs/checks.py tests/test_prereqs.py
git commit -m "feat(prereqs): add kvm.access capability check (WARNING on unusable)"
```

---

## Task 3: `check_libvirt_connect` — prove an authenticated read connection

**Files:**
- Modify: `src/kdive/prereqs/checks.py`
- Test: `tests/test_prereqs.py`

- [ ] **Step 1: Write the failing tests**

`FakeRunner.run` in `tests/test_prereqs.py` returns `(1, "", "unsupported")` for any command except `virsh uri`. The capabilities probe needs its own runner. Add to `tests/test_prereqs.py`:

```python
class LibvirtCapabilitiesRunner(FakeRunner):
    def __init__(self, available: set[str], *, code: int, stderr: str = "") -> None:
        super().__init__(available)
        self._code = code
        self._stderr = stderr
        self.last_command: list[str] | None = None

    def run(self, command: list[str], timeout: int) -> tuple[int, str, str]:
        self.last_command = command
        return (self._code, "<capabilities/>" if self._code == 0 else "", self._stderr)


def test_libvirt_connect_skipped_without_profile() -> None:
    from kdive.prereqs.checks import check_libvirt_connect

    check = check_libvirt_connect(None)
    assert check.check_id == "libvirt.connect"
    assert check.status == "skipped"


def test_libvirt_connect_passes_and_uses_profile_uri() -> None:
    from kdive.prereqs.checks import check_libvirt_connect

    target = TargetProfile(name="t", architecture="x86_64", libvirt_uri="qemu:///session")
    runner = LibvirtCapabilitiesRunner({"virsh"}, code=0)
    check = check_libvirt_connect(target, runner=runner)
    assert check.status == "passed"
    assert runner.last_command == ["virsh", "-c", "qemu:///session", "capabilities"]


def test_libvirt_connect_defaults_uri_when_profile_unset() -> None:
    from kdive.prereqs.checks import check_libvirt_connect

    target = TargetProfile(name="t", architecture="x86_64", libvirt_uri=None)
    runner = LibvirtCapabilitiesRunner({"virsh"}, code=0)
    check_libvirt_connect(target, runner=runner)
    assert runner.last_command == ["virsh", "-c", "qemu:///system", "capabilities"]


def test_libvirt_connect_fails_distinguishes_system_and_session() -> None:
    from kdive.prereqs.checks import check_libvirt_connect

    system_target = TargetProfile(name="t", architecture="x86_64", libvirt_uri="qemu:///system")
    system = check_libvirt_connect(
        system_target, runner=LibvirtCapabilitiesRunner({"virsh"}, code=1, stderr="polkit denied")
    )
    assert system.status == "failed"
    assert "polkit" in (system.suggested_fix or "").lower()

    session_target = TargetProfile(name="t", architecture="x86_64", libvirt_uri="qemu:///session")
    session = check_libvirt_connect(
        session_target, runner=LibvirtCapabilitiesRunner({"virsh"}, code=1, stderr="failed to connect")
    )
    assert session.status == "failed"
    assert "virtqemud" in (session.suggested_fix or "")


def test_libvirt_connect_fails_when_virsh_missing() -> None:
    from kdive.prereqs.checks import check_libvirt_connect

    target = TargetProfile(name="t", architecture="x86_64", libvirt_uri="qemu:///system")
    check = check_libvirt_connect(target, runner=LibvirtCapabilitiesRunner(set(), code=0))
    assert check.status == "failed"
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run python -m pytest tests/test_prereqs.py -k libvirt_connect -q`
Expected: FAIL with `ImportError: cannot import name 'check_libvirt_connect'`.

- [ ] **Step 3: Implement `DEFAULT_LIBVIRT_URI` and `check_libvirt_connect`**

Append to `src/kdive/prereqs/checks.py`:

```python
# Matches the build-time default URI baked into DEFAULT_TARGET_PROFILES (server.py); used when a
# target profile leaves libvirt_uri unset.
DEFAULT_LIBVIRT_URI = "qemu:///system"


def check_libvirt_connect(
    target_profile: TargetProfile | None,
    *,
    runner: PrerequisiteRunner | None = None,
) -> PrerequisiteCheck:
    """Report whether an authenticated *read* connection to the profile's libvirt URI succeeds.

    Runs ``virsh -c <uri> capabilities`` — strictly more than ``virsh uri``, which only reads local
    config. Advisory only (like ``check_gdbstub_port``): it does **not** prove ``org.libvirt.unix.manage``
    (define/start), so a PASS can still be followed by a polkit denial at ``target.boot``.
    """
    if target_profile is None:
        return PrerequisiteCheck(
            check_id="libvirt.connect", status=PrerequisiteStatus.SKIPPED, message="no target profile selected"
        )
    runner = runner or SubprocessPrerequisiteRunner()
    uri = target_profile.libvirt_uri or DEFAULT_LIBVIRT_URI
    if runner.which("virsh") is None:
        return PrerequisiteCheck(
            check_id="libvirt.connect",
            status=PrerequisiteStatus.FAILED,
            message="virsh was not found",
            suggested_fix="Install libvirt client tools.",
        )
    try:
        code, _stdout, stderr = runner.run(["virsh", "-c", uri, "capabilities"], timeout=10)
    except subprocess.TimeoutExpired as exc:
        return PrerequisiteCheck(
            check_id="libvirt.connect",
            status=PrerequisiteStatus.FAILED,
            message=f"virsh capabilities timed out after {exc.timeout} seconds against {uri}",
            suggested_fix="Confirm the libvirt daemon for this URI is running and responsive.",
        )
    except OSError as exc:
        return PrerequisiteCheck(
            check_id="libvirt.connect",
            status=PrerequisiteStatus.FAILED,
            message=f"virsh capabilities could not run: {exc}",
            suggested_fix="Confirm libvirt client tools are installed and runnable.",
        )
    if code == 0:
        return PrerequisiteCheck(
            check_id="libvirt.connect",
            status=PrerequisiteStatus.PASSED,
            message=f"authenticated read connection to {uri} (advisory: does not prove define/start)",
            details={"uri": uri},
        )
    if uri.startswith("qemu:///session"):
        fix = "Start the per-user daemon: systemctl --user start virtqemud.socket."
    else:
        fix = "Join the 'libvirt' group or install the libvirt polkit rule for org.libvirt.unix.manage."
    return PrerequisiteCheck(
        check_id="libvirt.connect",
        status=PrerequisiteStatus.FAILED,
        message=f"could not connect to {uri}",
        details={"uri": uri, "stderr": stderr.strip()},
        suggested_fix=fix,
    )
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `uv run python -m pytest tests/test_prereqs.py -k libvirt_connect -q`
Expected: 6 passed.

- [ ] **Step 5: Commit**

```bash
git add src/kdive/prereqs/checks.py tests/test_prereqs.py
git commit -m "feat(prereqs): add advisory libvirt.connect capability check"
```

---

## Task 4: Wire the three checks into `host.check_prerequisites`

**Files:**
- Modify: `src/kdive/server.py:113-116` (imports), `src/kdive/server.py:1263-1296` (`prerequisites_handler`)
- Test: `tests/test_prereqs.py`

- [ ] **Step 1: Write the failing test**

Add to `tests/test_prereqs.py` (it imports nothing from `server` yet — add the import at the top of the new test):

```python
def test_handler_includes_new_capability_checks() -> None:
    from kdive.server import prerequisites_handler

    response = prerequisites_handler(
        artifact_root=Path("/tmp/does-not-matter"),
        source_path=None,
        target_profile=None,
        runner=FakeRunner({"virt-builder", "qemu-img", "virsh"}),
        kvm_probe=lambda: True,
    )
    ids = {check["check_id"] for check in response.data["checks"]}
    assert {"kvm.access", "rootfs.builder", "libvirt.connect"} <= ids
    by_id = {check["check_id"]: check for check in response.data["checks"]}
    assert by_id["kvm.access"]["status"] == "passed"
    assert by_id["rootfs.builder"]["status"] == "passed"
    # No target profile selected -> libvirt.connect is SKIPPED, not FAILED.
    assert by_id["libvirt.connect"]["status"] == "skipped"
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run python -m pytest tests/test_prereqs.py -k handler_includes_new -q`
Expected: FAIL with `TypeError: prerequisites_handler() got an unexpected keyword argument 'runner'`.

- [ ] **Step 3: Add imports in `src/kdive/server.py`**

Find the import block at `src/kdive/server.py:113-116`:

```python
    check_gdbstub_port,
    check_kernel_config,
    check_prerequisites,
    check_rootfs_image,
```

Replace with (keep alphabetical-ish grouping, add the new names and the runner class):

```python
    PrerequisiteRunner,
    SubprocessPrerequisiteRunner,
    check_gdbstub_port,
    check_kernel_config,
    check_kvm_access,
    check_libvirt_connect,
    check_prerequisites,
    check_rootfs_builder,
    check_rootfs_image,
```

(If the surrounding `from kdive.prereqs.checks import (` block also lists `PortProbeResult`, leave that entry intact; only add the new names.)

- [ ] **Step 4: Thread `runner`/`kvm_probe` and append the checks in `prerequisites_handler`**

In `src/kdive/server.py:1263-1296`, add two params to the signature (after `port_probe`):

```python
    port_probe: Callable[[str, int], PortProbeResult] | None = None,
    runner: PrerequisiteRunner | None = None,
    kvm_probe: Callable[[], bool] | None = None,
) -> ToolResponse:
```

`PrerequisiteRunner` (the Protocol used in the type hint) was added to the Step 3 import block. `Callable` is already imported in `server.py` (the existing `port_probe` hint uses it). Then resolve `runner` once and pass it through. Replace the `check_prerequisites(...)` call and the three `checks.append(...)` lines:

```python
    runner = runner or SubprocessPrerequisiteRunner()
    checks = check_prerequisites(
        artifact_root=artifact_root,
        source_path=source,
        enable_libvirt_check=enable_libvirt_check,
        runner=runner,
    )
    build_obj, build_err = _resolve_readiness_profile("build", build_profile, build_profiles)
    rootfs_obj, rootfs_err = _resolve_readiness_profile("rootfs", rootfs_profile, rootfs_profiles)
    target_obj, target_err = _resolve_readiness_profile("target", target_profile, target_profiles)
    checks.append(build_err or check_kernel_config(source, build_obj))
    checks.append(rootfs_err or check_rootfs_image(rootfs_obj))
    checks.append(target_err or check_gdbstub_port(target_obj, port_probe=port_probe))
    checks.append(check_kvm_access(kvm_probe=kvm_probe))
    checks.append(check_rootfs_builder(runner=runner))
    checks.append(target_err or check_libvirt_connect(target_obj, runner=runner))
```

- [ ] **Step 5: Run the new test and the full prereqs + server suites**

Run: `uv run python -m pytest tests/test_prereqs.py -q`
Expected: all pass (existing + new).
Run: `uv run python -m pytest tests/test_server.py -q`
Expected: all pass (the tool wrapper `host_check_prerequisites` needs no change; the new params default to `None`).

- [ ] **Step 6: Lint + type-check the changed Python**

Run: `uv run ruff check src/kdive/prereqs/checks.py src/kdive/server.py tests/test_prereqs.py`
Run: `uv run ruff format --check src/kdive/prereqs/checks.py src/kdive/server.py tests/test_prereqs.py`
Run: `uv run ty check src`
Expected: no errors. Fix any before committing.

- [ ] **Step 7: Commit**

```bash
git add src/kdive/server.py tests/test_prereqs.py
git commit -m "feat(prereqs): surface kvm/libvirt/builder checks via host.check_prerequisites"
```

---

## Task 5: Rewrite `scripts/build-rootfs.sh` — two unprivileged stages

**Files:**
- Rewrite: `scripts/build-rootfs.sh`

No TDD (bash); verification is shellcheck + shfmt + (Task 6) the no-sudo guard + (Task 7) the integration test.

- [ ] **Step 1: Replace the entire script body**

Overwrite `scripts/build-rootfs.sh` with:

```bash
#!/usr/bin/env bash
# Build a minimal, bootable Fedora rootfs qcow2 for kdive — fully unprivileged.
#
# Two unprivileged libguestfs stages (see docs/adr/0037-unprivileged-tooling.md):
#   1. virt-builder customizes a partitioned Fedora scratch image (sshd, authorized key,
#      kdive-ready serial unit).
#   2. virt-tar-out + virt-make-fs --type=ext4 repack the root tree into a no-partition-table
#      whole-disk ext4 qcow2 — the only layout the boot provider mounts (root=/dev/vda, no
#      initramfs). /etc/fstab is then normalized to a lone "/" entry and /etc/crypttab removed,
#      because the scratch image's GPT-layout mount entries would stall local-fs.target and the
#      kdive-ready marker would never fire.
#
# SELinux is disabled in this local debug rootfs (guest-internal /etc/selinux/config) so the
# host-written authorized_keys is read without a relabel and the first boot does not relabel+reboot
# (which would risk a false BOOT_TIMEOUT). This is the guest's internal SELinux only and is
# independent of the host-side virt_image_t/0644 labeling of the image file, which still applies
# (see docs/fedora-libvirt-user-guide.md §5 / ADR 0037 decision #6).
#
# No host-side sudo/pkexec/doas. The output directory is pre-prepared once by an OS admin
# (see docs/fedora-libvirt-user-guide.md §5); the per-build write and the final chmod are
# unprivileged. The chmod 0644 lets the separate qemu user read the base image as a backing
# file under qemu:///system.
set -euo pipefail

ROOTFS_PATH="${KDIVE_ROOTFS:-/var/lib/kdive/rootfs/minimal.qcow2}"
RELEASEVER="${KDIVE_ROOTFS_RELEASEVER:-43}"
# NOTE: the 2G default was tuned for the old minimal dnf --installroot tree. A fuller
# virt-builder Fedora base + sshd may need more headroom for the Stage-2 ext4 to fit
# content + fs overhead; raise KDIVE_ROOTFS_SIZE if virt-make-fs reports "too small".
IMAGE_SIZE="${KDIVE_ROOTFS_SIZE:-2G}"
SSH_USER="${KDIVE_ROOTFS_SSH_USER:-root}"
MARKER="kdive-ready"

invoking_user="${USER:-$(id -un)}"
invoking_home="${HOME:-$(getent passwd "${invoking_user}" | cut -d: -f6)}"

resolve_authorized_key() {
  if [[ -n "${KDIVE_ROOTFS_AUTHORIZED_KEY:-}" ]]; then
    printf '%s\n' "${KDIVE_ROOTFS_AUTHORIZED_KEY}"
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
    echo "error: required command '$1' not found on PATH (install libguestfs-tools)" >&2
    exit 1
  }
}

require virt-builder
require virt-tar-out
require virt-make-fs
require guestfish
require qemu-img

authorized_key="$(resolve_authorized_key)"
if [[ -z "${authorized_key}" || ! -f "${authorized_key}" ]]; then
  echo "error: no SSH public key found. Set KDIVE_ROOTFS_AUTHORIZED_KEY" >&2
  echo "       to a .pub file, or create ${invoking_home}/.ssh/id_ed25519.pub" >&2
  exit 1
fi

if ! virt-builder --list 2>/dev/null | grep -qE "^fedora-${RELEASEVER}[[:space:]]"; then
  echo "error: template 'fedora-${RELEASEVER}' is not in the libguestfs index." >&2
  echo "       Run 'virt-builder --list' to see available releases and set" >&2
  echo "       KDIVE_ROOTFS_RELEASEVER to one of them." >&2
  exit 1
fi

unit_file="$(mktemp)"
fstab_file="$(mktemp)"
selinux_file="$(mktemp)"
scratch="$(mktemp --suffix=.qcow2)"
rootfs_tar="$(mktemp --suffix=.tar)"
cleanup() { rm -f "${unit_file}" "${fstab_file}" "${selinux_file}" "${scratch}" "${rootfs_tar}"; }
trap cleanup EXIT

cat >"${unit_file}" <<EOF
[Unit]
Description=Signal kdive serial readiness
After=dev-ttyS0.device
Wants=dev-ttyS0.device

[Service]
Type=oneshot
ExecStart=/bin/sh -c 'echo ${MARKER} > /dev/ttyS0'
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

printf '/dev/vda / ext4 defaults 0 1\n' >"${fstab_file}"
printf 'SELINUX=disabled\nSELINUXTYPE=targeted\n' >"${selinux_file}"

# virt-builder applies operations in its own fixed order; useradd is sequenced before
# --ssh-inject so a non-root SSH_USER exists when the key is injected.
builder_args=(
  "fedora-${RELEASEVER}"
  --format qcow2 --size "${IMAGE_SIZE}" --output "${scratch}"
  --install openssh-server
  --run-command 'systemctl enable sshd.service'
)
if [[ "${SSH_USER}" != "root" ]]; then
  builder_args+=(--run-command "useradd --create-home --shell /bin/bash ${SSH_USER}")
fi
builder_args+=(
  --ssh-inject "${SSH_USER}:file:${authorized_key}"
  --upload "${unit_file}:/etc/systemd/system/${MARKER}.service"
  --run-command "systemctl enable ${MARKER}.service"
)

echo "Stage 1: customizing fedora-${RELEASEVER} scratch image ..."
virt-builder "${builder_args[@]}"

echo "Stage 2: repacking to whole-disk ext4 ${ROOTFS_PATH} ..."
mkdir -p "$(dirname "${ROOTFS_PATH}")"
virt-tar-out -a "${scratch}" / "${rootfs_tar}"
virt-make-fs --type=ext4 --format=qcow2 --size="${IMAGE_SIZE}" "${rootfs_tar}" "${ROOTFS_PATH}"

# Normalize the inherited mount config and disable guest-internal SELinux. Disabling SELinux
# means the host-written authorized_keys is read without a relabel and the first boot does not
# relabel+reboot (which would risk a false BOOT_TIMEOUT). This is the guest's internal SELinux
# only; it is independent of the host-side virt_image_t/0644 labeling of the image file (which
# still applies — see §2 / ADR #6).
guestfish --rw -a "${ROOTFS_PATH}" -i <<GFEOF
upload ${fstab_file} /etc/fstab
upload ${selinux_file} /etc/selinux/config
rm-f /etc/crypttab
GFEOF

# The caller owns the file it just wrote; chmod is unprivileged. 0644 lets the separate
# qemu user read the base image as a backing file under qemu:///system.
chmod 0644 "${ROOTFS_PATH}"

echo "Done: ${ROOTFS_PATH}"
qemu-img info "${ROOTFS_PATH}" 2>/dev/null || true
```

- [ ] **Step 2: Lint and format-check the script**

Run: `shellcheck scripts/build-rootfs.sh`
Expected: no findings.
Run: `shfmt -i 2 -d scripts/build-rootfs.sh`
Expected: no diff (run `shfmt -i 2 -w scripts/build-rootfs.sh` if it reports one, then re-run `-d`).

- [ ] **Step 3: Static sanity — no escalation tokens remain**

Run: `! rg -n '(^|\s)(sudo|pkexec|doas)\s' scripts/build-rootfs.sh && echo CLEAN`
Expected: prints `CLEAN`.

- [ ] **Step 4: Commit**

```bash
git add scripts/build-rootfs.sh
git commit -m "feat(rootfs): rewrite build-rootfs.sh as two unprivileged libguestfs stages"
```

---

## Task 6: Static no-escalation guard — just recipe + pytest + CI

**Files:**
- Modify: `justfile` (add `check-no-sudo`)
- Create: `tests/test_no_privilege_escalation.py`
- Modify: `.github/workflows/ci.yml` (add `no-sudo` job)

- [ ] **Step 1: Write the failing pytest**

Create `tests/test_no_privilege_escalation.py`:

```python
"""Guard: no host-side privilege-escalation command invocation in scripts/ or justfile.

Mirrors the `just check-no-sudo` recipe so the invariant holds under pytest/CI even when `just`
is absent. Scoped to scripts/ + justfile only: the ~20 `sudo` references in src/ are in-guest SSH
privilege prefixes (ADR 0011/0028), a distinct concern out of this guard's scope.
"""

from __future__ import annotations

import re
from pathlib import Path

ESCALATION = re.compile(r"(^|\s)(sudo|pkexec|doas)\s")
REPO_ROOT = Path(__file__).resolve().parent.parent


def _targets() -> list[Path]:
    targets = sorted((REPO_ROOT / "scripts").rglob("*"))
    files = [path for path in targets if path.is_file()]
    justfile = REPO_ROOT / "justfile"
    if justfile.is_file():
        files.append(justfile)
    return files


def test_no_host_side_privilege_escalation() -> None:
    offenders: list[str] = []
    for path in _targets():
        text = path.read_text(encoding="utf-8", errors="replace")
        for lineno, line in enumerate(text.splitlines(), start=1):
            if ESCALATION.search(line):
                offenders.append(f"{path.relative_to(REPO_ROOT)}:{lineno}: {line.strip()}")
    assert not offenders, "host-side privilege escalation found:\n" + "\n".join(offenders)
```

- [ ] **Step 2: Run the test to verify it passes against the rewritten tree**

Run: `uv run python -m pytest tests/test_no_privilege_escalation.py -q`
Expected: PASS (Task 5 removed all `sudo` from `scripts/`; the `justfile` has none).

- [ ] **Step 3: Verify the test actually catches a violation (mutation check)**

Run:
```bash
printf '\nbad:\n\tsudo true\n' >> justfile
uv run python -m pytest tests/test_no_privilege_escalation.py -q || echo "GUARD TRIPPED AS EXPECTED"
git checkout -- justfile
```
Expected: the run FAILS naming `justfile:<n>: sudo true`, then prints `GUARD TRIPPED AS EXPECTED`; `git checkout` restores the clean justfile.

- [ ] **Step 4: Add the `check-no-sudo` just recipe**

In `justfile`, after the `check-ipmi` recipe (ends at line 54), add:

```makefile
check-no-sudo:
    # Host-side no-escalation guard (ADR 0037): no sudo/pkexec/doas command invocation in
    # scripts/ or justfile. Scoped to host-side tools only — src/ has in-guest SSH privilege
    # prefixes (ADR 0011/0028) and is deliberately not scanned. \s-delimited like check-ipmi.
    ! rg -n '(^|\s)(sudo|pkexec|doas)\s' scripts justfile
```

- [ ] **Step 5: Run the recipe**

Run: `just check-no-sudo && echo OK`
Expected: prints the recipe comment then `OK` (no matches → `rg` exits non-zero → `!` inverts to success).

- [ ] **Step 6: Add the CI job**

In `.github/workflows/ci.yml`, after the `ipmi-policy` job (ends at line 106), add a sibling job mirroring it:

```yaml
  no-sudo:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd  # v6.0.2
        with:
          persist-credentials: false
      - run: |
          set -euo pipefail
          sudo apt-get update && sudo apt-get install -y --no-install-recommends ripgrep just
          just check-no-sudo
```

(The `sudo apt-get` here is GitHub-Actions host provisioning, not a project tool — out of the guard's scope, exactly as the `docs`/`ipmi-policy` jobs already do.)

- [ ] **Step 7: Lint the workflow**

Run: `uv run --with 'actionlint-py==1.7.12.24' actionlint`
Run: `uv run --with 'zizmor==1.25.2' zizmor .github/workflows/ci.yml`
Expected: no errors (look up current stable versions if these are stale).

- [ ] **Step 8: Commit**

```bash
git add justfile tests/test_no_privilege_escalation.py .github/workflows/ci.yml
git commit -m "feat(ci): add host-side no-escalation guard (recipe + pytest + CI job)"
```

---

## Task 7: Two-tier env-gated integration test

**Files:**
- Create: `tests/test_unprivileged_build_integration.py`

Both tiers silent-skip unless opted in. No `conftest.py` — the gate helper lives in the module.

- [ ] **Step 1: Write the test module**

Create `tests/test_unprivileged_build_integration.py`:

```python
"""Env-gated unprivileged-build integration tests (two tiers).

Tier 1 (no KVM): build the image and assert the boot-contract precondition — single whole-disk
ext4 with no partition table, a normalized /etc/fstab (no non-"/" entries) with no /etc/crypttab,
file mode 0644, caller ownership, and no escalation in the script/argv. Gated on tools + the opt-in
env var; runs under TCG when /dev/kvm is absent.

Tier 2 (capable host): boot the built image to the kdive-ready serial marker. Gated additionally on
the libvirt boot env (adapts the qemu:///system harness shape from test_libvirt_boot_integration).
Tier 2 builds the base image into, and runs its copy-on-write overlay under, the operator's
pre-prepared virt_image_t-labeled directory (located via KDIVE_ROOTFS) so the separate qemu user can
read both the overlay and its read-only backing file under qemu:///system; it cleans both up afterward.

Neither tier runs in default CI (no network/tools/KVM). The always-on protection is the
check-no-sudo guard + the prereqs unit tests + the documented boot-contract precondition.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
BUILD_SCRIPT = REPO_ROOT / "scripts" / "build-rootfs.sh"
BUILD_TOOLS = ["virt-builder", "virt-tar-out", "virt-make-fs", "guestfish", "qemu-img", "virt-filesystems"]
ESCALATION = re.compile(r"(^|\s)(sudo|pkexec|doas)\s")


def require_build_tier() -> None:
    if os.environ.get("KDIVE_BUILD_TEST") != "1":
        pytest.skip("unprivileged-build integration test skipped; set KDIVE_BUILD_TEST=1 to run it.")
    missing = [tool for tool in BUILD_TOOLS if shutil.which(tool) is None]
    if missing:
        pytest.skip(f"missing build tools: {', '.join(missing)} (install libguestfs-tools).")


def build_image(target: Path, *, key_dir: Path | None = None) -> None:
    key = (key_dir or target.parent) / "id_ed25519.pub"
    key.write_text("ssh-ed25519 AAAATESTKEYONLY test@kdive\n", encoding="utf-8")
    env = {
        **os.environ,
        "KDIVE_ROOTFS": str(target),
        "KDIVE_ROOTFS_RELEASEVER": os.environ.get("KDIVE_ROOTFS_RELEASEVER", "43"),
        "KDIVE_ROOTFS_AUTHORIZED_KEY": str(key),
    }
    subprocess.run(["bash", str(BUILD_SCRIPT)], check=True, env=env, timeout=1800)


def guestfish_cat(image: Path, guest_path: str) -> tuple[int, str]:
    completed = subprocess.run(
        ["guestfish", "--ro", "-a", str(image), "-i", "cat", guest_path],
        check=False,
        capture_output=True,
        text=True,
        timeout=120,
    )
    return completed.returncode, completed.stdout


def test_tier1_layout_and_permissions(tmp_path: Path) -> None:
    require_build_tier()
    image = tmp_path / "minimal.qcow2"
    build_image(image)

    # Owned by the caller; group/other-readable (0644) so qemu can read it under qemu:///system.
    stat = image.stat()
    assert stat.st_uid == os.getuid(), "image must be owned by the caller"
    assert stat.st_mode & 0o077 == 0o044, f"image must be 0644-readable, got {oct(stat.st_mode & 0o777)}"

    # No partition table: a whole-disk filesystem reports no partitions.
    partitions = subprocess.run(
        ["virt-filesystems", "--partitions", "-a", str(image)],
        check=True,
        capture_output=True,
        text=True,
        timeout=120,
    ).stdout
    assert partitions.strip() == "", f"expected no partition table, got:\n{partitions}"

    # Exactly one whole-disk filesystem, and it is ext4 (parse "device: type" lines; do not
    # hard-code the device node).
    filesystems = subprocess.run(
        ["guestfish", "--ro", "-a", str(image), "run", ":", "list-filesystems"],
        check=True,
        capture_output=True,
        text=True,
        timeout=120,
    ).stdout
    entries = [line.split(":", 1) for line in filesystems.splitlines() if ":" in line]
    assert len(entries) == 1, f"expected exactly one filesystem, got:\n{filesystems}"
    assert entries[0][1].strip() == "ext4", f"expected ext4, got:\n{filesystems}"

    # Normalized /etc/fstab: only the root entry; /etc/crypttab absent.
    code, fstab = guestfish_cat(image, "/etc/fstab")
    assert code == 0
    mount_entries = [
        line.split()[1]
        for line in fstab.splitlines()
        if line.strip() and not line.lstrip().startswith("#") and len(line.split()) >= 2
    ]
    assert mount_entries == ["/"], f"fstab must contain only the root mount, got {mount_entries}:\n{fstab}"
    crypttab_code, _ = guestfish_cat(image, "/etc/crypttab")
    assert crypttab_code != 0, "/etc/crypttab must be absent in the repacked image"

    # No escalation in the script source.
    script_text = BUILD_SCRIPT.read_text(encoding="utf-8")
    assert not ESCALATION.search(script_text), "build script must contain no sudo/pkexec/doas"


def require_boot_tier() -> dict[str, str]:
    require_build_tier()
    needed = ["KDIVE_LIBVIRT_TEST", "KDIVE_SOURCE", "KDIVE_DOMAIN", "KDIVE_LIBVIRT_URI", "KDIVE_ROOTFS"]
    values = {name: os.environ[name] for name in needed if name in os.environ}
    missing = [name for name in needed if name not in values]
    if "KDIVE_LIBVIRT_TEST" in values and values["KDIVE_LIBVIRT_TEST"] != "1":
        missing.append("KDIVE_LIBVIRT_TEST=1")
    if missing:
        pytest.skip(
            f"boot tier skipped; set {', '.join(missing)} (KVM-capable libvirt host). "
            "KDIVE_ROOTFS must point into a pre-prepared, virt_image_t-labeled, qemu-traversable "
            "directory (the §5 host-prep dir): Tier 2 builds and boots there under qemu:///system."
        )
    return values


def test_tier2_boot_reaches_readiness_marker(tmp_path: Path) -> None:
    env = require_boot_tier()
    # KDIVE_ROOTFS locates the operator's pre-prepared, virt_image_t-labeled, qemu-traversable dir.
    # Both the base image and the run tree (overlay) must live here so the separate qemu user can
    # read the overlay AND its read-only backing file under qemu:///system (libvirt relabels only the
    # writable overlay, not the backing file — libvirt_qemu.py:380-381,377-394).
    prepared_dir = Path(env["KDIVE_ROOTFS"]).expanduser().parent
    base_image = prepared_dir / "kdive-build-test.qcow2"
    artifact_root = prepared_dir / "kdive-build-test-runs"

    from kdive.artifacts.store import ArtifactStore
    from kdive.config import RootfsProfile, TargetProfile
    from kdive.domain import ArtifactRef, StepResult, StepStatus
    from kdive.server import create_run_handler, target_boot_handler

    source = Path(env["KDIVE_SOURCE"]).expanduser()
    kernel_image = source / "arch" / "x86" / "boot" / "bzImage"
    assert kernel_image.is_file(), f"build a bzImage at {kernel_image} before running Tier 2"

    run_id = "run-unprivileged-build-tier2"
    # The copy_on_write overlay lands under artifact_root (libvirt_qemu.py:377-394); its ancestor
    # dirs are created with umask-masked mkdir() (store.py:68-71), so under qemu:///system the
    # separate qemu user can only traverse them if they are 0755. Force a 0022 umask for the run
    # tree (and the build) so the chain is qemu-traversable regardless of the operator's login umask.
    previous_umask = os.umask(0o022)
    try:
        # A prior run killed before the finally below would wedge create_run with "run already
        # exists" because artifact_root persists in the prepared dir — pre-clean both artifacts.
        shutil.rmtree(artifact_root, ignore_errors=True)
        base_image.unlink(missing_ok=True)

        build_image(base_image, key_dir=tmp_path)  # built file inherits virt_image_t; builder chmods 0644

        create_response = create_run_handler(
            artifact_root=artifact_root,
            source_path=str(source),
            build_profile="x86_64-default",
            target_profile="local-qemu",
            rootfs_profile="minimal",
            run_id=run_id,
        )
        assert create_response.ok is True, create_response.model_dump(mode="json")

        # Boot reads the kernel image from a recorded build StepResult, not a boot arg — seed it.
        ArtifactStore(artifact_root, create_root=False).record_step_result(
            run_id,
            StepResult(
                step_name="build",
                status=StepStatus.SUCCEEDED,
                summary="seeded",
                artifacts=[ArtifactRef(path=str(kernel_image), kind="kernel-image")],
                details={"architecture": "x86_64", "output_path": str(kernel_image.parent)},
            ),
        )

        boot_response = target_boot_handler(
            artifact_root=artifact_root,
            run_id=run_id,
            force_reboot=True,
            target_profiles={
                "local-qemu": TargetProfile(
                    name="local-qemu",
                    architecture="x86_64",
                    target_ref=env["KDIVE_DOMAIN"],
                    managed_domain=True,
                    managed_domain_prefix="kdive-",
                    libvirt_uri=env["KDIVE_LIBVIRT_URI"],
                    timeout_seconds=600,
                )
            },
            rootfs_profiles={
                "minimal": RootfsProfile(
                    name="minimal",
                    source=str(base_image),
                    source_type="disk_image",
                    source_kind="builder",
                    mutability="copy_on_write",
                    readiness_marker="kdive-ready",
                )
            },
        )

        assert boot_response.ok is True, boot_response.model_dump(mode="json")
        assert boot_response.data["matched_marker"] == "kdive-ready"
    finally:
        shutil.rmtree(artifact_root, ignore_errors=True)
        base_image.unlink(missing_ok=True)
        os.umask(previous_umask)
```

> **Adapted from** `tests/test_libvirt_boot_integration.py` — the call shape matches (no `store=` on create,
> no `kernel_image_path=` on boot, the build step seeded, boot dict keys equal to the names passed at create),
> but with deliberate deltas: `mutability="copy_on_write"` (vs the reference's `read_only`) to exercise the
> overlay → read-only-backing-file chain the 0644 base-image fix is about; an added `source_kind="builder"`;
> a hardcoded `kdive-ready` readiness marker; and a narrowed assertion set (only `matched_marker`, dropping
> the reference's `data["domain"]` check). `timeout_seconds=600` gives the TCG path headroom. Keep the
> shared call shape in sync with the reference test when it changes.
>
> **Why build into the prepared dir, not `tmp_path`:** the per-boot overlay lands at
> `attempt_dir/rootfs-overlay.qcow2` under `artifact_root` (`libvirt_qemu.py:377-394`) and its read-only
> backing file is the base image (`:380-381`). Under the default `qemu:///system` the separate `qemu` user
> must read **both** — and libvirt's security driver relabels only the writable overlay, never the backing
> file. So both the base image and `artifact_root` live in the `virt_image_t`-labeled, qemu-traversable §5
> host-prep dir (derived from `KDIVE_ROOTFS`), **not** pytest's `0700` `tmp_path`. That is what makes the test
> genuinely exercise the 0644 + `virt_image_t` read-only-backing-file read; under `tmp_path` it would
> false-fail with EACCES before the 0644 path is ever reached. A test-specific filename
> (`kdive-build-test.qcow2`) keeps the operator's production `minimal.qcow2` untouched, and the `finally`
> block removes both the base image and the run tree.
>
> **Two non-obvious preconditions the test enforces itself, so it cannot false-fail like round-2 #1.**
> (a) *Run-tree traversal:* the overlay's ancestor dirs (`artifact_root → <run_id> → boot → attempt-N`) are
> created with umask-masked `mkdir()` (`store.py:68-71`, `libvirt_qemu.py:884`), and libvirt relabels/chowns
> only the overlay *file*, never widens `+x` on those operator-owned dirs — so under an operator umask of
> `077` the chain is `0700` and the `qemu` user gets EACCES traversing it (the same failure class round-2 #1
> raised, relocated to the overlay path). The test sets `os.umask(0o022)` for the run tree and restores it in
> `finally`. (b) *Re-run safety:* because `artifact_root` now persists in the prepared dir (not throwaway
> `tmp_path`), a prior run killed before cleanup would wedge `create_run` with "run already exists"; the test
> pre-cleans `artifact_root` and `base_image` before `create_run_handler` in addition to the `finally`.

- [ ] **Step 2: Confirm both tiers skip cleanly without opt-in**

Run: `uv run python -m pytest tests/test_unprivileged_build_integration.py -q`
Expected: 2 skipped (no `KDIVE_BUILD_TEST=1`).

- [ ] **Step 3: Lint + type-check**

Run: `uv run ruff check tests/test_unprivileged_build_integration.py`
Run: `uv run ruff format --check tests/test_unprivileged_build_integration.py`
Expected: no errors.

- [ ] **Step 4: Commit**

```bash
git add tests/test_unprivileged_build_integration.py
git commit -m "test: add two-tier env-gated unprivileged-build integration test"
```

---

## Task 8: Rewrite `docs/fedora-libvirt-user-guide.md` §5

**Files:**
- Modify: `docs/fedora-libvirt-user-guide.md` (§5, around the current `sudo dnf --installroot` recipe near lines 253-317)

- [ ] **Step 1: Read the current §5**

Run: `sed -n '200,320p' docs/fedora-libvirt-user-guide.md`
Identify (a) the `sudo dnf --installroot ... virt-make-fs` recipe block to replace, and (b) the existing one-time host-prep block (`sudo mkdir -p /var/lib/kdive/rootfs && chown ... && semanage fcontext -t virt_image_t ... && restorecon`) to **keep**.

- [ ] **Step 2: Replace the build recipe with the sudo-free flow**

Replace the manual `sudo dnf --installroot` recipe with guidance that the rootfs is now built by `just rootfs` (which runs `scripts/build-rootfs.sh` unprivileged). Document the env-var interface (`KDIVE_ROOTFS`, `KDIVE_ROOTFS_RELEASEVER`, `KDIVE_ROOTFS_SIZE`, `KDIVE_ROOTFS_SSH_USER`, `KDIVE_ROOTFS_AUTHORIZED_KEY`) and state the two stages briefly (virt-builder customize → whole-disk-ext4 repack). Use this prose (adapt headings to the doc's style):

```markdown
### 5. Build the rootfs image (`just rootfs`)

`just rootfs` runs `scripts/build-rootfs.sh` as a regular user — no `sudo`. It builds the image
in two unprivileged libguestfs stages: `virt-builder` customizes a Fedora image (installs
`openssh-server`, injects your SSH public key, enables sshd and the `kdive-ready` serial unit),
then `virt-tar-out` + `virt-make-fs --type=ext4` repack the root tree into a **single whole-disk
ext4 qcow2 with no partition table**. That layout is required: the boot provider boots
`root=/dev/vda` with no initramfs, so a partitioned image would panic. The build normalizes
`/etc/fstab` to a lone `/` entry so the guest reaches `multi-user.target`. It also disables
guest-internal SELinux in the image, so the host-written SSH key is read without a relabel and the
first boot does not relabel+reboot. That is separate from the host-side `virt_image_t` label on the
image *file*, which is still required (see below).

Configure it with environment variables (defaults in parentheses):

| Variable | Default | Meaning |
|---|---|---|
| `KDIVE_ROOTFS` | `/var/lib/kdive/rootfs/minimal.qcow2` | output image path |
| `KDIVE_ROOTFS_RELEASEVER` | `43` | Fedora release (must be in `virt-builder --list`) |
| `KDIVE_ROOTFS_SIZE` | `2G` | image size (raise if `virt-make-fs` reports "too small") |
| `KDIVE_ROOTFS_SSH_USER` | `root` | guest user that receives the key |
| `KDIVE_ROOTFS_AUTHORIZED_KEY` | your `~/.ssh/id_ed25519.pub` or `id_rsa.pub` | public key to install |

Prerequisite: `libguestfs-tools` (provides `virt-builder`, `virt-tar-out`, `virt-make-fs`,
`guestfish`, `qemu-img`). Building also needs network access to download and GPG-verify the
template. `host.check_prerequisites` reports the `rootfs.builder`, `kvm.access`, and
`libvirt.connect` capabilities.
```

- [ ] **Step 3: Add the base-image 0644 + label requirement**

Immediately after the one-time host-prep block (the `semanage fcontext -t virt_image_t` step you kept), add:

```markdown
**Why the image must be 0644 + `virt_image_t`.** Under the default `qemu:///system`, a separate
`qemu` user reads the image. With the per-boot copy-on-write overlay the built image is the
read-only *backing file* in the disk chain, and libvirt's security driver relabels only the
writable overlay, not the backing file. So the base image must be **independently readable**:
mode `0644` (the builder sets this with an unprivileged `chmod` — you own the file) **and**
labeled `virt_image_t` (inherited from the pre-prepared directory's fcontext above). If you put
the image under `$HOME` instead, use `qemu:///session` (a per-user qemu that runs as you and can
read it) — a `0700` home and `user_home_t` labels block the system `qemu` user.
```

- [ ] **Step 4: Verify the doc guard still passes**

Run: `just check-docs`
Expected: exit 0 (no "sprint" terms introduced).

- [ ] **Step 5: Commit**

```bash
git add docs/fedora-libvirt-user-guide.md
git commit -m "docs: rewrite user-guide §5 for the sudo-free rootfs build + 0644/label requirement"
```

---

## Final verification

- [ ] **Run the full unit suite + lint + types**

Run: `uv run python -m pytest -q`
Run: `uv run ruff check . && uv run ruff format --check .`
Run: `uv run ty check src`
Run: `just check-docs && just check-no-sudo`
Run: `shellcheck scripts/build-rootfs.sh && shfmt -i 2 -d scripts/build-rootfs.sh`
Expected: all green.

- [ ] **Spec cross-check**: confirm every spec section maps to a task — builder rewrite (Task 5), three preflight checks (Tasks 1–4), no-escalation guard (Task 6), two-tier integration test (Task 7), docs + 0644/label (Task 8). The ADR 0037 supersession of the ADR 0031 build-recipe portion is recorded in the ADR (already committed); no code change needed.
