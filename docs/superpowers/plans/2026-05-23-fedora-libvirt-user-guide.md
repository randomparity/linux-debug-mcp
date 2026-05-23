# Fedora Libvirt User Guide Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add user-facing documentation that explains how to prepare a Fedora host for the current libvirt boot pilot and run the opt-in integration test with an existing Linux tree at `~/src/linux`.

**Architecture:** Keep `README.md` as the concise entry point and move the full host setup/runbook into a dedicated guide under `docs/`. The guide should describe both `qemu:///session` for immediate unprivileged use and `qemu:///system` for managed system libvirt, including authentication/permission setup, required rootfs behavior, and cleanup commands.

**Tech Stack:** Markdown documentation, Fedora `dnf`, libvirt/QEMU tools (`virsh`, `virtqemud`, `qemu-system-x86_64`, `virt-install`), existing pytest integration test `tests/test_libvirt_boot_integration.py`.

---

## Commit Policy

This documentation update should land as one reviewable commit after all guide
and README verification passes. Do not create per-task commits while executing
this plan; stage the relevant documentation files during Tasks 1 and 2, then
commit once in Task 3.

## Current Context

- This repository currently has `README.md` with a short "Pilot Libvirt Boot Host" section.
- There is no user guide under `docs/`.
- The current host example should assume Fedora 43 Workstation and an existing Linux source directory at `~/src/linux`.
- The current host has `~/src/linux` present, but the guide must still explain how to build `arch/x86/boot/bzImage` if it is absent.
- The libvirt integration test requires:
  - `LINUX_DEBUG_MCP_LIBVIRT_TEST=1`
  - `LINUX_DEBUG_MCP_ROOTFS`
  - `LINUX_DEBUG_MCP_SOURCE`
  - `LINUX_DEBUG_MCP_DOMAIN`
  - `LINUX_DEBUG_MCP_LIBVIRT_URI`
  - `LINUX_DEBUG_MCP_READINESS_MARKER`
- The domain must start with `mcp-linux-debug-`.
- A rootfs disk image must print the configured readiness marker on `ttyS0`.

## Files

- Create: `docs/fedora-libvirt-user-guide.md`
- Modify: `README.md`

## Task 1: Create The Fedora Libvirt User Guide

**Files:**
- Create: `docs/fedora-libvirt-user-guide.md`

- [ ] **Step 1: Create the guide with complete Fedora host setup content**

Create `docs/fedora-libvirt-user-guide.md` with exactly this initial structure and content:

````markdown
# Fedora Libvirt User Guide

This guide walks through preparing a Fedora host and running the current
`target.boot` libvirt pilot. It assumes:

- Fedora 43 Workstation or a current Fedora release with modular libvirt daemons.
- The repository is checked out at `~/src/linux-debug-mcp`.
- A Linux source tree already exists at `~/src/linux`.
- The libvirt boot domain is dedicated to this project and starts with
  `mcp-linux-debug-`.

The current pilot boots an x86_64 kernel with direct kernel boot, attaches a
disk-image rootfs as `/dev/vda`, and waits for a serial readiness marker on
`ttyS0`. It does not create rootfs images, configure SSH, run guest tests,
attach gdb, or manage production VMs.

## 1. Install Fedora Host Packages

Install the host tools used by the server, the kernel build, and the libvirt
pilot:

```bash
sudo dnf install -y \
  git make gcc flex bison elfutils-libelf-devel openssl-devel bc \
  python3 python3-pip uv \
  qemu-kvm qemu-img libvirt virt-install virt-viewer \
  guestfs-tools libguestfs-tools-c policycoreutils-python-utils
```

Enable and start the Fedora libvirt QEMU daemon:

```bash
sudo systemctl enable --now virtqemud.socket
sudo systemctl enable --now virtnetworkd.socket
sudo systemctl enable --now virtstoraged.socket
```

Check that the expected tools are visible:

```bash
command -v virsh
command -v qemu-system-x86_64
command -v qemu-img
command -v virt-install
```

## 2. Choose A Libvirt URI And Authentication Mode

For quick local testing, use per-user session libvirt:

```bash
virsh -c qemu:///session list --all
```

This usually works without extra host authorization and is the recommended
first path for a developer workstation.

For system libvirt, use:

```bash
virsh -c qemu:///system list --all
```

If that command fails with a polkit or authorization error, configure one of
these host access paths:

```bash
sudo usermod -aG libvirt "$USER"
newgrp libvirt
```

Then test again:

```bash
virsh -c qemu:///system list --all
```

On some Fedora installs, group membership alone is not enough for
noninteractive `qemu:///system` access. If `virsh -c qemu:///system list --all`
still fails outside a graphical desktop session, either use `qemu:///session` or
install a local polkit rule for the dedicated developer account.

For a single-user development host, create this rule after replacing `dave` with
the account that will run the MCP server:

```bash
sudo tee /etc/polkit-1/rules.d/80-linux-debug-mcp-libvirt.rules >/dev/null <<'EOF'
polkit.addRule(function(action, subject) {
  if (action.id == "org.libvirt.unix.manage" &&
      subject.user == "dave") {
    return polkit.Result.YES;
  }
});
EOF
```

Then restart polkit and test again:

```bash
sudo systemctl restart polkit
virsh -c qemu:///system list --all
```

If system access is not needed, prefer `qemu:///session` and set
`LINUX_DEBUG_MCP_LIBVIRT_URI` to `qemu:///session`.

## 3. Prepare The Python Development Environment

From the MCP server checkout:

```bash
cd ~/src/linux-debug-mcp
just setup
```

If `just` is not installed, use the direct editable install:

```bash
cd ~/src/linux-debug-mcp
uv venv --allow-existing
uv pip install -e '.[test,dev]'
```

Run the prerequisite check with libvirt enabled:

```bash
uv run python - <<'PY'
from pathlib import Path
from linux_debug_mcp.server import prerequisites_handler

response = prerequisites_handler(
    artifact_root=Path.home() / ".local/state/linux-debug-mcp/runs",
    source_path=str(Path.home() / "src/linux"),
    enable_libvirt_check=True,
)
print(response.model_dump_json(indent=2))
PY
```

All required host tools should pass. If `libvirt.uri` reports `qemu:///session`,
use `qemu:///session` in the integration test unless you intentionally
configured `qemu:///system`.

## 4. Prepare The Linux Kernel Image

The integration test expects `~/src/linux/arch/x86/boot/bzImage` to exist. If it
is already present, verify it:

```bash
test -f ~/src/linux/arch/x86/boot/bzImage
ls -lh ~/src/linux/arch/x86/boot/bzImage
```

If it is missing, build a basic x86_64 kernel image from the existing source
tree:

```bash
cd ~/src/linux
make x86_64_defconfig
make -j"$(nproc)" bzImage
```

The current provider does not run `defconfig` or generate kernel configs for
you. The source tree must already have whatever configuration you want to boot.

Because the pilot uses direct kernel boot without an initramfs, the kernel
configuration must include the root disk, filesystem, devtmpfs, and serial
console support needed to mount `/dev/vda` and print readiness on `ttyS0`.
Check the current config:

```bash
cd ~/src/linux
scripts/config --state CONFIG_VIRTIO_PCI
scripts/config --state CONFIG_VIRTIO_BLK
scripts/config --state CONFIG_EXT4_FS
scripts/config --state CONFIG_DEVTMPFS
scripts/config --state CONFIG_SERIAL_8250_CONSOLE
```

For this pilot, each should be `y`. If any are `m` or `n`, enable them and
rebuild:

```bash
cd ~/src/linux
scripts/config --enable CONFIG_VIRTIO_PCI
scripts/config --enable CONFIG_VIRTIO_BLK
scripts/config --enable CONFIG_EXT4_FS
scripts/config --enable CONFIG_DEVTMPFS
scripts/config --enable CONFIG_SERIAL_8250_CONSOLE
make olddefconfig
make -j"$(nproc)" bzImage
```

## 5. Prepare A Bootable Rootfs Disk Image

Provide a qcow2 disk image that can boot as `/dev/vda` and print a readiness
marker on the serial console. The guide uses this example path:

```bash
sudo mkdir -p /var/lib/linux-debug-mcp/rootfs
sudo chown "$USER":"$USER" /var/lib/linux-debug-mcp/rootfs
export LINUX_DEBUG_MCP_ROOTFS=/var/lib/linux-debug-mcp/rootfs/minimal.qcow2
```

If you already have a compatible rootfs image, copy it to that path and make
sure it writes this exact marker to `ttyS0`:

```text
linux-debug-mcp-ready
```

To create a representative Fedora rootfs for the pilot, build a minimal
installroot and pack it into a qcow2 image. This uses a whole-disk ext4
filesystem so the provider's `root=/dev/vda` kernel argument can mount it
directly:

```bash
ROOTFS_WORK="$(mktemp -d)"
sudo dnf --installroot="${ROOTFS_WORK}" \
  --releasever=43 \
  --setopt=install_weak_deps=False \
  --setopt=tsflags=nodocs \
  install -y systemd fedora-release passwd

sudo tee "${ROOTFS_WORK}/etc/fstab" >/dev/null <<'EOF'
/dev/vda / ext4 defaults 0 1
EOF

sudo tee "${ROOTFS_WORK}/etc/systemd/system/linux-debug-mcp-ready.service" >/dev/null <<'EOF'
[Unit]
Description=Signal linux-debug-mcp serial readiness
After=dev-ttyS0.device
Wants=dev-ttyS0.device

[Service]
Type=oneshot
ExecStart=/bin/sh -c 'echo linux-debug-mcp-ready > /dev/ttyS0'
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

sudo mkdir -p "${ROOTFS_WORK}/etc/systemd/system/multi-user.target.wants"
sudo ln -sf ../linux-debug-mcp-ready.service \
  "${ROOTFS_WORK}/etc/systemd/system/multi-user.target.wants/linux-debug-mcp-ready.service"

sudo virt-make-fs \
  --format=qcow2 \
  --type=ext4 \
  --size=2G \
  "${ROOTFS_WORK}" \
  "${LINUX_DEBUG_MCP_ROOTFS}"
sudo chown "$USER":"$USER" "${LINUX_DEBUG_MCP_ROOTFS}"
sudo rm -rf "${ROOTFS_WORK}"
```

Verify the image exists before running the integration test:

```bash
qemu-img info "${LINUX_DEBUG_MCP_ROOTFS}"
```

If you use `qemu:///system` with SELinux enforcing, label the rootfs directory
for libvirt image access:

```bash
sudo semanage fcontext -a -t virt_image_t '/var/lib/linux-debug-mcp/rootfs(/.*)?'
sudo restorecon -Rv /var/lib/linux-debug-mcp/rootfs
```

If `semanage` reports that the rule already exists, update it instead:

```bash
sudo semanage fcontext -m -t virt_image_t '/var/lib/linux-debug-mcp/rootfs(/.*)?'
sudo restorecon -Rv /var/lib/linux-debug-mcp/rootfs
```

This rootfs recipe is a development smoke image, not a production guest. The
MCP server still does not create rootfs images automatically; the commands above
are a host preparation step you run manually.

## 6. Run The Opt-In Libvirt Integration Test

Use a dedicated domain name with the required prefix:

```bash
export LINUX_DEBUG_MCP_DOMAIN=mcp-linux-debug-dev
```

Choose the libvirt URI that works on your host:

```bash
export LINUX_DEBUG_MCP_LIBVIRT_URI=qemu:///session
```

Use `qemu:///system` only after `virsh -c qemu:///system list --all` works from
the same shell without prompting.

Run the integration test:

```bash
cd ~/src/linux-debug-mcp
LINUX_DEBUG_MCP_LIBVIRT_TEST=1 \
LINUX_DEBUG_MCP_ROOTFS="${LINUX_DEBUG_MCP_ROOTFS}" \
LINUX_DEBUG_MCP_SOURCE=~/src/linux \
LINUX_DEBUG_MCP_DOMAIN="${LINUX_DEBUG_MCP_DOMAIN}" \
LINUX_DEBUG_MCP_LIBVIRT_URI="${LINUX_DEBUG_MCP_LIBVIRT_URI}" \
LINUX_DEBUG_MCP_READINESS_MARKER=linux-debug-mcp-ready \
uv run pytest tests/test_libvirt_boot_integration.py -q
```

Expected success output is one passing test:

```text
1 passed
```

Without the environment variables, the same command should skip safely:

```bash
uv run pytest tests/test_libvirt_boot_integration.py -q
```

Expected skipped output:

```text
1 skipped
```

## 7. Inspect Artifacts And Clean Up

The integration test uses a temporary artifact root managed by pytest. For MCP
tool runs outside the integration test, boot artifacts are written under:

```text
<artifact-root>/<run-id>/
  logs/console.log
  logs/boot.log
  target/domain.xml
  target/boot-plan.json
  summaries/boot-summary.json
```

Successful integration runs may leave the dedicated domain running. Stop it
manually when needed:

```bash
virsh -c "${LINUX_DEBUG_MCP_LIBVIRT_URI}" destroy "${LINUX_DEBUG_MCP_DOMAIN}"
```

Inspect the domain XML if a run fails ownership validation:

```bash
virsh -c "${LINUX_DEBUG_MCP_LIBVIRT_URI}" dumpxml "${LINUX_DEBUG_MCP_DOMAIN}"
```

Remove the domain definition only if it is dedicated to this project:

```bash
virsh -c "${LINUX_DEBUG_MCP_LIBVIRT_URI}" undefine "${LINUX_DEBUG_MCP_DOMAIN}"
```

## Troubleshooting

### `qemu:///system` fails with polkit authentication

Use `qemu:///session` for local development, or configure system libvirt access
for your user and verify:

```bash
virsh -c qemu:///system list --all
```

### The test times out waiting for readiness

Check that the rootfs prints the exact marker to `ttyS0`:

```text
linux-debug-mcp-ready
```

Also check `logs/console.log` in the run artifacts.

### The domain is rejected as not MCP-owned

The provider will not mutate an existing domain unless its XML metadata matches
the MCP provider, domain, and target profile. Use a fresh dedicated domain name
starting with `mcp-linux-debug-`, or manually remove the old dedicated test
domain after confirming it is safe:

```bash
virsh -c "${LINUX_DEBUG_MCP_LIBVIRT_URI}" undefine "${LINUX_DEBUG_MCP_DOMAIN}"
```
````

- [ ] **Step 2: Verify the guide mentions the required Fedora and run details**

Run:

```bash
rg -n "Fedora 43|dnf install|virtqemud|qemu:///session|qemu:///system|~/src/linux|mcp-linux-debug-|CONFIG_VIRTIO_BLK|virt-make-fs|semanage fcontext|LINUX_DEBUG_MCP_ROOTFS|LINUX_DEBUG_MCP_READINESS_MARKER|uv run pytest tests/test_libvirt_boot_integration.py" docs/fedora-libvirt-user-guide.md
```

Expected: PASS with matches for every listed pattern.

- [ ] **Step 3: Stage the user guide**

Run:

```bash
git add docs/fedora-libvirt-user-guide.md
```

Expected: `git diff --cached --name-only` includes `docs/fedora-libvirt-user-guide.md`.

## Task 2: Refocus README As The Entry Point

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Replace the long Pilot Libvirt Boot Host section with a concise summary and guide link**

Edit `README.md` so the `## Pilot Libvirt Boot Host` section reads:

```markdown
## Pilot Libvirt Boot Host

`target.boot` supports a narrow pilot path for a dedicated local libvirt/QEMU
domain. It boots an x86_64 kernel with direct kernel boot, attaches a disk-image
rootfs as `/dev/vda`, captures serial console output, and waits for a configured
readiness marker on `ttyS0`.

For full Fedora host setup, libvirt authentication options, rootfs expectations,
and the opt-in integration command, see
[`docs/fedora-libvirt-user-guide.md`](docs/fedora-libvirt-user-guide.md).

At a high level, a real-host run needs:

- Fedora host packages for kernel builds, QEMU, and libvirt.
- A working libvirt URI such as `qemu:///session` or `qemu:///system`.
- A dedicated managed domain whose name starts with `mcp-linux-debug-`.
- A Linux source tree with a built `arch/x86/boot/bzImage`.
- A disk-image rootfs that prints the configured readiness marker on `ttyS0`.

The pilot boot path does not create root filesystems, run SSH commands, run
guest test suites, attach gdb, use remote builders, generate kernel configs, or
apply config fragments automatically.
```

Leave the rest of `README.md` intact unless a sentence now duplicates the new section in an obviously confusing way.

- [ ] **Step 2: Verify README links to the guide and keeps the scope clear**

Run:

```bash
rg -n "docs/fedora-libvirt-user-guide.md|target.boot|mcp-linux-debug-|ttyS0|does not create root filesystems" README.md
```

Expected: PASS with matches for all key phrases.

- [ ] **Step 3: Verify the guide link target exists**

Run:

```bash
test -f docs/fedora-libvirt-user-guide.md
```

Expected: PASS with exit status 0.

- [ ] **Step 4: Stage the README update**

Run:

```bash
git add README.md
```

Expected: `git diff --cached --name-only` includes `README.md`.

## Task 3: Documentation Verification

**Files:**
- Verify: `README.md`
- Verify: `docs/fedora-libvirt-user-guide.md`

- [ ] **Step 1: Run unit and integration skip smoke**

Run:

```bash
uv run pytest tests/test_libvirt_boot_integration.py -q
```

Expected: PASS with `1 skipped` unless the libvirt integration environment is explicitly set.

- [ ] **Step 2: Run project lint**

Run:

```bash
uv run ruff check .
```

Expected: PASS with `All checks passed!`.

- [ ] **Step 3: Check for unresolved placeholder markers in the new guide**

Run:

```bash
python - <<'PY'
from pathlib import Path

markers = [
    "T" + "BD",
    "TO" + "DO",
    "PLACE" + "HOLDER",
    "<root" + "fs>",
    "<do" + "main>",
    "fill" + " in",
]
paths = [Path("docs/fedora-libvirt-user-guide.md"), Path("README.md")]
matches: list[str] = []
for path in paths:
    text = path.read_text(encoding="utf-8")
    for marker in markers:
        if marker in text:
            matches.append(f"{path}: contains {marker!r}")
if matches:
    raise SystemExit("\n".join(matches))
PY
```

Expected: PASS with exit status 0.

- [ ] **Step 4: Check exact current-host assumptions are represented**

Run:

```bash
rg -n "Fedora 43|~/src/linux|qemu:///session|qemu:///system" docs/fedora-libvirt-user-guide.md
```

Expected: PASS with matches for all four terms.

- [ ] **Step 5: Commit the documentation change once**

Run:

```bash
python - <<'PY'
import subprocess

expected = ["README.md", "docs/fedora-libvirt-user-guide.md"]
staged = subprocess.check_output(
    ["git", "diff", "--cached", "--name-only"],
    text=True,
).splitlines()
if sorted(staged) != sorted(expected):
    raise SystemExit(
        "unexpected staged files:\n"
        + "\n".join(staged)
        + "\n\nexpected only:\n"
        + "\n".join(expected)
    )
PY
git commit -m "docs: add Fedora libvirt user guide"
```

Expected: the staged-file guard passes and the commit succeeds.

## Self-Review Notes

- Spec coverage: Task 1 creates a full user guide under `docs/` that walks through Fedora host package installation, libvirt service setup, user authentication/authorization choices, existing `~/src/linux`, rootfs/readiness requirements, running the integration test, artifact inspection, cleanup, and troubleshooting. Task 2 keeps `README.md` representative and links to the guide. Task 3 verifies the docs and skipped integration behavior.
- Placeholder scan: The plan avoids unresolved marker words in the intended documentation text. Verification explicitly checks the produced docs for placeholder markers.
- Type consistency: This plan only changes Markdown docs and does not introduce new Python APIs. Environment variable names match `tests/test_libvirt_boot_integration.py`.
