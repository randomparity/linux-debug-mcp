# Fedora Libvirt User Guide

This guide walks through preparing a Fedora host and running the current
`target.boot` libvirt pilot. It assumes:

- Fedora 43 Workstation or a current Fedora release with modular libvirt daemons.
- The repository is checked out at `~/src/linux-debug-mcp`.
- A Linux source tree already exists at `~/src/linux`.
- The libvirt boot domain is dedicated to this project and starts with
  `mcp-linux-debug-`.

The current pilot boots an x86_64 kernel with direct kernel boot, attaches a
disk-image rootfs as `/dev/vda`, waits for a serial readiness marker on
`ttyS0`, and can run SSH smoke tests after boot. It does not create rootfs
images, configure SSH, attach gdb, or manage production VMs.

For Python package installation, server smoke checks, and MCP client
registration, see [Installation](installation.md) and
[Client Setup](client-setup.md). For the implemented MCP tool surface and
workflow request examples, see [Tool Reference](tool-reference.md).

## 1. Install Fedora Host Packages

Install the host tools used by the server, the kernel build, and the libvirt
pilot:

```bash
sudo dnf install -y \
  git make gcc flex bison elfutils-libelf-devel openssl-devel bc \
  python3 python3-pip uv \
  gdb \
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
command -v gdb
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

## SSH Requirements For Smoke Tests

The Fedora rootfs must boot far enough for sshd to accept key-based or otherwise
noninteractive login. The MCP server uses `ssh` with `BatchMode=yes`, a
run-local `known_hosts` file, and bounded connection timeouts.

The MCP server does not install SSH keys, edit `sshd_config`, create host port
forwards, parse DHCP leases, or discover guest IP addresses. Configure the
`RootfsProfile` with `ssh_host`, `ssh_port`, `ssh_user`, optional `ssh_key_ref`,
and the allowed SSH options before running `target.run_tests` or
`workflow.build_boot_test`.

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

## 7. Run The Live QEMU Gdbstub Debug Pilot

The debug workflow uses the same host, kernel, rootfs, and readiness setup,
plus `gdb` and a debug-enabled target profile. The default local debug profile
exposes QEMU's gdbstub on `127.0.0.1:1234` only. It must not be exposed on a
non-local interface.

Because the default gdbstub endpoint uses a fixed local port, only one debug
boot can own `127.0.0.1:1234` at a time. If another process already listens on
that port, the boot fails before mutating the domain and reports the collision
as an infrastructure failure. Stop the other debug run or choose a different
local endpoint for a custom target profile. For the integration test, set
`LINUX_DEBUG_MCP_GDBSTUB_ENDPOINT=127.0.0.1:<port>` to use a different local
port. Keep the host as `127.0.0.1`.

Run the live gdbstub integration test with a dedicated debug domain:

```bash
cd ~/src/linux-debug-mcp
export LINUX_DEBUG_MCP_DEBUG_DOMAIN=mcp-linux-debug-dev-debug
LINUX_DEBUG_MCP_LIVE_GDBSTUB=1 \
LINUX_DEBUG_MCP_SOURCE=~/src/linux \
LINUX_DEBUG_MCP_ROOTFS="${LINUX_DEBUG_MCP_ROOTFS}" \
LINUX_DEBUG_MCP_DOMAIN="${LINUX_DEBUG_MCP_DEBUG_DOMAIN}" \
LINUX_DEBUG_MCP_LIBVIRT_URI="${LINUX_DEBUG_MCP_LIBVIRT_URI}" \
LINUX_DEBUG_MCP_GDBSTUB_ENDPOINT=127.0.0.1:1234 \
LINUX_DEBUG_MCP_READINESS_MARKER=linux-debug-mcp-ready \
uv run pytest tests/test_qemu_gdbstub_integration.py -q
```

The source tree must contain both `arch/x86/boot/bzImage` and the matching
unstripped `vmlinux`. The workflow builds, boots with gdbstub enabled, waits for
serial readiness, and attaches the managed gdb session. It does not run SSH
smoke tests; run `workflow.build_boot_test` or `target.run_tests` separately if
you need guest command coverage.

## 8. Inspect Artifacts And Clean Up

The integration test uses a temporary artifact root managed by pytest. For MCP
tool runs outside the integration test, boot and debug artifacts are written
under:

```text
<artifact-root>/<run-id>/
  logs/console.log
  logs/boot.log
  target/domain.xml
  target/boot-plan.json
  debug/
  summaries/boot-summary.json
```

Successful integration runs may leave the dedicated domain running. Stop it
manually when needed. Use the same domain variable you passed to the specific
integration test:

```bash
virsh -c "${LINUX_DEBUG_MCP_LIBVIRT_URI}" destroy "${LINUX_DEBUG_MCP_DEBUG_DOMAIN:-$LINUX_DEBUG_MCP_DOMAIN}"
```

Inspect the domain XML if a run fails ownership validation:

```bash
virsh -c "${LINUX_DEBUG_MCP_LIBVIRT_URI}" dumpxml "${LINUX_DEBUG_MCP_DEBUG_DOMAIN:-$LINUX_DEBUG_MCP_DOMAIN}"
```

Remove the domain definition only if it is dedicated to this project:

```bash
virsh -c "${LINUX_DEBUG_MCP_LIBVIRT_URI}" undefine "${LINUX_DEBUG_MCP_DEBUG_DOMAIN:-$LINUX_DEBUG_MCP_DOMAIN}"
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
