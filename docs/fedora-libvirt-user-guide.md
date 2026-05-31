# Fedora Libvirt User Guide

This guide walks through preparing a Fedora host and running the current
`target.boot` libvirt pilot. It assumes:

- Fedora 43 Workstation or a current Fedora release with modular libvirt daemons.
- The repository is checked out at `~/src/kdive`.
- A Linux source tree already exists at `~/src/linux`.
- The libvirt boot domain is dedicated to this project and starts with
  `kdive-`.

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
sudo tee /etc/polkit-1/rules.d/80-kdive-libvirt.rules >/dev/null <<'EOF'
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
`KDIVE_LIBVIRT_URI` to `qemu:///session`.

## 3. Prepare The Python Development Environment

From the MCP server checkout:

```bash
cd ~/src/kdive
just setup
```

If `just` is not installed, use the direct editable install:

```bash
cd ~/src/kdive
uv venv --allow-existing
uv pip install -e '.[test,dev]'
```

Run the prerequisite check with libvirt enabled:

```bash
uv run python - <<'PY'
from pathlib import Path
from kdive.server import prerequisites_handler

response = prerequisites_handler(
    artifact_root=Path.home() / ".local/state/kdive/runs",
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

The provider does not run `defconfig`: the source tree must already have a base
`.config` (or one already staged in the run's build dir). It will, however,
apply inline `config_lines` overrides on top of that base — the run writes them
to `inputs/override.config` and merges them with `scripts/kconfig/merge_config.sh`
followed by `make olddefconfig`. `config_lines` augment an existing base config;
they cannot bootstrap one from nothing.

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
sudo mkdir -p /var/lib/kdive/rootfs
sudo chown "$USER":"$USER" /var/lib/kdive/rootfs
export KDIVE_ROOTFS=/var/lib/kdive/rootfs/minimal.qcow2
```

### One command: `just rootfs`

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

```bash
just rootfs
```

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

The default `minimal` rootfs profile is `source_kind="builder"` and
`mutability="copy_on_write"`: a missing image makes `target.boot` fail with a
`configuration_error` whose `suggested_fix` names `just rootfs`, and each boot runs
from a throwaway qcow2 overlay so the base image stays pristine. `copy_on_write`
requires `qemu-img` on the host and a qcow2 base image.

If you already have a compatible rootfs image, copy it to that path and make
sure it writes this exact marker to `ttyS0`:

```text
kdive-ready
```

Verify the image exists before running the integration test:

```bash
qemu-img info "${KDIVE_ROOTFS}"
```

If you use `qemu:///system` with SELinux enforcing, label the rootfs directory
for libvirt image access:

```bash
sudo semanage fcontext -a -t virt_image_t '/var/lib/kdive/rootfs(/.*)?'
sudo restorecon -Rv /var/lib/kdive/rootfs
```

If `semanage` reports that the rule already exists, update it instead:

```bash
sudo semanage fcontext -m -t virt_image_t '/var/lib/kdive/rootfs(/.*)?'
sudo restorecon -Rv /var/lib/kdive/rootfs
```

**Why the image must be 0644 + `virt_image_t`.** Under the default `qemu:///system`, a separate
`qemu` user reads the image. With the per-boot copy-on-write overlay the built image is the
read-only *backing file* in the disk chain, and libvirt's security driver relabels only the
writable overlay, not the backing file. So the base image must be **independently readable**:
mode `0644` (the builder sets this with an unprivileged `chmod` — you own the file) **and**
labeled `virt_image_t` (inherited from the pre-prepared directory's fcontext above). If you put
the image under `$HOME` instead, use `qemu:///session` (a per-user qemu that runs as you and can
read it) — a `0700` home and `user_home_t` labels block the system `qemu` user.

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
export KDIVE_DOMAIN=kdive-dev
```

Choose the libvirt URI that works on your host:

```bash
export KDIVE_LIBVIRT_URI=qemu:///session
```

Use `qemu:///system` only after `virsh -c qemu:///system list --all` works from
the same shell without prompting.

Run the integration test:

```bash
cd ~/src/kdive
KDIVE_LIBVIRT_TEST=1 \
KDIVE_ROOTFS="${KDIVE_ROOTFS}" \
KDIVE_SOURCE=~/src/linux \
KDIVE_DOMAIN="${KDIVE_DOMAIN}" \
KDIVE_LIBVIRT_URI="${KDIVE_LIBVIRT_URI}" \
KDIVE_READINESS_MARKER=kdive-ready \
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
`KDIVE_GDBSTUB_ENDPOINT=127.0.0.1:<port>` to use a different local
port. Keep the host as `127.0.0.1`.

Run the live gdbstub integration test with a dedicated debug domain:

```bash
cd ~/src/kdive
export KDIVE_DEBUG_DOMAIN=kdive-dev-debug
KDIVE_LIVE_GDBSTUB=1 \
KDIVE_SOURCE=~/src/linux \
KDIVE_ROOTFS="${KDIVE_ROOTFS}" \
KDIVE_DOMAIN="${KDIVE_DEBUG_DOMAIN}" \
KDIVE_LIBVIRT_URI="${KDIVE_LIBVIRT_URI}" \
KDIVE_GDBSTUB_ENDPOINT=127.0.0.1:1234 \
KDIVE_READINESS_MARKER=kdive-ready \
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
virsh -c "${KDIVE_LIBVIRT_URI}" destroy "${KDIVE_DEBUG_DOMAIN:-$KDIVE_DOMAIN}"
```

Inspect the domain XML if a run fails ownership validation:

```bash
virsh -c "${KDIVE_LIBVIRT_URI}" dumpxml "${KDIVE_DEBUG_DOMAIN:-$KDIVE_DOMAIN}"
```

Remove the domain definition only if it is dedicated to this project:

```bash
virsh -c "${KDIVE_LIBVIRT_URI}" undefine "${KDIVE_DEBUG_DOMAIN:-$KDIVE_DOMAIN}"
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
kdive-ready
```

Also check `logs/console.log` in the run artifacts.

### The domain is rejected as not MCP-owned

The provider will not mutate an existing domain unless its XML metadata matches
the MCP provider, domain, and target profile. Use a fresh dedicated domain name
starting with `kdive-`, or manually remove the old dedicated test
domain after confirming it is safe:

```bash
virsh -c "${KDIVE_LIBVIRT_URI}" undefine "${KDIVE_DOMAIN}"
```
