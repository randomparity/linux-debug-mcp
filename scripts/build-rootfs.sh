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
