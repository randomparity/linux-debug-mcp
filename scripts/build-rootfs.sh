#!/usr/bin/env bash
# Build a minimal, bootable Fedora rootfs qcow2 for linux-debug-mcp.
#
# Produces a whole-disk ext4 qcow2 that boots as /dev/vda, prints the readiness
# marker on ttyS0, runs sshd, and carries an authorized public key. This is a
# host-prep convenience: the MCP server never builds images at tool-call time.
#
# Run unprivileged; the script elevates only the commands that need root.
set -euo pipefail

ROOTFS_PATH="${LINUX_DEBUG_MCP_ROOTFS:-/var/lib/linux-debug-mcp/rootfs/minimal.qcow2}"
RELEASEVER="${LINUX_DEBUG_MCP_ROOTFS_RELEASEVER:-43}"
IMAGE_SIZE="${LINUX_DEBUG_MCP_ROOTFS_SIZE:-2G}"
SSH_USER="${LINUX_DEBUG_MCP_ROOTFS_SSH_USER:-root}"
MARKER="linux-debug-mcp-ready"

# Resolve the invoking user's home even when launched via sudo, so the default
# authorized key is the human's, not root's.
invoking_user="${SUDO_USER:-${USER:-$(id -un)}}"
invoking_home="$(getent passwd "${invoking_user}" | cut -d: -f6)"
: "${invoking_home:=${HOME:-}}"

resolve_authorized_key() {
  if [[ -n "${LINUX_DEBUG_MCP_ROOTFS_AUTHORIZED_KEY:-}" ]]; then
    printf '%s\n' "${LINUX_DEBUG_MCP_ROOTFS_AUTHORIZED_KEY}"
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
    echo "error: required command '$1' not found on PATH" >&2
    exit 1
  }
}

require dnf
require virt-make-fs

authorized_key="$(resolve_authorized_key)"
if [[ -z "${authorized_key}" || ! -f "${authorized_key}" ]]; then
  echo "error: no SSH public key found. Set LINUX_DEBUG_MCP_ROOTFS_AUTHORIZED_KEY" >&2
  echo "       to a .pub file, or create ${invoking_home}/.ssh/id_ed25519.pub" >&2
  exit 1
fi

if [[ "${SSH_USER}" == "root" ]]; then
  ssh_home="/root"
else
  ssh_home="/home/${SSH_USER}"
fi

work="$(mktemp -d)"
cleanup() { sudo rm -rf "${work}"; }
trap cleanup EXIT

echo "Installing Fedora ${RELEASEVER} into ${work} ..."
sudo dnf --installroot="${work}" \
  --releasever="${RELEASEVER}" \
  --setopt=install_weak_deps=False \
  --setopt=tsflags=nodocs \
  install -y systemd fedora-release passwd openssh-server

sudo tee "${work}/etc/fstab" >/dev/null <<'EOF'
/dev/vda / ext4 defaults 0 1
EOF

sudo tee "${work}/etc/systemd/system/${MARKER}.service" >/dev/null <<EOF
[Unit]
Description=Signal linux-debug-mcp serial readiness
After=dev-ttyS0.device
Wants=dev-ttyS0.device

[Service]
Type=oneshot
ExecStart=/bin/sh -c 'echo ${MARKER} > /dev/ttyS0'
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

sudo mkdir -p "${work}/etc/systemd/system/multi-user.target.wants"
sudo ln -sf "../${MARKER}.service" \
  "${work}/etc/systemd/system/multi-user.target.wants/${MARKER}.service"
sudo ln -sf /usr/lib/systemd/system/sshd.service \
  "${work}/etc/systemd/system/multi-user.target.wants/sshd.service"

sudo mkdir -p "${work}${ssh_home}/.ssh"
sudo cp "${authorized_key}" "${work}${ssh_home}/.ssh/authorized_keys"
sudo chmod 700 "${work}${ssh_home}/.ssh"
sudo chmod 600 "${work}${ssh_home}/.ssh/authorized_keys"
sudo chown -R "${SSH_USER}:${SSH_USER}" "${work}${ssh_home}/.ssh" 2>/dev/null || true

# If a SELinux policy is ever pulled in transitively, relabel on first boot so the
# host-written authorized_keys gets the correct context before sshd matters.
sudo touch "${work}/.autorelabel"

echo "Packing ${ROOTFS_PATH} ..."
sudo mkdir -p "$(dirname "${ROOTFS_PATH}")"
sudo virt-make-fs --format=qcow2 --type=ext4 --size="${IMAGE_SIZE}" "${work}" "${ROOTFS_PATH}"
sudo chown "${invoking_user}:${invoking_user}" "${ROOTFS_PATH}"

echo "Done: ${ROOTFS_PATH}"
qemu-img info "${ROOTFS_PATH}" 2>/dev/null || true
