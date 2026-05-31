# ADR 0037 — unprivileged project tooling: rootless rootfs builder + permission preflight

**Status:** Accepted (2026-05-30) · **Issue:** epic #100 (first-run readiness) · **Affects:**
`scripts/build-rootfs.sh` (rootless rewrite), `src/kdive/prereqs/checks.py` (`check_kvm_access`,
`check_libvirt_connect`, `check_rootfs_builder`), `src/kdive/server.py`
(`host.check_prerequisites` handler wiring), `justfile` (`check-no-sudo` recipe),
`tests/test_no_privilege_escalation.py` + `tests/test_unprivileged_build_integration.py` (new),
`docs/fedora-libvirt-user-guide.md` §5.
Spec: [2026-05-30-unprivileged-tooling-design.md](../superpowers/specs/2026-05-30-unprivileged-tooling-design.md).
**Supersedes:** the build-recipe (`scripts/build-rootfs.sh`) privilege-model portion of
[ADR 0031](0031-rootfs-image-source-abstraction.md) (decision 2's "the builder is a human-run host-prep
script" stands; the *how* — `sudo dnf --installroot` — is replaced). The `source_kind` abstraction,
`copy_on_write` overlay, and `builder` gate from #102 are unchanged.

## Context

During epic #100 verification, `just rootfs` required root: `scripts/build-rootfs.sh` ran
`sudo dnf --installroot` and then every later `sudo` (tee/mkdir/ln/chroot/chown/virt-make-fs/rm) only
existed to manipulate the root-owned files that first `sudo` created. This contradicts the project goal
that **all project tools run as a regular user**; the MCP server's runtime tools already honor it, but the
host-prep builder — the first thing a user hits on a clean machine — did not.

A second gap: nothing machine-checks that the running user actually *has* the permissions the workflow
needs. The existing preflight (ADR 0034) checks tool *presence* and runs `virsh uri`, but `virsh uri` only
reads local config and passes even when the user cannot connect to libvirt or reach `/dev/kvm`.

The decisions below are the ones this work leaves open and that have viable alternatives. The
build-time/runtime privilege boundary itself is settled (the server never escalates at tool-call time, ADR
0031 decision 2); what is open is *how the host-prep builder avoids root* and *how the preflight verifies
capability*.

## Decision

### 1. Rootless two-stage `virt-builder` builder → whole-disk-ext4 repack; fail loud on a missing template

`scripts/build-rootfs.sh` is rewritten to run with **no `sudo`/`pkexec`/`doas`**, in **two unprivileged
libguestfs stages**. `virt-builder "fedora-${RELEASEVER}"` emits a *partitioned* image (GPT + a separate
`/boot` + a btrfs/LVM root), but the boot provider boots whole-disk `root=/dev/vda`
(`libvirt_qemu.py:321,744`), **rejects** any other `root=` (`:778`), attaches the image as whole-disk `vda`
(`:667`), and supplies **no `<initrd>`** (`:658-661`) — a partitioned image would panic with `VFS: Cannot
open root device`. So:

- **Stage 1 (customize):** `virt-builder "fedora-${RELEASEVER}"` into a scratch image (`--install
  openssh-server`, `--run-command 'systemctl enable …'`, `--ssh-inject`,
  `--upload <tmpfile>:/etc/systemd/system/kdive-ready.service`). The `kdive-ready` unit is written to a temp
  file and `--upload`ed (a multi-line unit cannot ride `--write "path:literal"`).
- **Stage 2 (repack):** `virt-tar-out -a <scratch> / <tar>` then `virt-make-fs --type=ext4 --format=qcow2
  --size="${KDIVE_ROOTFS_SIZE}" <tar> "${KDIVE_ROOTFS}"` writes the root tree into a **no-partition-table
  whole-disk ext4 qcow2** — exactly the layout the old `virt-make-fs --type=ext4` recipe produced and the
  only layout the provider boots. A post-repack `guestfish` step then **normalizes `/etc/fstab`** to a lone
  `/ ext4` entry and removes `/etc/crypttab`: `virt-tar-out` captures the scratch image's fstab, written for
  its GPT layout (separate `/boot`, btrfs `subvol=root`, swap/EFI), and those entries reference devices the
  whole-disk artifact lacks — left intact, `local-fs.target` fails and `multi-user.target` is never reached,
  so the `kdive-ready` marker never fires (a boot-block of the same class as the partitioned-image panic).
  Scratch image + tar are user-owned temp files removed with plain `rm`.

**Boot-contract precondition** (recorded as part of the decision): the artifact is a single whole-disk ext4
filesystem with no partition table, directly mountable as `root=/dev/vda` with no initramfs; ext4 +
virtio-blk are in the default kernel (defconfig; `x86_64-debug` pins `CONFIG_VIRTIO_BLK=y`,
`server.py:255-273`); and its `/etc/fstab` describes only that single-device layout (no inherited
`/boot`/swap/EFI/`subvol=` entries; no `/etc/crypttab`). Partitioned/btrfs/LVM layouts are out — they would
need an initramfs the provider does not supply.

**SELinux sub-decision:** contexts must land on the **final** ext4 (relabeling the scratch image is
discarded when `virt-make-fs` builds a fresh filesystem, so `--selinux-relabel`/`.autorelabel` on the
scratch image is wrong). Mechanism: **first-boot `.autorelabel`** written into the final image is the
**safe default** (requires `selinux-policy` present, which a virt-builder Fedora image has; one-time
relabel + reboot before the marker); **xattr-preserving repack** (carry `security.selinux` through
`virt-tar-out` → `virt-make-fs`, no boot-time cost) is adopted **only if** `virt-tar-out` is confirmed to
preserve `security.selinux` xattrs — it exposes no xattr flag and many tar paths drop `security.*`, so an
unlabeled enforcing root is the silent failure mode.

libguestfs uses `/dev/kvm` when available and TCG otherwise; both are unprivileged. A template not in the
libguestfs index fails non-zero with a message naming `virt-builder --list` and `KDIVE_ROOTFS_RELEASEVER`
— no silent Cloud-image fallback, because a fallback would ship a different (preconfigured) base than
intended. Because `virt-builder` downloads and GPG-verifies the template, allocates the image, and runs
the appliance — and the repack stage extracts and rebuilds a filesystem — the failure contract also
enumerates no/blocked network, GPG/keyserver failure, disk-full, `virt-tar-out`/`virt-make-fs` repack
failure, `virt-make-fs` size-too-small (`KDIVE_ROOTFS_SIZE` — whose `2G` default was tuned for the old
minimal `dnf --installroot` tree and is re-validated against the fuller `virt-builder` footprint at
implementation), the `guestfish` fstab-normalization step, and the slow-TCG path, each with an actionable
message where the exit code allows.

### 2. Capability-based preflight: test the device and the connection, not group membership

Three new pure check functions, surfaced through `host.check_prerequisites` (ADR 0034 pattern):

- `check_kvm_access()` (`kvm.access`) — `os.access("/dev/kvm", R_OK|W_OK)`. PASSED when usable, **WARNING**
  otherwise. Because `/dev/kvm` access on stock Fedora comes from a logind `uaccess` seat ACL that exists
  only in an interactive login session, the same probe can PASS interactively and FAIL in the server's
  service/cron/non-login-SSH context; the `suggested_fix` therefore recommends **`kvm` group membership**
  (durable across contexts), not the ACL.
- `check_libvirt_connect(target_profile)` (`libvirt.connect`) — `virsh -c <uri> capabilities` against the
  URI the profile will use. This proves an authenticated *read* connection the daemon services (strictly
  more than `virsh uri`), but is **advisory**: it does **not** prove `org.libvirt.unix.manage`
  (define/start) permission, so a PASS can still be followed by a polkit denial at `target.boot` — the same
  advisory posture as `check_gdbstub_port`. `suggested_fix` distinguishes a `qemu:///system` polkit denial
  from a dead `qemu:///session` per-user daemon.
- `check_rootfs_builder()` (`rootfs.builder`) — `virt-builder` + `qemu-img` present; FAILED naming
  `libguestfs-tools`. It does not require `dnf`/`sudo`.

### 3. KVM access is a WARNING, not a FAILED

The workflow still functions under TCG (functional but slow), so a missing `/dev/kvm` surfaces the
performance consequence without gating capable-but-unaccelerated hosts.

### 4. Host-side-only no-escalation static guard, scoped to `scripts/`+`justfile`

A `just check-no-sudo` recipe (and a mirror `tests/test_no_privilege_escalation.py`) enforces "no host-side
privilege-escalation command invocation," matching escalation as a **command form**
(`! rg -n '(^|\s)(sudo|pkexec|doas)\s' scripts justfile`), mirroring the word-boundary anchoring of the
existing `check-docs`/`check-ipmi` guards. It is scoped to `scripts/` and `justfile` and deliberately does
**not** scan `src/`: the ~20 `sudo` references there are privilege prefixes for commands run *in the guest
over SSH* (`_target_python_remote_argv`, the `sudo -n true` preflight, ADR 0011/0028) — a distinct,
necessary concern, out of this guard's scope. The `docs/` prose that discusses escalation is not scanned.

### 5. Configurable image dir with a libvirt-readable default; do not flip the URI now

The image path is configurable (`KDIVE_ROOTFS` env / profile `source`). The default **stays**
`/var/lib/kdive/rootfs/minimal.qcow2` (`DEFAULT_ROOTFS_PROFILES["minimal"].source` — **no constant
change**) because the still-default `qemu:///system` boot requires both 0711+ traversal and the
`virt_image_t` SELinux label, which that curated, OS-admin-pre-prepared dir provides. The per-build write
into it is unprivileged; the one-time `sudo mkdir -p && chown $USER && semanage fcontext -t virt_image_t …
&& restorecon` is OS administration done once (already in the guide), out of scope. A `$HOME`/XDG path is
documented **only** as the `qemu:///session` alternative.

### 6. The base image must be independently qemu-readable under `qemu:///system`

With the `copy_on_write` overlay (ADR 0031) the base image is a **read-only backing file** the separate
`qemu` user must read. The provider handles only the **writable overlay** it is handed — `render_domain_xml`
emits a plain `<source file=…>` with no `chown`/`<seclabel>`/relabel for the base
(`libvirt_qemu.py:645-688`) — and libvirt's security driver is **not guaranteed** to relabel the read-only
backing file in the chain across versions/configs. Directory traversal + label are therefore necessary but
**not sufficient**; the base file's own DAC mode and MAC label matter. The builder closes this with two
unprivileged steps: the final `chmod 0644 "${KDIVE_ROOTFS}"` (caller owns the file) for DAC and the dir's
`virt_image_t` fcontext, inherited by the new file, for MAC. This is ADR 0031's host-prep documented in
*kind*, now at **file granularity** (mode 0644 + `virt_image_t` on the base, not only directory traversal).

### 7. Two-tier integration test: layout assertion (no KVM) + full boot (capable host)

`tests/test_unprivileged_build_integration.py` is split into two env-gated tiers. **Tier 1** (no boot, no
KVM; needs network + libguestfs) builds the image and asserts the boot-contract precondition directly —
single whole-disk ext4 filesystem with no partition table (via `virt-filesystems`/`guestfish`/`qemu-img
info`), a normalized `/etc/fstab` (no non-`/` entries) with no `/etc/crypttab`, file mode 0644, and caller
ownership of the image + temp files. **Tier 2** (capable host, KVM)
boots `minimal` to the `kdive-ready` serial marker, mirroring `test_libvirt_boot_integration.py:112`.
*Neither tier runs in default CI* (no network/tools/KVM), so the always-on protection is the §4 static
no-sudo guard + the `prereqs` unit tests + the documented boot-contract precondition; the tiers are opt-in
confirmation on a capable host, not a CI gate.

## Consequences

- A clean machine reaches a bootable default rootfs with `just rootfs` and **no root**; the lone host-prep
  escalation is gone.
- The preflight reports real capability (`kvm.access`, `libvirt.connect`, `rootfs.builder`) as a
  backward-compatible superset of ADR 0034's checks, `SKIPPED` when the gating profile name is omitted.
- The no-escalation invariant becomes machine-enforced for host-side tools, in both `just` and CI/pytest.
- `virt-builder` introduces a build-time network + template-download dependency, and the Stage-2 repack
  (`virt-tar-out` + `virt-make-fs` + the `guestfish` fstab/crypttab normalization) adds an
  extract-rebuild-normalize step (larger failure surface, §1); the old `dnf --installroot` repo-config
  dependency is gone.
- The default `qemu:///system` boot keeps working under the **existing provider contract**: the artifact is
  a whole-disk ext4 image (`root=/dev/vda`, no initramfs) and is independently qemu-readable (0644 +
  `virt_image_t`). The image dir and its SELinux label are unchanged; the build now also produces the right
  *layout* and *file mode* for that boot, where a raw `virt-builder` (partitioned) image would have panicked
  and a 0600 base would have hit EACCES.
- `check_libvirt_connect` can still PASS before a polkit `manage` denial at `target.boot`; this is an
  accepted advisory limitation, consistent with `check_gdbstub_port`.

## Considered & rejected

1. **Keep `dnf --installroot` under rootless podman / `unshare --map-root-user` + fakeroot.** Rejected:
   fragile (dnf-in-userns device-node and ownership quirks) and still conceptually "fake root";
   `virt-builder` reuses tooling already present and is genuinely unprivileged. (decision 1)
2. **`mkosi`.** Rejected: idiomatic for kernel dev but a new, heavier dependency with its own config model,
   not installed on the target host. (decision 1)
3. **Cloud image + `virt-customize`, as the primary path or an automatic fallback.** Rejected:
   `fedora-41/42/43` are in the index so the from-scratch minimal image is achievable directly; a Cloud
   base is heavier and preconfigured, and a silent fallback ships a different image than intended. A
   missing template fails loud with a one-line release-selection remedy instead. (decision 1)
4. **Check `kvm`/`libvirt` group membership.** Rejected: group membership is a proxy; `os.access` and a
   live `virsh capabilities` connection test the real thing. (The `kvm.access` `suggested_fix` still names
   `kvm` group for *durability* across login contexts — but as the remedy, not the probe.) (decision 2)
5. **Keep `virsh uri` as the libvirt check.** Rejected: it reads local config and passes when the user
   cannot connect. `virsh … capabilities` exercises the real read path; the check is named
   `libvirt.connect` to signal it proves connectivity, not `manage` permission. (decision 2)
6. **FAILED on missing `/dev/kvm`.** Rejected: the workflow functions under TCG, so a hard failure would
   block capable-but-unaccelerated hosts (e.g. nested virt). WARNING surfaces the cost without gating.
   (decision 3)
7. **Grep `src/` in the no-escalation guard.** Rejected: the ~20 `sudo` references in `src/` are in-guest
   SSH privilege prefixes (ADR 0011/0028), so a `src/` scan false-positives on the clean tree and fails CI.
   The guard targets host-side escalation only. (decision 4)
8. **Rely on review only for the no-escalation invariant.** Rejected: the original `sudo` crept in
   unflagged; an enforced guard is the only thing that keeps the invariant true over time. (decision 4)
9. **Default the image to `$HOME`/XDG for a sudo-free write.** Rejected: it breaks the still-default
   `qemu:///system` boot — a 0700 home blocks the `qemu` user's traversal, and home content is
   `user_home_t`, not the required `virt_image_t`. The pre-prepared `/var/lib/kdive/rootfs/` keeps the
   write sudo-free *and* libvirt-readable; `$HOME` is the documented `qemu:///session` alternative.
   (decision 5)
10. **Flip the default `libvirt_uri` to `qemu:///session` now.** Rejected: it drags in the guest-IP /
    user-mode-networking rework owned by #103 (ADR 0032 assumes libvirt-managed NAT). The preflight already
    verifies whichever URI a profile uses; changing the *default* is a tracked follow-up. (decision 5)
11. **Use the `virt-builder` output directly (partitioned image).** Rejected: the provider boots whole-disk
    `root=/dev/vda` with no initramfs (`libvirt_qemu.py:321,744,778,658-661`), so the partitioned/btrfs
    image `virt-builder` produces panics (`VFS: Cannot open root device`). The Stage-2 repack to whole-disk
    ext4 is what makes the artifact bootable under the existing contract. (decision 1)
12. **Change the provider to boot partitioned images (initramfs + partition-aware `root=`/`root=UUID`).**
    Rejected: large blast radius — the boot provider, the `root=` validator (`libvirt_qemu.py:778`), ADR
    0007/0031, and the gdbstub direct-boot path would all have to change. Repacking the image instead keeps
    the provider contract untouched. (decision 1)
13. **Rely on libvirt to relabel the backing chain.** Rejected: not guaranteed across libvirt
    versions/configs — the security driver relabels the writable overlay it is handed, not necessarily the
    read-only backing file (`libvirt_qemu.py:645-688` emits no seclabel for the base). The base is made
    independently readable (0644 + `virt_image_t`) instead. (decision 6)
14. **A single full-boot test as the only gate.** Rejected: it never runs in default CI (no KVM/network),
    so a layout or permission regression ships green. The KVM-free Tier 1 layout assertion closes that gap
    on any host with the tools. (decision 7)
15. **Keep the scratch image's `/etc/fstab` in the repacked artifact.** Rejected: it is written for the
    GPT layout (separate `/boot`, btrfs `subvol=root`, swap/EFI) whose devices the whole-disk ext4 lacks, so
    `local-fs.target` fails and `multi-user.target` (and the `kdive-ready` marker) is never reached — a
    boot-block invisible to the no-boot Tier 1 unless the fstab is normalized. Stage 2 rewrites it to a lone
    `/ ext4` entry and drops `/etc/crypttab`; Tier 1 asserts the result. (decision 1)
16. **Adopt the xattr-preserving repack as the default SELinux mechanism.** Rejected as the *default*:
    `virt-tar-out` exposes no xattr flag and tar paths commonly drop `security.*`, so it would silently
    ship an unlabeled enforcing root. `.autorelabel` first-boot is the safe default; the xattr path is
    adopted only after the roundtrip is confirmed to preserve `security.selinux`. (decision 1)
