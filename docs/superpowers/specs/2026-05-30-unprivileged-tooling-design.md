# Unprivileged project tooling: rootless rootfs builder + permission preflight

**Status:** Accepted (2026-05-30) · **Epic:** #100 (first-run readiness) ·
**ADR:** [0037](../../adr/0037-unprivileged-tooling.md) ·
**Supersedes:** the build-recipe (`scripts/build-rootfs.sh` privilege model) portion of
[ADR 0031](../../adr/0031-rootfs-image-source-abstraction.md). The `source_kind` abstraction,
`copy_on_write` overlay, and `builder` gate from #102 are unchanged.

## Problem

During epic #100 verification, `just rootfs` required root credentials to complete. The recipe runs
`scripts/build-rootfs.sh`, which uses `sudo` for `dnf --installroot`, the in-installroot
`tee`/`mkdir`/`ln`/`chroot`/`chown`, `virt-make-fs`, the final output `chown`, and the cleanup
`rm -rf`. The root requirement **cascades from one root**: `sudo dnf --installroot` creates root-owned
files in the work tree, and every later `sudo` exists only to read, modify, pack, or delete those
root-owned files.

This violates the project goal that **all project tools run as a regular user, without elevated
permissions**. The MCP server's runtime tools already honor this (an established invariant: "the server
performs no privileged provisioning at tool-call time"). The host-prep builder is the lone exception, and
it is the one a user hits first on a clean machine.

A second gap: there is no machine-checkable verification that the running user actually *has* the
permissions the workflow needs (KVM acceleration, a usable libvirt connection for the selected URI, the
unprivileged build toolchain). The existing preflight (`check_prerequisites`, ADR 0034) checks tool
*presence* and runs `virsh uri`, but `virsh uri` only reads local config — it passes even when the user
cannot actually connect or define a domain.

## Goal

1. `just rootfs` — and every other project tool — completes as an unprivileged user with **no host-side**
   `sudo`, `pkexec`, `doas`, or setuid escalation in its invocation. (In-guest `sudo` run *over SSH* by the
   server's runtime tools is a separate, blessed concern — see the background fact below and §4.)
2. The rootfs image is built entirely inside an unprivileged libguestfs appliance and written to a
   **configurable** path whose default is a curated, libvirt-readable system dir (pre-prepared once by an
   OS admin; the per-build write is unprivileged).
3. The preflight reports, as `PrerequisiteCheck` results, whether the running user has the permissions the
   roundtrip needs — by **testing the actual capability**, not proxies like group membership.
4. A static guard prevents privilege-escalation from regressing back into project tools.
5. Env-gated integration tests prove the unprivileged build path: a KVM-free Tier 1 asserts the artifact's
   whole-disk-ext4 layout + qemu-readable mode, and a capable-host Tier 2 boots it end-to-end.

Out of scope (see Non-goals): flipping the default libvirt URI to `qemu:///session` and the
networking/guest-IP rework that implies; OS administration the human does once (installing packages,
configuring polkit) — that is not a "project tool".

## Background facts (verified on the development host, Fedora 43)

- `virt-builder`, `virt-customize`, `virt-make-fs`, `guestfish`, `qemu-img` are installed; `mkosi` is not.
- `virt-builder --list` includes `fedora-41`, `fedora-42`, and `fedora-43` (x86_64) — the host's release
  is covered, so the from-scratch `virt-builder` path needs no Cloud-image fallback.
- libguestfs runs **unprivileged** (a `guestfish -N disk` smoke completed as uid 1000, exit 0).
- `/dev/kvm` is present and usable by the invoking user. The access model is **context-dependent**: stock
  Fedora ships `/dev/kvm` as `0660 root:kvm` plus a logind `uaccess` seat ACL that grants the *interactive
  login* user access without `kvm` group membership (the `crw-rw-rw-` world-rw mode seen on this host is a
  local, non-default deviation). That seat ACL does **not** follow into a service/cron/non-login-SSH
  context, so durable access across contexts comes from `kvm` **group membership**, not the seat ACL.
- Default profiles hardcode `libvirt_uri="qemu:///system"` (`server.py`); `TargetProfile.libvirt_uri`
  defaults to `None`.
- `sudo` appears in `src/` ~20 times (e.g. `server.py:371`, `server.py:3665`, `prereqs/drgn_probe.py`,
  `providers/local_ssh_tests.py`) and is **legitimate**: these are privilege prefixes for commands run *on
  the remote guest over SSH* (`_target_python_remote_argv`, the `_execute_introspect_call` `sudo -n true`
  preflight), governed by ADR 0011/0028 — a distinct, necessary concern, **out of scope** for this work.
  Host-side escalation lives only in `scripts/build-rootfs.sh` (CI runner setup aside — that is
  GitHub-Actions host provisioning, not a project tool).

## Design

### 1. Rootless rootfs builder (`scripts/build-rootfs.sh` rewrite)

The script is rewritten to run **with no `sudo`**. The whole image is produced inside the libguestfs
appliance via `virt-builder`. There is **no Cloud-image fallback**: a missing template fails loud (see
below). The `fedora-41/42/43` x86_64 templates are confirmed present in the libguestfs index, so the
host's current release is covered; an older index simply yields the actionable error. The
environment-variable interface and defaults are preserved unchanged (the output path default stays
`/var/lib/kdive/rootfs/minimal.qcow2`; see §2):

| Variable | Default | Meaning |
|---|---|---|
| `KDIVE_ROOTFS` | `/var/lib/kdive/rootfs/minimal.qcow2` | output image path (a libvirt-readable, `virt_image_t`-labeled dir; see §2) |
| `KDIVE_ROOTFS_RELEASEVER` | `43` | Fedora release |
| `KDIVE_ROOTFS_SIZE` | `2G` | image size (**verify at implementation:** the `2G` default was tuned for the old minimal `dnf --installroot` tree; a fuller `virt-builder` Fedora base + sshd may need more headroom for the Stage-2 ext4 to fit content + fs overhead — re-validate against the real repacked footprint and raise if `virt-make-fs` reports size-too-small) |
| `KDIVE_ROOTFS_SSH_USER` | `root` | guest user that receives the authorized key |
| `KDIVE_ROOTFS_AUTHORIZED_KEY` | first existing of the invoking user's `~/.ssh/id_ed25519.pub`, `~/.ssh/id_rsa.pub` | public key to install |

The build is **two stages, both unprivileged libguestfs**, because `virt-builder "fedora-${RELEASEVER}"`
emits a *partitioned* Fedora image (GPT + a separate `/boot` + a btrfs/LVM root) that the boot provider
cannot mount: the provider boots whole-disk `root=/dev/vda` (`libvirt_qemu.py:321,744`), **rejects** any
other `root=` (`:778`), attaches the image as whole-disk `vda` (`:667`), and supplies **no `<initrd>`**
(`:658-661`). A partitioned image would panic with `VFS: Cannot open root device`. The first stage
customizes; the second repacks the root tree into a no-partition-table whole-disk ext4 qcow2 — exactly the
layout the old `virt-make-fs --type=ext4` recipe produced (`docs/fedora-libvirt-user-guide.md:254-255`),
and the contract the provider requires.

**Stage 1 — customize (partitioned scratch image).** The `kdive-ready` serial unit is written to a temp
file first (a multi-line unit cannot ride `--write "path:literal"`), then `--upload`ed:

```bash
unit_file="$(mktemp)"
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

scratch="$(mktemp --suffix=.qcow2)"
virt-builder "fedora-${RELEASEVER}" \
  --format qcow2 --size "${IMAGE_SIZE}" --output "${scratch}" \
  --install openssh-server \
  --run-command 'systemctl enable sshd.service' \
  --ssh-inject "${SSH_USER}:file:${authorized_key}" \
  --upload "${unit_file}:/etc/systemd/system/${MARKER}.service" \
  --run-command "systemctl enable ${MARKER}.service"
```

**Stage 2 — repack to whole-disk ext4 (the boot artifact).** Extract the customized root tree, write it
into a no-partition-table ext4 qcow2, then **normalize the inherited mount config**:

```bash
rootfs_tar="$(mktemp --suffix=.tar)"
virt-tar-out -a "${scratch}" / "${rootfs_tar}"
virt-make-fs --type=ext4 --format=qcow2 --size="${IMAGE_SIZE}" "${rootfs_tar}" "${KDIVE_ROOTFS}"

# Normalize /etc/fstab (and drop /etc/crypttab): the scratch image's entries reference the
# partitions/subvols of its GPT layout (separate /boot, btrfs subvol=root, swap/EFI) that the
# whole-disk ext4 artifact does not have. Left intact they make local-fs.target fail and block
# multi-user.target — so the kdive-ready marker never fires. A single root entry is sufficient
# (the kernel already mounts root via root=/dev/vda). The same session disables guest-internal
# SELinux so the host-written authorized_keys is read without a relabel and the first boot does
# not relabel+reboot (a false BOOT_TIMEOUT risk); this is independent of the host-side
# virt_image_t/0644 labeling of the image file (§2).
guestfish --rw -a "${KDIVE_ROOTFS}" -i <<'EOF'
write /etc/fstab "/dev/vda / ext4 defaults 0 1\n"
write /etc/selinux/config "SELINUX=disabled\nSELINUXTYPE=targeted\n"
rm-f /etc/crypttab
EOF

chmod 0644 "${KDIVE_ROOTFS}"   # caller owns the file; no sudo — see §2 (qemu read under qemu:///system)
rm -f "${scratch}" "${rootfs_tar}" "${unit_file}"
```

The unit body is the existing one from `scripts/build-rootfs.sh:79-92` (echoes the marker to `/dev/ttyS0`).
Both stages run inside the unprivileged appliance; the scratch image, tar, and unit file are all user-owned
temp files removed with plain `rm`.

**Why the fstab normalization is load-bearing.** `virt-tar-out` captures the *whole booted-OS tree*,
including the scratch image's `/etc/fstab`, which is written for its GPT layout (a separate `/boot`, a
btrfs `subvol=root` root, possibly swap/EFI), each keyed by a UUID or device absent in the single
whole-disk ext4 artifact. Left intact, `systemd-fstab-generator` emits mount units for those entries;
the missing devices make `local-fs.target` fail (or block on the device-timeout), `multi-user.target` is
never reached, and the `kdive-ready` unit (`WantedBy=multi-user.target`) never writes the marker — a
boot-block of the same class as the partitioned-image panic, one layer down. The old `dnf --installroot`
recipe never hit this because it built the tree (and its fstab) from scratch; repacking a full OS image
does not get that for free, so the normalization is mandatory, not cosmetic.

- `--ssh-inject`, `--run-command`, `--upload` perform key install, sshd enable, and the `kdive-ready`
  serial-unit install as unprivileged libguestfs operations on the scratch image; `virt-tar-out` +
  `virt-make-fs` repack the result into the whole-disk ext4 artifact.
- A non-root `KDIVE_ROOTFS_SSH_USER` is created with an extra Stage-1 `--run-command 'useradd …'` so the
  injected key lands on a real account (root always exists). **Verify at implementation:** `virt-builder`
  applies operations in its own fixed order, not CLI order, so confirm the user-create is sequenced before
  `--ssh-inject` per `virt-builder(1)` (or create the user via a guaranteed-ordered `--firstboot`/cloud
  step) — otherwise the inject targets a not-yet-existent user.

**Boot-contract precondition (the artifact must satisfy this, not merely "be qcow2").** The produced image
is a **single whole-disk ext4 filesystem with no partition table**, directly mountable as `root=/dev/vda`
with **no initramfs** — matching the provider (`libvirt_qemu.py:321,744,778` whole-disk `root=/dev/vda`
enforced; `:658-661` no `<initrd>`; `:667` whole-disk `vda`) and the old recipe's rationale
(`docs/fedora-libvirt-user-guide.md:254-255`). ext4 + virtio-blk are in the default kernel (defconfig;
`x86_64-debug` pins `CONFIG_VIRTIO_BLK=y`, `server.py:255-273`). Partitioned or btrfs/LVM layouts are
explicitly **out**: they would need an initramfs to assemble the root device, which the provider does not
supply. The image's `/etc/fstab` must describe **only** this single-device layout (a lone `/ ext4` entry,
or empty) — no inherited `/boot`/swap/EFI/`subvol=` entries — and `/etc/crypttab` must be absent, or boot
stalls before the marker (see Stage 2). The qcow2 container also still satisfies the `copy_on_write`
overlay's qcow2-base precondition (ADR 0031 §3).

**SELinux in the repacked image — disabled.** This local QEMU debug rootfs ships with **guest-internal
SELinux disabled**: the Stage-2 `guestfish` normalization uploads a canonical `/etc/selinux/config` with
`SELINUX=disabled` alongside the `/etc/fstab` rewrite. This is chosen over trying to label the repacked
filesystem because (a) it **sidesteps the "contexts must land on the final ext4" problem entirely** —
relabeling the scratch image is discarded when `virt-make-fs` builds a fresh filesystem, and `virt-tar-out`
exposes no xattr flag (many tar paths drop `security.*`), so a labeled repack is not reliable; (b) it
**removes the first-boot relabel + reboot** an `.autorelabel` would force, which risks a false
`BOOT_TIMEOUT` before the `kdive-ready` marker fires (worse under TCG, where readiness is a single
`deadline = timeout`, `libvirt_qemu.py:239`); and (c) it is **acceptable because this is a disposable local
QEMU debug rootfs, not a security boundary**. This is **guest-internal** SELinux only and does **not**
change the host-side `virt_image_t` + 0644 requirement on the base image *file* (§2 is unaffected).

**Missing template — fail loud.** If `virt-builder` reports `fedora-${RELEASEVER}` is not in the index
(an older libguestfs install), the script exits non-zero with a message naming `virt-builder --list` and
`KDIVE_ROOTFS_RELEASEVER` so the human selects an available release. No automatic Cloud-image download or
alternate build path is attempted — the remedy is a one-line release selection, and a silent fallback
would ship a different (preconfigured) base than intended.

**Privilege model.** No command in the script runs under `sudo`/`pkexec`/`doas`. libguestfs uses
`/dev/kvm` when available (fast) and TCG otherwise (slow but unprivileged). The script writes into the
**pre-prepared** default dir `/var/lib/kdive/rootfs/` **unprivileged** — no `chown`, because the one-time
`sudo mkdir -p /var/lib/kdive/rootfs && chown $USER && semanage fcontext -t virt_image_t … &&
restorecon` is OS administration done once (already in the guide,
`docs/fedora-libvirt-user-guide.md:211-212, 309-317`), not a per-build step. That pre-prep is what makes
the per-build write sudo-free without breaking the default `qemu:///system` boot. The final
`chmod 0644 "${KDIVE_ROOTFS}"` is likewise unprivileged — the caller owns the file it just wrote — and is
what makes the base image readable by the separate `qemu` user under `qemu:///system` (§2).

**Failure contract.** `virt-builder` does real work — it downloads and GPG-verifies the template,
allocates the image, and runs the libguestfs appliance — so it fails in more than one way. Fail fast with
actionable messages:

- required tool missing (`virt-builder`/`qemu-img`) → names `libguestfs-tools`.
- no SSH public key found → names `KDIVE_ROOTFS_AUTHORIZED_KEY`.
- template not in the index → names `virt-builder --list` and `KDIVE_ROOTFS_RELEASEVER`.
- no/blocked **network** (template download can't reach the mirror) → names that network + template
  download are build-time prerequisites.
- missing GPG key / unreachable keyserver (template signature can't be verified) → names the keyserver/GPG
  failure where the exit context allows.
- **disk-full** while allocating the image or running the appliance → names the target dir and free-space
  need.
- **repack failure** (`virt-tar-out` extract or `virt-make-fs` filesystem build) → names the failing tool
  and that the libguestfs repack stage produces the bootable whole-disk ext4 artifact.
- **fstab-normalization failure** (the post-repack `guestfish` rewrite of `/etc/fstab`/`crypttab`) → names
  the step and that an un-normalized image stalls at boot before the `kdive-ready` marker.
- **`virt-make-fs` size-too-small** (the extracted tree exceeds `--size`) → names `KDIVE_ROOTFS_SIZE` as
  the knob to raise.
- slow/failed appliance when `/dev/kvm` is absent (TCG path) → notes the build is running unaccelerated
  (see the `kvm.access` check) and may be slow rather than broken.

`virt-builder`'s exit codes do not cleanly distinguish all of these; where they don't, the script emits a
single "build failed — network access and template download are required" note pointing at the most
common causes rather than guessing. `rootfs.builder` (the check) and a build-start note both state that
**network access and template download are build-time prerequisites**. Any temp files are user-owned and
removed with plain `rm`.

### 2. Image path is configurable; the default stays a libvirt-readable system dir

The image path is **configurable** (the `KDIVE_ROOTFS` env var for the builder, the profile `source`
field for boot). The default stays `/var/lib/kdive/rootfs/minimal.qcow2` — **no constant change**:

- `scripts/build-rootfs.sh` `KDIVE_ROOTFS` default keeps `/var/lib/kdive/rootfs/minimal.qcow2`.
- `DEFAULT_ROOTFS_PROFILES["minimal"].source` in `server.py:294-305` is already that path and is unchanged.

The default is deliberately a **curated, libvirt-readable, `virt_image_t`-labeled** system dir, because the
still-default `qemu:///system` boot requires both 0711+ traversal to the image and the `virt_image_t`
SELinux label. A `$HOME`/XDG path would break that boot under `qemu:///system`: a 0700 home directory
blocks the `qemu` user's traversal, and home content carries the `user_home_t` label, not `virt_image_t`.
A `$HOME`/XDG location is therefore documented **only** as the `qemu:///session` alternative, where a
per-user qemu runs as the invoking user and can read it.

The per-build write into the curated dir is unprivileged because the dir is pre-prepared once by an OS
admin (§1 "Privilege model"); the build itself never escalates. Frozen manifests are unaffected (the
immutable `RunRequest`/`RootfsProfile` keep whatever they were created with).

**The base image must be independently qemu-readable under `qemu:///system`.** With the `copy_on_write`
overlay (ADR 0031), the base image is now a **read-only backing file** in the disk chain and the separate
`qemu` user must *read* it. The provider handles only the **writable overlay** it is handed: it emits no
`chown`/`<seclabel>`/relabel for the base (confirmed — `render_domain_xml` writes a plain
`<source file=…>` with no security label, `libvirt_qemu.py:645-688`), and libvirt's security driver, while
it relabels the writable overlay, is **not guaranteed** to relabel the read-only backing file in the chain
across versions/configs. Directory traversal + label are therefore necessary but **not sufficient**; the
base file's own DAC mode and MAC label matter. The builder closes this with two unprivileged steps it
already does: the final `chmod 0644 "${KDIVE_ROOTFS}"` (the caller owns the file — no sudo) for DAC, and
the `virt_image_t` fcontext on the pre-prepared dir, inherited by the newly created file, for MAC. This is
the host-prep ADR 0031 already documents in *kind*, now stated at **file granularity** (mode 0644 +
`virt_image_t` on the base, not only directory traversal). `docs/fedora-libvirt-user-guide.md` §5
(downstream) documents the 0644 + label requirement.

### 3. Permission preflight checks (`prereqs/checks.py`)

Three new **pure** check functions, surfaced through the existing `host.check_prerequisites` tool and
`just check-host`. They follow ADR 0034's pattern: pure functions taking resolved profile objects (or
`None`), name resolution stays in the server handler, gated by the `target_profile`/`rootfs_profile`
parameters that already exist. No new tool, response type, or `ErrorCategory`.

**The governing principle: test the capability, not a proxy.** Each check exercises the real operation
rather than a stand-in like group membership. The one caveat is that a capability test is only true *for
the context it runs in* — see the kvm context-skew note below.

- **`check_kvm_access()`** → `check_id="kvm.access"`. Uses `os.access("/dev/kvm", os.R_OK | os.W_OK)` —
  this tests reality, not group membership. PASSED when usable. **WARNING** (not FAILED) when
  absent/unusable, with a message that KVM acceleration is unavailable so libguestfs/qemu fall back to TCG
  (functional but slow). **Context-skew caveat:** `/dev/kvm` access on stock Fedora is granted by a logind
  `uaccess` seat ACL that exists only in an interactive login session, so this check can PASS when run
  interactively while the MCP server FAILS the same probe in a service/cron/non-login-SSH context. The
  `suggested_fix` therefore recommends **`kvm` group membership** (durable across all contexts) rather
  than relying on the seat ACL. WARNING — not FAILED — because the workflow still works under TCG.
- **`check_libvirt_connect(target_profile)`** → `check_id="libvirt.connect"`. Resolves the URI the profile
  will use (profile `libvirt_uri`, else the build-time default), then runs `virsh -c <uri> capabilities`
  as the probe. This proves an **authenticated read connection** the daemon services — strictly more than
  the `virsh uri`-only `_libvirt_check`, which passes on local config it cannot actually use. It does
  **not** prove `define`/`start` (`org.libvirt.unix.manage`) permission, so a PASS here can still be
  followed by a polkit denial at `target.boot`; the check is therefore **advisory**, like
  `check_gdbstub_port` (`prereqs/checks.py:450-504`) which warns that a free port can be taken before boot
  binds it. PASSED on exit 0; FAILED otherwise, distinguishing the actionable causes in `suggested_fix`:
  polkit/permission denial under `qemu:///system` (join `libvirt` group / install the polkit rule) vs. a
  non-running per-user daemon under `qemu:///session` (`systemctl --user start virtqemud.socket`). Probe
  is injected (the `PrerequisiteRunner`) for deterministic unit tests.
- **`check_rootfs_builder()`** → `check_id="rootfs.builder"`. Verifies the unprivileged toolchain:
  `virt-builder` and `qemu-img` present. FAILED naming `libguestfs-tools` when either is missing. It
  explicitly does **not** require `dnf` or `sudo` (the old recipe's dependencies are gone).

The handler appends these to the flat `checks` list, `SKIPPED` when the relevant name is omitted —
a backward-compatible superset, consistent with ADR 0034.

### 4. Static "no host-side privilege escalation" guard

The invariant is **"no host-side privilege-escalation command invocation"**, scoped to **`scripts/` and
`justfile` only**. It deliberately does **not** grep `src/`: the ~20 `sudo` references there are privilege
prefixes for commands run *in the guest over SSH* (`_target_python_remote_argv`, the `sudo -n true`
preflight), which are a distinct, necessary concern governed by ADR 0011/0028 and explicitly out of this
guard's scope. Greping `src/` would false-positive on the clean tree and fail CI.

- `just check-no-sudo` recipe matching escalation as a **command form**, not a substring — mirroring the
  word-boundary anchoring the existing `check-docs`/`check-ipmi` guards use:
  `! rg -n '(^|\s)(sudo|pkexec|doas)\s' scripts justfile`. (The `\s`-delimited form matches an invocation
  like `sudo dnf …` but not the word inside a comment or a variable name.)
- The `docs/` exemption posture from `check-docs` is kept: ADR/spec prose that *discusses* escalation is
  not scanned (it legitimately cites the rejected approaches), and `src/` is simply not in scope.
- A mirror pytest (`tests/test_no_privilege_escalation.py`) asserts the **same scoped invariant**
  (`scripts/` + `justfile`) so the guard runs both under `just` and under `pytest`/CI even when `just` is
  absent.
- Wired into CI alongside `check-docs`/`check-ipmi`.

### 5. Host-capability integration tests (two env-gated tiers)

`tests/test_unprivileged_build_integration.py`, env-gated like `test_libvirt_boot_integration.py` /
`test_qemu_gdbstub_integration.py` (skipped unless an opt-in env var is set and the tools exist). It is
split into **two tiers** so a layout regression (Finding #1/#2) is caught without requiring a KVM-capable
host:

**Tier 1 — layout assertion (no boot, no KVM).** Build the image (needs network + libguestfs; runs under
TCG if `/dev/kvm` is absent) then assert the **boot-contract precondition** directly, before any boot:
- via `virt-filesystems`/`guestfish`/`qemu-img info` that the artifact is a **single whole-disk ext4
  filesystem with no partition table** (no GPT, no `/boot`, no btrfs/LVM root) — the exact failure mode the
  provider would panic on;
- via `guestfish` that the repacked `/etc/fstab` contains **no non-`/` mount entries** (no inherited
  `/boot`/swap/EFI/`subvol=`) and `/etc/crypttab` is absent — the fstab-stall failure mode (Stage 2) that a
  layout-only check would otherwise miss, caught here without a boot;
- that the file mode is group/other-readable (**0644**, i.e. qemu-readable under `qemu:///system`, §2);
- that the produced image and the scratch image/tar/unit temp files are **owned by the caller**
  (`stat().st_uid == os.getuid()`).
This tier is fast and gated only on **tools + network**, not KVM.

**Tier 2 — full boot (capable host).** `target.boot` with the `minimal` profile reaches the
**`kdive-ready` marker** on the serial console — the existing observable the other boot integration tests
already assert (mirrors `test_libvirt_boot_integration.py` gating/marker assertion, `:112`), not a vague
"boots far enough". Needs KVM ideally.

Both tiers also assert the round-1 signals: the **script source and the argv the test invokes** contain
**no `sudo`/`pkexec`/`doas` and no setuid** invocation (the durable static guarantee is the §4 guard;
inspecting `virt-builder`'s live child process tree post-hoc is racy and not relied on). (The earlier
draft's `os.geteuid()`-unchanged assertion stays dropped: the test process never escalates, so it can only
ever pass.)

**Coverage gap, stated plainly (no silent caps).** *Neither tier runs in default CI* — Tier 1 needs network
+ libguestfs and Tier 2 needs KVM, and the default runners have none. The unit tests only patch
`os.access`/inject a runner, so they cannot catch a layout or permission regression. The **always-on
protection** is therefore the §4 static no-sudo guard, the `prereqs` unit tests, and the documented
boot-contract precondition (§1) — the integration tiers are an opt-in confirmation on a capable host, not a
CI gate. Both tiers silent-skip on incapable hosts so CI stays green; the gating is preserved exactly as the
existing integration tests do it.

### 6. Docs + ADR

- **ADR 0037** records the decisions with their rejected alternatives (see below) and supersedes the
  build-recipe privilege-model portion of ADR 0031.
- `docs/fedora-libvirt-user-guide.md` §5 is rewritten to the sudo-free `just rootfs` and documents the
  base-image **0644 + `virt_image_t`** requirement (§2): the file must be group/other-readable and
  `virt_image_t`-labeled so the separate `qemu` user can read it as a backing file under `qemu:///system`.
  The one-time `sudo mkdir/chown /var/lib/kdive/rootfs` + SELinux labeling (`semanage fcontext -t
  virt_image_t …`, `restorecon`) **stays** as a documented OS-admin pre-prep step (already at
  `docs/fedora-libvirt-user-guide.md:211-212, 309-317`) — it is what makes the per-build write sudo-free
  while keeping the dir libvirt-readable for `qemu:///system`. The libvirt host-setup `sudo` (package
  install, polkit, socket enablement) likewise **stays** — that is OS administration, not a project tool,
  and is explicitly out of scope.

## Decisions to record in ADR 0037 (with rejected alternatives)

1. **Unprivileged two-stage libguestfs builder: `virt-builder` customize → repack to whole-disk ext4 (fail
   loud on a missing template).** Stage 1 `virt-builder`s a partitioned scratch image; Stage 2
   `virt-tar-out` + `virt-make-fs --type=ext4` repacks the root tree into a no-partition-table whole-disk
   ext4 qcow2, the only layout the provider boots (`root=/dev/vda`, no initramfs). The repack also
   **normalizes the inherited `/etc/fstab`** (to a lone `/ ext4` entry) and drops `/etc/crypttab`, else the
   scratch image's GPT-layout mount entries stall boot before the marker. Guest-internal SELinux is
   **disabled** in the repacked image (a canonical `/etc/selinux/config`), which avoids both the unreliable
   labeled-repack and the first-boot relabel+reboot (false-`BOOT_TIMEOUT` risk); the host-side
   `virt_image_t`/0644 labeling of the image *file* is unaffected (§2).
   - Rejected: *keep `dnf --installroot` under rootless podman / `unshare --map-root-user` + fakeroot* —
     fragile (dnf-in-userns device-node and ownership quirks), and still conceptually "fake root".
   - Rejected: *mkosi* — idiomatic for kernel dev but a new, heavier dependency with its own config model;
     not installed on the target host. virt-builder reuses tooling already present.
   - Rejected: *Cloud image + `virt-customize`, either as the primary path or an automatic fallback* —
     `fedora-41/42/43` are present in the index, so the from-scratch minimal image is achievable directly;
     a Cloud base is heavier and preconfigured, and a silent fallback would ship a different image than
     intended. A missing template instead fails loud with a one-line release-selection remedy.
   - Rejected: *use the `virt-builder` output directly (partitioned)* — the provider boots whole-disk
     `root=/dev/vda` with no initramfs (`libvirt_qemu.py:321,744,778,658-661`), so a partitioned/btrfs
     image panics (`VFS: Cannot open root device`). The repack is what makes the artifact bootable.
   - Rejected: *change the provider to boot partitioned images (initramfs + partition-aware
     `root=`/`root=UUID`)* — large blast radius (boot provider, the `root=` validator
     `libvirt_qemu.py:778`, ADR 0007/0031, gdbstub direct-boot); not pursued. Repacking the image keeps the
     provider contract untouched.
2. **Capability-based preflight: `kvm.access` tests the device, `libvirt.connect` tests connectivity.**
   - Rejected: *check `kvm`/`libvirt` group membership* — group membership is a proxy; `os.access` and a
     live `virsh capabilities` connection test the real thing. (Context-skew is acknowledged in the
     `kvm.access` `suggested_fix`, which still recommends `kvm` group for durability.)
   - Rejected: *keep `virsh uri` as the libvirt check* — it reads local config and passes when the user
     cannot actually connect. The check is `libvirt.connect`, proving an authenticated *read* connection;
     it is **advisory** and does **not** prove `org.libvirt.unix.manage` (define/start) permission, so a
     PASS can still be followed by a polkit denial at `target.boot`.
3. **KVM access is a WARNING, not a FAILED.**
   - Rejected: *FAILED on missing `/dev/kvm`* — the workflow still functions under TCG, so a hard failure
     would block capable-but-unaccelerated hosts (e.g. nested virt without KVM). WARNING surfaces the
     performance consequence without gating.
4. **Host-side-only no-escalation guard, scoped to `scripts/`+`justfile`, mirrors `check-docs`/`check-ipmi`.**
   - Rejected: *grep `src/` too* — the ~20 `sudo` references in `src/` are in-guest SSH privilege prefixes
     (ADR 0011/0028), so a `src/` scan false-positives on the clean tree and fails CI. The guard targets
     host-side escalation only.
   - Rejected: *rely on review only* — the original sudo crept in unflagged; an enforced guard is the only
     thing that keeps the invariant true over time.
5. **Configurable image dir with a libvirt-readable default; do not flip the URI now.**
   - Rejected: *default the image to `$HOME`/XDG* — breaks the still-default `qemu:///system` boot (0700
     home blocks the `qemu` user's traversal; home content is `user_home_t`, not the required
     `virt_image_t`). The default stays the curated `/var/lib/kdive/rootfs/`; `$HOME` is documented only as
     the `qemu:///session` alternative.
   - Rejected: *flip the default `libvirt_uri` to `qemu:///session` now* — that drags in the guest-IP /
     user-mode-networking rework owned by #103; deferred to that follow-up.
6. **The base image must be independently qemu-readable under `qemu:///system` (mode 0644 +
   `virt_image_t`).** With the `copy_on_write` overlay the base is a read-only backing file the separate
   `qemu` user must read; the provider relabels only the writable overlay, not the backing file
   (`libvirt_qemu.py:645-688`). The builder closes this with the unprivileged final `chmod 0644` (DAC) and
   the dir's inherited `virt_image_t` fcontext (MAC).
   - Rejected: *rely on libvirt to relabel the backing chain* — not guaranteed across libvirt
     versions/configs; the security driver relabels the writable overlay it is handed, not necessarily the
     read-only backing file.
7. **Two-tier integration test: layout assertion (no KVM) + full boot (capable host).** Tier 1 builds and
   asserts whole-disk-ext4 + 0644 + caller-owned (network + libguestfs, no KVM); Tier 2 boots to the
   `kdive-ready` marker (needs KVM). Neither runs in default CI, so the §4 static guard + `prereqs` unit
   tests + the documented boot-contract precondition are the always-on protection.
   - Rejected: *a single full-boot test as the only gate* — it never runs in default CI (no KVM/network),
     so a layout or permission regression ships green. The KVM-free Tier 1 closes that gap on any host with
     the tools.

## Failure contract (additions)

| Condition | Surface | Category / Status |
|---|---|---|
| `virt-builder` template missing | `just rootfs` exit | non-zero, message names `virt-builder --list` + `KDIVE_ROOTFS_RELEASEVER` |
| no/blocked network or template download/GPG failure | `just rootfs` exit | non-zero, names network + template download as build prerequisites |
| disk full during build | `just rootfs` exit | non-zero, names target dir + free-space need (where exit code allows) |
| repack failure (`virt-tar-out`/`virt-make-fs`) | `just rootfs` exit | non-zero, names the failing tool + the libguestfs whole-disk-ext4 repack stage |
| `virt-make-fs` size too small (tree exceeds `--size`) | `just rootfs` exit | non-zero, names `KDIVE_ROOTFS_SIZE` |
| base image not qemu-readable under `qemu:///system` | `target.boot` | boot fails with an EACCES/permission error; remedy = `chmod 0644` + dir `virt_image_t` label (host-prep), or use `qemu:///session` |
| inherited `/etc/fstab` references absent partitions/subvols | `target.boot` (Tier 2) / Tier 1 fstab assertion | boot stalls in emergency mode before `kdive-ready`; prevented by the Stage-2 fstab/crypttab normalization and asserted by Tier 1 without a boot |
| build toolchain missing | `rootfs.builder` check | `FAILED`, names `libguestfs-tools` |
| `/dev/kvm` unusable | `kvm.access` check | `WARNING`, recommends `kvm` group (durable) + TCG consequence; notes context-skew |
| libvirt URI not connectable | `libvirt.connect` check | `FAILED` (advisory — connectivity only), distinguishes polkit denial vs. dead per-user daemon |
| escalation command in `scripts/` or `justfile` | `just check-no-sudo` / pytest | non-zero / test failure |

## Verification

- Builder: `scripts/build-rootfs.sh` passes `shellcheck` and `shfmt -d`; contains **no** `sudo`/`pkexec`/
  `doas`; runs the two stages (`virt-builder` customize → `virt-tar-out` + `virt-make-fs --type=ext4`
  repack) with the documented flags (including `--upload` for the `kdive-ready` unit), normalizes
  `/etc/fstab`/`crypttab` on the final image, `chmod 0644`s it, exits non-zero with the
  `virt-builder --list` / `KDIVE_ROOTFS_RELEASEVER` message on a missing template, and writes a
  whole-disk-ext4 qcow2 to the `/var/lib/kdive/rootfs/` default.
- Preflight unit tests (`tests/test_prereqs.py` or a sibling): `check_kvm_access` PASSED/WARNING via a
  patched `os.access`; `check_libvirt_connect` PASSED/FAILED via an injected runner (capabilities exit 0
  vs. non-zero), with the right URI selected from the profile vs. default; `check_rootfs_builder` PASSED
  when `virt-builder` and `qemu-img` resolve, FAILED (naming `libguestfs-tools`) when either is absent; all
  three `SKIPPED` when the gating name is omitted.
- Default-profile test: `minimal.source` is unchanged (`/var/lib/kdive/rootfs/minimal.qcow2`) and matches
  the script default.
- Guard: `just check-no-sudo` and the pytest fail on an injected `sudo` line in `scripts/`/`justfile` and
  pass on the clean tree (and do **not** flag the in-guest `sudo` in `src/`).
- Gated acceptance (env-gated, like existing integration tests), in two tiers (§5): **Tier 1** (no KVM,
  needs network + libguestfs) asserts the artifact is a single whole-disk ext4 filesystem with no partition
  table, a normalized `/etc/fstab` (no non-`/` entries) with no `/etc/crypttab`, mode 0644, owned by the
  caller, with no escalation in the script/argv; **Tier 2** (capable host,
  KVM) runs `target.boot` with `minimal` to the `kdive-ready` marker. **Neither tier runs in default CI**
  (no network/tools/KVM), so the always-on protection is the §4 static no-sudo guard + the `prereqs` unit
  tests + the documented boot-contract precondition (§1) — the gated tiers are opt-in confirmation, not a
  CI gate.

## Non-goals

- Flipping the default `libvirt_uri` to `qemu:///session` and the user-mode-networking / port-forward SSH
  rework it requires (lease-based guest-IP discovery, ADR 0032 / #103, assumes libvirt-managed NAT). The
  preflight is built to verify whichever URI a profile uses, including session; changing the *default* is a
  tracked follow-up.
- Changing the MCP server's runtime tools (already unprivileged by invariant).
- OS administration the human performs once (package install, polkit rules, libvirt socket enablement).
- Architectures/distros beyond x86_64 + Fedora.
