# Unprivileged project tooling: rootless rootfs builder + permission preflight

**Status:** Accepted (2026-05-30) · **Epic:** #100 (first-run readiness) ·
**ADR:** 0037 (to be written during implementation) ·
**Supersedes:** the build-recipe (`scripts/build-rootfs.sh` privilege model) portions of
[spec 2026-05-30-rootfs-image-sources.md](../../specs/2026-05-30-rootfs-image-sources.md) /
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

1. `just rootfs` — and every other project tool — completes as an unprivileged user with **no** `sudo`,
   `pkexec`, `doas`, or setuid escalation anywhere in the invocation.
2. The rootfs image is built entirely inside an unprivileged libguestfs appliance and written to a
   user-writable path.
3. The preflight reports, as `PrerequisiteCheck` results, whether the running user has the permissions the
   roundtrip needs — by **testing the actual capability**, not proxies like group membership.
4. A static guard prevents privilege-escalation from regressing back into project tools.
5. An env-gated integration test proves the unprivileged build + boot path end-to-end on a capable host.

Out of scope (see Non-goals): flipping the default libvirt URI to `qemu:///session` and the
networking/guest-IP rework that implies; OS administration the human does once (installing packages,
configuring polkit) — that is not a "project tool".

## Background facts (verified on the development host, Fedora 43)

- `virt-builder`, `virt-customize`, `virt-make-fs`, `guestfish`, `qemu-img` are installed; `mkosi` is not.
- `virt-builder --list` includes `fedora-41`, `fedora-42`, and `fedora-43` (x86_64) — the host's release
  is covered, so the from-scratch `virt-builder` path needs no Cloud-image fallback.
- libguestfs runs **unprivileged** (a `guestfish -N disk` smoke completed as uid 1000, exit 0).
- `/dev/kvm` is `crw-rw-rw-` (world-rw) and usable by the user, who is **not** in the `kvm` group — proof
  that group membership is the wrong thing to check; the device permission/ACL is what grants access.
- Default profiles hardcode `libvirt_uri="qemu:///system"` (`server.py`); `TargetProfile.libvirt_uri`
  defaults to `None`.
- `sudo` in tracked, non-doc files appears **only** in `scripts/build-rootfs.sh` (and CI runner setup,
  which is GitHub-Actions host provisioning, not a project tool).

## Design

### 1. Rootless rootfs builder (`scripts/build-rootfs.sh` rewrite)

The script is rewritten to run **with no `sudo`**. The whole image is produced inside the libguestfs
appliance via `virt-builder`. There is **no Cloud-image fallback**: a missing template fails loud (see
below). The `fedora-41/42/43` x86_64 templates are confirmed present in the libguestfs index, so the
host's current release is covered; an older index simply yields the actionable error. The
environment-variable interface and defaults are preserved except the output path (below):

| Variable | Default | Meaning |
|---|---|---|
| `KDIVE_ROOTFS` | `${XDG_DATA_HOME:-$HOME/.local/share}/kdive/rootfs/minimal.qcow2` | output image path |
| `KDIVE_ROOTFS_RELEASEVER` | `43` | Fedora release |
| `KDIVE_ROOTFS_SIZE` | `2G` | image size |
| `KDIVE_ROOTFS_SSH_USER` | `root` | guest user that receives the authorized key |
| `KDIVE_ROOTFS_AUTHORIZED_KEY` | first existing of the invoking user's `~/.ssh/id_ed25519.pub`, `~/.ssh/id_rsa.pub` | public key to install |

A single `virt-builder` invocation replaces the entire `dnf --installroot` + `virt-make-fs` + chroot
dance:

```bash
virt-builder "fedora-${RELEASEVER}" \
  --format qcow2 --size "${IMAGE_SIZE}" --output "${KDIVE_ROOTFS}" \
  --install openssh-server \
  --run-command 'systemctl enable sshd.service' \
  --ssh-inject "${SSH_USER}:file:${authorized_key}" \
  --write "/etc/systemd/system/${MARKER}.service:${unit_contents}" \
  --run-command "systemctl enable ${MARKER}.service" \
  --selinux-relabel
```

- `--ssh-inject`, `--run-command`, `--write`, `--selinux-relabel` perform key install, sshd enable, the
  `kdive-ready` serial unit, and SELinux relabeling as unprivileged libguestfs operations.
- `--selinux-relabel` replaces the old `.autorelabel` touch: contexts are correct at build time rather
  than on first boot, so a guest with an enforcing policy accepts the host-written `authorized_keys`.
- A non-root `KDIVE_ROOTFS_SSH_USER` is created with an extra `--run-command 'useradd …'` before the
  key inject (mirroring the old `useradd` step; root always exists).
- Output is qcow2, satisfying the `copy_on_write` overlay's qcow2-base precondition (ADR 0031 §3).

**Missing template — fail loud.** If `virt-builder` reports `fedora-${RELEASEVER}` is not in the index
(an older libguestfs install), the script exits non-zero with a message naming `virt-builder --list` and
`KDIVE_ROOTFS_RELEASEVER` so the human selects an available release. No automatic Cloud-image download or
alternate build path is attempted — the remedy is a one-line release selection, and a silent fallback
would ship a different (preconfigured) base than intended.

**Privilege model.** No command in the script runs under `sudo`/`pkexec`/`doas`. libguestfs uses
`/dev/kvm` when available (fast) and TCG otherwise (slow but unprivileged). The output directory is
created with a plain `mkdir -p` under the user-writable XDG path; no `chown` is needed because every file
is created by the invoking user.

**Failure contract.** Fail fast with actionable messages: required tool missing
(`virt-builder`/`qemu-img`) names `libguestfs-tools`; no SSH public key found names
`KDIVE_ROOTFS_AUTHORIZED_KEY`; template missing names `virt-builder --list` and
`KDIVE_ROOTFS_RELEASEVER`. Any temp files are user-owned and removed with plain `rm`.

### 2. Default image path moves out of root-owned `/var/lib`

For a sudo-free write the image leaves `/var/lib/kdive/rootfs/` (root-owned) for
`${XDG_DATA_HOME:-$HOME/.local/share}/kdive/rootfs/minimal.qcow2`. Two coupled defaults change together so
the `builder` source-kind gate still resolves the produced image:

- `scripts/build-rootfs.sh` `KDIVE_ROOTFS` default (above).
- `DEFAULT_ROOTFS_PROFILES["minimal"].source` in `server.py`.

`RootfsProfile.source` stays a plain path string; only the default constant changes. Frozen manifests are
unaffected (the immutable `RunRequest`/`RootfsProfile` keep whatever they were created with); only new
runs pick up the new default. The home-dir location is also readable by a per-user qemu, easing the
future `qemu:///session` direction; under the still-default `qemu:///system` the existing host-prep
requirement (make server-supplied paths libvirt-readable) is unchanged in *kind* (ADR 0031 already
documents it for the kernel image and base image).

### 3. Permission preflight checks (`prereqs/checks.py`)

Three new **pure** check functions, surfaced through the existing `host.check_prerequisites` tool and
`just check-host`. They follow ADR 0034's pattern: pure functions taking resolved profile objects (or
`None`), name resolution stays in the server handler, gated by the `target_profile`/`rootfs_profile`
parameters that already exist. No new tool, response type, or `ErrorCategory`.

**The governing principle: test the capability, not a proxy.** Group membership is explicitly *not*
checked — the host shows `/dev/kvm` usable without `kvm` group membership, so a group check would be a
false negative. Each check exercises the real operation.

- **`check_kvm_access()`** → `check_id="kvm.access"`. Uses `os.access("/dev/kvm", os.R_OK | os.W_OK)`.
  PASSED when usable. **WARNING** (not FAILED) when absent/unusable, with a message that KVM acceleration
  is unavailable so libguestfs/qemu fall back to TCG (functional but slow); `suggested_fix` names the
  udev-ACL / `kvm`-group remedy. WARNING because the workflow still works without KVM.
- **`check_libvirt_usable(target_profile)`** → `check_id="libvirt.usable"`. Resolves the URI the profile
  will use (profile `libvirt_uri`, else the build-time default), then runs `virsh -c <uri> capabilities`
  (a real connection that the daemon must service). PASSED on exit 0; FAILED otherwise, distinguishing the
  actionable causes in `suggested_fix`: polkit/permission denial under `qemu:///system` (join `libvirt`
  group / install the polkit rule) vs. a non-running per-user daemon under `qemu:///session`
  (`systemctl --user start virtqemud.socket`). This supersedes the `virsh uri`-only `_libvirt_check`,
  which passes on config it cannot actually use. Probe is injected (the `PrerequisiteRunner`) for
  deterministic unit tests.
- **`check_rootfs_builder()`** → `check_id="rootfs.builder"`. Verifies the unprivileged toolchain:
  `virt-builder` and `qemu-img` present. FAILED naming `libguestfs-tools` when either is missing. It
  explicitly does **not** require `dnf` or `sudo` (the old recipe's dependencies are gone).

The handler appends these to the flat `checks` list, `SKIPPED` when the relevant name is omitted —
a backward-compatible superset, consistent with ADR 0034.

### 4. Static "no privilege escalation" guard

A regression lock making "all project tools run as a regular user" an enforced invariant:

- `just check-no-sudo` recipe: greps `scripts/`, `justfile`, and `src/` for `sudo`, `pkexec`, `doas`, and
  setuid usage, failing the build on a match. Modeled on the existing `check-docs` / `check-ipmi` guards.
- Allow-list: ADR/spec prose under `docs/` that *discusses* escalation is excluded (these legitimately
  cite the rejected approaches), matching `check-docs`'s `docs/superpowers/**` exclusion posture.
- A mirror pytest (`tests/test_no_privilege_escalation.py`) so the guard runs both in `just` and under
  `pytest`/CI even when `just` is absent.
- Wired into CI alongside `check-docs`/`check-ipmi`.

### 5. Host-capability integration test

`tests/test_unprivileged_build_integration.py`, env-gated like `test_libvirt_boot_integration.py` /
`test_qemu_gdbstub_integration.py` (skipped unless an opt-in env var is set and the tools exist). It runs
the builder for a tiny image, asserts the process tree used no escalation and ran as the current uid
(`os.geteuid()` unchanged; no `sudo` in the argv), and boots the result far enough to confirm usability.
Silent-skips on incapable hosts so CI stays green; the gating is preserved exactly as the existing
integration tests do it.

### 6. Docs + ADR

- **ADR 0037** records the three decisions with their rejected alternatives (see below) and supersedes the
  build-recipe privilege-model portions of ADR 0031.
- `docs/fedora-libvirt-user-guide.md` §5 is rewritten to the sudo-free `just rootfs`; the
  `sudo mkdir/chown /var/lib/kdive/rootfs` steps are dropped (image now lives under `$HOME`). The libvirt
  host-setup `sudo` (package install, polkit, socket enablement) **stays** — that is OS administration,
  not a project tool, and is explicitly out of scope.

## Decisions to record in ADR 0037 (with rejected alternatives)

1. **Unprivileged libguestfs builder (`virt-builder`, fail loud on a missing template).**
   - Rejected: *keep `dnf --installroot` under rootless podman / `unshare --map-root-user` + fakeroot* —
     fragile (dnf-in-userns device-node and ownership quirks), and still conceptually "fake root".
   - Rejected: *mkosi* — idiomatic for kernel dev but a new, heavier dependency with its own config model;
     not installed on the target host. virt-builder reuses tooling already present.
   - Rejected: *Cloud image + `virt-customize`, either as the primary path or an automatic fallback* —
     `fedora-41/42/43` are present in the index, so the from-scratch minimal image is achievable directly;
     a Cloud base is heavier and preconfigured, and a silent fallback would ship a different image than
     intended. A missing template instead fails loud with a one-line release-selection remedy.
2. **Capability-based preflight, not group membership.**
   - Rejected: *check `kvm`/`libvirt` group membership* — false negatives (host has `/dev/kvm` access
     without `kvm` group via ACL); the device permission and the live daemon connection are the truth.
   - Rejected: *keep `virsh uri` as the libvirt check* — it reads local config and passes when the user
     cannot actually connect; `virsh … capabilities` exercises the real path.
3. **KVM access is a WARNING, not a FAILED.**
   - Rejected: *FAILED on missing `/dev/kvm`* — the workflow still functions under TCG, so a hard failure
     would block capable-but-unaccelerated hosts (e.g. nested virt without KVM). WARNING surfaces the
     performance consequence without gating.
4. **No-escalation static guard mirrors `check-docs`/`check-ipmi`.**
   - Rejected: *rely on review only* — the original sudo crept in unflagged; an enforced guard is the only
     thing that keeps the invariant true over time.

## Failure contract (additions)

| Condition | Surface | Category / Status |
|---|---|---|
| `virt-builder` template missing | `just rootfs` exit | non-zero, message names `virt-builder --list` + `KDIVE_ROOTFS_RELEASEVER` |
| build toolchain missing | `rootfs.builder` check | `FAILED`, names `libguestfs-tools` |
| `/dev/kvm` unusable | `kvm.access` check | `WARNING`, names ACL/group remedy + TCG consequence |
| libvirt URI not actually usable | `libvirt.usable` check | `FAILED`, distinguishes polkit denial vs. dead per-user daemon |
| escalation token in `scripts/`/`justfile`/`src/` | `just check-no-sudo` / pytest | non-zero / test failure |

## Verification

- Builder: `scripts/build-rootfs.sh` passes `shellcheck` and `shfmt -d`; contains **no** `sudo`/`pkexec`/
  `doas`; uses `virt-builder` with the documented flags, exits non-zero with the `virt-builder --list` /
  `KDIVE_ROOTFS_RELEASEVER` message on a missing template, and writes qcow2 to the XDG default.
- Preflight unit tests (`tests/test_prereqs.py` or a sibling): `check_kvm_access` PASSED/WARNING via a
  patched `os.access`; `check_libvirt_usable` PASSED/FAILED via an injected runner (capabilities exit 0 vs.
  non-zero), with the right URI selected from the profile vs. default; `check_rootfs_builder` PASSED when
  `virt-builder` and `qemu-img` resolve, FAILED (naming `libguestfs-tools`) when either is absent; all three `SKIPPED` when
  the gating name is omitted.
- Default-profile test: `minimal.source` is the XDG path and matches the script default.
- Guard: `just check-no-sudo` and the pytest fail on an injected `sudo` line and pass on the clean tree.
- Gated acceptance (env-gated, like existing integration tests): on a capable Fedora host the builder
  produces a bootable image **with no escalation and unchanged euid**, and `target.boot` with `minimal`
  reaches `kdive-ready`.

## Non-goals

- Flipping the default `libvirt_uri` to `qemu:///session` and the user-mode-networking / port-forward SSH
  rework it requires (lease-based guest-IP discovery, ADR 0032 / #103, assumes libvirt-managed NAT). The
  preflight is built to verify whichever URI a profile uses, including session; changing the *default* is a
  tracked follow-up.
- Changing the MCP server's runtime tools (already unprivileged by invariant).
- OS administration the human performs once (package install, polkit rules, libvirt socket enablement).
- Architectures/distros beyond x86_64 + Fedora.
