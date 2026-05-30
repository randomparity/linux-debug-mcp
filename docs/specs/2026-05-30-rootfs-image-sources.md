# Rootfs image sources: pluggable acquisition (Phase 1 local builder)

**Status:** Accepted (2026-05-30) · **Issue:** #102 · **Epic:** #100 (first-run readiness) ·
**ADR:** [0031](../adr/0031-rootfs-image-source-abstraction.md) ·
**Roadmap:** Phase 2 #106 (prebuilt catalog), Phase 3 #107 (URL source), Phase 4 #108 (advanced builders)

## Problem

An agent cannot boot anything out of the box. The default `minimal` rootfs profile
(`src/linux_debug_mcp/server.py`) points at `/var/lib/linux-debug-mcp/rootfs/minimal.qcow2`, a path the
server intentionally does not create and that does not exist on a fresh machine. Only a prose recipe
exists (`docs/fedora-libvirt-user-guide.md` §5), and it omits sshd and authorized-key setup, so even a
hand-built image cannot satisfy the SSH test tier. The profile is also `mutability="read_only"`, which
breaks systemd/sshd at boot (they need a writable root). And the libvirt provider does not actually
support a writable-but-pristine-preserving mode: `_validate_profiles` rejects everything except
`read_only` and `mutable` (`mutable` writes the base image in place, destroying reproducibility).

## Goal

A clean machine reaches a bootable rootfs through one documented command. `target.boot` with the default
`minimal` profile reaches the `linux-debug-mcp-ready` marker on `ttyS0`, the base image stays pristine
across boots, and the image is SSH-capable (sshd enabled + an authorized key installed) so that — once
guest-IP discovery lands (#103) — `target.run_tests` can log in.

This issue is **Phase 1** of a four-phase rootfs-acquisition roadmap. It delivers the source-kind
abstraction plus the `local_path` and `builder` kinds; `prebuilt` (#106) and `url` (#107) are accepted by
the model but report `not_implemented` until their phases land.

## Design

### `RootfsProfile.source_kind`: an image-source discriminator

`RootfsProfile` gains:

```python
source_kind: Literal["local_path", "builder", "prebuilt", "url"] = "local_path"
```

The default is `local_path`, which is exactly today's behavior (`source` is a path to a disk image), so
every existing profile and frozen manifest is unchanged. `source` keeps its current meaning for
`local_path` and `builder` (the on-disk path of the image); Phases 2–3 reinterpret `source` as a catalog
name / URL for their kinds.

### Resolution: a pre-boot gate, not a tool-call provisioner

A new pure module `src/linux_debug_mcp/rootfs/sources.py` exposes:

```python
def resolve_rootfs_source(profile: RootfsProfile) -> Path: ...
class RootfsSourceError(Exception):  # carries .category and .suggested_fix
```

`resolve_rootfs_source` maps a profile's `source_kind` to a concrete on-disk image path, or raises
`RootfsSourceError`. It is invoked by `target_boot_handler` **before** `provider.plan_boot`, after the
short-circuit for an already-SUCCEEDED boot and after boot overrides are applied. Per kind:

| `source_kind` | Behavior |
|---|---|
| `local_path` | Return `Path(source)`. Existence is left to the provider's existing `_resolve_existing_path`, preserving today's generic "rootfs source path does not exist" error. |
| `builder` | Return `Path(source)` if it exists; else raise `RootfsSourceError(CONFIGURATION_ERROR, suggested_fix="Run `just rootfs` to build the default image …")`. |
| `prebuilt` | Raise `RootfsSourceError(NOT_IMPLEMENTED, "rootfs source_kind 'prebuilt' is not implemented yet (tracked in #106)")`. |
| `url` | Raise `RootfsSourceError(NOT_IMPLEMENTED, "rootfs source_kind 'url' is not implemented yet (tracked in #107)")`. |

The resolver does **not** build, fetch, or write anything in Phase 1; the only kind that touches the
filesystem is `builder`, and only to `Path.exists()`. This honors the project invariant that the server
performs no privileged provisioning at tool-call time. The `builder` kind exists so its absent-image
failure can name the canonical remedy (`just rootfs`) instead of the generic provider error; for Phases
2–4 the resolver is the seam where fetch/cache/build-dispatch will live.

The resolver returns a path for `local_path`/`builder` but the provider re-resolves `profile.source`
itself, so Phase 1 does not thread the returned path through the boot plan. The return value is part of
the contract for Phases 2–3, where the resolved path differs from `source` (a cache location) and the
handler will pass a `model_copy(update={"source": resolved})` profile to the provider.

#### Failure surfacing

On `RootfsSourceError` the handler returns `ToolResponse.failure(category=err.category, …)` with
`details["suggested_fix"] = err.suggested_fix` (when set) and `suggested_next_actions=["artifacts.get_manifest"]`.
`suggested_fix` rides `details` rather than a new `ErrorInfo` field, matching ADR 0030 decision 6 — there
is no MCP tool that builds an image, so the actionable remedy is a shell command, not a next tool. The
resolver failure is recorded as a FAILED boot `StepResult` so it is discoverable through the manifest,
consistent with other boot failures.

### `copy_on_write`: a per-boot qemu-img overlay

The libvirt provider learns a third mutability mode. `copy_on_write` creates, at boot time, an ephemeral
qcow2 overlay whose backing file is the pristine base image, and attaches the **overlay** (writable) to
the domain. The base is never written, so every boot starts from the same known-good state while
systemd/sshd get a writable root.

- `_validate_profiles` accepts `copy_on_write` in addition to `read_only` and `mutable`.
- `plan_boot` (pure): for `copy_on_write`, resolve the base via `_resolve_existing_path` into
  `rootfs_backing_path`, set `rootfs_path` to `<boot-attempt-dir>/rootfs-overlay.qcow2` (not yet on
  disk), and record `overlay_create_argv = ["qemu-img", "create", "-f", "qcow2", "-F", "qcow2", "-b",
  <abs-base>, <overlay>]`. For `read_only`/`mutable`, `rootfs_backing_path=None`,
  `overlay_create_argv=None`, and `rootfs_path` is the resolved base (unchanged).
- `execute_boot` (side effects): when `overlay_create_argv` is set, require `qemu-img` on `PATH`
  (extend the existing `virsh` MISSING_DEPENDENCY check to list missing tools) and run the create
  command **before** `define`. A nonzero/timed-out `qemu-img` returns `INFRASTRUCTURE_FAILURE` via the
  existing `_command_failure_result` path. Re-running into an existing overlay file (a forced reboot)
  overwrites it; `qemu-img create` is idempotent for our purposes because the overlay is ephemeral.
- `render_domain_xml`: the disk `<source file=…>` already points at `plan.rootfs_path` (the overlay for
  `copy_on_write`); the `<readonly/>` element is emitted only for `read_only`. `copy_on_write` and
  `mutable` are both writable.

The overlay lives in the run's boot-attempt directory so its lifecycle matches the run (removed when the
run is cleaned). Under `qemu:///system` the libvirt qemu user must be able to read both the overlay and
the backing file; this is a documented host-prep requirement (see §"Host requirements" below and the
user guide), not something the server arranges — the same posture as the base-image SELinux labeling
already documented for the `mutable`/`read_only` paths.

### One-command Fedora builder

`scripts/build-rootfs.sh` (bash, `set -euo pipefail`, shellcheck/shfmt clean) turns the §5 prose recipe
into a reproducible script and adds the two things the recipe lacked: sshd enabled at boot and an
authorized public key installed for the configured SSH user. It is parameterized by environment with
documented defaults:

| Variable | Default | Meaning |
|---|---|---|
| `LINUX_DEBUG_MCP_ROOTFS` | `/var/lib/linux-debug-mcp/rootfs/minimal.qcow2` | output image path |
| `LINUX_DEBUG_MCP_ROOTFS_RELEASEVER` | `43` | Fedora release to install |
| `LINUX_DEBUG_MCP_ROOTFS_SIZE` | `2G` | image size |
| `LINUX_DEBUG_MCP_ROOTFS_SSH_USER` | `root` | guest user that receives the authorized key |
| `LINUX_DEBUG_MCP_ROOTFS_AUTHORIZED_KEY` | first of `~/.ssh/id_ed25519.pub`, `~/.ssh/id_rsa.pub` | public key to install |

The script installs `openssh-server` (in addition to `systemd fedora-release passwd`), enables `sshd` via
a `multi-user.target.wants` symlink, writes the authorized key to the user's `~/.ssh/authorized_keys`
(mode 600, `.ssh` mode 700, correct ownership), and keeps the existing `linux-debug-mcp-ready.service`
that echoes the marker to `/dev/ttyS0`. It fails fast with an actionable message if `dnf`,
`virt-make-fs`, or the authorized key file are missing. `just rootfs` invokes the script.

The script requires `sudo` (dnf installroot, chown) and is therefore host-prep run by a human, not by the
server. The user guide §5 is updated to lead with `just rootfs` and keep the manual recipe as the
fallback / explanation.

### Default `minimal` profile changes

```python
"minimal": RootfsProfile(
    name="minimal",
    source="/var/lib/linux-debug-mcp/rootfs/minimal.qcow2",
    source_kind="builder",          # was implicit local_path
    mutability="copy_on_write",     # was read_only
    readiness_marker="linux-debug-mcp-ready",
    ssh_host="127.0.0.1",
    ssh_port=22,
    ssh_user="root",
)
```

`source_kind="builder"` makes a missing image point the agent at `just rootfs`. `copy_on_write` makes the
root writable without mutating the base. `ssh_key_ref` stays unset: the matching private key is per-user
and is configured via override/profile, documented in the guide; the image being SSH-capable (sshd + an
authorized key) is this issue's deliverable, and the IP/host wiring that completes the login is #103.

### SSH login boundary (relationship to #103)

This issue makes the **image** able to accept SSH. It does not perform guest-IP discovery, install host
port forwards, or parse DHCP leases — that is #103. The acceptance clause "`target.run_tests` can log in
over SSH" is satisfied end-to-end only with #103 also in place; #102's testable contribution is sshd +
authorized key in the produced image and the `ssh_*` profile fields already present.

## Failure contract

| Condition | Category | Detail |
|---|---|---|
| `builder` image missing | `CONFIGURATION_ERROR` | `details["suggested_fix"]` names `just rootfs`; FAILED boot recorded |
| `prebuilt` / `url` selected | `NOT_IMPLEMENTED` | message names the tracking issue (#106 / #107) |
| `copy_on_write` selected, `qemu-img` missing | `MISSING_DEPENDENCY` | missing-tools list includes `qemu-img` |
| `qemu-img create` fails / times out | `INFRASTRUCTURE_FAILURE` | command failure via `_command_failure_result` |
| `local_path` image missing | `CONFIGURATION_ERROR` | unchanged provider error |

## Host requirements

- `copy_on_write` under `qemu:///system`: the libvirt qemu user must read the overlay (in the run dir)
  and the backing image. Either label/relabel the artifact root for libvirt access, or use
  `qemu:///session`. Documented in the user guide; not arranged by the server.
- The base image directory must be writable by the invoking user for the builder (`chown` step in §5).

## Scope / non-goals

- x86_64 + Fedora only (the provider's sole architecture; the builder's sole distro). Other distros and
  builders are Phase 4 (#108).
- No fetch/cache/checksum machinery — that is Phases 2–3 (#106/#107); the resolver only gates and, for
  `builder`, checks existence.
- No guest-IP discovery, port forwarding, or lease parsing — that is #103.
- The server never builds, fetches, or relabels at tool-call time.

## Verification

- Resolver unit tests (`tests/test_rootfs_sources.py`): `local_path` passthrough; `builder` present →
  path; `builder` missing → `CONFIGURATION_ERROR` carrying the `just rootfs` `suggested_fix`;
  `prebuilt`/`url` → `NOT_IMPLEMENTED` naming #106/#107.
- Config-model tests (`tests/test_config.py`): `source_kind` default is `local_path`; each literal
  accepted; an unknown kind rejected by `extra="forbid"`/`Literal` validation.
- Provider tests (`tests/test_libvirt_qemu_provider.py`): `copy_on_write` accepted by validation;
  `plan_boot` computes the overlay path + backing path + `overlay_create_argv`; `execute_boot` runs
  `qemu-img create` before `define` (argv + ordering assertions with an injected fake runner);
  `qemu-img` missing → `MISSING_DEPENDENCY`; `qemu-img` failure → `INFRASTRUCTURE_FAILURE`; domain XML
  for `copy_on_write` points the disk at the overlay and omits `<readonly/>`.
- Boot-handler tests: a `builder`-missing profile returns `CONFIGURATION_ERROR` with the `suggested_fix`
  and records a FAILED boot; a `prebuilt`/`url` profile returns `NOT_IMPLEMENTED`.
- Default-profile test: `minimal` is `source_kind="builder"`, `mutability="copy_on_write"`.
- `scripts/build-rootfs.sh` passes `shellcheck` and `shfmt -d`.
- Gated acceptance (not CI, env-gated like the existing libvirt integration test): `just rootfs` on a
  Fedora host yields an image; `target.boot` with `minimal` reaches `linux-debug-mcp-ready`; with #103,
  `target.run_tests` logs in over SSH.
