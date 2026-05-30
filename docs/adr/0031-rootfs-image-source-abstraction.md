# ADR 0031 — rootfs image-source abstraction (Phase 1: local builder)

**Status:** Accepted (2026-05-30) · **Issue:** #102 · **Epic:** #100 · **Affects:**
`src/linux_debug_mcp/config.py` (`RootfsProfile.source_kind`),
`src/linux_debug_mcp/rootfs/sources.py` (new: `resolve_rootfs_source`, `RootfsSourceError`),
`src/linux_debug_mcp/providers/libvirt_qemu.py` (`copy_on_write` validation, `BootPlan.rootfs_backing_path`
+ `BootPlan.overlay_create_argv`, `plan_boot`, `execute_boot`, `render_domain_xml`),
`src/linux_debug_mcp/server.py` (`target_boot_handler` resolver call; `DEFAULT_ROOTFS_PROFILES["minimal"]`
flips to `source_kind="builder"` + `mutability="copy_on_write"`), `scripts/build-rootfs.sh` (new),
`justfile` (`rootfs` recipe), `docs/fedora-libvirt-user-guide.md` §5.
Spec: [2026-05-30-rootfs-image-sources.md](../specs/2026-05-30-rootfs-image-sources.md).

## Context

#102 (child of first-run-readiness epic #100) makes the default rootfs bootable out of the box. Today
`minimal` points at a non-existent image, is `read_only` (which breaks systemd/sshd), and only a prose
recipe exists. The issue introduces a `source_kind` discriminator (`local_path` | `builder` | `prebuilt`
| `url`) with `builder` as the implemented Phase 1 acquisition path, flips the default to
`copy_on_write`, and ships a one-command Fedora builder. The decisions below are the ones #102 leaves
open and that have viable alternatives. Phases 2–4 are #106/#107/#108.

## Decision

### 1. Resolution is a handler-layer pre-boot gate, not provider logic

`source_kind` resolution lives in a new pure module `rootfs/sources.py` (`resolve_rootfs_source`),
invoked by `target_boot_handler` **inside `store.boot_lock`, immediately before `provider.plan_boot`** so a
`RootfsSourceError` is recorded as a FAILED boot `StepResult` with the correct attempt/`replace_succeeded`
handling, mirroring the existing `ProviderBootError` branch. The provider stays `source_kind`-agnostic: it
continues to resolve `profile.source` as a path. Resolution is acquisition *policy* (which kinds exist,
where caches live, what remedy a missing image suggests); the provider is libvirt *mechanism*. Keeping
policy out of the provider also means Phases 2–4 add source kinds without touching libvirt code, and the
resolver is reusable by other (future) target providers.

### 2. `builder` does not build at tool-call time; it gates and names the remedy

The server performs no privileged provisioning during a tool call (an established project invariant). So
`builder` resolution only checks `Path.exists()` and, when absent, raises a `CONFIGURATION_ERROR` whose
`suggested_fix` names `just rootfs`. The image is produced out-of-band by a human-run script. `builder`
differs from `local_path` solely in that absent-image guidance today; it is also the seam where Phase 4
builder dispatch will attach.

### 3. `copy_on_write` is a per-boot qemu-img overlay over a pristine base

The default flips to `copy_on_write` because `read_only` breaks systemd/sshd and `mutable` corrupts
reproducibility by writing the base in place. `copy_on_write` creates an ephemeral qcow2 overlay
(`qemu-img create -f qcow2 -F qcow2 -b <base> <overlay>`) at boot and attaches the overlay writable; the
base is never modified, so every boot is fresh. It requires a qcow2 base (the `-F qcow2` backing format
and the provider's unconditional `driver type="qcow2"`); the default builder produces qcow2. Overlay creation is a side effect, so it runs in
`execute_boot` (after the pure `plan_boot` computes the paths and argv), guarded by a `qemu-img`
dependency check.

### 4. The overlay lives in the run's boot-attempt directory

Overlay placement options were (a) the run/boot-attempt dir, (b) a sibling of the base image in the
labeled rootfs dir, (c) a configurable overlay dir. We chose (a): the overlay is run-scoped ephemeral
state and belongs with the run's other artifacts, so its lifecycle matches the run (cleaned with it) and
it never pollutes the curated base-image directory. The cost — under `qemu:///system` the qemu user must
be granted access to the artifact root — is a documented host-prep requirement, consistent with the
SELinux labeling already documented for the base image, and avoidable with `qemu:///session`.

### 5. `prebuilt` and `url` are accepted by the model but report `NOT_IMPLEMENTED`

The full `source_kind` enum ships now so the wire contract is stable and `providers`/profile validation
accept Phase 2–3 values, but selecting `prebuilt` or `url` raises `RootfsSourceError(NOT_IMPLEMENTED)`
naming the tracking issue. This mirrors the future-stub posture elsewhere in the codebase: a valid
request for an unbuilt capability returns `not_implemented`, not a validation error.

### 6. `suggested_fix` rides `details`, not a new `ErrorInfo` field

As in ADR 0030 decision 6, the missing-image remedy is a shell command (`just rootfs`), not a next MCP
tool, so it travels in `ToolResponse` `details["suggested_fix"]` and `suggested_next_actions` stays
`["artifacts.get_manifest"]`. No schema churn.

### 7. SSH-capability is in scope; IP/host discovery is #103

The builder enables sshd and installs an authorized key, making the image able to accept SSH. Guest-IP
discovery, lease parsing, and port forwarding stay out of scope (owned by #103). `ssh_key_ref` on the
default profile stays unset because the matching private key is per-user; the guide documents wiring it.
Because the key file is written host-side, the builder also `touch`es `.autorelabel` in the installroot
and relies on no SELinux policy being installed (`install_weak_deps=False`), so the host-written context
cannot defeat pubkey login under an enforcing guest.

## Consequences

- A clean machine boots the default rootfs after one `just rootfs`; a missing image yields an actionable
  `CONFIGURATION_ERROR` instead of a generic path error.
- The base image stays byte-for-byte stable across boots; systemd/sshd get a writable root.
- `BootPlan` gains `rootfs_backing_path` and `overlay_create_argv`; provider unit tests adapt.
- `copy_on_write` adds a `qemu-img` dependency, advertised in the capability's `required_host_tools` (so
  `providers.list`/#105 surface it) and surfaced as `MISSING_DEPENDENCY` at boot when absent.
- Under `qemu:///system`, operators must grant libvirt access to the run-dir overlay — but this is the
  **same** access already required for the by-path kernel image (`<kernel>` in the domain XML) and the
  base image, so the overlay introduces no new *class* of host-prep. Documented in the user guide.
- Existing frozen manifests are unaffected: `source_kind` defaults to `local_path` and the immutable
  `RunRequest`/`RootfsProfile` keep whatever they were created with; only new runs pick up the flipped
  `minimal` default.

## Considered & rejected

1. **Resolve `source_kind` inside the provider's `plan_boot`.** Rejected: it couples libvirt mechanism to
   acquisition policy, forces every future target provider to re-implement kind handling, and makes
   Phases 2–4 edit provider code. Resolution is a provider-independent gate. (decision 1)
2. **`builder` builds the image at tool-call time.** Rejected: it violates the no-privileged-provisioning
   invariant (dnf installroot needs `sudo`), makes a tool call do minutes of root-privileged work, and
   blurs the host-prep boundary. The builder is a human-run host-prep script; the kind only gates. (d2)
3. **Flip the default to `mutable` instead of `copy_on_write`.** Rejected: `mutable` writes the base image
   in place, so reproducibility is lost after the first boot and concurrent runs would race on one file.
   `copy_on_write` preserves the base and isolates each boot. (decision 3)
4. **Place the overlay beside the base image in the labeled rootfs dir.** Rejected: it mixes ephemeral
   run state into the curated base directory, needs separate cleanup, and risks collisions across runs.
   Run-local placement has a clean lifecycle (removed with the run). The apparent advantage of the
   labeled-dir placement — `qemu:///system` readability — is moot because the provider already attaches
   the kernel image by host path, so the operator must already make server-supplied paths libvirt-readable;
   the overlay rides that same, pre-existing requirement rather than justifying a placement that pollutes
   the base dir. (decision 4)
5. **Omit `prebuilt`/`url` from the enum until their phases land.** Rejected: adding enum members later
   would churn the wire contract and any persisted profiles. Shipping the full enum now with
   `NOT_IMPLEMENTED` behavior keeps the contract stable. (decision 5)
6. **Add a dedicated `suggested_fix` field to `ErrorInfo`.** Rejected as out-of-scope schema churn; the
   `details` channel already reaches the failure response (consistent with ADR 0030). (decision 6)
7. **Have #102 also discover the guest IP so SSH login works end-to-end here.** Rejected: IP/lease
   discovery is a distinct concern with its own issue (#103). Bundling it would expand scope and duplicate
   that design. #102 delivers an SSH-capable image; #103 wires the connection. (decision 7)
