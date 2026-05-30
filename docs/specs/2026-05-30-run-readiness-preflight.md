# host.check_prerequisites: run-readiness preflight for selected profiles

**Status:** Accepted (2026-05-30) · **Issue:** #105 · **Epic:** #100 (first-run readiness) ·
**ADR:** [0034](../adr/0034-run-readiness-preflight.md)

## Problem

`host.check_prerequisites` (`src/linux_debug_mcp/prereqs/checks.py`) validates the host *toolchain* —
Python version/packages, CLI tools, the gdb-mi behavioral probe, a C compiler, artifact-root writability,
source-tree shape, and (optionally) the libvirt URI. It does not validate the three inputs that actually
gate the documented local build→boot→debug roundtrip on a fresh machine:

1. **Rootfs image.** The default `minimal` profile points at
   `/var/lib/linux-debug-mcp/rootfs/minimal.qcow2`, which does not exist until `just rootfs` runs (#102).
   A missing image only surfaces at `target.boot`, inside the boot lock, after a run already exists.
2. **Kernel `.config`.** A clean source tree has no `.config`. `kernel.build` now derives one from the
   build profile's `base_config` (#101), but a profile with an empty `base_config` and no source `.config`
   fast-fails — and that only surfaces at `kernel.build`.
3. **gdbstub port.** A `debug_gdbstub` target binds `gdbstub_endpoint` (default `127.0.0.1:1234`). If
   another process already holds that port, the failure surfaces only when QEMU starts at `target.boot`.

Each blocker appears mid-roundtrip instead of up front. An agent rediscovers manual host-prep on every
fresh checkout. This is the preflight the rest of epic #100 referenced as its natural home (see the #102
spec "Host requirements" note).

## Goal

`host.check_prerequisites`, when given the build/target/rootfs profile names a caller intends to use,
names every roundtrip-blocking gap **before** any run is created, each as a `PrerequisiteCheck` with a
concrete `suggested_fix`. On a clean machine with the default profiles selected, the response enumerates:
the missing rootfs image (fix: `just rootfs`), the derivable-or-present `.config` (pass for
`x86_64-default`, which carries `base_config=["defconfig"]`), and a free gdbstub port. With no profile
names supplied, behavior is unchanged except for three additional `SKIPPED` checks, so existing callers
see a stable, superset response shape.

## Design

### Surface: extend the existing tool, three new profile-name parameters

`host.check_prerequisites` gains three optional parameters — `build_profile`, `target_profile`,
`rootfs_profile` — each a profile *name* resolved against the same default registries
(`DEFAULT_BUILD_PROFILES`, `DEFAULT_TARGET_PROFILES`, `DEFAULT_ROOTFS_PROFILES`) that `kernel.create_run`
uses. There is no `debug_profile` parameter: none of the three checks reads a `DebugProfile` field. The
gdbstub port is owned by the **target** profile (`TargetProfile.gdbstub_endpoint` / `debug_gdbstub`); the
debug profile only narrows `enabled_operations`. Adding an unused parameter would be a speculative
feature (see ADR 0034, rejected alternative 2).

The response stays a single flat `checks` list: the existing host/toolchain checks plus exactly three
readiness checks (`kernel.config`, `rootfs.image`, `gdbstub.port`), always present, so the shape does not
depend on which names were supplied.

### Three readiness checks (pure functions in `prereqs/checks.py`)

Each is a pure function taking an already-resolved profile object (or `None`) and returning one
`PrerequisiteCheck`. Name→object resolution and the unknown-name case live in the server handler, which
owns the registries; `checks.py` stays free of the default-profile constants.

**`check_kernel_config(source_path, build_profile)` → `kernel.config`**

| condition | status | message / fix |
|---|---|---|
| `build_profile is None` | `SKIPPED` | "no build profile selected" |
| `build_profile.base_config` non-empty | `PASSED` | ".config derivable via `make <targets>`" |
| empty `base_config`, `source_path is None` | `SKIPPED` | "no source path supplied; cannot verify .config" |
| empty `base_config`, `<source>/.config` is a file | `PASSED` | "source .config present" |
| empty `base_config`, no `<source>/.config` | `FAILED` | fix: provide a `.config` (`make defconfig`) or select a build profile with a `base_config` such as `x86_64-default` |

Rationale: this mirrors the `kernel.build` precedence ladder (#101) at its first two rungs that are
knowable *before a run exists* — a per-run output `.config` cannot exist yet, so the preflight checks
only "source `.config` present" OR "derivable from `base_config`". `build_overrides` are intentionally not
modeled here: the preflight evaluates the **named profile**, and override merging is a create-run concern.

**`check_rootfs_image(rootfs_profile)` → `rootfs.image`**

Delegates to `resolve_rootfs_source` (#102) so the preflight and the boot-time gate share one resolution
policy.

| condition | status | message / fix |
|---|---|---|
| `rootfs_profile is None` | `SKIPPED` | "no rootfs profile selected" |
| `resolve_rootfs_source` raises `RootfsSourceError` | `FAILED` | the exception message + its `suggested_fix` (builder-missing names `just rootfs`); for `NOT_IMPLEMENTED` kinds, a fallback fix: "select a `local_path` or `builder` rootfs profile" |
| resolved path does not exist | `FAILED` | "rootfs image not found: `<path>`" + same builder/local fix |
| resolved path exists | `PASSED` | "rootfs image present", `details.path` |

The explicit `path.exists()` after resolution is load-bearing for the `local_path` kind:
`resolve_rootfs_source` returns a `local_path` source **without** an existence check (the boot provider
reports that generically), so the preflight must check it here to "name every missing piece".

**`check_gdbstub_port(target_profile, *, port_probe)` → `gdbstub.port`**

The probe must not collapse every bind failure into "in use": a privileged port (`<1024`) without root
fails with `EACCES`, and a non-loopback `gdbstub_endpoint` host that is not a local address fails with
`EADDRNOTAVAIL` — neither is "already in use", and a "stop the holder" fix misdirects both. The probe
therefore returns a small result, not a bare bool: `free`, `in_use` (`EADDRINUSE`), or `error` carrying
the OS error string. The default probe maps `errno.EADDRINUSE` → `in_use` and any other `OSError` →
`error`.

| condition | status | message / fix |
|---|---|---|
| `target_profile is None` | `SKIPPED` | "no target profile selected" |
| `not target_profile.debug_gdbstub` | `SKIPPED` | "target profile does not enable gdbstub" |
| `gdbstub_endpoint` unparseable | `FAILED` | "could not parse gdbstub_endpoint: `<value>`" |
| probe → `in_use` | `FAILED` | "gdbstub endpoint `<host>:<port>` is already in use" + fix: stop the process holding it or pick a different `gdbstub_endpoint` |
| probe → `error` | `FAILED` | "could not bind gdbstub endpoint `<host>:<port>`: `<os error>`" + fix: for a privileged port run with the needed capability or choose a port `>=1024`; for a non-local host confirm the address is configured on this machine |
| probe → `free` | `PASSED` | "gdbstub endpoint `<host>:<port>` is free", `details.host`/`details.port` |

`port_probe` is an injected `Callable[[str, int], PortProbeResult]` (default: a plain TCP `bind`, no
`SO_REUSEADDR`, so a port held by another process reads as `in_use`). Injection keeps the unit test
deterministic without binding real ports (mock the boundary, not the logic). Endpoint parsing is
`rsplit(":", 1)` with host non-empty and port an int in `1..65535`; the IPv6 bracket form `[::1]:1234` is
out of scope (the default and every shipped profile are IPv4) and reports the parse-error `FAILED`.

**This check is a point-in-time advisory, not a reservation.** A `PASSED` means the endpoint was free at
probe time; another process (or QEMU from a prior run) can take it before `target.boot` binds it, and the
boot path remains the authoritative failure point. The default probe binds a real socket for the duration
of the probe, so two preflights run concurrently against the *same* endpoint can make one observe
`EADDRINUSE` and report a false `in_use`; callers should not run concurrent preflights against one
endpoint. The check exists to surface the common, persistent case (a long-lived process already holding
`1234`) up front, not to guarantee availability at boot.

### Unknown profile name → `FAILED` check, not a hard failure

When a supplied name does not resolve, the handler emits a `FAILED` check under that concern's
`check_id` ("unknown <kind> profile: <name>", fix listing the known names) rather than returning a
`ToolResponse.failure`. A preflight whose job is "name every missing piece" should report a typo'd
profile name as one of those pieces and still run the other checks. See ADR 0034 decision 3.

### Handler and response contract

`prerequisites_handler` resolves the three names (injecting `*_profiles` registries for tests, mirroring
the other handlers), assembles `base checks + 3 readiness checks`, and returns
`ToolResponse.success`. The summary counts failures; `suggested_next_actions` stays
`["Fix failed checks", "kernel.create_run"]`. No new `ErrorCategory` is introduced — the readiness checks
are status fields inside an otherwise-successful response, exactly like every existing prerequisite check.
None of the probes surface guest output or secrets, so no new redaction path is required (resolved
filesystem paths and a host:port are not sensitive; they already appear in profiles and manifests).

## Acceptance

On a clean machine with `build_profile="x86_64-debug"`, `target_profile="local-qemu-debug"`,
`rootfs_profile="minimal"` (a coherent gdbstub-debug roundtrip — `x86_64-debug` carries the DWARF/KASLR
config the gdbstub tier needs and `base_config=["defconfig"]`; the preflight does **not** itself validate
build/target pairing coherence):

- `kernel.config` is `PASSED` ("derivable via `make defconfig`").
- `rootfs.image` is `FAILED`, message names the missing `minimal.qcow2`, fix names `just rootfs`.
- `gdbstub.port` is `PASSED` when `127.0.0.1:1234` is free, `FAILED` naming the endpoint when held.
- With no names supplied, all three are `SKIPPED` and the prior checks are unchanged.

## Out of scope

- Acquiring/building any artifact during the tool call (project invariant: no privileged provisioning in
  a tool call). The preflight only inspects and reports.
- `build_overrides`/inline profile specs (the preflight keys off named profiles only).
- `prebuilt`/`url` rootfs acquisition (#106/#107) — reported as `FAILED` "not implemented" with the
  local/builder remedy.
- IPv6 bracket-form endpoints.
