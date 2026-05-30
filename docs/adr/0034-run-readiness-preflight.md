# ADR 0034 — run-readiness preflight for selected profiles

**Status:** Accepted (2026-05-30) · **Issue:** #105 · **Epic:** #100 · **Affects:**
`src/kdive/prereqs/checks.py` (new: `check_kernel_config`, `check_rootfs_image`,
`check_gdbstub_port`; `check_prerequisites` unchanged), `src/kdive/server.py`
(`prerequisites_handler` resolves profile names + assembles readiness checks; `host.check_prerequisites`
tool gains `build_profile`/`target_profile`/`rootfs_profile` params).
Spec: [2026-05-30-run-readiness-preflight.md](../specs/2026-05-30-run-readiness-preflight.md).

## Context

#105 (child of first-run-readiness epic #100) closes the gap where the three roundtrip inputs introduced
by its sibling issues — a rootfs image (#102), a derivable kernel `.config` (#101), and a free gdbstub
port (the `debug_gdbstub` target) — are only discovered mid-roundtrip. The decisions below are the ones
#105 leaves open and that have viable alternatives.

## Decision

### 1. Extend `host.check_prerequisites`, do not add a separate readiness tool

The three new checks are appended to the existing tool's flat `checks` list, gated by three new optional
profile-name parameters. One preflight call answers "is this host ready for the roundtrip I intend",
matching the acceptance criterion ("names every missing piece up front") with a single round trip and a
single mental model. The checks share the `PrerequisiteCheck` contract and the existing
success-envelope-with-status-fields shape, so no new response type or `ErrorCategory` appears.

### 2. Parameters are build/target/rootfs only — no `debug_profile`

The gdbstub port is owned by `TargetProfile` (`gdbstub_endpoint`, `debug_gdbstub`), not `DebugProfile`
(which only narrows `enabled_operations`). No readiness check reads a `DebugProfile` field, so a
`debug_profile` parameter would be an unused, speculative knob (global "no speculative features"). The
port check is gated by `target_profile.debug_gdbstub`, which is the field that actually decides whether a
gdbstub is bound.

### 3. An unknown profile name is a `FAILED` check, not a hard `ToolResponse.failure`

When a supplied name does not resolve, the handler emits a `FAILED` check under that concern's `check_id`
and continues running the other checks. The preflight's purpose is to enumerate gaps; a typo'd or
removed profile is itself a gap, and a hard failure would hide every other readiness result behind the
first bad name. This keeps the response a complete, comparable list across calls.

### 4. Readiness check functions are pure; name resolution lives in the handler

`prereqs/checks.py` gains three pure functions that take resolved profile objects (or `None`). Name→object
resolution and the unknown-name `FAILED` case live in the server handler, which already owns the
`DEFAULT_*_PROFILES` registries and supports test injection of alternate registries. This keeps
`checks.py` free of the default-profile constants (avoiding a server→config→checks import knot) and keeps
each check unit-testable with a constructed profile, no registry needed.

### 5. The gdbstub port probe is an injected `bind`-based callable returning a 3-way result

`check_gdbstub_port` takes `port_probe: Callable[[str, int], PortProbeResult]`, defaulting to a plain TCP
`bind` (no `SO_REUSEADDR`). The result is three-way (`free` / `in_use` / `error`), not a bool, because
`bind` failures are not all "in use": `EADDRINUSE` is, but `EACCES` (privileged port without root) and
`EADDRNOTAVAIL` (a non-local `gdbstub_endpoint` host) are different conditions with different remedies,
and reporting them all as "already in use" misdirects the fix. The default probe maps `EADDRINUSE` →
`in_use` and any other `OSError` → `error` (carrying the OS message). Injection makes the unit test
deterministic without occupying a real port (mock the socket boundary, not the logic). A plain bind — not
a connect — is the right probe: QEMU's gdbstub binds the listener, so bind-failure is the exact condition
that will break `target.boot`. The check is advisory (point-in-time), not a reservation; the boot path
stays the authoritative binder (see spec, gdbstub.port section).

### 6. `rootfs.image` delegates to `resolve_rootfs_source`, then checks existence

The check reuses #102's `resolve_rootfs_source` so the preflight and the boot-time gate cannot drift.
Because that resolver returns a `local_path` source **without** an existence check, the preflight adds an
explicit `Path.exists()` after resolution — otherwise a missing `local_path` image would pass the
preflight and only fail at boot, defeating the goal.

## Consequences

- One tool answers host readiness for an intended profile set; agents call it once before `kernel.create_run`.
- The response shape gains three always-present checks (`SKIPPED` when the relevant name is omitted),
  a backward-compatible superset for existing callers.
- The preflight and boot/build paths share resolution logic (`resolve_rootfs_source`, the `base_config`
  precedence intent), so a future change to acquisition policy updates both at once.
- The port probe performs a real (transient) `bind` in production; it holds the socket only for the
  duration of the probe and never on the injected test path.

## Considered & rejected

1. **A separate `host.check_run_readiness` tool.** Rejected: two tools for "is my host ready" splits the
   answer and the agent's mental model; the checks share the `PrerequisiteCheck` contract and belong in
   one list. The single-tool superset response is strictly more discoverable.
2. **Add a `debug_profile` parameter for symmetry.** Rejected: no check reads a `DebugProfile` field;
   the port lives on the target profile. An unused parameter is speculative surface.
3. **Hard-fail the whole call on an unknown profile name.** Rejected: it hides every other readiness
   result behind the first bad name and contradicts "name every missing piece". The `FAILED`-check form
   reports the bad name *and* the rest of the host's state in one response.
4. **Resolve `build_overrides`/inline specs in the preflight.** Rejected: override merging is a
   create-run concern with its own validation; duplicating it here would drift from `kernel.create_run`.
   The preflight evaluates the named profile, which is what an agent selects before a run exists.
5. **Probe the gdbstub port with a `connect` instead of a `bind`.** Rejected: a refused connect cannot
   distinguish "free" from "firewalled/host-down", and the failure that breaks boot is QEMU's *bind*.
   A bind probe tests the exact precondition.
6. **Build/fetch the rootfs image during the preflight when missing.** Rejected: the server performs no
   privileged provisioning in a tool call (established invariant, ADR 0031 decision 2). The preflight
   reports and names the remedy (`just rootfs`); the human/script produces the image out of band.
