# ADR 0017 — Symbol version-lock for the gdb tier: a shared build-id primitive verified pre-attach in the handler, not over RSP

**Status:** Accepted (2026-05-29) · **Issue:** #70 (epic #9, split from #17, consumed by #13/#14/#53) · **Affects:** `symbols/verify.py` (new `verify_vmlinux_provenance`); `server.py` `debug_start_session_handler` (new pre-attach call + `build_id_reader` param) and the `debug.introspect.from_vmcore` read-then-verify (re-pointed to the shared primitive). No change to `seams/guard.py`, the gdb provider's banner/linkage checks, or the #53 live-wrapper path.

## Context

interface-contracts §4.2 requires every symbol-using tier to verify the
`KernelProvenance.build_id` against the kernel before loading `vmlinux` DWARF and
to fail loud on mismatch. Two tiers already comply: `debug.introspect` (#53, live
drgn — wrapper self-abort + host `verify_build_id`) and
`debug.introspect.from_vmcore` (#14 — vmcore-embedded id vs host-parsed vmlinux
ELF id).

The live gdb tier (#13, `debug.start_session` → `QemuGdbstubProvider`) does **not**
compare build-ids. It checks `same_run_artifact_linkage` (the loaded vmlinux is the
same *path* the build recorded) and `live_banner_match` (the running kernel's
`linux_banner` **release string** equals the build's `kernel_release`), gated by
`DebugProfile.symbol_identity_required` (default `True`). Release strings collide:
two builds tagged `6.9.0-test` with different content have different build-ids but
identical banners, so they pass and gdb loads mismatched symbols — exactly the
silent-garbage failure §4.2 forbids.

The build-id machinery already exists (ADR 0008): `read_elf_build_id`,
`verify_build_id`, `BUILD_ID_RE`, `ProvenanceMismatch`, `BuildIdReadError`. The
open questions are **where the gdb-tier check runs** and **what it compares
against**, given: (a) `SessionGuard` (#66) ships empty pre/post-attach precondition
slots whose docstring names #70 as their first occupant; (b) `SessionGuard` is a
process singleton built in `_build_transport_machinery` *without* an
`artifact_root`, while `artifact_root` is a per-call parameter of
`debug.start_session`; (c) `SessionGuardContext` is a frozen data-only record
(ADR 0013) carrying no vmlinux path or build-id.

## Decision

1. **One shared primitive owns the read+shape+compare step.** Add
   `symbols.verify.verify_vmlinux_provenance(*, expected_build_id, vmlinux_path,
   build_id_reader=read_elf_build_id) -> str`: it reads the vmlinux ELF build-id,
   relies on the caller having validated `expected_build_id`'s shape (the recorded
   §4.2 value), and `verify_build_id`s observed-vs-expected, returning the observed
   id. It raises the existing `BuildIdReadError` / `ProvenanceMismatch`. This is
   the §4.2 "expose verification for the tiers to consume" seam. The #14 vmcore
   handler's inline three lines are re-pointed to it (same behavior, same codes);
   the #53 live path keeps its wrapper+host check unchanged.

2. **The gdb tier verifies pre-attach, against the boot-recorded
   `KernelProvenance`.** `debug_start_session_handler` extracts
   `boot_result.details["kernel_provenance"].build_id` (reusing the live-introspect
   extraction: `provenance_missing` on absent/capture-error, `provenance_corrupt`
   on a build_id failing `BUILD_ID_RE`) and calls the primitive against the on-disk
   vmlinux **before** acquiring the debug lock / opening the transport / halting the
   kernel. Mismatch → `CONFIGURATION_ERROR` `provenance_mismatch`; unreadable →
   `vmlinux_build_id_unreadable`. The boot-recorded record (not the build step) is
   §4.2-authoritative and is what #53 already standardized on.

3. **The check is a direct call in the handler, not a `SessionGuard` slot, and is
   unconditional.** A `build_id_reader` parameter (default real) makes it
   injectable for unit tests, mirroring the vmcore handler. It runs regardless of
   `DebugProfile.symbol_identity_required` (a detected mismatch always fails;
   the flag still governs banner/linkage *confirmability*) and before the
   `transport_enabled` branch (covers the legacy non-transport path too).

## Consequences

- The gdb tier now fails loud on a build-id mismatch before halting the kernel,
  with nothing acquired to tear down, using the same `CONFIGURATION_ERROR`
  vocabulary as the other two tiers — one version-lock contract across #13/#14/#53.
- `debug.start_session` now **requires** a boot-recorded `KernelProvenance`;
  pre-#70 runs without one fail `provenance_missing` until re-booted with
  `force_reboot=true` (same stance the live introspect tier already takes). Shared
  test fixtures gain a helper to seed a `kernel_provenance` into the boot step.
- Symbol-source integrity (vmlinux-on-disk vs the booted build's recorded id) is
  now enforced; running-kernel identity remains covered by `live_banner_match`.
  Reading the running kernel's build-id over RSP is left as future work (rejected A).

## Considered & rejected

- **A. Read the running kernel's build-id over the RSP/gdbstub channel
  (post-attach).** The faithful "build-id vs *running* kernel" check. Rejected:
  locating the build-id note in live kernel memory is arch-specific and only
  testable through the gated gdb integration job; it is redundant with the existing
  `live_banner_match` live cross-check; and the architecture design explicitly
  allows "the `vmlinux` build ID **or other available identity**" for this tier.
  The actual gap is symbol-source integrity, which the static pre-attach check
  closes deterministically and unit-testably. Recorded as future work.

- **B. Register a `SessionGuard.PreAttachPrecondition`.** The reserved #70 slot.
  Rejected: `SessionGuard` is a singleton built without the per-call
  `artifact_root`, and the facts the check needs (resolved vmlinux path, recorded
  build_id) are per-call handler-scope values. Carrying them would mean either
  re-deriving `artifact_root` in the precondition (it cannot — it is a per-call
  tool parameter) or widening the frozen `SessionGuardContext` (ADR 0013) with
  #70-only fields that every other step ignores. ADR 0016 already set the
  precedent that data placement can justify a direct call over a slot (the
  watchdog *relax* is a post-acquire call, not a registered step). The slots stay
  available for future preconditions that key only on `SessionGuardContext`.

- **C. Verify inside the gdb provider's `start_session`, beside the banner/linkage
  checks.** Rejected: those checks run *after* gdb has attached and halted the
  kernel; a pre-attach handler check fails before acquisition, so a mismatch never
  halts the target or leaves a session/guard/record to tear down.

- **D. Compare against the build-step `build_id` instead of the boot-recorded
  `KernelProvenance`.** Rejected: §4.2 names `KernelProvenance` (the boot record)
  authoritative, and the live introspect handler already standardized on it
  ("build_id flows from the boot-recorded KernelProvenance … not the build step",
  `server.py` ~2628). Using the build step would fork the contract.

- **E. Make the build-id check opt-in via `symbol_identity_required`.** Rejected:
  §4.2 mandates fail-loud on a detected mismatch. A positively-detected build-id
  mismatch is bogus-symbol territory and must fail even when an operator relaxes
  `symbol_identity_required` (which exists to relax the *confirmability* of the
  banner/linkage signals, not to permit known-mismatched symbols).
