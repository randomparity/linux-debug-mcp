# ADR 0017 — Symbol version-lock for the gdb tier: a shared build-id primitive verified pre-attach in the handler, not over RSP

**Status:** Accepted (2026-05-29) · **Issue:** #70 (epic #9, split from #17, consumed by #13/#14/#53) · **Affects:** `symbols/verify.py` (new `verify_vmlinux_provenance`); `server.py` `debug_start_session_handler` (new pre-attach call + `build_id_reader` param). No change to `seams/guard.py`, the gdb provider's banner/linkage checks, the #53 live-wrapper path, or the #14 vmcore path (both already verify build-id in the shared introspect finalizer).

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
`DebugProfile.symbol_identity_required` (default `True`). The concrete, grounded
hole is the relaxed profile: with `symbol_identity_required=False` the provider
enforces *neither* linkage nor banner-match (`qemu_gdbstub.py:281`, `343`), so gdb
attaches against whatever vmlinux is recorded and loads its symbols with no
fail-loud even if that vmlinux does not match the booted build — exactly the
silent-garbage failure §4.2 forbids. (With the default profile, linkage already
blocks loading a foreign vmlinux, so there the build-id gate is a symbol-source
*integrity* check — the recorded vmlinux has not been swapped/truncated since
build.)

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
   id. It raises the existing `BuildIdReadError` / `ProvenanceMismatch`, composing
   `read_elf_build_id` + `verify_build_id` (ADR 0008) into the one read+compare the
   gdb tier needs. The #53 live and #14 vmcore tiers already verify build-id in the
   shared introspect finalizer (`_finalize_introspect_call` → `verify_build_id`),
   where the vmcore-flow operands (vmlinux id = *expected*, vmcore-embedded id =
   *observed*, compared downstream of the inline vmlinux read) do not match this
   primitive's signature — so they are left untouched (rejected F).

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
- A **fresh** `debug.start_session` attach now **requires** a boot-recorded
  `KernelProvenance`; a pre-#70 boot without one fails `provenance_missing` until
  re-booted with `force_reboot=true` (same stance the live introspect tier takes).
  Because the check runs after the idempotent SUCCEEDED-session short-circuit
  (decision 3), re-reading an already-attached pre-#70 session still returns it
  unchanged — the new requirement applies only to new attaches. Shared test
  fixtures gain a helper to seed a `kernel_provenance` into the boot step.
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

- **F. Re-point the #14 vmcore path to the new primitive.** Tempting for "owns the
  contract" uniformity. Rejected: the vmcore flow does not read-then-compare at one
  site. Its inline step (`server.py` ~3738) only reads the vmlinux ELF id and
  shape-checks it; the actual compare against the vmcore-embedded id happens
  downstream in the shared `_finalize_introspect_call` (wrapper self-abort at
  ~3239 + host `verify_build_id` at ~3295), with the vmlinux id as *expected* and
  the vmcore-embedded id as *observed* — the inverse of this primitive's signature,
  and the embedded id is not even available at the inline site. Re-pointing would
  invert operand roles and lose the existing shape-check for no behavior change, so
  the vmcore path is left untouched. "Owns the contract" is satisfied by the gdb
  tier consuming build-id verification alongside the two tiers that already do.
