# ADR 0008 — a dedicated `symbols/` package for build_id verification and vmlinux/modules resolution

**Status:** Accepted (2026-05-28) · **Issue:** #53 · **Epic:** #9 · **Affects:** `src/kdive/symbols/` (new package), `safety/paths.py` (`confine_run_relative`), `server.py` (`_capture_kernel_provenance`, `debug.introspect.run` re-point), `providers/local_drgn_introspect.py` (shared `BUILD_ID_RE`)

## Context

#53 introduces host-side build_id verification and vmlinux/modules path resolution consumed by the live drgn runner (#51) and the eventual offline vmcore caller (#55). The §4.2 interface-contract rule is the spine: a consumer MUST verify `build_id` against the live/crashed kernel before loading symbols and MUST fail loud on mismatch rather than emitting garbage symbols.

The two callers are asymmetric. On the **live path** the running kernel's `build_id` is observable only from the target (the drgn wrapper's `prog.main_module().build_id`), and drgn loads the target's own on-disk debuginfo — so the build_id check is an identity/provenance guard, and there is no host-side path resolution. On the **offline/vmcore path** the host supplies `vmlinux_ref`/`modules_ref` and a mismatch means garbage symbols — verification and resolution are both host-side. Because the verification *locus* differs, the verifier and resolver are separate units; only the verifier's comparison *rule* is shared.

## Decision

Place both units in a new `src/kdive/symbols/` package as pure functions (`verify.py`: `BUILD_ID_RE`, `ProvenanceMismatch`, `verify_build_id`; `resolve.py`: `resolve_symbols` and its result/warning/error types), with no IO or manifest coupling. Path confinement lives in the existing leaf `safety/paths.py` as a public `confine_run_relative(ref, *, run_dir) -> Path`; the resolver imports it and wraps `PathSafetyError` as its own `SymbolResolutionError`. Keep the boot-capture adapter (`_capture_kernel_provenance`) in `server.py` next to the existing boot-snapshot adapter; synthesizing a `KernelProvenance` is provisioning's job (#17), and keeping it out of `symbols/` lets #17 relocate it without touching the library. `BUILD_ID_RE` is defined once in `verify.py` and replaces the duplicate `_BUILD_ID_RE` definitions formerly in `local_drgn_introspect.py` and `server.py`.

## Consequences

- Both callers import one library; it is unit-testable in isolation with no IO/manifest fakes.
- #17 can replace the local-qemu boot-capture adapter with provider-owned capture without touching `symbols/`; the seams and the manifest field they write are unchanged.
- One `BUILD_ID_RE` rule governs the live wrapper's `EXPECTED_BUILD_ID` validation, the boot adapter, and the offline caller — no drift across three copies.
- The resolver's confinement is run-relative only — a deliberate narrow boundary. A vmcore with an externally-supplied `vmlinux`/modules outside any run is #55's trust decision to admit, not this seam's.

## Considered & rejected

1. **Build seam-only: consume the existing build-step `build_id`, no boot capture.** Rejected: the §4.2 acceptance criterion references a boot-recorded `KernelProvenance`; without capture the adapter would be untested in any real flow and the criterion deferred entirely.
2. **One unified host-side verifier that the live wrapper also calls.** Rejected: the wrapper runs on the target and cannot import host code, so live enforcement is inevitably in-wrapper; a single host-only verifier would either drop the fail-fast guard or duplicate the rule. Separate units with one shared pure comparison is cleaner.
3. **Belt-and-suspenders: keep both a full in-wrapper mechanism and a full host-side mechanism.** Rejected as redundant; the host call is a single pure `verify_build_id` on already-returned data, not a second mechanism.
4. **Fold the seams into `seams/` or `prereqs/`.** Rejected: `seams/` is admission/transport snapshot territory and `prereqs/` is host-capability probing; symbol/provenance logic is a distinct concern.
5. **Absolute host paths or opaque `file://` URIs for refs.** Rejected: absolute paths leak host layout into the manifest and are not portable; URIs are speculative (YAGNI) while local-only. Run-relative refs confined to the run sandbox extend the path-safety leaf with `confine_run_relative`. The debug-scoped `_require_run_debug_path` cannot guard a `build/`-relative ref and lives in `server.py`, which the pure `symbols/` library must not import, so it is not reused.

## References

design `docs/archive/superpowers/specs/2026-05-28-kernelprovenance-verification-symbol-resolution-design.md`; plan `docs/archive/superpowers/plans/2026-05-28-kernelprovenance-verification-symbol-resolution.md`; interface contract `docs/specs/interface-contracts.md` §4.2; `src/kdive/symbols/verify.py`, `resolve.py`; `safety/paths.py` (`confine_run_relative`); `server.py` (`_capture_kernel_provenance`, `debug.introspect.run`); `seams/target.py` (`KernelProvenance`).
