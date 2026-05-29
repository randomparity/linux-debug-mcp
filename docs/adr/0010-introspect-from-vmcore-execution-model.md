# ADR 0010 — `debug.introspect.from_vmcore`: run-scoped offline execution, shared wrapper body, and a shared post-runner finalizer

**Status:** Accepted (2026-05-29) · **Issue:** #55 · **Epic:** #9 · **Affects:** `src/linux_debug_mcp/domain.py` (two request models), `src/linux_debug_mcp/providers/local_drgn_introspect.py` (`_WRAPPER_PROLOGUE_*`/`_WRAPPER_BODY` split, `render_vmcore_wrapper`, capability operations), `src/linux_debug_mcp/symbols/build_id.py` (new), `src/linux_debug_mcp/server.py` (`_execute_vmcore_introspect_call`, `_finalize_introspect_call` extraction, two handlers, tool registration), `src/linux_debug_mcp/config.py` (`ALLOWED_DEBUG_OPERATIONS`)

## Context

#55 adds offline vmcore introspection alongside the live SSH runner (#51) and the
helper layer (#54). `interface-contracts.md` §5.6 rule 3 makes vmcore analysis
**always concurrent-safe** (no live dependency, never gated); §4.2 requires a
build_id fail-loud before symbols load. ADR 0008 deliberately left the vmcore trust
boundary ("a vmcore with an externally-supplied vmlinux outside any run") to #55.
The spec (`docs/superpowers/specs/2026-05-29-debug-introspect-from-vmcore-design.md`)
left four decisions open that needed settling before implementation: the call's
scoping/identity, where the fail-loud reference build_id comes from, how the vmcore
wrapper relates to the live wrapper, and how to invoke drgn locally.

## Decision

### 1. Run-scoped, run-relative refs; no target in the call path

`from_vmcore` takes a `run_id` (for manifest persistence, the shared
`introspect:` call budget, and the `sensitive/` mode preflight) plus
caller-supplied `vmcore_ref`, `vmlinux_ref`, and optional `modules_ref`, all
**run-relative** and confined to `<run_dir>` via #53's `confine_run_relative` /
`resolve_symbols`. The request carries **no** `target_ref`/`*_profile` field. The
manifest is never read for a target profile, boot snapshot, or recorded
`KernelProvenance`. There is no admission gate, no `StopCapableGuard`, no console
lease, no sudo, no SSH. A vmcore is analysable against a run whose boot failed or
whose target was reclaimed — that is the whole point of an offline tier.

### 2. Build_id fail-loud compares the vmcore's embedded id against the supplied vmlinux's id

The expected build_id is the **host-parsed ELF build-id of the supplied
`vmlinux`** (`symbols/build_id.py: read_elf_build_id`, a pure-Python `struct`
parse, no new dependency), not the boot-recorded `KernelProvenance`. The observed
id is the vmcore's embedded `prog.main_module().build_id`. The wrapper checks
`observed == ${EXPECTED_BUILD_ID}` **before** `load_debug_info`, and the host
re-runs `verify_build_id(expected, observed)` on the returned id as
defence-in-depth. A mismatch is `CONFIGURATION_ERROR` / `provenance_mismatch` and
no symbols are loaded. This matches AC#2 ("mismatch between the vmcore and the
provided vmlinux") and §4.2 ("verify against the crashed kernel before loading").

### 3. One wrapper body, two prologues

The live `WRAPPER_TEMPLATE` is split (no behaviour change) into
`_WRAPPER_PROLOGUE_LIVE` (drgn open + build_id + provenance self-abort) and
`_WRAPPER_BODY` (emit/caps/`${ARGS_B64}`/user-script exec/output framing). Both
the live and vmcore templates are `Template(prologue + _WRAPPER_BODY)`. A test
asserts the recomposed live template is byte-identical to a golden snapshot. The
vmcore prologue swaps `set_kernel()/load_default_debug_info()` for
`set_core_dump(vmcore)` + post-check `load_debug_info([vmlinux])` and adds
`${VMCORE_PATH}`/`${VMLINUX_PATH}`/`${MODULES_PATH}` placeholders.

### 4. Local execution reuses `SubprocessSshRunner`; post-runner stages are a shared finalizer

drgn runs on the agent host via the existing `SubprocessSshRunner` fed a **local**
argv (`["timeout","--kill-after=2s","<t>s","python3","-"]`, wrapper on stdin) — it
is a generic subprocess-with-stdin-and-output-cap runner; only `build_ssh_argv`
is SSH-specific, and the vmcore path simply does not call it. The ~150 lines of
post-runner logic that are identical between the two paths (runner-result triage,
outcome-status discrimination, host `verify_build_id`, redaction, manifest step
write, success/post-validator response) are extracted from
`_execute_introspect_call` into a shared `_finalize_introspect_call(...)`,
parametrised by the handful of differing values (expected build_id, `ssh_user`
forensic detail, operation name, drgn-open message, post-validator). The live and
vmcore orchestrators keep their own pre-runner setup.

## Consequences

- The §5.6-rule-3 "never gated" property is structural: the gate code simply is
  not in `_execute_vmcore_introspect_call`. A lifecycle-independence test (no boot
  step, no admission service injected) proves it.
- One ELF build-id reader is the single host-authoritative provenance source for
  the offline path; the host never trusts the wrapper to self-report the vmlinux id.
- The shared `_WRAPPER_BODY` and `_finalize_introspect_call` mean a redaction,
  caps, or output-framing fix lands in both paths at once — no drift. The
  byte-identical-template test and the existing live test suite catch any
  regression introduced by the extraction.
- `read_elf_build_id` is injectable (`build_id_reader` seam) so handler tests need
  no synthesised ELF, while the reader is unit-tested in isolation.
- Vmcore and live calls share one `introspect:` step namespace and call budget; a
  run's total introspection work (live + offline) is bounded by one ceiling.

## Considered & rejected

1. **Verify the vmcore id against the boot-recorded `KernelProvenance.build_id`
   (like the live path).** Rejected: an offline vmcore may be analysed against a
   run with no successful boot (no recorded provenance), or paired with a vmlinux
   that differs from what booted. AC#2 names the comparison explicitly — "between
   the vmcore and the provided vmlinux" — so the vmlinux's own ELF id is the
   correct, always-available reference. Reading it on the host keeps it
   host-authoritative.

2. **Standalone tool with absolute host paths, no `run_id`.** Rejected: breaks the
   issue's "same manifest persistence pattern as the live runner" requirement and
   ADR 0008's run-relative confinement boundary; absolute paths leak host layout
   into the manifest and bypass the path-safety leaf. Staging a vmcore into the run
   directory first is a small, explicit cost that keeps the trust boundary intact.

3. **Parametrise the existing `_execute_introspect_call` with `is_vmcore`/
   `skip_admission` flags.** Rejected: the live core is already a long function
   tightly coupled to admission rollback, sudo preflight, and SSH argv building;
   threading mode flags through it would push it past the complexity limit and
   entangle two control flows whose pre-runner halves share almost nothing. A
   separate orchestrator plus a shared *post-runner* finalizer splits along the
   real seam (everything after the subprocess returns is identical).

4. **Duplicate the post-runner tail into the vmcore orchestrator.** Rejected:
   ~150 lines of redaction/outcome-discrimination/manifest logic copied is exactly
   the drift hazard ADR 0009 cited when it shared `_execute_introspect_call`. The
   extraction is behaviour-preserving and guarded by the live suite.

5. **A new vmcore wrapper template copied wholesale from the live one.** Rejected:
   the emit/caps/exec/output-framing body is security-critical and heavily
   reviewed; two copies would drift. The prologue/body split keeps the body a
   single literal shared by both, with a byte-identical-template regression test on
   the live recomposition.

6. **A new `LocalCommandRunner` abstraction for host subprocess execution.**
   Rejected as premature (CLAUDE.md "no premature abstraction"): `SubprocessSshRunner.run`
   already is a generic subprocess runner taking a full argv, stdin, output cap,
   and cancel event. Reusing it (with a documented local argv) avoids a third
   runner type for one new caller. Revisit if a second non-SSH local runner
   appears.

7. **Add a `DebugProfile`/`enabled_operations` gate to the vmcore path.** Rejected:
   §5.6 rule 3 says vmcore analysis is never gated. The operations are still listed
   in `ALLOWED_DEBUG_OPERATIONS` for enumerability, but `_ensure_debug_operation_enabled`
   is not called — there is no profile in the request and no admission tier to
   narrow.

8. **Run `drgn -c <core> -s <vmlinux> <script>` as a CLI instead of the
   python-wrapper-on-stdin.** Rejected: the wrapper owns the `emit()` JSON framing,
   the caps, the truncation markers, and the build_id self-abort; the `drgn` CLI
   gives none of those and would force re-implementing the entire output contract.
   Reusing the wrapper body is what makes the offline output "equivalent to a live
   run" (AC#1).

## References

spec `docs/superpowers/specs/2026-05-29-debug-introspect-from-vmcore-design.md`;
interface contract `docs/specs/interface-contracts.md` §4.2, §5.6 rule 3;
ADR 0008 (symbols package + run-relative confinement boundary), ADR 0009
(shared executor + typed-result convention); `src/linux_debug_mcp/symbols/verify.py`
(`verify_build_id`), `resolve.py` (`resolve_symbols`); `providers/local_drgn_introspect.py`
(`WRAPPER_TEMPLATE`); `providers/local_ssh_tests.py` (`SubprocessSshRunner`).
