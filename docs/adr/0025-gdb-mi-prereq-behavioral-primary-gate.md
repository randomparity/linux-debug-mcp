# ADR 0025: gdb/MI prerequisite — the mi3 `^done` behavioral probe is the primary gate; the version string is advisory

- **Status:** Accepted
- **Date:** 2026-05-30
- **Relates to:** #84 (Phase A gdb-prereq refinement), #79 (Phase A foundation), #13 (debug.gdb tier), ADR 0019 (gdb/MI tier decomposition)

## Context

The Phase A gdb prerequisite (`_gdb_mi_capability_check` in `prereqs/checks.py`) decides whether a host's `gdb` can drive the `debug.gdb` tier's `mi3` machine interface. It collects two independent signals:

1. **A version string** parsed from `gdb --version`, compared against a pinned minimum of `9.1` — the release the GDB manual names as introducing the `mi3` interpreter ("GDB/MI" chapter).
2. **A behavioral probe** that runs one real `mi3` command (`gdb -nx -q -ex 'interpreter-exec mi3 "-list-features"' -ex quit`) and asserts a well-formed `^done` record.

As originally implemented, the two signals were joined as `gdb absent OR version < 9.1 OR no ^done`, evaluated in that order: the **version gate ran first and could veto a host that the behavioral probe would have passed**. This is the defect #84 tracks.

The version `9.1` is a *documentation* statement, not the exact capability boundary. Per the GDB `NEWS` history, the first `mi3`-specific change and "default MI version is now 3" are filed under the "since GDB 8.3" section. So a `gdb 8.3.x` can emit a valid `mi3` `^done` record yet be hard-failed by the `< 9.1` check. The two criteria can therefore disagree, and the original ordering let the *less* authoritative signal (a version string) override the *more* authoritative one (the host actually answering an `mi3` command). The acceptance criterion was mildly self-contradictory: it claimed to require a working `mi3` interpreter while rejecting some hosts that demonstrably have one.

## Decision

1. **The behavioral `^done` probe is the primary, authoritative gate.** A host passes the prerequisite **iff** `gdb` is present, the probe runs without a host-level error, and the probe returns `mi_code == 0` with a `^done` record. Whether `gdb` can drive the tier is decided by whether it answers an `mi3` command — not by its self-reported version.

2. **The version string is advisory context only.** The parsed version is recorded in `details["version"]` and named in messages, but it never changes pass/fail on its own. The documented minimum is recorded as `details["mi3_documented_minimum"] = "9.1"`.

3. **When a host passes behaviorally but reports a version below the documented minimum (or an unparseable version), the pass message says so.** The check still PASSES, with a message noting the version is below — or could not be parsed against — the documented `9.1` minimum and that the host was accepted on the behavioral signal. This keeps the operator-facing output honest rather than silently passing a "too old" gdb.

4. **A behavioral failure names the detected version for context.** When the probe fails (no `^done` / non-zero), the failure message includes the detected version (or "unknown") and the documented minimum, so the remediation hint is actionable.

5. **Single source of truth for the documented minimum.** `_MI_MIN_VERSION` in `prereqs/checks.py` is the one constant naming `9.1`. The duplicate, unused `MIN_GDB_VERSION` constant in `providers/gdb_mi.py` is removed (it gated nothing; the engine relies on this prerequisite check, not its own version compare).

## Consequences

- A `gdb` that genuinely speaks `mi3` is admitted regardless of whether its version parses to `≥ 9.1`, removing the self-contradiction: the tier no longer rejects hosts that demonstrably satisfy its only hard requirement.
- The change is strictly *more* permissive than before on the disputed case (sub-9.1 gdb that emits `^done`); it never admits a host the old logic would have passed-then-this-rejects, because the behavioral probe was already the second gate. No host that previously passed now fails.
- A broken or too-old gdb that cannot answer an `mi3` command still hard-fails, with a clearer, version-naming message.
- One existing test (`old gdb + ^done` → previously `failed`) inverts to `passed` with an advisory note; this is the intended behavior change, not a regression.

## Considered & rejected

- **Document the version-precedence as intentional (keep the version veto).** Rejected: it preserves the contradiction the issue raises — a version *string* overriding a *demonstrated* capability. "Conservative-safe" (rejecting some working gdbs) is still rejecting working gdbs for no capability reason.
- **Require BOTH version ≥ 9.1 AND `^done` (AND, not behavioral-primary).** Rejected: identical user-visible behavior to the old veto on the disputed case; still fails a working sub-9.1 gdb.
- **Drop the version probe entirely.** Rejected: the version is useful advisory context in pass/fail messages and remediation hints; removing it makes failures less actionable. It is demoted, not deleted.
- **Lower the pinned minimum to 8.3.** Rejected: 8.3 is itself only an approximate boundary from `NEWS`; pinning any version re-introduces a version gate that can disagree with the behavioral probe. The behavioral probe is the correct boundary at any version.
