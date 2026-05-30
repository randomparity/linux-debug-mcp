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

2. **The version string is advisory context only.** The parsed version is recorded in `details["version"]` and named in messages, but it never changes pass/fail on its own. The documented minimum is recorded as `details["mi3_documented_minimum"] = "9.1"`. When the version cannot be parsed from `gdb --version`, `details["version"] = "unknown"` (the key is always present on a pass, never absent), so a consumer never has to distinguish "missing key" from "unparseable".

3. **The advisory sub-minimum pass is machine-detectable, not just prose.** When a host passes behaviorally but reports a version below the documented minimum — *or* an unparseable version (which cannot be confirmed to meet it) — the check still PASSES, sets `details["version_below_documented_minimum"] = True`, and the message notes it was admitted on the behavioral signal. On a clean pass (parsed version ≥ minimum) the flag is `False`. A programmatic consumer branches on the boolean, never on the message string — the same "structured signal over string-matching" principle this ADR applies to the gate itself. This keeps the operator-facing output honest rather than silently passing a "too old" gdb.

4. **A behavioral failure names the detected version defensively.** When the probe fails (no `^done` / non-zero), the failure message includes the detected version (or `"unknown"`) and the documented minimum, so the remediation hint is actionable. **Removing the version early-return (decision 1) makes this failure path reachable with `version is None`** — gdb present, `gdb --version` unparseable, and the probe yields no `^done`. The implementation MUST format the version defensively on this path and MUST NOT index a possibly-`None` version (the pre-demotion code dereferenced `version[0]` safely only because the `version is None` early-return ran first; that guard is now gone). This is a named regression hazard, not a hypothetical.

5. **Single source of truth for the documented minimum.** `_MI_MIN_VERSION` in `prereqs/checks.py` is the one constant naming `9.1`. The duplicate, unused `MIN_GDB_VERSION` constant in `providers/gdb_mi.py` is removed (it gated nothing; the engine relies on this prerequisite check, not its own version compare).

6. **`mi_code == 0` plus a `^done` substring is the sole capability authority, and that is sufficient by construction.** With the version conjunct gone, the behavioral signal is the only gate. It is trustworthy because the probe input is a single, fixed, deterministic MI command (`-list-features`) with bounded output: a successful `-list-features` emits exactly one `^done` result record, and a gdb that cannot run it exits non-zero or emits `^error` (no `^done`). The substring match is therefore the trust anchor on purpose, not by oversight. The plan adds a negative test for a non-zero exit whose output nonetheless contains the literal `^done`, to pin that `mi_code == 0` is a required conjunct and the gate cannot be spoofed by stray output alone.

## Consequences

- A `gdb` that genuinely speaks `mi3` is admitted regardless of whether its version parses to `≥ 9.1`, removing the self-contradiction: the tier no longer rejects hosts that demonstrably satisfy its only hard requirement.
- The change is strictly *more* permissive than before on the disputed case (sub-9.1 gdb that emits `^done`); it never admits a host the old logic would have passed-then-this-rejects, because the behavioral probe was already the second gate. No host that previously passed now fails.
- A broken or too-old gdb that cannot answer an `mi3` command still hard-fails, with a clearer, version-naming message.
- One existing test (`old gdb + ^done` → previously `failed`) inverts to `passed` with `details["version_below_documented_minimum"] = True`; this is the intended behavior change, not a regression.
- The no-`^done` failure path is now reachable with an unparseable version (previously masked by the version early-return). It is covered by a new test: gdb present, unparseable `gdb --version`, no `^done` → FAILED, message says `"unknown"`, no exception raised.

## Considered & rejected

- **Document the version-precedence as intentional (keep the version veto).** Rejected: it preserves the contradiction the issue raises — a version *string* overriding a *demonstrated* capability. "Conservative-safe" (rejecting some working gdbs) is still rejecting working gdbs for no capability reason.
- **Require BOTH version ≥ 9.1 AND `^done` (AND, not behavioral-primary).** Rejected: identical user-visible behavior to the old veto on the disputed case; still fails a working sub-9.1 gdb.
- **Drop the version probe entirely.** Rejected: the version is useful advisory context in pass/fail messages and remediation hints; removing it makes failures less actionable. It is demoted, not deleted.
- **Lower the pinned minimum to 8.3.** Rejected: 8.3 is itself only an approximate boundary from `NEWS`; pinning any version re-introduces a version gate that can disagree with the behavioral probe. The behavioral probe is the correct boundary at any version.
