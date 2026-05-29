---
description: Implement a GitHub issue end-to-end — design, TDD, adversarial-review loop, PR, CI, merge handoff, cleanup
argument-hint: <issue-number>
---

Implement GitHub issue **#$ARGUMENTS** end-to-end on a feature branch, following this
repo's conventions in `CLAUDE.md`, and drive it to a CI-green PR ready to merge.

Work the steps in order. Keep the guardrails green at every commit; do not advance
past a red guardrail.

## 1. Scope the issue

Run `gh issue view $ARGUMENTS` (and follow any linked issues/PRs). Restate the
requirement and the acceptance criteria in your own words before touching code. Ask
me only if something is genuinely ambiguous **and** the answer changes the design —
otherwise state your assumption and proceed.

## 2. Branch

Sync `main` to the latest `origin/main`, then create `feat/<short-slug>-$ARGUMENTS`
off it. Never work on `main`.

## 3. Design first (when non-trivial)

Tighten the design *before* writing code — defects are cheapest to fix in the spec,
then the plan, then last in the source. For a small, obvious bugfix this whole section
is a no-op; skip to step 4.

**3a. Spec + ADR.** Use `superpowers:brainstorming` first if the design space is wide.
Write or update the design doc under `docs/specs/` (or `docs/superpowers/specs/`). For
any decision the spec leaves open — layer boundaries, interface/ownership splits,
concurrency invariants, a new failure contract, anything with viable alternatives —
write or update an ADR under `docs/adr/` (Status · Context · Decision · Consequences ·
**Considered & rejected**), link it from the spec, and add it to `docs/adr/README.md`.
Commit the spec/ADR.

**3b. Adversarial-review the spec (enforced).** Install a goal so the loop cannot be
skipped:

> `/goal` for the spec/design doc(s) for issue #$ARGUMENTS, run a cycle of `/challenge`
> and then address those review recommendations, committing the doc after every review,
> until either 5 iterations have completed or `/challenge` returns `approve`.

Run `/challenge <path-to-spec.md>`. Feed the ADR's rejected-alternatives to the review
so settled choices aren't reopened. Address every defensible finding — tighten hidden
assumptions, vague/unfalsifiable success criteria, missing edge cases, and
under-specified failure modes. Commit after each pass. Repeat until `approve` or 5
iterations. The goal auto-clears on success.

**3c. Implementation plan.** Use `superpowers:writing-plans` to write the plan under
`docs/superpowers/plans/`, derived from the hardened spec. Commit it.

**3d. Adversarial-review the plan (enforced).** Same `/goal` process as 3b, targeting
the plan:

> `/goal` for the plan doc for issue #$ARGUMENTS, run a cycle of `/challenge` and then
> address those review recommendations, committing the doc after every review, until
> either 5 iterations have completed or `/challenge` returns `approve`.

Run `/challenge <path-to-plan.md>`. Focus on phase ordering and prerequisite gaps,
steps that can't run in the claimed order, rollback/cleanup paths, and verification
gaps. Commit after each pass. Repeat until `approve` or 5 iterations.

## 4. Build with TDD

Use `superpowers:test-driven-development`: write the failing test, then the
implementation. Test behavior and the edges/error paths, not just the happy path —
empty/null/malformed input, boundaries, timeouts, partial failure. Honor the repo
contracts:

- Keep the env-gated libvirt/gdb/drgn integration tests gated; never un-gate them.
- Handlers are the unit of testing — call them directly with injected providers/
  profiles, not through MCP.
- Return `ToolResponse.success/failure` with the most specific `ErrorCategory`;
  populate `suggested_next_actions` with literal next tool names.
- Redact anything that may carry guest output or secrets before it is returned **and**
  before it is persisted.
- If you change a Pydantic model that has a committed JSON-schema snapshot
  (e.g. `introspect_helpers/schemas/*.json`), regenerate the snapshot.

## 5. Guardrails (green at every commit)

`uv run ruff check` + `uv run ruff format`, `uv run ty check src`, and
`uv run python -m pytest -q`. Zero warnings — fix every one or add a justified inline
ignore. `ty` is hard-gating in CI.

## 6. Adversarial-review loop (enforced)

Install a goal so the loop cannot be skipped:

> `/goal` for the changes on the current branch (main..HEAD), run a cycle of
> `/challenge` and then address those review recommendations, committing after every
> review, until either 5 iterations have completed or `/challenge` returns `approve`.

Run `/challenge main..HEAD`. Address every defensible finding. Before implementing a
suggestion, apply `superpowers:receiving-code-review` — verify it's correct rather
than agreeing reflexively. Commit after each pass (one logical change per commit,
imperative subject ≤72 chars, ending with the project's `Co-Authored-By` trailer).
Repeat until `approve` or 5 iterations. The goal auto-clears on success.

## 7. Ship it

Push the branch and open a PR against `main` with `gh pr create`. The body describes
only what's in the diff, in plain factual language (no "critical/robust/comprehensive"
inflation), and ends with `Closes #$ARGUMENTS`. Then watch CI with
`gh pr checks <PR> --watch` until every required check passes. The
gdbstub/libvirt/drgn integration jobs skipping in CI is expected. If a check fails,
fix it, re-push, and keep watching.

## 8. Hand off, then clean up

When CI is green, stop and tell me the PR is ready to merge — do **not** self-merge.
After I confirm the merge: switch to `main`, fast-forward pull, delete the merged
local branch, and `git remote prune origin`. Verify the working tree is clean.
