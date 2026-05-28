# CI and Pre-Commit — Design

Date: 2026-05-28

## Goal

Give `linux-debug-mcp` a baseline CI workflow and an updated local pre-commit
configuration that together enforce, on every PR and push to `main`, the same
lint/format/test/docs/security checks that contributors run locally. Bring all
tool versions to the current stable releases (most pre-commit pins are six or
more months old) and add the supply-chain, workflow-hygiene, type-check, and
package-smoke jobs that today only exist in the global standards document.

## Non-goals

- No change to the existing `transport-integration.yml` job logic — that
  workflow stays specialized for the agent-proxy / live-gdbstub integration
  gates. The only edit here is keeping its action SHAs consistent with the new
  ones (no behavior change).
- No change to the test suite itself beyond enabling `pytest-cov`. The one
  pre-existing local failure (see "Known precondition" below) is called out as a
  blocker for the implementation plan, not silently worked around.
- No `mypy`/`pyright`. The advisory type-checker is Astral's `ty`, per the
  global standard.
- No coverage upload to a third-party service (Codecov, etc.). Coverage is
  enforced via `--cov-fail-under` and the XML report is retained as a workflow
  artifact only.

## Architecture

Two complementary layers share the hook list:

1. **Pre-commit** (`.pre-commit-config.yaml`) runs locally via `pre-commit` (or
   `prek`) and in the `pre-commit` CI job. Identical hook revs in both places
   means a contributor's local pass is sufficient to know CI's lint stage will
   pass.
2. **CI** (`.github/workflows/ci.yml`) runs the pre-commit job plus the checks
   that are too heavy, too environment-coupled, or too network-dependent for
   per-commit hooks: pytest matrix with coverage, advisory `ty` typecheck,
   `just check-docs`, `zizmor` workflow audit, `pip-audit` supply-chain audit,
   and a `uv build` + stdio-startup smoke test.

`transport-integration.yml` is unchanged in behavior; its action SHAs are
already current.

## Pre-commit configuration

The full `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v6.0.0
    hooks:
      - id: check-added-large-files
      - id: check-merge-conflict
      - id: check-toml
      - id: check-yaml
      - id: end-of-file-fixer
      - id: trailing-whitespace
      - id: check-executables-have-shebangs

  - repo: https://github.com/astral-sh/ruff-pre-commit
    rev: v0.15.14
    hooks:
      - id: ruff
        args: ["--fix"]
      - id: ruff-format

  - repo: https://github.com/Yelp/detect-secrets
    rev: v1.5.0
    hooks:
      - id: detect-secrets
        args: ["--baseline", ".secrets.baseline"]

  - repo: https://github.com/rhysd/actionlint
    rev: v1.7.12
    hooks:
      - id: actionlint
```

Rationale for each change vs the current config:

- `pre-commit-hooks` v5.0.0 → **v6.0.0**: current stable (Aug 2025). Adds
  `check-executables-have-shebangs`, which we enable to catch any
  accidentally-committed executable Python or shell file that lacks a shebang
  line.
- `ruff-pre-commit` v0.8.6 → **v0.15.14**: current stable (May 2026). Roughly
  one year of lint/format improvements; required for the `ruff>=0.15` floor in
  `pyproject.toml`.
- `detect-secrets` **v1.5.0**: already current; no change.
- `actionlint` **v1.7.12** added: lints `.github/workflows/*.yml` locally and in
  CI for invalid syntax, shellcheck issues inside `run:` blocks, and unknown
  action inputs. Cheap enough to gate per-commit; complements `zizmor` (which
  runs only in CI).

`zizmor` and `pip-audit` are deliberately CI-only — they hit the network
(checking advisory databases) and are heavier than a per-commit hook should be.

## CI workflow (`ci.yml`)

```yaml
name: ci
on:
  pull_request:
  push:
    branches: [main]
  schedule:
    - cron: '17 6 * * *'  # daily, SLA-bearing — see "Advisory triage"

permissions:
  contents: read

concurrency:
  group: ci-${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true

jobs:
  pre-commit:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd  # v6.0.2
        with:
          persist-credentials: false
      - uses: actions/setup-python@a309ff8b426b58ec0e2a45f0f869d46889d02405  # v6.2.0
        with:
          python-version: "3.11"
      - uses: astral-sh/setup-uv@08807647e7069bb48b6ef5acd8ec9567f424441b  # v8.1.0
      - run: |
          set -euo pipefail
          uv venv --allow-existing
          uv pip install -e '.[dev,test]'
          uv run pre-commit run --all-files --show-diff-on-failure

  tests:
    runs-on: ubuntu-24.04
    strategy:
      fail-fast: false
      matrix:
        python-version: ["3.11", "3.13"]
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd  # v6.0.2
        with:
          persist-credentials: false
      - uses: actions/setup-python@a309ff8b426b58ec0e2a45f0f869d46889d02405  # v6.2.0
        with:
          python-version: ${{ matrix.python-version }}
      - uses: astral-sh/setup-uv@08807647e7069bb48b6ef5acd8ec9567f424441b  # v8.1.0
      - run: |
          set -euo pipefail
          uv venv --allow-existing --python ${{ matrix.python-version }}
          uv pip install -e '.[dev,test]'
          uv run python -m pytest \
            --cov=src/linux_debug_mcp \
            --cov-report=xml \
            --cov-report=term \
            --cov-fail-under=85
      - uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a  # v7.0.1
        if: always()
        with:
          name: coverage-${{ matrix.python-version }}
          path: coverage.xml

  typecheck:
    runs-on: ubuntu-24.04
    continue-on-error: true
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd  # v6.0.2
        with:
          persist-credentials: false
      - uses: astral-sh/setup-uv@08807647e7069bb48b6ef5acd8ec9567f424441b  # v8.1.0
      - run: |
          set -euo pipefail
          uv venv --allow-existing
          uv pip install -e '.[dev,test]'
          status=0
          {
            echo '## ty check'
            echo
            echo '```'
            uv run ty check src 2>&1 | tee /tmp/ty.log || status=$?
            echo '```'
          } >> "$GITHUB_STEP_SUMMARY"
          exit "$status"

  docs:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd  # v6.0.2
        with:
          persist-credentials: false
      - run: |
          set -euo pipefail
          sudo apt-get update && sudo apt-get install -y --no-install-recommends ripgrep just
          just check-docs

  workflow-hygiene:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd  # v6.0.2
        with:
          persist-credentials: false
      - uses: astral-sh/setup-uv@08807647e7069bb48b6ef5acd8ec9567f424441b  # v8.1.0
      - run: uv run --with 'zizmor==1.25.2' zizmor --persona=auditor .github/workflows

  supply-chain-runtime:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd  # v6.0.2
        with:
          persist-credentials: false
      - uses: astral-sh/setup-uv@08807647e7069bb48b6ef5acd8ec9567f424441b  # v8.1.0
      - run: |
          set -euo pipefail
          uv venv --allow-existing
          uv pip install -e .
          uv run --with 'pip-audit==2.10.0' pip-audit --strict --disable-pip

  supply-chain-dev:
    runs-on: ubuntu-24.04
    continue-on-error: true
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd  # v6.0.2
        with:
          persist-credentials: false
      - uses: astral-sh/setup-uv@08807647e7069bb48b6ef5acd8ec9567f424441b  # v8.1.0
      - run: |
          set -euo pipefail
          uv venv --allow-existing
          uv pip install -e '.[dev,test]'
          uv run --with 'pip-audit==2.10.0' pip-audit --strict --disable-pip

  package-smoke:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd  # v6.0.2
        with:
          persist-credentials: false
      - uses: astral-sh/setup-uv@08807647e7069bb48b6ef5acd8ec9567f424441b  # v8.1.0
      - run: |
          set -euo pipefail
          uv build
          uv pip install --system dist/*.whl
          # stdio server: succeeds, then we kill it on the 2s timeout.
          timeout 2 linux-debug-mcp || test $? -eq 124
```

Notes and invariants:

- **Action pinning.** All third-party actions are pinned to a full commit SHA
  with a `# vX.Y.Z` comment, matching the global standard and the existing
  `transport-integration.yml` style. `upload-artifact`'s SHA is resolved at
  implementation time from the then-current release.
- **`persist-credentials: false`** is set on every `actions/checkout` use, per
  the same standard.
- **`permissions: contents: read`** at the workflow level (jobs inherit and may
  narrow further). No job here needs `write` to anything.
- **Concurrency group** cancels superseded runs on the same ref. This matters
  on long-running force-push sequences.
- **Matrix `fail-fast: false`** so a 3.11 failure does not mask a 3.13 failure
  (and vice versa).
- **Coverage floor 85 %.** Current branch coverage is 89 % (statements 91 %,
  branches enabled via `branch = true`); the 85 % floor leaves a 4-point
  cushion against the stronger branch metric. **This 85 % is provisional and
  load-bearing on the local measurement.** The implementation plan must
  re-measure branch coverage on the `ubuntu-24.04` runner *after* the triage
  table is implemented (every new `pytest.mark.skipif` removes branches from
  the runner total) and re-justify the floor — lowering it if necessary —
  before `tests` becomes a required check. Plan to ratchet via PR once the
  suite is stable in CI.
- **`typecheck` is `continue-on-error: true`.** The `run:` block tees `ty
  check src` into `$GITHUB_STEP_SUMMARY` inside a fenced code block, so
  findings are visible directly from the workflow run summary rather than
  buried in the step log. Job status still propagates via `exit "$status"`,
  but `continue-on-error: true` keeps it from blocking the PR. This is the
  explicit choice made in brainstorming: keep CLAUDE.md honest about the gap,
  give the team data, do not gate yet.
- **`docs` job** installs `ripgrep` and `just` from apt rather than pulling in
  the full uv toolchain — `check-docs` only needs those two and the workspace
  itself.
- **Supply chain is two jobs, not one.** `supply-chain-runtime` installs the
  package with no extras (`uv pip install -e .`) and runs `pip-audit
  --strict --disable-pip` as a hard gate — this is the surface that ships to
  users. `supply-chain-dev` installs `.[dev,test]` and runs the same audit
  with `continue-on-error: true` — advisory only, because a CVE in a
  developer tool should not gate a production code merge. `--disable-pip`
  keeps pip-audit from invoking pip directly under uv-managed envs;
  `--strict` upgrades unresolved/skipped packages to failures so silent gaps
  in the lock are caught. `pip-audit` itself is pinned via `uv run --with
  'pip-audit==2.10.0'` so the gate version is independent of the project's
  dev extras. Both the CI jobs and the justfile `audit` recipe pin pip-audit
  at the same exact version; bumps are deliberate, single-commit edits.

## `pyproject.toml` changes

```toml
[project.optional-dependencies]
dev = [
  "detect-secrets>=1.5,<2",
  "pre-commit>=4.3,<5",
  "ruff>=0.15,<1",
  "ty>=0.0.40,<0.1",
]
test = [
  "pytest>=8.2,<9",
  "pytest-cov>=7,<8",
]

[tool.coverage.run]
source = ["src/linux_debug_mcp"]
branch = true

[tool.coverage.report]
exclude_also = [
  "pragma: no cover",
  "if TYPE_CHECKING:",
  "raise NotImplementedError",
]

[tool.ty.rules]
# Permissive starting profile — advisory only in CI. Tighten incrementally.
unresolved-import = "warn"
```

`pyproject.toml` keeps its current `[tool.ruff]` block; only the version floor
moves. `ty`'s rule block stays minimal so the advisory job emits signal without
drowning out the team.

## `justfile` additions

Two recipes so contributors can run CI-only checks locally without copying
shell snippets out of YAML:

```just
audit:
    uv venv --allow-existing
    uv pip install -e .
    uv run --with 'pip-audit==2.10.0' pip-audit --strict --disable-pip

lint-workflows: sync-dev
    uv run --with 'zizmor==1.25.2' zizmor --persona=auditor .github/workflows
    uv run --with 'actionlint-py' actionlint .github/workflows
```

`audit` mirrors `supply-chain-runtime` step-for-step so a local pass is the
same guarantee CI gives. Do not collapse the install line back into a
`sync-dev` dependency — `sync-dev` installs dev extras (`ruff`, `ty`,
`pre-commit`) that the runtime audit must not see, and an empty `.venv`
audits clean even with pip-audit present.

`lint` and `format` are unchanged (they only need `ruff`). `setup` already
chains `install-hooks`, so updating `.pre-commit-config.yaml` is enough for new
contributors to pick up the new revs on their next `just setup`.

## `CLAUDE.md` updates

The current text says "There is no separate type-checker configured; do not
invoke `ty` or `mypy` here." Replace with:

> Python 3.11+. Ruff is the linter/formatter (line length 120, selects
> `E,F,I,UP,B,SIM`). `ty check src` runs in CI as an **advisory** job
> (`continue-on-error: true`); type errors do not block PRs but are surfaced in
> the run summary. Do not invoke `mypy` or `pyright`. The hard-fail checks per
> commit are ruff, the pre-commit hygiene hooks, and `detect-secrets`.

No other CLAUDE.md sections need to move.

## Error / skipping behavior

- A pre-commit hook failure fails the `pre-commit` CI job. There is no
  `continue-on-error` on it; the lint stage is a hard gate.
- `tests` is a hard gate at the 85 % floor. A 3.11-only or 3.13-only failure
  fails the matrix (because `fail-fast: false` lets both branches report).
- `typecheck` is advisory (`continue-on-error: true`). It writes findings to
  `$GITHUB_STEP_SUMMARY` but does not block the PR. If we decide to harden it
  later, removing `continue-on-error: true` is the only edit.
- `supply-chain-dev` is advisory (`continue-on-error: true`) because it
  audits the dev/test extras; a CVE in `pytest` or `ruff` should not gate a
  production code merge.
- `docs`, `workflow-hygiene`, `supply-chain-runtime`, and `package-smoke` are
  hard gates. None of them have flake characteristics in the steady state.
  `supply-chain-runtime` is the production-surface audit and the one that
  fails the PR.
- `transport-integration.yml`'s gating behavior is unchanged. Its
  `gdbstub-integration` job continues to require the `GDBSTUB_RUNNER_AVAILABLE`
  variable on a self-hosted runner.

### Advisory triage

When `supply-chain-runtime` fires on an advisory with no released fix, the
process is:

1. Open a tracking issue capturing the advisory ID, affected package and
   version range, exposed code paths (which module imports it, on which code
   path), and the upstream status link.
2. If exploitation requires a code path we do not exercise, suppress with a
   targeted `--ignore-vuln <id>` flag added to the `supply-chain-runtime`
   `pip-audit` invocation, with an inline comment naming the issue and the
   review date.
3. If exploitation is plausible, pin to a non-vulnerable revision (even a
   git pin) or remove the dependency. Do not ship to `main` with an
   unsuppressed runtime advisory.

Target SLA: 5 business days from the failing CI run to either a suppression
with rationale or a fix. `supply-chain-dev` findings follow the same shape
but without the SLA — they are tracked, not gated.

The 5-day SLA is enforced by the `schedule:` trigger in `ci.yml`'s `on:`
block (daily 06:17 UTC). On a scheduled run, `supply-chain-runtime` failure
does not block any in-flight PR (there is none); it fails the workflow on
`main` visibly on the repo home page, which is the SLA trigger event.
Removing the `schedule:` trigger requires revising this SLA.

A standalone `.pip-audit-ignore` file is **not** pre-created here; the
implementation plan introduces it only if and when the first advisory needs
it. Spec mandate is the process, not the artifact.

## Known precondition (blocker for the implementation plan)

`tests/test_process_identity.py::test_proc_probe_owns_listener_matches_our_own_listening_socket`
fails locally on the development host this spec was written on (1 failed, 1053
passed). That single known failure is a **floor** on the expected
`ubuntu-24.04` delta, not a ceiling: the GitHub-hosted runner is a different
kernel, different `/proc` shape, different filesystem layout, different
PTY allocation behavior, and may surface additional failures or
environment-coupled skips that have never run on the developer's host.

The implementation plan **must**, before `tests` becomes a required check:

1. Execute the full `pytest` suite once on `ubuntu-24.04` — either via a
   `ubuntu-24.04` container locally, or via a throwaway one-shot GitHub
   Actions workflow whose only job is to dump pytest output as an artifact.
2. Produce a triage table covering **every** failure and every
   environment-coupled skip observed on that run. Each row must end in one of
   three dispositions:
   - **Fix the test** — host-specific assumption is hidden, replace with a
     portable check.
   - **Fix the underlying code** — the test exposed a real bug; fix the
     code, leave the test alone.
   - **Skip with precise condition** — add a `pytest.mark.skipif(...)` with a
     specific predicate (kernel feature probe, filesystem detection, etc., not
     `sys.platform != "linux"`-class breadth) and a documented reason
     pointing at the proc/PTY/etc. coupling.

Risk surface to inspect proactively (these are the parts of the codebase
most likely to differ on the runner kernel):

- `/proc/net/tcp` and `/proc/net/tcp6` ordering, encoding, and the
  listener-detection heuristic in `seams/process_identity.py` —
  ordering of socket entries is kernel-version-sensitive.
- PTY allocation and file-lock behavior under `transport/serial_local`
  — runner kernels may differ on `O_NONBLOCK` semantics on PTYs and on
  `flock`/`fcntl` interaction with bind-mounts.
- Anything that walks `/proc` (cgroup hierarchy, `/proc/<pid>/fd`,
  `/proc/<pid>/status` field layout) — cgroup v1 vs v2 layout and
  format-version drift across kernels are common breakage modes.

`tests` does not become a required check until the triage table is
committed and every row's disposition is implemented. The first known
failure (`test_proc_probe_owns_listener_matches_our_own_listening_socket`)
is one row in that table, not the whole table. The triage may reduce
runner branch coverage below the locally measured 89 %; the implementation
plan owns re-measuring on the runner and adjusting `--cov-fail-under`
accordingly (see "Coverage floor" above).

## Considered & rejected alternatives

- **Single matrix job that also runs lint.** Rejected because pre-commit
  failures and pytest failures want different signal: combining them makes
  re-running just the lint step impossible from the GitHub UI and adds N×
  duplicate lint runs across the matrix.
- **Codecov / Coveralls integration.** Rejected to avoid a third-party
  dependency and an extra token. XML artifact + `--cov-fail-under` gives us the
  gating behavior we asked for without the integration surface.
- **`mypy` or `pyright` instead of `ty`.** Rejected: `ty` is the global
  standard, is significantly faster (matters when added to per-commit hooks
  later if we tighten the gate), and is from the same vendor as `ruff` and
  `uv`.
- **Splitting into `quality.yml`, `tests.yml`, `security.yml`.** Rejected at
  this size of project: more YAML to keep in sync, duplicated checkout/uv
  setup, and one badge per file. A single `ci.yml` with named jobs gives the
  same per-job re-run granularity without the duplication.
- **Adopt `ty` strictly from day one.** Rejected because the codebase has not
  been written against any typechecker; gating on first-run findings would
  block unrelated PRs. Advisory mode produces the same signal without the
  disruption, with a clear future tightening path.
- **Run `zizmor` as a pre-commit hook.** Rejected because it hits the GitHub
  advisory database for some checks and is slower than the per-commit budget.
  Kept as a CI-only check with a `just lint-workflows` local recipe for
  developers who want to run it on demand.
- **Promote `transport-integration.yml` into `ci.yml` as additional jobs.**
  Rejected: that workflow has a different runner availability model
  (self-hosted gated on `vars.GDBSTUB_RUNNER_AVAILABLE`) and a separate
  triggering story. Mixing it into the per-PR baseline would either make every
  PR red on missing infrastructure or hide real failures behind `if:` clauses.
- **Single `supply-chain` audit on `.[dev,test]` with an allowlist for
  dev-tool CVEs.** Rejected because the allowlist becomes the choke point:
  every CVE in `pytest`, `ruff`, `pre-commit`, etc. now needs a triage
  decision *before* the production code can merge, even when the dev tool is
  not part of the shipped surface. Splitting into a hard-gate runtime audit
  and an advisory dev audit moves dev-tool advisories out of the merge
  critical path while keeping production exposure tight.
- **Demote `supply-chain` to advisory entirely.** Rejected because runtime
  CVEs are exactly the thing this gate exists to catch — a known-exploitable
  vulnerability in a runtime dependency reaching `main` is the failure mode
  the audit is supposed to prevent. Advisory-only would reduce the gate to a
  notification system.
- **Drop `branch = true` to keep the statement-coverage cushion.** Rejected
  because branch coverage is the stronger signal — it catches missed
  `else`-arms and short-circuited boolean paths that statement coverage
  silently passes. The 4-point cushion against the 89 % measured branch
  total is smaller than the 6-point cushion against statement-only coverage,
  but the gain in metric strength outweighs the loss in cushion. The
  cushion is still wide enough to absorb routine refactoring.
- **Leave `pip-audit` pinned in `[dev]` and rely on the `--with` version
  everywhere it runs.** Rejected for the same reason `zizmor` was collapsed:
  two pin lifecycles for one tool produces drift between local and CI. The
  `--with` form is now the canonical pin.
- **Floor-pin `pip-audit` (`>=2.10,<3`).** Rejected: a floor pin allows
  silent patch and minor drift; an `--ignore-vuln` syntax change between
  2.10 and 2.11 would land without review. Exact pin at all three sites
  (CI runtime, CI dev, justfile `audit`) makes every bump a deliberate,
  reviewable edit and matches the `zizmor==1.25.2` precedent.
- **Add `schedule:` + job-level `if:` filters so only the supply-chain jobs
  run on cron.** Rejected: pollutes every other job with
  `if: github.event_name != 'schedule'`, and `ubuntu-24.04` runner minutes
  for one daily matrix run are cheap compared to the YAML noise.
- **Soften the advisory-triage SLA to "starts at next push-triggered run"
  instead of adding a `schedule:` trigger.** Rejected: that reduces the
  gate to whatever PR cadence the project happens to have, which on a
  quiet week is "never." The whole point of the `supply-chain-runtime`
  hard gate is that a runtime CVE in `main` gets caught quickly; a daily
  cron is the cheapest enforcement of that promise.

## Out-of-scope follow-ups

- Ratcheting `--cov-fail-under` upward as coverage stabilizes.
- Tightening `[tool.ty.rules]` and eventually flipping `typecheck` to a hard
  gate.
- Adding `pip-audit` and `zizmor` to `.pre-commit-config.yaml` once they are
  fast enough or have offline modes that fit a per-commit budget.
- Caching uv's wheel cache between runs via `astral-sh/setup-uv`'s
  `enable-cache: true` once we have measured CI time and confirmed cache hit
  rates are worth the cache-storage cost.
- Enumerating and triaging the full `ubuntu-24.04` test delta — handled
  inside the implementation plan (see "Known precondition"), not in further
  spec revisions.
