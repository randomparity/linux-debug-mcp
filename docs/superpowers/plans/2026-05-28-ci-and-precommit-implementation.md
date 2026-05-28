# CI and Pre-Commit Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Materialize the CI/pre-commit design spec
(`docs/superpowers/specs/2026-05-28-ci-and-precommit-design.md`) into
working files: refreshed `.pre-commit-config.yaml`, new
`.github/workflows/ci.yml`, updated `pyproject.toml`, two new `justfile`
recipes, and the `CLAUDE.md` `ty` paragraph rewrite. Then close out the
spec's "Known precondition" obligation by running pytest on
`ubuntu-24.04`, producing a per-failure/per-skip triage table, applying
the dispositions, re-measuring coverage on the runner, and ratcheting
`--cov-fail-under` to whatever the runner actually supports.

**Architecture:** Foundation files first (pyproject, pre-commit,
justfile, CLAUDE.md) so local `just lint` / `just setup` already match
what CI will run. Then `ci.yml` is built job-by-job — each job committed
individually so a regression in one job can be reverted without
unwinding the rest. After the workflow lands, the first PR run is the
ground truth: we read its pytest output and coverage XML to build the
triage table and ratchet the floor. `tests` is a hard-fail job in
`ci.yml` from day one (no `continue-on-error`) but does **not** become a
GitHub branch-protection required check until the triage table is fully
implemented — that final step is a GitHub UI/API change owned by the
maintainer, not a code change in this plan.

**Tech Stack:** GitHub Actions on `ubuntu-24.04`, `uv` (Python package
manager and venv), `pre-commit`, `ruff`, `ty` (advisory typecheck),
`pytest` + `pytest-cov`, `pip-audit==2.10.0`, `zizmor==1.25.2`,
`actionlint`, `detect-secrets`, `just`.

**Branch:** Stack all implementation commits on `docs/ci-precommit-spec`
on top of the squashed spec commit (`fd24a8d` at plan-writing time).
Final PR covers spec + implementation together.

**Spec line references throughout this plan point at the squashed spec
commit on disk** (`docs/superpowers/specs/2026-05-28-ci-and-precommit-design.md`).

---

## File map

Files this plan creates:

- `.github/workflows/ci.yml` — new workflow, ~140 lines of YAML, eight jobs.

Files this plan modifies:

- `pyproject.toml` — `[project.optional-dependencies]` (ruff floor, add
  `ty`, add `pytest-cov`), `[tool.coverage.run]`, `[tool.coverage.report]`,
  `[tool.ty.rules]`, and removal of the conflicting `[dependency-groups]`
  block.
- `.pre-commit-config.yaml` — bump `pre-commit-hooks` to v6.0.0, add
  `check-executables-have-shebangs`, bump `ruff-pre-commit` to v0.15.14,
  add `actionlint` hook.
- `justfile` — add `audit` recipe and `lint-workflows` recipe.
- `CLAUDE.md` — replace the one paragraph about `ty`.

Files potentially modified by the triage phase (which tests need a
`pytest.mark.skipif` or a fix is determined by what the runner actually
fails on — see Phase 3):

- `tests/test_process_identity.py` (known failure)
- Other tests TBD by the triage table

The triage phase may also modify production code if a row's disposition
is "fix the underlying code." Exact paths cannot be enumerated until the
runner produces output.

---

## Phase 1: Foundation files

### Task 1: Update `pyproject.toml`

**Files:**
- Modify: `pyproject.toml`

**Context:** The current `pyproject.toml` declares dev/test extras
under `[project.optional-dependencies]` but also has a duplicate
`[dependency-groups]` block with `dev = ["hypothesis>=6.153.6"]`. Two
sources of truth for the `dev` group is exactly the drift the spec
rejects elsewhere — merge hypothesis into the canonical
`[project.optional-dependencies].test` block (it's a test dependency, not
a general dev tool) and remove the `[dependency-groups]` block entirely.

- [ ] **Step 1: Read the current `pyproject.toml`**

Run: `cat pyproject.toml`

Expected: shows the file as documented in the plan's File map context.
Confirm both `[project.optional-dependencies]` and `[dependency-groups]`
blocks exist.

- [ ] **Step 2: Replace the file contents**

Overwrite `pyproject.toml` with the following content. This merges
`hypothesis` into the canonical `test` extra, bumps `ruff` and
`pre-commit` floors to match the spec's pre-commit revs, adds `ty` and
`pytest-cov`, and adds the coverage and ty configuration. The
`[dependency-groups]` block is removed because it duplicated the `dev`
extra.

```toml
[build-system]
requires = ["setuptools>=69", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "linux-debug-mcp"
version = "0.1.0"
description = "MCP server foundation for Linux kernel build-boot-debug workflows"
readme = "README.md"
requires-python = ">=3.11"
dependencies = [
  "mcp>=1.9,<2",
  "pydantic>=2.7,<3",
]

[project.optional-dependencies]
dev = [
  "detect-secrets>=1.5,<2",
  "pre-commit>=4.3,<5",
  "ruff>=0.15,<1",
  "ty>=0.0.40,<0.1",
]
test = [
  "hypothesis>=6.153,<7",
  "pytest>=8.2,<9",
  "pytest-cov>=7,<8",
]

[tool.ruff]
line-length = 120
target-version = "py311"

[tool.ruff.lint]
select = ["E", "F", "I", "UP", "B", "SIM"]

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

[project.scripts]
linux-debug-mcp = "linux_debug_mcp.server:main"

[tool.setuptools.packages.find]
where = ["src"]

[tool.pytest.ini_options]
testpaths = ["tests"]
pythonpath = ["src"]
addopts = "-ra"
```

- [ ] **Step 3: Re-sync the venv and confirm the new extras install**

Run:
```bash
uv venv --allow-existing
uv pip install -e '.[dev,test]'
```

Expected: clean install, no resolver errors. `ruff`, `ty`,
`pytest-cov`, `hypothesis`, `pre-commit`, `detect-secrets` all
installed.

- [ ] **Step 4: Smoke-check `ty` runs**

Run: `uv run ty check src 2>&1 | head -40`

Expected: `ty` executes (may emit warnings — that is fine; only
unresolved-import is configured to `warn` and the rest are advisory by
default). The point is to confirm `ty>=0.0.40` resolved a usable binary.

- [ ] **Step 5: Smoke-check `pytest-cov` works**

Run: `uv run python -m pytest --co -q 2>&1 | tail -5 && uv run python -m pytest --cov=src/linux_debug_mcp --cov-report=term --collect-only 2>&1 | tail -10`

Expected: collection succeeds, no errors about unknown `--cov` flag.
(We are not running the suite yet — just verifying the plugin loads.)

- [ ] **Step 6: Run the existing test suite to confirm nothing broke**

Run: `uv run python -m pytest -q 2>&1 | tail -20`

Expected: same outcome as before this task (one known failure in
`test_process_identity.py`, ~1053 passes). If a *new* failure
appeared, stop — the extras change leaked something. If only the known
failure persists, continue.

- [ ] **Step 7: Commit**

```bash
git add pyproject.toml
git commit -m "build: refresh extras + add coverage and ty config

- Bump ruff floor to >=0.15 to match the new pre-commit rev.
- Bump pre-commit floor to >=4.3.
- Add ty>=0.0.40 (advisory typecheck — wired into ci.yml's typecheck
  job, never per-commit).
- Add pytest-cov>=7 (CI tests job runs --cov-fail-under=85 against
  branch coverage).
- Merge hypothesis from the duplicated [dependency-groups] block into
  [project.optional-dependencies].test and drop [dependency-groups]
  so there is one source of truth for the dev/test extras.
- Add [tool.coverage.{run,report}] with branch = true and the standard
  exclude_also patterns (pragma: no cover, TYPE_CHECKING, NotImplementedError).
- Add [tool.ty.rules] with only unresolved-import = warn so the
  advisory typecheck emits signal without drowning the team."
```

---

### Task 2: Update `.pre-commit-config.yaml`

**Files:**
- Modify: `.pre-commit-config.yaml`

**Context:** The spec calls for `pre-commit-hooks` v5.0.0 → v6.0.0
(adds `check-executables-have-shebangs`), `ruff-pre-commit` v0.8.6 →
v0.15.14, and a new `actionlint` hook at v1.7.12. `detect-secrets`
stays at v1.5.0. After this task, `pre-commit run --all-files` is the
local pass that mirrors the CI `pre-commit` job exactly.

- [ ] **Step 1: Replace the file contents**

Overwrite `.pre-commit-config.yaml` with:

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

- [ ] **Step 2: Re-install hooks so the new revs are pulled**

Run: `uv run pre-commit install && uv run pre-commit autoupdate --dry-run 2>&1 | tail -10`

Expected: hooks install. `autoupdate --dry-run` should report
"already up to date" (we just pinned to current stable).

- [ ] **Step 3: Run all hooks across all files**

Run: `uv run pre-commit run --all-files 2>&1 | tail -40`

Expected outcomes per hook:
  - `check-added-large-files`: PASS
  - `check-merge-conflict`: PASS
  - `check-toml`: PASS
  - `check-yaml`: PASS (parses `transport-integration.yml`)
  - `end-of-file-fixer`: may fix files; if it fixes, re-run until it
    reports no changes.
  - `trailing-whitespace`: same — may fix and need a re-run.
  - `check-executables-have-shebangs`: PASS (no broken executables in
    the tree at plan-writing time).
  - `ruff (--fix)`: PASS or auto-fixes. If it fixes, re-run.
  - `ruff-format`: PASS or auto-formats. If it formats, re-run.
  - `detect-secrets`: PASS against `.secrets.baseline`.
  - `actionlint`: PASS against the only current workflow,
    `.github/workflows/transport-integration.yml`. If it flags anything
    in that workflow, stop and treat it as a separate bug; do not edit
    `transport-integration.yml` as part of this task.

- [ ] **Step 4: If any file was modified by hook auto-fix, stage the fixes**

Run: `git status`

If `pre-commit run` modified files, those are intentional formatting
fixes the new revs introduced. Stage them in this commit; they are not
out-of-scope.

- [ ] **Step 5: Commit**

```bash
git add .pre-commit-config.yaml [any-files-modified-by-hooks]
git commit -m "ci: refresh pre-commit hooks to current stable

- pre-commit-hooks v5.0.0 -> v6.0.0; adds check-executables-have-shebangs
  to catch committed-executable Python/shell files missing a shebang.
- ruff-pre-commit v0.8.6 -> v0.15.14 (current stable, May 2026);
  matches the >=0.15 floor in pyproject.toml. Roughly one year of
  lint/format improvements applied to the tree by this rev — bundled
  with the rev bump rather than split across two commits.
- Add actionlint v1.7.12 to lint .github/workflows/*.yml locally and
  in the pre-commit CI job: syntax, shellcheck inside run: blocks,
  unknown action inputs.
- detect-secrets v1.5.0 unchanged."
```

(If no auto-fixes happened, drop the third line from the body.)

---

### Task 3: Add `audit` and `lint-workflows` recipes to `justfile`

**Files:**
- Modify: `justfile`

**Context:** Two new recipes so contributors can run CI-only checks
locally. `audit` MUST be self-contained per the spec (round 3) — its
own `uv venv --allow-existing` + `uv pip install -e .` (no `[dev,test]`
extras, mirroring `supply-chain-runtime` exactly) + the pinned
pip-audit invocation. Do **not** chain it off `sync-dev` — `sync-dev`
installs dev extras (ruff, ty, pre-commit) that the runtime audit must
not see. `lint-workflows` chains off `sync-dev` because it only audits
the workflow files, not the package surface.

- [ ] **Step 1: Append the two recipes to `justfile`**

Edit `justfile`. Append at the end of the file (after the `check-docs`
recipe):

```just

audit:
    uv venv --allow-existing
    uv pip install -e .
    uv run --with 'pip-audit==2.10.0' pip-audit --strict --path .venv

lint-workflows: sync-dev
    uv run --with 'zizmor==1.25.2' zizmor .github/workflows
    uv run --with 'actionlint-py' actionlint
```

- [ ] **Step 2: List recipes to confirm `just` parses the file**

Run: `just --list`

Expected: `audit` and `lint-workflows` appear in the recipe list.

- [ ] **Step 3: Run `just audit` locally**

Run: `just audit 2>&1 | tail -20`

Expected: pip-audit installs to its own ephemeral env, audits the
production install (just `.` — no extras), reports `No known
vulnerabilities found` or lists advisories. **A non-empty advisory list
is fine for this step** — the gate is in CI; here we are confirming the
recipe runs end-to-end. If it lists advisories, capture them; we will
need to triage them in CI later.

- [ ] **Step 4: Run `just lint-workflows` locally**

Run: `just lint-workflows 2>&1 | tail -20`

Expected: zizmor and actionlint both run against
`.github/workflows/transport-integration.yml`. Both should pass at
plan-writing time — `transport-integration.yml` already follows the
SHA-pinning + `persist-credentials: false` standard. If either flags
the existing workflow, stop and treat it as a separate bug, not part of
this task.

- [ ] **Step 5: Commit**

```bash
git add justfile
git commit -m "build: add audit and lint-workflows recipes

- audit: self-contained pip-audit run mirroring supply-chain-runtime
  in ci.yml step-for-step (uv venv --allow-existing + uv pip install -e .
  + uv run --with 'pip-audit==2.10.0' pip-audit --strict --path .venv).
  Deliberately NOT chained off sync-dev: sync-dev installs dev extras
  (ruff, ty, pre-commit) that the runtime audit must not see. A local
  pass on this recipe gives the same guarantee CI gives.
- lint-workflows: zizmor (security audit, default persona -- NOT
  --persona=auditor; see the spec's 'Considered & rejected' entry) +
  actionlint (syntax/shellcheck) on .github/workflows/. Chained off
  sync-dev because it audits the workflow files rather than the
  package surface."
```

---

### Task 4: Update the `ty` paragraph in `CLAUDE.md`

**Files:**
- Modify: `CLAUDE.md`

**Context:** CLAUDE.md currently says: "Python 3.11+. Ruff is the only
linter/formatter (line length 120, selects `E,F,I,UP,B,SIM`). There is
no separate type-checker configured; do not invoke `ty` or `mypy` here."
The spec replaces that paragraph with the advisory-`ty` language.

- [ ] **Step 1: Edit the paragraph**

Replace this exact text in `CLAUDE.md`:

> Python 3.11+. Ruff is the only linter/formatter (line length 120, selects `E,F,I,UP,B,SIM`). There is no separate type-checker configured; do not invoke `ty` or `mypy` here. Pre-commit uses `pre-commit` (not `prek`) with `detect-secrets` against `.secrets.baseline`.

with:

> Python 3.11+. Ruff is the linter/formatter (line length 120, selects `E,F,I,UP,B,SIM`). `ty check src` runs in CI as an **advisory** job (`continue-on-error: true`); type errors do not block PRs but are surfaced in the run summary. Do not invoke `mypy` or `pyright`. The hard-fail checks per commit are ruff, the pre-commit hygiene hooks, and `detect-secrets`. Pre-commit uses `pre-commit` (not `prek`) with `detect-secrets` against `.secrets.baseline`.

- [ ] **Step 2: Verify the edit applied cleanly**

Run: `rg -n 'There is no separate type-checker' CLAUDE.md`

Expected: no matches. The old sentence is gone.

Run: `rg -n 'ty check src.*advisory' CLAUDE.md`

Expected: one match in the paragraph just edited.

- [ ] **Step 3: Commit**

```bash
git add CLAUDE.md
git commit -m "docs: replace the 'no type-checker' CLAUDE.md paragraph

Reflects the advisory ty job that ci.yml's typecheck step adds.
ty check src runs with continue-on-error: true, surfaces findings
in \$GITHUB_STEP_SUMMARY, does not gate the PR. mypy/pyright are
still off-limits per the global standard."
```

---

## Phase 2: Build `ci.yml` job-by-job

Each job is committed individually. After each commit, run
`actionlint .github/workflows/ci.yml` (via `just lint-workflows` or
directly) and confirm no new errors appear. Job order in the file
matches the spec's job order.

### Task 5: Scaffold `ci.yml` (header, on, permissions, concurrency)

**Files:**
- Create: `.github/workflows/ci.yml`

- [ ] **Step 1: Create the file with only the workflow scaffolding (no jobs yet)**

Create `.github/workflows/ci.yml` with this exact content:

```yaml
name: ci
on:
  pull_request:
  push:
    branches: [main]
  schedule:
    - cron: '17 6 * * *'  # daily, SLA-bearing — see spec "Advisory triage"

permissions:
  contents: read

concurrency:
  group: ci-${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true

jobs: {}
```

Note: `jobs: {}` is intentionally empty here; subsequent tasks add
jobs one at a time. `actionlint` will flag the empty-jobs map; that is
expected for this commit only.

- [ ] **Step 2: Lint the partial file**

Run: `uv run --with 'actionlint-py' actionlint .github/workflows/ci.yml 2>&1 || true`

Expected: actionlint reports the empty `jobs:` map as an error
(something like "jobs section is empty"). That is intentional and will
be fixed by Task 6. Capture the error text in case it changes shape;
proceed.

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: scaffold ci.yml (header, triggers, permissions, concurrency)

Pull_request + push to main + daily schedule cron (17 6 * * *) so the
supply-chain advisory SLA has a wall-clock cadence. Workflow-level
permissions: contents: read; jobs may narrow further. Concurrency group
cancels superseded runs on the same ref.

Empty jobs: {} is intentional and will be filled in by subsequent
commits, one job each, so any regression can be reverted without
unwinding the rest."
```

---

### Task 6: Add the `pre-commit` job

**Files:**
- Modify: `.github/workflows/ci.yml`

- [ ] **Step 1: Replace `jobs: {}` with the `pre-commit` job**

Replace the line `jobs: {}` with:

```yaml
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
```

- [ ] **Step 2: Lint the workflow**

Run: `just lint-workflows 2>&1 | tail -20`

Expected: actionlint passes; zizmor passes. If zizmor flags anything,
do not edit the SHA pins — the SHAs are the ones the spec specified.
If zizmor objects, capture the exact finding and stop.

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: add pre-commit job

Runs uv venv + uv pip install -e '.[dev,test]' + uv run pre-commit run
--all-files --show-diff-on-failure on ubuntu-24.04 / Python 3.11. Hard
gate: no continue-on-error. Identical hook revs to .pre-commit-config.yaml
so a local pre-commit pass is sufficient to know this job will pass."
```

---

### Task 7: Add the `tests` matrix job

**Files:**
- Modify: `.github/workflows/ci.yml`

**Context:** This job is a **hard gate** in the file (no
`continue-on-error`). It will be RED on the first PR push because of
the known `test_process_identity.py` failure and any additional
runner-only failures. That is intentional — the failing run produces
the pytest output we use to build the triage table in Phase 3. The job
does not become a GitHub *required* check until the triage is done; the
hard-fail behavior in this commit only controls whether the workflow
shows red, not whether the PR can merge.

- [ ] **Step 1: Add the `tests` job after `pre-commit`**

Append to `jobs:`, after the `pre-commit:` block:

```yaml
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
```

- [ ] **Step 2: Lint the workflow**

Run: `just lint-workflows 2>&1 | tail -20`

Expected: actionlint + zizmor pass.

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: add tests job (pytest matrix 3.11/3.13 with coverage)

Branch-coverage --cov-fail-under=85 gates the job. fail-fast: false so a
3.11 failure does not mask 3.13 and vice versa. coverage.xml uploaded
as a per-matrix-leg artifact even on failure (if: always) so the triage
phase can read the actual numbers off the runner.

This job is a hard-fail gate at the workflow level (no continue-on-error)
but does NOT become a GitHub required-check until the Phase 3 ubuntu-24.04
triage table is implemented. The first PR run will be RED on the known
local failure plus whatever else the runner surfaces — that is the
ground-truth input for the triage table."
```

---

### Task 8: Add the `typecheck` advisory job

**Files:**
- Modify: `.github/workflows/ci.yml`

**Context:** Advisory (`continue-on-error: true`). The `run:` block
uses `status=0` + `|| status=$?` to capture ty's exit code under
`pipefail` without losing it to the brace group's early exit (round-two
challenge finding — preserve this shape exactly).

- [ ] **Step 1: Append the `typecheck` job**

Append after `tests:`:

```yaml
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
```

- [ ] **Step 2: Lint the workflow**

Run: `just lint-workflows 2>&1 | tail -20`

Expected: pass. (actionlint runs shellcheck inside the `run:` block
and may have opinions about the redirect; the `status=0` + `|| status=$?`
shape is intentional — do not change it to silence shellcheck.)

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: add advisory typecheck job (ty check src)

continue-on-error: true keeps it from blocking PRs. The run block tees
ty output into \$GITHUB_STEP_SUMMARY inside a fenced code block so
findings are visible from the workflow run page rather than buried in
step logs.

The status=0 + '|| status=\$?' shape is required under set -euo pipefail:
without status=0, a ty failure makes the pipeline fail, set -e exits
the brace group early, status is never assigned, and the closing fence
is never written -- corrupting the step summary in exactly the case the
job exists to serve."
```

---

### Task 9: Add the `docs` job

**Files:**
- Modify: `.github/workflows/ci.yml`

- [ ] **Step 1: Append the `docs` job**

Append after `typecheck:`:

```yaml
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
```

- [ ] **Step 2: Lint the workflow**

Run: `just lint-workflows 2>&1 | tail -20`

Expected: pass.

- [ ] **Step 3: Verify `just check-docs` still passes locally**

Run: `just check-docs`

Expected: exits 0 (no `sprint*` in `README.md` or `docs/` outside
`docs/superpowers/`).

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: add docs job (check-docs guard)

Installs ripgrep + just from apt (no uv toolchain needed — check-docs
only uses those two and the workspace itself). Hard gate."
```

---

### Task 10: Add the `workflow-hygiene` job

**Files:**
- Modify: `.github/workflows/ci.yml`

- [ ] **Step 1: Append the `workflow-hygiene` job**

Append after `docs:`:

```yaml
  workflow-hygiene:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd  # v6.0.2
        with:
          persist-credentials: false
      - uses: astral-sh/setup-uv@08807647e7069bb48b6ef5acd8ec9567f424441b  # v8.1.0
      - run: uv run --with 'zizmor==1.25.2' zizmor .github/workflows
```

- [ ] **Step 2: Lint the workflow**

Run: `just lint-workflows 2>&1 | tail -20`

Expected: pass. Note: zizmor will run against ci.yml in its OWN
output the next time `just lint-workflows` is invoked — that is fine
and exactly what the job exists to do.

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: add workflow-hygiene job (zizmor audit)

uv run --with 'zizmor==1.25.2' zizmor .github/workflows on ubuntu-24.04.
Default persona (NOT --persona=auditor) -- see the spec's 'Considered
& rejected' entry on persona choice. Single source of truth for
zizmor's version: same pin as the justfile's lint-workflows recipe,
deliberately not in [project.optional-dependencies]."
```

---

### Task 11: Add the `supply-chain-runtime` job

**Files:**
- Modify: `.github/workflows/ci.yml`

- [ ] **Step 1: Append the `supply-chain-runtime` job**

Append after `workflow-hygiene:`:

```yaml
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
          uv run --with 'pip-audit==2.10.0' pip-audit --strict --path .venv
```

- [ ] **Step 2: Lint the workflow**

Run: `just lint-workflows 2>&1 | tail -20`

Expected: pass.

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: add supply-chain-runtime job (pip-audit, production extras only)

uv pip install -e . (no [dev,test] extras) + uv run --with
'pip-audit==2.10.0' pip-audit --strict --path .venv. This is the
production-surface audit and the hard gate. --strict upgrades
unresolved/skipped packages to failures; --path .venv points pip-audit
at the venv that uv pip install populated so it reads installed-package
metadata directly without re-invoking pip under the uv-managed env
(--disable-pip would have needed -r requirements.txt).

Mirrors the justfile audit recipe step-for-step; a local 'just audit'
pass is the same guarantee this job gives."
```

---

### Task 12: Add the `supply-chain-dev` job

**Files:**
- Modify: `.github/workflows/ci.yml`

- [ ] **Step 1: Append the `supply-chain-dev` job**

Append after `supply-chain-runtime:`:

```yaml
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
          uv run --with 'pip-audit==2.10.0' pip-audit --strict --path .venv
```

- [ ] **Step 2: Lint the workflow**

Run: `just lint-workflows 2>&1 | tail -20`

Expected: pass.

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: add supply-chain-dev advisory job

Same pip-audit invocation as supply-chain-runtime (--strict --path .venv),
but installs '.[dev,test]' extras and is continue-on-error: true. A CVE
in pytest, ruff, ty, etc. should not gate a production code merge -- it
is tracked, not gated. Findings still appear in the run summary so the
team can triage them on the same SLA as runtime advisories."
```

---

### Task 13: Add the `package-smoke` job

**Files:**
- Modify: `.github/workflows/ci.yml`

- [ ] **Step 1: Append the `package-smoke` job**

Append after `supply-chain-dev:`:

```yaml
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

- [ ] **Step 2: Lint the workflow**

Run: `just lint-workflows 2>&1 | tail -20`

Expected: pass on actionlint and zizmor. Confirm the final ci.yml is
~140 lines and contains all eight jobs (`pre-commit`, `tests`,
`typecheck`, `docs`, `workflow-hygiene`, `supply-chain-runtime`,
`supply-chain-dev`, `package-smoke`).

Run: `rg -c '^  [a-z-]+:$' .github/workflows/ci.yml`

Expected: `8` (eight job keys at the right indent).

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: add package-smoke job (uv build + stdio startup)

Builds the wheel, installs it system-wide on the runner, runs the
linux-debug-mcp console script under timeout 2; exit 124 (the timeout)
counts as success because the stdio server has no work to do without
an MCP client connected. Hard gate: a broken entry-point wiring fails
the workflow here rather than at a user's first install."
```

---

## Phase 3: First PR push, ubuntu-24.04 triage, coverage ratchet

This phase is where the workflow meets the runner. The plan can specify
the *process* exactly but cannot enumerate the *content* of the triage
table until the runner produces pytest output. Each task below has
deterministic instructions; the artifacts they produce drive the
following tasks.

### Task 14: Push the branch and capture the first CI run

**Files:** none (push + observe)

- [ ] **Step 1: Verify branch state before pushing**

Run: `git log --oneline main..HEAD`

Expected: a sequence of ~10 commits — the squashed spec commit followed
by the foundation-file commits (Tasks 1-4) and the eight ci.yml commits
(Tasks 5-13). Exact count depends on how many auto-fix commits Task 2
generated.

Run: `git status`

Expected: clean working tree (no uncommitted changes).

- [ ] **Step 2: Push the branch**

Run: `git push -u origin docs/ci-precommit-spec`

Expected: push succeeds; GitHub returns a PR-creation hint URL.

- [ ] **Step 3: Open the PR**

Run:
```bash
gh pr create --title "CI and pre-commit: design spec + implementation" --body "$(cat <<'EOF'
## Summary

- Adds the CI/pre-commit design spec at
  `docs/superpowers/specs/2026-05-28-ci-and-precommit-design.md`
  (converged across three /challenge rounds, 11 findings closed).
- Materializes the spec: refreshed `.pre-commit-config.yaml`, new
  `.github/workflows/ci.yml` (eight jobs), updated `pyproject.toml`
  (extras + coverage + ty config), new `audit` and `lint-workflows`
  justfile recipes, and a one-paragraph CLAUDE.md rewrite.
- First push is **expected to be red** on the `tests` job — the
  known `test_process_identity.py` failure plus any additional
  ubuntu-24.04 deltas are the input to the spec's "Known precondition"
  triage table, which lands in follow-up commits on this branch.

## Test plan

- [ ] `pre-commit` job: green
- [ ] `tests` (3.11): red on first push, triaged, then green
- [ ] `tests` (3.13): red on first push, triaged, then green
- [ ] `typecheck`: advisory; summary visible on run page
- [ ] `docs`: green
- [ ] `workflow-hygiene`: green
- [ ] `supply-chain-runtime`: green (or single tracked advisory)
- [ ] `supply-chain-dev`: advisory; advisories tracked
- [ ] `package-smoke`: green

After the triage table commit, this branch is ready to merge and
`tests` can be added to branch protection as a required check.
EOF
)"
```

Expected: PR opens; CI starts. Capture the PR URL.

- [ ] **Step 4: Wait for the workflow run to complete and capture failures**

Run: `gh run watch --exit-status 2>&1 | tail -20` (or use `gh run list --workflow=ci.yml --limit=1` + `gh run view <id>`).

Expected: many jobs green, `tests` likely red on both matrix legs.
Other jobs may also fail in unexpected ways — capture each.

- [ ] **Step 5: Download the pytest output and coverage XML for both matrix legs**

Run:
```bash
RUN_ID=$(gh run list --workflow=ci.yml --branch=docs/ci-precommit-spec --limit=1 --json databaseId --jq '.[0].databaseId')
gh run view "$RUN_ID" --log-failed > /tmp/ci-failed.log
gh run download "$RUN_ID" --name coverage-3.11 --dir /tmp/cov-3.11 || true
gh run download "$RUN_ID" --name coverage-3.13 --dir /tmp/cov-3.13 || true
ls -la /tmp/cov-3.11 /tmp/cov-3.13 2>&1
```

Expected: failure log captured; coverage XML downloaded (or noted as
missing if both legs failed before reaching the upload step). If
neither XML was produced, the `tests` job failed *before* pytest could
emit XML; in that case Task 17's coverage measurement waits until at
least one matrix leg makes it through pytest, even with failures —
which `--cov-fail-under=85` does (pytest still writes XML, then fails
on the fail-under threshold).

- [ ] **Step 6: No commit in this task**

Captures only. Proceed to Task 15.

---

### Task 15: Build the ubuntu-24.04 triage table

**Files:**
- Create: `docs/superpowers/runner-triage/2026-MM-DD-ubuntu-24.04-pytest-triage.md`
  (date is the day this task runs)

**Context:** Per the spec, every failure and every environment-coupled
skip observed on the runner gets one row in this table with one of
three dispositions:

- **fix-test** — host-specific assumption is hidden; the test is the bug.
- **fix-code** — the test exposed a real bug; fix production code, leave
  the test alone.
- **skipif** — add a precise-condition `pytest.mark.skipif(...)` with a
  specific predicate (kernel feature probe, filesystem detection, etc.,
  NOT `sys.platform != "linux"`-class breadth) and a documented reason.

The spec calls out three risk surfaces to inspect proactively even if
those tests didn't fail this run:

- `/proc/net/tcp` and `/proc/net/tcp6` ordering and encoding — see
  `seams/process_identity.py`.
- PTY allocation and file-lock behavior under `transport/serial_local`.
- Anything walking `/proc` (cgroup hierarchy, `/proc/<pid>/fd`,
  `/proc/<pid>/status` field layout).

- [ ] **Step 1: Make the directory if it does not exist**

Run: `mkdir -p docs/superpowers/runner-triage`

- [ ] **Step 2: Create the triage document**

Create `docs/superpowers/runner-triage/2026-MM-DD-ubuntu-24.04-pytest-triage.md`
(replace `2026-MM-DD` with today's date) with this skeleton, then fill
in one row per failure and per environment-coupled skip observed in
Task 14:

```markdown
# ubuntu-24.04 pytest triage

Date: 2026-MM-DD
CI run: https://github.com/<owner>/linux-debug-mcp/actions/runs/<RUN_ID>
Python matrix legs: 3.11, 3.13

## Failures and environment-coupled skips

| # | Test (file::test) | Python leg | Disposition | Rationale | Predicate (if skipif) |
|---|---|---|---|---|---|
| 1 | tests/test_process_identity.py::test_proc_probe_owns_listener_matches_our_own_listening_socket | 3.11+3.13 | TBD | TBD | TBD |
| 2 | ... | ... | TBD | TBD | TBD |

## Risk surfaces inspected even if no test failed there

- `seams/process_identity.py` (`/proc/net/tcp` parser): [findings, or
  "no change needed — runner output matches local"]
- `transport/serial_local` (PTY + flock): [findings]
- `/proc/<pid>/*` walkers: [findings]

## Coverage on the runner

- 3.11: <statements%> / <branches%>
- 3.13: <statements%> / <branches%>

Floor recommendation: --cov-fail-under=<N> (see Task 18 commit message
for the justification).
```

- [ ] **Step 3: Fill in the failures from `/tmp/ci-failed.log`**

For each failed test or environment-coupled skip in the captured
output: add a row. Determine disposition by inspecting the test source
and the failure detail. Do NOT pick `skipif` as the default —
`fix-test` is preferred when the test's assumption is portable. Use
`skipif` only when the underlying capability genuinely is not available
on `ubuntu-24.04` and the test exists to exercise that capability.

- [ ] **Step 4: Inspect the three risk surfaces proactively**

For each risk surface listed in the template, read the relevant
production module and the tests touching it; cross-reference against
the actual runner behavior captured in the failure log (or run the
relevant probe via a one-shot debug step if needed). Write a one- to
two-sentence finding under "Risk surfaces inspected" for each.

- [ ] **Step 5: Commit the triage document with all dispositions filled**

```bash
git add docs/superpowers/runner-triage/2026-MM-DD-ubuntu-24.04-pytest-triage.md
git commit -m "docs: triage ubuntu-24.04 pytest failures and env-coupled skips

Per the CI/pre-commit spec's 'Known precondition' obligation: one row
per failure and per environment-coupled skip observed on the runner,
each ending in fix-test / fix-code / skipif. Risk surfaces (/proc/net/tcp
ordering, PTY/flock, /proc walkers) inspected proactively per the
spec's risk list.

The dispositions are applied in the following commits."
```

---

### Task 16: Apply triage dispositions

**Files:** Determined by the table rows. Each row maps to either a test
file edit (`fix-test`, `skipif`) or a production module edit (`fix-code`).

**Context:** This task may be one commit per row, or batched
disposition-by-disposition (all `fix-test` rows in one commit, all
`skipif` rows in another, etc.) depending on volume. The plan does not
prescribe — use judgement based on the table size. Each *commit* must
correspond to a closeable chunk of dispositions (e.g., "fix three tests
that assumed cgroup v1") rather than mixing dispositions arbitrarily.

- [ ] **Step 1: For each `fix-test` row: edit the test, then run that one test**

For a row with file `tests/test_X.py::test_Y` and disposition `fix-test`:

```bash
# Edit the test per the rationale column
uv run python -m pytest tests/test_X.py::test_Y -q
```

Expected: PASS (or, if the test depends on infrastructure that simply
isn't present on this dev host, document that and switch the
disposition to `skipif`).

- [ ] **Step 2: For each `fix-code` row: edit the production code, run the test plus a broader scope**

For a row with file `tests/test_X.py::test_Y` and disposition `fix-code`:

```bash
# Edit the production code per the rationale column
uv run python -m pytest tests/test_X.py -q  # the whole test module
uv run python -m pytest -q -x              # the whole suite, stop on first fail
```

Expected: the targeted test passes; no other tests regress.

- [ ] **Step 3: For each `skipif` row: add the precise-condition marker**

For a row with disposition `skipif` and a predicate column like
"`cgroup_v1_only`":

Edit the test file. Add a top-level helper if multiple tests share the
predicate; otherwise inline. Example shape (do not copy-paste — the
actual predicate is in the table row):

```python
import pytest
import pathlib

_HAS_CGROUP_V1 = pathlib.Path("/sys/fs/cgroup/memory").is_dir()

@pytest.mark.skipif(
    not _HAS_CGROUP_V1,
    reason="test exercises cgroup v1 layout; ubuntu-24.04 runners are v2-only",
)
def test_Y():
    ...
```

The reason string MUST cite the concrete missing capability, not
`sys.platform`-class breadth. After adding, run:

```bash
uv run python -m pytest tests/test_X.py::test_Y -q
```

Expected: SKIPPED with the documented reason (on this dev host if the
predicate matches the host's lack, or run in a container that lacks it,
or accept that locally it may PASS and the SKIP only fires on the
runner — note which in the commit message).

- [ ] **Step 4: Commit per disposition group**

Suggested commit-message shape per group:

```
test: <fix-test|skipif|fix-code> for <short description of the group>

Per row(s) <N>-<M> of
docs/superpowers/runner-triage/2026-MM-DD-ubuntu-24.04-pytest-triage.md:
<one-sentence summary of what changed>.

<For skipif:> Predicate: <exact predicate>. Reason cites <concrete
capability>, not platform breadth, per spec mandate.
```

- [ ] **Step 5: After every disposition is committed, run the full suite locally**

Run: `uv run python -m pytest -q 2>&1 | tail -20`

Expected: 0 failures locally. Some new SKIPS (the ones whose predicate
matches the dev host). No regressions in tests untouched by this phase.

---

### Task 17: Push the triage commits and re-measure coverage on the runner

**Files:** none (push + observe + capture)

- [ ] **Step 1: Push**

Run: `git push`

Expected: push succeeds; CI re-runs.

- [ ] **Step 2: Watch the run**

Run: `gh run watch --exit-status` and capture results.

Expected: `tests` is now GREEN on both matrix legs (or the next round
of failures exposes a row missed in the triage table — if so, return to
Task 15, add the missed rows, repeat).

- [ ] **Step 3: Download the coverage XML for both matrix legs**

Run:
```bash
RUN_ID=$(gh run list --workflow=ci.yml --branch=docs/ci-precommit-spec --limit=1 --json databaseId --jq '.[0].databaseId')
gh run download "$RUN_ID" --name coverage-3.11 --dir /tmp/cov-3.11
gh run download "$RUN_ID" --name coverage-3.13 --dir /tmp/cov-3.13
```

- [ ] **Step 4: Extract the statement and branch percentages from each XML**

Run (per leg):
```bash
python -c '
import xml.etree.ElementTree as ET
for leg in ["3.11", "3.13"]:
    tree = ET.parse(f"/tmp/cov-{leg}/coverage.xml")
    root = tree.getroot()
    lr = float(root.get("line-rate", 0)) * 100
    br = float(root.get("branch-rate", 0)) * 100
    print(f"{leg}: statements={lr:.2f}% branches={br:.2f}%")
'
```

Expected: prints two lines with the actual percentages. Record both.
The smaller of the two branch percentages is the floor input for Task 18.

- [ ] **Step 5: Update the runner-triage doc with the measured coverage**

Edit `docs/superpowers/runner-triage/2026-MM-DD-ubuntu-24.04-pytest-triage.md`,
filling in the "Coverage on the runner" section with the measured numbers
and a one-line statement of which leg is the binding constraint.

- [ ] **Step 6: No commit yet — Task 18 commits the doc update plus the cov-fail-under change together**

---

### Task 18: Ratchet `--cov-fail-under` to the runner's actual branch coverage minus the cushion

**Files:**
- Modify: `.github/workflows/ci.yml` (the `tests` job's pytest invocation)
- Modify: `docs/superpowers/runner-triage/2026-MM-DD-ubuntu-24.04-pytest-triage.md`
  (already edited in Task 17 step 5; commit it now)

**Context:** Spec rule: branch coverage is the metric; cushion stays
~4 points. If the binding leg measures, e.g., 87% branch coverage, the
floor becomes `--cov-fail-under=83`. If the binding leg measures
≥89%, leave the floor at 85 (the spec's nominal value). Never raise the
floor higher than `(measured_branch_rate - 4)`.

- [ ] **Step 1: Compute the new floor**

Take the smaller of the two `branches=` percentages from Task 17 Step 4.
Subtract 4 (the cushion). Round down to an integer. That is the new
`--cov-fail-under`. If the result is ≥85, leave the workflow at 85
(don't ratchet UP — only DOWN, so the floor matches what the runner
actually supports today, not aspirations).

- [ ] **Step 2: Edit `ci.yml`'s `tests` job**

Find the line `--cov-fail-under=85` in `.github/workflows/ci.yml` and
replace `85` with the computed value (or leave it if step 1 said
≥85). Stage.

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/ci.yml docs/superpowers/runner-triage/
git commit -m "ci: ratchet --cov-fail-under to runner-measured floor

ubuntu-24.04 measured branch coverage (binding leg): <N>% (3.11) /
<M>% (3.13). Floor = min(N, M) - 4 cushion = <FLOOR>%. Triage doc
captures the measurements; this commit pins the floor to what the
runner produces today, leaving room for the cushion the spec's
'Coverage floor' bullet requires.

Future ratchet-UP commits should accompany code that demonstrably
raises the runner-measured percentage; ratchet-DOWN should accompany
a regression triage row added to the runner-triage doc."
```

- [ ] **Step 4: Push and confirm a green run end-to-end**

Run: `git push && gh run watch --exit-status`

Expected: ALL jobs green except `supply-chain-dev` and `typecheck`
(both advisory; either may still fail). `tests` is green on both
matrix legs.

---

### Task 19: Mark the spec's "Known precondition" as resolved

**Files:**
- Modify: `docs/superpowers/specs/2026-05-28-ci-and-precommit-design.md`
  (add a brief resolution note to the "Known precondition" section)

**Context:** The spec's "Known precondition" section currently reads as
a forward-looking obligation. Now that the obligation is met, append a
short note pointing at the triage doc, so future readers of the spec
see it is closed.

- [ ] **Step 1: Edit the spec**

In `docs/superpowers/specs/2026-05-28-ci-and-precommit-design.md`, at
the very end of the "## Known precondition (blocker for the
implementation plan)" section (just before the next `##` header), add
the following paragraph:

```markdown
**Resolution (2026-MM-DD):** The triage table and dispositions are
captured in
`docs/superpowers/runner-triage/2026-MM-DD-ubuntu-24.04-pytest-triage.md`.
`--cov-fail-under` was ratcheted to the runner-measured floor in the
same PR. `tests` is now suitable for inclusion in the GitHub branch-
protection required-checks list — that final step is a repo-settings
change, not a code change.
```

(Replace `2026-MM-DD` with the dates of the triage commit and the
ratchet commit.)

- [ ] **Step 2: Commit**

```bash
git add docs/superpowers/specs/2026-05-28-ci-and-precommit-design.md
git commit -m "docs: mark CI spec 'Known precondition' as resolved

Points the spec at the committed triage doc. The repo-settings change
that adds 'tests' as a required check is intentionally out of scope of
this PR (it cannot be made via a code commit)."
```

- [ ] **Step 3: Push final**

Run: `git push && gh run watch --exit-status`

Expected: green; the resolution-note edit is a docs-only change and
should not perturb any job.

---

### Task 20: Hand off the required-check toggle

**Files:** none (this is a maintainer action, captured in the PR
description / a follow-up comment so it doesn't get lost)

- [ ] **Step 1: Add a PR comment naming the required-check toggle**

Run:
```bash
gh pr comment --body "Ready for merge. After merge, please add the following CI job(s) to the branch-protection required-checks list for \`main\`:

- \`ci / tests (3.11)\`
- \`ci / tests (3.13)\`
- \`ci / pre-commit\`
- \`ci / docs\`
- \`ci / workflow-hygiene\`
- \`ci / supply-chain-runtime\`
- \`ci / package-smoke\`

\`typecheck\` and \`supply-chain-dev\` are advisory by design — do **not** add them as required checks."
```

- [ ] **Step 2: Final task complete**

The plan is done. The maintainer toggles required checks via the
repository Settings → Branches UI (or `gh api`). That action is the
last step of converting `tests` from a workflow-level hard gate into
a merge-blocking gate.

---

## Out of scope

- Adding the eight required-check entries to branch protection — Task
  20 hands this to the maintainer; it cannot be done via a code commit.
- Tightening `[tool.ty.rules]` past the spec's permissive starting
  profile. Out-of-scope follow-up per the spec.
- Caching uv's wheel cache between runs. Out-of-scope follow-up per
  the spec.
- Adding `pip-audit` / `zizmor` to `.pre-commit-config.yaml`. Out-of-scope
  follow-up per the spec.
- Ratcheting `--cov-fail-under` UPWARD beyond what Task 18 sets. Spec
  out-of-scope; future PRs may raise the floor when accompanied by
  code that genuinely raises the runner measurement.
- Editing `transport-integration.yml`. The spec's non-goal list calls
  out leaving its job logic untouched; this plan preserves that.
