# Project Documentation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Create user-facing documentation that explains what the Linux Debug MCP server does, how to install it, how to connect Claude Code and Codex, and how to run the implemented local build, boot, test, artifact, and debug workflows.

**Architecture:** Keep `README.md` as the short landing page and move detailed procedural material into focused docs under `docs/`. Use exact commands copied from the current package entrypoint and MCP client CLIs, with the Fedora/libvirt guide remaining the deep host-preparation guide. Add a documentation verification command that treats no-match searches as success and fails only when development-iteration terminology appears in public docs.

**Tech Stack:** Markdown, Python 3.11+, `uv`, `just`, Python MCP SDK/FastMCP, Claude Code MCP CLI, Codex MCP CLI/config TOML.

---

## Source Facts To Preserve

- Package name: `linux-debug-mcp`.
- Console script: `linux-debug-mcp = "linux_debug_mcp.server:main"`.
- Local development setup: `just setup`, or `uv venv --allow-existing && uv pip install -e '.[test,dev]'`.
- Minimal editable install: `python -m pip install -e '.[test]'`.
- Test command: `python -m pytest`; `just test` also runs through `uv`.
- Server entrypoint: `linux-debug-mcp` starts a stdio MCP server with `create_app().run()`.
- Default artifact root: `.linux-debug-mcp/runs`.
- Implemented local workflow tools include `host.check_prerequisites`, `providers.list`, `kernel.create_run`, `kernel.build`, `target.boot`, `target.run_tests`, `artifacts.collect`, `artifacts.get_manifest`, `workflow.build_boot_test`, `workflow.build_boot_debug`, and `debug.*`.
- Future-provider tools are callable stubs and should be documented as non-executing: `remote.*`, `reservation.*`, `provision.*`, `hardware.*`, `console.*`, and `workflow.reserve_provision_boot`.

## File Structure

- Modify: `README.md` as the project overview, quick install, quick client setup links, and first workflow example.
- Create: `docs/installation.md` for Python, `uv`, `just`, editable install, host checks, test commands, and server smoke checks.
- Create: `docs/client-setup.md` for Claude Code and Codex MCP setup, verification, and security notes.
- Create: `docs/tool-reference.md` for the implemented tool surface, request examples, artifact layout, and future-provider stub boundaries.
- Modify: `docs/fedora-libvirt-user-guide.md` only to link back to the new install/client docs and avoid duplicated setup details.
- Modify: `docs/ppc64le-provider-spike.md` only to link from the tool reference and keep ppc64le status aligned with provider stubs.
- Optional modify: `justfile` to add a docs terminology check if the project wants enforcement in CI.

## Task 1: Documentation Skeleton And README Landing Page

**Files:**
- Modify: `README.md`
- Create: `docs/installation.md`
- Create: `docs/client-setup.md`
- Create: `docs/tool-reference.md`

- [ ] **Step 1: Create the documentation skeleton**

Create each file with only its own top-level heading and no placeholder
language:

`docs/installation.md`:

```markdown
# Installation
```

`docs/client-setup.md`:

```markdown
# Client Setup
```

`docs/tool-reference.md`:

```markdown
# Tool Reference
```

- [ ] **Step 2: Rewrite `README.md` as a concise landing page**

Replace the README body with this minimum content structure:

````markdown
# Linux Development MCP Server

Linux Debug MCP is a Python MCP server for local Linux kernel build, boot,
smoke-test, artifact, and QEMU gdbstub debug workflows.

## What Works Today

- local host prerequisite checks
- local x86_64 kernel builds from a prepared Linux source tree
- local libvirt/QEMU direct kernel boot for a dedicated managed domain
- SSH smoke tests against a prepared rootfs profile
- artifact manifest and bundle indexing
- local QEMU gdbstub debug sessions with constrained `debug.*` tools
- discoverable future-provider stubs for remote, provisioning, hardware,
  console, and real-boot workflows

## Quick Start

```bash
git clone git@github.com:randomparity/linux-debug-mcp.git linux-debug-mcp
cd linux-debug-mcp
just setup
uv run python -m pytest
```

See [Installation](docs/installation.md) for direct `uv`, minimal `pip`, host
check, and server smoke-check commands.

## Connect A Client

The server runs over stdio. See [Client Setup](docs/client-setup.md) for Claude
Code and Codex configuration.

## Local Workflow

Use `providers.list` and `host.check_prerequisites` before selecting a workflow.
The implemented end-to-end local examples are documented in
[Tool Reference](docs/tool-reference.md). Host preparation for libvirt/QEMU is
documented in [Fedora Libvirt User Guide](docs/fedora-libvirt-user-guide.md).

## Development

```bash
just test
just lint
```
````

- [ ] **Step 3: Run the terminology check**

Run:

```bash
! rg -n "sprin[t]|Sprin[t]|SPRIN[T]" README.md docs
```

Expected: no matches.

- [ ] **Step 4: Commit**

```bash
git add README.md docs/installation.md docs/client-setup.md docs/tool-reference.md
git commit -m "docs: add project documentation skeleton"
```

## Task 2: Installation Guide

**Files:**
- Modify: `docs/installation.md`
- Modify: `README.md`

- [ ] **Step 1: Document prerequisites**

Replace the skeleton with sections covering:

- `Python`: Python 3.11 or newer, matching `requires-python = ">=3.11"`.
- `uv`: recommended environment and command runner.
- `just`: repository task shortcuts for contributors.
- `make`: required by the local kernel build provider.
- `Optional local workflow tools`: `virsh`, QEMU/libvirt, `ssh`, and `gdb`.
- `Linux source tree`: a prepared checkout with `Kconfig`, `Makefile`, and an
  existing `.config` or per-run build `.config`.
- `Rootfs`: a prepared disk image/profile for boot and SSH workflows; link to
  `docs/fedora-libvirt-user-guide.md`.

- [ ] **Step 2: Document development install**

Add:

```bash
git clone git@github.com:randomparity/linux-debug-mcp.git linux-debug-mcp
cd linux-debug-mcp
just setup
```

Also document the direct equivalent:

```bash
uv venv --allow-existing
uv pip install -e '.[test,dev]'
uv run python -m linux_debug_mcp.dev_setup check-host
```

Explain that `just setup` verifies `uv`, creates or reuses `.venv`, installs
editable `dev` and `test` dependencies, runs host checks, refreshes the secrets
baseline, installs pre-commit hooks, and runs hooks once.

- [ ] **Step 3: Document minimal install**

Add:

```bash
python -m pip install -e '.[test]'
python -m pytest
```

State that this path skips pre-commit setup and the `just setup` host
preparation checks.

- [ ] **Step 4: Document server smoke check**

Add:

```bash
timeout 2 uv run linux-debug-mcp || test $? -eq 124
```

Expected: exit `124` is acceptable because the server stayed running until `timeout` stopped it. Any import, packaging, or immediate startup failure is a real failure.

- [ ] **Step 5: Link from README**

Add a README link to `docs/installation.md` under Quick Start.

- [ ] **Step 6: Verify commands**

Run:

```bash
uv run python -m pytest
timeout 2 uv run linux-debug-mcp || test $? -eq 124
```

Expected: tests pass; server smoke check exits successfully through the timeout condition.

- [ ] **Step 7: Commit**

```bash
git add README.md docs/installation.md
git commit -m "docs: document installation"
```

## Task 3: Claude Code And Codex Client Setup

**Files:**
- Modify: `docs/client-setup.md`
- Modify: `README.md`

- [ ] **Step 1: Document Claude Code setup**

Add a project-scoped command:

```bash
claude mcp add --transport stdio --scope project linux-debug-mcp -- \
  uv --directory /home/dave/src/linux-debug-mcp run linux-debug-mcp
```

Add a user-scoped variant:

```bash
claude mcp add --transport stdio --scope user linux-debug-mcp -- \
  uv --directory /home/dave/src/linux-debug-mcp run linux-debug-mcp
```

Verification:

```bash
claude mcp list
```

Inside Claude Code:

```text
/mcp
```

- [ ] **Step 2: Document Codex CLI setup**

Add the CLI command:

```bash
codex mcp add linux-debug-mcp -- \
  uv --directory /home/dave/src/linux-debug-mcp run linux-debug-mcp
```

Verification:

```bash
codex mcp list
codex mcp get linux-debug-mcp
```

- [ ] **Step 3: Document Codex TOML setup**

Add this example for `~/.codex/config.toml`:

```toml
[mcp_servers.linux-debug-mcp]
command = "uv"
args = ["--directory", "/home/dave/src/linux-debug-mcp", "run", "linux-debug-mcp"]
enabled = true
```

- [ ] **Step 4: Explain path choices**

State that the repository path in the examples must be an absolute path for reliable cross-client startup. If the package is installed into a stable environment, users may set `command` to the absolute `linux-debug-mcp` console script instead.

- [ ] **Step 5: Add safety notes**

Document that this MCP server can run local build, libvirt, SSH, and gdb-related commands through constrained tools. Users should connect it only in workspaces where they intend to expose those workflows to the agent.

- [ ] **Step 6: Link from README**

Add a README link to `docs/client-setup.md`.

- [ ] **Step 7: Verify client command syntax locally**

Run:

```bash
claude mcp add --help | rg -- "--scope"
claude mcp add --help | rg -- "--transport"
codex mcp add --help | rg -- "<NAME>"
codex mcp add --help | rg -- "<COMMAND>"
```

Expected: Claude exposes `--scope` and `--transport`; Codex exposes stdio
command registration through `mcp add <NAME> -- <COMMAND>...`.

- [ ] **Step 8: Commit**

```bash
git add README.md docs/client-setup.md
git commit -m "docs: document mcp client setup"
```

## Task 4: Tool And Workflow Reference

**Files:**
- Modify: `docs/tool-reference.md`
- Modify: `README.md`
- Modify: `docs/fedora-libvirt-user-guide.md`
- Modify: `docs/ppc64le-provider-spike.md`

- [ ] **Step 1: Document discovery tools**

Cover:

- `host.check_prerequisites`
- `providers.list`
- `artifacts.get_manifest`

Include this example:

```json
{
  "tool": "host.check_prerequisites",
  "arguments": {
    "artifact_root": ".linux-debug-mcp/runs",
    "source_path": "/home/dave/src/linux",
    "enable_libvirt_check": true
  }
}
```

- [ ] **Step 2: Document local build, boot, test workflow**

Include:

```json
{
  "tool": "workflow.build_boot_test",
  "arguments": {
    "source_path": "/home/dave/src/linux",
    "build_profile": "x86_64-default",
    "target_profile": "local-qemu",
    "rootfs_profile": "minimal",
    "test_suite": "smoke-basic"
  }
}
```

- [ ] **Step 3: Document local debug workflow**

Include:

```json
{
  "tool": "workflow.build_boot_debug",
  "arguments": {
    "source_path": "/home/dave/src/linux",
    "build_profile": "x86_64-default",
    "target_profile": "local-qemu-debug",
    "rootfs_profile": "minimal",
    "debug_profile": "qemu-gdbstub-default"
  }
}
```

- [ ] **Step 4: Document artifact layout**

Describe:

- build logs under `<artifact-root>/<run-id>/logs/build.log`
- build summaries under `<artifact-root>/<run-id>/summaries/build-summary.json`
- serial and boot logs under `<artifact-root>/<run-id>/logs/`
- smoke output under `<artifact-root>/<run-id>/tests/attempt-NNN/`
- debug artifacts under `<artifact-root>/<run-id>/debug/`
- bundle index under `<artifact-root>/<run-id>/summaries/artifact-bundle.json`

- [ ] **Step 5: Document future-provider stubs**

State that future-provider tools are discoverable for planning and contract validation only. Valid requests return `not_implemented`; malformed requests return `configuration_error`; no remote host, console, provisioning, or hardware-control side effects occur.

- [ ] **Step 6: Link related guides**

Add links:

- `docs/fedora-libvirt-user-guide.md` from tool reference and README.
- `docs/ppc64le-provider-spike.md` from tool reference.

- [ ] **Step 7: Commit**

```bash
git add README.md docs/tool-reference.md docs/fedora-libvirt-user-guide.md docs/ppc64le-provider-spike.md
git commit -m "docs: document mcp tools and workflows"
```

## Task 5: Documentation Verification

**Files:**
- Optional modify: `justfile`

- [ ] **Step 1: Decide whether to add a docs check target**

If this project wants a committed guard, add:

```make
check-docs:
    ! rg -n "sprin[t]|Sprin[t]|SPRIN[T]" README.md docs
```

- [ ] **Step 2: Run final docs verification**

Run:

```bash
! rg -n "sprin[t]|Sprin[t]|SPRIN[T]" README.md docs
uv run python -m pytest
```

Expected: terminology search has no matches and exits successfully through the negated command; tests pass.

- [ ] **Step 3: Review changed docs**

Run:

```bash
git diff -- README.md docs justfile
```

Confirm:

- install instructions include `just setup`, direct `uv`, and minimal `pip` paths.
- Claude Code setup includes project and user scope commands.
- Codex setup includes `codex mcp add` and `~/.codex/config.toml`.
- local workflows identify required host/rootfs/kernel expectations.
- future-provider stubs are not described as executable.
- no development-iteration terminology remains.

- [ ] **Step 4: Commit**

```bash
git add justfile README.md docs
git commit -m "docs: add documentation verification"
```

## Self-Review

- Spec coverage: The plan covers installation, client setup for Claude Code and Codex, implemented MCP tools, workflow examples, host/libvirt links, future-provider boundaries, and terminology cleanup.
- Placeholder scan: The plan uses concrete example paths and a concrete repository URL; there are no unresolved implementation placeholders.
- Type consistency: Tool names and profile names match `src/linux_debug_mcp/server.py`; package and script names match `pyproject.toml`.
