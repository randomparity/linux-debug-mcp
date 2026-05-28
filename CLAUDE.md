# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

`linux-debug-mcp` is a stdio MCP server (FastMCP / `mcp>=1.9`) that exposes Linux kernel build, boot, smoke-test, artifact, and QEMU gdbstub debug workflows to coding agents. Today's implementation is local-only (x86_64 + libvirt/QEMU); ppc64le, remote build, reservation, BMC console, and real-hardware boot exist only as discoverable future-provider stubs.

Architecture spec: `docs/specs/2026-05-22-linux-debug-mcp-architecture-design.md`.
Future-work epics (remote interactive debug, transports, drgn/KDB/KGDB/postmortem tiers): `00-epic-remote-interactive-debug.md` and `01-…08-…md` at repo root.

## Common commands

| Task | Command |
|---|---|
| Full setup (venv, install, host check, pre-commit) | `just setup` |
| Run all tests | `just test` or `uv run python -m pytest` |
| Run one test | `uv run python -m pytest tests/test_server.py::test_name -q` |
| Lint + format check | `just lint` |
| Auto-fix + format | `just format` |
| Host prerequisite check | `just check-host` |
| Server stdio smoke | `timeout 2 uv run linux-debug-mcp \|\| test $? -eq 124` |
| Doc terminology guard | `just check-docs` (forbids "sprint*" in `README.md` and `docs/`, excluding the internal `docs/superpowers/` planning artifacts) |

Python 3.11+. Ruff is the linter/formatter (line length 120, selects `E,F,I,UP,B,SIM`). `ty check src` runs in CI as a **hard-gating** job; type errors block PRs and are also surfaced in the run summary. Do not invoke `mypy` or `pyright`. The hard-fail checks per commit are ruff, the pre-commit hygiene hooks, `detect-secrets`, and `ty`. Pre-commit uses `pre-commit` (not `prek`) with `detect-secrets` against `.secrets.baseline`.

## Architecture

### Tool wiring (`server.py`)

`create_app()` returns a `FastMCP` instance with every tool registered via `@app.tool(name="...")`. Each registration is a thin wrapper that calls a module-level `*_handler()` function and `.model_dump(mode="json")`s the result. Handlers are the unit of testing — tests call them directly with injected providers/profiles, not through MCP.

Entry point: `linux-debug-mcp` console script → `linux_debug_mcp.server:main` → `configure_logging()` + `create_app().run()`.

Default profiles (`x86_64-default`, `local-qemu`, `local-qemu-debug`, `minimal`, `smoke-basic`, `qemu-gdbstub-default`) are constants in `server.py`. The default artifact root is `.linux-debug-mcp/runs` (gitignored).

### Run lifecycle and the manifest invariant

Every workflow creates an `ArtifactStore` run directory `<artifact-root>/<run-id>/` containing fixed subdirs (`inputs logs build target tests debug summaries sensitive`) and a `manifest.json`.

The `RunRequest` inside the manifest is **immutable** once `kernel.create_run` returns. Any later tool that accepts the same profile fields (e.g. `kernel.build`'s `build_profile`, `target.boot`'s `target_profile`/`rootfs_profile`) must either omit them or pass values identical to the recorded manifest — otherwise the handler returns `configuration_error`. This is enforced per step in `server.py`.

Steps (`build`, `boot`, `run_tests`, `debug`, plus `collect`) are **idempotent by run_id + step name**: a re-invocation of a SUCCEEDED step returns the recorded `StepResult` unchanged unless the caller passes the corresponding `force_*` flag. When adding a new step, follow the existing pattern in `kernel_build_handler` / `target_boot_handler`:

1. Load manifest; short-circuit on existing SUCCEEDED/RUNNING result.
2. Acquire the step's file lock (`store.build_lock`, `boot_lock`, `tests_lock`, `debug_lock`; `target.boot` also takes `target_lock(target_ref)` to serialize per-VM).
3. Re-load under the lock and re-check (TOCTOU guard).
4. Write a `RUNNING` `StepResult`, execute the provider, then record a terminal `SUCCEEDED`/`FAILED` result — pass `replace_succeeded=True` only when `force_*` was set.

`_record_terminal_build_result` shows the manifest-lock retry-with-backoff pattern; reuse it for any path where the manifest lock may transiently fail.

### Providers and capabilities

Providers live under `src/linux_debug_mcp/providers/` and are discovered through `ProviderRegistry.with_defaults()`, which loads `built_in_provider_plugin_specs()`. Each `ProviderPluginSpec` produces one or more `ProviderCapability` objects via factories — that is what `providers.list` returns.

- Implemented (`builtins.local`): `local-artifacts`, `local-prereqs`, `local-kernel-build`, `local-libvirt-qemu`, `local-ssh-tests`, `local-qemu-gdbstub`.
- Stubs (`builtins.future-stubs`): remote/reservation/provision/hardware/console/workflow tools. Routed through `_future_stub_handler`, which validates the request against the matching `ProviderRequest` Pydantic contract, picks a provider via `select_future_provider`, and returns `not_implemented` for valid requests / `configuration_error` for malformed ones. Stubs must not open network, serial, or power-control resources.

When adding a tool, also add it to the relevant capability's `operations` list (and `operation_capabilities` if you need per-op overrides), or `providers.list` won't advertise it.

### Domain model and responses

`domain.py` defines the wire types. All `BaseModel`s inherit from `Model` / `ConfigModel`, which set `extra="forbid"` and `validate_assignment=True` — extra fields are a hard error.

Every handler returns a `ToolResponse` built with `ToolResponse.success(...)` or `ToolResponse.failure(category=ErrorCategory.X, ...)`. The `ErrorCategory` enum is the agent-facing taxonomy; pick the most specific value (`CONFIGURATION_ERROR`, `BUILD_FAILURE`, `BOOT_TIMEOUT`, `DEBUG_ATTACH_FAILURE`, `INFRASTRUCTURE_FAILURE`, `NOT_IMPLEMENTED`, …) — do not invent strings.

`suggested_next_actions` is part of the contract; populate it with the literal next tool name (`"artifacts.get_manifest"`, `"debug.start_session"`, …).

### Redaction is mandatory on test/debug paths

Anything that may surface guest output, gdb transcripts, or secret-bearing details must be passed through `Redactor()` before being returned **and** before being persisted to the manifest. The patterns are visible in `target_run_tests_handler` and the `_debug_*` helpers (`_redacted_artifacts`, `redactor.redact_value`, `redactor.redact_text`). Raw gdb transcripts stay on disk under `<run>/debug/` and are referenced by `ArtifactRef`; only redacted snippets go into responses.

`debug.read_memory` is capped at 4096 bytes per call; preserve that cap if you touch the provider.

### Constrained debug surface

The set of allowed debug operations is the hard-coded `SPRINT_4_DEBUG_OPERATIONS` list in `config.py`. `DebugProfile.enabled_operations` may further narrow it. `_ensure_debug_operation_enabled` enforces both layers — call it from any new `debug.*` handler before invoking the provider.

### Path safety

User-supplied paths (kernel source path, artifact root, anything resolved out of a debug session file) must go through `safety/paths.py` (`validate_source_path`, `validate_artifact_root`, `validate_run_id`) or, for debug-session paths, `_require_run_debug_path` in `server.py`, which confines a path under `<run>/debug/`. `PathSafetyError` maps to `CONFIGURATION_ERROR`.

## Design decisions (ADRs)

Record every non-trivial design decision as an ADR before implementing it — especially decisions the spec/roadmap leaves open (layer boundaries, interface/ownership splits, concurrency invariants, anything with viable alternatives).

- Location: `docs/adr/NNNN-short-title.md`, numbered sequentially (`docs/adr/README.md` is the index).
- Format: Status (proposed/accepted/superseded) · Context · Decision · Consequences · **Considered & rejected** (each alternative + why it lost).
- The "Considered & rejected" list is mandatory — it is what stops a decision being relitigated later.
- Link the ADR from the spec/plan it affects; supersede (never delete) an ADR when a decision changes.
- Adversarial review runs against a *decided* design: write/update the ADR first, and feed its rejected-alternatives to the reviewer so rounds don't reopen settled choices. (Review converges on bounded, falsifiable, decided artifacts; an open design question read by a fresh reviewer each round oscillates instead.)

## Tests

`pytest` config in `pyproject.toml` adds `src` to `pythonpath` and targets `tests/`. Handler tests instantiate the handler directly and pass in fakes for providers (`provider=...`) and profile dicts (`target_profiles=...`, `rootfs_profiles=...`, `debug_profiles=...`, `test_suites=...`); use that injection rather than monkey-patching defaults. `test_libvirt_boot_integration.py` and `test_qemu_gdbstub_integration.py` exercise real `virsh`/`gdb` and are skipped without those tools — keep that gating intact.

There is no `conftest.py`; fixtures live inside individual test modules.

## Doc style

Do not use the word "sprint" (or capitalizations) in `README.md` or anywhere under `docs/` — `just check-docs` will fail the build. The internal `docs/superpowers/` planning and spec artifacts are excluded from the guard because they legitimately cite code constants. Historical sprint numbering is preserved only in code constants like `SPRINT_4_DEBUG_OPERATIONS`.
