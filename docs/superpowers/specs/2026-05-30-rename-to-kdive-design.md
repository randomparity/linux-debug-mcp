# Rename `linux-debug-mcp` → `kdive`

Status: approved
Date: 2026-05-30
Branch: `chore/rename-to-kdive`

## Context

The project is being renamed from `linux-debug-mcp` to **`kdive`** (Kernel Debug,
Inspect, Validate, Explore) ahead of distribution. This is a behavior-preserving
rename: no functional change, no new features. The footprint is ~286 textual
references across code, config, and docs plus the package directory and one
dated spec filename.

PyPI `kdive` is unregistered (a `GET` for its JSON metadata returns 404), so the
single-token distribution name is viable.

## Decisions

1. **Single-token identity.** Import package, distribution/PyPI name, console
   script, and the `FastMCP` server name all become `kdive`.
2. **Clean break on runtime/state identifiers.** On-disk paths, the libvirt
   domain metadata namespace/tag, the rootfs readiness marker, runtime lock and
   registry directories, and the `KDIVE_*` environment variables all switch to
   the new name. Existing VMs, run directories, and rootfs images created under
   the old name become undiscoverable and must be rebuilt — acceptable
   pre-distribution.
3. **Historical planning artifacts stay frozen.** Everything under
   `docs/superpowers/**` (dated plans and specs, ~55 references) is left verbatim
   as a historical record. Only live docs are rewritten.
4. **Repo and remote renames are post-merge manual steps**, captured here as a
   checklist; they cannot be expressed in a branch diff.

## Transformation rules

Three token forms, mutually non-overlapping, each collapsing to `kdive`:

| Form  | From               | To       | Surfaces |
|-------|--------------------|----------|----------|
| snake | `linux_debug_mcp`  | `kdive`  | import package, `python -m …` invocations, coverage source path |
| kebab | `linux-debug-mcp`  | `kdive`  | dist name, CLI, `FastMCP("…")`, on-disk paths, `urn:…:domain`, readiness marker, libvirt metadata tag |
| upper | `LINUX_DEBUG_MCP_*` | `KDIVE_*` | environment variables (see list) |

Because the three forms differ in case and separators, the order of
search-and-replace does not matter for correctness; scope is what matters.

Environment variables (14, all `LINUX_DEBUG_MCP_*` → `KDIVE_*`):
`_CONFIG`, `_DOMAIN`, `_EARLY_SYMBOL`, `_GDBSTUB_ENDPOINT`, `_LIBVIRT_TEST`,
`_LIBVIRT_URI`, `_LIVE_GDBSTUB`, `_READINESS_MARKER`, `_ROOTFS`,
`_ROOTFS_AUTHORIZED_KEY`, `_ROOTFS_RELEASEVER`, `_ROOTFS_SIZE`,
`_ROOTFS_SSH_USER`, `_SOURCE`.

## Scope

### Structural renames (`git mv`, history preserved)
- `src/linux_debug_mcp/` → `src/kdive/` (the entire package; ~85 tracked files).
- `docs/specs/2026-05-22-linux-debug-mcp-architecture-design.md` →
  `docs/specs/2026-05-22-kdive-architecture-design.md`; update the reference in
  `CLAUDE.md` and any ADR/spec cross-links.

### Runtime / state identifiers (clean break)
- Artifact root `.linux-debug-mcp/runs` → `.kdive/runs`; `dev_setup` default
  `.linux-debug-mcp` → `.kdive`.
- Default rootfs path `/var/lib/linux-debug-mcp/rootfs` → `/var/lib/kdive/rootfs`.
- Readiness marker `linux-debug-mcp-ready` → `kdive-ready`.
- libvirt metadata namespace `urn:linux-debug-mcp:domain` → `urn:kdive:domain`;
  metadata tag `linux-debug-mcp` → `kdive`.
- Runtime lock/registry dirs `$XDG_RUNTIME_DIR/linux-debug-mcp/{locks,registry}`
  and `linux-debug-mcp-<uid>` fallback → `kdive` equivalents.
- Tempfile prefix `linux-debug-mcp-registry-` → `kdive-registry-`.
- Registry instance-lock error message string.
- `scripts/build-rootfs.sh`: header comment, `LINUX_DEBUG_MCP_ROOTFS` env var,
  default path, `MARKER`, and the systemd unit `Description`.

### Config / build / CI
- `pyproject.toml`: `[project].name`, `[project.scripts]`, and
  `[tool.coverage.run] source = ["src/kdive"]`.
- `justfile`: `python -m kdive.dev_setup`; the ipmi-guard glob
  `src/kdive/safety/ipmi.py`.
- `.github/workflows/ci.yml`: `--cov=src/kdive`; `.venv/bin/kdive` smoke check.
- Regenerate `uv.lock` with `uv lock` (do not hand-edit).
- Delete `src/linux_debug_mcp.egg-info` (gitignored; regenerates as
  `kdive.egg-info`).

### Docs — live only
Rewrite occurrences in `README.md`, `CLAUDE.md`, `docs/*.md`, `docs/adr/*.md`,
and `docs/specs/*.md` (~28 files).

### Excluded
- `docs/superpowers/**` — left verbatim (~55 references) as historical record.
- Generated/ignored: `.venv`, `.ruff_cache`, `.pytest_cache`, `.hypothesis`,
  `.linux-debug-mcp/` runtime dir, egg-info (deleted, not edited).

## Verification (acceptance gate)

This is a behavior-preserving rename, so the existing test suite is the
regression guard; no new tests are added. The branch is complete when:

1. `rg -i 'linux.debug.mcp'` returns matches **only** under `docs/superpowers/**`.
2. Editable install produces a working `kdive` console script:
   `timeout 2 uv run kdive || test $? -eq 124`.
3. `just lint`, `ty check src`, and the full `just test` are all green.
4. `just check-host` runs via `kdive.dev_setup`.
5. pre-commit / `detect-secrets` run clean against `.secrets.baseline`.

## Post-merge manual checklist (out of branch scope)

1. Rename working directory `~/src/linux-debug-mcp` → `~/src/kdive`.
2. `gh repo rename kdive`; update the `origin` remote URL.
3. Rebuild rootfs (`scripts/build-rootfs.sh`) so guests carry the `kdive-ready`
   marker; re-define any libvirt VMs so they carry the `urn:kdive:domain`
   metadata. Old `.linux-debug-mcp/runs` directories can be deleted.

## Considered & rejected

- **`kdive-mcp` distribution name** (import `kdive`, ship `kdive-mcp`): rejected —
  PyPI `kdive` is free, so a second token adds tracking burden for no benefit.
- **Keep runtime IDs stable for backward compatibility**: rejected — there are no
  external users yet, and a permanent code↔name mismatch is worse maintenance
  debt than rebuilding local state once.
- **Rewrite every historical doc**: rejected — dated plans/specs are a record of
  what the project was called at the time; rewriting them falsifies history for a
  much larger diff.
