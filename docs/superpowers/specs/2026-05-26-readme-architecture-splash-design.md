# README Architecture Splash — Design

Date: 2026-05-26

## Goal

Rework the project `README.md` so a newcomer can, from the splash screen alone,
understand the abstraction layers behind the server and see how the MCP tools
are divided among providers. The rework includes aspirational design concepts
(future-provider stubs) and is honest about per-CPU-architecture maturity as the
project moves from proof-of-concept to functioning design. This is not the full
architecture document — that remains in progress — but the README should orient
the reader to the layered model and the implemented-vs-aspirational split.

## Non-goals

- No new documentation files (the deep-dive architecture doc is out of scope).
- No code changes; this is documentation only.
- No restatement of installation, client setup, or tool-by-tool reference
  content already covered in `docs/`.

## Source of truth

The README content must match the code, not aspiration. Verified facts:

- **Layers:** MCP tools → provider registry (`registry.py`,
  `find_by_operation_and_architecture`) → provider plugins (`plugins.py`:
  `builtins.local`, `builtins.future-stubs`) → providers (each with a
  `provider_family` and `implementation_state`) → typed contracts
  (`contracts.py`: secret-reference-only fields, safe-label validation).
- **Implementation states** (`domain.py` `ImplementationState`): `implemented`,
  `stub`, `external_reserved`. Only `implemented` and `stub` are used by any
  provider today; `external_reserved` is enum-only (reserved for future
  externally-hosted providers).
- **Implemented providers** (`builtins.local`), all `architectures=["x86_64"]`:
  - host / local-prereqs → `host.check_prerequisites`
  - artifacts / local-artifacts → `kernel.create_run`, `artifacts.get_manifest`
  - build / local-kernel-build → `kernel.build`
  - boot / local-libvirt-qemu → `target.boot`
  - test / local-ssh-tests → `target.run_tests`
  - debug / local-qemu-gdbstub → 11 `debug.*` operations
- **Future-provider stubs** (`builtins.future-stubs`, `stub` state),
  `architectures=["x86_64", "ppc64le"]`:
  - build / remote-build-stub → `remote.build_kernel`
  - artifacts / remote-artifact-sync-stub → `remote.sync_artifacts`
  - reservation / reservation-stub → `reservation.request_host`,
    `reservation.release_host`
  - provisioning / provisioning-stub → `provision.prepare_target`
  - hardware / hardware-control-stub → `hardware.power_control`
  - console / console-access-stub → `console.open_session`, `console.read`,
    `console.write`
  - boot / real-boot-stub → `hardware.boot_kernel`,
    `workflow.reserve_provision_boot`
- **Architectures:** `KNOWN_ARCHITECTURES = {x86_64, ppc64le}` in the contract
  layer; only `x86_64` has functioning implemented providers. `ppc64le` appears
  only in stub metadata and contracts; design notes in
  `docs/ppc64le-provider-spike.md`.
- Stub behavior: valid requests return `not_implemented`, malformed requests
  return `configuration_error`, no external side effects.

## Decisions

- **Scope:** Rework existing README sections into an architecture-first framing;
  fold the current "What Works Today" content into the new structure. No
  separate architecture doc file.
- **Diagram:** Mermaid `flowchart` (renders on GitHub, editable as text).
- **Terminology:** "providers" / "provider families", matching the codebase and
  the `providers.list` tool. Avoid introducing a parallel "backend" vocabulary.
- **State visibility:** A `State` column in the providers table sets
  expectations (implemented vs stub).
- **Architecture honesty:** An `Arch` column in the table plus a short
  "Architecture support" note stating that x86_64 is the only functioning
  architecture today and ppc64le is contract/discovery-only, linking the
  ppc64le spike.

## Target README structure

1. **Title + one-line description** — unchanged.

2. **`## Architecture`** (new, leads the splash)
   - 3–4 sentences naming the five layers: MCP tools (atomic operations over
     stdio) → provider registry (routes an `(operation, architecture)` pair to
     exactly one provider; surfaced via `providers.list`) → provider plugins
     (`builtins.local`, `builtins.future-stubs`) → providers (one family each,
     with an `implementation_state`) → typed contracts (secret-reference-only
     fields, safe labels).
   - Mermaid `flowchart` showing the layered flow:
     `MCP client → MCP tools → provider registry → provider plugins → providers
     (grouped by family) → targets (local / virtual / remote / physical)`, with
     the two plugin bundles labeled.

3. **`## Providers`** (new) — table grouped by family, implemented rows first:

   | Family | Provider | State | Arch | Representative operations | Target |
   |--------|----------|-------|------|---------------------------|--------|

   Rows for the six implemented providers (Arch: x86_64) and the seven stub
   providers (Arch: x86_64, ppc64le), per the verified lists above. Followed by
   a short note: stubs are discovery/contract-validation only (return
   `not_implemented`, no side effects); `external_reserved` is a reserved state
   with no provider yet.

   - **`### Architecture support`** subsection: x86_64 is the only functioning
     architecture today (all implemented providers are x86_64-only). ppc64le is
     recognized by the contract layer and advertised by future-provider stubs
     but has no functioning implementation; see
     [ppc64le Provider Spike](docs/ppc64le-provider-spike.md). Framed as the
     current proof-of-concept → functioning-design boundary.

4. **`## What Works Today`** — trimmed to a short callout; the providers table
   now carries the per-provider detail. Include one line noting a full
   architecture document is in progress.

5. **`## Quick Start`** — unchanged.

6. **`## Connect A Client`** — unchanged.

7. **`## Local Workflow`** — kept; trimmed only where the new Architecture /
   Providers sections now cover the same ground.

8. **`## Development`** — unchanged.

## Accuracy guardrails

- Provider names, families, operations, states, and architectures must match the
  verified lists above. No invented operations or providers.
- Mermaid block must render on GitHub (valid `flowchart` syntax).
- Do not claim ppc64le (or any non-x86_64 arch) works; describe it as
  contract/discovery-only.
- Keep the splash scannable; prefer the table over long prose.

## Success criteria

- A newcomer reading only the README can name the five layers and tell which
  providers are implemented vs aspirational, and for which architectures.
- Every provider/operation/state/arch claim is traceable to the code.
- The Mermaid diagram renders on GitHub.
- No new files; no code changes.
