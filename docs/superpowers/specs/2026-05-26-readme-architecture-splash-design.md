# README Architecture Splash — Design

Date: 2026-05-26

## Goal

Rework the project `README.md` so a newcomer can, from the splash screen alone,
understand the abstraction layers behind the server, see how most MCP tools map
to providers, and see which orchestration tools the server registers directly.
The rework includes aspirational design concepts
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

Every README claim — including the rows for future-provider stubs — must be
traceable to code-declared metadata. The rule is *report declared state
faithfully*, not *omit aspiration*: stubs are real, code-registered providers
carrying `implementation_state = stub`, so the README presents them as
discovery-only stubs, never as working features. What is forbidden is describing
any non-implemented capability as functional, implying a delivery timeline, or
inventing providers, operations, or architectures not present in the code.
Verified facts:

- **Registration (per call, not startup):** there is no persistent registry —
  `create_app()` neither builds nor retains one. `ProviderRegistry.with_defaults()`
  is a factory that materializes a fresh registry on demand from provider plugin
  specs (`plugins.py`: `builtins.local`, `builtins.future-stubs`); each spec's
  factories produce `ProviderCapability` records stored in that instance's
  `_providers`, with plugin metadata stored separately. It is invoked only inside
  `list_providers_handler` and `_future_stub_handler`.
- **Discovery:** `providers.list` materializes a default registry and returns its
  capabilities and plugin metadata (families, `implementation_state`, operations,
  architectures, limitations, doc paths). Discovery is the registry's primary
  role today.
- **Dispatch — two distinct paths, verified in `server.py`:**
  - *Implemented local tools* (`kernel.build`, `target.boot`,
    `target.run_tests`, the `debug.*` operations, `workflow.build_boot_debug`):
    the handler instantiates the concrete provider class directly
    (`LocalKernelBuildProvider`, `LibvirtQemuProvider`, `LocalSshTestProvider`,
    `QemuGdbstubProvider`) and calls it. The registry is **not** consulted for
    dispatch, and these tools do not use the `contracts.py` models. Two finer
    cases exist among implemented tools: `host.check_prerequisites`,
    `kernel.create_run`, and `artifacts.get_manifest` are advertised by
    *metadata-only* capabilities (`local-prereqs` / `local-artifacts` are
    `sprint0_capability` records with no provider class) and execute in server
    handlers; `artifacts.collect`, `workflow.build_boot_test`, and
    `providers.list` are not advertised by any provider at all.
  - *Future-stub tools* (`remote.*`, `reservation.*`, `provision.*`,
    `hardware.*`, `console.*`, `workflow.reserve_provision_boot`):
    `_future_stub_handler` validates the payload against a typed `contracts.py`
    model (`ValidationError` → `configuration_error`), then
    `select_future_provider(registry, ...)` resolves the advertised provider,
    then returns `not_implemented`. This is the only request path that consults
    the registry.
- **Registry selection semantics (future-stub path only):**
  `find_by_operation_and_architecture` returns *all* matching providers (a list,
  not one); `select_future_provider` treats zero matches and multiple matches as
  `configuration_error`; selection is unique only after an explicit
  `provider_name` or the ambiguity check. The registry does not guarantee a
  single provider per `(operation, architecture)`.
- **Typed contracts** (`contracts.py`: secret-reference-only fields, safe-label
  validation) are used by the future-stub path only; implemented local tools use
  their own profile/domain models. The registry, typed contracts, and
  registry-mediated selection are the forward-looking machinery for the future
  provider surface — the concrete proof-of-concept → functioning-design boundary.
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
  - debug / local-qemu-gdbstub → `workflow.build_boot_debug` plus 11 `debug.*`
    operations (`QEMU_GDBSTUB_OPERATIONS`, 12 total)
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
- Stub behavior: a request returns `not_implemented` only when it is
  contract-valid *and* resolves to exactly one advertised provider.
  `configuration_error` is returned for contract validation failures and for
  provider-selection failures — unknown `provider_name`, a provider that does not
  advertise the requested operation or architecture, zero matches, or multiple
  matches. No external side effects in either case.
- **Tools not advertised by any provider:** `providers.list`,
  `artifacts.collect`, and `workflow.build_boot_test` are registered directly in
  `server.py` and appear in no provider's `operations` (distinct from the
  metadata-only capabilities above, which *do* advertise their operations).
  (Asymmetry to preserve, not "fix", in docs: `workflow.build_boot_debug` *is*
  advertised by the debug provider, whereas `workflow.build_boot_test` is not
  advertised by any provider.) The README must not claim that every tool maps to
  a provider or routes through the registry.

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
   - A short description covering registration, discovery, and the dispatch
     paths (not one linear chain):
     - **Registration:** provider plugins (`builtins.local`,
       `builtins.future-stubs`) define the capabilities that
       `ProviderRegistry.with_defaults()` materializes on demand (per call, when
       a handler needs discovery or stub selection) — not at server startup.
     - **Discovery:** `providers.list` exposes the registry's capability and
       plugin metadata (families, `implementation_state`, operations,
       architectures).
     - **Implemented concrete-provider dispatch:** the MCP tool's server handler
       calls a concrete provider directly (e.g. `LocalKernelBuildProvider`,
       `LibvirtQemuProvider`, `LocalSshTestProvider`, `QemuGdbstubProvider`); the
       registry is not consulted.
     - **Implemented server-handler / orchestration dispatch:** other implemented
       tools run entirely in server handlers with no provider class — both the
       metadata-only-capability tools (`host.check_prerequisites`,
       `kernel.create_run`, `artifacts.get_manifest`) and the tools advertised by
       no provider (`providers.list`, `artifacts.collect`,
       `workflow.build_boot_test`).
     - **Future-stub dispatch:** the handler validates a typed `contracts.py`
       model, then resolves the advertised provider via the registry
       (`select_future_provider`; unknown provider, unadvertised
       operation/architecture, or zero/multiple matches → `configuration_error`).
       Only a contract-valid, uniquely-resolved request returns
       `not_implemented`. This is the only path that routes through the registry.
   - Must not claim that implemented local tools route through the registry, that
     the registry yields exactly one provider per pair, that every tool maps to a
     provider (some are server orchestration), or that implemented tools use the
     `contracts.py` models.
   - Mermaid `flowchart` showing these relationships, not one straight line:
     - implemented concrete-provider dispatch: `MCP client → MCP tool → concrete
       provider (by family: build / boot / test / debug) → target (local /
       virtual)`
     - implemented server-handler / orchestration dispatch (no provider class):
       `MCP tool → server handler → artifact store / host work`, covering both
       the metadata-only-capability tools (`host.check_prerequisites`,
       `kernel.create_run`, `artifacts.get_manifest`) and the tools advertised by
       no provider (`providers.list`, `artifacts.collect`,
       `workflow.build_boot_test`); label this branch so it is clearly distinct
       from concrete-provider dispatch and does not pass through any provider.
     - future-stub path: `MCP tool → typed contract → provider registry
       (select_future_provider) → not_implemented`
     - discovery + registration edges: plugins (`builtins.local`,
       `builtins.future-stubs`) feeding the registry (dashed `-.->`, labeled
       per-call registration / materialized on demand) and `providers.list`
       reading the registry, so the registry reads as a discovery catalog +
       future-stub dispatch point, not a persistent startup component or a hop on
       the implemented-tool path.

3. **`## Providers`** (new) — two explicitly labeled groups so a reader never
   mistakes a stub for working functionality. Each group is its own table with
   the same columns:

   | Family | Provider | State | Arch | Representative operations | Target |
   |--------|----------|-------|------|---------------------------|--------|

   - **Implemented** — the six implemented providers (Arch: x86_64), per the
     verified list above.
   - **Discovery-only stubs (not yet implemented)** — the seven stub providers
     (Arch: x86_64, ppc64le), per the verified list above. A short note states
     these advertise contracts only: a request returns `not_implemented` only
     when it is contract-valid and resolves to exactly one advertised provider;
     contract validation failures and provider-selection failures (unknown
     provider, unadvertised operation/architecture, zero or multiple matches)
     return `configuration_error`; and they perform no external side effects.
     Note that `external_reserved` is a reserved state with no provider yet.

   - **Orchestration / utility tools** — a short labeled list (not a provider
     row) for `providers.list`, `artifacts.collect`, and
     `workflow.build_boot_test`: implemented MCP tools the server registers
     directly, outside provider capability metadata, so the splash neither hides
     them nor implies they belong to a provider.

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
- Stub rows are allowed precisely because their name, family, operations, `stub`
  state, and architectures are code-declared metadata in `stubs.py`. Forbidden:
  describing stub behavior as functional, implying a delivery timeline, or adding
  any provider/operation/architecture absent from the code.
- Tool-to-provider claims must match each provider's `operations`. Tools with no
  provider (`providers.list`, `artifacts.collect`, `workflow.build_boot_test`)
  must be shown as server-registered orchestration tools, never attributed to a
  provider; trace them to `server.py`.
- Mermaid block must render on GitHub (valid `flowchart` syntax).
- Do not claim ppc64le (or any non-x86_64 arch) works; describe it as
  contract/discovery-only.
- Keep the splash scannable; prefer the table over long prose.

## Success criteria

- A newcomer reading only the README can describe how tools dispatch
  (implemented tools run either via a concrete provider or via a server-handler
  orchestration path, neither through the registry; future-stub tools validate a
  contract and resolve a provider via the registry, returning `not_implemented`),
  understand that the registry is a discovery catalog
  materialized on demand from plugin specs (not a persistent startup component,
  and not a hop on the implemented-tool path), and tell which providers are
  implemented vs aspirational and for which architectures.
- Every provider/operation/state/arch claim is traceable to code-declared
  metadata (implemented providers to their capability factories, stubs to
  `stubs.py`); no claim describes a non-implemented capability as working.
- Implemented tools that have no provider (`providers.list`, `artifacts.collect`,
  `workflow.build_boot_test`) still appear in the splash, labeled as server-
  registered orchestration tools rather than provider operations.
- The Mermaid diagram renders on GitHub.
- No new files; no code changes.
