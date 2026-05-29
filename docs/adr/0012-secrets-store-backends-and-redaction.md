# ADR 0012: Secrets store backends and global credential redaction

**Status:** Proposed
**Date:** 2026-05-29
**Context layer:** Hardening (08) — secret resolution + redaction, consumed by transport
(Layer 3/4)
**Issue:** #65
**Spec:** `docs/superpowers/specs/2026-05-29-secrets-store-and-redaction-design.md`

## Context

`interface-contracts.md` §3.2 makes a transport's credentials opaque `secret_refs`,
resolved "via the Secrets interface (08); never inline." §6 assigns secret resolution to
Hardening (08); §8 requires that no `secret_ref` ever resolves to an inline secret in any
`TransportRef`, log line, or tool output. The codebase currently ships only a placeholder
env-only resolver (`EnvSecretsResolver`) whose result is discarded by the open
transaction, and a `Redactor` that is applied on some return paths but is not a global
logging filter. This issue makes the secrets interface real and the redaction global.

Several decisions are open: the interface shape, which backends ship, where resolution
happens, how redaction reaches all output, and how to extend detect-secrets. Each has
viable alternatives, recorded below.

## Decision

1. **Two-level interface.** A `SecretsBackend` ABC (`get(reference) -> str | None`) is
   the per-source primitive (the `Secrets` ABC #65 asks for). A `SecretsStore`
   implements the existing `SecretsResolver` Protocol (`resolve(refs) -> dict[str,str]`)
   by dispatching each ref to the backend named by its server-side `SecretReference`
   definition. The transport wiring (`TransportTransaction(secrets=...)`) is unchanged.

2. **Three backends, caller-opaque references.** `env` (live, no new dep), `keyring`
   (optional `keyring` dependency, lazy import), `external` (operator-configured command
   adapter; secret read from child stdout). Backend, source, and required-ness come from
   **server-side** `SecretReference` definitions; the caller supplies only opaque ref
   strings and can neither choose a backend nor point at an arbitrary file/keyring entry.

3. **`file` kind is rejected, not implemented.** #65 forbids repo-file credential
   sources; a non-repo file backend has no consumer. `resolve()` rejects a `file`
   definition without reading the file.

4. **Resolution is centralized in the open transaction.** The transaction resolves
   `secret_refs` once and hands the resolved values to `Transport.attach(..., secrets=)`.
   Transports never read `os.environ`/keyring/files directly.

5. **Global redaction via a process-global registry + a logging filter.** A thread-safe
   `SecretRegistry` records every resolved value at resolution time. A
   `SecretRedactionFilter` (installed on the root logger in `configure_logging()`)
   redacts the fully formatted message of every record. The existing return/persistence
   `Redactor` posture is retained and seeded from the registry snapshot.

6. **detect-secrets extended via a custom `RegexBasedDetector` plugin** for
   BMC/HMC/NovaLink/IPMI credential patterns, wired with `--custom-plugins`; the baseline
   is regenerated.

## Consequences

- `EnvSecretsResolver` is removed and replaced by `SecretsStore` (replace, don't
  deprecate). Its behavioral invariants (env resolution, required/optional, duplicate
  rejection, deferral errors carrying no secret) are ported to `SecretsStore`.
- `SecretReferenceKind` gains `KEYRING`. The kind taxonomy is implementation-internal
  (the contract carries only opaque strings), so no contract change is needed.
- `Transport.attach` gains a keyword-only `secrets: Mapping[str,str]` parameter; the two
  live transports and test fakes ignore it. A future remote transport has a defined
  contract for receiving credentials.
- `keyring` is an optional extra; CI and the local-only baseline do not install it, and
  keyring tests fake the `get` seam so they run without it.
- The `SecretRegistry` holds resolved values in memory for the process lifetime. This is
  the accepted cost of guaranteed masking; values are never persisted.

## Considered & rejected

- **Single-method interface only (`resolve(refs)->dict`), no `SecretsBackend` ABC.**
  Rejected: #65 explicitly asks for a `Secrets` ABC with `get(ref)`, and a per-source
  primitive is what lets env/keyring/external be tested and swapped independently. The
  `SecretsStore`/`SecretsBackend` split gives both — the unchanged resolver Protocol for
  wiring, and the `get` primitive for backends.
- **Per-transport resolution** (each transport calls the Secrets interface itself).
  Rejected: it scatters the no-leak/redaction guarantee across every transport, so one
  forgetful provider leaks. Centralizing in the open transaction makes the registry
  registration and redaction enforceable in one audited place; transports receive only
  resolved values.
- **Caller-supplied `SecretReference` (kind+source on the wire).** Rejected: it would let
  a caller choose the `file` backend, read an arbitrary path, or target an arbitrary
  keyring entry — privilege escalation. Definitions are server-side; the wire carries
  opaque strings only.
- **Ship a Vault/AWS SDK backend.** Rejected as speculative and dependency-heavy with no
  live consumer. The generic `external` command adapter works with any store via its CLI
  (`vault`, `secret-tool`, `aws`); a vendor backend is a future `SecretsBackend` subclass
  if a real need appears.
- **Pass the external secret via argv or a child env var.** Rejected: argv is
  world-readable via `/proc/<pid>/cmdline` and a child env can leak via the child's own
  diagnostics. The secret is read from the child's stdout only; the (non-secret)
  reference key may be an argv element.
- **Force `keyring` as a hard dependency.** Rejected: the local-only baseline has no
  keyring-backed transport, so a hard dep is attack surface and install weight for
  nobody. It is an optional extra with a lazy import and a clear "install the extra"
  error.
- **Implement the `file` kind (read non-repo credential files).** Rejected for now: #65
  forbids repo files and no consumer needs systemd/tmpfs credential files yet; adding it
  would be a speculative backend. Kept as a defined-but-rejected kind so a future issue
  can enable it deliberately.
- **Redact only on return/persistence (no global logging filter).** Rejected per the
  issue decision: a subprocess or provider `log.debug` can emit a credential before any
  return path runs. A root-logger filter is the only place that covers all logging; the
  return/persistence `Redactor` remains as defense in depth.
- **A second pre-commit grep hook instead of a detect-secrets plugin.** Rejected: a
  custom `RegexBasedDetector` is detect-secrets' supported extension point, so the new
  patterns participate in the same baseline/audit workflow rather than being a parallel
  unaudited gate.
