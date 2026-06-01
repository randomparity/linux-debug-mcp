# Secrets store + backends + global credential redaction — Design

**Status:** Proposed
**Date:** 2026-05-29
**Issue:** #65 (epic #9, split from #17)
**Related:** ADR 0012 (secrets store backends + redaction posture), ADR 0004 (process
identity is an injectable seam — the pattern this follows), `docs/specs/interface-contracts.md`
§3.2 (`secret_refs`), §6 ownership map ("Secret resolution → Hardening (08)"), §8
("No `secret_refs` value is ever resolved to an inline secret in any … log line, or tool output").

## Summary

Replace the placeholder env-only `EnvSecretsResolver` seam with a real **secrets store**
that resolves a transport's `secret_refs` through one of three backends — environment
variable, OS keyring, and an operator-configured external command — and a **global
credential redaction filter** that scrubs resolved secret values (and secret-shaped
key/value pairs) from all log output before it is emitted and from all tool
output/manifest data before it is returned or persisted.

The store is the single choke point where credentials enter the process. No transport
reads a credential directly; the open transaction resolves `secret_refs` and hands the
resolved values to the backend's `attach()`. Every resolved value is registered with a
redaction registry the moment it is produced, so a value that is resolved can never
subsequently appear in a log line, tool response, persisted manifest, session record, or
endpoint URL.

## Goals / Non-goals

### Goals
- A `SecretsBackend` ABC: `get(reference) -> str | None`. Concrete backends: `env`,
  `keyring` (OS keyring), `external` (operator-configured resolver command).
- A `SecretsStore` that implements the existing `SecretsResolver` Protocol
  (`resolve(refs) -> dict[str, str]`, ADR 0004 transport wiring) by dispatching each
  ref to the backend named by its server-side `SecretReference` definition.
- Caller-supplied `secret_refs` are **opaque strings**; the backend, source, and
  required-ness come from server-side `SecretReference` definitions, never from the
  caller. A caller cannot select a backend, read an arbitrary file, or point the store
  at an arbitrary keyring entry.
- A global `SecretRedactionFilter` (a `logging.Filter`) installed in
  `configure_logging()` on the root logger, backed by a `SecretRegistry` of resolved
  values plus the existing `Redactor` key/value patterns.
- Resolved values reach transports only through `Transport.attach(..., secrets=...)`;
  transports never touch `os.environ`, the keyring, or credential files.
- detect-secrets policy extended with BMC/HMC/NovaLink/IPMI out-of-band credential
  patterns via a custom `RegexBasedDetector` plugin; `.secrets.baseline` regenerated.
- Tests prove no resolved secret value appears in logs (including tracebacks), tool
  output, persisted manifest/session JSON, or any endpoint.

### Non-goals
- No credential **storage**: the server never creates accounts, never writes a
  credential to disk, and never persists a password. Repo-file credential sources are
  forbidden (the `file` reference kind is rejected by policy, below).
- No live remote/out-of-band transport consumer: BMC/HMC/NovaLink transports are future
  stubs. This issue ships the seam end-to-end and exercises it via tests; it does not
  add a remote transport.
- IPMI cipher-suite policy and management-plane network policy are out of scope (split
  to their own issues per #65).
- No vendor SDK (Vault, AWS Secrets Manager, …). The `external` backend is a generic
  command adapter; a vendor-specific backend, if ever needed, is a future
  `SecretsBackend` subclass.

## Background

`docs/specs/interface-contracts.md` §3.2 defines `TransportRef.secret_refs: list[str]`
as opaque references "resolved via the Secrets interface (08); never inline." §6 assigns
secret resolution to Hardening (08); §8 makes "no inline secret in any TransportRef, log
line, or tool output" a contract conformance test.

Today `seams/secrets.py` ships `SecretsResolver` (Protocol, `resolve(refs)->dict`) and
`EnvSecretsResolver` (env-only, file/external deferred), wired in `server.py` as
`EnvSecretsResolver([])` and consumed in `coordination/transaction.py` at open() step
(6), where the resolved dict is currently **discarded** — secrets are validated but never
reach `attach()`. `safety/secrets.py` defines `SecretReference{kind,label,reference,required}`
and `SecretReferenceKind = FILE|ENV|EXTERNAL`. `safety/redaction.py` ships `Redactor`
(explicit values + secret-keyword key/value patterns), used today on the test/debug
return paths but not installed as a global logging filter.

## Design

### Two-level interface

**`SecretsBackend` (ABC)** — the per-source primitive the issue calls for:

```python
class SecretsBackend(ABC):
    @property
    @abstractmethod
    def kind(self) -> SecretReferenceKind: ...

    @abstractmethod
    def get(self, reference: SecretReference) -> str | None:
        """Return the secret value, or None if the source has no value for this
        reference. Raising is reserved for backend faults (keyring locked, helper
        command failed); 'absent' is None so the store can apply required-ness
        uniformly. Implementations MUST NOT include any secret value in an exception
        message or log line, and MUST NOT log child-process stdout/stderr."""
```

**`SecretsStore`** implements the existing `SecretsResolver` Protocol so the transport
wiring (`TransportTransaction(secrets=...)`) is unchanged:

```python
class SecretsStore:  # satisfies SecretsResolver
    def __init__(self, definitions: list[SecretReference],
                 backends: dict[SecretReferenceKind, SecretsBackend],
                 registry: SecretRegistry) -> None: ...
    def resolve(self, refs: list[str], *, scope: object | None = None) -> dict[str, str]: ...
```

`resolve(refs, scope)`:
1. Map each ref string to its `SecretReference` definition; unknown ref → `SecretsResolutionError`.
2. Look up the backend for `definition.kind`; no backend registered for that kind →
   `SecretsResolutionError` ("kind not enabled").
3. `value = backend.get(definition)`. If `None` and `definition.required` → error; if
   `None` and optional → skip. An empty-string value is treated as **absent**
   (misconfiguration) — required → error, optional → skip — so an empty credential is
   never silently accepted or registered. Otherwise register the value with the
   `SecretRegistry` under `scope` **before** the value is returned, used, or any further
   IO runs, and add it to the result dict keyed by the ref string.

`scope` is an **eviction handle** the caller owns; values registered under a scope are
deregistered when the caller releases it (below). It is decoupled from `session_id` so
resolution can run before the session id is minted: the open transaction allocates a
scope object at the start of `open()`, passes it to `resolve()`, binds it to the session
on commit, and releases it in close/rollback. `scope=None` registers process-globally
(no eviction) — used only where no owner lifecycle exists.

The `SecretsResolver` **Protocol itself gains the optional keyword-only param** —
`resolve(self, refs: list[str], *, scope: object | None = None) -> dict[str, str]` — so
the transaction (whose `_secrets` is typed as the Protocol) can call `resolve(refs,
scope=...)` and still pass the hard-gating `ty` typecheck. This is a backward-compatible
widening: the bare `resolve(refs)` call site and the existing `_FakeResolver` in
`tests/test_seams_secrets.py` still satisfy the Protocol, but `_FakeResolver` is updated
to accept and ignore `scope` so it remains a faithful stand-in.

Duplicate-definition handling (a ref string defined twice, even cross-kind) is rejected
at construction, preserving the existing `EnvSecretsResolver` invariant (an optional
definition must not silently mask a required one; an env definition must not mask a
file/external one).

### Reference kinds and backends

`SecretReferenceKind` gains `KEYRING`. The mapping:

| kind     | backend                  | source                                                |
|----------|--------------------------|-------------------------------------------------------|
| `env`    | `EnvSecretsBackend`      | `os.environ[reference]`                                |
| `keyring`| `KeyringSecretsBackend`  | OS keyring entry named by `reference`                  |
| `external`| `ExternalSecretsBackend`| operator-configured resolver command; secret on stdout|
| `file`   | *(no backend — rejected)*| repo files forbidden; non-repo file creds deferred    |

- **`EnvSecretsBackend`** — reads `os.environ`. No new dependency.
- **`KeyringSecretsBackend`** — uses the `keyring` library, imported lazily in
  `__init__`; if `keyring` is not installed, construction raises a clear
  `SecretsResolutionError` telling the operator to install the `keyring` extra. `keyring`
  is an **optional** dependency (`linux-debug-mcp[keyring]`) — not forced on the
  local-only baseline that has no keyring-backed transport. `reference` encodes the
  keyring service and username (`service` and `username` split on the first `/`); the
  backend never logs either component.
- **`ExternalSecretsBackend`** — invokes an operator-configured command template (set at
  store construction from server config/env, **never** from caller input). The
  `reference` is a non-secret key/path into the store and is passed as a single argv
  element; the resolved secret is read from the child's **stdout**, never from argv, env,
  or a constructed URL. The backend captures stdout/stderr but **never logs either**;
  stderr is used only to decide success/failure and is discarded. The command runs with
  a timeout; non-zero exit or timeout → `SecretsResolutionError` carrying the command
  name (not its output). The resolved stdout value is registered with the
  `SecretRegistry` before the streams are surfaced to any caller.

`file` is intentionally unsupported: #65 forbids repo files, and a non-repo file backend
(systemd credentials, tmpfs) has no consumer yet. A `file` definition is rejected at
`resolve()` with a message that never reads the file.

### Resolution is centralized in the open transaction

`TransportTransaction.open()` already resolves `channel.secret_refs` at step (6). The
resolved dict — currently discarded — is threaded to the backend via a new keyword-only
parameter:

```python
Transport.attach(self, request, *, cancel, deadline, on_partial, secrets: Mapping[str, str]) -> BackendAttachment
```

`secrets` defaults to an empty mapping. The two live transports (qemu-gdbstub,
serial-local) are loopback and ignore it; a future remote transport reads its credential
from this mapping and from nowhere else. All existing `attach` implementations and test
fakes gain the keyword-only parameter (default `{}`), so positional callers are
unaffected. Centralizing resolution in the transaction (not delegating to each transport)
keeps the no-leak/redaction guarantee enforced in one place. See ADR 0012 for the
rejected per-transport-resolution alternative.

The transaction allocates an **eviction scope** at the start of `open()` (before
`new_session_id()`), passes it to `resolve(refs, scope=...)`, binds it to the session on
commit, and releases it on close/rollback — see the registry lifecycle below for the
release ordering. The scope is the caller-owned handle that decouples registration from
`session_id` (which does not exist yet at resolve time).

### Global redaction

**`SecretRegistry`** — a thread-safe container of known secret values, scoped to the
process. `SecretsStore.resolve()` registers every resolved value. Values are held in
memory only, never persisted.

- **Lifecycle / eviction.** Registration is **scoped to an eviction handle** the caller
  owns (the open transaction's per-`open()` scope, above). `resolve()` records each value
  under its `scope`; the registry reference-counts by value, so a value registered by two
  live scopes survives until both release. The transaction releases the scope **only
  after** the session's close/rollback teardown — including any teardown error logging —
  has fully completed (release is the last action of close/rollback), so a credential
  that appears in a close-time exception traceback is still value-redacted when that
  traceback is logged. This bounds the registry to credentials for currently-open
  sessions (a long-running server does not accumulate every credential ever seen, and the
  per-record redaction cost stays proportional to live secrets, not lifetime
  resolutions), without reopening a leak window on the teardown path. The registry
  exposes a `(version, snapshot)` pair; `version` increments on every add/remove.
- **Read path.** The registry read is a cheap snapshot taken **per log record** (or a
  cached `Redactor` rebuilt only when `version` changed since the last record), so there
  is no add/read race that could format a record with a `Redactor` missing a
  just-registered value: registration in `resolve()` completes before the value is used,
  and the per-record snapshot always reflects the latest `version`.

**`SecretRedactionFilter(logging.Filter)`** — installed **on every handler** (not only on
the root logger) in `configure_logging()`. Handler-attached filters run regardless of a
logger's `propagate` setting, so a module or dependency that attaches its own handler or
sets `propagate=False` cannot bypass redaction; the invariant is "redaction is enforced
at the handler boundary." `configure_logging()` adds the filter to each root handler it
installs and exposes a helper to attach it to any handler the process adds later. For each
record the filter redacts the **fully rendered** record, not just the format string:
- `record.getMessage()` is computed defensively (if `%`-interpolation raises, the filter
  falls back to redacting the raw template plus `repr(args)` rather than letting the
  exception break logging); a non-string `record.msg` is stringified before redaction.
  The redacted text is written back to `record.msg` and `record.args` is cleared.
- If `record.exc_info`/`record.exc_text` or `record.stack_info` is present, the filter
  forces the traceback to render, redacts the rendered text, and stores the redacted
  string in `record.exc_text` (and clears `record.exc_info` so a downstream handler
  cannot re-render the un-redacted traceback). This closes the common
  `log.exception(...)`/`exc_info=True` leak path where a raised exception carries a
  credential.

Redaction covers both registered values and the existing secret-keyword `key=value`
patterns, so a credential is masked whether or not the store has seen it.

### Persistence/return paths

The existing `Redactor` posture (already present in `target_run_tests_handler`, the
`_debug_*` helpers, and `transport_inject_break_handler`) is retained, but the `Redactor`
is now seeded from the `SecretRegistry` snapshot in addition to its patterns, so a
resolved value is masked even when it does not match a `key=value` pattern.

### Hard rule: no credentials in URLs / argv / logs

- Endpoint types are structurally credential-free: `TcpEndpoint` is host+port,
  `UnixSocketEndpoint` is a path; no code constructs a userinfo-bearing URL.
- `ExternalSecretsBackend` reads the secret from child **stdout**; the secret is never an
  argv element or a child env value.
- The redaction filter covers all logging (message + traceback); the registry-seeded
  `Redactor` covers return and persistence.
- A conformance test asserts a resolved value appears in **none** of: captured log output
  (message and traceback), any `ToolResponse` payload, the persisted `manifest.json`, the
  persisted `TransportSession` JSON, or any serialized endpoint.

### detect-secrets policy

A custom `RegexBasedDetector` plugin at `tools/detect_secrets_plugins/oob_credentials.py`
flags out-of-band management credential **assignments with a concrete value** —
BMC/HMC/NovaLink/IPMI password/key patterns of the form `<keyword>\s*[=:]\s*['"]?\S…`
(an assignment to a non-empty value), **not** bare keyword mentions. This keeps the
plugin from flagging prose: a sentence in this spec or the plan that names "ipmi password"
has no `= value` and is ignored, while `bmc_password = "…"` in a fixture is caught. The
baseline regeneration is verified not to flag any `docs/` prose. It is wired into the
pre-commit `detect-secrets` hook via `--custom-plugins
tools/detect_secrets_plugins/oob_credentials.py`, **and the same flag is added to every
other detect-secrets entry point** (any CI invocation and the documented manual/`audit`
command) so the recorded `plugins_used` always matches the plugin set at scan time. The
`.secrets.baseline` is regenerated with the flag. The plugin path is repo-relative and
importable from the repo root (the invocation CWD for all entry points). A test asserts
that invoking detect-secrets **without** `--custom-plugins` no longer reproduces the
baseline (fails loud) rather than silently dropping the OOB patterns.

## Failure contract

All failures raise `SecretsResolutionError` (subclass of `ValueError`, existing). The
message never contains a resolved secret value, a file's contents, or backend output.
Cases: unknown ref, kind not enabled / no backend, `file` kind rejected, required value
absent (including empty-string), duplicate definition (construction), keyring
unavailable, external command non-zero/timeout. In the open transaction, a
`SecretsResolutionError` propagates and the write-ahead transaction rolls back fully
(existing behavior), leaking no guard, lease, record, or backend; the scope's registry
release runs as the last step of rollback (after any rollback error logging) so a
partially-resolved value is neither leaked during teardown nor retained afterward.

At the MCP handler boundary a secret-resolution failure surfaces as
`ToolResponse.failure(category=CONFIGURATION_ERROR, ...)` for caller-fixable problems
(unknown ref, required env unset, kind not enabled) and `INFRASTRUCTURE_FAILURE` for
backend faults (keyring locked, helper command failed); `suggested_next_actions` points
at `"artifacts.get_manifest"`.

## Success criteria (falsifiable)

1. `SecretsStore.resolve(["R"])` returns `{"R": <value>}` for an `env`, `keyring`, and
   `external` definition, with the keyring/external sources faked at the backend seam.
2. `resolve` raises `SecretsResolutionError` (no secret in message) for: unknown ref,
   `file` kind, required-absent, required empty-string, and a kind whose backend is not
   registered.
3. `KeyringSecretsBackend` construction raises a clear, secret-free error when `keyring`
   is not importable.
4. `ExternalSecretsBackend` passes the (non-secret) reference via argv, reads the secret
   from stdout, applies a timeout, never places the resolved value in argv or env, and
   never logs child stdout/stderr.
5. With the `SecretRedactionFilter` installed, a log call that interpolates a registered
   value into a secret-keyword message emits `[REDACTED]` for both the registered value
   and the keyword pair; captured output contains neither.
6. `log.exception(...)` (or `exc_info=True`) where the raised exception carries a
   registered value produces `[REDACTED]` in the captured traceback — no credential in
   `exc_text`.
7. A child logger with `propagate=False` and its own handler still redacts a registered
   value (proving handler-boundary enforcement, not root-only).
8. A handler path that resolves a secret and then persists a manifest/session produces
   JSON in which the resolved value does not appear; the same value does not appear in
   the returned `ToolResponse`.
9. `Transport.attach` receives resolved secrets only via the `secrets` parameter; a fake
   transport asserts it never reads `os.environ`/keyring/files for the credential.
10. Eviction is scope-bound and release-ordered: after the owning scope is released a new
    `Redactor` no longer force-masks the value (eviction), a value still held by another
    live scope is retained (reference counting), and a value referenced in an exception
    raised *during* close is still `[REDACTED]` because release runs after teardown
    logging.
11. The custom detect-secrets plugin flags a planted BMC-password assignment-with-value
    (test fixture) but does **not** flag a prose mention of the same keyword; it is
    present in `.secrets.baseline` `plugins_used`; `pre-commit run detect-secrets` passes <!-- pragma: allowlist secret -->
    on the clean tree, and a run without `--custom-plugins` fails to reproduce the
    baseline.

## Test plan

- Unit: `tests/test_seams_secrets.py` extended for `SecretsStore` + each backend
  (env real; keyring/external faked at the `get` seam; keyring-missing path; external
  argv/stdout/timeout/no-stream-logging; empty-string-absent). Preserve the existing
  `EnvSecretsResolver` behavioral tests by porting them to `SecretsStore` (replace, don't
  deprecate — `EnvSecretsResolver` is removed).
- Unit: `tests/test_redaction_filter.py` for `SecretRegistry` + `SecretRedactionFilter`
  (registered value, key/value pattern, args-interpolation, `getMessage()` failure
  fallback, non-string `msg`, `exc_info`/traceback redaction, eviction on deregister,
  reference-counted multi-session retention, thread-safety smoke).
- Integration (handler-level, no MCP): a transaction open that resolves a faked secret
  and asserts (a) the value reaches `attach` via `secrets`, (b) the value is absent from
  the persisted session JSON and from logs, (c) the value is deregistered after close.
- detect-secrets: a test (or pre-commit run) confirming the OOB plugin flags planted
  patterns, the baseline records the plugin, and omitting `--custom-plugins` fails loud.
