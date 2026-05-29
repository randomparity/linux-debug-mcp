# Secrets store + global credential redaction — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the env-only `EnvSecretsResolver` seam with a real secrets store (env / keyring / external backends) and install a global credential redaction filter on all logging plus the return/persistence paths.

**Architecture:** A `SecretsBackend` ABC (`get(reference)->str|None`) per source; a `SecretsStore` that implements the widened `SecretsResolver` Protocol (`resolve(refs, *, scope=None)`) by dispatching each opaque ref to the backend named by its server-side `SecretReference`. Resolution is centralized in the open transaction, which registers every resolved value in a scope-keyed, reference-counted `SecretRegistry`; a `SecretRedactionFilter` on every log handler (plus the existing `Redactor` posture, now registry-seeded) masks those values in messages, tracebacks, tool output, and persisted JSON. Resolved values reach transports only via `Transport.attach(..., secrets=...)`. detect-secrets gains a custom OOB-credential plugin.

**Tech Stack:** Python 3.11+, pydantic v2, stdlib `logging`/`subprocess`, optional `keyring` extra, detect-secrets `RegexBasedDetector`, pytest.

**Spec:** `docs/superpowers/specs/2026-05-29-secrets-store-and-redaction-design.md` · **ADR:** `docs/adr/0012-secrets-store-backends-and-redaction.md`

**Guardrails (run after every task, must stay green):**
```bash
uv run ruff check && uv run ruff format --check && uv run ty check src && uv run python -m pytest -q
```

---

## Phase 0 — Enabling changes (no behavior change)

### Task 0.1: Add `KEYRING` reference kind

**Files:**
- Modify: `src/linux_debug_mcp/safety/secrets.py`
- Test: `tests/test_safety_secrets_kind.py` (create)

- [ ] **Step 1: Write the failing test**

```python
from linux_debug_mcp.safety.secrets import SecretReference, SecretReferenceKind


def test_keyring_kind_exists_and_constructs():
    ref = SecretReference(kind=SecretReferenceKind.KEYRING, label="bmc", reference="svc/user")
    assert ref.kind is SecretReferenceKind.KEYRING
    assert SecretReferenceKind("keyring") is SecretReferenceKind.KEYRING
```

- [ ] **Step 2: Run it — expect FAIL** (`AttributeError: KEYRING`)

Run: `uv run python -m pytest tests/test_safety_secrets_kind.py -q`

- [ ] **Step 3: Add the enum member**

In `safety/secrets.py`, add to `SecretReferenceKind`:
```python
class SecretReferenceKind(StrEnum):
    FILE = "file"
    ENV = "env"
    EXTERNAL = "external"
    KEYRING = "keyring"
```

- [ ] **Step 4: Run it — expect PASS**

- [ ] **Step 5: Commit**

```bash
git add src/linux_debug_mcp/safety/secrets.py tests/test_safety_secrets_kind.py
git commit -m "feat(secrets): add keyring reference kind"
```

### Task 0.2: Declare the optional `keyring` extra

**Files:**
- Modify: `pyproject.toml`

- [ ] **Step 1: Add the extra** under `[project.optional-dependencies]`:
```toml
keyring = [
  "keyring>=25,<26",
]
```
(Look up the current stable `keyring` major before pinning; adjust the bound if newer.)

- [ ] **Step 2: Verify install resolves without pulling keyring into the base set**

Run: `uv run python -c "import importlib.util as u; print(u.find_spec('keyring'))"`
Expected: `None` (keyring is NOT installed by the default/test env) — confirms backends must lazy-import it and tests must fake the seam.

- [ ] **Step 3: Commit**

```bash
git add pyproject.toml
git commit -m "build(secrets): add optional keyring extra"
```

---

## Phase 1 — Redaction registry + global filter

### Task 1.1: `SecretRegistry` (scope-keyed, reference-counted)

**Files:**
- Create: `src/linux_debug_mcp/safety/secret_registry.py`
- Test: `tests/test_secret_registry.py` (create)

- [ ] **Step 1: Write the failing test**

```python
from linux_debug_mcp.safety.secret_registry import SecretRegistry


def test_register_snapshot_and_version():
    reg = SecretRegistry()
    v0 = reg.version()
    reg.register("hunter2", scope="s1")
    assert "hunter2" in reg.snapshot()
    assert reg.version() > v0


def test_empty_value_is_ignored():
    reg = SecretRegistry()
    reg.register("", scope="s1")
    reg.register(None, scope="s1")  # type: ignore[arg-type]
    assert reg.snapshot() == frozenset()


def test_refcount_retains_until_all_scopes_release():
    reg = SecretRegistry()
    reg.register("shared", scope="a")
    reg.register("shared", scope="b")
    reg.release("a")
    assert "shared" in reg.snapshot()  # still held by b
    reg.release("b")
    assert "shared" not in reg.snapshot()


def test_release_unknown_scope_is_noop():
    reg = SecretRegistry()
    reg.release("never-registered")  # must not raise


def test_scope_none_is_process_global_and_not_evictable():
    reg = SecretRegistry()
    reg.register("global", scope=None)
    reg.release(None)  # releasing the global scope is a no-op
    assert "global" in reg.snapshot()
```

- [ ] **Step 2: Run — expect FAIL** (module missing)

- [ ] **Step 3: Implement**

```python
from __future__ import annotations

import threading


class SecretRegistry:
    """Process-scoped, thread-safe registry of known secret values used to seed the
    redaction filter and the return/persistence `Redactor`. Values are reference-counted
    per eviction scope so a long-running server holds only credentials for live owners.

    Empty/None values are never stored (an empty credential would force-mask everything).
    `scope=None` registers process-globally and is never evicted by `release`."""

    _GLOBAL = object()

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._refcount: dict[str, int] = {}
        self._by_scope: dict[object, list[str]] = {}
        self._version = 0

    def register(self, value: str | None, *, scope: object | None) -> None:
        if not value:
            return
        key = self._GLOBAL if scope is None else scope
        with self._lock:
            self._by_scope.setdefault(key, []).append(value)
            self._refcount[value] = self._refcount.get(value, 0) + 1
            self._version += 1

    def release(self, scope: object | None) -> None:
        if scope is None:
            return  # the global scope is never evicted
        with self._lock:
            values = self._by_scope.pop(scope, [])
            if not values:
                return
            for value in values:
                remaining = self._refcount.get(value, 0) - 1
                if remaining <= 0:
                    self._refcount.pop(value, None)
                else:
                    self._refcount[value] = remaining
            self._version += 1

    def snapshot(self) -> frozenset[str]:
        with self._lock:
            return frozenset(self._refcount)

    def version(self) -> int:
        with self._lock:
            return self._version
```

- [ ] **Step 4: Run — expect PASS**

- [ ] **Step 5: Commit**

```bash
git add src/linux_debug_mcp/safety/secret_registry.py tests/test_secret_registry.py
git commit -m "feat(secrets): scope-keyed reference-counted SecretRegistry"
```

### Task 1.2: `SecretRedactionFilter` (handler-boundary, message + traceback)

**Files:**
- Modify: `src/linux_debug_mcp/safety/redaction.py` (add the filter; keep `Redactor` as-is)
- Test: `tests/test_redaction_filter.py` (create)

- [ ] **Step 1: Write the failing tests**

```python
import logging

from linux_debug_mcp.safety.redaction import REDACTION, SecretRedactionFilter
from linux_debug_mcp.safety.secret_registry import SecretRegistry


def _capture(records):
    handler = logging.Handler()
    handler.emit = lambda record: records.append(handler.format(record))  # type: ignore[method-assign]
    return handler


def test_registered_value_and_keyword_pair_are_redacted():
    reg = SecretRegistry()
    reg.register("hunter2", scope="s")
    records: list[str] = []
    handler = _capture(records)
    handler.addFilter(SecretRedactionFilter(reg))
    logger = logging.getLogger("t1")
    logger.addHandler(handler)
    logger.propagate = False
    logger.error("auth token=%s value hunter2 here", "abc123")
    assert "hunter2" not in records[0]
    assert "abc123" not in records[0]  # token= keyword pair masked
    assert REDACTION in records[0]


def test_non_propagating_child_logger_still_redacts():
    reg = SecretRegistry()
    reg.register("sekret", scope="s")
    records: list[str] = []
    handler = _capture(records)
    handler.addFilter(SecretRedactionFilter(reg))
    child = logging.getLogger("parent.child")
    child.handlers = [handler]
    child.propagate = False
    child.error("leak sekret")
    assert "sekret" not in records[0]


def test_exception_traceback_is_redacted():
    reg = SecretRegistry()
    reg.register("tracecred", scope="s")
    records: list[str] = []
    handler = _capture(records)
    handler.setFormatter(logging.Formatter("%(message)s"))
    handler.addFilter(SecretRedactionFilter(reg))
    logger = logging.getLogger("t3")
    logger.handlers = [handler]
    logger.propagate = False
    try:
        raise RuntimeError("boom tracecred")
    except RuntimeError:
        logger.exception("failed")
    assert "tracecred" not in records[0]


def test_bad_format_string_does_not_break_logging():
    reg = SecretRegistry()
    records: list[str] = []
    handler = _capture(records)
    handler.addFilter(SecretRedactionFilter(reg))
    logger = logging.getLogger("t4")
    logger.handlers = [handler]
    logger.propagate = False
    logger.error("missing arg %s and %s", "only-one")  # would raise in getMessage()
    assert records  # a record was still emitted, no exception escaped


def test_non_string_msg_is_handled():
    reg = SecretRegistry()
    reg.register("objcred", scope="s")
    records: list[str] = []
    handler = _capture(records)
    handler.addFilter(SecretRedactionFilter(reg))
    logger = logging.getLogger("t5")
    logger.handlers = [handler]
    logger.propagate = False
    logger.error({"k": "objcred"})  # non-string msg
    assert "objcred" not in records[0]
```

- [ ] **Step 2: Run — expect FAIL** (`SecretRedactionFilter` missing)

- [ ] **Step 3: Implement the filter** (append to `safety/redaction.py`)

```python
import logging
import traceback

from linux_debug_mcp.safety.secret_registry import SecretRegistry


class SecretRedactionFilter(logging.Filter):
    """Handler-boundary redaction. Attach to every handler (not only the root logger) so a
    module that sets `propagate=False` or owns its handler cannot bypass redaction. Masks
    the fully rendered message AND any exception/stack text against the registry snapshot
    plus the `Redactor` key/value patterns. Caches a `Redactor`, rebuilding only when the
    registry version changes."""

    def __init__(self, registry: SecretRegistry) -> None:
        super().__init__()
        self._registry = registry
        self._cached_version = -1
        self._redactor = Redactor()

    def _current(self) -> Redactor:
        version = self._registry.version()
        if version != self._cached_version:
            self._redactor = Redactor(list(self._registry.snapshot()))
            self._cached_version = version
        return self._redactor

    def filter(self, record: logging.LogRecord) -> bool:
        redactor = self._current()
        try:
            message = record.getMessage()
        except Exception:  # bad %-formatting must never break logging
            message = f"{record.msg!r} args={record.args!r}"
        record.msg = redactor.redact_text(message if isinstance(message, str) else str(message))
        record.args = ()
        if record.exc_info:
            record.exc_text = "".join(traceback.format_exception(*record.exc_info))
            record.exc_info = None
        if record.exc_text:
            record.exc_text = redactor.redact_text(record.exc_text)
        if record.stack_info:
            record.stack_info = redactor.redact_text(record.stack_info)
        return True
```

- [ ] **Step 4: Run — expect PASS**

- [ ] **Step 5: Commit**

```bash
git add src/linux_debug_mcp/safety/redaction.py tests/test_redaction_filter.py
git commit -m "feat(secrets): handler-boundary SecretRedactionFilter"
```

### Task 1.3: Install the filter in `configure_logging`; expose a process registry

**Files:**
- Modify: `src/linux_debug_mcp/logging.py`
- Test: `tests/test_logging_filter_install.py` (create)

- [ ] **Step 1: Write the failing test**

```python
import io
import logging

from linux_debug_mcp.logging import SECRET_REGISTRY, attach_redaction_filter, configure_logging
from linux_debug_mcp.safety.redaction import REDACTION, SecretRedactionFilter


def test_configure_logging_attaches_filter_to_root_handlers():
    configure_logging("INFO")
    root = logging.getLogger()
    assert root.handlers, "configure_logging must install at least one handler"
    assert all(
        any(isinstance(f, SecretRedactionFilter) for f in h.filters) for h in root.handlers
    )


def test_attach_redaction_filter_redacts_on_a_controlled_handler():
    # Avoid basicConfig/capfd fragility: drive the installed filter on a buffer handler.
    SECRET_REGISTRY.register("rootcred", scope="install-test")
    try:
        buffer = io.StringIO()
        handler = logging.StreamHandler(buffer)
        handler.setFormatter(logging.Formatter("%(message)s"))
        attach_redaction_filter_logger = logging.getLogger("install.controlled")
        attach_redaction_filter_logger.handlers = [handler]
        attach_redaction_filter_logger.propagate = False
        attach_redaction_filter(attach_redaction_filter_logger)
        attach_redaction_filter_logger.info("value rootcred")
        out = buffer.getvalue()
        assert "rootcred" not in out
        assert REDACTION in out
    finally:
        SECRET_REGISTRY.release("install-test")
```

- [ ] **Step 2: Run — expect FAIL** (`SECRET_REGISTRY` missing / no filter)

- [ ] **Step 3: Implement**

```python
from __future__ import annotations

import logging

from linux_debug_mcp.safety.redaction import SecretRedactionFilter
from linux_debug_mcp.safety.secret_registry import SecretRegistry

SECRET_REGISTRY = SecretRegistry()


def configure_logging(level: str = "INFO") -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    attach_redaction_filter(logging.getLogger())


def attach_redaction_filter(logger: logging.Logger) -> None:
    """Attach the secret-redaction filter to every handler on `logger`, idempotently."""
    for handler in logger.handlers:
        if not any(isinstance(f, SecretRedactionFilter) for f in handler.filters):
            handler.addFilter(SecretRedactionFilter(SECRET_REGISTRY))
```

- [ ] **Step 4: Run — expect PASS**

- [ ] **Step 5: Commit**

```bash
git add src/linux_debug_mcp/logging.py tests/test_logging_filter_install.py
git commit -m "feat(secrets): install redaction filter in configure_logging"
```

---

## Phase 2 — Backends + SecretsStore (replaces EnvSecretsResolver)

### Task 2.1: `SecretsBackend` ABC + `EnvSecretsBackend`

**Files:**
- Modify: `src/linux_debug_mcp/seams/secrets.py`
- Test: `tests/test_seams_secrets.py` (extend)

- [ ] **Step 1: Write the failing test**

```python
from linux_debug_mcp.safety.secrets import SecretReference, SecretReferenceKind
from linux_debug_mcp.seams.secrets import EnvSecretsBackend, SecretsBackend


def test_env_backend_is_a_backend_and_reads_env(monkeypatch):
    monkeypatch.setenv("MY_TOKEN", "s3cr3t")
    backend = EnvSecretsBackend()
    assert isinstance(backend, SecretsBackend)
    assert backend.kind is SecretReferenceKind.ENV
    ref = SecretReference(kind=SecretReferenceKind.ENV, label="t", reference="MY_TOKEN")
    assert backend.get(ref) == "s3cr3t"


def test_env_backend_absent_is_none(monkeypatch):
    monkeypatch.delenv("ABSENT", raising=False)
    ref = SecretReference(kind=SecretReferenceKind.ENV, label="t", reference="ABSENT")
    assert EnvSecretsBackend().get(ref) is None
```

- [ ] **Step 2: Run — expect FAIL**

- [ ] **Step 3: Implement** (add to `seams/secrets.py`, keep imports)

```python
import os
from abc import ABC, abstractmethod

from linux_debug_mcp.safety.secrets import SecretReference, SecretReferenceKind


class SecretsBackend(ABC):
    @property
    @abstractmethod
    def kind(self) -> SecretReferenceKind: ...

    @abstractmethod
    def get(self, reference: SecretReference) -> str | None:
        """Return the secret value, or None if the source has no value. Raise
        SecretsResolutionError only on backend faults. Never include a secret value in an
        exception/log message; never log child-process streams."""


class EnvSecretsBackend(SecretsBackend):
    @property
    def kind(self) -> SecretReferenceKind:
        return SecretReferenceKind.ENV

    def get(self, reference: SecretReference) -> str | None:
        return os.environ.get(reference.reference)
```

- [ ] **Step 4: Run — expect PASS**

- [ ] **Step 5: Commit**

```bash
git add src/linux_debug_mcp/seams/secrets.py tests/test_seams_secrets.py
git commit -m "feat(secrets): SecretsBackend ABC + EnvSecretsBackend"
```

### Task 2.2: `KeyringSecretsBackend` (lazy import, optional dep)

**Files:**
- Modify: `src/linux_debug_mcp/seams/secrets.py`
- Test: `tests/test_seams_secrets.py` (extend)

- [ ] **Step 1: Write the failing tests**

```python
import sys

import pytest

from linux_debug_mcp.seams.secrets import KeyringSecretsBackend, SecretsResolutionError


def test_keyring_backend_missing_lib_raises_secret_free(monkeypatch):
    # Simulate keyring not installed: force the import to fail.
    monkeypatch.setitem(sys.modules, "keyring", None)
    with pytest.raises(SecretsResolutionError) as exc:
        KeyringSecretsBackend()
    assert "keyring" in str(exc.value).lower()


def test_keyring_backend_reads_via_injected_getter():
    # Inject the keyring get_password seam so the test runs without the library.
    calls = {}

    def fake_get(service, username):
        calls["args"] = (service, username)
        return "kr-secret"

    backend = KeyringSecretsBackend(get_password=fake_get)
    from linux_debug_mcp.safety.secrets import SecretReference, SecretReferenceKind

    ref = SecretReference(kind=SecretReferenceKind.KEYRING, label="bmc", reference="svc/user")
    assert backend.get(ref) == "kr-secret"
    assert calls["args"] == ("svc", "user")
```

- [ ] **Step 2: Run — expect FAIL**

- [ ] **Step 3: Implement**

```python
from collections.abc import Callable


class KeyringSecretsBackend(SecretsBackend):
    """OS keyring backend. `keyring` is an optional extra imported lazily; tests inject
    `get_password` so they run without the library. `reference` is `service/username`
    (split on the first `/`)."""

    def __init__(self, *, get_password: Callable[[str, str], str | None] | None = None) -> None:
        if get_password is None:
            try:
                import keyring  # noqa: PLC0415 (lazy: optional extra)
            except ImportError as exc:
                raise SecretsResolutionError(
                    "keyring backend requires the 'keyring' extra: pip install linux-debug-mcp[keyring]"
                ) from exc
            get_password = keyring.get_password
        self._get_password = get_password

    @property
    def kind(self) -> SecretReferenceKind:
        return SecretReferenceKind.KEYRING

    def get(self, reference: SecretReference) -> str | None:
        service, _, username = reference.reference.partition("/")
        if not service or not username:
            raise SecretsResolutionError(
                f"keyring reference {reference.label!r} must be 'service/username'"
            )
        try:
            return self._get_password(service, username)
        except Exception as exc:  # keyring backend fault — never include the value
            raise SecretsResolutionError(f"keyring lookup failed for {reference.label!r}") from exc
```

- [ ] **Step 4: Run — expect PASS**

- [ ] **Step 5: Commit**

```bash
git add src/linux_debug_mcp/seams/secrets.py tests/test_seams_secrets.py
git commit -m "feat(secrets): KeyringSecretsBackend with lazy optional import"
```

### Task 2.3: `ExternalSecretsBackend` (command adapter, stdout-only)

**Files:**
- Modify: `src/linux_debug_mcp/seams/secrets.py`
- Test: `tests/test_seams_secrets.py` (extend)

- [ ] **Step 1: Write the failing tests**

```python
from linux_debug_mcp.seams.secrets import ExternalSecretsBackend


def _ref(reference="kv/bmc"):
    from linux_debug_mcp.safety.secrets import SecretReference, SecretReferenceKind

    return SecretReference(kind=SecretReferenceKind.EXTERNAL, label="bmc", reference=reference)


def test_external_reads_stdout_and_passes_reference_via_argv():
    seen = {}

    def fake_run(argv, timeout):
        seen["argv"] = argv
        seen["timeout"] = timeout
        return 0, "ext-secret\n", ""

    backend = ExternalSecretsBackend(command=["helper"], runner=fake_run, timeout=5.0)
    assert backend.get(_ref("kv/bmc")) == "ext-secret"  # stdout, trailing newline stripped
    assert seen["argv"] == ["helper", "kv/bmc"]  # reference is the final argv element
    assert seen["timeout"] == 5.0


def test_external_nonzero_exit_raises_without_output():
    def fake_run(argv, timeout):
        return 3, "should-not-leak", "stderr-should-not-leak"

    backend = ExternalSecretsBackend(command=["helper"], runner=fake_run, timeout=5.0)
    import pytest

    with pytest.raises(SecretsResolutionError) as exc:
        backend.get(_ref())
    assert "should-not-leak" not in str(exc.value)
    assert "stderr-should-not-leak" not in str(exc.value)


def test_external_timeout_raises():
    import subprocess

    def fake_run(argv, timeout):
        raise subprocess.TimeoutExpired(cmd=argv, timeout=timeout)

    backend = ExternalSecretsBackend(command=["helper"], runner=fake_run, timeout=0.1)
    import pytest

    with pytest.raises(SecretsResolutionError):
        backend.get(_ref())
```

- [ ] **Step 2: Run — expect FAIL**

- [ ] **Step 3: Implement**

```python
import subprocess


class ExternalSecretsBackend(SecretsBackend):
    """Operator-configured resolver command. The (non-secret) reference is the final argv
    element; the secret is read from the child's stdout. stderr is used only to decide
    success and is never logged or surfaced. `runner` is an injectable seam: it returns
    `(returncode, stdout, stderr)` and may raise `subprocess.TimeoutExpired`."""

    def __init__(
        self,
        *,
        command: list[str],
        runner: Callable[[list[str], float], tuple[int, str, str]] | None = None,
        timeout: float = 10.0,
    ) -> None:
        if not command:
            raise SecretsResolutionError("external secrets command must be non-empty")
        self._command = list(command)
        self._timeout = timeout
        self._runner = runner or self._default_runner

    @staticmethod
    def _default_runner(argv: list[str], timeout: float) -> tuple[int, str, str]:
        proc = subprocess.run(  # noqa: S603 (argv list, no shell; reference is non-secret)
            argv, capture_output=True, text=True, timeout=timeout, check=False
        )
        return proc.returncode, proc.stdout, proc.stderr

    @property
    def kind(self) -> SecretReferenceKind:
        return SecretReferenceKind.EXTERNAL

    def get(self, reference: SecretReference) -> str | None:
        argv = [*self._command, reference.reference]
        try:
            returncode, stdout, _stderr = self._runner(argv, self._timeout)
        except subprocess.TimeoutExpired as exc:
            raise SecretsResolutionError(
                f"external secrets command timed out for {reference.label!r}"
            ) from exc
        if returncode != 0:
            raise SecretsResolutionError(
                f"external secrets command failed ({self._command[0]}) for {reference.label!r}"
            )
        value = stdout.strip("\n")
        return value or None
```

- [ ] **Step 4: Run — expect PASS**

- [ ] **Step 5: Commit**

```bash
git add src/linux_debug_mcp/seams/secrets.py tests/test_seams_secrets.py
git commit -m "feat(secrets): ExternalSecretsBackend command adapter (stdout-only)"
```

### Task 2.4: `SecretsStore` + widen Protocol; remove `EnvSecretsResolver`

**Files:**
- Modify: `src/linux_debug_mcp/seams/secrets.py` (add `SecretsStore`; widen `SecretsResolver`; delete `EnvSecretsResolver`)
- Modify: `tests/test_seams_secrets.py` (port `EnvSecretsResolver` tests to `SecretsStore`; update `_FakeResolver`)
- Modify: `src/linux_debug_mcp/server.py` (`EnvSecretsResolver` import + `:5825` wiring → built in Task 4.1; for now build an env-only store inline to keep green)

- [ ] **Step 1: Widen the Protocol**

In `seams/secrets.py`:
```python
@runtime_checkable
class SecretsResolver(Protocol):
    def resolve(self, refs: list[str], *, scope: object | None = None) -> dict[str, str]: ...
```

- [ ] **Step 2: Write the failing tests** (replace the `EnvSecretsResolver` tests; keep the behavioral cases)

```python
from linux_debug_mcp.safety.secret_registry import SecretRegistry
from linux_debug_mcp.safety.secrets import SecretReference, SecretReferenceKind
from linux_debug_mcp.seams.secrets import (
    EnvSecretsBackend,
    SecretsResolutionError,
    SecretsResolver,
    SecretsStore,
)


def _store(defs, *, registry=None):
    return SecretsStore(
        definitions=defs,
        backends={SecretReferenceKind.ENV: EnvSecretsBackend()},
        registry=registry or SecretRegistry(),
    )


def test_store_satisfies_protocol():
    assert isinstance(_store([]), SecretsResolver)


def test_resolves_env_and_registers_value(monkeypatch):
    monkeypatch.setenv("MY_TOKEN", "s3cr3t")
    reg = SecretRegistry()
    store = _store(
        [SecretReference(kind=SecretReferenceKind.ENV, label="t", reference="MY_TOKEN")],
        registry=reg,
    )
    assert store.resolve(["MY_TOKEN"], scope="sess") == {"MY_TOKEN": "s3cr3t"}
    assert "s3cr3t" in reg.snapshot()
    reg.release("sess")
    assert "s3cr3t" not in reg.snapshot()


def test_unknown_reference_raises():
    with pytest.raises(SecretsResolutionError):
        _store([]).resolve(["nope"])


def test_kind_without_backend_raises():
    store = SecretsStore(
        definitions=[SecretReference(kind=SecretReferenceKind.KEYRING, label="k", reference="s/u")],
        backends={},  # no keyring backend registered
        registry=SecretRegistry(),
    )
    with pytest.raises(SecretsResolutionError) as exc:
        store.resolve(["s/u"])
    assert "s/u" not in str(exc.value) or "not enabled" in str(exc.value)


def test_file_kind_is_rejected_without_reading(tmp_path):
    secret_file = tmp_path / "key"
    secret_file.write_text("TOP-SECRET-VALUE", encoding="utf-8")
    store = SecretsStore(
        definitions=[SecretReference(kind=SecretReferenceKind.FILE, label="f", reference=str(secret_file))],
        backends={SecretReferenceKind.ENV: EnvSecretsBackend()},
        registry=SecretRegistry(),
    )
    with pytest.raises(SecretsResolutionError) as exc:
        store.resolve([str(secret_file)])
    assert "TOP-SECRET-VALUE" not in str(exc.value)


def test_missing_required_raises(monkeypatch):
    monkeypatch.delenv("ABSENT_VAR", raising=False)
    store = _store([SecretReference(kind=SecretReferenceKind.ENV, label="t", reference="ABSENT_VAR")])
    with pytest.raises(SecretsResolutionError):
        store.resolve(["ABSENT_VAR"])


def test_empty_required_is_absent(monkeypatch):
    monkeypatch.setenv("EMPTY_VAR", "")
    store = _store([SecretReference(kind=SecretReferenceKind.ENV, label="t", reference="EMPTY_VAR")])
    with pytest.raises(SecretsResolutionError):
        store.resolve(["EMPTY_VAR"])


def test_missing_optional_is_skipped(monkeypatch):
    monkeypatch.delenv("OPT_VAR", raising=False)
    store = _store(
        [SecretReference(kind=SecretReferenceKind.ENV, label="o", reference="OPT_VAR", required=False)]
    )
    assert store.resolve(["OPT_VAR"]) == {}


def test_duplicate_definition_rejected_at_construction():
    with pytest.raises(SecretsResolutionError):
        _store(
            [
                SecretReference(kind=SecretReferenceKind.ENV, label="a", reference="DUP", required=True),
                SecretReference(kind=SecretReferenceKind.ENV, label="b", reference="DUP", required=False),
            ]
        )
```

Update `_FakeResolver.resolve` to `def resolve(self, refs, *, scope=None):`.

- [ ] **Step 3: Run — expect FAIL** (`SecretsStore` missing)

- [ ] **Step 4: Implement `SecretsStore`** (and delete `EnvSecretsResolver`)

```python
class SecretsStore:
    """Implements `SecretsResolver` by dispatching each opaque ref to the backend named by
    its server-side `SecretReference`. The caller never selects a backend. Every resolved
    value is registered with the `SecretRegistry` under `scope` before it is returned."""

    def __init__(
        self,
        *,
        definitions: list[SecretReference],
        backends: dict[SecretReferenceKind, SecretsBackend],
        registry: SecretRegistry,
    ) -> None:
        by_reference: dict[str, SecretReference] = {}
        for definition in definitions:
            if definition.reference in by_reference:
                raise SecretsResolutionError(
                    f"duplicate secret reference: {definition.reference}; resolution would be "
                    "order-dependent (requiredness/kind could be silently overridden)"
                )
            by_reference[definition.reference] = definition
        self._by_reference = by_reference
        self._backends = dict(backends)
        self._registry = registry

    def resolve(self, refs: list[str], *, scope: object | None = None) -> dict[str, str]:
        resolved: dict[str, str] = {}
        for ref in refs:
            definition = self._by_reference.get(ref)
            if definition is None:
                raise SecretsResolutionError(f"unknown secret reference: {ref}")
            if definition.kind is SecretReferenceKind.FILE:
                raise SecretsResolutionError(
                    f"file-backed secret {definition.label!r} is not supported "
                    "(repo files are forbidden); use env/keyring/external"
                )
            backend = self._backends.get(definition.kind)
            if backend is None:
                raise SecretsResolutionError(
                    f"{definition.kind} secret backend is not enabled for {definition.label!r}"
                )
            value = backend.get(definition)
            if not value:  # None or empty == absent
                if definition.required:
                    raise SecretsResolutionError(f"required secret not set: {definition.label!r}")
                continue
            self._registry.register(value, scope=scope)
            resolved[ref] = value
        return resolved
```
Remove the `EnvSecretsResolver` class and its now-unused `os`/import lines only if unused.

- [ ] **Step 5: Keep `server.py` green** — replace the `EnvSecretsResolver([])` wiring with an inline env-only store using the process registry (final wiring is Task 4.1):
```python
from linux_debug_mcp.logging import SECRET_REGISTRY
from linux_debug_mcp.seams.secrets import EnvSecretsBackend, SecretsStore
...
secrets=SecretsStore(
    definitions=[],
    backends={SecretReferenceKind.ENV: EnvSecretsBackend()},
    registry=SECRET_REGISTRY,
),
```
Delete the `from linux_debug_mcp.seams.secrets import EnvSecretsResolver` import.

- [ ] **Step 6: Run full suite — expect PASS** (`uv run python -m pytest -q`)

- [ ] **Step 7: Commit**

```bash
git add src/linux_debug_mcp/seams/secrets.py tests/test_seams_secrets.py src/linux_debug_mcp/server.py
git commit -m "feat(secrets): SecretsStore resolver replacing EnvSecretsResolver"
```

---

## Phase 3 — Thread resolved secrets into transports + scope eviction

### Task 3.1: Add `secrets` to the `Transport.attach` contract + impls + fake

**Files:**
- Modify: `src/linux_debug_mcp/transport/base.py` (ABC `attach`)
- Modify: `src/linux_debug_mcp/transport/serial_local.py`, `src/linux_debug_mcp/transport/qemu_gdbstub.py`
- Modify: `tests/_layer4_fakes.py` (the `attach` fake)
- Test: `tests/test_transport_attach_secrets.py` (create)

- [ ] **Step 1: Write the failing test** (fake captures the secrets it received)

```python
import threading

from linux_debug_mcp.transport.base import BackendAttachment


def test_attach_receives_secrets_via_parameter():
    from _layer4_fakes import FakeQemuTransport, make_open_request

    captured = {}
    transport = FakeQemuTransport(on_attach_secrets=lambda s: captured.update(s))
    request = make_open_request()
    transport.attach(
        request,
        cancel=threading.Event(),
        deadline=0.0,
        on_partial=lambda *_: None,
        secrets={"R": "cred"},
    )
    assert captured == {"R": "cred"}
```
(If `make_open_request`/constructor hooks do not exist in `_layer4_fakes.py`, add a minimal `on_attach_secrets` callback param to the fake and a small request builder mirroring the existing fixtures.)

- [ ] **Step 2: Run — expect FAIL** (`attach() got unexpected keyword 'secrets'`)

- [ ] **Step 3: Implement** — add `secrets: Mapping[str, str] = MappingProxyType({})` as a keyword-only param to:
  - `Transport.attach` (ABC, `transport/base.py`) — import `MappingProxyType` from `types` (already imported) and `Mapping` (already imported); update the docstring to state credentials arrive only here.
  - `serial_local.py` `attach` (still raises `NotImplementedError`; just accept the param).
  - `qemu_gdbstub.py` transport `attach` (loopback; accepts and ignores `secrets`).
  - `_layer4_fakes.py` `attach` (accept `secrets`; if `on_attach_secrets` set, call it).

Example ABC change:
```python
@abstractmethod
def attach(
    self,
    request: OpenRequest,
    *,
    cancel: threading.Event,
    deadline: float,
    on_partial: Callable[[str, object], None],
    secrets: Mapping[str, str] = MappingProxyType({}),
) -> BackendAttachment: ...
```

- [ ] **Step 4: Run full suite — expect PASS**

- [ ] **Step 5: Commit**

```bash
git add src/linux_debug_mcp/transport/ tests/_layer4_fakes.py tests/test_transport_attach_secrets.py
git commit -m "feat(secrets): thread resolved secrets into Transport.attach"
```

### Task 3.2: Transaction resolves with a scope, passes secrets to attach, releases on teardown

**Files:**
- Modify: `src/linux_debug_mcp/coordination/transaction.py`
- Test: `tests/test_transaction_secrets_scope.py` (create) — handler/transaction-level, injected fakes

- [ ] **Step 1: Write the failing tests**

**Prerequisite helper extension (done in this task's Step 3):** extend `tests/_layer4_fakes.py`:
- `FakeQemuTransport.__init__(self, *, on_attach_secrets=None)` stores the callback; its
  `attach(..., secrets)` calls `on_attach_secrets(dict(secrets))` when set.
- `build_txn(transport, *, registry, secrets=None, secret_registry=None, secret_refs=())`
  threads `secrets`/`secret_registry` into `TransportTransaction` and stamps `secret_refs`
  onto the authoritative channel the admission handle returns (so `open()` resolves them).
- A module-level `LEAK = "LEAKME-9f3"` test credential and a one-value fake store factory.

```python
from linux_debug_mcp.safety.secret_registry import SecretRegistry
from linux_debug_mcp.safety.secrets import SecretReference, SecretReferenceKind
from linux_debug_mcp.seams.secrets import SecretsStore


class _OneSecretBackend:
    @property
    def kind(self) -> SecretReferenceKind:
        return SecretReferenceKind.EXTERNAL

    def get(self, reference: SecretReference) -> str | None:
        return "LEAKME-9f3"


def _one_secret_store(registry: SecretRegistry) -> SecretsStore:
    return SecretsStore(
        definitions=[SecretReference(kind=SecretReferenceKind.EXTERNAL, label="c", reference="cred-ref")],
        backends={SecretReferenceKind.EXTERNAL: _OneSecretBackend()},
        registry=registry,
    )


def test_open_passes_resolved_secret_to_attach_and_registers_under_scope(tmp_path):
    from _layer4_fakes import FakeQemuTransport, build_txn, make_open_request

    from linux_debug_mcp.coordination.registry import SessionRegistry

    secret_registry = SecretRegistry()
    captured: dict[str, str] = {}
    transport = FakeQemuTransport(on_attach_secrets=captured.update)
    reg = SessionRegistry(directory=tmp_path)
    txn, admission = build_txn(
        transport,
        registry=reg,
        secrets=_one_secret_store(secret_registry),
        secret_registry=secret_registry,
        secret_refs=("cred-ref",),
    )
    txn.open(make_open_request())
    assert captured == {"cred-ref": "LEAKME-9f3"}
    assert "LEAKME-9f3" in secret_registry.snapshot()


def test_close_releases_scope_and_evicts_value(tmp_path):
    from _layer4_fakes import FakeQemuTransport, build_txn, make_open_request

    from linux_debug_mcp.coordination.registry import SessionRegistry

    secret_registry = SecretRegistry()
    reg = SessionRegistry(directory=tmp_path)
    txn, admission = build_txn(
        FakeQemuTransport(),
        registry=reg,
        secrets=_one_secret_store(secret_registry),
        secret_registry=secret_registry,
        secret_refs=("cred-ref",),
    )
    session = txn.open(make_open_request())
    txn.close(session.session_id)
    assert "LEAKME-9f3" not in secret_registry.snapshot()


def test_rollback_releases_scope(tmp_path):
    import pytest

    from _layer4_fakes import FakeQemuTransport, build_txn, make_open_request

    from linux_debug_mcp.coordination.registry import SessionRegistry

    secret_registry = SecretRegistry()
    reg = SessionRegistry(directory=tmp_path)
    txn, admission = build_txn(
        FakeQemuTransport(),
        registry=reg,
        secrets=_one_secret_store(secret_registry),
        secret_registry=secret_registry,
        secret_refs=("cred-ref",),
    )
    with pytest.raises(Exception):
        txn.open(make_open_request(), crash_after=frozenset({"attached"}))
    assert "LEAKME-9f3" not in secret_registry.snapshot()


def test_force_drop_releases_scope(tmp_path):
    # A lifecycle invalidation (RESETTING/CRASHED) tears the session down out-of-band via
    # the subscriber's force_drop(); that path MUST also evict the scope.
    from _layer4_fakes import FakeQemuTransport, build_txn, make_open_request

    from linux_debug_mcp.coordination.registry import SessionRegistry

    secret_registry = SecretRegistry()
    reg = SessionRegistry(directory=tmp_path)
    txn, admission = build_txn(
        FakeQemuTransport(),
        registry=reg,
        secrets=_one_secret_store(secret_registry),
        secret_registry=secret_registry,
        secret_refs=("cred-ref",),
    )
    session = txn.open(make_open_request())
    # Drive the out-of-band teardown the lifecycle dispatcher would trigger.
    txn._subscribers_force_drop(session.session_id)  # helper exposed for the test
    assert "LEAKME-9f3" not in secret_registry.snapshot()
```
If `make_open_request`/`build_txn` do not yet expose these knobs, add them in Step 3 —
they are small, mechanical fixture extensions, not new production surface.

- [ ] **Step 2: Run — expect FAIL**

- [ ] **Step 3: Implement** in `TransportTransaction`:
  - At the start of `open()` (before `new_session_id()`), allocate a scope: `scope = object()` and keep it in the `_OpenState`.
  - Change step (6) from `self._secrets.resolve(list(channel.secret_refs))` to
    `resolved = self._secrets.resolve(list(channel.secret_refs), scope=scope)` and store `resolved` in the open state.
  - Pass `secrets=resolved` into the `transport.attach(...)` call.
  - Bind the scope to the session on commit (store `self._scopes[session_id] = scope`).
  - In `close()` and every rollback path, call `self._secrets`-owning registry release **as the last teardown step**. Since the store owns the registry, expose `SecretsStore.release(scope)` that calls `registry.release(scope)`, and have the transaction hold the store (it does) — call `self._secrets.release(scope)` (add `release` to the `SecretsResolver` Protocol as an optional method, or store the registry on the transaction). Simplest: give the transaction the `SecretRegistry` reference (constructor param, defaulting to `SECRET_REGISTRY`) and call `registry.release(scope)` in teardown.

  Decision: add `registry: SecretRegistry` to `TransportTransaction.__init__` (defaulting to the process `SECRET_REGISTRY`) and call `self._registry.release(scope)` as the final action of `close()`/rollback. This keeps the `SecretsResolver` Protocol minimal.

- [ ] **Step 4: Run full suite — expect PASS**

- [ ] **Step 5: Commit**

```bash
git add src/linux_debug_mcp/coordination/transaction.py tests/_layer4_fakes.py tests/test_transaction_secrets_scope.py
git commit -m "feat(secrets): resolve under scope, pass to attach, release on teardown"
```

---

## Phase 4 — Server wiring + return/persistence seeding

### Task 4.1: Build the real `SecretsStore` in the server

**Files:**
- Modify: `src/linux_debug_mcp/server.py` (`_build_transport_transaction` + caller)
- Test: `tests/test_server_secrets_wiring.py` (create)

- [ ] **Step 1: Write the failing test** — `create_app()` builds without error and the transaction is constructed with a `SecretsStore` over the process registry and the env backend (keyring/external only when configured via env, e.g. `LDM_SECRETS_EXTERNAL_CMD`). Assert no crash and that an env secret definition (if configured) resolves.

```python
def test_app_builds_with_env_backend(monkeypatch):
    from linux_debug_mcp.server import create_app

    app = create_app()
    assert app is not None
```

- [ ] **Step 2: Run — expect PASS or FAIL depending on current wiring** (it should already build from Task 2.4; this task hardens backend selection).

- [ ] **Step 3: Implement** — in `_build_transport_transaction`, default `secrets` to a `SecretsStore` assembled from:
  - `EnvSecretsBackend()` always;
  - `KeyringSecretsBackend()` only if the `keyring` extra is importable (wrap construction in try/except → skip if unavailable, so the base install never fails);
  - `ExternalSecretsBackend(command=shlex.split(os.environ["LDM_SECRETS_EXTERNAL_CMD"]))` only if that env var is set;
  - `registry=SECRET_REGISTRY`;
  - `definitions=[]` (no transport ships secret_refs in the local-only baseline; definitions are loaded from server config when a real transport lands — document this).
  Pass `registry=SECRET_REGISTRY` to `TransportTransaction` too (Task 3.2).

- [ ] **Step 4: Run full suite — expect PASS**

- [ ] **Step 5: Commit**

```bash
git add src/linux_debug_mcp/server.py tests/test_server_secrets_wiring.py
git commit -m "feat(secrets): assemble SecretsStore backends in the server"
```

### Task 4.2: Seed the return/persistence `Redactor` from the registry

**Files:**
- Modify: `src/linux_debug_mcp/server.py` (the `Redactor()` construction sites on test/debug/transport paths)
- Test: `tests/test_secret_no_leak_conformance.py` (create)

- [ ] **Step 1: Write the failing conformance test**

```python
def test_resolved_secret_absent_from_response_manifest_and_logs(tmp_path, capfd):
    # Open a session that resolves a faked secret value "LEAKME-9f3", persist, and assert
    # the value appears in NONE of: the returned ToolResponse JSON, the persisted
    # manifest.json, the persisted TransportSession JSON, or captured stderr logs.
    ...
```

- [ ] **Step 2: Run — expect FAIL** (some path emits the value)

- [ ] **Step 3: Implement** — at each `Redactor(...)` construction on a return/persistence path, pass the registry snapshot: `Redactor([*existing_values, *SECRET_REGISTRY.snapshot()])`. Add a tiny helper `_response_redactor(extra=())` in `server.py` that returns `Redactor([*extra, *SECRET_REGISTRY.snapshot()])` and use it at the existing sites.

- [ ] **Step 4: Run full suite — expect PASS**

- [ ] **Step 5: Commit**

```bash
git add src/linux_debug_mcp/server.py tests/test_secret_no_leak_conformance.py
git commit -m "feat(secrets): seed return/persistence redactor from the registry"
```

---

## Phase 5 — detect-secrets OOB plugin

### Task 5.1: Custom `RegexBasedDetector` for BMC/HMC/NovaLink/IPMI

**Files:**
- Create: `tools/detect_secrets_plugins/oob_credentials.py`
- Create: `tools/detect_secrets_plugins/__init__.py` (empty)
- Test: `tests/test_oob_secrets_plugin.py` (create)

- [ ] **Step 1: Write the failing tests**

```python
from tools.detect_secrets_plugins.oob_credentials import OobCredentialDetector


def test_flags_assignment_with_value():
    det = OobCredentialDetector()
    line = 'bmc_password = "<bmc-secret>"'  # pragma: allowlist secret
    assert det.analyze_line(filename="x.py", line=line, line_number=1)


def test_does_not_flag_prose_mention():
    det = OobCredentialDetector()
    line = "The bmc password is resolved via the Secrets interface."
    assert not det.analyze_line(filename="x.md", line=line, line_number=1)
```
(`analyze_line` is detect-secrets' `RegexBasedDetector` entry point; if the installed version uses `analyze_string`, adapt the test to the installed API — verify with `uv run python -c "import detect_secrets.plugins.base as b; print(b.RegexBasedDetector.__abstractmethods__)"`.)

- [ ] **Step 2: Run — expect FAIL**

- [ ] **Step 3: Implement**

```python
from __future__ import annotations

import re

from detect_secrets.plugins.base import RegexBasedDetector


class OobCredentialDetector(RegexBasedDetector):
    """Flag hardcoded out-of-band management credentials (BMC/HMC/NovaLink/IPMI) assigned
    to a concrete value. Matches `<keyword> = "value"` / `<keyword>: value`, NOT bare
    keyword mentions, so design docs naming these systems are not flagged."""

    secret_type = "Out-of-band management credential"  # pragma: allowlist secret

    denylist = (
        re.compile(
            r"(?i)\b(?:bmc|hmc|novalink|ipmi)[ _-]?(?:password|passwd|pass|secret|token|key)\b"
            r"\s*[=:]\s*['\"]?\S+"
        ),
    )
```

- [ ] **Step 4: Run — expect PASS**

- [ ] **Step 5: Commit**

```bash
git add tools/detect_secrets_plugins/ tests/test_oob_secrets_plugin.py
git commit -m "feat(secrets): detect-secrets OOB credential plugin"
```

### Task 5.2: Wire the plugin into pre-commit + regenerate the baseline

**Files:**
- Modify: `.pre-commit-config.yaml` (detect-secrets `args`)
- Modify: `.secrets.baseline`

- [ ] **Step 1: Add the flag** to the detect-secrets hook args:
```yaml
      - id: detect-secrets
        args: ["--baseline", ".secrets.baseline", "--custom-plugins", "tools/detect_secrets_plugins/oob_credentials.py"]
```

- [ ] **Step 2: Regenerate the baseline with the plugin**

Run:
```bash
uv run detect-secrets scan --custom-plugins tools/detect_secrets_plugins/oob_credentials.py --baseline .secrets.baseline
```
Verify `OobCredentialDetector` (or its registered name) now appears in `.secrets.baseline` `plugins_used`:
```bash
uv run python -c "import json;print([p['name'] for p in json.load(open('.secrets.baseline'))['plugins_used']])"
```

- [ ] **Step 3: Confirm the hook passes on the clean tree**

Run: `uv run pre-commit run detect-secrets --all-files`
Expected: Passed.

- [ ] **Step 4: Commit**

```bash
git add .pre-commit-config.yaml .secrets.baseline
git commit -m "build(secrets): wire OOB plugin into detect-secrets + regen baseline"
```

---

## Phase 6 — Final verification

### Task 6.1: Full guardrail sweep + spec criteria audit

- [ ] **Step 1: Run all guardrails**
```bash
uv run ruff check && uv run ruff format --check && uv run ty check src && uv run python -m pytest -q
```
Expected: all green; gdb/libvirt/drgn integration tests skipped (no tools) is expected.

- [ ] **Step 2: Audit spec success criteria 1–11** against the tests written; for any criterion lacking a test, add it (e.g. criterion 7 `propagate=False`, criterion 10 close-time exception redaction, criterion 11 "omit --custom-plugins fails to reproduce baseline").

- [ ] **Step 3: Flip ADR 0012 + spec Status to Accepted**
```bash
# edit Status: Proposed -> Accepted in the ADR and spec; update docs/adr/README.md row
git add docs/
git commit -m "docs(secrets): accept ADR 0012 after implementation"
```

---

## Self-review notes (spec coverage)

- Backends env/keyring/external → Tasks 2.1–2.3. `file` rejected → Task 2.4.
- `SecretsStore` resolver + Protocol widening + EnvSecretsResolver removal → Task 2.4.
- Global redaction filter (handler boundary, traceback, non-propagating) → Tasks 1.2–1.3.
- Scope-keyed reference-counted registry + eviction ordering → Tasks 1.1, 3.2.
- Secrets reach transports only via `attach(secrets=)` → Task 3.1.
- Return/persistence seeded from registry → Task 4.2; no-leak conformance → Task 4.2.
- detect-secrets OOB plugin + baseline + fail-loud-without-flag → Tasks 5.1–5.2 (+6.2 criterion 11 test).
- Optional keyring extra; base install never requires it → Tasks 0.2, 4.1.
- Failure contract (`SecretsResolutionError`, secret-free messages, CONFIGURATION_ERROR vs INFRASTRUCTURE_FAILURE at the handler) → Tasks 2.2–2.4; map categories at the handler boundary where secret resolution is surfaced (Task 4.2 if a handler returns the failure).
