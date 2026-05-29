"""Conformance: a value resolved through the SecretsStore (and thus registered with the
process SecretRegistry) is redacted from log output AND from any tool-output/manifest-like
structure built through a registry-seeded Redactor. This is the issue #65 acceptance
criterion "no credential ever appears in logs, tool output, or any URL (verified by test)"
exercised at the seam where credentials enter the process."""

import logging

from linux_debug_mcp.safety.redaction import REDACTION, Redactor, SecretRedactionFilter
from linux_debug_mcp.safety.secret_registry import PROCESS_SECRET_REGISTRY, SecretRegistry
from linux_debug_mcp.safety.secrets import SecretReference, SecretReferenceKind
from linux_debug_mcp.seams.secrets import EnvSecretsBackend, SecretsStore

LEAK = "LEAKME-9f3xQ"  # pragma: allowlist secret


def _store_resolving(value: str, registry: SecretRegistry) -> SecretsStore:
    class _OneBackend(EnvSecretsBackend):
        def get(self, reference: SecretReference) -> str | None:
            return value

    return SecretsStore(
        definitions=[SecretReference(kind=SecretReferenceKind.ENV, label="c", reference="cred-ref")],
        backends={SecretReferenceKind.ENV: _OneBackend()},
        registry=registry,
    )


def test_resolved_value_absent_from_logs_and_redacted_output():
    registry = SecretRegistry()
    store = _store_resolving(LEAK, registry)
    assert store.resolve(["cred-ref"]) == {"cred-ref": LEAK}

    # 1) logs: the SecretRedactionFilter seeded from this registry masks the value.
    records: list[str] = []

    class _Capture(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(self.format(record))

    handler = _Capture()
    handler.setFormatter(logging.Formatter("%(message)s"))
    handler.addFilter(SecretRedactionFilter(registry))
    logger = logging.getLogger("conformance.leak")
    logger.handlers = [handler]
    logger.propagate = False
    logger.setLevel(logging.INFO)
    logger.info("connecting with %s now", LEAK)
    assert LEAK not in records[0]
    assert REDACTION in records[0]

    # 2) tool output / manifest: a Redactor seeded from the registry snapshot masks the
    #    value even when it is not in a key=value pattern (e.g. embedded in a list/dict).
    redactor = Redactor(list(registry.snapshot()))
    payload = {"endpoint": f"console://host/{LEAK}", "items": [LEAK, "safe"]}
    redacted = redactor.redact_value(payload)
    assert LEAK not in str(redacted)
    assert redacted["items"][1] == "safe"


def test_value_not_registered_is_not_masked_by_value():
    # Negative control: a value the store never resolved is not force-masked (only the
    # keyword/pattern path would catch it). Proves redaction is driven by the registry.
    registry = SecretRegistry()
    redactor = Redactor(list(registry.snapshot()))
    assert redactor.redact_text("plain LEAKME-other text") == "plain LEAKME-other text"


def test_bare_redactor_seeds_from_process_registry():
    # The server's return/persistence paths construct a bare ``Redactor()`` with no
    # secret_values. ADR 0012 Decision 5 requires those to still mask a credential that
    # was resolved through the SecretsStore. A value registered in the process-global
    # registry must therefore be redacted by ``Redactor()`` without any explicit seeding.
    PROCESS_SECRET_REGISTRY.register(LEAK, scope="conformance-bare")
    try:
        payload = {"endpoint": f"console://host/{LEAK}", "items": [LEAK, "safe"]}
        redacted = Redactor().redact_value(payload)
        assert LEAK not in str(redacted)
        assert REDACTION in str(redacted)
        assert redacted["items"][1] == "safe"
    finally:
        PROCESS_SECRET_REGISTRY.release("conformance-bare")
    # After release the process registry is clean again, so a fresh bare Redactor no
    # longer force-masks the value (keeps the global state isolated across tests).
    assert Redactor().redact_text(f"plain {LEAK} text") == f"plain {LEAK} text"


def test_process_registry_isolation_invariant():
    # Locks the safety invariant behind Redactor's process-global seeding: the registry is
    # empty by default (a bare Redactor masks nothing it wasn't given), and a scoped
    # register/release round-trip leaves no residue. A leak here means global state is
    # bleeding across tests and silently force-masking unrelated output.
    arbitrary = "NOT-A-SECRET-7yQ2"  # pragma: allowlist secret
    assert Redactor().redact_text(arbitrary) == arbitrary
    PROCESS_SECRET_REGISTRY.register(arbitrary, scope="isolation-probe")
    assert arbitrary not in Redactor().redact_text(arbitrary)  # masked while registered
    PROCESS_SECRET_REGISTRY.release("isolation-probe")
    assert Redactor().redact_text(arbitrary) == arbitrary  # no residue after release
