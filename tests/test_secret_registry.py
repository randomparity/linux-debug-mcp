from kdive.safety.secret_registry import SecretRegistry


def test_register_snapshot_and_version():
    reg = SecretRegistry()
    v0 = reg.version()
    reg.register("hunter2", scope="s1")
    assert "hunter2" in reg.snapshot()
    assert reg.version() > v0


def test_empty_value_is_ignored():
    reg = SecretRegistry()
    reg.register("", scope="s1")
    reg.register(None, scope="s1")
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
    reg.register("globalcred", scope=None)
    reg.release(None)  # releasing the global scope is a no-op
    assert "globalcred" in reg.snapshot()
