from __future__ import annotations

import threading


class SecretRegistry:
    """Process-scoped, thread-safe registry of known secret values used to seed the
    redaction filter and the return/persistence ``Redactor``. Values are reference-counted
    per eviction scope so a long-running server holds only credentials for live owners.

    Empty/None values are never stored (an empty credential would force-mask every string).
    ``scope=None`` registers process-globally and is never evicted by ``release``."""

    _GLOBAL = "__global__"

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._refcount: dict[str, int] = {}
        self._by_scope: dict[object, list[str]] = {}
        self._version = 0

    def register(self, value: str | None, *, scope: object | None) -> None:
        if not value:
            return
        key: object = self._GLOBAL if scope is None else scope
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
