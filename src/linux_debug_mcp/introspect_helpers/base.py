"""Curated drgn introspection helpers. Spec §3."""

from __future__ import annotations

from dataclasses import dataclass

from linux_debug_mcp.domain import Model


class NoArgs(Model):
    """Empty args model for helpers that take no parameters."""


@dataclass(frozen=True)
class HelperSpec:
    name: str
    version: int
    script: str
    args_model: type[Model]
    output_model: type[Model]
