"""Best-effort, total parsers for crash command output. ADR 0026 decision 3.

``parse_command`` dispatches on the command's leading token(s). Any command
without a parser, or whose parser raises, yields the raw-passthrough form. No
parser raises out of ``parse_command``; redaction is the handler's job, not the
parser's.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any

_BT_HEADER = re.compile(r'PID:\s*(\d+).*?COMMAND:\s*"([^"]*)"')
_BT_FRAME = re.compile(r"#(\d+)\s+\[\w+\]\s+(\S+)\s+at\s+(\S+)")
_LOG_LINE = re.compile(r"^\[\s*(\d+\.\d+)\]\s?(.*)$")


def parse_bt(text: str) -> dict[str, Any]:
    result: dict[str, Any] = {"parsed": True, "frames": []}
    header = _BT_HEADER.search(text)
    if header is not None:
        result["pid"] = int(header.group(1))
        result["command"] = header.group(2)
    for line in text.splitlines():
        frame = _BT_FRAME.search(line)
        if frame is not None:
            result["frames"].append({"level": int(frame.group(1)), "symbol": frame.group(2), "pc_addr": frame.group(3)})
    return result


def parse_ps(text: str) -> dict[str, Any]:
    processes: list[dict[str, Any]] = []
    for line in text.splitlines():
        body = line.lstrip(">").strip()
        fields = body.split()
        if len(fields) < 9 or not fields[0].isdigit():
            continue
        processes.append(
            {
                "pid": int(fields[0]),
                "ppid": int(fields[1]),
                "cpu": fields[2],
                "task_addr": fields[3],
                "st": fields[4],
                "comm": fields[-1].strip("[]"),
            }
        )
    return {"parsed": True, "processes": processes}


def parse_sys(text: str) -> dict[str, Any]:
    system: dict[str, str] = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip()
        if key:
            system[key] = value.strip().strip('"')
    return {"parsed": True, "system": system}


def parse_log(text: str) -> dict[str, Any]:
    lines: list[dict[str, Any]] = []
    for line in text.splitlines():
        match = _LOG_LINE.match(line)
        if match is not None:
            lines.append({"ts": float(match.group(1)), "text": match.group(2)})
        elif line:
            lines.append({"ts": None, "text": line})
    return {"parsed": True, "lines": lines}


def parse_kmem_i(text: str) -> dict[str, Any]:
    memory: dict[str, dict[str, Any]] = {}
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 2:
            continue
        # Row label is the leading alphabetic words; the first numeric field is pages.
        label_parts = []
        rest = fields
        for token in fields:
            if token.replace(",", "").isdigit():
                break
            label_parts.append(token)
            rest = fields[len(label_parts) :]
        if not label_parts or not rest:
            continue
        memory[" ".join(label_parts)] = {"pages": rest[0], "detail": " ".join(rest[1:])}
    return {"parsed": True, "memory": memory}


_PARSERS: dict[str, Callable[[str], dict[str, Any]]] = {
    "bt": parse_bt,
    "ps": parse_ps,
    "sys": parse_sys,
    "log": parse_log,
}


def _dispatch_key(command: str) -> str | None:
    tokens = command.strip().split()
    if not tokens:
        return None
    verb = tokens[0].lower()
    if verb == "kmem" and len(tokens) > 1 and tokens[1] == "-i":
        return "kmem -i"
    return verb if verb in _PARSERS else None


def parse_command(command: str, raw_text: str) -> dict[str, Any]:
    """Parse ``raw_text`` for ``command`` into a typed dict, or the raw-passthrough
    form (``parsed: False``) for an unknown verb or a parser exception."""
    key = _dispatch_key(command)
    if key == "kmem -i":
        parser: Callable[[str], dict[str, Any]] | None = parse_kmem_i
    else:
        parser = _PARSERS.get(key or "")
    if parser is None:
        return {"parsed": False, "reason": "unknown_command", "raw": raw_text}
    try:
        return parser(raw_text)
    except Exception:
        # Best-effort: any parser failure -> raw passthrough. Parser totality
        # (never raising out of parse_command) is the contract (ADR 0026 decision
        # 3); a narrower except would let an unforeseen parser bug crash the
        # handler. (BLE is not in the repo's ruff select set, so no noqa needed.)
        return {"parsed": False, "reason": "parse_failed", "raw": raw_text}
