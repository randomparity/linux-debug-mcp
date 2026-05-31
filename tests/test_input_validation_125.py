"""Trust-boundary input-validation tests for issue #125.

Each test drives a boundary with malformed/hostile input and asserts the code rejects it with a
structured error (or safely degrades) instead of letting a raw ValueError/KeyError/struct.error or
an unbounded loop escape. Grouped here because they span several modules but share one theme.
"""

from __future__ import annotations

import socket
import struct

import pytest

import kdive.server as server
from kdive.coordination.registry import RecoveryTombstone, SessionRegistry
from kdive.domain import ErrorCategory
from kdive.postmortem.dumps import is_within_dump_dir, parse_dump_listing
from kdive.prereqs.checks import PortProbeResult, _default_port_probe
from kdive.prereqs.drgn_probe import PROBE_SCRIPT
from kdive.providers.local.gdb_mi import MAX_MEMORY_READ_BYTES, GdbMiError
from kdive.seams.target import TargetKey
from kdive.transport.serial_local import SerialLocalConfigError, SerialLocalTransport


# --- TD-04: serial-local port/baud int() coercion ---------------------------------------------
def test_serial_build_source_rejects_non_integer_port() -> None:
    with pytest.raises(SerialLocalConfigError) as excinfo:
        SerialLocalTransport._build_source("/dev/ttyUSB0", {"host": "h", "port": "not-an-int"})
    assert excinfo.value.category is ErrorCategory.CONFIGURATION_ERROR


def test_serial_build_source_rejects_non_integer_baud() -> None:
    with pytest.raises(SerialLocalConfigError) as excinfo:
        SerialLocalTransport._build_source("/dev/ttyUSB0", {"baud": "fast"})
    assert excinfo.value.category is ErrorCategory.CONFIGURATION_ERROR


def test_serial_build_source_accepts_valid_values() -> None:
    remote = SerialLocalTransport._build_source("/dev/ttyUSB0", {"host": "h", "port": "1234"})
    assert remote.port == 1234
    local = SerialLocalTransport._build_source("/dev/ttyUSB0", {"baud": "9600"})
    assert local.baud == 9600


# --- TD-14: read_memory value bounds at the handler ------------------------------------------
class _RecordingEngine:
    def __init__(self) -> None:
        self.calls: list[tuple[int, int]] = []

    def read_memory(self, attachment: object, *, address: int, byte_count: int) -> dict[str, object]:
        self.calls.append((address, byte_count))
        return {"bytes": ""}


def _read_memory(engine: _RecordingEngine, *, address: object, byte_count: object) -> dict[str, object]:
    return server._engine_op_data(
        engine=engine,  # type: ignore[arg-type]
        attachment=object(),  # type: ignore[arg-type]
        method_name="read_memory",
        kwargs={"address": address, "byte_count": byte_count},
    )


@pytest.mark.parametrize(
    "address, byte_count",
    [(-1, 4), (0x1000, 0), (0x1000, -8), (0x1000, MAX_MEMORY_READ_BYTES + 1)],
)
def test_read_memory_rejects_out_of_range_values(address: int, byte_count: int) -> None:
    engine = _RecordingEngine()
    with pytest.raises(GdbMiError) as excinfo:
        _read_memory(engine, address=address, byte_count=byte_count)
    assert excinfo.value.category is ErrorCategory.CONFIGURATION_ERROR
    assert engine.calls == []  # rejected before touching the engine


def test_read_memory_accepts_in_range_values() -> None:
    engine = _RecordingEngine()
    _read_memory(engine, address=0, byte_count=MAX_MEMORY_READ_BYTES)
    assert engine.calls == [(0, MAX_MEMORY_READ_BYTES)]


# --- TD-17: corrupted recovery tombstones must not crash read/reconcile -----------------------
class _NoopMarker:
    def mark_recovery_required(self, target_key: TargetKey, generation: int) -> None: ...


class _DeadProxy:
    def stop_by_identity(self, pid: int, start_time: str | None) -> bool:
        return False


def _key() -> TargetKey:
    return TargetKey(provisioner="local-qemu", target_id="run-1")


def test_read_tombstone_skips_malformed_file(tmp_path, caplog) -> None:
    reg = SessionRegistry(directory=tmp_path)
    reg.write_tombstone(RecoveryTombstone(target_key=_key(), generation=3, reason="halted"))
    tomb = next(tmp_path.glob("tomb-*.json"))
    tomb.write_text('{"provisioner": "local-qemu"}', encoding="utf-8")  # truncated: missing keys
    assert reg.read_tombstone(_key()) is None  # KeyError swallowed -> None, not a crash
    assert "malformed tombstone" in caplog.text


def test_reconcile_skips_malformed_tombstone(tmp_path) -> None:
    reg = SessionRegistry(directory=tmp_path)
    (tmp_path / "tomb-garbage.json").write_text("{not json", encoding="utf-8")
    report = reg.reconcile(proxy=_DeadProxy(), admission=_NoopMarker())  # must not raise
    assert report.reaped == []


# --- TD-22: bounds on remote-supplied size/mtime ----------------------------------------------
def test_parse_dump_listing_clamps_negative_size_to_zero() -> None:
    probe = {"dumps": [{"dir": "/var/crash/x", "size": -5, "file_sizes": {"vmcore": -1}}]}
    entry = parse_dump_listing(probe)[0]
    assert entry.size_bytes == 0
    assert entry.file_sizes["vmcore"] == 0


def test_parse_dump_listing_handles_non_numeric_size() -> None:
    probe = {"dumps": [{"dir": "/var/crash/x", "size": "huge"}]}
    assert parse_dump_listing(probe)[0].size_bytes == 0


def test_parse_dump_listing_handles_infinite_size() -> None:
    # json.loads('1e400') yields float('inf'); int(inf) raises OverflowError, which must degrade to
    # 0 rather than escape parse_dump_listing (TD-22).
    probe = {"dumps": [{"dir": "/var/crash/x", "size": float("inf"), "file_sizes": {"vmcore": float("inf")}}]}
    entry = parse_dump_listing(probe)[0]
    assert entry.size_bytes == 0
    assert entry.file_sizes["vmcore"] == 0


@pytest.mark.parametrize("mtime", [-1, 99999999999, "yesterday", float("inf")])
def test_parse_dump_listing_rejects_out_of_range_mtime(mtime: object) -> None:
    probe = {"dumps": [{"dir": "/var/crash/x", "mtime": mtime, "size": 1}]}
    assert parse_dump_listing(probe)[0].capture_time is None


def test_parse_dump_listing_accepts_plausible_mtime() -> None:
    probe = {"dumps": [{"dir": "/var/crash/x", "mtime": 1_700_000_000, "size": 1}]}
    assert parse_dump_listing(probe)[0].capture_time is not None


# --- TD-23: dump path containment against the enumerated dir -----------------------------------
@pytest.mark.parametrize(
    "path, dump_dir, expected",
    [
        ("/var/crash/127.0.0.1-2024", "/var/crash", True),
        ("/var/crash", "/var/crash", True),
        ("/var/crash/../../etc", "/var/crash", False),
        ("/var/crash-evil/x", "/var/crash", False),  # prefix-string trap
        ("/etc/shadow", "/var/crash", False),
        ("/srv/dumps/a", "/srv/dumps", True),
    ],
)
def test_is_within_dump_dir(path: str, dump_dir: str, expected: bool) -> None:
    assert is_within_dump_dir(path, dump_dir) is expected


# --- TD-34: on-target ELF parser bounds the program-header table ------------------------------
def _probe_namespace() -> dict[str, object]:
    # Exec only the function-definition prefix of the on-target probe (everything before the main
    # body), so we can call _elf_build_id in isolation without running the probe's file/stdout work.
    prefix = PROBE_SCRIPT.split("\nrel = _safe(", 1)[0]
    namespace: dict[str, object] = {}
    exec(compile(prefix, "<probe>", "exec"), namespace)  # noqa: S102 - trusted in-repo probe source
    return namespace


def test_probe_elf_build_id_rejects_oversized_phnum(tmp_path) -> None:
    # An unbounded parser also returns None (the first phdr read hits EOF -> struct.error), so a
    # plain None assertion would not catch a regression. The bound's observable effect is that it
    # returns BEFORE the phdr loop: only the 64-byte header is read. Count reads via an injected
    # `open` and assert no phdr-sized read happened (unbounded code would do one before struct.error).
    elf = bytearray(64)
    elf[0:4] = b"\x7fELF"
    elf[4] = 2  # ELFCLASS64
    elf[5] = 1  # little-endian
    struct.pack_into("<Q", elf, 32, 64)  # e_phoff just past the header
    struct.pack_into("<H", elf, 54, 56)  # e_phentsize
    struct.pack_into("<H", elf, 56, 0xFFFF)  # e_phnum: table would run far past a 64-byte file
    target = tmp_path / "vmlinux"
    target.write_bytes(bytes(elf))

    reads: list[int | None] = []
    real_open = open

    def counting_open(path, mode="r", *args, **kwargs):
        handle = real_open(path, mode, *args, **kwargs)
        real_read = handle.read

        def read(size=-1, /):
            reads.append(size)
            return real_read(size)

        handle.read = read  # type: ignore[method-assign]
        return handle

    namespace = _probe_namespace()
    namespace["open"] = counting_open  # shadow builtin in the probe's globals
    assert namespace["_elf_build_id"](str(target)) is None
    assert reads == [64]  # only the ELF header; the per-phdr loop never ran


def test_probe_elf_build_id_rejects_non_elf(tmp_path) -> None:
    target = tmp_path / "notelf"
    target.write_bytes(b"this is not an ELF file at all, just text padding...........")
    assert _probe_namespace()["_elf_build_id"](str(target)) is None


# --- TD-35: address-family detection via getaddrinfo, not a ':' heuristic ----------------------
def test_default_port_probe_detects_ipv4_in_use() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        port = listener.getsockname()[1]
        assert _default_port_probe("127.0.0.1", port) == PortProbeResult("in_use")


def test_default_port_probe_handles_ipv6_host() -> None:
    if not socket.has_ipv6:
        pytest.skip("no IPv6 support")
    try:
        listener = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    except OSError:
        pytest.skip("cannot create IPv6 socket")
    with listener:
        try:
            listener.bind(("::1", 0))
        except OSError:
            pytest.skip("IPv6 loopback not available")
        listener.listen()
        port = listener.getsockname()[1]
        # The old `':' in host` heuristic happened to pick AF_INET6 here too, but getaddrinfo makes
        # it robust; the point is a bracketless IPv6 literal resolves and binds without raising.
        assert _default_port_probe("::1", port) == PortProbeResult("in_use")
