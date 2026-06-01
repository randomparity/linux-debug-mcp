from __future__ import annotations

import struct

import pytest

from kdive.symbols.vmcore_build_id import (
    VmcoreBuildIdAbsent,
    VmcoreBuildIdError,
    VmcoreFormatUnsupported,
    read_vmcore_build_id,
)

BUILD_ID = "abcdef0123456789abcdef0123456789abcdef01"  # pragma: allowlist secret


def _note(name: bytes, ntype: int, desc: bytes, endian: str = "<") -> bytes:
    # ELF note: namesz, descsz, type, name (padded to 4), desc (padded to 4).
    body = struct.pack(endian + "III", len(name), len(desc), ntype)
    body += name + b"\x00" * (-len(name) % 4)
    body += desc + b"\x00" * (-len(desc) % 4)
    return body


def _elf64_with_notes(note_blob: bytes, endian: str = "<") -> bytes:
    # Minimal ELF64 with one PT_NOTE program header pointing at note_blob.
    ei = b"\x7fELF" + bytes([2, 1 if endian == "<" else 2, 1]) + b"\x00" * 9
    e_phoff = 64
    e_phentsize = 56
    e_phnum = 1
    ehdr = ei + struct.pack(
        endian + "HHIQQQIHHHHHH",
        4,
        62,
        1,
        0,
        e_phoff,
        0,
        0,
        64,
        e_phentsize,
        e_phnum,
        0,
        0,
        0,
    )
    note_off = e_phoff + e_phentsize
    phdr = struct.pack(
        endian + "IIQQQQQQ",
        4,
        0,
        note_off,
        0,
        0,
        len(note_blob),
        len(note_blob),
        0,
    )
    return ehdr + phdr + note_blob


def test_reads_vmcoreinfo_build_id(tmp_path) -> None:
    vmcoreinfo = f"OSRELEASE=6.1.0\nBUILD-ID={BUILD_ID}\nPAGESIZE=4096\n".encode()
    blob = _note(b"VMCOREINFO", 0, vmcoreinfo)
    p = tmp_path / "vmcore"
    p.write_bytes(_elf64_with_notes(blob))
    assert read_vmcore_build_id(p) == BUILD_ID


def test_absent_build_id_raises_absent(tmp_path) -> None:
    blob = _note(b"VMCOREINFO", 0, b"OSRELEASE=6.1.0\nPAGESIZE=4096\n")
    p = tmp_path / "vmcore"
    p.write_bytes(_elf64_with_notes(blob))
    with pytest.raises(VmcoreBuildIdAbsent):
        read_vmcore_build_id(p)


def test_non_elf_raises_unsupported(tmp_path) -> None:
    p = tmp_path / "vmcore"
    p.write_bytes(b"KDUMP   " + b"\x00" * 64)
    with pytest.raises(VmcoreFormatUnsupported):
        read_vmcore_build_id(p)


def test_truncated_elf_raises_error(tmp_path) -> None:
    p = tmp_path / "vmcore"
    p.write_bytes(b"\x7fELF" + bytes([2, 1, 1]) + b"\x00" * 5)  # header cut short
    with pytest.raises(VmcoreBuildIdError):
        read_vmcore_build_id(p)


def test_implausibly_small_program_header_entry_raises_error(tmp_path) -> None:
    blob = bytearray(_elf64_with_notes(_note(b"VMCOREINFO", 0, b"BUILD-ID=" + BUILD_ID.encode() + b"\n")))
    struct.pack_into("<H", blob, 54, 8)
    p = tmp_path / "vmcore"
    p.write_bytes(blob)

    with pytest.raises(VmcoreBuildIdError, match="implausible e_phentsize"):
        read_vmcore_build_id(p)


def test_program_header_table_past_eof_raises_error(tmp_path) -> None:
    blob = bytearray(_elf64_with_notes(_note(b"VMCOREINFO", 0, b"BUILD-ID=" + BUILD_ID.encode() + b"\n")))
    struct.pack_into("<H", blob, 56, 8)
    p = tmp_path / "vmcore"
    p.write_bytes(blob)

    with pytest.raises(VmcoreBuildIdError, match="extends past EOF"):
        read_vmcore_build_id(p)


def test_uppercase_build_id_is_lowercased(tmp_path) -> None:
    vmcoreinfo = b"BUILD-ID=ABCDEF0123456789ABCDEF0123456789ABCDEF01\n"
    blob = _note(b"VMCOREINFO", 0, vmcoreinfo)
    p = tmp_path / "vmcore"
    p.write_bytes(_elf64_with_notes(blob))
    assert read_vmcore_build_id(p) == BUILD_ID
