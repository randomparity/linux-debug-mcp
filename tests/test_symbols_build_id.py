from __future__ import annotations

import struct
from pathlib import Path

import pytest

from kdive.symbols import BuildIdReadError, read_elf_build_id

BUILD_ID = bytes.fromhex("0123456789abcdef0123456789abcdef01234567")


def _note(endian: str) -> bytes:
    # NT_GNU_BUILD_ID = 3, name "GNU\0" (namesz counts the NUL -> 4), desc = BUILD_ID.
    name = b"GNU\x00"
    desc = BUILD_ID
    hdr = struct.pack(f"{endian}III", 4, len(desc), 3)
    body = name + desc  # 4 + 20 = 24, already 4-byte aligned
    return hdr + body


def _elf(*, bits: int, endian: str) -> bytes:
    e = "<" if endian == "little" else ">"
    ei_class = 1 if bits == 32 else 2
    ei_data = 1 if endian == "little" else 2
    ident = bytes([0x7F]) + b"ELF" + bytes([ei_class, ei_data, 1]) + bytes(9)
    note = _note(e)
    if bits == 64:
        ehsize, phentsize = 64, 56
        note_off = ehsize + phentsize
        eh = struct.pack(f"{e}HHIQQQIHHHHHH", 2, 0x3E, 1, 0, ehsize, 0, 0, ehsize, phentsize, 1, 0, 0, 0)
        ph = struct.pack(f"{e}IIQQQQQQ", 4, 0, note_off, 0, 0, len(note), len(note), 0)
    else:
        ehsize, phentsize = 52, 32
        note_off = ehsize + phentsize
        eh = struct.pack(f"{e}HHIIIIIHHHHHH", 2, 0x3E, 1, 0, ehsize, 0, 0, ehsize, phentsize, 1, 0, 0, 0)
        ph = struct.pack(f"{e}IIIIIIII", 4, note_off, 0, 0, len(note), len(note), 0, 0)
    return ident + eh + ph + note


@pytest.mark.parametrize("bits", [32, 64])
@pytest.mark.parametrize("endian", ["little", "big"])
def test_reads_build_id(tmp_path: Path, bits: int, endian: str) -> None:
    p = tmp_path / "vmlinux"
    p.write_bytes(_elf(bits=bits, endian=endian))
    assert read_elf_build_id(p) == BUILD_ID.hex()


def test_non_elf_raises(tmp_path: Path) -> None:
    p = tmp_path / "x"
    p.write_bytes(b"not an elf file at all")
    with pytest.raises(BuildIdReadError):
        read_elf_build_id(p)


def test_truncated_raises(tmp_path: Path) -> None:
    p = tmp_path / "x"
    p.write_bytes(_elf(bits=64, endian="little")[:30])
    with pytest.raises(BuildIdReadError):
        read_elf_build_id(p)


def test_note_absent_raises(tmp_path: Path) -> None:
    e = "<"
    ident = bytes([0x7F]) + b"ELF" + bytes([2, 1, 1]) + bytes(9)
    name = b"GNU\x00"
    desc = b"\x00\x00\x00\x00"
    note = struct.pack(f"{e}III", 4, len(desc), 1) + name + desc  # type 1 != NT_GNU_BUILD_ID
    ehsize, phentsize = 64, 56
    note_off = ehsize + phentsize
    eh = struct.pack(f"{e}HHIQQQIHHHHHH", 2, 0x3E, 1, 0, ehsize, 0, 0, ehsize, phentsize, 1, 0, 0, 0)
    ph = struct.pack(f"{e}IIQQQQQQ", 4, 0, note_off, 0, 0, len(note), len(note), 0)
    p = tmp_path / "x"
    p.write_bytes(ident + eh + ph + note)
    with pytest.raises(BuildIdReadError):
        read_elf_build_id(p)


def test_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(BuildIdReadError):
        read_elf_build_id(tmp_path / "nope")


def _elf64_header(e: str, *, e_phoff: int, e_phentsize: int, e_phnum: int) -> bytes:
    ident = bytes([0x7F]) + b"ELF" + bytes([2, 1, 1]) + bytes(9)
    eh = struct.pack(f"{e}HHIQQQIHHHHHH", 2, 0x3E, 1, 0, e_phoff, 0, 0, 64, e_phentsize, e_phnum, 0, 0, 0)
    return ident + eh


def test_undersized_phentsize_raises_build_id_error(tmp_path: Path) -> None:
    # TD-02: an e_phentsize smaller than a real program-header entry would make the parser
    # read fields past the entry; reject it as a clean BuildIdReadError, not a raw struct.error.
    p = tmp_path / "x"
    # An 8-byte "entry" whose p_type is PT_NOTE: the parser would unpack p_offset past the
    # entry (raw struct.error) without the e_phentsize guard.
    undersized_entry = struct.pack("<I", 4) + bytes(4)
    p.write_bytes(_elf64_header("<", e_phoff=64, e_phentsize=8, e_phnum=1) + undersized_entry)
    with pytest.raises(BuildIdReadError):
        read_elf_build_id(p)


def test_phdr_table_larger_than_file_raises_without_giant_read(tmp_path: Path) -> None:
    # TD-02: a header claiming a ~4 GB program-header table must be rejected by the file-size
    # containment check before any read attempts to allocate it.
    p = tmp_path / "x"
    p.write_bytes(_elf64_header("<", e_phoff=64, e_phentsize=0xFFFF, e_phnum=0xFFFF))
    with pytest.raises(BuildIdReadError):
        read_elf_build_id(p)
