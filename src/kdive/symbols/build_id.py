"""Host-side ELF GNU build-id extraction. ADR 0010 / spec §5.

Pure-Python parse of the fixed ELF header -> program-header table -> PT_NOTE
segments, reading the NT_GNU_BUILD_ID note. No drgn/pyelftools dependency.

Reads only the header, the program-header table, and each PT_NOTE segment via
``seek`` -- never the whole file. A vmlinux carrying DWARF is often hundreds of
MB; the build-id note is a handful of bytes in an early PT_NOTE segment, so
slurping the file would waste that much host RAM per call.
"""

from __future__ import annotations

import struct
from pathlib import Path
from typing import BinaryIO

NT_GNU_BUILD_ID = 3
PT_NOTE = 4


class BuildIdReadError(Exception):
    """The file is not an ELF, is truncated, or carries no GNU build-id note.

    Callers map this to a caller-facing CONFIGURATION_ERROR
    (``vmlinux_build_id_unreadable``) -- the caller supplied the wrong file.
    """


def _read_exact(fh: BinaryIO, offset: int, size: int) -> bytes:
    fh.seek(offset)
    blob = fh.read(size)
    if len(blob) != size:
        raise BuildIdReadError(f"ELF truncated reading {size} bytes at offset {offset}")
    return blob


def _scan_notes(blob: bytes, endian: str) -> str | None:
    off = 0
    while off + 12 <= len(blob):
        namesz, descsz, ntype = struct.unpack_from(endian + "III", blob, off)
        off += 12
        name_end = off + namesz
        desc_start = name_end + (-name_end % 4)
        desc_end = desc_start + descsz
        if desc_end > len(blob):
            return None
        if ntype == NT_GNU_BUILD_ID and blob[off:name_end].rstrip(b"\x00") == b"GNU":
            return blob[desc_start:desc_end].hex()
        off = desc_end + (-desc_end % 4)
    return None


def read_elf_build_id(path: Path) -> str:
    """Return the lower-case hex NT_GNU_BUILD_ID note from an ELF file.

    Raises :class:`BuildIdReadError` on a non-ELF (incl. compressed
    vmlinux.xz / vmlinuz), truncated, or note-absent file. The handler maps
    this to a caller-facing CONFIGURATION_ERROR (``vmlinux_build_id_unreadable``),
    not an infrastructure fault -- the caller supplied the wrong file.
    """
    try:
        with path.open("rb") as fh:
            ident = _read_exact(fh, 0, 16)
            if ident[:4] != b"\x7fELF":
                raise BuildIdReadError("not an ELF file (bad magic)")
            ei_class, ei_data = ident[4], ident[5]
            if ei_class not in (1, 2) or ei_data not in (1, 2):
                raise BuildIdReadError("unsupported ELF class/endianness")
            endian = "<" if ei_data == 1 else ">"
            is64 = ei_class == 2
            if is64:
                ehdr = _read_exact(fh, 0, 64)
                (e_phoff,) = struct.unpack_from(endian + "Q", ehdr, 32)
                e_phentsize, e_phnum = struct.unpack_from(endian + "HH", ehdr, 54)
            else:
                ehdr = _read_exact(fh, 0, 52)
                (e_phoff,) = struct.unpack_from(endian + "I", ehdr, 28)
                e_phentsize, e_phnum = struct.unpack_from(endian + "HH", ehdr, 42)
            if e_phnum == 0:
                raise BuildIdReadError("no program headers; cannot locate notes")
            min_phentsize = 56 if is64 else 32
            if e_phentsize < min_phentsize:
                raise BuildIdReadError(f"implausible e_phentsize {e_phentsize} for {'ELF64' if is64 else 'ELF32'}")
            table_bytes = e_phentsize * e_phnum
            file_size = fh.seek(0, 2)
            if e_phoff < 0 or e_phoff + table_bytes > file_size:
                raise BuildIdReadError(
                    f"program-header table ({table_bytes} bytes at offset {e_phoff}) extends past EOF ({file_size})"
                )
            phdrs = _read_exact(fh, e_phoff, table_bytes)
            for i in range(e_phnum):
                ph = i * e_phentsize
                (p_type,) = struct.unpack_from(endian + "I", phdrs, ph)
                if p_type != PT_NOTE:
                    continue
                if is64:
                    (p_offset,) = struct.unpack_from(endian + "Q", phdrs, ph + 8)
                    (p_filesz,) = struct.unpack_from(endian + "Q", phdrs, ph + 32)
                else:
                    (p_offset,) = struct.unpack_from(endian + "I", phdrs, ph + 4)
                    (p_filesz,) = struct.unpack_from(endian + "I", phdrs, ph + 16)
                found = _scan_notes(_read_exact(fh, p_offset, p_filesz), endian)
                if found is not None:
                    return found
    except OSError as exc:
        raise BuildIdReadError(f"cannot read {path}: {exc}") from exc
    raise BuildIdReadError("no NT_GNU_BUILD_ID note found")
