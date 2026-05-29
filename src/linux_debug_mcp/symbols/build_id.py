"""Host-side ELF GNU build-id extraction. ADR 0010 / spec §5.

Pure-Python parse of the fixed ELF header -> program-header table -> PT_NOTE
segments, reading the NT_GNU_BUILD_ID note. No drgn/pyelftools dependency.
"""

from __future__ import annotations

import struct
from pathlib import Path

NT_GNU_BUILD_ID = 3
PT_NOTE = 4


class BuildIdReadError(Exception):
    """The file is not an ELF, is truncated, or carries no GNU build-id note.

    Callers map this to a caller-facing CONFIGURATION_ERROR
    (``vmlinux_build_id_unreadable``) -- the caller supplied the wrong file.
    """


def _u(data: bytes, off: int, fmt: str, endian: str) -> tuple[int, ...]:
    size = struct.calcsize(endian + fmt)
    if off + size > len(data):
        raise BuildIdReadError(f"ELF truncated at offset {off}")
    return struct.unpack_from(endian + fmt, data, off)


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
    vmlinux.xz / vmlinuz), truncated, or note-absent file.
    """
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise BuildIdReadError(f"cannot read {path}: {exc}") from exc
    if data[:4] != b"\x7fELF":
        raise BuildIdReadError("not an ELF file (bad magic)")
    if len(data) < 6:
        raise BuildIdReadError("ELF header truncated")
    ei_class, ei_data = data[4], data[5]
    if ei_class not in (1, 2) or ei_data not in (1, 2):
        raise BuildIdReadError("unsupported ELF class/endianness")
    endian = "<" if ei_data == 1 else ">"
    is64 = ei_class == 2
    if is64:
        (e_phoff,) = _u(data, 32, "Q", endian)
        e_phentsize, e_phnum = _u(data, 54, "HH", endian)
    else:
        (e_phoff,) = _u(data, 28, "I", endian)
        e_phentsize, e_phnum = _u(data, 42, "HH", endian)
    for i in range(e_phnum):
        ph = e_phoff + i * e_phentsize
        (p_type,) = _u(data, ph, "I", endian)
        if p_type != PT_NOTE:
            continue
        if is64:
            (p_offset,) = _u(data, ph + 8, "Q", endian)
            (p_filesz,) = _u(data, ph + 32, "Q", endian)
        else:
            (p_offset,) = _u(data, ph + 4, "I", endian)
            (p_filesz,) = _u(data, ph + 16, "I", endian)
        if p_offset + p_filesz > len(data):
            raise BuildIdReadError("PT_NOTE segment out of bounds")
        found = _scan_notes(data[p_offset : p_offset + p_filesz], endian)
        if found is not None:
            return found
    raise BuildIdReadError("no NT_GNU_BUILD_ID note found")
