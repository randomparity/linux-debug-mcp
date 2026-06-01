"""Host-side VMCOREINFO build-id extraction from an ELF vmcore. ADR 0026 / spec §5.2.

Parses the ELF header -> program-header table -> PT_NOTE segments, locating the
``VMCOREINFO`` note and reading its ``BUILD-ID=<hex>`` line. This is the same
kernel id drgn exposes as ``main_module().build_id`` for a vmcore, so the crash
and drgn offline tiers compare the same value. Pure-Python ``struct`` parse, no
drgn/crash/pyelftools dependency; only the ELF header, program headers, and each
PT_NOTE segment are read via ``seek``.
"""

from __future__ import annotations

import re
import struct
from pathlib import Path
from typing import BinaryIO

PT_NOTE = 4
_BUILD_ID_LINE = re.compile(rb"^BUILD-ID=([0-9A-Fa-f]+)\s*$", re.MULTILINE)


class VmcoreBuildIdError(Exception):
    """The vmcore is an ELF but is truncated or otherwise unreadable."""


class VmcoreFormatUnsupported(Exception):
    """The vmcore is not an ELF container (e.g. compressed-kdump). Host build-id
    extraction is ELF-only in this PR; a non-ELF container fails loud rather than
    silently skipping the §4.2 build-id check (spec §5.3)."""


class VmcoreBuildIdAbsent(Exception):
    """The vmcore is a readable ELF but carries no ``VMCOREINFO BUILD-ID`` --
    provenance cannot be verified (spec §5.2: ``provenance_unverifiable``)."""


def _read_exact(fh: BinaryIO, offset: int, size: int) -> bytes:
    fh.seek(offset)
    blob = fh.read(size)
    if len(blob) != size:
        raise VmcoreBuildIdError(f"vmcore truncated reading {size} bytes at offset {offset}")
    return blob


def _scan_vmcoreinfo(blob: bytes, endian: str) -> str | None:
    off = 0
    while off + 12 <= len(blob):
        namesz, descsz, _ntype = struct.unpack_from(endian + "III", blob, off)
        off += 12
        name_end = off + namesz
        desc_start = name_end + (-name_end % 4)
        desc_end = desc_start + descsz
        if desc_end > len(blob):
            return None
        if blob[off:name_end].rstrip(b"\x00") == b"VMCOREINFO":
            match = _BUILD_ID_LINE.search(blob[desc_start:desc_end])
            if match is not None:
                return match.group(1).decode("ascii").lower()
        off = desc_end + (-desc_end % 4)
    return None


def read_vmcore_build_id(path: Path) -> str:
    """Return the lower-case hex kernel build-id from an ELF vmcore's VMCOREINFO.

    Raises:
        VmcoreFormatUnsupported: the file is not an ELF container.
        VmcoreBuildIdError: the ELF is truncated/unreadable.
        VmcoreBuildIdAbsent: the ELF carries no ``VMCOREINFO BUILD-ID``.
    """
    try:
        with path.open("rb") as fh:
            ident = fh.read(16)
            if ident[:4] != b"\x7fELF":
                raise VmcoreFormatUnsupported("vmcore is not an ELF container")
            if len(ident) < 16:
                raise VmcoreBuildIdError("ELF ident truncated")
            ei_class, ei_data = ident[4], ident[5]
            if ei_class not in (1, 2) or ei_data not in (1, 2):
                raise VmcoreBuildIdError("unsupported ELF class/endianness")
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
                raise VmcoreBuildIdAbsent("vmcore has no program headers")
            min_phentsize = 56 if is64 else 32
            if e_phentsize < min_phentsize:
                raise VmcoreBuildIdError(f"implausible e_phentsize {e_phentsize} for {'ELF64' if is64 else 'ELF32'}")
            table_bytes = e_phentsize * e_phnum
            file_size = fh.seek(0, 2)
            if e_phoff + table_bytes > file_size:
                raise VmcoreBuildIdError(
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
                found = _scan_vmcoreinfo(_read_exact(fh, p_offset, p_filesz), endian)
                if found is not None:
                    return found
    except OSError as exc:
        raise VmcoreBuildIdError(f"cannot read {path}: {exc}") from exc
    raise VmcoreBuildIdAbsent("no VMCOREINFO BUILD-ID note found")
