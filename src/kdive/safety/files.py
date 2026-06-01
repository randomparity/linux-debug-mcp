from __future__ import annotations

import contextlib
import os
import uuid
from pathlib import Path


def atomic_write_text(path: Path, text: str) -> None:
    """Write UTF-8 text through a sibling temp file and atomic rename."""
    temp_path = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    temp_fd = os.open(temp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(temp_fd, "w", encoding="utf-8") as temp_file:
            temp_file.write(text)
            temp_file.flush()
        os.replace(temp_path, path)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            temp_path.unlink()
        raise
