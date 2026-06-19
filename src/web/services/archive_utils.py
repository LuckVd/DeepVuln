"""Safe archive extraction with path-traversal (zip-slip / tar-slip) protection.

Drop-in replacement for ``shutil.unpack_archive`` that validates every member
path stays within the destination directory. Works on Python 3.10+ (does not
rely on the 3.12 ``filter`` argument). Supports zip and tar/tar.gz/tar.bz2;
other formats raise to avoid silent, un-validated extraction.
"""

from __future__ import annotations

import os
import tarfile
import zipfile
from pathlib import Path


def _is_within(member_path: str, base: str) -> bool:
    """True if member_path resolves inside base (no traversal escape)."""
    target = os.path.realpath(os.path.join(base, member_path))
    return target == base or target.startswith(base + os.sep)


def safe_unpack_archive(filename: str | Path, extract_dir: str | Path) -> None:
    """Extract ``filename`` into ``extract_dir``, rejecting path traversal.

    Raises:
        ValueError: if the archive is unsupported or contains an entry that
            would escape ``extract_dir`` (zip-slip / tar-slip).
    """
    base = os.path.realpath(str(extract_dir))
    os.makedirs(base, exist_ok=True)
    filename = str(filename)

    if zipfile.is_zipfile(filename):
        with zipfile.ZipFile(filename) as zf:
            for name in zf.namelist():
                if name.endswith("/"):
                    continue
                if not _is_within(name, base):
                    raise ValueError(f"Refusing to extract unsafe path: {name}")
            zf.extractall(base)
        return

    if tarfile.is_tarfile(filename):
        with tarfile.open(filename) as tf:
            for member in tf.getmembers():
                if not _is_within(member.name, base):
                    raise ValueError(f"Refusing to extract unsafe path: {member.name}")
                # Reject device/symlink members pointing outside the destination
                if member.issym() or member.isdev():
                    if not _is_within(member.linkname, base):
                        raise ValueError(
                            f"Refusing to extract unsafe link target: {member.linkname}"
                        )
            tf.extractall(base)
        return

    raise ValueError(f"Unsupported archive format (use zip/tar): {filename}")
