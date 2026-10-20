"""File reading, content-based identification, and extension comparison."""

from dataclasses import dataclass
import hashlib
from pathlib import Path
import struct
import zipfile

from .signatures import (
    SORTED_SIGNATURES,
    TEXT_EXTENSIONS,
    ZIP_TYPE_EXTENSIONS,
)

HEADER_SIZE = 512


@dataclass(frozen=True)
class Detection:
    """The content-derived type and extensions accepted for that type."""

    type_name: str
    allowed_extensions: frozenset[str]
    weak_match: bool = False


@dataclass(frozen=True)
class ScanResult:
    """One file's detection outcome and any error encountered while scanning."""

    path: str
    extension: str
    detected_type: str
    status: str
    sha256: str | None = None
    error: str | None = None


def _is_plain_text(header: bytes) -> bool:
    """Return whether the non-empty header contains only printable ASCII."""
    return bool(header) and all(
        byte in (9, 10, 11, 12, 13) or 32 <= byte <= 126 for byte in header
    )


def _zip_type(path: Path) -> Detection | None:
    """Identify common ZIP-based formats from their member names, without extraction."""
    try:
        with zipfile.ZipFile(path) as archive:
            names = set(archive.namelist())
    except zipfile.BadZipFile:
        return None

    if any(name.startswith("word/") for name in names):
        type_name = "DOCX"
    elif any(name.startswith("xl/") for name in names):
        type_name = "XLSX"
    elif any(name.startswith("ppt/") for name in names):
        type_name = "PPTX"
    elif any(name.upper() == "META-INF/MANIFEST.MF" for name in names):
        type_name = "JAR"
    elif "AndroidManifest.xml" in names:
        type_name = "APK"
    else:
        return None

    return Detection(type_name, ZIP_TYPE_EXTENSIONS[type_name])


def identify_content(header: bytes, path: Path | None = None) -> Detection:
    """Identify content from its first 512 bytes and validate select formats."""
    for item in SORTED_SIGNATURES:
        end = item.offset + len(item.signature)
        if header[item.offset:end] != item.signature:
            continue

        if item.type_name == "Windows PE":
            # The MZ header stores the PE-header offset at byte 0x3C.
            if len(header) >= 0x40:
                pe_offset = struct.unpack_from("<I", header, 0x3C)[0]
                if header[pe_offset:pe_offset + 4] == b"PE\x00\x00":
                    return Detection(item.type_name, item.extensions)
            return Detection("MZ (weak match)", item.extensions, weak_match=True)

        if item.type_name == "ZIP" and path is not None:
            deeper_type = _zip_type(path)
            if deeper_type is not None:
                return deeper_type

        return Detection(item.type_name, item.extensions)

    if _is_plain_text(header):
        return Detection("Plain text", TEXT_EXTENSIONS)
    return Detection("Unknown / binary data", frozenset())


def _calculate_sha256(path: Path) -> str:
    """Hash a file in chunks when the caller explicitly requests a hash."""
    digest = hashlib.sha256()
    with path.open("rb") as file_handle:
        for chunk in iter(lambda: file_handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def identify_file(path: Path, include_hash: bool = False) -> ScanResult:
    """Read a file header, determine its type, and compare its final extension."""
    extension = path.suffix.lower()
    try:
        with path.open("rb") as file_handle:
            header = file_handle.read(HEADER_SIZE)
        detection = identify_content(header, path)
        if not header:
            detection = Detection("Empty file", frozenset())
        sha256 = _calculate_sha256(path) if include_hash else None
    except OSError as error:
        return ScanResult(
            str(path), extension, "Unreadable", "ERROR", error=str(error)
        )

    if not extension:
        status = "NO EXTENSION"
    elif extension in detection.allowed_extensions:
        status = "OK"
    else:
        status = "MISMATCH"

    return ScanResult(
        str(path),
        extension,
        detection.type_name,
        status,
        sha256=sha256,
    )
