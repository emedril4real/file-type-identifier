"""Magic-byte signatures and the extensions commonly used for each format."""

from dataclasses import dataclass


@dataclass(frozen=True)
class Signature:
    """A byte signature, its offset, a display name, and allowed extensions."""

    type_name: str
    signature: bytes
    offset: int
    extensions: frozenset[str]


SIGNATURES = (
    Signature("PNG", b"\x89PNG\r\n\x1a\n", 0, frozenset({".png"})),
    Signature("JPEG", b"\xff\xd8\xff", 0, frozenset({".jpg", ".jpeg"})),
    Signature("GIF", b"GIF87a", 0, frozenset({".gif"})),
    Signature("GIF", b"GIF89a", 0, frozenset({".gif"})),
    Signature("BMP", b"BM", 0, frozenset({".bmp"})),
    Signature("PDF", b"%PDF-", 0, frozenset({".pdf"})),
    Signature("ZIP", b"PK\x03\x04", 0, frozenset({".zip"})),
    Signature("ZIP", b"PK\x05\x06", 0, frozenset({".zip"})),
    Signature("ZIP", b"PK\x07\x08", 0, frozenset({".zip"})),
    Signature("RAR", b"Rar!\x1a\x07\x00", 0, frozenset({".rar"})),
    Signature("RAR", b"Rar!\x1a\x07\x01\x00", 0, frozenset({".rar"})),
    Signature("7-Zip", b"7z\xbc\xaf'\x1c", 0, frozenset({".7z"})),
    Signature("GZIP", b"\x1f\x8b", 0, frozenset({".gz", ".gzip"})),
    Signature("Windows PE", b"MZ", 0, frozenset({".exe", ".dll", ".sys"})),
    Signature("Linux ELF", b"\x7fELF", 0, frozenset({".elf", ".so"})),
    Signature("OLE2", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", 0, frozenset({".doc", ".xls", ".ppt", ".msi"})),
    Signature("SQLite", b"SQLite format 3\x00", 0, frozenset({".sqlite", ".sqlite3", ".db"})),
    Signature("MP3", b"ID3", 0, frozenset({".mp3"})),
    Signature("TAR", b"ustar", 257, frozenset({".tar"})),
)

# Longer signatures are checked first so a short prefix cannot take a more
# specific match. Stable sorting preserves the declared order for ties.
SORTED_SIGNATURES = tuple(
    sorted(SIGNATURES, key=lambda item: len(item.signature), reverse=True)
)

ZIP_TYPE_EXTENSIONS = {
    "DOCX": frozenset({".docx"}),
    "XLSX": frozenset({".xlsx"}),
    "PPTX": frozenset({".pptx"}),
    "JAR": frozenset({".jar"}),
    "APK": frozenset({".apk"}),
}

TEXT_EXTENSIONS = frozenset({".txt", ".text", ".csv", ".md", ".log"})
