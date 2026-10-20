"""Generate harmless sample files for exercising the identifier."""

import argparse
import io
from pathlib import Path
import sqlite3
import tarfile
import zipfile


def _write_zip(path: Path, members: dict[str, bytes]) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        for name, content in members.items():
            archive.writestr(name, content)


def generate_samples(destination: Path) -> None:
    """Create test fixtures containing signatures, not executable payloads."""
    destination.mkdir(parents=True, exist_ok=True)
    (destination / "sample.png").write_bytes(
        b"\x89PNG\r\n\x1a\n" + b"\x00" * 32
    )
    (destination / "sample.jpg").write_bytes(b"\xff\xd8\xff\xd9")
    (destination / "sample.gif").write_bytes(
        b"GIF89a" + b"\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff"
        + b"\x2c" + b"\x00" * 9 + b"\x02\x00\x3b"
    )
    (destination / "sample.bmp").write_bytes(b"BM" + b"\x00" * 30)
    (destination / "sample.pdf").write_bytes(b"%PDF-1.4\n% harmless sample\n")
    _write_zip(destination / "sample.zip", {"readme.txt": b"harmless"})
    (destination / "sample.rar").write_bytes(b"Rar!\x1a\x07\x00")
    (destination / "sample.7z").write_bytes(b"7z\xbc\xaf'\x1c")
    (destination / "sample.gz").write_bytes(b"\x1f\x8b\x08\x00")

    pe_header = bytearray(128)
    pe_header[:2] = b"MZ"
    pe_header[0x3C:0x40] = (64).to_bytes(4, "little")
    pe_header[64:68] = b"PE\x00\x00"
    (destination / "sample.exe").write_bytes(pe_header)

    elf_header = bytearray(64)
    elf_header[:16] = b"\x7fELF\x02\x01\x01" + b"\x00" * 9
    (destination / "sample.elf").write_bytes(elf_header)
    (destination / "sample.doc").write_bytes(
        b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 24
    )
    sqlite_path = destination / "sample.sqlite"
    connection = sqlite3.connect(sqlite_path)
    try:
        connection.execute("CREATE TABLE sample (value TEXT)")
        connection.commit()
    finally:
        connection.close()
    (destination / "sample.mp3").write_bytes(
        b"ID3\x03\x00\x00\x00\x00\x00\x00"
    )

    tar_path = destination / "sample.tar"
    with tarfile.open(tar_path, "w") as archive:
        member = tarfile.TarInfo("sample.txt")
        content = b"harmless"
        member.size = len(content)
        archive.addfile(member, io.BytesIO(content))

    _write_zip(destination / "sample.docx", {"word/document.xml": b"<document/>"})
    _write_zip(destination / "sample.xlsx", {"xl/workbook.xml": b"<workbook/>"})
    _write_zip(destination / "sample.pptx", {"ppt/presentation.xml": b"<presentation/>"})
    _write_zip(destination / "sample.jar", {"META-INF/MANIFEST.MF": b"Manifest-Version: 1.0"})
    _write_zip(destination / "sample.apk", {"AndroidManifest.xml": b"<manifest/>"})


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "destination",
        type=Path,
        nargs="?",
        default=Path("sample-files"),
        help="directory where harmless sample files are written",
    )
    generate_samples(parser.parse_args().destination)


if __name__ == "__main__":
    main()
