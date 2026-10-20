"""Tests for signature recognition, extension checks, and recursive scanning."""

from pathlib import Path

import pytest

from identifier.core import identify_file
from identifier.scanner import scan_path
from main import main
from tests.generate_samples import generate_samples


@pytest.fixture
def samples(tmp_path: Path) -> Path:
    sample_dir = tmp_path / "samples"
    generate_samples(sample_dir)
    return sample_dir


@pytest.mark.parametrize(
    ("filename", "expected"),
    [
        ("sample.png", "PNG"),
        ("sample.jpg", "JPEG"),
        ("sample.gif", "GIF"),
        ("sample.bmp", "BMP"),
        ("sample.pdf", "PDF"),
        ("sample.zip", "ZIP"),
        ("sample.rar", "RAR"),
        ("sample.7z", "7-Zip"),
        ("sample.gz", "GZIP"),
        ("sample.exe", "Windows PE"),
        ("sample.elf", "Linux ELF"),
        ("sample.doc", "OLE2"),
        ("sample.sqlite", "SQLite"),
        ("sample.mp3", "MP3"),
        ("sample.tar", "TAR"),
        ("sample.docx", "DOCX"),
        ("sample.xlsx", "XLSX"),
        ("sample.pptx", "PPTX"),
        ("sample.jar", "JAR"),
        ("sample.apk", "APK"),
    ],
)
def test_identifies_sample_formats(
    samples: Path, filename: str, expected: str
) -> None:
    result = identify_file(samples / filename)
    assert result.detected_type == expected
    assert result.status == "OK"


def test_png_renamed_to_pdf_is_mismatch(tmp_path: Path) -> None:
    path = tmp_path / "image.pdf"
    path.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 10)
    result = identify_file(path)
    assert (result.detected_type, result.status) == ("PNG", "MISMATCH")


def test_text_renamed_to_jpg_is_mismatch(tmp_path: Path) -> None:
    path = tmp_path / "notes.jpg"
    path.write_text("plain harmless text\n", encoding="ascii")
    result = identify_file(path)
    assert (result.detected_type, result.status) == ("Plain text", "MISMATCH")


def test_xlsx_renamed_to_docx_is_mismatch(samples: Path, tmp_path: Path) -> None:
    path = tmp_path / "renamed.docx"
    path.write_bytes((samples / "sample.xlsx").read_bytes())
    result = identify_file(path)
    assert (result.detected_type, result.status) == ("XLSX", "MISMATCH")


def test_empty_file_is_detected_without_crashing(tmp_path: Path) -> None:
    path = tmp_path / "empty.bin"
    path.touch()
    result = identify_file(path)
    assert (result.detected_type, result.status) == ("Empty file", "MISMATCH")


def test_two_byte_file_is_detected_without_crashing(tmp_path: Path) -> None:
    path = tmp_path / "tiny.bin"
    path.write_bytes(b"\x00\x01")
    result = identify_file(path)
    assert result.detected_type == "Unknown / binary data"


def test_uppercase_extension_is_case_insensitive(tmp_path: Path) -> None:
    path = tmp_path / "image.PNG"
    path.write_bytes(b"\x89PNG\r\n\x1a\n")
    assert identify_file(path).status == "OK"


def test_file_without_extension(tmp_path: Path) -> None:
    path = tmp_path / "no-extension"
    path.write_bytes(b"%PDF-1.7")
    result = identify_file(path)
    assert (result.detected_type, result.status) == ("PDF", "NO EXTENSION")


def test_double_extension_uses_final_extension(tmp_path: Path) -> None:
    path = tmp_path / "report.pdf.txt"
    path.write_text("plain text", encoding="ascii")
    result = identify_file(path)
    assert result.extension == ".txt"
    assert result.status == "OK"


def test_recursive_scan_includes_nested_files(samples: Path, tmp_path: Path) -> None:
    nested = samples / "nested" / "deeper"
    nested.mkdir(parents=True)
    nested_file = nested / "nested.png"
    nested_file.write_bytes(b"\x89PNG\r\n\x1a\n")
    results = scan_path(samples)
    assert any(Path(result.path) == nested_file for result in results)


def test_bad_pe_header_is_reported_as_weak_match(tmp_path: Path) -> None:
    path = tmp_path / "weak.exe"
    path.write_bytes(b"MZ" + b"\x00" * 62)
    result = identify_file(path)
    assert result.detected_type == "MZ (weak match)"
    assert result.status == "OK"


def test_hash_is_optional_and_matches_sha256(tmp_path: Path) -> None:
    path = tmp_path / "hash.txt"
    path.write_text("test", encoding="ascii")
    result = identify_file(path, include_hash=True)
    assert result.sha256 == "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"


def test_cli_exit_codes(tmp_path: Path) -> None:
    matching = tmp_path / "matching.png"
    matching.write_bytes(b"\x89PNG\r\n\x1a\n")
    mismatch = tmp_path / "mismatch.pdf"
    mismatch.write_bytes(b"\x89PNG\r\n\x1a\n")

    assert main([str(matching)]) == 0
    assert main([str(mismatch)]) == 1
    assert main([str(tmp_path / "missing.bin")]) == 2


def test_csv_output_contains_scan_results(tmp_path: Path) -> None:
    target = tmp_path / "sample.png"
    target.write_bytes(b"\x89PNG\r\n\x1a\n")
    output = tmp_path / "results.csv"

    assert main([str(target), "--csv", str(output)]) == 0
    contents = output.read_text(encoding="utf-8")
    assert "detected_type" in contents
    assert "PNG" in contents
