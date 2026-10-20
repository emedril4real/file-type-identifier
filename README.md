# file-type-identifier

A small cross-platform command-line tool that identifies file types from content
signatures (magic bytes), then compares the detected type with the final filename
extension. It does not execute files, open them in another program, or modify them.

## How it works

The scanner reads at most the first 512 bytes to recognize signatures. Longer
signatures are tried before shorter ones so a generic prefix cannot hide a more
specific format. ZIP-based formats are inspected read-only for member names;
files are never extracted. An `MZ` header is called Windows PE only when its
stored PE-header offset points to the expected `PE\0\0` marker; otherwise it is
reported as a weak MZ match. Plain ASCII text and common whitespace are also
recognized.

## Install

Python 3.10 or newer is required. The identifier itself uses only the Python
standard library. Install pytest only if you want to run the tests:

```powershell
python -m pip install -r requirements.txt
```

## Usage

```powershell
python main.py path\to\file
python main.py path\to\folder
python main.py path\to\folder --mismatches-only
python main.py path\to\folder --csv results.csv
python main.py path\to\folder --json
python main.py path\to\folder --hash
```

The tool prints an aligned table and a summary. Exit codes are `0` when no
mismatches or scan errors occur, `1` when at least one mismatch is found, and
`2` when a path cannot be scanned or an output file cannot be written. When
`--hash` is used, SHA-256 is streamed over each complete file; identification
itself remains header-only.

## Supported types

PNG, JPEG, GIF, BMP, PDF, ZIP, RAR, 7-Zip, GZIP, Windows PE (including weak MZ
matches), Linux ELF, OLE2, SQLite, MP3 with an ID3 tag, TAR, DOCX, XLSX, PPTX,
JAR, APK, plain text, and unknown/binary data.

## Add a signature

Add a `Signature` to `SIGNATURES` in `identifier/signatures.py`, providing the
display type name, signature bytes, byte offset, and allowed extensions (include
the leading dot and use lowercase). `SORTED_SIGNATURES` orders entries by
signature length automatically. If the format needs additional validation,
implement it in `identify_content` in `identifier/core.py` and add a harmless
sample and test.

## Known limitations

This is a lightweight identifier, not a full format validator. A matching
header can be forged, and polyglot files or files with appended data may be
misleading. ZIP classification uses archive member names rather than validating
the full internal document format. TAR detection relies on the `ustar` marker at
offset 257, so older TAR variants without that marker are not recognized. Text
detection is limited to printable ASCII and common ASCII whitespace; other
encodings may be labeled unknown. Permission and filesystem behavior also varies
by operating system.

## Tests and harmless samples

Run tests with:

```powershell
python -m pytest
```

Generate harmless fixtures in a directory of your choice (defaults to
`sample-files`):

```powershell
python tests\generate_samples.py sample-files
```

The generated executable-looking sample contains only a synthetic MZ/PE header;
it is not a functional program and must not be executed.

## Future improvements

Possible extensions include richer format validation, configurable extension
maps, Unicode text heuristics, and reporting additional metadata such as file
size and modification time.
