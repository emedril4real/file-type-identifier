"""Console, CSV, and JSON representations of scan results."""

import csv
import json
from pathlib import Path
import sys
from typing import TextIO

from .core import ScanResult


def _summary(results: list[ScanResult]) -> str:
    mismatches = sum(result.status == "MISMATCH" for result in results)
    no_extension = sum(result.status == "NO EXTENSION" for result in results)
    ok = sum(result.status == "OK" for result in results)
    return (
        f"Scanned {len(results)} file(s): {mismatches} mismatch(es), "
        f"{no_extension} without extension, {ok} OK."
    )


def _visible_results(
    results: list[ScanResult], mismatches_only: bool
) -> list[ScanResult]:
    if mismatches_only:
        return [result for result in results if result.status == "MISMATCH"]
    return results


def print_table(
    results: list[ScanResult],
    mismatches_only: bool = False,
    include_hash: bool = False,
    stream: TextIO = sys.stdout,
) -> None:
    """Print aligned results and the summary, including actionable errors."""
    visible = _visible_results(results, mismatches_only)
    headers = ["FILE", "EXT", "DETECTED TYPE", "STATUS"]
    if include_hash:
        headers.append("SHA-256")
    if any(result.error for result in visible):
        headers.append("ERROR")

    rows = [
        [
            result.path,
            result.extension or "(none)",
            result.detected_type,
            result.status,
            *([result.sha256 or ""] if include_hash else []),
            *([result.error or ""] if "ERROR" in headers else []),
        ]
        for result in visible
    ]
    widths = [
        max(len(headers[index]), *(len(row[index]) for row in rows))
        if rows else len(headers[index])
        for index in range(len(headers))
    ]
    print("  ".join(header.ljust(widths[index]) for index, header in enumerate(headers)), file=stream)
    print("  ".join("-" * width for width in widths), file=stream)
    for row in rows:
        print("  ".join(value.ljust(widths[index]) for index, value in enumerate(row)), file=stream)
    print(_summary(results), file=stream)
    error_count = sum(result.status == "ERROR" for result in results)
    if error_count:
        print(f"Errors: {error_count}.", file=stream)


def write_csv(
    path: Path,
    results: list[ScanResult],
    mismatches_only: bool = False,
) -> None:
    """Write scan results to CSV, including hashes and error details when present."""
    visible = _visible_results(results, mismatches_only)
    fields = ["file", "extension", "detected_type", "status", "sha256", "error"]
    with path.open("w", newline="", encoding="utf-8") as output:
        writer = csv.DictWriter(output, fieldnames=fields)
        writer.writeheader()
        for result in visible:
            writer.writerow(
                {
                    "file": result.path,
                    "extension": result.extension,
                    "detected_type": result.detected_type,
                    "status": result.status,
                    "sha256": result.sha256 or "",
                    "error": result.error or "",
                }
            )


def print_json(
    results: list[ScanResult],
    mismatches_only: bool = False,
    stream: TextIO = sys.stdout,
) -> None:
    """Print machine-readable results with totals based on the complete scan."""
    visible = _visible_results(results, mismatches_only)
    payload = {
        "summary": _summary(results),
        "results": [
            {
                "file": result.path,
                "extension": result.extension,
                "detected_type": result.detected_type,
                "status": result.status,
                "sha256": result.sha256,
                "error": result.error,
            }
            for result in visible
        ],
    }
    json.dump(payload, stream, indent=2)
    print(file=stream)
