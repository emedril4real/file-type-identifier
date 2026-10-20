"""Single-file and recursive directory scanning."""

import os
from pathlib import Path

from .core import ScanResult, identify_file


def scan_path(path: Path, include_hash: bool = False) -> list[ScanResult]:
    """Scan a file or all files below a directory without following symlink dirs."""
    if path.is_file():
        return [identify_file(path, include_hash)]
    if not path.is_dir():
        return [
            ScanResult(
                str(path), path.suffix.lower(), "Unavailable", "ERROR",
                error="Path does not exist or is not a regular file or directory.",
            )
        ]

    results: list[ScanResult] = []

    def record_walk_error(error: OSError) -> None:
        results.append(
            ScanResult(
                str(error.filename or path),
                "",
                "Unreadable directory",
                "ERROR",
                error=str(error),
            )
        )

    for root, _, filenames in os.walk(path, onerror=record_walk_error):
        for filename in filenames:
            results.append(identify_file(Path(root) / filename, include_hash))
    return results
