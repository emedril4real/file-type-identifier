"""Command-line entry point for file-type-identifier."""

import argparse
from pathlib import Path
import sys

from identifier.report import print_json, print_table, write_csv
from identifier.scanner import scan_path


def build_parser() -> argparse.ArgumentParser:
    """Create the command-line argument parser."""
    parser = argparse.ArgumentParser(
        description="Identify files by their content and flag extension mismatches."
    )
    parser.add_argument("file_or_folder", type=Path, help="file or folder to scan")
    parser.add_argument("--csv", type=Path, metavar="PATH", help="save results to CSV")
    parser.add_argument(
        "--mismatches-only",
        action="store_true",
        help="show or export only extension mismatches",
    )
    parser.add_argument("--json", action="store_true", help="print results as JSON")
    parser.add_argument(
        "--hash", action="store_true", help="calculate a SHA-256 hash for each file"
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run the scan and return the documented process exit status."""
    arguments = build_parser().parse_args(argv)
    results = scan_path(arguments.file_or_folder, include_hash=arguments.hash)

    try:
        if arguments.csv:
            write_csv(arguments.csv, results, arguments.mismatches_only)
    except OSError as error:
        print(f"Could not write CSV file: {error}", file=sys.stderr)
        return 2

    if arguments.json:
        print_json(results, arguments.mismatches_only)
    else:
        print_table(results, arguments.mismatches_only, arguments.hash)

    if any(result.status == "ERROR" for result in results):
        return 2
    if any(result.status == "MISMATCH" for result in results):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
