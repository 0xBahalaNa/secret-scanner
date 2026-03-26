"""Command-line interface for the secret scanner.

This module handles argument parsing, input validation, and orchestration.
It's the glue that connects the user's CLI invocation to the scanner core
and output formatters. Separating CLI logic from scanning logic means the
scanner can be imported and used as a library without argparse being involved.

Usage:
    python -m secret_scanner [directory] [--exit-zero] [--patterns FILE] [--output json] [--output-file PATH]
    python -m secret_scanner --files FILE [FILE ...] [--exit-zero]

If no directory is provided, defaults to test_configs/.
Use --files to scan specific files (e.g., from a pre-commit hook).
"""

import argparse
import sys
from pathlib import Path

from . import __version__
from .output.console import print_summary
from .output.json_report import write_json_report
from .patterns import load_all_patterns
from .patterns.custom import load as load_custom_patterns
from .scanner import scan, scan_files


def build_parser():
    """Build and return the argument parser.

    Separated into its own function so it can be tested independently
    and reused if the scanner is embedded in a larger tool.

    Returns:
        An argparse.ArgumentParser configured with all scanner flags.
    """
    parser = argparse.ArgumentParser(
        description="Scan a directory for secrets, credentials, and sensitive patterns."
    )

    # positional argument with a default — the directory to scan.
    # nargs="?" means "zero or one argument," so it's optional.
    parser.add_argument(
        "directory",
        nargs="?",
        default="test_configs",
        help="Path to the directory to scan (default: test_configs/)",
    )

    # --exit-zero: always exit 0, even when findings exist.
    # Useful for informational/audit runs in CI where you want visibility
    # without blocking the pipeline.
    parser.add_argument(
        "--exit-zero",
        action="store_true",
        help="Always exit with code 0, even if alerts are found (informational mode)",
    )

    # --patterns: load additional detection patterns from a JSON file.
    # Custom patterns are merged with (not replacing) the built-in defaults.
    parser.add_argument(
        "--patterns",
        metavar="FILE",
        help="Path to a JSON file with additional detection patterns ({name: regex})",
    )

    # --output: choose an output format for scan results.
    # "json" writes a structured JSON file for OSCAL evidence pipelines.
    parser.add_argument(
        "--output",
        choices=["json"],
        metavar="FORMAT",
        help="Output format for results file: 'json' writes structured JSON (see --output-file)",
    )

    # --output-file: control where JSON results are written.
    # Addresses AU-9 (Protection of Audit Information): previous scan
    # results should not be silently destroyed.
    parser.add_argument(
        "--output-file",
        default="scan_results.json",
        metavar="PATH",
        help="Path for JSON output file (default: scan_results.json). Requires --output json.",
    )

    # --files: scan specific files instead of a directory.
    # Used by pre-commit hooks where only staged files should be scanned.
    # nargs="+" means "one or more arguments" — at least one file is required.
    # The pre-commit framework appends staged file paths after this flag.
    parser.add_argument(
        "--files",
        nargs="+",
        metavar="FILE",
        help="Scan specific files instead of a directory (used by pre-commit hooks)",
    )

    return parser


def main():
    """Entry point for the secret scanner CLI.

    Parses arguments, loads patterns, runs the scan, prints results,
    and exits with the appropriate code. This is the function that
    __main__.py calls.
    """
    parser = build_parser()
    args = parser.parse_args()

    # Build the pattern set: start with built-in, then merge custom.
    patterns = load_all_patterns()

    if args.patterns:
        custom = load_custom_patterns(args.patterns)
        print(f"Loaded {len(custom)} custom pattern(s) from {args.patterns}")
        patterns.update(custom)

    # Two scan modes: --files for specific files (pre-commit hooks),
    # or directory mode (default) for recursive scanning.
    if args.files:
        # File mode: scan only the specified files. Used by pre-commit
        # hooks where only staged files should be scanned for performance.
        print(f"Scanning {len(args.files)} file(s)")
        print(f"Active patterns: {len(patterns)}")
        result = scan_files(args.files, patterns)
        scan_target = "staged files"
    else:
        # Directory mode: scan all files recursively.
        folder = Path(args.directory)

        if not folder.exists():
            print(f"[ERROR] Path does not exist: {folder}")
            sys.exit(1)

        if not folder.is_dir():
            print(f"[ERROR] Path is not a directory: {folder}")
            sys.exit(1)

        print(f"Scanning folder: {folder}")
        print(f"Active patterns: {len(patterns)}")
        result = scan(folder, patterns)
        scan_target = str(folder)

    # Print human-readable summary to console.
    print_summary(result)

    # Write JSON report if requested.
    if args.output == "json":
        write_json_report(
            scan_result=result,
            output_file=args.output_file,
            scanner_version=__version__,
            folder=scan_target,
            patterns_active=len(patterns),
        )

    # Exit with a non-zero code when secrets are found so CI/CD pipelines
    # fail. --exit-zero overrides this for informational/audit-only runs.
    if result["total_findings"] > 0 and not args.exit_zero:
        sys.exit(1)
    else:
        sys.exit(0)
