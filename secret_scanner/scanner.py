"""Core scanning logic for the secret scanner.

This module contains the scan() function — the heart of the scanner. It
takes a directory and a set of patterns, iterates through every file
recursively, and returns structured results. The scan logic is separated
from CLI parsing and output formatting so it can be:
  1. Called from the CLI (python -m secret_scanner)
  2. Imported into other Python scripts (from secret_scanner.scanner import scan)
  3. Tested in isolation (test_scanner.py)

This separation of concerns is the primary goal of the modular refactor.
"""

import time
from pathlib import Path

from .output.console import print_alert, print_skip
from .patterns import CONTROL_MAP, SEVERITY_MAP

# Resource limits to prevent the scanner from consuming excessive memory
# on unusually large files. Config files and source code are typically
# well under these thresholds — anything larger is likely a binary file
# that passed UTF-8 decoding or a data dump that shouldn't be scanned.
# These limits address SC-5 (Denial of Service Protection): a compliance
# tool in a CA-7 continuous monitoring pipeline must not be OOM-killable.
MAX_FILE_SIZE = 10 * 1024 * 1024    # 10 MB — skip files larger than this
MAX_LINE_LENGTH = 1 * 1024 * 1024   # 1 MB — skip individual lines longer than this


def scan(directory, patterns):
    """Scan a directory recursively for secrets matching the given patterns.

    This is the core function that the CLI calls. It walks every file in
    the directory tree, reads each line, and tests it against all patterns.
    Results are returned as a dict — the caller decides what to do with them
    (print to console, write JSON, feed into OSCAL pipeline, etc.).

    The function handles three error cases gracefully:
    - Symlinks pointing outside the scan directory (AC-6: Least Privilege)
    - Files too large to scan safely (SC-5: DoS Protection)
    - Binary files that can't be decoded as text (UnicodeDecodeError)
    - Permission-denied files (PermissionError)

    Args:
        directory: Path object pointing to the directory to scan.
        patterns: Dict of {name: compiled regex} patterns to match against.

    Returns:
        A dict containing:
        - findings: list of finding dicts (file_path, line_number, etc.)
        - total_files_scanned: int
        - total_findings: int
        - files_with_findings: int
        - skipped_files: int
        - directories_scanned: int
        - scan_duration: float (seconds, rounded to 3 decimal places)
        - affected_files: sorted list of relative path strings
    """
    folder = Path(directory)

    # Resolve the scan root for symlink escape detection.
    resolved_root = folder.resolve()

    # Counters and accumulators.
    findings = []
    files_with_issues = set()
    skipped_files = 0
    directories_scanned = set()
    total_files_scanned = 0

    scan_start = time.time()

    # Iterates recursively through every file inside directory and its
    # subdirectories. is_file() filters out directories.
    for item in folder.rglob("*"):
        if not item.is_file():
            continue

        # Symlink escape check: resolve the file to its real absolute path
        # and verify it's still under the scan root. A symlink pointing to
        # /etc/shadow or another file outside the target directory would
        # resolve to a path that doesn't start with resolved_root — skip it.
        resolved_item = item.resolve()
        if not str(resolved_item).startswith(str(resolved_root)):
            print_skip(item, "Symlink points outside scan directory.")
            skipped_files += 1
            continue

        total_files_scanned += 1
        directories_scanned.add(item.parent)

        # Build the display path relative to the scan root.
        relative_path = item.relative_to(folder)

        # File size check: skip files larger than MAX_FILE_SIZE.
        try:
            file_size = item.stat().st_size
        except OSError:
            print_skip(relative_path, "Could not read file metadata.")
            skipped_files += 1
            continue

        if file_size > MAX_FILE_SIZE:
            print_skip(
                relative_path,
                f"File exceeds {MAX_FILE_SIZE // (1024 * 1024)}MB size limit."
            )
            skipped_files += 1
            continue

        found_issue = False

        # Read the file line-by-line using enumerate() for 1-indexed line
        # numbers. Line-level reporting satisfies AU-3 (Content of Audit
        # Records): analysts need to know exactly where a finding is.
        try:
            with open(item, "r") as f:
                for line_number, line in enumerate(f, start=1):
                    # Skip extremely long lines (e.g., minified JS/JSON).
                    if len(line) > MAX_LINE_LENGTH:
                        continue

                    for pattern_name, pattern_regex in patterns.items():
                        if pattern_regex.search(line):
                            severity = SEVERITY_MAP.get(pattern_name, "MEDIUM")
                            print_alert(relative_path, line_number, pattern_name, severity)
                            found_issue = True

                            findings.append({
                                "file_path": str(relative_path),
                                "line_number": line_number,
                                "finding_type": pattern_name,
                                "pattern_matched": pattern_regex.pattern,
                                "severity": severity,
                                "control_ids": CONTROL_MAP.get(pattern_name, []),
                            })

        except UnicodeDecodeError:
            print_skip(relative_path, "The file type is not compatible.")
            skipped_files += 1
            continue
        except PermissionError:
            print_skip(
                relative_path,
                "You do not have the necessary permissions for this file."
            )
            skipped_files += 1
            continue

        if found_issue:
            files_with_issues.add(str(relative_path))

    scan_duration = round(time.time() - scan_start, 3)

    return {
        "findings": findings,
        "total_files_scanned": total_files_scanned,
        "total_findings": len(findings),
        "files_with_findings": len(files_with_issues),
        "skipped_files": skipped_files,
        "directories_scanned": len(directories_scanned),
        "scan_duration": scan_duration,
        "affected_files": sorted(files_with_issues),
    }
