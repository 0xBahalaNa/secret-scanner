"""Core scanning logic for the secret scanner.

This module contains two scan functions:
  - scan(directory, patterns) — recursively scans all files in a directory
  - scan_files(file_paths, patterns) — scans a specific list of files

The scan logic is separated from CLI parsing and output formatting so it
can be:
  1. Called from the CLI (python -m secret_scanner)
  2. Used as a pre-commit hook (python -m secret_scanner --files ...)
  3. Imported into other Python scripts (from secret_scanner.scanner import scan)
  4. Tested in isolation (test_scanner.py)

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
    total_bytes_scanned = 0

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

        # Accumulate bytes for throughput metrics. Only counts files that
        # pass all pre-scan checks (not skipped for size, symlink, etc.).
        total_bytes_scanned += file_size

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

    # Throughput metrics: files per second and bytes per second.
    # Guard against zero-division when scan completes in under 1ms
    # (common for small test directories).
    files_per_second = round(total_files_scanned / scan_duration, 1) if scan_duration > 0 else 0
    bytes_per_second = round(total_bytes_scanned / scan_duration, 1) if scan_duration > 0 else 0

    return {
        "findings": findings,
        "total_files_scanned": total_files_scanned,
        "total_findings": len(findings),
        "files_with_findings": len(files_with_issues),
        "skipped_files": skipped_files,
        "directories_scanned": len(directories_scanned),
        "scan_duration": scan_duration,
        "total_bytes_scanned": total_bytes_scanned,
        "files_per_second": files_per_second,
        "bytes_per_second": bytes_per_second,
        "affected_files": sorted(files_with_issues),
    }


def scan_files(file_paths, patterns):
    """Scan a specific list of files for secrets matching the given patterns.

    This is the function used by pre-commit hooks, where only staged files
    should be scanned — not the entire directory. It applies the same
    pattern matching and error handling as scan(), but iterates over an
    explicit list of file paths instead of recursing a directory.

    No symlink escape check is performed here because the caller (the
    pre-commit framework or the standalone hook script) controls which
    files are passed. The file size and line length limits still apply.

    Args:
        file_paths: List of path strings to scan.
        patterns: Dict of {name: compiled regex} patterns to match against.

    Returns:
        A dict with the same structure as scan() — findings, counts, etc.
    """
    findings = []
    files_with_issues = set()
    skipped_files = 0
    directories_scanned = set()
    total_files_scanned = 0
    total_bytes_scanned = 0

    scan_start = time.time()

    for file_path_str in file_paths:
        item = Path(file_path_str)

        if not item.is_file():
            print_skip(file_path_str, "Not a file or does not exist.")
            skipped_files += 1
            continue

        total_files_scanned += 1
        directories_scanned.add(item.parent)

        # File size check.
        try:
            file_size = item.stat().st_size
        except OSError:
            print_skip(file_path_str, "Could not read file metadata.")
            skipped_files += 1
            continue

        if file_size > MAX_FILE_SIZE:
            print_skip(
                file_path_str,
                f"File exceeds {MAX_FILE_SIZE // (1024 * 1024)}MB size limit."
            )
            skipped_files += 1
            continue

        total_bytes_scanned += file_size

        found_issue = False

        try:
            with open(item, "r") as f:
                for line_number, line in enumerate(f, start=1):
                    if len(line) > MAX_LINE_LENGTH:
                        continue

                    for pattern_name, pattern_regex in patterns.items():
                        if pattern_regex.search(line):
                            severity = SEVERITY_MAP.get(pattern_name, "MEDIUM")
                            print_alert(file_path_str, line_number, pattern_name, severity)
                            found_issue = True

                            findings.append({
                                "file_path": file_path_str,
                                "line_number": line_number,
                                "finding_type": pattern_name,
                                "pattern_matched": pattern_regex.pattern,
                                "severity": severity,
                                "control_ids": CONTROL_MAP.get(pattern_name, []),
                            })

        except UnicodeDecodeError:
            print_skip(file_path_str, "The file type is not compatible.")
            skipped_files += 1
            continue
        except PermissionError:
            print_skip(
                file_path_str,
                "You do not have the necessary permissions for this file."
            )
            skipped_files += 1
            continue

        if found_issue:
            files_with_issues.add(file_path_str)

    scan_duration = round(time.time() - scan_start, 3)
    files_per_second = round(total_files_scanned / scan_duration, 1) if scan_duration > 0 else 0
    bytes_per_second = round(total_bytes_scanned / scan_duration, 1) if scan_duration > 0 else 0

    return {
        "findings": findings,
        "total_files_scanned": total_files_scanned,
        "total_findings": len(findings),
        "files_with_findings": len(files_with_issues),
        "skipped_files": skipped_files,
        "directories_scanned": len(directories_scanned),
        "scan_duration": scan_duration,
        "total_bytes_scanned": total_bytes_scanned,
        "files_per_second": files_per_second,
        "bytes_per_second": bytes_per_second,
        "affected_files": sorted(files_with_issues),
    }
