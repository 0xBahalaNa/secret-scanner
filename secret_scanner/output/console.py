"""Console (human-readable) output formatter for the secret scanner.

This module handles all print-based output: real-time alerts as they're
found, skip messages for problematic files, and the final scan summary.
Separating output from scanning logic means the scanner doesn't need to
know how results are displayed — it just returns data.
"""


def _format_bytes(num_bytes):
    """Format a byte count as a human-readable string (e.g., 1.2 KB, 3.4 MB).

    Uses 1024-based units (KiB convention but labeled KB/MB for readability).
    This is a private helper — the underscore prefix is a Python convention
    meaning "internal to this module, not part of the public API."

    Args:
        num_bytes: Integer or float byte count.

    Returns:
        A formatted string like "1.2 KB" or "3.4 MB".
    """
    if num_bytes < 1024:
        return f"{num_bytes} B"
    elif num_bytes < 1024 * 1024:
        return f"{num_bytes / 1024:.1f} KB"
    else:
        return f"{num_bytes / (1024 * 1024):.1f} MB"


def print_alert(relative_path, line_number, pattern_name, severity):
    """Print a single finding alert to the console.

    Format: [SEVERITY] path/to/file:line_number — Pattern Name

    The severity level replaces the generic [ALERT] tag so analysts can
    visually scan output for CRITICAL findings. The path:line_number
    format is deliberate — many editors and terminals make this clickable,
    jumping directly to the finding location.

    Args:
        relative_path: File path relative to the scan root.
        line_number: 1-indexed line number where the pattern matched.
        pattern_name: Human-readable name of the matched pattern.
        severity: Severity level string (CRITICAL, HIGH, MEDIUM, LOW, INFO).
    """
    print(f"[{severity}] {relative_path}:{line_number} — {pattern_name}")


def print_skip(relative_path, reason):
    """Print a skip message when a file can't be scanned.

    Args:
        relative_path: File path relative to the scan root.
        reason: Human-readable reason the file was skipped.
    """
    print(f"[SKIP] {relative_path}: {reason}")


def print_summary(scan_result):
    """Print the final scan summary to the console.

    Includes a severity breakdown so analysts get an at-a-glance risk
    picture. This supports RA-3 (Risk Assessment) by surfacing how many
    findings fall into each severity tier.

    Args:
        scan_result: A dict containing scan results with keys:
            - directories_scanned: int
            - total_files_scanned: int
            - total_findings: int
            - files_with_findings: int
            - skipped_files: int
            - scan_duration: float (seconds)
            - affected_files: sorted list of relative path strings
            - findings: list of finding dicts (each with "severity" key)
    """
    print("\n--- Scan Summary ---")
    print(f"Directories scanned: {scan_result['directories_scanned']}")
    print(f"Files scanned: {scan_result['total_files_scanned']}")
    print(f"Total alerts: {scan_result['total_findings']}")
    print(f"Files with issues: {scan_result['files_with_findings']}")
    print(f"Skipped files: {scan_result['skipped_files']}")
    print(f"Scan duration: {scan_result['scan_duration']}s")

    # Performance metrics: bytes scanned and throughput.
    # _format_bytes converts raw byte counts to human-readable units.
    total_bytes = scan_result.get("total_bytes_scanned", 0)
    print(f"Bytes scanned: {_format_bytes(total_bytes)}")
    files_per_sec = scan_result.get("files_per_second", 0)
    bytes_per_sec = scan_result.get("bytes_per_second", 0)
    if files_per_sec > 0:
        print(f"Throughput: {files_per_sec} files/s, {_format_bytes(bytes_per_sec)}/s")

    # Severity breakdown: count findings by severity level.
    # Uses dict.get() with a default of 0 (PCC3e Ch 6: Dictionaries).
    # The severity order is fixed (CRITICAL first) so the output is
    # always consistent regardless of which severities appear.
    if scan_result["findings"]:
        severity_counts = {}
        for finding in scan_result["findings"]:
            sev = finding["severity"]
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        print("Severity breakdown:")
        for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            count = severity_counts.get(level, 0)
            if count > 0:
                print(f"  {level}: {count}")

    if scan_result["affected_files"]:
        print("Affected files:")
        for fname in scan_result["affected_files"]:
            print(f" - {fname}")
