"""JSON output formatter for the secret scanner.

Produces structured JSON files that can feed into OSCAL evidence pipelines
or compliance dashboards. The output structure has three sections:
  1. scan_metadata — who/what/when context for the scan
  2. findings — individual finding records with control mappings
  3. summary — aggregate counts for quick assessment

This supports CA-2 (Control Assessments) by producing machine-readable
assessment evidence, and CA-7 (Continuous Monitoring) by enabling
automated trend analysis across scans.
"""

import json
from datetime import datetime, timezone
from pathlib import Path


def write_json_report(scan_result, output_file, scanner_version, folder,
                      patterns_active):
    """Write scan results to a structured JSON file.

    The JSON schema includes metadata (timestamp, version, duration),
    individual findings with control IDs, and aggregate summary counts.
    This is the foundation for OSCAL evidence pipelines — machine-readable
    output that can be transformed into OSCAL Assessment Results format
    (see: FedRAMP 20x requirements).

    Args:
        scan_result: Dict containing findings list and summary counts.
        output_file: Path string for the output JSON file.
        scanner_version: Version string for metadata.
        folder: The scanned directory path (for metadata).
        patterns_active: Number of active patterns (for metadata).
    """
    # Build findings_by_type and findings_by_severity: dicts of {key: count}.
    # These use simple loops instead of collections.Counter — both work,
    # but the explicit loop is easier to follow when you're learning Python.
    findings_by_type = {}
    findings_by_severity = {}
    for finding in scan_result["findings"]:
        finding_type = finding["finding_type"]
        findings_by_type[finding_type] = findings_by_type.get(finding_type, 0) + 1

        severity = finding["severity"]
        findings_by_severity[severity] = findings_by_severity.get(severity, 0) + 1

    # datetime.now(timezone.utc) returns the current time in UTC with timezone
    # info attached. .isoformat() formats it as ISO 8601 (e.g.,
    # "2026-03-19T14:30:00+00:00"), which is the standard for machine-readable
    # timestamps. UTC avoids timezone ambiguity in compliance evidence.
    json_output = {
        "scan_metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "target_directory": str(folder),
            "scanner_version": scanner_version,
            "duration_seconds": scan_result["scan_duration"],
            "patterns_active": patterns_active,
            "total_bytes_scanned": scan_result.get("total_bytes_scanned", 0),
            "files_per_second": scan_result.get("files_per_second", 0),
            "bytes_per_second": scan_result.get("bytes_per_second", 0),
        },
        "findings": scan_result["findings"],
        "summary": {
            "total_files_scanned": scan_result["total_files_scanned"],
            "total_findings": scan_result["total_findings"],
            "files_with_findings": scan_result["files_with_findings"],
            "skipped_files": scan_result["skipped_files"],
            "findings_by_type": findings_by_type,
            "findings_by_severity": findings_by_severity,
        },
    }

    output_path = Path(output_file)

    # Warn if the output file already exists. The warning makes the
    # overwrite visible rather than silent. Supports AU-9: protection
    # of audit information.
    if output_path.exists():
        print(f"\n[WARN] Output file already exists and will be overwritten: {output_path}")

    # json.dump() writes a Python dict to a file as JSON (PCC3e Ch 10).
    # indent=2 makes it human-readable. ensure_ascii=False allows Unicode
    # characters in file paths to render correctly instead of being escaped.
    with open(output_path, "w") as f:
        json.dump(json_output, f, indent=2, ensure_ascii=False)

    print(f"\nJSON results written to: {output_path}")
