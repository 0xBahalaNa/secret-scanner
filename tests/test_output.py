"""Tests for output formatters.

Tests the console and JSON output modules to ensure they produce
correct, well-structured output. Uses pytest's capsys fixture to
capture stdout for console output tests, and tmp_path for JSON file
output tests.

capsys is a pytest built-in fixture that captures what your code
prints to stdout and stderr. After calling your function, you use
capsys.readouterr() to get the captured text — then assert on it.
"""

import json

from secret_scanner.output.console import print_alert, print_skip, print_summary
from secret_scanner.output.json_report import write_json_report


# --- Console output tests ---

def test_print_alert_format(capsys):
    """Alert output should include severity, path, line number, and pattern."""
    print_alert("config.json", 5, "AWS Access Key ID", "CRITICAL")
    captured = capsys.readouterr()
    assert "[CRITICAL]" in captured.out
    assert "config.json:5" in captured.out
    assert "AWS Access Key ID" in captured.out


def test_print_alert_severity_levels(capsys):
    """Each severity level should appear in the output tag."""
    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        print_alert("test.txt", 1, "Test", severity)
    captured = capsys.readouterr()
    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        assert f"[{severity}]" in captured.out


def test_print_skip_format(capsys):
    """Skip output should include path and reason."""
    print_skip("image.png", "The file type is not compatible.")
    captured = capsys.readouterr()
    assert "[SKIP]" in captured.out
    assert "image.png" in captured.out
    assert "not compatible" in captured.out


def test_print_summary_content(capsys):
    """Summary should include all key metrics."""
    scan_result = {
        "directories_scanned": 3,
        "total_files_scanned": 10,
        "total_findings": 5,
        "files_with_findings": 2,
        "skipped_files": 1,
        "scan_duration": 0.042,
        "affected_files": ["config.json", "secrets.env"],
        "findings": [
            {"severity": "CRITICAL"},
            {"severity": "CRITICAL"},
            {"severity": "HIGH"},
            {"severity": "MEDIUM"},
            {"severity": "LOW"},
        ],
    }
    print_summary(scan_result)
    captured = capsys.readouterr()

    assert "Directories scanned: 3" in captured.out
    assert "Files scanned: 10" in captured.out
    assert "Total alerts: 5" in captured.out
    assert "Files with issues: 2" in captured.out
    assert "Skipped files: 1" in captured.out
    assert "0.042s" in captured.out
    assert "config.json" in captured.out
    assert "secrets.env" in captured.out


def test_print_summary_severity_breakdown(capsys):
    """Summary should include severity counts."""
    scan_result = {
        "directories_scanned": 1,
        "total_files_scanned": 1,
        "total_findings": 3,
        "files_with_findings": 1,
        "skipped_files": 0,
        "scan_duration": 0.001,
        "affected_files": ["test.txt"],
        "findings": [
            {"severity": "CRITICAL"},
            {"severity": "CRITICAL"},
            {"severity": "LOW"},
        ],
    }
    print_summary(scan_result)
    captured = capsys.readouterr()

    assert "CRITICAL: 2" in captured.out
    assert "LOW: 1" in captured.out


def test_print_summary_no_findings(capsys):
    """Summary with zero findings should not print severity or affected files."""
    scan_result = {
        "directories_scanned": 1,
        "total_files_scanned": 1,
        "total_findings": 0,
        "files_with_findings": 0,
        "skipped_files": 0,
        "scan_duration": 0.001,
        "affected_files": [],
        "findings": [],
    }
    print_summary(scan_result)
    captured = capsys.readouterr()

    assert "Total alerts: 0" in captured.out
    assert "Severity breakdown" not in captured.out
    assert "Affected files" not in captured.out


# --- JSON output tests ---

def test_json_report_structure(tmp_path):
    """JSON report should contain metadata, findings, and summary sections."""
    scan_result = {
        "findings": [
            {
                "file_path": "config.json",
                "line_number": 4,
                "finding_type": "AWS Access Key ID",
                "pattern_matched": "AKIA[0-9A-Z]{16}",
                "severity": "CRITICAL",
                "control_ids": ["IA-5(7)", "SC-12", "SC-28"],
            }
        ],
        "total_files_scanned": 5,
        "total_findings": 1,
        "files_with_findings": 1,
        "skipped_files": 0,
        "scan_duration": 0.003,
    }
    output_file = tmp_path / "results.json"

    write_json_report(scan_result, str(output_file), "0.8.0", "/scan/dir", 13)

    data = json.loads(output_file.read_text())

    # Top-level sections
    assert "scan_metadata" in data
    assert "findings" in data
    assert "summary" in data

    # Metadata fields
    assert "timestamp" in data["scan_metadata"]
    assert data["scan_metadata"]["scanner_version"] == "0.8.0"
    assert data["scan_metadata"]["patterns_active"] == 13

    # Finding fields
    assert len(data["findings"]) == 1
    assert data["findings"][0]["severity"] == "CRITICAL"
    assert data["findings"][0]["control_ids"] == ["IA-5(7)", "SC-12", "SC-28"]

    # Summary fields
    assert data["summary"]["total_findings"] == 1
    assert "findings_by_type" in data["summary"]
    assert "findings_by_severity" in data["summary"]
    assert data["summary"]["findings_by_severity"]["CRITICAL"] == 1


def test_json_report_overwrites_with_warning(tmp_path, capsys):
    """Overwriting an existing file should produce a warning."""
    output_file = tmp_path / "results.json"
    output_file.write_text("{}")  # Pre-existing file

    scan_result = {
        "findings": [],
        "total_files_scanned": 0,
        "total_findings": 0,
        "files_with_findings": 0,
        "skipped_files": 0,
        "scan_duration": 0.001,
    }

    write_json_report(scan_result, str(output_file), "0.8.0", "/scan", 13)
    captured = capsys.readouterr()

    assert "[WARN]" in captured.out
    assert "already exists" in captured.out
