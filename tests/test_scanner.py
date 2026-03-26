"""Tests for the core scanning logic.

Tests the scan() function from secret_scanner.scanner with various
directory configurations. Uses pytest's tmp_path fixture to create
isolated temporary directories for each test — this is dependency
injection, where pytest sees tmp_path in the function signature and
automatically provides a unique Path object.

These tests verify the scanner handles edge cases gracefully:
binary files, empty directories, permission errors, symlinks outside
the scan root, and large files that exceed the size limit.
"""

import os

from secret_scanner.patterns import load_all_patterns
from secret_scanner.scanner import scan, scan_files, MAX_FILE_SIZE


def test_scan_finds_aws_key(tmp_path):
    """Scanner should detect an AWS Access Key ID in a file."""
    config = tmp_path / "config.json"
    config.write_text('{"aws_access_key_id": "AKIAIOSFODNN7EXAMPLE"}')

    patterns = load_all_patterns()
    result = scan(tmp_path, patterns)

    assert result["total_findings"] == 1
    assert result["findings"][0]["finding_type"] == "AWS Access Key ID"
    assert result["findings"][0]["severity"] == "CRITICAL"


def test_scan_clean_file(tmp_path):
    """Scanner should produce zero findings for a clean file."""
    config = tmp_path / "clean.json"
    config.write_text('{"app_name": "test", "debug": false}')

    patterns = load_all_patterns()
    result = scan(tmp_path, patterns)

    assert result["total_findings"] == 0
    assert result["total_files_scanned"] == 1


def test_scan_empty_directory(tmp_path):
    """Scanner should handle an empty directory without errors."""
    patterns = load_all_patterns()
    result = scan(tmp_path, patterns)

    assert result["total_findings"] == 0
    assert result["total_files_scanned"] == 0
    assert result["skipped_files"] == 0


def test_scan_binary_file_skipped(tmp_path):
    """Binary files should be skipped, not crash the scanner."""
    binary = tmp_path / "image.png"
    binary.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\xff" * 100)

    patterns = load_all_patterns()
    result = scan(tmp_path, patterns)

    assert result["skipped_files"] == 1
    assert result["total_findings"] == 0


def test_scan_nested_directories(tmp_path):
    """Scanner should recurse into subdirectories."""
    nested = tmp_path / "level1" / "level2"
    nested.mkdir(parents=True)

    # Place files at two different depths so directories_scanned >= 2.
    top_config = tmp_path / "top.json"
    top_config.write_text('api_key = "top_level_key"')
    deep_config = nested / "secret.json"
    deep_config.write_text('password = "deep_secret"')

    patterns = load_all_patterns()
    result = scan(tmp_path, patterns)

    assert result["total_findings"] >= 2
    assert result["directories_scanned"] >= 2


def test_scan_empty_file(tmp_path):
    """Empty files should be scanned without errors or findings."""
    empty = tmp_path / "empty.txt"
    empty.write_text("")

    patterns = load_all_patterns()
    result = scan(tmp_path, patterns)

    assert result["total_files_scanned"] == 1
    assert result["total_findings"] == 0
    assert result["skipped_files"] == 0


def test_scan_file_no_trailing_newline(tmp_path):
    """Files without a trailing newline should still be scanned."""
    config = tmp_path / "config.env"
    # write_text adds no trailing newline by default
    config.write_text('password = "no_newline"')

    patterns = load_all_patterns()
    result = scan(tmp_path, patterns)

    assert result["total_findings"] >= 1


def test_scan_multiple_findings_per_file(tmp_path):
    """A file with multiple secrets should produce multiple findings."""
    config = tmp_path / "multi.conf"
    config.write_text(
        'aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n'
        'password = "hunter2"\n'
        'api_key = "sk-live-abc123def456"\n'
    )

    patterns = load_all_patterns()
    result = scan(tmp_path, patterns)

    assert result["total_findings"] >= 3
    assert result["files_with_findings"] == 1


def test_scan_line_numbers_correct(tmp_path):
    """Line numbers should be 1-indexed and accurate."""
    config = tmp_path / "lines.conf"
    config.write_text(
        "# comment line 1\n"
        "# comment line 2\n"
        'password = "on_line_3"\n'
    )

    patterns = load_all_patterns()
    result = scan(tmp_path, patterns)

    assert result["findings"][0]["line_number"] == 3


def test_scan_symlink_outside_directory_skipped(tmp_path):
    """Symlinks pointing outside the scan root should be skipped."""
    # Create a file outside the scan directory
    import tempfile
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write('password = "external_secret"')
        external_path = f.name

    try:
        # Create a symlink inside tmp_path pointing to the external file
        link = tmp_path / "external_link.txt"
        link.symlink_to(external_path)

        patterns = load_all_patterns()
        result = scan(tmp_path, patterns)

        # The symlink should be skipped, not scanned
        assert result["skipped_files"] == 1
        assert result["total_findings"] == 0
    finally:
        os.unlink(external_path)


def test_scan_large_file_skipped(tmp_path):
    """Files exceeding MAX_FILE_SIZE should be skipped."""
    large = tmp_path / "huge.txt"
    # Create a file just over the limit using seek (doesn't write actual data)
    with open(large, "wb") as f:
        f.seek(MAX_FILE_SIZE + 1)
        f.write(b"\0")

    patterns = load_all_patterns()
    result = scan(tmp_path, patterns)

    assert result["skipped_files"] == 1
    assert result["total_findings"] == 0


def test_scan_result_has_all_keys(tmp_path):
    """Scan result dict should contain all expected keys."""
    config = tmp_path / "test.txt"
    config.write_text("clean content")

    patterns = load_all_patterns()
    result = scan(tmp_path, patterns)

    expected_keys = {
        "findings", "total_files_scanned", "total_findings",
        "files_with_findings", "skipped_files", "directories_scanned",
        "scan_duration", "affected_files",
    }
    assert set(result.keys()) == expected_keys


def test_scan_affected_files_sorted(tmp_path):
    """Affected files list should be sorted alphabetically."""
    for name in ["c_config.txt", "a_config.txt", "b_config.txt"]:
        (tmp_path / name).write_text('password = "test"')

    patterns = load_all_patterns()
    result = scan(tmp_path, patterns)

    assert result["affected_files"] == sorted(result["affected_files"])


def test_scan_finding_has_all_fields(tmp_path):
    """Each finding dict should contain all required fields."""
    config = tmp_path / "test.conf"
    config.write_text("AKIAIOSFODNN7EXAMPLE")

    patterns = load_all_patterns()
    result = scan(tmp_path, patterns)

    finding = result["findings"][0]
    expected_fields = {
        "file_path", "line_number", "finding_type",
        "pattern_matched", "severity", "control_ids",
    }
    assert set(finding.keys()) == expected_fields


# --- scan_files() tests ---

def test_scan_files_finds_secret(tmp_path):
    """scan_files should detect secrets in the specified files."""
    config = tmp_path / "config.json"
    config.write_text('{"aws_access_key_id": "AKIAIOSFODNN7EXAMPLE"}')

    patterns = load_all_patterns()
    result = scan_files([str(config)], patterns)

    assert result["total_findings"] == 1
    assert result["findings"][0]["finding_type"] == "AWS Access Key ID"


def test_scan_files_clean_file(tmp_path):
    """scan_files should produce zero findings for a clean file."""
    config = tmp_path / "clean.json"
    config.write_text('{"app_name": "test"}')

    patterns = load_all_patterns()
    result = scan_files([str(config)], patterns)

    assert result["total_findings"] == 0
    assert result["total_files_scanned"] == 1


def test_scan_files_multiple_files(tmp_path):
    """scan_files should scan all specified files."""
    secret = tmp_path / "secret.txt"
    secret.write_text("AKIAIOSFODNN7EXAMPLE")
    clean = tmp_path / "clean.txt"
    clean.write_text("nothing here")

    patterns = load_all_patterns()
    result = scan_files([str(secret), str(clean)], patterns)

    assert result["total_files_scanned"] == 2
    assert result["total_findings"] == 1
    assert result["files_with_findings"] == 1


def test_scan_files_nonexistent_skipped(tmp_path):
    """scan_files should skip files that don't exist."""
    patterns = load_all_patterns()
    result = scan_files(["/nonexistent/file.txt"], patterns)

    assert result["skipped_files"] == 1
    assert result["total_files_scanned"] == 0


def test_scan_files_binary_skipped(tmp_path):
    """scan_files should skip binary files."""
    binary = tmp_path / "image.png"
    binary.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\xff" * 100)

    patterns = load_all_patterns()
    result = scan_files([str(binary)], patterns)

    assert result["skipped_files"] == 1
    assert result["total_findings"] == 0


def test_scan_files_empty_list():
    """scan_files with an empty list should return zero counts."""
    patterns = load_all_patterns()
    result = scan_files([], patterns)

    assert result["total_files_scanned"] == 0
    assert result["total_findings"] == 0


def test_scan_files_result_has_all_keys(tmp_path):
    """scan_files result should have the same structure as scan()."""
    config = tmp_path / "test.txt"
    config.write_text("clean content")

    patterns = load_all_patterns()
    result = scan_files([str(config)], patterns)

    expected_keys = {
        "findings", "total_files_scanned", "total_findings",
        "files_with_findings", "skipped_files", "directories_scanned",
        "scan_duration", "affected_files",
    }
    assert set(result.keys()) == expected_keys
