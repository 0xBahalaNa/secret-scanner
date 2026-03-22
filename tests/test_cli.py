"""Tests for CLI argument parsing and entry point behavior.

Tests the argument parser and exit code logic. Uses pytest's capsys
fixture for output capture and monkeypatch for overriding sys.argv.

These tests verify that the CLI interface contract is maintained:
correct exit codes, proper error messages, and flag behavior.
"""

from secret_scanner.cli import build_parser


# --- Argument parser tests ---

def test_parser_default_directory():
    """Default directory should be test_configs when no arg provided."""
    parser = build_parser()
    args = parser.parse_args([])
    assert args.directory == "test_configs"


def test_parser_custom_directory():
    """Custom directory should be parsed correctly."""
    parser = build_parser()
    args = parser.parse_args(["/some/path"])
    assert args.directory == "/some/path"


def test_parser_exit_zero_flag():
    """--exit-zero should set exit_zero to True."""
    parser = build_parser()
    args = parser.parse_args(["--exit-zero"])
    assert args.exit_zero is True


def test_parser_exit_zero_default():
    """exit_zero should default to False."""
    parser = build_parser()
    args = parser.parse_args([])
    assert args.exit_zero is False


def test_parser_output_json():
    """--output json should be parsed correctly."""
    parser = build_parser()
    args = parser.parse_args(["--output", "json"])
    assert args.output == "json"


def test_parser_output_default():
    """output should default to None."""
    parser = build_parser()
    args = parser.parse_args([])
    assert args.output is None


def test_parser_output_file():
    """--output-file should override the default filename."""
    parser = build_parser()
    args = parser.parse_args(["--output-file", "custom.json"])
    assert args.output_file == "custom.json"


def test_parser_output_file_default():
    """output_file should default to scan_results.json."""
    parser = build_parser()
    args = parser.parse_args([])
    assert args.output_file == "scan_results.json"


def test_parser_patterns_flag():
    """--patterns should accept a file path."""
    parser = build_parser()
    args = parser.parse_args(["--patterns", "custom.json"])
    assert args.patterns == "custom.json"


def test_parser_all_flags_combined():
    """All flags should work together without conflict."""
    parser = build_parser()
    args = parser.parse_args([
        "/scan/dir",
        "--exit-zero",
        "--output", "json",
        "--output-file", "out.json",
        "--patterns", "extra.json",
    ])
    assert args.directory == "/scan/dir"
    assert args.exit_zero is True
    assert args.output == "json"
    assert args.output_file == "out.json"
    assert args.patterns == "extra.json"


# --- Exit code tests (integration) ---

def test_exit_code_1_on_findings(tmp_path):
    """Scanner should exit 1 when findings exist."""
    import subprocess
    config = tmp_path / "secret.txt"
    config.write_text("AKIAIOSFODNN7EXAMPLE")

    result = subprocess.run(
        ["python", "-m", "secret_scanner", str(tmp_path)],
        capture_output=True, text=True,
    )
    assert result.returncode == 1


def test_exit_code_0_on_clean(tmp_path):
    """Scanner should exit 0 when no findings exist."""
    import subprocess
    config = tmp_path / "clean.txt"
    config.write_text("nothing secret here")

    result = subprocess.run(
        ["python", "-m", "secret_scanner", str(tmp_path)],
        capture_output=True, text=True,
    )
    assert result.returncode == 0


def test_exit_zero_flag_overrides(tmp_path):
    """--exit-zero should force exit 0 even with findings."""
    import subprocess
    config = tmp_path / "secret.txt"
    config.write_text("AKIAIOSFODNN7EXAMPLE")

    result = subprocess.run(
        ["python", "-m", "secret_scanner", str(tmp_path), "--exit-zero"],
        capture_output=True, text=True,
    )
    assert result.returncode == 0


def test_exit_code_1_on_nonexistent_directory():
    """Scanner should exit 1 for a nonexistent directory."""
    import subprocess
    result = subprocess.run(
        ["python", "-m", "secret_scanner", "/nonexistent/dir"],
        capture_output=True, text=True,
    )
    assert result.returncode == 1
    assert "[ERROR]" in result.stderr or "[ERROR]" in result.stdout
