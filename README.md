# Secret Scanner

A Python tool that scans directories for sensitive content using compiled regex patterns. Detects AWS credentials, API keys, passwords, private keys, JWTs, connection strings, and CJIS Criminal Justice Information (CJI) leakage. Designed for use in CI/CD pipelines and GRC engineering workflows targeting public safety technology environments.

Maps to NIST 800-53 Rev 5 controls: **IA-5(7)**, **SC-12**, **SC-28**.
Maps to CJIS v6.0 controls: **SC-12**, **SC-13**, **SC-28**.

## Features

- Recursively scans all files in a target directory and its subdirectories
- Reports findings with file path and line number (e.g., `config.json:12`)
- Detects secrets using compiled regex patterns that require assignment context to reduce false positives
- Supports custom pattern files via `--patterns` for organization-specific detection rules
- Gracefully skips binary files and permission-denied files
- Returns a non-zero exit code when secrets are found (CI/CD integration)
- Supports `--exit-zero` for informational-only runs
- Prints a summary with total alerts, affected files, directories scanned, and skipped files

## Detection Patterns

### Secrets and Credentials

| Pattern | Example Match |
|---------|--------------|
| AWS Access Key ID | `AKIAIOSFODNN7EXAMPLE` |
| AWS Secret Access Key | `aws_secret_access_key = "wJalr..."` |
| AWS Session Token | `aws_session_token = "FwoGZX..."` |
| Password Assignment | `password = "hunter2"` |
| Secret Assignment | `secret_key = "abc123"` |
| API Key | `api_key = "sk-live-..."` |
| Private Key Header | `-----BEGIN RSA PRIVATE KEY-----` |
| JWT Token | `eyJhbGciOiJIUzI1NiIs...` |
| Connection String | `postgresql://admin:pass@host:5432/db` |

### CJIS Criminal Justice Information (CJI)

| Pattern | What It Detects | Example Match |
|---------|----------------|--------------|
| CJI: ORI Number | Originating Agency Identifiers | `ori = "CA0380000"` |
| CJI: NCIC Query Code | NCIC message format indicators | `NCIC QH hot file query` |
| CJI: FBI Number | FBI Universal Control Numbers | `fbi_number = "123456AA7"` |
| CJI: State ID (SID) | State criminal history record IDs | `sid = "CA12345678"` |

CJI patterns address CJIS Security Policy v6.0 requirements: CJI must never appear in plaintext outside of authorized, encrypted systems. Detecting CJI leakage in config files and source code identifies violations of SC-28 (Protection of Information at Rest) and SC-13 (Cryptographic Protection).

## Usage

Scan the default `test_configs/` directory:

```bash
python secret_scanner.py
```

Scan a specific directory:

```bash
python secret_scanner.py /path/to/configs
```

Run in informational mode (always exit 0, even if secrets are found):

```bash
python secret_scanner.py /path/to/configs --exit-zero
```

Load additional detection patterns from a JSON file:

```bash
python secret_scanner.py /path/to/configs --patterns custom_patterns.json
```

The patterns file should be a flat JSON object of `{"pattern_name": "regex_string"}`:

```json
{
    "Slack Token": "xox[baprs]-[0-9a-zA-Z-]{10,}",
    "GitHub PAT": "ghp_[A-Za-z0-9]{36}"
}
```

Custom patterns are merged with the built-in defaults. If a custom pattern has the same name as a built-in, it overrides the built-in.

Export findings as structured JSON for evidence pipelines:

```bash
python secret_scanner.py /path/to/configs --output json
```

This writes `scan_results.json` with three sections:
- **scan_metadata**: timestamp (ISO 8601), target directory, scanner version, duration
- **findings[]**: each finding with `file_path`, `line_number`, `finding_type`, `pattern_matched`, `severity`, and `control_ids` (NIST 800-53)
- **summary**: total counts and findings grouped by type

See [`examples/sample_output.json`](examples/sample_output.json) for the full schema. Console output still prints in real time when using `--output json`.

View all options:

```bash
python secret_scanner.py --help
```

## Exit Codes

| Code | Meaning |
|------|---------|
| `0`  | No secrets found, or `--exit-zero` was used |
| `1`  | Secrets detected (default behavior) |

In a CI/CD pipeline, the non-zero exit code will cause the step to fail, blocking merges that contain exposed secrets.

## Test Data

The `test_configs/` directory contains **intentionally fake credentials and CJI identifiers** for testing the scanner. All values use the AWS example key format (`AKIAIOSFODNN7EXAMPLE`), clearly fake strings, or fabricated CJI data (fake ORI numbers, FBI numbers, etc.).

**Never place real credentials in test files.** If you need to test against real-world patterns, use a `.env` or `.secrets` file — both are excluded from version control by `.gitignore`.

## Requirements

- Python 3.x (no third-party dependencies)

## License

MIT License
