# Secret Scanner

A Python tool that scans directories for sensitive content using compiled regex patterns. Detects AWS credentials, API keys, passwords, private keys, JWTs, connection strings, and CJIS Criminal Justice Information (CJI) leakage. Designed for use in CI/CD pipelines and GRC engineering workflows targeting public safety technology environments.

Maps to NIST 800-53 Rev 5 controls: **IA-5(7)**, **SC-12**, **SC-28**.
Maps to FedRAMP High baseline controls: **IA-5(7)**, **SC-12**, **SC-28**.
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

## Compliance Controls Addressed

| Framework | Control ID | Control Name | How This Tool Validates |
|-----------|-----------|--------------|------------------------|
| NIST 800-53 Rev 5 | IA-5(7) | No Embedded Unencrypted Static Authenticators | Detects hardcoded passwords, API keys, AWS credentials, and private keys in source code and config files |
| NIST 800-53 Rev 5 | SC-12 | Cryptographic Key Establishment and Management | Identifies exposed cryptographic keys (AWS secret keys, PEM private keys) that should be managed through key management services |
| NIST 800-53 Rev 5 | SC-28 | Protection of Information at Rest | Detects sensitive data (credentials, CJI) stored in plaintext files instead of encrypted storage |
| NIST 800-53 Rev 5 | SC-13 | Cryptographic Protection | Identifies CJI data outside FIPS 140-2/3 validated cryptographic boundaries |
| FedRAMP High | IA-5(7) | No Embedded Unencrypted Static Authenticators | Same as NIST — FedRAMP High inherits this control with no additional enhancements |
| FedRAMP High | SC-12 | Cryptographic Key Establishment and Management | Same as NIST — FedRAMP High requires FIPS 140-2 validated key management |
| FedRAMP High | SC-28 | Protection of Information at Rest | Same as NIST — FedRAMP High requires encryption for all data at rest |
| CJIS v6.0 | SC-12 | Cryptographic Key Establishment and Management | Detects CJI identifiers (ORI, FBI numbers, SIDs) that must be protected with agency-managed encryption keys |
| CJIS v6.0 | SC-13 | Cryptographic Protection | Identifies CJI in plaintext — CJIS requires FIPS 140-2/3 validated encryption for all CJI at rest |
| CJIS v6.0 | SC-28 | Protection of Information at Rest | Detects NCIC query codes, ORI numbers, and other CJI that must never appear in plaintext config files |

## How This Supports Audits

This tool produces evidence artifacts that directly support compliance assessments:

- **Pre-audit scanning**: Run against infrastructure-as-code repos, config directories, and deployment artifacts before an assessment to identify findings proactively
- **Continuous monitoring evidence**: Use `--output json` in CI/CD pipelines to generate timestamped, machine-readable scan results for each build — demonstrating ongoing compliance with IA-5(7) and SC-28
- **Remediation tracking**: JSON output includes `findings_by_type` counts that can be compared across scans to show remediation progress over time
- **Audit record content**: Each finding includes file path, line number, pattern type, and mapped control IDs — satisfying AU-3 (Content of Audit Records) requirements for specificity

### Sample Evidence Output

See [`examples/sample_output.json`](examples/sample_output.json) for the full JSON schema produced by `--output json`.

## FedRAMP 20x Alignment

FedRAMP 20x (Pilot) emphasizes machine-readable compliance artifacts and continuous validation over point-in-time assessments. This tool aligns with FedRAMP 20x in the following ways:

- **JSON output format**: The `--output json` flag produces structured findings with ISO 8601 timestamps and NIST 800-53 control mappings — the foundation for transforming scan results into OSCAL Assessment Results format
- **CI/CD integration**: Non-zero exit codes and `--exit-zero` mode support both enforcement and monitoring pipeline configurations
- **Continuous evidence generation**: Each scan produces a timestamped evidence artifact, supporting the FedRAMP 20x shift from annual assessments to continuous monitoring with Key Security Indicators (KSIs)

## CJIS v6.0 Relevance

CJIS Security Policy v6.0 (effective April 1, 2026) aligns with NIST 800-53 Rev 5 and introduces stricter requirements for Criminal Justice Information (CJI) protection. This tool is specifically relevant to public safety technology environments because:

- **CJI-specific detection**: Detects ORI numbers, NCIC query codes, FBI numbers, and State IDs — data types unique to law enforcement systems that generic secret scanners miss entirely
- **Plaintext CJI is a policy violation**: Under CJIS v6.0 SC-28, CJI must be encrypted at rest using FIPS 140-2/3 validated cryptography. CJI appearing in a config file or log means encryption requirements are not being met
- **Agency-managed keys (SC-12)**: CJIS requires that encryption keys for CJI be managed by the criminal justice agency, not the cloud provider. Detecting exposed CJI helps identify where this requirement applies
- **Background check implications**: FBI numbers and SIDs link to criminal history records (CHRI) generated through fingerprint-based background checks — among the most sensitive categories of CJI

## Test Data

The `test_configs/` directory contains **intentionally fake credentials and CJI identifiers** for testing the scanner. All values use the AWS example key format (`AKIAIOSFODNN7EXAMPLE`), clearly fake strings, or fabricated CJI data (fake ORI numbers, FBI numbers, etc.).

**Never place real credentials in test files.** If you need to test against real-world patterns, use a `.env` or `.secrets` file — both are excluded from version control by `.gitignore`.

## Requirements

- Python 3.x (no third-party dependencies)

## License

MIT License
