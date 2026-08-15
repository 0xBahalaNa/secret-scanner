![License](https://img.shields.io/badge/License-MIT-green?style=flat)
![Python](https://img.shields.io/badge/Python-3.11%2B-3776ab?style=flat)
![NIST 800-53](https://img.shields.io/badge/NIST-800--53%20Rev%205-004990?style=flat)
![FedRAMP](https://img.shields.io/badge/FedRAMP-High%20Baseline-0071bc?style=flat)
![CJIS](https://img.shields.io/badge/CJIS-Security%20Policy%20v6.1-cc0000?style=flat)

# Secret Scanner

I built this to scan directories for sensitive content using compiled regex patterns: AWS credentials, API keys, passwords, private keys, JWTs, connection strings, and CJIS Criminal Justice Information (CJI) leakage. It's meant to run in CI/CD pipelines and GRC engineering workflows targeting public safety technology environments.

Maps to NIST 800-53 Rev 5 controls: **IA-5(7)**, **SC-12**, **SC-28**.
Maps to FedRAMP High baseline controls: **IA-5(7)**, **SC-12**, **SC-28**.
Maps to CJIS v6.1 controls: **SC-12**, **SC-13**, **SC-28**.

## Architecture Overview

```mermaid
flowchart TD
    CLI["python -m secret_scanner<br/>CLI entry"] --> WALK["Walk target directory"]
    WALK --> PAT["Compiled regex patterns<br/>secrets + CJI"]
    PAT --> OPT["Optional --patterns<br/>org-specific rules"]
    PAT --> FIND["Findings<br/>file:line"]
    OPT --> FIND
    FIND --> CON["Console summary<br/>alerts · files · skipped"]
    FIND --> JSON["Optional JSON export<br/>scan_results.json"]
    FIND --> EXIT["CI exit code<br/>non-zero on secrets"]
    CON --> HUM["Operators / reviewers"]
    JSON --> PIPE["Evidence pipelines<br/>GRC / CI artifacts"]
    EXIT --> CI["CI/CD gate"]
```

Editable Mermaid source (kept in sync with the fence above): [`docs/architecture.mmd`](docs/architecture.mmd).

`python -m secret_scanner` walks a target directory, runs compiled secret and CJI regex patterns (optional `--patterns` for org rules), and reports `file:line` findings. Operators get a console summary; optional JSON export feeds evidence pipelines; a non-zero exit code gates CI unless `--exit-zero` is set.

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

CJI patterns address CJIS Security Policy v6.1 requirements: CJI must never appear in plaintext outside of authorized, encrypted systems. Detecting CJI leakage in config files and source code identifies violations of SC-28 (Protection of Information at Rest) and SC-13 (Cryptographic Protection).

## Usage

Scan the default `test_configs/` directory:

```bash
python -m secret_scanner
```

Scan a specific directory:

```bash
python -m secret_scanner /path/to/configs
```

Run in informational mode (always exit 0, even if secrets are found):

```bash
python -m secret_scanner /path/to/configs --exit-zero
```

Load additional detection patterns from a JSON file:

```bash
python -m secret_scanner /path/to/configs --patterns custom_patterns.json
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
python -m secret_scanner /path/to/configs --output json
```

This writes `scan_results.json` with three sections:
- **scan_metadata**: timestamp (ISO 8601), target directory, scanner version, duration
- **findings[]**: each finding with `file_path`, `line_number`, `finding_type`, `pattern_matched`, `severity`, and `control_ids` (NIST 800-53)
- **summary**: total counts and findings grouped by type

See [`examples/sample_output.json`](examples/sample_output.json) for the full schema. Console output still prints in real time when using `--output json`.

View all options:

```bash
python -m secret_scanner --help
```

## Exit Codes

| Code | Meaning |
|------|---------|
| `0`  | No secrets found, or `--exit-zero` was used |
| `1`  | Secrets detected (default behavior) |

In a CI/CD pipeline, the non-zero exit code will cause the step to fail, blocking merges that contain exposed secrets.

## Pre-commit Integration

The scanner can run as a pre-commit hook, catching secrets before they enter version control. That early gate is the highest-value use case: a preventive control at the CI/CD pipeline boundary (CM-3: Configuration Change Control).

### Option 1: Pre-commit Framework

If your team uses the [pre-commit framework](https://pre-commit.com), add this to your `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/0xBahalaNa/secret-scanner
    rev: main
    hooks:
      - id: secret-scanner
```

The framework automatically passes only staged files to the scanner.

### Option 2: Standalone Git Hook

For a dependency-free setup, install the bundled hook script:

```bash
make install-hooks
```

Or manually:

```bash
cp hooks/pre-commit .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

The standalone hook uses `git diff --cached --name-only --diff-filter=ACM` to scan only staged files that are added, copied, or modified.

### Scanning Specific Files

Both hook options use the `--files` flag, which you can also use directly:

```bash
python -m secret_scanner --files config.json terraform.tf
```

This scans only the specified files instead of recursing a directory.

## Compliance Controls Addressed

| Framework | Control ID | Control Name | How This Tool Validates |
|-----------|-----------|--------------|------------------------|
| NIST 800-53 Rev 5 | IA-5(7) | No Embedded Unencrypted Static Authenticators | Detects hardcoded passwords, API keys, AWS credentials, and private keys in source code and config files |
| NIST 800-53 Rev 5 | SC-12 | Cryptographic Key Establishment and Management | Identifies exposed cryptographic keys (AWS secret keys, PEM private keys) that should be managed through key management services |
| NIST 800-53 Rev 5 | SC-28 | Protection of Information at Rest | Detects sensitive data (credentials, CJI) stored in plaintext files instead of encrypted storage |
| NIST 800-53 Rev 5 | SC-13 | Cryptographic Protection | Identifies CJI data outside FIPS 140-2/3 validated cryptographic boundaries |
| FedRAMP High | IA-5(7) | No Embedded Unencrypted Static Authenticators | Same as NIST. FedRAMP High inherits this control with no additional enhancements |
| FedRAMP High | SC-12 | Cryptographic Key Establishment and Management | Same as NIST. FedRAMP High requires FIPS 140-2 validated key management |
| FedRAMP High | SC-28 | Protection of Information at Rest | Same as NIST. FedRAMP High requires encryption for all data at rest |
| CJIS v6.1 | SC-12 | Cryptographic Key Establishment and Management | Detects CJI identifiers (ORI, FBI numbers, SIDs) that must be protected with agency-managed encryption keys |
| CJIS v6.1 | SC-13 | Cryptographic Protection | Identifies CJI in plaintext. CJIS requires FIPS 140-2/3 validated encryption for all CJI at rest |
| CJIS v6.1 | SC-28 | Protection of Information at Rest | Detects NCIC query codes, ORI numbers, and other CJI that must never appear in plaintext config files |

## How This Supports Audits

Run it against infrastructure-as-code repos, config directories, and deployment artifacts before an assessment, and the findings are proactive evidence rather than a scramble the week of the audit. In CI/CD, `--output json` generates a timestamped, machine-readable scan result for every build, which is what demonstrates ongoing compliance with IA-5(7) and SC-28 rather than a point-in-time check. The JSON output also carries `findings_by_type` counts, so remediation progress is something you can compare across scans instead of taking on faith. Each finding includes file path, line number, pattern type, and mapped control IDs. That specificity is what satisfies AU-3 (Content of Audit Records).

### Sample Evidence Output

See [`examples/sample_output.json`](examples/sample_output.json) for the full JSON schema produced by `--output json`.

## FedRAMP 20x Alignment

FedRAMP 20x (Pilot) wants machine-readable compliance artifacts and continuous validation instead of point-in-time assessments, and that's the shape this tool already produces. `--output json` writes structured findings with ISO 8601 timestamps and NIST 800-53 control mappings, which is the foundation for transforming scan results into OSCAL Assessment Results format. The non-zero exit code (or `--exit-zero` for monitoring-only runs) works as either an enforcement gate or a passive collector, depending on how the pipeline is wired. Every scan is a timestamped evidence artifact on its own, which is the actual mechanism behind FedRAMP 20x's shift from annual assessments to continuous monitoring with Key Security Indicators (KSIs).

## Integration with OSCAL Evidence Pipeline

This scanner is used as the **first adapter** in [`oscal-evidence-pipeline`](https://github.com/0xBahalaNa/oscal-evidence-pipeline), the OSCAL Assessment Results (SAR) transformation layer for FedRAMP 20x and CJIS v6.1 evidence. The `--output json` findings (file path, line number, finding type, NIST 800-53 control IDs) are the upstream input that the pipeline transforms into OSCAL `observation` and `finding` entries.

This integration also makes `secret-scanner` the live demonstration of the adapter pattern used for every downstream tool (`s3-audit`, `sg-audit`, `cloudtrail-audit`, `evidence-logger`) as they're brought into the pipeline.

## CJIS v6.1 Relevance

CJIS Security Policy v6.1 (released June 25, 2026) is the current policy, aligned with NIST 800-53 Rev 5. v6.x has been the default audit baseline since April 1, 2026 (v5.9.5 sunset March 31, 2026); modernized Priority 2-4 controls are fully enforceable Oct 1, 2027 (timing varies by state CSA). It carries stricter requirements for Criminal Justice Information (CJI) protection, and that's where this tool earns its keep in a public safety environment. It detects ORI numbers, NCIC query codes, FBI numbers, and State IDs, data types unique to law enforcement systems that a generic secret scanner misses entirely. Under CJIS v6.1 SC-28, CJI has to be encrypted at rest using FIPS 140-2/3 validated cryptography, so CJI showing up in a config file or log is itself the violation, not just a risk. CJIS also requires that encryption keys for CJI be managed by the criminal justice agency rather than the cloud provider (SC-12), and finding exposed CJI is one way to surface where that requirement actually applies. FBI numbers and SIDs matter more than most fields here: they link to criminal history records (CHRI) generated through fingerprint-based background checks, one of the most sensitive categories of CJI there is.

## Test Data

The `test_configs/` directory contains **intentionally fake credentials and CJI identifiers** for testing the scanner. All values use the AWS example key format (`AKIAIOSFODNN7EXAMPLE`), clearly fake strings, or fabricated CJI data (fake ORI numbers, FBI numbers, etc.).

**Never place real credentials in test files.** If you need to test against real-world patterns, use a `.env` or `.secrets` file. Both are excluded from version control by `.gitignore`.

## Requirements

- Python 3.x (no third-party dependencies)

## License

MIT License
