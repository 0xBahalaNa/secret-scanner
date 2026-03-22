"""secret_scanner — A compliance-focused secret detection tool.

Scans directories for sensitive information (AWS credentials, API keys,
passwords, private keys, JWT tokens, connection strings, and CJIS Criminal
Justice Information) in configuration files and source code.

Maps findings to NIST 800-53 Rev 5, FedRAMP High, and CJIS v6.0 controls.
Produces structured JSON output for OSCAL evidence pipelines.

Usage as CLI:
    python -m secret_scanner [directory] [--output json] [--output-file PATH]

Usage as library:
    from secret_scanner.scanner import scan
    from secret_scanner.patterns import load_all_patterns

    patterns = load_all_patterns()
    results = scan("/path/to/scan", patterns)
"""

# Scanner version — included in JSON output metadata so consumers can track
# which version produced a given evidence artifact. Bump this when detection
# capabilities change (new patterns, new output fields, etc.).
__version__ = "0.7.0"
