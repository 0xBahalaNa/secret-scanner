"""
secret_scanner.py

This script scans a directory for sensitive information such as:
- AWS credentials (Access Key IDs, Secret Keys, Session Tokens)
- API keys and generic secrets
- Database credentials and connection strings
- Private key files (PEM headers)
- JWT tokens
- CJIS Criminal Justice Information (ORI numbers, NCIC codes, FBI numbers, SIDs)

Detection uses compiled regex patterns instead of simple substring matching.
This reduces false positives (a comment mentioning 'password' won't trigger)
and catches more secret types with precise pattern matching.

Usage:
    python secret_scanner.py [directory] [--exit-zero] [--patterns FILE] [--output json] [--output-file PATH]

If no directory is provided, defaults to test_configs/.
"""

import argparse
from datetime import datetime, timezone
import json
import re
import sys
import time
from pathlib import Path

# Scanner version — included in JSON output metadata so consumers can track
# which version produced a given evidence artifact. Bump this when detection
# capabilities change (new patterns, new output fields, etc.).
SCANNER_VERSION = "0.6.0"

# Resource limits to prevent the scanner from consuming excessive memory
# on unusually large files. Config files and source code are typically
# well under these thresholds — anything larger is likely a binary file
# that passed UTF-8 decoding or a data dump that shouldn't be scanned.
# These limits address SC-5 (Denial of Service Protection): a compliance
# tool in a CA-7 continuous monitoring pipeline must not be OOM-killable.
MAX_FILE_SIZE = 10 * 1024 * 1024    # 10 MB — skip files larger than this
MAX_LINE_LENGTH = 1 * 1024 * 1024   # 1 MB — skip individual lines longer than this


def load_default_patterns():
    """Return the built-in detection patterns as a dict of {name: compiled regex}.

    Each pattern targets a specific secret type. Using re.compile() pre-compiles
    the regex into an internal representation once, so it doesn't need to be
    re-parsed for every line of every file. This is a performance best practice
    when the same pattern is reused many times (see: docs.python.org/3/library/re.html).

    Pattern design philosophy: require an assignment context (= or :) where possible.
    This means 'password' in a comment won't trigger, but 'password = hunter2' will.
    This is the single biggest false-positive reduction vs. substring matching.
    """
    return {
        # Matches AWS Access Key IDs: literal "AKIA" followed by exactly 16
        # uppercase letters or digits. This is the documented AWS key format.
        "AWS Access Key ID": re.compile(r"AKIA[0-9A-Z]{16}"),

        # Matches AWS Secret Access Keys: the key name (aws_secret_access_key
        # or secret_key) followed by an assignment operator and a 40-character
        # base64 string. The (?i) flag makes it case-insensitive inline.
        "AWS Secret Access Key": re.compile(
            r"(?i)(aws_secret_access_key|secret_key)\s*[=:]\s*[\"']?[A-Za-z0-9/+=]{40}"
        ),

        # Matches AWS Session Tokens assigned to the standard variable name.
        # Session tokens are long base64 strings (typically 100+ chars), so we
        # require at least 16 characters after the assignment.
        "AWS Session Token": re.compile(
            r"(?i)aws_session_token\s*[=:]\s*[\"']?[A-Za-z0-9/+=]{16,}"
        ),

        # Matches password assignments: the keyword (password, passwd, or pwd)
        # followed by = or : and a non-whitespace value. Requires an assignment
        # operator so that comments like "# never store passwords" don't trigger.
        # The optional ["'] before [=:] handles JSON keys like "password": "value"
        # where a closing quote sits between the keyword and the colon.
        "Password Assignment": re.compile(
            r"(?i)(password|passwd|pwd)[\"']?\s*[=:]\s*[\"']?\S+"
        ),

        # Matches secret assignments: similar logic to password — requires a value
        # after the assignment. Catches patterns like secret = "abc123" or
        # secret_key: some_value. Excludes bare mentions of "secret" in comments.
        # Same optional quote handling as password for JSON compatibility.
        "Secret Assignment": re.compile(
            r"(?i)(secret|secret_key)[\"']?\s*[=:]\s*[\"']?\S+"
        ),

        # Matches API key assignments using common variable naming conventions:
        # api_key, apikey, or api-key followed by an assignment and value.
        "API Key": re.compile(
            r"(?i)(api_key|apikey|api-key)\s*[=:]\s*[\"']?\S+"
        ),

        # Matches PEM-encoded private key headers. These should never appear in
        # config files or repos — a private key in source code is an immediate
        # IA-5(7) finding (no embedded unencrypted static authenticators).
        "Private Key Header": re.compile(
            r"-----BEGIN\s+(RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----"
        ),

        # Matches JWT tokens. JWTs always start with "eyJ" (base64 for '{"')
        # followed by two dot-separated base64url segments. The minimum segment
        # length of 10 chars avoids matching short strings that happen to
        # start with "eyJ".
        "JWT Token": re.compile(
            r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"
        ),

        # Matches connection strings with embedded credentials, e.g.:
        # postgresql://admin:s3cret@db.example.com:5432/mydb
        # The pattern requires scheme://user:password@host format.
        "Connection String": re.compile(
            r"[\w+]+://[^/\s:]+:[^/\s@]+@[^/\s]+"
        ),

        # === CJI (Criminal Justice Information) Patterns ===
        # CJIS Security Policy v6.0 requires that CJI — including ORI numbers,
        # NCIC codes, FBI numbers, and State IDs — never appear in plaintext
        # outside of authorized, encrypted systems. Detecting CJI leakage in
        # config files and source code addresses:
        #   - SC-28 (Protection of Information at Rest): CJI must be encrypted
        #   - SC-13 (Cryptographic Protection): FIPS 140-2/3 validated crypto
        # A CJI leak in a config file is an immediate CJIS audit finding.

        # ORI (Originating Agency Identifier): assigned by the FBI to every
        # law enforcement agency. Format is two-letter state code + 7 digits
        # (e.g., CA0380000 = LAPD, TX0140000 = Houston PD). We require an
        # assignment context (ori, agency_id, originating_agency, etc.) to
        # avoid false positives on random alphanumeric strings. The state
        # codes are validated against US state/territory FIPS codes.
        "CJI: ORI Number": re.compile(
            r"(?i)(ori|agency_id|originating.agency)[\"']?\s*[=:]\s*[\"']?"
            r"(?:A[LKSZR]|C[AOT]|D[EC]|F[LM]|G[AU]|HI|I[ADLN]|K[SY]|LA|"
            r"M[ADEHINOPST]|N[CDEHJMVY]|O[HKR]|P[ARW]|RI|S[CD]|T[NX]|UT|"
            r"V[AIT]|W[AIVY]|DC|AS|GU|MP|PR|VI)"
            r"\d{7}"
        ),

        # NCIC (National Crime Information Center) message format indicators.
        # NCIC queries use two-letter prefixes: QH (hot file query), QW (wanted
        # persons), QR (vehicle registration), QV (stolen vehicle), QI (III/
        # Interstate Identification Index). These are extremely sensitive — an
        # NCIC query in a log or config file means CJI is being processed.
        # We require the "NCIC" keyword nearby to avoid false positives on
        # common two-letter combos. The pattern matches lines that contain
        # both "NCIC" and a query code in assignment or message context.
        "CJI: NCIC Query Code": re.compile(
            r"(?i)ncic[^a-z\n]{0,30}(Q[HWRVIGM]|[AM]H|IC|EW)\b"
        ),

        # FBI Number (Universal Control Number): assigned to individuals in
        # the III (Interstate Identification Index). Common format is a series
        # of digits, optionally with a letter suffix, assigned after a
        # fingerprint-based background check. We require the keyword "fbi_number",
        # "ucn", or "fbi_id" in assignment context to avoid matching arbitrary
        # numbers. Example: fbi_number = "123456AA7"
        "CJI: FBI Number": re.compile(
            r"(?i)(fbi.number|fbi.id|ucn)[\"']?\s*[=:]\s*[\"']?\d{5,10}[A-Z]{0,2}\d?"
        ),

        # State ID / SID (State Identification Number): assigned by state
        # criminal history repositories. Format varies by state but typically
        # follows a keyword like "sid", "state_id", or "sid_number" plus a
        # numeric or alphanumeric value. CJI because it links to criminal
        # history records (CHRI), which are among the most sensitive CJI types.
        "CJI: State ID (SID)": re.compile(
            r"(?i)(sid|state.id|sid.number)[\"']?\s*[=:]\s*[\"']?[A-Z0-9]{4,15}"
        ),
    }


def load_custom_patterns(patterns_file):
    """Load additional patterns from a JSON file and return as compiled regexes.

    The JSON file should be a flat dict of {"pattern_name": "regex_string"}.
    Example:
        {
            "Slack Token": "xox[baprs]-[0-9a-zA-Z-]{10,}",
            "GitHub PAT": "ghp_[A-Za-z0-9]{36}"
        }

    This uses json.load() to parse the file (PCC3e Ch 10: Files and Exceptions),
    then re.compile() on each value to turn the raw strings into pattern objects.

    Args:
        patterns_file: Path to the JSON patterns file.

    Returns:
        A dict of {name: compiled regex} for the custom patterns.

    Raises:
        SystemExit: If the file can't be read, isn't valid JSON, or contains
            invalid regex. A compliance tool must fail loudly — silent skipping
            would mean secrets go undetected (an IA-5(7) gap).
    """
    path = Path(patterns_file)

    if not path.exists():
        print(f"[ERROR] Patterns file does not exist: {path}")
        sys.exit(1)

    try:
        with open(path, "r") as f:
            raw_patterns = json.load(f)
    except json.JSONDecodeError as e:
        print(f"[ERROR] Invalid JSON in patterns file {path}: {e}")
        sys.exit(1)

    if not isinstance(raw_patterns, dict):
        print(f"[ERROR] Patterns file must contain a JSON object (dict), got {type(raw_patterns).__name__}")
        sys.exit(1)

    compiled = {}
    for name, regex_string in raw_patterns.items():
        try:
            compiled[name] = re.compile(regex_string)
        except re.error as e:
            # re.error is raised when a regex string has invalid syntax.
            # We fail hard here rather than skipping — a broken pattern means
            # a class of secrets would go undetected.
            print(f"[ERROR] Invalid regex for pattern '{name}': {e}")
            sys.exit(1)

    return compiled


# --- Control ID mapping ---
# Maps each pattern name to the NIST 800-53 Rev 5 controls it addresses.
# This is the bridge between "we found a secret" and "here's why it matters
# to your compliance posture." When findings are exported as JSON, each
# finding carries its control_ids — making the output directly usable in
# compliance workflows (CA-2 assessment evidence, CA-7 continuous monitoring).
#
# CJI patterns additionally map to CJIS v6.0 controls. We use the NIST
# control IDs since CJIS v6.0 aligns with 800-53 Rev 5 as of Dec 2024.
CONTROL_MAP = {
    "AWS Access Key ID": ["IA-5(7)", "SC-12", "SC-28"],
    "AWS Secret Access Key": ["IA-5(7)", "SC-12", "SC-28"],
    "AWS Session Token": ["IA-5(7)", "SC-12", "SC-28"],
    "Password Assignment": ["IA-5(7)", "SC-28"],
    "Secret Assignment": ["IA-5(7)", "SC-28"],
    "API Key": ["IA-5(7)", "SC-12", "SC-28"],
    "Private Key Header": ["IA-5(7)", "SC-12", "SC-28"],
    "JWT Token": ["IA-5(7)", "SC-28"],
    "Connection String": ["IA-5(7)", "SC-28"],
    "CJI: ORI Number": ["SC-28", "SC-13"],
    "CJI: NCIC Query Code": ["SC-28", "SC-13"],
    "CJI: FBI Number": ["SC-28", "SC-13"],
    "CJI: State ID (SID)": ["SC-28", "SC-13"],
}


# --- Argument parsing ---
# argparse replaces manual sys.argv parsing. It handles --help automatically,
# validates inputs, and makes adding new flags straightforward.
parser = argparse.ArgumentParser(
    description="Scan a directory for secrets, credentials, and sensitive patterns."
)

# positional argument with a default — the directory to scan.
# nargs="?" means "zero or one argument," so it's optional.
parser.add_argument(
    "directory",
    nargs="?",
    default="test_configs",
    help="Path to the directory to scan (default: test_configs/)",
)

# --exit-zero: always exit 0, even when findings exist.
# Useful for informational/audit runs in CI where you want visibility
# without blocking the pipeline (e.g., during initial secret triage).
parser.add_argument(
    "--exit-zero",
    action="store_true",
    help="Always exit with code 0, even if alerts are found (informational mode)",
)

# --patterns: load additional detection patterns from a JSON file.
# This supports customization for different compliance contexts — e.g., a CJIS
# team might add ORI number patterns, while a PCI team adds card number patterns.
# Custom patterns are merged with (not replacing) the built-in defaults.
parser.add_argument(
    "--patterns",
    metavar="FILE",
    help="Path to a JSON file with additional detection patterns ({name: regex})",
)

# --output: choose an output format for scan results.
# "json" writes a structured JSON file (scan_results.json) containing metadata,
# individual findings with control IDs, and a summary. This is the foundation
# for OSCAL evidence pipelines — machine-readable output that can be transformed
# into OSCAL Assessment Results format (see: FedRAMP 20x requirements).
# Console output still prints regardless so you get real-time feedback.
parser.add_argument(
    "--output",
    choices=["json"],
    metavar="FORMAT",
    help="Output format for results file: 'json' writes structured JSON (see --output-file)",
)

# --output-file: control where JSON results are written.
# Defaults to scan_results.json. This prevents silent overwrites of
# existing files and supports CI/CD pipelines that need timestamped or
# run-specific output filenames (e.g., scan_results_2026-03-22.json).
# Addresses AU-9 (Protection of Audit Information): previous scan results
# should not be silently destroyed.
parser.add_argument(
    "--output-file",
    default="scan_results.json",
    metavar="PATH",
    help="Path for JSON output file (default: scan_results.json). Requires --output json.",
)

args = parser.parse_args()
folder = Path(args.directory)

# Validate that the path exists and is a directory before scanning.
# Without this check, rglob() on a nonexistent path would raise FileNotFoundError,
# producing a traceback instead of a clear, actionable error message.
if not folder.exists():
    print(f"[ERROR] Path does not exist: {folder}")
    sys.exit(1)

if not folder.is_dir():
    print(f"[ERROR] Path is not a directory: {folder}")
    sys.exit(1)

# --- Build the pattern set ---
# Start with built-in patterns, then merge any custom patterns from --patterns.
# Using a dict means custom patterns with the same name as a built-in will
# override the built-in — this is intentional, allowing users to refine defaults.
patterns = load_default_patterns()

if args.patterns:
    custom = load_custom_patterns(args.patterns)
    print(f"Loaded {len(custom)} custom pattern(s) from {args.patterns}")
    patterns.update(custom)

# Resolve the scan root to an absolute path with symlinks resolved.
# We'll compare each file's resolved path against this to ensure we
# never read files outside the target directory (symlink escape defense).
# This addresses AC-6 (Least Privilege): the scanner should only access
# files within its authorized scope.
resolved_root = folder.resolve()

print(f"Scanning folder: {folder}")
print(f"Active patterns: {len(patterns)}")

# Counter to track the total number of alerts found across all files in directory.
issues = 0

# A set to store filenames that triggered at least one alert (avoids duplicates).
files_with_issues = set()

skipped_files = 0

# Track unique directories encountered during recursion.
directories_scanned = set()

# Track total files scanned (not just files with findings).
total_files_scanned = 0

# Accumulator list for structured findings — each finding is a dict with
# file_path, line_number, finding_type, pattern_matched, severity, and
# control_ids. This is the accumulator pattern: start with an empty list,
# append to it during the loop, then process the full list after the loop.
# We collect findings regardless of --output mode — it's cheap and keeps
# the scan loop clean (no conditional logic for output format).
findings = []

# Record the scan start time using time.time(), which returns a float of
# seconds since the Unix epoch. We'll subtract this from the end time to
# get scan duration. time.time() is in the time module (standard library,
# docs.python.org/3/library/time.html).
scan_start = time.time()

# Iterates recursively through every file inside directory and its subdirectories.
# is_file() filters out directories — without this, open() would fail on directories
# and they'd be silently skipped, giving a misleading skipped_files count.
for item in folder.rglob("*"):
    if not item.is_file():
        continue

    # Symlink escape check: resolve the file to its real absolute path
    # and verify it's still under the scan root. A symlink pointing to
    # /etc/shadow or another file outside the target directory would
    # resolve to a path that doesn't start with resolved_root — skip it.
    # This is the standard defense against path traversal via symlinks.
    resolved_item = item.resolve()
    if not str(resolved_item).startswith(str(resolved_root)):
        print(f"[SKIP] {item}: Symlink points outside scan directory.")
        skipped_files += 1
        continue

    total_files_scanned += 1

    # Record the parent directory so we can report how deep the scan went.
    directories_scanned.add(item.parent)

    # Build the display path relative to the scan root (e.g., "nested/test.json"
    # instead of just "test.json") so findings in subdirectories are identifiable.
    relative_path = item.relative_to(folder)

    # File size check: skip files larger than MAX_FILE_SIZE. This prevents
    # the scanner from attempting to read huge files that are almost certainly
    # not config files (e.g., database dumps, log archives, large binaries
    # that happen to pass UTF-8 decoding). item.stat() returns file metadata
    # without reading the file — st_size is the size in bytes.
    try:
        file_size = item.stat().st_size
    except OSError:
        print(f"[SKIP] {relative_path}: Could not read file metadata.")
        skipped_files += 1
        continue

    if file_size > MAX_FILE_SIZE:
        print(f"[SKIP] {relative_path}: File exceeds {MAX_FILE_SIZE // (1024 * 1024)}MB size limit.")
        skipped_files += 1
        continue

    # Track whether any alert was triggered for this file.
    found_issue = False

    # Read the file line-by-line using enumerate() so we can report exact
    # line numbers. enumerate(f, start=1) yields (line_number, line_text)
    # pairs — this is more Pythonic than maintaining a manual counter.
    # Line-level reporting satisfies AU-3 (Content of Audit Records):
    # analysts need to know exactly where a finding is, not just which file.
    try:
        with open(item, "r") as f:
            for line_number, line in enumerate(f, start=1):
                # Skip extremely long lines (e.g., minified JS/JSON). A line
                # over MAX_LINE_LENGTH is unlikely to be a config assignment and
                # running regex against it wastes memory and CPU.
                if len(line) > MAX_LINE_LENGTH:
                    continue

                # Loop over every pattern and check if it matches this line.
                # This replaces the old three separate if-blocks. Adding a new
                # secret type now means adding one line to PATTERNS — the scan
                # loop doesn't change. This is the Open/Closed Principle in
                # practice: open for extension, closed for modification.
                for pattern_name, pattern_regex in patterns.items():
                    if pattern_regex.search(line):
                        print(
                            f"[ALERT] {relative_path}:{line_number} "
                            f"— {pattern_name}"
                        )
                        issues += 1
                        found_issue = True

                        # Build a structured finding dict for JSON output.
                        # control_ids comes from CONTROL_MAP; custom patterns
                        # without a mapping get an empty list (safe default).
                        # severity is null for now — issue #12 will add
                        # severity classification logic.
                        findings.append({
                            "file_path": str(relative_path),
                            "line_number": line_number,
                            "finding_type": pattern_name,
                            "pattern_matched": pattern_regex.pattern,
                            "severity": None,
                            "control_ids": CONTROL_MAP.get(pattern_name, []),
                        })

    except UnicodeDecodeError:
        print(f"[SKIP] {relative_path}: The file type is not compatible.")
        skipped_files += 1
        continue
    except PermissionError:
        print(f"[SKIP] {relative_path}: You do not have the necessary permissions for this file.")
        skipped_files += 1
        continue

    # If any alert was found in this file, record the relative path in the set.
    if found_issue:
        files_with_issues.add(str(relative_path))

# Calculate scan duration by subtracting start time from current time.
# round() to 3 decimal places gives millisecond precision — more than
# enough for a file scanner, and avoids ugly floating-point noise like
# 0.0023456789012345.
scan_duration = round(time.time() - scan_start, 3)

# Print summary of the scan results, total number of alerts, and unique affected files.
print("\n--- Scan Summary ---")
print(f"Directories scanned: {len(directories_scanned)}")
print(f"Files scanned: {total_files_scanned}")
print(f"Total alerts: {issues}")
print(f"Files with issues: {len(files_with_issues)}")
print(f"Skipped files: {skipped_files}")
print(f"Scan duration: {scan_duration}s")

# List the relative paths of affected files so the user knows exactly where to look.
if files_with_issues:
    print("Affected files:")
    for fname in sorted(files_with_issues):
        print(f" - {fname}")

# --- JSON output ---
# When --output json is specified, write a structured JSON file that can feed
# into OSCAL evidence pipelines or compliance dashboards. The structure has
# three sections:
#   1. scan_metadata — who/what/when context for the scan
#   2. findings — individual finding records with control mappings
#   3. summary — aggregate counts for quick assessment
#
# This supports CA-2 (Control Assessments) by producing machine-readable
# assessment evidence, and CA-7 (Continuous Monitoring) by enabling
# automated trend analysis across scans.
if args.output == "json":
    # Build findings_by_type: a dict of {pattern_name: count}.
    # This uses a simple loop instead of collections.Counter — both work,
    # but the explicit loop is easier to follow when you're learning Python.
    # Counter is worth knowing about though: it's in the collections module
    # and does exactly this in one line (Counter(f["finding_type"] for f in findings)).
    findings_by_type = {}
    for finding in findings:
        finding_type = finding["finding_type"]
        findings_by_type[finding_type] = findings_by_type.get(finding_type, 0) + 1

    # datetime.now(timezone.utc) returns the current time in UTC with timezone
    # info attached. .isoformat() formats it as ISO 8601 (e.g.,
    # "2026-03-19T14:30:00+00:00"), which is the standard for machine-readable
    # timestamps. UTC avoids timezone ambiguity in compliance evidence —
    # auditors in different timezones see the same time.
    scan_results = {
        "scan_metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "target_directory": str(folder),
            "scanner_version": SCANNER_VERSION,
            "duration_seconds": scan_duration,
            "patterns_active": len(patterns),
        },
        "findings": findings,
        "summary": {
            "total_files_scanned": total_files_scanned,
            "total_findings": len(findings),
            "files_with_findings": len(files_with_issues),
            "skipped_files": skipped_files,
            "findings_by_type": findings_by_type,
        },
    }

    # Use the --output-file flag value (defaults to "scan_results.json").
    # This replaces the old hardcoded filename so users can control where
    # results go — important for CI/CD pipelines that need run-specific
    # filenames and for avoiding silent overwrites of previous evidence.
    output_file = Path(args.output_file)

    # Warn if the output file already exists. We don't block the write
    # (the user asked for output, so we deliver it), but the warning
    # makes the overwrite visible rather than silent. In audit terms,
    # this supports AU-9: protection of audit information.
    if output_file.exists():
        print(f"\n[WARN] Output file already exists and will be overwritten: {output_file}")

    # json.dump() writes a Python dict to a file as JSON (PCC3e Ch 10).
    # indent=2 makes it human-readable. ensure_ascii=False allows Unicode
    # characters in file paths to render correctly instead of being escaped.
    with open(output_file, "w") as f:
        json.dump(scan_results, f, indent=2, ensure_ascii=False)

    print(f"\nJSON results written to: {output_file}")

# Exit with a non-zero code when secrets are found so CI/CD pipelines fail.
# Without this, a pipeline step using this scanner would always "pass," meaning
# the scanner enforces nothing — a finding for SA-11 and CM-3.
# --exit-zero overrides this for informational/audit-only runs.
if issues > 0 and not args.exit_zero:
    sys.exit(1)
else:
    sys.exit(0)
