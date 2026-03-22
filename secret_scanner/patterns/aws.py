"""AWS credential detection patterns.

These patterns detect AWS Access Key IDs, Secret Access Keys, and Session
Tokens in configuration files and source code. AWS credentials in plaintext
are an immediate IA-5(7) finding — NIST 800-53 Rev 5 requires that no
unencrypted static authenticators are embedded in applications or scripts.

Each pattern returns a dict of {name: compiled regex} so they can be merged
into the scanner's master pattern set using dict.update() (PCC3e Ch 6:
Dictionaries — merging dictionaries).
"""

import re


def load():
    """Return AWS credential patterns as a dict of {name: compiled regex}.

    Three patterns cover the primary AWS credential types:
    - Access Key ID: the public half of an IAM keypair
    - Secret Access Key: the private half (40-char base64 string)
    - Session Token: temporary credentials from STS AssumeRole
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
    }
