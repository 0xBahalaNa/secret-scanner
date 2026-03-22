"""Generic secret detection patterns.

These patterns detect common credential types that aren't specific to a
single cloud provider or compliance framework: passwords, API keys, private
keys, JWT tokens, connection strings, and generic secret assignments.

Pattern design philosophy: require an assignment context (= or :) where
possible. This means 'password' in a comment won't trigger, but
'password = hunter2' will. This is the single biggest false-positive
reduction vs. substring matching.
"""

import re


def load():
    """Return generic secret patterns as a dict of {name: compiled regex}.

    Six patterns cover the most common credential types found across
    all technology stacks and compliance frameworks.
    """
    return {
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
    }
