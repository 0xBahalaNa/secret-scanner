"""Loader for user-defined custom detection patterns.

Custom patterns allow teams to extend the scanner for their specific
compliance context without modifying the scanner's source code. For example,
a PCI team might add credit card number patterns, while a healthcare team
adds PHI identifier patterns.

The JSON file should be a flat dict of {"pattern_name": "regex_string"}.
See custom_patterns.json.example in the repository root for the format.
"""

import json
import re
import sys
from pathlib import Path


def load(patterns_file):
    """Load additional patterns from a JSON file and return as compiled regexes.

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
