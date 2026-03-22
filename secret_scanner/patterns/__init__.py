"""Pattern loading and control mapping for the secret scanner.

This subpackage collects all built-in detection patterns from their
category modules (aws, cji, generic) and provides a single function
to load them all. This is the "Patterns loadable/extensible without
modifying scanner core" requirement from the modular architecture.

The control_map dict lives here because it's tightly coupled to the
pattern names — if you add a pattern, you should map it to controls
in the same place.
"""

from . import aws, cji, generic


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


def load_all_patterns():
    """Load and merge all built-in detection patterns.

    Calls the load() function from each category module (aws, cji, generic)
    and merges the results into a single dict. This uses dict.update()
    (PCC3e Ch 6: Dictionaries) to combine multiple dicts — later updates
    overwrite earlier keys, but since our pattern names are unique across
    modules, no collisions occur.

    Returns:
        A dict of {name: compiled regex} containing all built-in patterns.
    """
    patterns = {}
    patterns.update(aws.load())
    patterns.update(generic.load())
    patterns.update(cji.load())
    return patterns
