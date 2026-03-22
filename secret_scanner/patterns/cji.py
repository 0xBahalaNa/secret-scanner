"""CJIS Criminal Justice Information (CJI) detection patterns.

CJIS Security Policy v6.0 requires that CJI — including ORI numbers, NCIC
codes, FBI numbers, and State IDs — never appear in plaintext outside of
authorized, encrypted systems. Detecting CJI leakage in config files and
source code addresses:
  - SC-28 (Protection of Information at Rest): CJI must be encrypted
  - SC-13 (Cryptographic Protection): FIPS 140-2/3 validated crypto

A CJI leak in a config file is an immediate CJIS audit finding. These
patterns are the primary differentiator for this scanner in a public safety
technology context.
"""

import re


def load():
    """Return CJI detection patterns as a dict of {name: compiled regex}.

    Four patterns cover the primary CJI identifier types found in law
    enforcement systems: ORI numbers, NCIC query codes, FBI numbers
    (UCN), and State IDs (SID).
    """
    return {
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
        # common two-letter combos.
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
