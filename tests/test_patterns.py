"""Tests for secret detection patterns.

Each test verifies that a pattern matches known-positive strings and
does NOT match known-negative strings (false positive prevention).
This is the most critical test file — if a pattern regresses, secrets
go undetected, which is an IA-5(7) gap.

Uses pytest's plain assert statements (PCC3e Ch 11: Testing Your Code).
No fixtures needed — patterns are pure functions that return compiled regex.
"""

from secret_scanner.patterns import load_all_patterns, CONTROL_MAP, SEVERITY_MAP
from secret_scanner.patterns import aws, cji, generic
from secret_scanner.patterns.custom import load as load_custom


# --- Pattern loading tests ---

def test_load_all_patterns_returns_13():
    """All 13 built-in patterns should be loaded."""
    patterns = load_all_patterns()
    assert len(patterns) == 13


def test_load_all_patterns_names():
    """Verify all expected pattern names are present."""
    patterns = load_all_patterns()
    expected = {
        "AWS Access Key ID", "AWS Secret Access Key", "AWS Session Token",
        "Password Assignment", "Secret Assignment", "API Key",
        "Private Key Header", "JWT Token", "Connection String",
        "CJI: ORI Number", "CJI: NCIC Query Code",
        "CJI: FBI Number", "CJI: State ID (SID)",
    }
    assert set(patterns.keys()) == expected


def test_every_pattern_has_control_mapping():
    """Every built-in pattern must have a CONTROL_MAP entry."""
    patterns = load_all_patterns()
    for name in patterns:
        assert name in CONTROL_MAP, f"Missing CONTROL_MAP entry for '{name}'"


def test_every_pattern_has_severity_mapping():
    """Every built-in pattern must have a SEVERITY_MAP entry."""
    patterns = load_all_patterns()
    for name in patterns:
        assert name in SEVERITY_MAP, f"Missing SEVERITY_MAP entry for '{name}'"


def test_aws_loads_3_patterns():
    """AWS module should provide exactly 3 patterns."""
    assert len(aws.load()) == 3


def test_cji_loads_4_patterns():
    """CJI module should provide exactly 4 patterns."""
    assert len(cji.load()) == 4


def test_generic_loads_6_patterns():
    """Generic module should provide exactly 6 patterns."""
    assert len(generic.load()) == 6


# --- AWS pattern matching tests ---

class TestAWSAccessKeyID:
    """Tests for the AWS Access Key ID pattern."""

    def setup_method(self):
        """Load patterns once for each test method."""
        self.pattern = load_all_patterns()["AWS Access Key ID"]

    def test_matches_valid_key(self):
        assert self.pattern.search("AKIAIOSFODNN7EXAMPLE")

    def test_matches_key_in_assignment(self):
        assert self.pattern.search('aws_access_key_id = "AKIAIOSFODNN7EXAMPLE"')

    def test_rejects_short_key(self):
        """Key ID must be exactly AKIA + 16 chars."""
        assert not self.pattern.search("AKIATOOSHORT")

    def test_rejects_lowercase(self):
        """AWS key IDs are uppercase only."""
        assert not self.pattern.search("AKIAiosfodnn7example")

    def test_rejects_no_akia_prefix(self):
        assert not self.pattern.search("XKIAIOSFODNN7EXAMPLE")


class TestAWSSecretAccessKey:
    """Tests for the AWS Secret Access Key pattern."""

    def setup_method(self):
        self.pattern = load_all_patterns()["AWS Secret Access Key"]

    def test_matches_with_equals(self):
        assert self.pattern.search(
            "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        )

    def test_matches_with_colon(self):
        assert self.pattern.search(
            'secret_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"'
        )

    def test_matches_case_insensitive(self):
        assert self.pattern.search(
            "AWS_SECRET_ACCESS_KEY = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        )

    def test_rejects_short_value(self):
        """Secret keys are 40 chars — shorter values shouldn't match."""
        assert not self.pattern.search("aws_secret_access_key = tooshort")

    def test_rejects_comment_mention(self):
        """A comment about secret keys without assignment shouldn't match."""
        assert not self.pattern.search("# The aws_secret_access_key goes here")


class TestAWSSessionToken:
    """Tests for the AWS Session Token pattern."""

    def setup_method(self):
        self.pattern = load_all_patterns()["AWS Session Token"]

    def test_matches_token_assignment(self):
        assert self.pattern.search(
            "aws_session_token = FwoGZXIvYXdzEBYaDHqa0AP"
        )

    def test_rejects_no_assignment(self):
        assert not self.pattern.search("aws_session_token is required")


# --- Generic pattern matching tests ---

class TestPasswordAssignment:
    """Tests for the Password Assignment pattern."""

    def setup_method(self):
        self.pattern = load_all_patterns()["Password Assignment"]

    def test_matches_password_equals(self):
        assert self.pattern.search('password = "hunter2"')

    def test_matches_passwd_colon(self):
        assert self.pattern.search('passwd: "s3cret"')

    def test_matches_pwd_equals(self):
        assert self.pattern.search("pwd = mypassword123")

    def test_matches_json_format(self):
        assert self.pattern.search('"password": "hunter2"')

    def test_rejects_bare_mention(self):
        """A comment mentioning 'password' without assignment shouldn't match."""
        assert not self.pattern.search("# never store passwords in plaintext")


class TestSecretAssignment:
    """Tests for the Secret Assignment pattern."""

    def setup_method(self):
        self.pattern = load_all_patterns()["Secret Assignment"]

    def test_matches_secret_equals(self):
        assert self.pattern.search('secret = "abc123"')

    def test_matches_secret_key_colon(self):
        assert self.pattern.search("secret_key: some_value")

    def test_rejects_bare_mention(self):
        assert not self.pattern.search("# this is a secret feature")


class TestAPIKey:
    """Tests for the API Key pattern."""

    def setup_method(self):
        self.pattern = load_all_patterns()["API Key"]

    def test_matches_api_key_equals(self):
        assert self.pattern.search('api_key = "sk-live-abc123"')

    def test_matches_apikey_colon(self):
        assert self.pattern.search("apikey: my-secret-key")

    def test_matches_api_dash_key(self):
        assert self.pattern.search("api-key = something")

    def test_rejects_bare_mention(self):
        assert not self.pattern.search("# get your api_key from the dashboard")


class TestPrivateKeyHeader:
    """Tests for the Private Key Header pattern."""

    def setup_method(self):
        self.pattern = load_all_patterns()["Private Key Header"]

    def test_matches_rsa(self):
        assert self.pattern.search("-----BEGIN RSA PRIVATE KEY-----")

    def test_matches_generic(self):
        assert self.pattern.search("-----BEGIN PRIVATE KEY-----")

    def test_matches_ec(self):
        assert self.pattern.search("-----BEGIN EC PRIVATE KEY-----")

    def test_matches_openssh(self):
        assert self.pattern.search("-----BEGIN OPENSSH PRIVATE KEY-----")

    def test_rejects_public_key(self):
        assert not self.pattern.search("-----BEGIN PUBLIC KEY-----")


class TestJWTToken:
    """Tests for the JWT Token pattern."""

    def setup_method(self):
        self.pattern = load_all_patterns()["JWT Token"]

    def test_matches_valid_jwt(self):
        assert self.pattern.search(
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkw"
        )

    def test_rejects_short_segments(self):
        """JWT segments must be at least 10 chars each."""
        assert not self.pattern.search("eyJhbG.eyJz")


class TestConnectionString:
    """Tests for the Connection String pattern."""

    def setup_method(self):
        self.pattern = load_all_patterns()["Connection String"]

    def test_matches_postgresql(self):
        assert self.pattern.search(
            "postgresql://admin:s3cret@db.example.com:5432/mydb"
        )

    def test_matches_mysql(self):
        assert self.pattern.search("mysql://root:password@localhost/test")

    def test_rejects_no_credentials(self):
        """URLs without embedded credentials shouldn't match."""
        assert not self.pattern.search("https://example.com/api/v1")


# --- CJI pattern matching tests ---

class TestCJIORI:
    """Tests for the CJI: ORI Number pattern."""

    def setup_method(self):
        self.pattern = load_all_patterns()["CJI: ORI Number"]

    def test_matches_california_ori(self):
        assert self.pattern.search('ori = "CA0380000"')

    def test_matches_texas_ori(self):
        assert self.pattern.search("agency_id: TX0140000")

    def test_matches_json_format(self):
        assert self.pattern.search('"ori": "NY0300000"')

    def test_rejects_invalid_state_code(self):
        """XX is not a valid FIPS state code."""
        assert not self.pattern.search('ori = "XX0380000"')

    def test_rejects_no_assignment_context(self):
        """Random alphanumeric strings shouldn't match without a keyword."""
        assert not self.pattern.search("CA0380000")


class TestCJINCIC:
    """Tests for the CJI: NCIC Query Code pattern."""

    def setup_method(self):
        self.pattern = load_all_patterns()["CJI: NCIC Query Code"]

    def test_matches_hot_file_query(self):
        assert self.pattern.search("NCIC QH hot file query")

    def test_matches_wanted_persons(self):
        assert self.pattern.search("NCIC QW wanted persons check")

    def test_rejects_without_ncic_keyword(self):
        """QH alone is too generic — requires NCIC nearby."""
        assert not self.pattern.search("QH query submitted")


class TestCJIFBI:
    """Tests for the CJI: FBI Number pattern."""

    def setup_method(self):
        self.pattern = load_all_patterns()["CJI: FBI Number"]

    def test_matches_fbi_number(self):
        assert self.pattern.search('fbi_number = "123456AA7"')

    def test_matches_ucn(self):
        assert self.pattern.search("ucn: 987654321")

    def test_rejects_no_keyword(self):
        assert not self.pattern.search("123456AA7")


class TestCJISID:
    """Tests for the CJI: State ID (SID) pattern."""

    def setup_method(self):
        self.pattern = load_all_patterns()["CJI: State ID (SID)"]

    def test_matches_sid(self):
        assert self.pattern.search('sid = "CA12345678"')

    def test_matches_state_id(self):
        assert self.pattern.search("state_id: NY98765432")

    def test_rejects_no_keyword(self):
        assert not self.pattern.search("CA12345678")


# --- Custom pattern loading tests ---

def test_custom_patterns_load(tmp_path):
    """Custom patterns file should load and compile regex."""
    patterns_file = tmp_path / "custom.json"
    patterns_file.write_text('{"Test Pattern": "test_[0-9]+"}')

    result = load_custom(str(patterns_file))
    assert "Test Pattern" in result
    assert result["Test Pattern"].search("test_123")


def test_custom_patterns_invalid_json(tmp_path):
    """Invalid JSON should cause SystemExit."""
    patterns_file = tmp_path / "bad.json"
    patterns_file.write_text("not json at all")

    import pytest
    with pytest.raises(SystemExit):
        load_custom(str(patterns_file))


def test_custom_patterns_invalid_regex(tmp_path):
    """Invalid regex syntax should cause SystemExit."""
    patterns_file = tmp_path / "bad_regex.json"
    patterns_file.write_text('{"Bad": "[invalid"}')

    import pytest
    with pytest.raises(SystemExit):
        load_custom(str(patterns_file))


def test_custom_patterns_nonexistent_file():
    """Nonexistent file should cause SystemExit."""
    import pytest
    with pytest.raises(SystemExit):
        load_custom("/nonexistent/path/patterns.json")
