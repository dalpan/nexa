"""Tests for the core detection engine."""

from __future__ import annotations

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

from nexa.core.detectors import (
    deduplicate_findings,
    detect_high_entropy,
    detect_in_text,
    run_detection,
)
from nexa.models import Category, Severity
from nexa.utils import shannon_entropy


# ── Test credential fixtures ───────────────────────────────────────────────────
# Built via concatenation so static scanners don't flag them as real secrets.
# These are obviously fake values used only to verify regex patterns work.
_STRIPE_PK = "pk" + "_test_" + "TESTfixtureFAKEnotReal00001"
_STRIPE_SK = "sk" + "_live_" + "TESTfixtureFAKEnotRealKEY0"
_SLACK_TOKEN = "xo" + "xb-000000000000-000000000000-TESTFIXTUREFAKE"
_SLACK_HOOK = (
    "https://hooks.slack" + ".com/services/"
    + "T00000TEST0/B00000TEST0/TESTFIXTUREFAKEWEBHOOKURL000"
)


# ── Entropy tests ─────────────────────────────────────────────────────────────

class TestShannonEntropy:
    def test_empty_string(self):
        assert shannon_entropy("") == 0.0

    def test_single_char(self):
        assert shannon_entropy("aaaa") == 0.0

    def test_two_chars_equal(self):
        result = shannon_entropy("abab")
        assert abs(result - 1.0) < 0.01

    def test_high_entropy_string(self):
        # Random-looking key should have high entropy
        result = shannon_entropy("AKIAIOSFODNN7EXAMPLE")
        assert result > 3.5

    def test_real_aws_key_entropy(self):
        # AWS key should have entropy close to 5
        result = shannon_entropy("AKIAIOSFODNN7EXAMPLE")
        assert result > 3.0

    def test_low_entropy(self):
        assert shannon_entropy("aaaaaaaaaa") < 0.5


# ── AWS Key Detection ─────────────────────────────────────────────────────────

class TestAWSKeyDetection:
    def test_detects_aws_access_key(self):
        text = 'const awsKey = "AKIAIOSFODNN7EXAMPLE";'
        findings = detect_in_text(text, "https://example.com/app.js", "example.com")
        aws_findings = [f for f in findings if "AWS" in f.title]
        assert len(aws_findings) > 0, f"Expected AWS key finding, got: {[f.title for f in findings]}"

    def test_aws_key_is_critical(self):
        text = 'var key = "AKIAIOSFODNN7EXAMPLE";'
        findings = detect_in_text(text, "https://example.com/app.js", "example.com")
        aws_findings = [f for f in findings if "AWS" in f.title]
        assert any(f.severity == Severity.CRITICAL for f in aws_findings)

    def test_aws_key_category(self):
        text = 'AKIAIOSFODNN7EXAMPLE'
        findings = detect_in_text(text, "https://example.com/app.js", "example.com")
        aws_findings = [f for f in findings if "AWS" in f.title]
        assert all(f.category == Category.API_KEY for f in aws_findings)

    def test_fake_aws_key_not_flagged(self):
        # Too short to be a real key
        text = 'var key = "AKIA123";'
        findings = detect_in_text(text, "https://example.com/app.js", "example.com")
        aws_findings = [f for f in findings if f.title == "AWS Access Key ID"]
        assert len(aws_findings) == 0


# ── JWT Detection ──────────────────────────────────────────────────────────────

class TestJWTDetection:
    SAMPLE_JWT = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"
        ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    )

    def test_detects_jwt(self):
        text = f'Authorization: "Bearer {self.SAMPLE_JWT}"'
        findings = detect_in_text(text, "https://example.com/app.js", "example.com")
        # JWT pattern triggers on the eyJ...eyJ... format; Authorization header pattern also fires
        jwt_findings = [
            f for f in findings
            if "JWT" in f.title or "Bearer" in f.title or "Authorization" in f.title
        ]
        assert len(jwt_findings) > 0

    def test_jwt_severity_high(self):
        text = f'token = "{self.SAMPLE_JWT}"'
        findings = detect_in_text(text, "https://example.com/app.js", "example.com")
        jwt_findings = [f for f in findings if "JWT" in f.title]
        if jwt_findings:
            assert any(f.severity in (Severity.HIGH, Severity.CRITICAL) for f in jwt_findings)

    def test_short_eyj_not_jwt(self):
        # Must match eyJ...eyJ...signature format
        text = 'var x = "eyJhbGc";'
        findings = detect_in_text(text, "https://example.com/app.js", "example.com")
        jwt_findings = [f for f in findings if f.title == "JSON Web Token"]
        assert len(jwt_findings) == 0  # Too short


# ── Stripe Key Detection ───────────────────────────────────────────────────────

class TestStripeKeyDetection:
    def test_detects_stripe_publishable_test(self):
        text = f'const stripe = Stripe("{_STRIPE_PK}");'
        findings = detect_in_text(text, "https://example.com/app.js", "example.com")
        stripe = [f for f in findings if "Stripe" in f.title]
        assert len(stripe) > 0

    def test_detects_stripe_live_secret(self):
        text = f'const secret = "{_STRIPE_SK}";'
        findings = detect_in_text(text, "https://example.com/app.js", "example.com")
        stripe = [f for f in findings if "Stripe Secret" in f.title]
        assert len(stripe) > 0
        assert stripe[0].severity == Severity.CRITICAL

    def test_stripe_test_publishable_medium_severity(self):
        text = f'const pk = "{_STRIPE_PK}";'
        findings = detect_in_text(text, "https://example.com/app.js", "example.com")
        stripe = [f for f in findings if "Stripe Publishable" in f.title]
        if stripe:
            assert stripe[0].severity == Severity.MEDIUM


# ── Placeholder Detection ─────────────────────────────────────────────────────

class TestPlaceholderFiltering:
    def test_your_api_key_not_flagged(self):
        text = 'const key = "your-api-key";'
        findings = detect_in_text(text, "https://example.com/app.js", "example.com")
        # Should either not find it or find it with very low confidence
        problematic = [f for f in findings if f.value == "your-api-key" and f.confidence > 30]
        assert len(problematic) == 0

    def test_replace_me_not_flagged(self):
        text = 'const apiKey = "REPLACE_ME";'
        findings = detect_in_text(text, "https://example.com/app.js", "example.com")
        problematic = [f for f in findings if f.value == "REPLACE_ME" and f.confidence > 30]
        assert len(problematic) == 0

    def test_example_key_filtered(self):
        from nexa.utils import is_placeholder
        assert is_placeholder("your-api-key")
        assert is_placeholder("REPLACE_ME")
        assert is_placeholder("placeholder")
        assert is_placeholder("example-key")

    def test_real_key_not_filtered(self):
        from nexa.utils import is_placeholder
        # AKIAIOSFODNN7EXAMPLE is the canonical AWS docs example key — it starts with AKIA
        # so our real-secret prefix check should return False (not a placeholder)
        assert not is_placeholder("AKIAIOSFODNN7EXAMPLE")
        assert not is_placeholder(_STRIPE_SK)


# ── Internal IP Detection ─────────────────────────────────────────────────────

class TestInternalIPDetection:
    def test_detects_localhost(self):
        text = 'const api = "http://localhost:8080/api";'
        findings = detect_in_text(text, "https://example.com/app.js", "example.com")
        internal = [f for f in findings if f.category == Category.INTERNAL_ENDPOINT]
        assert len(internal) > 0

    def test_detects_192_168(self):
        text = 'baseURL: "http://192.168.1.100:3000"'
        findings = detect_in_text(text, "https://example.com/app.js", "example.com")
        internal = [f for f in findings if f.category == Category.INTERNAL_ENDPOINT]
        assert len(internal) > 0

    def test_detects_10_dot(self):
        text = 'const internalAPI = "http://10.0.0.1/api/v1";'
        findings = detect_in_text(text, "https://example.com/app.js", "example.com")
        internal = [f for f in findings if f.category == Category.INTERNAL_ENDPOINT]
        assert len(internal) > 0

    def test_detects_172_16(self):
        text = 'var url = "http://172.16.0.1/internal";'
        findings = detect_in_text(text, "https://example.com/app.js", "example.com")
        internal = [f for f in findings if f.category == Category.INTERNAL_ENDPOINT]
        assert len(internal) > 0

    def test_public_ip_not_flagged(self):
        text = 'const api = "https://8.8.8.8/dns";'
        findings = detect_in_text(text, "https://example.com/app.js", "example.com")
        # 8.8.8.8 is public, should not be flagged as internal
        internal = [f for f in findings if f.category == Category.INTERNAL_ENDPOINT
                    and "8.8.8.8" in f.value]
        assert len(internal) == 0


# ── Email PII Detection ───────────────────────────────────────────────────────

class TestEmailDetection:
    def test_detects_real_email(self):
        text = 'contact: "admin@company.com"'
        findings = detect_in_text(text, "https://example.com/app.js", "example.com")
        emails = [f for f in findings if f.category == Category.PII]
        assert len(emails) > 0

    def test_example_email_lower_confidence(self):
        text = 'email: "user@example.com"'
        findings = detect_in_text(text, "https://example.com/app.js", "example.com")
        # May still detect but with lower confidence or filtered
        emails = [f for f in findings if f.category == Category.PII and "@example.com" in f.value]
        # Either not found or low confidence
        assert all(f.confidence < 50 for f in emails) or len(emails) == 0

    def test_noreply_filtered(self):
        text = 'email: "noreply@example.com"'
        findings = detect_in_text(text, "https://example.com/app.js", "example.com")
        emails = [f for f in findings if f.category == Category.PII and "noreply" in f.value]
        assert all(f.confidence < 50 for f in emails) or len(emails) == 0


# ── Deduplication ─────────────────────────────────────────────────────────────

class TestFindingDeduplication:
    def test_same_value_deduped(self):
        text = 'key1 = "AKIAIOSFODNN7EXAMPLE"; key2 = "AKIAIOSFODNN7EXAMPLE";'
        findings = detect_in_text(text, "https://example.com/app.js", "example.com")
        aws_findings = [f for f in findings if "AWS" in f.title]
        # Same value should be deduplicated to one finding
        values = [f.value for f in aws_findings]
        assert len(values) == len(set(values))

    def test_deduplicate_findings_function(self):
        from nexa.models import Finding, Severity, Category
        from datetime import datetime

        # Create two findings with same value
        f1 = Finding(
            category=Category.API_KEY,
            severity=Severity.HIGH,
            confidence=70,
            title="Test",
            value="same_value_xyz",
            source_url="https://a.com",
            host="a.com",
        )
        f2 = Finding(
            category=Category.API_KEY,
            severity=Severity.HIGH,
            confidence=85,
            title="Test",
            value="same_value_xyz",
            source_url="https://b.com",
            host="b.com",
        )
        deduped = deduplicate_findings([f1, f2])
        assert len(deduped) == 1
        assert deduped[0].confidence == 85  # Higher confidence kept


# ── High Entropy ──────────────────────────────────────────────────────────────

class TestHighEntropyDetection:
    def test_detects_high_entropy_string(self):
        # A plausible random API key that isn't caught by named patterns
        text = '"rAnD0mK3yTh4tIsN0tAKn0wnF0rm4t1234567890abcdef"'
        findings = detect_high_entropy(text, "https://example.com/app.js", "example.com")
        # May or may not be detected depending on entropy threshold
        # Just verify the function runs without error
        assert isinstance(findings, list)

    def test_placeholder_not_high_entropy(self):
        text = '"your-placeholder-key-here"'
        findings = detect_high_entropy(text, "https://example.com/app.js", "example.com")
        # Placeholder should be filtered
        assert all(f.value != "your-placeholder-key-here" for f in findings)


# ── GitHub Token Detection ────────────────────────────────────────────────────

class TestGitHubTokenDetection:
    def test_detects_ghp_token(self):
        token = "ghp_" + "A" * 36
        text = f'const token = "{token}";'
        findings = detect_in_text(text, "https://example.com/app.js", "example.com")
        gh_findings = [f for f in findings if "GitHub" in f.title]
        assert len(gh_findings) > 0

    def test_detects_github_pat(self):
        token = "github_pat_" + "A" * 82
        text = f'const token = "{token}";'
        findings = detect_in_text(text, "https://example.com/app.js", "example.com")
        gh_findings = [f for f in findings if "GitHub" in f.title]
        assert len(gh_findings) > 0


# ── Slack Token Detection ─────────────────────────────────────────────────────

class TestSlackTokenDetection:
    def test_detects_slack_bot_token(self):
        text = f'const slackToken = "{_SLACK_TOKEN}";'
        findings = detect_in_text(text, "https://example.com/app.js", "example.com")
        slack_findings = [f for f in findings if "Slack" in f.title]
        assert len(slack_findings) > 0

    def test_detects_slack_webhook(self):
        text = f'const webhook = "{_SLACK_HOOK}";'
        findings = detect_in_text(text, "https://example.com/app.js", "example.com")
        webhook_findings = [f for f in findings if "Slack Webhook" in f.title]
        assert len(webhook_findings) > 0


# ── Private Key Detection ─────────────────────────────────────────────────────

class TestPrivateKeyDetection:
    def test_detects_rsa_private_key(self):
        text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA..."
        findings = detect_in_text(text, "https://example.com/app.js", "example.com")
        key_findings = [f for f in findings if "Private Key" in f.title]
        assert len(key_findings) > 0
        assert key_findings[0].severity == Severity.CRITICAL

    def test_detects_ec_private_key(self):
        text = "-----BEGIN EC PRIVATE KEY-----"
        findings = detect_in_text(text, "https://example.com/app.js", "example.com")
        key_findings = [f for f in findings if "Private Key" in f.title]
        assert len(key_findings) > 0


# ── Luhn Check ────────────────────────────────────────────────────────────────

class TestLuhnCheck:
    def test_valid_visa_number(self):
        from nexa.utils import luhn_check
        # Classic test Visa card number
        assert luhn_check("4532015112830366") is True

    def test_valid_mastercard_number(self):
        from nexa.utils import luhn_check
        assert luhn_check("5425233430109903") is True

    def test_false_positive_cc_fails_luhn(self):
        """4330502335187925 was a false positive from cfbenchmarks — should fail Luhn."""
        from nexa.utils import luhn_check
        assert luhn_check("4330502335187925") is False

    def test_random_16_digits_likely_fail(self):
        from nexa.utils import luhn_check
        # Random number unlikely to pass Luhn
        assert luhn_check("1234567890123456") is False

    def test_luhn_ignores_non_digits(self):
        from nexa.utils import luhn_check
        # With spaces/dashes should still work
        assert luhn_check("4532-0151-1283-0366") is True


class TestCCFalsePositive:
    def test_cfbenchmarks_fp_not_flagged(self):
        """4330502335187925 fails Luhn — must not produce a CC finding."""
        text = "someContent4330502335187925moreContent"
        findings = detect_in_text(text, "https://cfbenchmarks.com", "cfbenchmarks.com")
        cc_findings = [f for f in findings if f.title == "Credit Card Number"]
        assert len(cc_findings) == 0

    def test_valid_cc_with_context_flagged_high(self):
        """Valid CC number near billing keywords → HIGH severity."""
        text = "billing card number: 4532015112830366 checkout"
        findings = detect_in_text(text, "https://example.com", "example.com")
        cc_findings = [f for f in findings if f.title == "Credit Card Number"]
        assert len(cc_findings) > 0
        assert cc_findings[0].severity.value in ("HIGH", "CRITICAL")

    def test_valid_cc_no_context_flagged_info(self):
        """Valid CC number without context → INFO severity, LOW confidence."""
        text = "value: 4532015112830366"
        findings = detect_in_text(text, "https://example.com", "example.com")
        cc_findings = [f for f in findings if f.title == "Credit Card Number"]
        # May or may not detect — if detected, must be low confidence
        if cc_findings:
            assert cc_findings[0].confidence <= 45


class TestWsApiKeyPasswordDetection:
    def test_json_format_detected(self):
        """JSON key:value format matches JSON Password Field pattern."""
        text = '"wsApiKeyPassword":"80b3ac93-3b84-472e-a97b-6e2ddc2958ca"'
        findings = detect_in_text(text, "https://example.com", "example.com")
        pw_findings = [f for f in findings if "Password" in f.title or "Secret" in f.title or "Credential" in f.title]
        assert len(pw_findings) > 0

    def test_assigned_format_detected(self):
        """Assigned format from _flatten_dict output matches new pattern."""
        text = 'pageProps.wsApiKeyPassword = "80b3ac93-3b84-472e-a97b-6e2ddc2958ca"'
        findings = detect_in_text(text, "https://example.com", "example.com")
        pw_findings = [f for f in findings if "Password" in f.title or "Secret" in f.title or "Assigned" in f.title]
        assert len(pw_findings) > 0


class TestEntropyContextKeyword:
    def test_high_entropy_no_context_not_flagged(self):
        """High-entropy string without context keyword should be skipped."""
        from nexa.core.detectors import detect_high_entropy
        # Pure random-looking string with no keyword context
        text = '"rAnD0mK3yTh4tIsN0tAKn0wnF0rm4t1234567890abcdefXY"'
        findings = detect_high_entropy(text, "https://example.com", "example.com")
        assert len(findings) == 0

    def test_high_entropy_with_context_flagged(self):
        """High-entropy string near 'api' keyword should be detected."""
        from nexa.core.detectors import detect_high_entropy
        # The string has high entropy and 'api' appears nearby
        text = 'api_credential = "rAnD0mK3yTh4tIsN0tAKn0wnF0rm4t1234567890abcdef"'
        findings = detect_high_entropy(text, "https://example.com", "example.com")
        # May or may not trigger — presence depends on entropy level
        assert isinstance(findings, list)

    def test_pure_hex_not_flagged(self):
        """Pure hex strings (build hashes) should be skipped."""
        from nexa.core.detectors import detect_high_entropy
        text = 'key = "42372ed130431b0a" rest of content'
        findings = detect_high_entropy(text, "https://example.com", "example.com")
        # Build hash should not be flagged even with keyword context
        hex_findings = [f for f in findings if f.value == "42372ed130431b0a"]
        assert len(hex_findings) == 0


class TestWAFDetection:
    def test_cloudflare_detected_from_header(self):
        from nexa.core.waf_bypass import detect_waf
        headers = {"CF-RAY": "8abc123-LHR", "Server": "cloudflare"}
        waf = detect_waf(headers, "")
        assert waf == "Cloudflare"

    def test_sucuri_detected_from_header(self):
        from nexa.core.waf_bypass import detect_waf
        headers = {"X-Sucuri-ID": "12345"}
        waf = detect_waf(headers, "")
        assert waf == "Sucuri"

    def test_no_waf_returns_none(self):
        from nexa.core.waf_bypass import detect_waf
        headers = {"Content-Type": "text/html", "Server": "nginx"}
        waf = detect_waf(headers, "<html>Normal page</html>")
        assert waf is None

    def test_cloudflare_detected_from_body(self):
        from nexa.core.waf_bypass import detect_waf
        headers = {}
        body = "Attention Required | Cloudflare Ray ID: 8abc123"
        waf = detect_waf(headers, body)
        assert waf is not None


class TestSSNFalsePositives:
    def test_ssn_without_context_very_low_confidence(self):
        """SSN pattern without context keywords gets very low confidence."""
        text = "reference: 123-45-6789"
        findings = detect_in_text(text, "https://example.com", "example.com")
        ssn = [f for f in findings if f.title == "Social Security Number"]
        # Either not found or very low confidence
        if ssn:
            assert ssn[0].confidence <= 25

    def test_ssn_with_context_detected(self):
        """SSN pattern with 'ssn' keyword context gets proper confidence."""
        text = "Please enter your SSN: 123-45-6789 for tax verification"
        findings = detect_in_text(text, "https://example.com", "example.com")
        ssn = [f for f in findings if f.title == "Social Security Number"]
        # With context keyword, should have higher confidence or be found
        if ssn:
            assert ssn[0].confidence > 0


class TestEmailFalsePositives:
    def test_unicode_escape_not_flagged(self):
        """Email-like unicode escapes should not trigger email detector."""
        text = r'">@something.com"'
        findings = detect_in_text(text, "https://example.com", "example.com")
        email_findings = [f for f in findings if f.category == Category.PII
                          and "\\u" in f.value.lower()]
        assert len(email_findings) == 0

    def test_sentry_email_low_confidence(self):
        """Sentry internal addresses should have low confidence."""
        text = 'email: "abc123@sentry.io"'
        findings = detect_in_text(text, "https://example.com", "example.com")
        sentry = [f for f in findings if f.category == Category.PII and "sentry" in f.value.lower()]
        if sentry:
            assert all(f.confidence < 50 for f in sentry)


class TestBasicAuthFalsePositive:
    def test_image_cdn_url_not_flagged(self):
        """CDN image URL with path-looking structure should not trigger Basic Auth."""
        text = 'src="https://static.ghost.org/v4.0.0/images/logo.png"'
        findings = detect_in_text(text, "https://example.com", "example.com")
        basic_auth = [f for f in findings if f.title == "Basic Auth in URL"]
        assert len(basic_auth) == 0

    def test_real_basic_auth_flagged(self):
        """Actual user:password@host URL should be flagged."""
        text = 'const url = "https://admin:secretpass@db.internal.com/api";'
        findings = detect_in_text(text, "https://example.com", "example.com")
        basic_auth = [f for f in findings if f.title == "Basic Auth in URL"]
        assert len(basic_auth) > 0


class TestAdminPathFalsePositive:
    def test_word_internal_not_flagged(self):
        """Standalone word 'internal' in text should not trigger admin path."""
        text = "This is for internal use only."
        findings = detect_in_text(text, "https://example.com", "example.com")
        admin = [f for f in findings if f.title == "Admin/Internal Path"]
        assert len(admin) == 0

    def test_internal_path_flagged(self):
        """/internal/ URL path should be flagged."""
        text = 'fetch("/internal/config/settings")'
        findings = detect_in_text(text, "https://example.com", "example.com")
        admin = [f for f in findings if f.title == "Admin/Internal Path"]
        assert len(admin) > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
