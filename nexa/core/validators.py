"""Passive validators for detected secrets and tokens."""

from __future__ import annotations

import base64
import binascii
import json
import logging
import re
from datetime import datetime, timezone
from typing import Optional

from nexa.models import Finding, ValidationResult

logger = logging.getLogger(__name__)


def _b64_decode(s: str) -> Optional[bytes]:
    """Attempt to base64-decode a string, trying multiple padding strategies."""
    for pad in range(4):
        try:
            return base64.urlsafe_b64decode(s + "=" * pad)
        except (binascii.Error, ValueError):
            continue
    try:
        return base64.b64decode(s + "==")
    except Exception:
        return None


def validate_jwt(value: str) -> ValidationResult:
    """Decode and validate a JWT format token."""
    parts = value.split(".")
    if len(parts) != 3:
        return ValidationResult(
            provider="JWT",
            format_valid=False,
            likely_test=False,
            notes=["Not a valid JWT (wrong number of segments)"],
        )

    header_data = _b64_decode(parts[0])
    payload_data = _b64_decode(parts[1])

    metadata: dict = {}
    notes: list[str] = []
    likely_test = False

    if header_data:
        try:
            header = json.loads(header_data.decode("utf-8", errors="replace"))
            metadata["algorithm"] = header.get("alg", "unknown")
            metadata["type"] = header.get("typ", "unknown")
            if header.get("alg") in ("none", "HS256") and not header.get("typ"):
                notes.append("Suspicious: alg=none or weak algorithm")
        except json.JSONDecodeError:
            notes.append("Could not decode JWT header")

    if payload_data:
        try:
            payload = json.loads(payload_data.decode("utf-8", errors="replace"))
            metadata["subject"] = payload.get("sub", "")
            metadata["issuer"] = payload.get("iss", "")
            metadata["audience"] = payload.get("aud", "")

            exp = payload.get("exp")
            if exp:
                try:
                    exp_dt = datetime.fromtimestamp(int(exp), tz=timezone.utc)
                    metadata["expires"] = exp_dt.isoformat()
                    if exp_dt < datetime.now(tz=timezone.utc):
                        notes.append(f"Token is EXPIRED (expired {exp_dt.isoformat()})")
                        likely_test = True
                    else:
                        notes.append(f"Token expires: {exp_dt.isoformat()}")
                except (ValueError, OSError):
                    pass

            iat = payload.get("iat")
            if iat:
                try:
                    iat_dt = datetime.fromtimestamp(int(iat), tz=timezone.utc)
                    metadata["issued_at"] = iat_dt.isoformat()
                except (ValueError, OSError):
                    pass

            # Detect test/demo tokens
            iss = str(payload.get("iss", "")).lower()
            sub = str(payload.get("sub", "")).lower()
            if any(kw in iss + sub for kw in ("test", "demo", "example", "dummy", "fake")):
                likely_test = True
                notes.append("Token claims suggest test/demo environment")

        except json.JSONDecodeError:
            notes.append("Could not decode JWT payload")

    return ValidationResult(
        provider="JWT",
        format_valid=True,
        likely_test=likely_test,
        metadata=metadata,
        notes=notes,
    )


def validate_aws_key(value: str) -> ValidationResult:
    """Validate AWS Access Key ID format."""
    notes: list[str] = []
    metadata: dict = {}

    if re.fullmatch(r"AKIA[0-9A-Z]{16}", value):
        metadata["type"] = "Access Key ID"
        metadata["prefix"] = value[:4]
        notes.append("Valid AKIA format — long-term access key")
        format_valid = True
    elif re.fullmatch(r"ASIA[0-9A-Z]{16}", value):
        metadata["type"] = "Temporary Access Key (STS)"
        notes.append("ASIA prefix indicates STS/assumed role temporary credentials")
        format_valid = True
    elif re.fullmatch(r"AROA[0-9A-Z]{16}", value):
        metadata["type"] = "Role ID"
        format_valid = True
    else:
        notes.append("Does not match standard AWS key format")
        format_valid = False

    return ValidationResult(
        provider="AWS",
        format_valid=format_valid,
        likely_test=False,
        metadata=metadata,
        notes=notes,
    )


def validate_stripe_key(value: str) -> ValidationResult:
    """Validate Stripe API key format."""
    notes: list[str] = []
    metadata: dict = {}
    likely_test = False

    if value.startswith("pk_test_"):
        metadata["type"] = "Publishable Key"
        metadata["environment"] = "test"
        likely_test = True
        notes.append("Stripe TEST publishable key — not a real key, but confirms Stripe integration")
    elif value.startswith("pk_live_"):
        metadata["type"] = "Publishable Key"
        metadata["environment"] = "live"
        notes.append("Stripe LIVE publishable key — safe to expose but confirms production environment")
    elif value.startswith("sk_test_"):
        metadata["type"] = "Secret Key"
        metadata["environment"] = "test"
        likely_test = True
        notes.append("Stripe TEST secret key — lower risk but should not be in frontend code")
    elif value.startswith("sk_live_"):
        metadata["type"] = "Secret Key"
        metadata["environment"] = "live"
        notes.append("Stripe LIVE secret key — CRITICAL: full API access in production")
    elif value.startswith("rk_"):
        metadata["type"] = "Restricted Key"
        notes.append("Stripe restricted key — may have limited permissions")
    else:
        return ValidationResult(provider="Stripe", format_valid=False, likely_test=False)

    return ValidationResult(
        provider="Stripe",
        format_valid=True,
        likely_test=likely_test,
        metadata=metadata,
        notes=notes,
    )


def validate_github_token(value: str) -> ValidationResult:
    """Validate GitHub token format."""
    notes: list[str] = []
    metadata: dict = {}

    token_types = {
        "ghp_": "Personal Access Token (classic)",
        "gho_": "OAuth Access Token",
        "ghu_": "User-to-server Token",
        "ghs_": "Server-to-server Token",
        "ghr_": "Refresh Token",
        "github_pat_": "Fine-Grained Personal Access Token",
    }

    for prefix, token_type in token_types.items():
        if value.startswith(prefix):
            metadata["type"] = token_type
            metadata["prefix"] = prefix
            notes.append(f"GitHub {token_type}")
            return ValidationResult(
                provider="GitHub",
                format_valid=True,
                likely_test=False,
                metadata=metadata,
                notes=notes,
            )

    return ValidationResult(
        provider="GitHub",
        format_valid=False,
        likely_test=False,
        notes=["Does not match known GitHub token prefixes"],
    )


def validate_slack_token(value: str) -> ValidationResult:
    """Validate Slack token format."""
    notes: list[str] = []
    metadata: dict = {}

    prefixes = {
        "xoxb-": "Bot Token",
        "xoxa-": "App-Level Token",
        "xoxp-": "User Token",
        "xoxr-": "Refresh Token",
        "xoxs-": "Session Token",
    }

    for prefix, token_type in prefixes.items():
        if value.startswith(prefix):
            metadata["type"] = token_type
            notes.append(f"Slack {token_type}")
            # Bot and user tokens have real API access
            if prefix in ("xoxb-", "xoxp-"):
                notes.append("This token type has API access — can read messages, post, etc.")
            return ValidationResult(
                provider="Slack",
                format_valid=True,
                likely_test=False,
                metadata=metadata,
                notes=notes,
            )

    return ValidationResult(
        provider="Slack",
        format_valid=False,
        likely_test=False,
        notes=["Does not match known Slack token prefixes"],
    )


def validate_generic(value: str) -> ValidationResult:
    """Generic validation: check if value looks like a real secret."""
    from nexa.utils import is_placeholder, shannon_entropy

    notes: list[str] = []
    likely_test = False

    if is_placeholder(value):
        notes.append("Value appears to be a placeholder")
        likely_test = True

    ent = shannon_entropy(value)
    metadata = {"entropy": round(ent, 3), "length": len(value)}

    if ent > 4.5:
        notes.append(f"High entropy ({ent:.2f}) — likely a real secret")
    elif ent < 3.0:
        notes.append(f"Low entropy ({ent:.2f}) — may not be a real secret")
        likely_test = True

    return ValidationResult(
        provider="Generic",
        format_valid=True,
        likely_test=likely_test,
        metadata=metadata,
        notes=notes,
    )


# Map of finding titles to validators
_VALIDATOR_MAP: dict[str, callable] = {
    "JSON Web Token": validate_jwt,
    "Supabase Anon Key": validate_jwt,
    "AWS Access Key ID": validate_aws_key,
    "Stripe Publishable Key": validate_stripe_key,
    "Stripe Secret Key": validate_stripe_key,
    "GitHub Personal Access Token": validate_github_token,
    "GitHub Fine-Grained PAT": validate_github_token,
    "Slack Token": validate_slack_token,
}


def validate_finding(finding: Finding) -> Finding:
    """Run the appropriate validator on a finding and attach the result."""
    validator = _VALIDATOR_MAP.get(finding.title)
    if validator:
        try:
            finding.validator_result = validator(finding.value)
        except Exception as e:
            logger.debug("Validator error for %s: %s", finding.title, e)
    else:
        finding.validator_result = validate_generic(finding.value)
    return finding


def validate_findings(findings: list[Finding]) -> list[Finding]:
    """Validate all findings in a list."""
    return [validate_finding(f) for f in findings]
