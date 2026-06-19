"""Core detection engine: credential/secret/PII detection with entropy + regex."""

from __future__ import annotations

import hashlib
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Iterator, Optional

from nexa.models import Category, Finding, Severity
from nexa.utils import get_context_window, is_placeholder, luhn_check, shannon_entropy

logger = logging.getLogger(__name__)

# ── Detection patterns ─────────────────────────────────────────────────────────

@dataclass
class DetectionPattern:
    name: str
    category: Category
    severity: Severity
    pattern: re.Pattern
    value_group: int = 1       # regex group containing the secret value
    base_confidence: int = 70
    description: str = ""
    provider: str = ""


def _c(pattern: str, flags: int = 0) -> re.Pattern:
    return re.compile(pattern, flags)


PATTERNS: list[DetectionPattern] = [
    # ── API Keys ──────────────────────────────────────────────────────────────
    DetectionPattern(
        name="AWS Access Key ID",
        category=Category.API_KEY,
        severity=Severity.CRITICAL,
        pattern=_c(r"\b(AKIA[0-9A-Z]{16})\b"),
        value_group=1,
        base_confidence=95,
        provider="AWS",
    ),
    DetectionPattern(
        name="AWS Secret Access Key",
        category=Category.API_KEY,
        severity=Severity.CRITICAL,
        pattern=_c(r'(?i)aws[_\-\s]?(?:secret|access)[_\-\s]?key\s*[:=]\s*["\']([a-zA-Z0-9/+=]{40})["\']'),
        value_group=1,
        base_confidence=90,
        provider="AWS",
    ),
    DetectionPattern(
        name="Google API Key",
        category=Category.API_KEY,
        severity=Severity.HIGH,
        pattern=_c(r"\b(AIza[0-9A-Za-z\-_]{35})\b"),
        value_group=1,
        base_confidence=90,
        provider="Google",
    ),
    DetectionPattern(
        name="Google OAuth Client ID",
        category=Category.API_KEY,
        severity=Severity.MEDIUM,
        pattern=_c(r"\b([0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com)\b"),
        value_group=1,
        base_confidence=92,
        provider="Google",
    ),
    DetectionPattern(
        name="Stripe Publishable Key",
        category=Category.API_KEY,
        severity=Severity.MEDIUM,
        pattern=_c(r"\b(pk_(?:test|live)_[0-9a-zA-Z]{24,})\b"),
        value_group=1,
        base_confidence=95,
        provider="Stripe",
    ),
    DetectionPattern(
        name="Stripe Secret Key",
        category=Category.API_KEY,
        severity=Severity.CRITICAL,
        pattern=_c(r"\b(sk_(?:test|live)_[0-9a-zA-Z]{24,})\b"),
        value_group=1,
        base_confidence=95,
        provider="Stripe",
    ),
    DetectionPattern(
        name="Twilio Account SID",
        category=Category.API_KEY,
        severity=Severity.HIGH,
        pattern=_c(r"\b(AC[a-z0-9]{32})\b"),
        value_group=1,
        base_confidence=85,
        provider="Twilio",
    ),
    DetectionPattern(
        name="Twilio Auth Token",
        category=Category.API_KEY,
        severity=Severity.CRITICAL,
        pattern=_c(r"\b(SK[a-z0-9]{32})\b"),
        value_group=1,
        base_confidence=80,
        provider="Twilio",
    ),
    DetectionPattern(
        name="GitHub Personal Access Token",
        category=Category.API_KEY,
        severity=Severity.CRITICAL,
        pattern=_c(r"\b(gh[pousr]_[A-Za-z0-9_]{36,255})\b"),
        value_group=1,
        base_confidence=95,
        provider="GitHub",
    ),
    DetectionPattern(
        name="GitHub Fine-Grained PAT",
        category=Category.API_KEY,
        severity=Severity.CRITICAL,
        pattern=_c(r"\b(github_pat_[A-Za-z0-9_]{82})\b"),
        value_group=1,
        base_confidence=98,
        provider="GitHub",
    ),
    DetectionPattern(
        name="Slack Token",
        category=Category.API_KEY,
        severity=Severity.HIGH,
        pattern=_c(r"\b(xox[baprs]-[0-9A-Za-z\-]{10,48})\b"),
        value_group=1,
        base_confidence=90,
        provider="Slack",
    ),
    DetectionPattern(
        name="Slack Webhook URL",
        category=Category.API_KEY,
        severity=Severity.HIGH,
        pattern=_c(r"(https://hooks\.slack\.com/services/T[A-Z0-9]{8,10}/B[A-Z0-9]{8,10}/[a-zA-Z0-9]{24})"),
        value_group=1,
        base_confidence=95,
        provider="Slack",
    ),
    DetectionPattern(
        name="Sentry DSN",
        category=Category.API_KEY,
        severity=Severity.MEDIUM,
        pattern=_c(r"(https://[0-9a-f]{32}@[a-z0-9.\-]+\.sentry\.io/[0-9]+)"),
        value_group=1,
        base_confidence=92,
        provider="Sentry",
    ),
    DetectionPattern(
        name="Mapbox Access Token",
        category=Category.API_KEY,
        severity=Severity.HIGH,
        pattern=_c(r"\b(pk\.eyJ1[a-zA-Z0-9\-_=]+)"),
        value_group=1,
        base_confidence=90,
        provider="Mapbox",
    ),
    DetectionPattern(
        name="Supabase Anon Key",
        category=Category.API_KEY,
        severity=Severity.MEDIUM,
        pattern=_c(r'["\']?(eyJ[a-zA-Z0-9_\-]{50,}\.[a-zA-Z0-9_\-]{50,}\.[a-zA-Z0-9_\-]{20,})["\']?'),
        value_group=1,
        base_confidence=70,
        provider="Supabase/JWT",
    ),
    DetectionPattern(
        name="SendGrid API Key",
        category=Category.API_KEY,
        severity=Severity.CRITICAL,
        pattern=_c(r"\b(SG\.[a-zA-Z0-9_\-]{22,}\.[a-zA-Z0-9_\-]{43,})\b"),
        value_group=1,
        base_confidence=95,
        provider="SendGrid",
    ),
    DetectionPattern(
        name="Generic API Key",
        category=Category.API_KEY,
        severity=Severity.MEDIUM,
        pattern=_c(r'(?i)(?:api[_\-]?key|apikey)\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,60})["\']'),
        value_group=1,
        base_confidence=55,
    ),
    # ── Auth Tokens ──────────────────────────────────────────────────────────
    DetectionPattern(
        name="JSON Web Token",
        category=Category.AUTH_TOKEN,
        severity=Severity.HIGH,
        pattern=_c(r"\b(eyJ[a-zA-Z0-9_\-]{10,}\.eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,})\b"),
        value_group=1,
        base_confidence=80,
    ),
    DetectionPattern(
        name="Bearer Token",
        category=Category.AUTH_TOKEN,
        severity=Severity.HIGH,
        pattern=_c(r'(?i)bearer\s+([a-zA-Z0-9_\-\.]{20,})'),
        value_group=1,
        base_confidence=65,
    ),
    DetectionPattern(
        name="Basic Auth in URL",
        category=Category.AUTH_TOKEN,
        severity=Severity.CRITICAL,
        # Strict: user must be [a-zA-Z0-9._%-] only; password alphanumeric+symbols but NO quotes/commas/spaces
        pattern=_c(r"(https?://[a-zA-Z0-9._%-]{2,60}:[a-zA-Z0-9!$%^&*_+\-]{5,100}@[a-zA-Z0-9.\-]+(?::\d+)?(?:/[^\s'\"<>]*)?)"),
        value_group=1,
        base_confidence=85,
    ),
    DetectionPattern(
        name="Hardcoded Authorization Header",
        category=Category.AUTH_TOKEN,
        severity=Severity.HIGH,
        pattern=_c(r'(?i)(?:Authorization|X-Auth-Token|X-API-Key)\s*[:=]\s*["\']([^"\']{10,})["\']'),
        value_group=1,
        base_confidence=70,
    ),
    # ── Credentials ──────────────────────────────────────────────────────────
    DetectionPattern(
        name="Hardcoded Password",
        category=Category.CREDENTIAL,
        severity=Severity.HIGH,
        # Removed bare "pass" — too common in minified JS (passphrase, bypass, compass, etc.)
        pattern=_c(r'(?i)(?:password|passwd|pwd)\s*[:=]\s*["\']([^"\']{4,})["\']'),
        value_group=1,
        base_confidence=60,
    ),
    DetectionPattern(
        name="Hardcoded Secret",
        category=Category.CREDENTIAL,
        severity=Severity.HIGH,
        pattern=_c(r'(?i)(?:secret|client_secret|app_secret)\s*[:=]\s*["\']([^"\']{4,})["\']'),
        value_group=1,
        base_confidence=60,
    ),
    DetectionPattern(
        name="Private Key",
        category=Category.CREDENTIAL,
        severity=Severity.CRITICAL,
        pattern=_c(r"(-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----)"),
        value_group=1,
        base_confidence=99,
    ),
    # ── PII ──────────────────────────────────────────────────────────────────
    DetectionPattern(
        name="Email Address",
        category=Category.PII,
        severity=Severity.LOW,
        pattern=_c(r"\b([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})\b"),
        value_group=1,
        base_confidence=70,
    ),
    DetectionPattern(
        name="International Phone Number",
        category=Category.PII,
        severity=Severity.LOW,
        pattern=_c(r"(\+[1-9]\d{6,14})\b"),
        value_group=1,
        base_confidence=60,
    ),
    DetectionPattern(
        name="Social Security Number",
        category=Category.PII,
        severity=Severity.LOW,
        pattern=_c(r"\b(\d{3}-\d{2}-\d{4})\b"),
        value_group=1,
        base_confidence=40,
    ),
    DetectionPattern(
        name="Credit Card Number",
        category=Category.PII,
        severity=Severity.HIGH,
        pattern=_c(r"\b(4[0-9]{15}|5[1-5][0-9]{14})\b"),
        value_group=1,
        base_confidence=40,
    ),
    # ── Internal Endpoints ───────────────────────────────────────────────────
    DetectionPattern(
        name="Internal IP/Host",
        category=Category.INTERNAL_ENDPOINT,
        severity=Severity.MEDIUM,
        # Each octet constrained to 0-255 to avoid matching SVG coordinates like 10.934.701.758
        pattern=_c(
            r"(?:https?://)?(?:localhost|127\.0\.0\.1|0\.0\.0\.0"
            r"|192\.168\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)"
            r"|10\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)"
            r"|172\.(?:1[6-9]|2\d|3[01])\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d))"
            r"(?::\d{1,5})?(?:/[^\s'\"<>]*)?"
        ),
        value_group=0,
        base_confidence=80,
    ),
    DetectionPattern(
        name="Admin/Internal Path",
        category=Category.INTERNAL_ENDPOINT,
        severity=Severity.LOW,
        # Require the word to appear as a URL path segment (slash-delimited), not as a standalone word
        pattern=_c(
            r'/(admin|dashboard|backoffice|internal|management|ops|devtools)/[^\s"\'<>]*',
            re.IGNORECASE,
        ),
        value_group=0,
        base_confidence=50,
    ),
    DetectionPattern(
        name="Private API Route",
        category=Category.INTERNAL_ENDPOINT,
        severity=Severity.MEDIUM,
        pattern=_c(r"(/api/v\d+/(?:admin|internal|private|system|management)[^\s'\"<>]*)", re.IGNORECASE),
        value_group=1,
        base_confidence=65,
    ),
    # ── Env Config ───────────────────────────────────────────────────────────
    DetectionPattern(
        name="NEXT_PUBLIC_ Env Var",
        category=Category.ENV_CONFIG,
        severity=Severity.INFO,
        pattern=_c(r'["\']?(NEXT_PUBLIC_[A-Z0-9_]+)["\']?\s*[:=]\s*["\']([^"\']{3,})["\']'),
        value_group=2,
        base_confidence=80,
    ),
    DetectionPattern(
        name="VITE_ Env Var",
        category=Category.ENV_CONFIG,
        severity=Severity.INFO,
        pattern=_c(r'["\']?(VITE_[A-Z0-9_]+)["\']?\s*[:=]\s*["\']([^"\']{3,})["\']'),
        value_group=2,
        base_confidence=80,
    ),
    DetectionPattern(
        name="REACT_APP_ Env Var",
        category=Category.ENV_CONFIG,
        severity=Severity.INFO,
        pattern=_c(r'["\']?(REACT_APP_[A-Z0-9_]+)["\']?\s*[:=]\s*["\']([^"\']{3,})["\']'),
        value_group=2,
        base_confidence=80,
    ),
    DetectionPattern(
        name="process.env Assignment",
        category=Category.ENV_CONFIG,
        severity=Severity.INFO,
        pattern=_c(r'process\.env\.([A-Z_][A-Z0-9_]*)\s*[=:]\s*["\']([^"\']{3,})["\']'),
        value_group=2,
        base_confidence=65,
    ),
    # ── JSON / __NEXT_DATA__ credential patterns ─────────────────────────────
    # Catches "wsApiKeyPassword":"uuid", "apiPassword":"value", etc. in JSON blobs
    DetectionPattern(
        name="JSON Password Field",
        category=Category.CREDENTIAL,
        severity=Severity.HIGH,
        pattern=_c(
            r'"[a-zA-Z]{0,30}(?:password|passwd|pwd|secret|apiSecret)[a-zA-Z]{0,20}"\s*:\s*"([^"]{4,200})"',
            re.IGNORECASE,
        ),
        value_group=1,
        base_confidence=72,
    ),
    DetectionPattern(
        name="JSON API Key/Token Field",
        category=Category.API_KEY,
        severity=Severity.HIGH,
        pattern=_c(
            r'"[a-zA-Z]{0,30}(?:apiKey|api_key|access_key|accessKey|clientSecret|client_secret|authToken|auth_token|wsApiKey[a-zA-Z]*)[a-zA-Z]{0,20}"\s*:\s*"([^"]{8,200})"',
            re.IGNORECASE,
        ),
        value_group=1,
        base_confidence=68,
    ),
    # Google reCAPTCHA site key (public by design — INFO only)
    DetectionPattern(
        name="Google reCAPTCHA Site Key",
        category=Category.API_KEY,
        severity=Severity.INFO,
        pattern=_c(r'\b(6Le[a-zA-Z0-9_\-]{36,38})\b'),
        value_group=1,
        base_confidence=85,
        provider="Google reCAPTCHA",
        description="Public site key — intentionally embedded in frontend. Confirms reCAPTCHA usage.",
    ),
    # Generic keyword:value in JSON — catches keys ending in Key, Token, Secret, Password
    DetectionPattern(
        name="JSON Credential-Like Key",
        category=Category.CREDENTIAL,
        severity=Severity.MEDIUM,
        pattern=_c(
            r'"[a-zA-Z0-9_]{3,40}(?:Key|Token|Secret|Password|Credential|Auth)"\s*:\s*"([a-zA-Z0-9_\-\.]{12,200})"',
        ),
        value_group=1,
        base_confidence=55,
    ),
    # Assigned variable format: key = "value" where key ends in password/secret/token
    # Catches output from _flatten_dict like 'pageProps.wsApiKeyPassword = "uuid"'
    DetectionPattern(
        name="Assigned Password/Secret Variable",
        category=Category.CREDENTIAL,
        severity=Severity.HIGH,
        pattern=_c(
            r'(?i)[a-zA-Z0-9_.]{0,40}(?:password|passwd|secret|apiKey|api_key|authToken)[a-zA-Z0-9_.]{0,20}\s*=\s*["\']([^"\']{6,200})["\']'
        ),
        value_group=1,
        base_confidence=72,
    ),
    # WebSocket / non-HTTP service URL embedded in JS/JSON config
    # Severity INFO — presence itself is a recon finding; callers should filter same-domain WS
    DetectionPattern(
        name="WebSocket/Service Endpoint in Config",
        category=Category.INTERNAL_ENDPOINT,
        severity=Severity.INFO,
        pattern=_c(r'"[a-zA-Z]{2,30}(?:Url|URL|Uri|URI|Endpoint|Host)"\s*:\s*"((?:wss?|grpc|amqp)://[^"]{5,200})"'),
        value_group=1,
        base_confidence=70,
    ),
]

# Values to ignore universally
IGNORE_VALUES: set[str] = {
    "", "null", "undefined", "false", "true", "none", "0", "1",
}

# Email allowlist patterns (example.com, noreply@ etc.)
# ^u[0-9a-f]{4} catches JSON unicode-escape artifacts like u003einfo@cfbenchmarks.com
# (the literal > in JSON text, with \ stripped by email regex, leaving u003e as username)
EMAIL_ALLOWLIST = re.compile(
    r"@example\.(com|org|net)|@test\.(com|org)|noreply@|no-reply@|test@|admin@example|@sentry\."
    r"|\\u[0-9a-f]{4}@|^u[0-9a-f]{4}[a-zA-Z0-9]",
    re.IGNORECASE,
)

# CC context keywords — number must appear near these to be flagged as HIGH
CC_CONTEXT_KEYWORDS = re.compile(
    r"card|credit|payment|billing|visa|mastercard|cvv|expiry|checkout|debit",
    re.IGNORECASE,
)

# SSN context keywords
SSN_CONTEXT_KEYWORDS = re.compile(
    r"ssn|social.security|tax.id|tin\b",
    re.IGNORECASE,
)


def _adjust_confidence(
    pattern: DetectionPattern,
    value: str,
    context: str,
) -> int:
    """Adjust base confidence based on entropy, context, and heuristics."""
    conf = pattern.base_confidence

    # Entropy boost
    ent = shannon_entropy(value)
    if ent > 5.0:
        conf = min(100, conf + 10)
    elif ent > 4.5:
        conf = min(100, conf + 5)
    elif ent < 3.0 and len(value) > 10:
        conf = max(0, conf - 15)

    # Placeholder penalty
    if is_placeholder(value):
        conf = max(0, conf - 50)

    # Context keyword boost
    ctx_lower = context.lower()
    boost_keywords = ("secret", "token", "key", "auth", "credential", "api", "private", "password")
    if any(k in ctx_lower for k in boost_keywords):
        conf = min(100, conf + 5)

    # Email-specific checks
    if pattern.category == Category.PII and "@" in value:
        if EMAIL_ALLOWLIST.search(value):
            conf = 0  # Kill the finding entirely — it's a known FP pattern

    return conf


def _get_value(match: re.Match, pattern: DetectionPattern) -> str:
    """Extract the relevant value from a regex match."""
    try:
        if pattern.value_group == 0:
            return match.group(0)
        return match.group(pattern.value_group)
    except IndexError:
        return match.group(0)


def detect_in_text(
    text: str,
    source_url: str,
    host: str,
    framework: str = "",
    line_offset: int = 0,
) -> list[Finding]:
    """Run all detection patterns against text, returning deduplicated findings."""
    findings_by_id: dict[str, Finding] = {}

    lines = text.splitlines(keepends=True)

    def line_number_for(pos: int) -> int:
        count = 0
        acc = 0
        for line in lines:
            acc += len(line)
            count += 1
            if acc >= pos:
                return count + line_offset
        return line_offset

    for dp in PATTERNS:
        try:
            for match in dp.pattern.finditer(text):
                value = _get_value(match, dp)
                if not value or value.lower() in IGNORE_VALUES:
                    continue
                if len(value) < 3:
                    continue

                context = get_context_window(text, match.start(), match.end(), window=200)
                confidence = _adjust_confidence(dp, value, context)
                dp_severity = dp.severity  # default; may be overridden below

                # Credit Card Number: require Luhn validity, adjust severity/confidence based on context
                if dp.name == "Credit Card Number":
                    digits = value.replace(" ", "").replace("-", "")
                    if not luhn_check(digits):
                        continue  # Not a real CC number — skip
                    if CC_CONTEXT_KEYWORDS.search(context):
                        confidence = 65
                        dp_severity = Severity.HIGH
                    else:
                        confidence = 40
                        dp_severity = Severity.INFO

                # Skip values containing JS structural characters — artifacts of minified object matching
                if any(c in value for c in "{}()[]") and dp.category == Category.CREDENTIAL:
                    continue

                # Skip template literal / interpolation patterns — value is a variable ref, not a real secret
                if re.search(r'[$#]\{|{{|\$\(', value):
                    continue

                # Authorization Header: skip algorithm names, URL paths, bare identifiers
                if dp.name == "Hardcoded Authorization Header":
                    if re.fullmatch(r'[A-Z][A-Z0-9_\-]{2,30}', value):
                        continue
                    if value.startswith("/"):
                        continue
                    if re.fullmatch(r'[a-zA-Z][a-zA-Z0-9_\-]{2,39}', value) and shannon_entropy(value) < 3.5:
                        continue

                elif dp.name in ("Hardcoded Password", "Hardcoded Secret"):
                    if re.fullmatch(r'[a-zA-Z][a-zA-Z0-9_\-]{2,49}', value) and shannon_entropy(value) < 3.5:
                        continue

                elif dp.name == "Assigned Password/Secret Variable":
                    if re.fullmatch(r'[0-9]?[A-Z][a-zA-Z0-9]{2,}', value) and re.fullmatch(r'[a-zA-Z0-9]+', value):
                        continue
                    if re.fullmatch(r"[A-Za-z ,.']{6,}", value):
                        continue
                    if shannon_entropy(value) < 3.5:
                        continue

                elif dp.name == "JSON Credential-Like Key":
                    if shannon_entropy(value) < 3.8 or len(value) < 20:
                        continue

                elif dp.name == "Generic API Key":
                    if shannon_entropy(value) < 3.5:
                        continue

                elif dp.name == "Bearer Token":
                    if shannon_entropy(value) < 3.5:
                        continue
                    # Skip if it looks like a variable name or path (no high-entropy chars)
                    if re.fullmatch(r'[a-zA-Z][a-zA-Z0-9_\-\.]{2,39}', value):
                        continue

                elif dp.name in ("JSON Password Field", "JSON API Key/Token Field"):
                    if shannon_entropy(value) < 3.2 or len(value) < 10:
                        continue

                elif dp.name == "process.env Assignment":
                    if shannon_entropy(value) < 3.5:
                        continue

                elif dp.name == "Admin/Internal Path":
                    # Only flag if the path has more specificity beyond just the keyword
                    if len(value) < 12:
                        continue

                # localhost/127.0.0.1 are ubiquitous in webpack/jest/dev bundles — lower noise
                elif dp.name == "Internal IP/Host" and (
                    value.strip("/").lower() in ("localhost", "127.0.0.1", "0.0.0.0")
                    or value.rstrip("/").lower() in ("http://localhost", "https://localhost",
                                                      "http://127.0.0.1", "https://127.0.0.1")
                ):
                    confidence = min(confidence, 35)
                    dp_severity = Severity.LOW

                # SSN: require context keywords or cap to very low confidence
                if dp.name == "Social Security Number":
                    if not SSN_CONTEXT_KEYWORDS.search(context):
                        confidence = min(confidence, 25)

                if confidence < 20:
                    continue  # skip near-zero confidence

                # Deduplicate by value hash
                value_hash = hashlib.sha256(value.encode()).hexdigest()[:16]
                if value_hash in findings_by_id:
                    # Update source if we already have this finding
                    continue

                ln = line_number_for(match.start())
                finding = Finding(
                    category=dp.category,
                    severity=dp_severity,
                    confidence=confidence,
                    title=dp.name,
                    value=value,
                    context=context,
                    source_url=source_url,
                    host=host,
                    framework=framework,
                    line_number=ln,
                    timestamp=datetime.now(timezone.utc),
                )
                findings_by_id[value_hash] = finding

        except re.error as e:
            logger.debug("Regex error in pattern %s: %s", dp.name, e)
        except Exception as e:
            logger.debug("Error in pattern %s: %s", dp.name, e)

    return list(findings_by_id.values())


_ENTROPY_CONTEXT_KEYWORDS = re.compile(
    r"key|token|secret|auth|password|api|credential|bearer|private|access",
    re.IGNORECASE,
)
_PURE_HEX_RE = re.compile(r'^[0-9a-fA-F]+$')
_PURE_ALPHANUM_RE = re.compile(r'^[a-zA-Z0-9]+$')
_VERSION_RE = re.compile(r'^v?\d+\.\d+')
_UUID_RE = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.IGNORECASE)

# CSS hex color allowlist (3 or 6 hex chars)
_CSS_HEX_RE = re.compile(r'^[0-9a-fA-F]{3}(?:[0-9a-fA-F]{3})?$')


def detect_high_entropy(
    text: str,
    source_url: str,
    host: str,
    framework: str = "",
    min_entropy: float = 4.8,
    min_len: int = 20,
    max_len: int = 100,
) -> list[Finding]:
    """Find high-entropy strings that weren't caught by named patterns."""
    findings: list[Finding] = []
    # Look for quoted strings of appropriate length
    string_re = re.compile(r'["\']([a-zA-Z0-9+/=_\-]{' + str(min_len) + r',' + str(max_len) + r'})["\']')
    seen: set[str] = set()

    for match in string_re.finditer(text):
        value = match.group(1)
        if value in seen:
            continue
        seen.add(value)

        if is_placeholder(value):
            continue

        # Skip pure hex strings (likely build hashes, git commits)
        if _PURE_HEX_RE.match(value):
            continue

        # Skip version strings
        if _VERSION_RE.match(value):
            continue

        # Skip UUIDs
        if _UUID_RE.match(value):
            continue

        # Skip short pure-alphanumeric strings (likely minified variable names or build IDs)
        if _PURE_ALPHANUM_RE.match(value) and len(value) < 24:
            continue

        ent = shannon_entropy(value)
        if ent < min_entropy:
            continue

        context = get_context_window(text, match.start(), match.end(), window=100)

        # Require context keyword — skip if surrounding 100 chars have no secret indicator
        if not _ENTROPY_CONTEXT_KEYWORDS.search(context):
            continue

        confidence = min(85, int(ent * 10))  # scale confidence with entropy

        finding = Finding(
            category=Category.API_KEY,
            severity=Severity.LOW,
            confidence=confidence,
            title="High-Entropy String",
            value=value,
            context=context,
            source_url=source_url,
            host=host,
            framework=framework,
            timestamp=datetime.now(timezone.utc),
        )
        findings.append(finding)

    return findings


def deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    """Deduplicate findings by value hash, keeping highest confidence."""
    by_id: dict[str, Finding] = {}
    for f in findings:
        if f.id not in by_id or f.confidence > by_id[f.id].confidence:
            by_id[f.id] = f
    return sorted(by_id.values(), key=lambda f: (f.severity, -f.confidence), reverse=True)


def run_detection(
    text: str,
    source_url: str,
    host: str,
    framework: str = "",
    include_entropy: bool = True,
) -> list[Finding]:
    """Run full detection pipeline on a chunk of text."""
    findings = detect_in_text(text, source_url, host, framework)
    if include_entropy:
        entropy_findings = detect_high_entropy(text, source_url, host, framework)
        # Only add entropy findings for values not already caught
        existing_values = {f.id for f in findings}
        for f in entropy_findings:
            if f.id not in existing_values:
                findings.append(f)
    return findings
