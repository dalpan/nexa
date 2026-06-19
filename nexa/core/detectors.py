"""Core detection engine — focused on findings with real bug bounty impact."""

from __future__ import annotations

import base64
import hashlib
import logging
import re
from datetime import datetime, timezone

from nexa.models import Category, Finding, Severity
from nexa.utils import get_context_window, is_placeholder, luhn_check, shannon_entropy

logger = logging.getLogger(__name__)


from dataclasses import dataclass


@dataclass
class DetectionPattern:
    name: str
    category: Category
    severity: Severity
    pattern: re.Pattern
    value_group: int = 1
    base_confidence: int = 70
    description: str = ""
    provider: str = ""


def _c(pattern: str, flags: int = 0) -> re.Pattern:
    return re.compile(pattern, flags)


# ──────────────────────────────────────────────────────────────────────────────
# PATTERNS — only include things that have direct bug bounty impact
# Philosophy: if it can be used to authenticate / access data → report it
#             if it's just "looks suspicious in minified JS" → don't report it
# ──────────────────────────────────────────────────────────────────────────────

PATTERNS: list[DetectionPattern] = [

    # ── Tier 1: Direct authentication credentials ─────────────────────────────
    # These can be copy-pasted into curl and immediately used

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
        name="Stripe Secret Key",
        category=Category.API_KEY,
        severity=Severity.CRITICAL,
        pattern=_c(r"\b(sk_(?:test|live)_[0-9a-zA-Z]{24,})\b"),
        value_group=1,
        base_confidence=95,
        provider="Stripe",
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
        name="SendGrid API Key",
        category=Category.API_KEY,
        severity=Severity.CRITICAL,
        pattern=_c(r"\b(SG\.[a-zA-Z0-9_\-]{22,}\.[a-zA-Z0-9_\-]{43,})\b"),
        value_group=1,
        base_confidence=95,
        provider="SendGrid",
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
        name="Private Key",
        category=Category.CREDENTIAL,
        severity=Severity.CRITICAL,
        pattern=_c(r"(-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----)"),
        value_group=1,
        base_confidence=99,
    ),

    # ── Tier 2: Credentials in JSON/HTML payload (the Kraken finding class) ──────
    # Credentials embedded in __NEXT_DATA__, __NUXT__, __remixContext, __GATSBY__,
    # SvelteKit state, and generic inline JS config objects.
    # These are directly usable — copy to Authorization header and curl.

    # 2a. Base64-encoded Basic Auth in JSON field (any framework state payload)
    # Matches: "wsApiKeyPassword":"dXNlcm5hbWU6cGFzc3dvcmQ=", "authorization":"...", etc.
    DetectionPattern(
        name="Basic Auth Credential in JSON",
        category=Category.CREDENTIAL,
        severity=Severity.CRITICAL,
        pattern=_c(
            r'["\']?[a-zA-Z]{0,40}(?:authorization|basicAuth|basic_auth|wsApiKey|wsApiKeyPassword'
            r'|apiPassword|clientCredential|apiCredential|bearerToken|accessCredential'
            r'|x-api-key|x_api_key|apitoken|api_token)[a-zA-Z0-9_]{0,20}["\']?'
            r'\s*[:=]\s*["\']([A-Za-z0-9+/]{20,}={0,2})["\']',
            re.IGNORECASE,
        ),
        value_group=1,
        base_confidence=85,
        description="Base64-encoded credential — likely Basic Auth (user:pass). Decode and test against backend APIs.",
    ),
    # 2b. Literal "Basic <base64>" value anywhere — catch it regardless of field name
    DetectionPattern(
        name="Basic Auth Header Value",
        category=Category.CREDENTIAL,
        severity=Severity.CRITICAL,
        pattern=_c(r'["\']?(Basic\s+[A-Za-z0-9+/]{20,}={0,2})["\']?'),
        value_group=1,
        base_confidence=88,
        description="Literal Basic Auth value — copy directly to Authorization header.",
    ),
    # 2c. Hardcoded credential in JS variable (var/let/const/window assignment)
    # Catches: const apiKey = "sk_live_...", window.AUTH_TOKEN = "...", let password = "..."
    DetectionPattern(
        name="Hardcoded Credential in JS Variable",
        category=Category.CREDENTIAL,
        severity=Severity.HIGH,
        pattern=_c(
            r'(?:(?:var|let|const)\s+[a-zA-Z_$][a-zA-Z0-9_$]{0,30}'
            r'(?:key|token|secret|password|passwd|credential|auth|apikey|api_key|bearer)[a-zA-Z0-9_$]{0,20}'
            r'|window\.[a-zA-Z_$][a-zA-Z0-9_$]{0,10}'
            r'(?:key|token|secret|password|passwd|credential|auth|apikey|api_key|bearer)[a-zA-Z0-9_$]{0,20})'
            r'\s*=\s*["\']([^"\']{8,200})["\']',
            re.IGNORECASE,
        ),
        value_group=1,
        base_confidence=70,
        description="Hardcoded credential assigned to JS variable — check if actively used in requests.",
    ),
    # 2d. Credential in JS object property (covers all frameworks' config objects)
    # Catches: { apiKey: "...", token: "...", password: "...", secret: "..." }
    # Both quoted and unquoted property names (JS object syntax)
    DetectionPattern(
        name="Credential in JS Object",
        category=Category.CREDENTIAL,
        severity=Severity.HIGH,
        pattern=_c(
            r'(?:^|[{,\s])\s*["\']?'
            r'(?:apiKey|api_key|accessKey|access_key|secretKey|secret_key'
            r'|authToken|auth_token|accessToken|access_token|refreshToken|refresh_token'
            r'|clientSecret|client_secret|appSecret|app_secret'
            r'|password|passwd|pwd|credentials?)'
            r'["\']?\s*:\s*["\']([^"\'$`\s]{8,200})["\']',
            re.IGNORECASE,
        ),
        value_group=1,
        base_confidence=65,
        description="Credential value in JS/JSON object — verify it is used in real requests.",
    ),
    DetectionPattern(
        name="Basic Auth in URL",
        category=Category.AUTH_TOKEN,
        severity=Severity.CRITICAL,
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
    DetectionPattern(
        name="Hardcoded Password",
        category=Category.CREDENTIAL,
        severity=Severity.HIGH,
        pattern=_c(r'(?i)(?:password|passwd|pwd)\s*[:=]\s*["\']([^"\']{6,})["\']'),
        value_group=1,
        base_confidence=60,
    ),
    DetectionPattern(
        name="Hardcoded Secret",
        category=Category.CREDENTIAL,
        severity=Severity.HIGH,
        pattern=_c(r'(?i)(?:client_secret|app_secret)\s*[:=]\s*["\']([^"\']{8,})["\']'),
        value_group=1,
        base_confidence=65,
    ),
    DetectionPattern(
        name="JSON Web Token",
        category=Category.AUTH_TOKEN,
        severity=Severity.HIGH,
        pattern=_c(r"\b(eyJ[a-zA-Z0-9_\-]{10,}\.eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,})\b"),
        value_group=1,
        base_confidence=80,
    ),
    DetectionPattern(
        name="JSON Password Field",
        category=Category.CREDENTIAL,
        severity=Severity.HIGH,
        pattern=_c(
            r'"[a-zA-Z]{0,30}(?:password|passwd|pwd|secret|apiSecret)[a-zA-Z]{0,20}"\s*:\s*"([^"]{6,200})"',
            re.IGNORECASE,
        ),
        value_group=1,
        base_confidence=72,
    ),
    # Companion to JSON Password Field — catches the "username" / key ID side of the pair.
    # e.g. "wsApiKeyId":"cfbenchmarksws2" paired with "wsApiKeyPassword":"uuid"
    DetectionPattern(
        name="JSON Credential Key ID",
        category=Category.CREDENTIAL,
        severity=Severity.HIGH,
        pattern=_c(
            r'"[a-zA-Z]{0,40}(?:wsApiKeyId|apiKeyId|api_key_id|clientId|client_id|keyId|key_id'
            r'|accessKeyId|access_key_id|accountId|account_id|keyName|key_name'
            r'|userName|user_name|loginName|login_name)[a-zA-Z0-9]{0,20}"\s*:\s*"([^"]{4,100})"',
            re.IGNORECASE,
        ),
        value_group=1,
        base_confidence=70,
        description="API key ID or username — check for paired password/secret field nearby in the same JSON payload.",
    ),
    # 2e. Generic API key in fetch/axios/XMLHttpRequest call
    # Catches: fetch(url, { headers: { 'x-api-key': '...' } })
    # Note: use [\s\S] not [^"'] so the intermediate chars can contain quotes
    DetectionPattern(
        name="API Key in HTTP Request",
        category=Category.API_KEY,
        severity=Severity.HIGH,
        pattern=_c(
            r'(?:fetch|axios|request|got|superagent|http\.get|http\.post)'
            r'[\s\S]{0,300}'
            r'["\'](?:x-api-key|x-auth-token|api-key|apikey|api_key|authorization)["\']'
            r'\s*:\s*["\']([^"\']{8,200})["\']',
            re.IGNORECASE,
        ),
        value_group=1,
        base_confidence=75,
        description="API key passed in HTTP request headers — directly usable.",
    ),
    # Stripe publishable key — INFO only, public by design but worth logging
    DetectionPattern(
        name="Stripe Publishable Key",
        category=Category.API_KEY,
        severity=Severity.INFO,
        pattern=_c(r"\b(pk_(?:test|live)_[0-9a-zA-Z]{24,})\b"),
        value_group=1,
        base_confidence=95,
        provider="Stripe",
    ),

    # ── Tier 3: Monitoring / analytics keys ───────────────────────────────────
    # Lower impact but valid — Sentry DSN leaks error data including stack traces

    DetectionPattern(
        name="Sentry DSN",
        category=Category.API_KEY,
        severity=Severity.MEDIUM,
        pattern=_c(r"(https://[0-9a-f]{32}@[a-z0-9.\-]+\.sentry\.io/[0-9]+)"),
        value_group=1,
        base_confidence=92,
        provider="Sentry",
    ),

    # ── Tier 4: Internal endpoints worth noting ────────────────────────────────

    DetectionPattern(
        name="Internal Network URL",
        category=Category.INTERNAL_ENDPOINT,
        severity=Severity.MEDIUM,
        # Private IP ranges appearing in JS — not localhost (always dev defaults)
        pattern=_c(
            r"(?:https?://)"
            r"(?:192\.168\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)"
            r"|10\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)"
            r"|172\.(?:1[6-9]|2\d|3[01])\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d))"
            r"(?::\d{1,5})?(?:/[^\s'\"<>]*)?"
        ),
        value_group=0,
        base_confidence=80,
    ),
]

# ──────────────────────────────────────────────────────────────────────────────
# Filters & helpers
# ──────────────────────────────────────────────────────────────────────────────

IGNORE_VALUES: set[str] = {
    "", "null", "undefined", "false", "true", "none", "0", "1",
    "SECRET_DO_NOT_PASS_THIS_OR_YOU_WILL_BE_FIRED",
    "DO_NOT_USE_OR_YOU_WILL_BE_FIRED",
}

# SRI hash prefix
_SRI_HASH_RE = re.compile(r'^sha(256|384|512)-', re.IGNORECASE)

# Blockchain config context — private IPs inside these are dev chain defaults
_BLOCKCHAIN_CONTEXT_RE = re.compile(
    r'testnet|nativeCurrency|rpcUrls|blockCreated|chainId|Anvil|Hardhat|ZKsync|Moonbeam',
    re.IGNORECASE,
)


# Known-bad credential values that are actually identifiers/constants, not real secrets
_PASSWORD_FP_RE = re.compile(
    r'^[A-Z][A-Z0-9_]{4,}$'                              # SCREAMING_SNAKE_CASE: AUTH_WAITING, EMBED_WALLET_SCREEN
    r'|^[a-z][a-zA-Z0-9]*[A-Z][a-zA-Z0-9]*$'            # camelCase with at least one uppercase: handleChange, setPassword
    r'|^[a-z][a-z0-9_]+_(?:screen|flow|step|state|mode|type|event|action|page|view)$',  # UI state: login_screen
    # Note: NO re.IGNORECASE — must match exactly so real passwords aren't filtered
)

# Known-bad authorization header values
_AUTH_HEADER_FP_RE = re.compile(
    r'^[A-Z][A-Z0-9_\-]{2,30}$'    # HTTP method names, algorithm names
    r'|^/[a-zA-Z]'                   # URL paths
    r'|^var\(--'                      # CSS variable references: var(--privy-color-accent)
    r'|--[a-zA-Z]'                    # CSS custom property values
)



def _try_decode_basic_auth(value: str) -> str | None:
    """Attempt to decode a base64 string as Basic Auth user:pass."""
    try:
        decoded = base64.b64decode(value + "==").decode("utf-8", errors="strict")
        if ":" in decoded and len(decoded) >= 5:
            user, _, pwd = decoded.partition(":")
            # Must look like a real credential: non-trivial user and password
            if len(user) >= 2 and len(pwd) >= 4 and not re.search(r'[\x00-\x1f]', decoded):
                return decoded
    except Exception:
        pass
    return None


def _adjust_confidence(pattern: DetectionPattern, value: str, context: str) -> int:
    conf = pattern.base_confidence
    ent = shannon_entropy(value)
    if ent > 5.0:
        conf = min(100, conf + 10)
    elif ent > 4.5:
        conf = min(100, conf + 5)
    elif ent < 3.0 and len(value) > 10:
        conf = max(0, conf - 15)
    if is_placeholder(value):
        conf = max(0, conf - 50)
    return conf


def _get_value(match: re.Match, pattern: DetectionPattern) -> str:
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
    """Run detection patterns against text. Only yields high-confidence, actionable findings."""
    findings_by_id: dict[str, Finding] = {}

    lines = text.splitlines(keepends=True)

    def line_number_for(pos: int) -> int:
        count, acc = 0, 0
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
                if len(value) < 4:
                    continue

                context = get_context_window(text, match.start(), match.end(), window=200)
                confidence = _adjust_confidence(dp, value, context)
                dp_severity = dp.severity

                # ── Pattern-specific filters ──────────────────────────────────

                if dp.name == "Basic Auth Credential in JSON":
                    decoded = _try_decode_basic_auth(value)
                    if not decoded:
                        continue
                    context = f"Decoded: {decoded[:8]}... | {context}"
                    confidence = 90

                elif dp.name == "Basic Auth Header Value":
                    # Extract just the base64 part and decode it
                    b64_part = re.search(r'Basic\s+([A-Za-z0-9+/]{20,}={0,2})', value, re.IGNORECASE)
                    if b64_part:
                        decoded = _try_decode_basic_auth(b64_part.group(1))
                        if decoded:
                            context = f"Decoded: {decoded[:8]}... | {context}"
                            confidence = 92
                        else:
                            confidence = max(confidence - 20, 20)

                elif dp.name in ("Hardcoded Credential in JS Variable", "Credential in JS Object"):
                    if shannon_entropy(value) < 3.5:
                        continue
                    if _PASSWORD_FP_RE.match(value):
                        continue
                    # Sentences (contain spaces) are error messages / strings, not credentials
                    if ' ' in value:
                        continue
                    # Dunder identifiers (__name__) are internal JS/framework markers, not secrets
                    if value.startswith('__') and value.endswith('__'):
                        continue
                    # Skip values that are clearly pure-word identifiers (no digits, no symbols)
                    if re.fullmatch(r'[a-zA-Z]{4,30}', value):
                        continue
                    # Skip template literal placeholders
                    if re.search(r'\$\{|\{%|<%', value):
                        continue
                    # Check if it could be Basic Auth (bonus: decode and annotate)
                    decoded = _try_decode_basic_auth(value)
                    if decoded:
                        context = f"Decoded: {decoded[:8]}... | {context}"
                        confidence = min(confidence + 15, 90)

                elif dp.name == "API Key in HTTP Request":
                    if shannon_entropy(value) < 3.5:
                        continue
                    if _PASSWORD_FP_RE.match(value):
                        continue

                elif dp.name == "Basic Auth in URL":
                    # Skip URLs where the "password" is actually a common path component or short token
                    if shannon_entropy(value) < 3.0:
                        continue

                elif dp.name == "Hardcoded Authorization Header":
                    if _AUTH_HEADER_FP_RE.match(value):
                        continue
                    if re.fullmatch(r'[a-zA-Z][a-zA-Z0-9_\-]{2,39}', value) and shannon_entropy(value) < 3.5:
                        continue

                elif dp.name in ("Hardcoded Password", "Hardcoded Secret"):
                    # Skip low-entropy values — they're variable names or placeholder strings
                    if shannon_entropy(value) < 3.5:
                        continue
                    if _PASSWORD_FP_RE.match(value):
                        continue
                    # Skip values containing JS structural characters
                    if any(c in value for c in "{}()[]<>"):
                        continue

                elif dp.name == "JSON Password Field":
                    if shannon_entropy(value) < 3.2 or len(value) < 8:
                        continue
                    # Skip enum/state values: camelCase, snake_case, SCREAMING_SNAKE_CASE
                    if _PASSWORD_FP_RE.match(value):
                        continue
                    if re.fullmatch(r'[a-z][a-zA-Z0-9]{4,}', value):
                        continue
                    if re.fullmatch(r'[a-z][a-z0-9_]{4,}', value) and '_' in value:
                        continue
                    # Annotate with field name so finding shows "wsApiKeyPassword: uuid" not just "uuid"
                    field_match = re.match(r'"([^"]+)"', match.group(0))
                    if field_match:
                        value = f'{field_match.group(1)}: {value}'

                elif dp.name == "JSON Credential Key ID":
                    if len(value) < 4:
                        continue
                    # Skip very short generic words (likely placeholder/default)
                    if re.fullmatch(r'[a-z]{2,8}', value):
                        continue
                    # Annotate with field name for display context
                    field_match = re.match(r'"([^"]+)"', match.group(0))
                    if field_match:
                        value = f'{field_match.group(1)}: {value}'

                elif dp.name == "JSON Web Token":
                    # Skip very short JWTs — likely test/example tokens
                    if len(value) < 100:
                        continue

                elif dp.name == "Internal Network URL":
                    if _BLOCKCHAIN_CONTEXT_RE.search(context):
                        continue

                # Skip template literals / interpolation — not real values
                if re.search(r'[$#]\{|{{|\$\(', value):
                    continue

                if confidence < 20:
                    continue

                value_hash = hashlib.sha256(value.encode()).hexdigest()[:16]
                if value_hash in findings_by_id:
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
_BASE58_RE = re.compile(r'^[1-9A-HJ-NP-Za-km-z]{32,50}$')


def detect_high_entropy(
    text: str,
    source_url: str,
    host: str,
    framework: str = "",
    min_entropy: float = 4.8,
    min_len: int = 20,
    max_len: int = 100,
) -> list[Finding]:
    """Find high-entropy strings with credential context keywords."""
    findings: list[Finding] = []
    string_re = re.compile(r'["\']([a-zA-Z0-9+/=_\-]{' + str(min_len) + r',' + str(max_len) + r'})["\']')
    seen: set[str] = set()

    for match in string_re.finditer(text):
        value = match.group(1)
        if value in seen:
            continue
        seen.add(value)

        if is_placeholder(value):
            continue
        if _PURE_HEX_RE.match(value):
            continue
        if _SRI_HASH_RE.match(value):
            continue
        if _BASE58_RE.match(value):
            continue
        # PostHog/analytics public keys — not secrets
        if re.match(r'^phc_', value, re.IGNORECASE):
            continue
        if _VERSION_RE.match(value):
            continue
        if _UUID_RE.match(value):
            continue
        if _PURE_ALPHANUM_RE.match(value) and len(value) < 24:
            continue

        ent = shannon_entropy(value)
        if ent < min_entropy:
            continue

        context = get_context_window(text, match.start(), match.end(), window=100)
        if not _ENTROPY_CONTEXT_KEYWORDS.search(context):
            continue

        confidence = min(85, int(ent * 10))

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
    findings = detect_in_text(text, source_url, host, framework)
    if include_entropy:
        entropy_findings = detect_high_entropy(text, source_url, host, framework)
        existing_values = {f.id for f in findings}
        for f in entropy_findings:
            if f.id not in existing_values:
                findings.append(f)
    return findings
