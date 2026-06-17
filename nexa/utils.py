"""Utility functions for NEXA."""

from __future__ import annotations

import logging
import math
import re
import unicodedata
from collections import Counter
from urllib.parse import urljoin, urlparse, urlunparse


def shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    entropy = -sum(
        (count / length) * math.log2(count / length)
        for count in counts.values()
        if count > 0
    )
    return round(entropy, 4)


def normalize_url(url: str, base: str = "") -> str:
    """Resolve relative URLs against a base and normalize."""
    if not url:
        return ""
    url = url.strip()
    # Strip fragments
    if "#" in url:
        url = url[: url.index("#")]
    if not url:
        return ""
    if base:
        try:
            url = urljoin(base, url)
        except Exception:
            pass
    # Normalize trailing slash inconsistency for root only
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return ""
    # Remove default ports
    netloc = parsed.netloc
    if parsed.scheme == "http" and netloc.endswith(":80"):
        netloc = netloc[:-3]
    elif parsed.scheme == "https" and netloc.endswith(":443"):
        netloc = netloc[:-4]
    normalized = urlunparse((
        parsed.scheme,
        netloc.lower(),
        parsed.path,
        parsed.params,
        parsed.query,
        "",  # no fragment
    ))
    return normalized


def extract_domain(url: str) -> str:
    """Extract the registered domain (host) from a URL."""
    try:
        return urlparse(url).netloc.lower()
    except Exception:
        return ""


def is_same_domain(url: str, domain: str) -> bool:
    """Check if URL belongs to the same domain or its subdomains."""
    host = extract_domain(url)
    if not host or not domain:
        return False
    domain = domain.lower().split(":")[0]
    host = host.split(":")[0]
    return host == domain or host.endswith("." + domain)


def deduplicate_urls(urls: list[str]) -> list[str]:
    """Remove duplicate URLs preserving order."""
    seen: set[str] = set()
    result: list[str] = []
    for url in urls:
        key = url.rstrip("/").lower()
        if key not in seen:
            seen.add(key)
            result.append(url)
    return result


def slugify(s: str) -> str:
    """Convert string to filesystem-safe slug."""
    s = str(s)
    s = unicodedata.normalize("NFKD", s)
    s = s.encode("ascii", "ignore").decode("ascii")
    s = re.sub(r"[^\w\s\-]", "", s).strip().lower()
    s = re.sub(r"[\s\-]+", "-", s)
    return s[:64]


def setup_logging(verbose: bool = False) -> None:
    """Configure logging for the application."""
    level = logging.DEBUG if verbose else logging.INFO
    fmt = "%(asctime)s [%(levelname)s] %(name)s: %(message)s" if verbose else "[%(levelname)s] %(message)s"
    logging.basicConfig(level=level, format=fmt, datefmt="%H:%M:%S")
    # Quiet noisy libraries
    for lib in ("httpx", "httpcore", "anyio"):
        logging.getLogger(lib).setLevel(logging.WARNING)


def truncate_value(value: str, max_len: int = 60) -> str:
    """Truncate a value for display, masking middle portion."""
    if len(value) <= max_len:
        return value
    keep = max_len // 4
    return value[:keep] + "..." + value[-keep:]


def redact_value(value: str) -> str:
    """Partially redact a sensitive value for reporting."""
    if len(value) <= 8:
        return "*" * len(value)
    visible = max(4, len(value) // 5)
    return value[:visible] + "*" * (len(value) - visible * 2) + value[-visible:]


def get_context_window(text: str, match_start: int, match_end: int, window: int = 100) -> str:
    """Extract surrounding context around a match."""
    start = max(0, match_start - window)
    end = min(len(text), match_end + window)
    ctx = text[start:end]
    # Replace newlines for compact display
    ctx = re.sub(r"\s+", " ", ctx).strip()
    return ctx


def luhn_check(number: str) -> bool:
    """Validate a credit card number using the Luhn algorithm."""
    digits = [int(d) for d in number if d.isdigit()]
    if not digits:
        return False
    total = 0
    for i, digit in enumerate(reversed(digits)):
        if i % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def is_placeholder(value: str) -> bool:
    """Detect common placeholder/example values that are not real secrets."""
    if not value:
        return True

    placeholders = {
        "example.com",
        "your-api-key",
        "your_api_key",
        "<your_key>",
        "<your-key>",
        "replace_me",
        "replaceme",
        "placeholder",
        "xxxxxxxxxx",
        "xxxxxxxxxxxx",
        "1234567890",
        "abcdefghij",
        "test123",
        "changeme",
        "insert_key_here",
        "api_key_here",
        "your-token",
        "your_token",
        "sk-xxx",
        "pk-xxx",
        "none",
        "null",
        "undefined",
        "false",
        "true",
        "todo",
        "fixme",
        # Generic credential-like words used as placeholders or in documentation
        "password",
        "secret",
        "token",
        "apikey",
        "api-key",
        "mypassword",
        "mytoken",
        "mysecret",
        "myapikey",
        "mysecretkey",
        "secretkey",
        "yourpassword",
        "yoursecret",
        "yourtoken",
    }
    lower = value.lower().strip()
    if lower in placeholders:
        return True
    if re.fullmatch(r"[x*_\-\.]+", lower):
        return True
    # %placeholder% style (e.g. Sentry's %filtered%, %redacted%)
    if re.fullmatch(r'%[a-z_]+%', lower):
        return True
    if re.fullmatch(r"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}", lower):
        # Nil UUID
        if lower == "00000000-0000-0000-0000-000000000000":
            return True

    # Known-format prefixes that indicate real secrets — never treat as placeholders
    REAL_SECRET_PREFIXES = (
        "akia", "asia", "sk_live_", "sk_test_", "pk_live_", "pk_test_",
        "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_",
        "xoxb-", "xoxp-", "xoxa-", "xoxs-",
        "sg.", "eyj",  # sendgrid, JWT
    )
    if any(lower.startswith(p) for p in REAL_SECRET_PREFIXES):
        return False

    for ph in ("your", "replace", "placeholder", "dummy", "fake", "sample", "test_key", "demo"):
        if ph in lower:
            return True
    # "example" only flags if it's a standalone word/suffix (not mid-key)
    if re.search(r'(?:^|[^a-z])example(?:[^a-z]|$)', lower):
        return True

    return False
