"""WAF bypass utilities for NEXA — passive, non-exploiting strategies."""

from __future__ import annotations

import asyncio
import logging
import random
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# ── User-Agent pool ────────────────────────────────────────────────────────────

USER_AGENTS: list[str] = [
    # Chrome on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    # Chrome on Mac
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    # Firefox on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    # Firefox on Linux
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
    # Safari on Mac
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    # Safari on iOS
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Mobile/15E148 Safari/604.1",
    # Edge on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    # Mobile Chrome on Android
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.60 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 13; SM-S908B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Mobile Safari/537.36",
    # Googlebot
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    # curl (useful for API endpoints)
    "curl/8.7.1",
]

# ── Accept header variations ───────────────────────────────────────────────────

ACCEPT_VARIATIONS: list[str] = [
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "application/json, text/plain, */*",
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
    "*/*",
]

# ── WAF signature detection ────────────────────────────────────────────────────

WAF_SIGNATURES: dict[str, list[str]] = {
    "Cloudflare": ["cf-ray", "cf-cache-status", "cf-mitigated"],
    "Sucuri": ["x-sucuri-id", "x-sucuri-cache"],
    "Akamai": ["x-akamai-transformed", "x-akamai-request-id", "x-check-cacheable"],
    "Incapsula": ["x-iinfo", "x-cdn"],
    "AWS WAF": ["x-amzn-requestid", "x-amz-cf-id"],
    "F5 BIG-IP ASM": ["x-cnection", "x-wa-info"],
    "ModSecurity": ["x-mod-security"],
}

WAF_BODY_PATTERNS: list[tuple[str, str]] = [
    ("Cloudflare", r"Ray ID:?\s*[0-9a-f]+"),
    ("Cloudflare", r"Attention Required\s*\|"),
    ("Generic WAF", r"Access Denied"),
    ("Cloudflare", r"cloudflare"),
    ("Incapsula", r"Incapsula incident"),
    ("Sucuri", r"Sucuri WebSite Firewall"),
]

_WAF_BODY_RES = [(name, re.compile(pat, re.IGNORECASE)) for name, pat in WAF_BODY_PATTERNS]

# Private IP ranges for X-Forwarded-For spoofing
_PRIVATE_IP_RANGES = [
    (10, 0, 0),
    (192, 168, 1),
    (172, 16, 0),
    (10, 10, 10),
]


def _random_private_ip() -> str:
    base = random.choice(_PRIVATE_IP_RANGES)
    return f"{base[0]}.{base[1]}.{base[2]}.{random.randint(1, 254)}"


# ── Config ─────────────────────────────────────────────────────────────────────

@dataclass
class WAFBypassConfig:
    enabled: bool = False
    strategy: str = "rotate"          # "rotate" | "random" | "aggressive"
    jitter_ms: int = 500              # max jitter in ms between requests
    spoof_forwarded_for: bool = False  # set automatically for "aggressive"

    def __post_init__(self) -> None:
        if self.strategy == "aggressive":
            self.spoof_forwarded_for = True


# ── Header builders ────────────────────────────────────────────────────────────

_ua_index = 0  # global rotation cursor


def get_next_user_agent(strategy: str) -> str:
    """Return next UA based on strategy."""
    global _ua_index
    if strategy == "random":
        return random.choice(USER_AGENTS)
    elif strategy in ("rotate", "aggressive"):
        ua = USER_AGENTS[_ua_index % len(USER_AGENTS)]
        _ua_index += 1
        return ua
    return USER_AGENTS[0]


def build_bypass_headers(ua: str, target_url: str, strategy: str) -> dict[str, str]:
    """Build headers that blend with real browser traffic."""
    parsed = urlparse(target_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    headers: dict[str, str] = {
        "Accept": random.choice(ACCEPT_VARIATIONS),
        "Accept-Language": "en-US,en;q=0.9",
        "DNT": "1",
        "Upgrade-Insecure-Requests": "1",
        "User-Agent": ua,
    }

    # Sec-Fetch-* headers (Chrome/Edge only — skip for non-Chromium UAs)
    if "Chrome" in ua or "Edg/" in ua:
        headers.update({
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
        })
        # Sec-CH-UA client hints
        chrome_version = "124"
        m = re.search(r"Chrome/(\d+)", ua)
        if m:
            chrome_version = m.group(1)
        headers["Sec-CH-UA"] = f'"Chromium";v="{chrome_version}", "Google Chrome";v="{chrome_version}", "Not-A.Brand";v="99"'
        headers["Sec-CH-UA-Mobile"] = "?0"
        headers["Sec-CH-UA-Platform"] = '"Windows"' if "Windows" in ua else '"macOS"'

    # Referer spoofing — simulate coming from Google or same-site
    referer_choices = [
        "https://www.google.com/",
        "https://www.bing.com/",
        origin + "/",
        "",  # direct (no referer)
    ]
    referer = random.choice(referer_choices)
    if referer:
        headers["Referer"] = referer

    # Aggressive: add forwarded-for spoofing
    if strategy == "aggressive":
        fake_ip = _random_private_ip()
        headers["X-Forwarded-For"] = fake_ip
        headers["X-Real-IP"] = fake_ip
        headers["X-Originating-IP"] = fake_ip

    return headers


# ── WAF detection ──────────────────────────────────────────────────────────────

def detect_waf(
    response_headers: dict[str, str],
    response_body: str,
) -> Optional[str]:
    """Inspect response for WAF fingerprints. Returns WAF name or None."""
    headers_lower = {k.lower(): v for k, v in response_headers.items()}

    # Check response headers
    for waf_name, header_keys in WAF_SIGNATURES.items():
        for hk in header_keys:
            if hk.lower() in headers_lower:
                return waf_name

    # Check Server header
    server = headers_lower.get("server", "").lower()
    if "incapsula" in server:
        return "Incapsula"
    if "cloudflare" in server:
        return "Cloudflare"

    # Check body patterns (only first 4096 bytes to avoid long scans)
    body_snippet = response_body[:4096] if response_body else ""
    for waf_name, pattern_re in _WAF_BODY_RES:
        if pattern_re.search(body_snippet):
            return waf_name

    return None


# ── Jitter ────────────────────────────────────────────────────────────────────

async def apply_jitter(max_ms: int) -> None:
    """Sleep for a random amount up to max_ms milliseconds."""
    if max_ms > 0:
        delay = random.randint(0, max_ms) / 1000.0
        if delay > 0:
            await asyncio.sleep(delay)
