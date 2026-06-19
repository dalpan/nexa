"""Security headers checker — runs on already-fetched page responses."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from nexa.models import Category, Finding, Severity


_CHECKS = [
    {
        "header": "strict-transport-security",
        "title": "Missing Strict-Transport-Security (HSTS)",
        "severity": Severity.MEDIUM,
        "confidence": 90,
        "description": "HSTS not set — site vulnerable to protocol downgrade attacks.",
        "https_only": True,
    },
    {
        "header": "content-security-policy",
        "title": "Missing Content-Security-Policy",
        "severity": Severity.MEDIUM,
        "confidence": 85,
        "description": "No CSP header — increases XSS risk.",
        "https_only": False,
    },
    {
        "header": "x-frame-options",
        "title": "Missing X-Frame-Options",
        "severity": Severity.LOW,
        "confidence": 80,
        "description": "No X-Frame-Options — site may be embeddable in iframes (clickjacking).",
        "https_only": False,
        "csp_fallback": "frame-ancestors",
    },
    {
        "header": "x-content-type-options",
        "title": "Missing X-Content-Type-Options",
        "severity": Severity.LOW,
        "confidence": 80,
        "description": "nosniff not set — browser may MIME-sniff responses.",
        "https_only": False,
    },
    {
        "header": "permissions-policy",
        "title": "Missing Permissions-Policy",
        "severity": Severity.INFO,
        "confidence": 70,
        "description": "No Permissions-Policy — browser features (camera, geolocation) unrestricted.",
        "https_only": False,
    },
]

_LEAK_HEADERS = [
    ("x-powered-by", "X-Powered-By Header Leaks Tech Stack", Severity.INFO, 85),
    ("server", "Server Header Leaks Version", Severity.INFO, 75),
    ("x-aspnet-version", "ASP.NET Version Disclosed", Severity.LOW, 90),
    ("x-aspnetmvc-version", "ASP.NET MVC Version Disclosed", Severity.LOW, 90),
]


def check_security_headers(
    url: str,
    host: str,
    headers: dict[str, str],
) -> list[Finding]:
    findings: list[Finding] = []
    lower_headers = {k.lower(): v for k, v in headers.items()}
    is_https = url.startswith("https://")
    csp_value = lower_headers.get("content-security-policy", "")

    for check in _CHECKS:
        if check.get("https_only") and not is_https:
            continue
        header_name = check["header"]
        if header_name in lower_headers:
            continue
        # CSP frame-ancestors can substitute for X-Frame-Options
        if check.get("csp_fallback") and check["csp_fallback"] in csp_value:
            continue

        findings.append(Finding(
            category=Category.SECURITY_HEADER,
            severity=check["severity"],
            confidence=check["confidence"],
            title=check["title"],
            value=f"{check['header']} not present",
            context=check["description"],
            source_url=url,
            host=host,
            timestamp=datetime.now(timezone.utc),
        ))

    # Leaky headers
    for header_name, title, severity, confidence in _LEAK_HEADERS:
        value = lower_headers.get(header_name, "")
        if not value:
            continue
        # "Server: nginx" without version is low signal — skip generic values
        if header_name == "server" and value.lower() in ("nginx", "apache", "cloudflare"):
            continue
        findings.append(Finding(
            category=Category.SECURITY_HEADER,
            severity=severity,
            confidence=confidence,
            title=title,
            value=value,
            context=f"{header_name}: {value}",
            source_url=url,
            host=host,
            timestamp=datetime.now(timezone.utc),
        ))

    return findings
