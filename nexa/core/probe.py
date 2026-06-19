"""Active probe for exposed sensitive files and debug endpoints."""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from urllib.parse import urljoin

from nexa.core.http import HttpClient
from nexa.models import Category, Finding, Severity

logger = logging.getLogger(__name__)

_SENSITIVE_PATHS = [
    # Environment files
    ("/.env",                   "Exposed .env File",              Severity.CRITICAL, 95),
    ("/.env.local",             "Exposed .env.local File",        Severity.CRITICAL, 95),
    ("/.env.production",        "Exposed .env.production File",   Severity.CRITICAL, 95),
    ("/.env.staging",           "Exposed .env.staging File",      Severity.HIGH,     90),
    ("/.env.backup",            "Exposed .env Backup",            Severity.CRITICAL, 90),
    ("/.env.old",               "Exposed .env Backup",            Severity.CRITICAL, 90),
    # Git exposure
    ("/.git/config",            "Exposed Git Config",             Severity.HIGH,     95),
    ("/.git/HEAD",              "Exposed Git Repository",         Severity.HIGH,     90),
    ("/.gitignore",             "Exposed .gitignore",             Severity.LOW,      70),
    # API docs
    ("/swagger.json",           "Exposed Swagger/OpenAPI Spec",   Severity.MEDIUM,   85),
    ("/openapi.json",           "Exposed OpenAPI Spec",           Severity.MEDIUM,   85),
    ("/api/swagger.json",       "Exposed Swagger/OpenAPI Spec",   Severity.MEDIUM,   85),
    ("/api/openapi.json",       "Exposed OpenAPI Spec",           Severity.MEDIUM,   85),
    ("/swagger-ui.html",        "Swagger UI Accessible",          Severity.MEDIUM,   85),
    ("/api-docs",               "API Docs Accessible",            Severity.MEDIUM,   80),
    # Spring Boot Actuator
    ("/actuator",               "Spring Boot Actuator Exposed",   Severity.HIGH,     90),
    ("/actuator/env",           "Actuator /env Endpoint",         Severity.CRITICAL, 95),
    ("/actuator/health",        "Actuator /health Endpoint",      Severity.LOW,      80),
    ("/actuator/beans",         "Actuator /beans Endpoint",       Severity.MEDIUM,   85),
    ("/actuator/mappings",      "Actuator /mappings Endpoint",    Severity.MEDIUM,   85),
    # Debug endpoints
    ("/__debug__",              "Debug Endpoint Exposed",         Severity.HIGH,     85),
    ("/_debug",                 "Debug Endpoint Exposed",         Severity.HIGH,     85),
    ("/debug",                  "Debug Endpoint Exposed",         Severity.MEDIUM,   75),
    ("/console",                "Console Endpoint Exposed",       Severity.HIGH,     80),
    ("/h2-console",             "H2 Database Console Exposed",    Severity.CRITICAL, 95),
    # GraphQL
    ("/graphql",                "GraphQL Endpoint Found",         Severity.INFO,     80),
    ("/graphiql",               "GraphiQL IDE Accessible",        Severity.MEDIUM,   85),
    ("/playground",             "GraphQL Playground Accessible",  Severity.MEDIUM,   85),
    # Config / backup files
    ("/config.json",            "Exposed config.json",            Severity.HIGH,     85),
    ("/config.yaml",            "Exposed config.yaml",            Severity.HIGH,     85),
    ("/settings.json",          "Exposed settings.json",          Severity.HIGH,     80),
    ("/backup.sql",             "Exposed Database Backup",        Severity.CRITICAL, 95),
    ("/dump.sql",               "Exposed Database Dump",          Severity.CRITICAL, 95),
    # Package files
    ("/package.json",           "Exposed package.json",           Severity.LOW,      75),
    ("/package-lock.json",      "Exposed package-lock.json",      Severity.INFO,     70),
    ("/yarn.lock",              "Exposed yarn.lock",              Severity.INFO,     65),
    # Security
    ("/.well-known/security.txt", "security.txt Present",         Severity.INFO,     60),
    ("/crossdomain.xml",        "crossdomain.xml Present",        Severity.LOW,      75),
    ("/clientaccesspolicy.xml", "clientaccesspolicy.xml Present", Severity.LOW,      70),
]

# Keywords that confirm a .env file is real
_ENV_KEYWORDS = (b"DB_", b"DATABASE_", b"SECRET", b"PASSWORD", b"API_KEY", b"TOKEN", b"AWS_", b"MAIL_")
# Keywords that confirm a Git config is real
_GIT_KEYWORDS = (b"[core]", b"[remote", b"repositoryformatversion")
# Keywords indicating Actuator data
_ACTUATOR_KEYWORDS = (b'"activeProfiles"', b'"systemProperties"', b'"propertySources"', b'"beans"')
_GRAPHQL_INTROSPECTION = b'{"query":"{__schema{types{name}}}"}'


async def probe_sensitive_files(
    client: HttpClient,
    base_url: str,
    host: str,
    concurrency: int = 10,
) -> list[Finding]:
    findings: list[Finding] = []
    sem = asyncio.Semaphore(concurrency)

    async def _probe(path: str, title: str, severity: Severity, confidence: int) -> None:
        url = urljoin(base_url, path)
        async with sem:
            content, status, headers, final_url = await client.get(url)

        if status not in (200, 206):
            return

        content_type = headers.get("content-type", "").lower()
        body = content.encode("utf-8", errors="replace") if isinstance(content, str) else content

        # Filter HTML responses — these are likely 200 redirect-to-homepage tricks
        if "text/html" in content_type and path not in ("/graphql", "/graphiql", "/playground", "/console", "/h2-console"):
            # Only flag if response contains confirming keywords
            if path.startswith("/.env"):
                if not any(kw in body for kw in _ENV_KEYWORDS):
                    return
            elif path == "/.git/config":
                if not any(kw in body for kw in _GIT_KEYWORDS):
                    return
            elif "/actuator" in path:
                if not any(kw in body for kw in _ACTUATOR_KEYWORDS):
                    return
            else:
                return

        # GraphQL: try introspection to confirm it's a real endpoint
        if path == "/graphql":
            intr_findings = await _check_graphql_introspection(client, url, host)
            findings.extend(intr_findings)
            if not intr_findings:
                return

        value = url
        if len(body) < 500:
            value = content[:300].strip() if content else url

        findings.append(Finding(
            category=Category.EXPOSED_FILE,
            severity=severity,
            confidence=confidence,
            title=title,
            value=value,
            context=f"HTTP {status} — {content_type} — {len(body)} bytes",
            source_url=url,
            host=host,
            timestamp=datetime.now(timezone.utc),
        ))
        logger.info("Exposed file found: %s (%d)", url, status)

    await asyncio.gather(*[
        _probe(path, title, severity, confidence)
        for path, title, severity, confidence in _SENSITIVE_PATHS
    ])

    return findings


async def _check_graphql_introspection(
    client: HttpClient,
    graphql_url: str,
    host: str,
) -> list[Finding]:
    """Send introspection query to confirm GraphQL endpoint and check if introspection is enabled."""
    import json
    findings: list[Finding] = []

    try:
        import httpx as _httpx
        async with _httpx.AsyncClient(verify=False, timeout=10, follow_redirects=True) as c:
            resp = await c.post(
                graphql_url,
                json={"query": "{__schema{types{name}}}"},
                headers={"Content-Type": "application/json"},
            )
            if resp.status_code == 200:
                try:
                    data = resp.json()
                except Exception:
                    return findings

                if "data" in data and "__schema" in str(data):
                    types = data.get("data", {}).get("__schema", {}).get("types", [])
                    type_names = [t.get("name", "") for t in types[:10]]
                    findings.append(Finding(
                        category=Category.EXPOSED_FILE,
                        severity=Severity.MEDIUM,
                        confidence=95,
                        title="GraphQL Introspection Enabled",
                        value=graphql_url,
                        context=f"Schema types: {', '.join(type_names)}",
                        source_url=graphql_url,
                        host=host,
                        timestamp=datetime.now(timezone.utc),
                    ))
                elif "data" in data:
                    findings.append(Finding(
                        category=Category.EXPOSED_FILE,
                        severity=Severity.INFO,
                        confidence=80,
                        title="GraphQL Endpoint Found",
                        value=graphql_url,
                        context="Endpoint responds to GraphQL queries (introspection disabled)",
                        source_url=graphql_url,
                        host=host,
                        timestamp=datetime.now(timezone.utc),
                    ))
    except Exception as e:
        logger.debug("GraphQL introspection check failed for %s: %s", graphql_url, e)

    return findings
