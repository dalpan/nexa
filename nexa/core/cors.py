"""CORS misconfiguration checker."""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone

import httpx

from nexa.models import Category, Finding, Severity

logger = logging.getLogger(__name__)

_TEST_ORIGINS = [
    "https://evil.nexa-probe.com",
    "null",
    "https://attacker.com",
]


async def check_cors(
    url: str,
    host: str,
    concurrency: int = 5,
) -> list[Finding]:
    """Test URL for CORS misconfiguration using spoofed Origin headers."""
    findings: list[Finding] = []
    sem = asyncio.Semaphore(concurrency)

    async def _test(origin: str) -> None:
        async with sem:
            try:
                async with httpx.AsyncClient(
                    verify=False,
                    timeout=10,
                    follow_redirects=True,
                ) as client:
                    resp = await client.options(
                        url,
                        headers={
                            "Origin": origin,
                            "Access-Control-Request-Method": "GET",
                            "Access-Control-Request-Headers": "authorization,content-type",
                        },
                    )
                    acao = resp.headers.get("access-control-allow-origin", "")
                    acac = resp.headers.get("access-control-allow-credentials", "").lower()

                    if not acao:
                        # Also try a GET request — some servers only send CORS on GET
                        resp = await client.get(url, headers={"Origin": origin})
                        acao = resp.headers.get("access-control-allow-origin", "")
                        acac = resp.headers.get("access-control-allow-credentials", "").lower()

                    if not acao:
                        return

                    severity = Severity.INFO
                    confidence = 60
                    detail = ""

                    if acao == "*" and acac == "true":
                        # Wildcard + credentials is invalid per spec but some servers do it
                        severity = Severity.HIGH
                        confidence = 90
                        detail = "ACAO: * with credentials=true (browser blocks but config is wrong)"
                    elif acao == origin and origin != "null" and acac == "true":
                        severity = Severity.HIGH
                        confidence = 95
                        detail = f"Origin reflected with credentials=true — arbitrary origin can read authenticated responses"
                    elif acao == "null" and acac == "true":
                        severity = Severity.HIGH
                        confidence = 90
                        detail = "null origin allowed with credentials=true — sandboxed iframes can exploit this"
                    elif acao == origin and origin != "null":
                        severity = Severity.MEDIUM
                        confidence = 80
                        detail = f"Origin reflected without credentials — still allows cross-origin reads"
                    elif acao == "*":
                        severity = Severity.LOW
                        confidence = 70
                        detail = "Wildcard CORS — acceptable for public APIs, review if endpoint has auth"
                    else:
                        return

                    findings.append(Finding(
                        category=Category.CORS,
                        severity=severity,
                        confidence=confidence,
                        title="CORS Misconfiguration",
                        value=f"ACAO: {acao} | Credentials: {acac or 'false'}",
                        context=f"Tested Origin: {origin}\n{detail}",
                        source_url=url,
                        host=host,
                        timestamp=datetime.now(timezone.utc),
                    ))

            except Exception as e:
                logger.debug("CORS check failed for %s with origin %s: %s", url, origin, e)

    await asyncio.gather(*[_test(o) for o in _TEST_ORIGINS])

    # Deduplicate — keep highest severity
    seen: dict[str, Finding] = {}
    for f in findings:
        key = f.source_url
        if key not in seen or f.severity > seen[key].severity:
            seen[key] = f
    return list(seen.values())
