"""HTML crawler: extract scripts, links, meta tags, and comments."""

from __future__ import annotations

import asyncio
import logging
import re
from collections import deque
from typing import Optional
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup, Comment

from nexa.core.http import HttpClient
from nexa.core.waf_bypass import detect_waf
from nexa.models import CrawlResult
from nexa.utils import deduplicate_urls, extract_domain, is_same_domain, normalize_url

logger = logging.getLogger(__name__)

# Patterns that indicate the response is a WAF challenge or ISP block page, not real content
_CF_CHALLENGE_RE = re.compile(r'cf-mitigated', re.IGNORECASE)
_BLOCK_TITLE_RE = re.compile(r'<title[^>]*>(?:Just a moment|Access Denied|Attention Required|403 Forbidden|Internet Positif|Blocked|Perhatian)[^<]*</title>', re.IGNORECASE)
_ISP_BLOCK_HOSTS = {"internet-positif.info", "trustpositif.kominfo.go.id", "nawala.org"}

# Patterns for sourceMappingURL in JS/inline content
SOURCEMAP_RE = re.compile(r"//[#@]\s*sourceMappingURL\s*=\s*(\S+)")


def _extract_sourcemap_hints(text: str) -> list[str]:
    return SOURCEMAP_RE.findall(text)


def _parse_html(url: str, html: str, headers: dict[str, str]) -> CrawlResult:
    """Parse HTML and extract all relevant data."""
    result = CrawlResult(url=url, raw_html=html, headers=headers)
    if not html:
        return result

    try:
        soup = BeautifulSoup(html, "html.parser")
    except Exception as e:
        logger.debug("BeautifulSoup parse error for %s: %s", url, e)
        return result

    base_tag = soup.find("base")
    base_url = url
    if base_tag and base_tag.get("href"):
        base_url = urljoin(url, base_tag["href"])

    # Script tags
    for tag in soup.find_all("script"):
        src = tag.get("src", "").strip()
        if src:
            norm = normalize_url(src, base_url)
            if norm:
                result.script_urls.append(norm)
        elif tag.string:
            text = tag.string
            result.inline_scripts.append(text)
            result.sourcemap_hints.extend(_extract_sourcemap_hints(text))

    # Preload / prefetch
    for tag in soup.find_all("link"):
        rel = tag.get("rel", [])
        if isinstance(rel, list):
            rel_str = " ".join(rel).lower()
        else:
            rel_str = str(rel).lower()

        href = tag.get("href", "").strip()
        if not href:
            continue
        norm = normalize_url(href, base_url)
        if not norm:
            continue

        if "manifest" in rel_str:
            result.manifest_urls.append(norm)
        elif any(x in rel_str for x in ("preload", "prefetch", "modulepreload")):
            as_attr = tag.get("as", "").lower()
            if as_attr in ("script", "fetch", "") or not as_attr:
                result.preload_urls.append(norm)
        elif "stylesheet" in rel_str:
            pass  # skip CSS

    # Meta tags
    for tag in soup.find_all("meta"):
        name = tag.get("name") or tag.get("property") or tag.get("http-equiv") or ""
        content = tag.get("content", "")
        if name and content:
            result.meta_tags[name.lower()] = content

    # Internal page links (for crawling)
    for tag in soup.find_all("a", href=True):
        href = tag["href"].strip()
        norm = normalize_url(href, base_url)
        if norm and is_same_domain(norm, extract_domain(url)):
            result.page_links.append(norm)

    # HTML comments
    comments = soup.find_all(string=lambda t: isinstance(t, Comment))
    for comment in comments:
        text = str(comment).strip()
        if text and len(text) > 3:
            result.html_comments.append(text)

    return result


def _detect_block(url: str, final_url: str, status: int, headers: dict[str, str], content: str) -> Optional[str]:
    """Return a block reason string if the response is a WAF challenge or ISP block, else None."""
    # ISP redirect to block page (Indonesia Internet Positif etc.)
    final_host = urlparse(final_url).hostname or ""
    if final_host in _ISP_BLOCK_HOSTS:
        return f"ISP block — redirected to {final_host}"

    # Cloudflare JS challenge header
    if headers.get("cf-mitigated", "").lower() == "challenge":
        return "Cloudflare JS Challenge (cf-mitigated: challenge) — requires browser JS execution"

    # Block page title patterns
    if content and _BLOCK_TITLE_RE.search(content[:2000]):
        waf = detect_waf(headers, content)
        reason = f"{waf} challenge/block page" if waf else "WAF/firewall block page"
        return reason

    # HTTP 403 + WAF signature in headers/body
    if status == 403:
        waf = detect_waf(headers, content)
        if waf:
            return f"{waf} returned 403 Forbidden"

    return None


async def crawl_page(client: HttpClient, url: str) -> Optional[CrawlResult]:
    """Fetch and parse a single page."""
    content, status, headers, final_url = await client.get(url)

    # If HTTPS fails completely, try HTTP fallback
    if (not content or status == 0) and url.startswith("https://"):
        http_url = "http://" + url[8:]
        logger.debug("HTTPS failed for %s, trying HTTP fallback", url)
        content, status, headers, final_url = await client.get(http_url)

    if not content or status == 0:
        logger.debug("No content for %s (status=%d)", url, status)
        return None

    result = _parse_html(final_url or url, content, headers)
    result.status_code = status

    # Detect WAF/ISP block — always, regardless of bypass mode
    block_reason = _detect_block(url, final_url or url, status, headers, content)
    if block_reason:
        result.is_blocked = True
        result.block_reason = block_reason
        logger.warning("Blocked: %s — %s", url, block_reason)

    # Check response headers for sourcemap hints (for JS responses)
    sm_header = headers.get("sourcemap") or headers.get("x-sourcemap") or headers.get("x-source-map")
    if sm_header:
        result.sourcemap_hints.append(sm_header)

    return result


async def discover_subdomains(
    client: HttpClient,
    domain: str,
) -> list[str]:
    """Query passive sources for subdomains."""
    subdomains: set[str] = set()

    # crt.sh
    crt_url = f"https://crt.sh/?q=%.{domain}&output=json"
    try:
        content, status, _, _ = await client.get(crt_url)
        if status == 200 and content:
            import json
            data = json.loads(content)
            for entry in data:
                name = entry.get("name_value", "")
                for sub in name.split("\n"):
                    sub = sub.strip().lstrip("*.")
                    if sub and sub.endswith(domain) and sub != domain:
                        subdomains.add(sub)
    except Exception as e:
        logger.debug("crt.sh query failed for %s: %s", domain, e)

    # HackerTarget
    ht_url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    try:
        content, status, _, _ = await client.get(ht_url)
        if status == 200 and content:
            for line in content.splitlines():
                parts = line.split(",")
                if parts:
                    sub = parts[0].strip()
                    if sub and sub.endswith(domain) and sub != domain:
                        subdomains.add(sub)
    except Exception as e:
        logger.debug("HackerTarget query failed for %s: %s", domain, e)

    # Validate subdomains with HEAD requests
    valid: list[str] = []
    async def check_sub(sub: str) -> None:
        for scheme in ("https", "http"):
            url = f"{scheme}://{sub}"
            status, _, _ = await client.head(url)
            if status and status < 600:
                valid.append(sub)
                return

    tasks = [check_sub(s) for s in list(subdomains)[:50]]
    await asyncio.gather(*tasks, return_exceptions=True)
    return valid


async def crawl_site(
    client: HttpClient,
    start_url: "str | list[str]",
    max_depth: int = 2,
    max_pages: int = 50,
) -> tuple[list[CrawlResult], list[str]]:
    """BFS crawl of a site, following same-domain links.

    Returns (results, warnings).
    ``start_url`` may be a single URL string or a list of starting URLs.
    All starting URLs share a single visited set so pages are never fetched twice.
    The domain is derived from the first starting URL.
    """
    if isinstance(start_url, list):
        start_urls = start_url
    else:
        start_urls = [start_url]

    if not start_urls:
        return [], []

    domain = extract_domain(start_urls[0])
    visited: set[str] = set()
    results: list[CrawlResult] = []
    warnings: list[str] = []
    blocked_urls: set[str] = set()

    # Seed queue with all starting URLs at depth 0
    queue: deque[tuple[str, int]] = deque([(u, 0) for u in start_urls])

    while queue and len(visited) < max_pages:
        url, depth = queue.popleft()
        norm = normalize_url(url, "")
        if not norm or norm in visited:
            continue
        visited.add(norm)

        logger.info("Crawling [depth=%d] %s", depth, url)
        result = await crawl_page(client, url)
        if result is None:
            continue

        if result.is_blocked:
            blocked_urls.add(url)
            warning = f"[BLOCKED] {url} — {result.block_reason}"
            if warning not in warnings:
                warnings.append(warning)
            # Don't follow links from a block page
            continue

        results.append(result)

        if depth < max_depth:
            for link in deduplicate_urls(result.page_links):
                if link not in visited and is_same_domain(link, domain):
                    queue.append((link, depth + 1))

    if blocked_urls and not results:
        warnings.append(
            "All pages were blocked by WAF/ISP — scan results may be incomplete. "
            "Try --waf-bypass or use a VPN/proxy."
        )

    logger.info("Crawled %d pages on %s", len(results), domain)
    return results, warnings


async def fetch_historical_urls(
    client: HttpClient,
    domain: str,
    limit: int = 5000,
) -> list[str]:
    """Fetch historical URLs from Wayback Machine CDX API."""
    cdx_url = (
        f"http://web.archive.org/cdx/search/cdx"
        f"?url=*.{domain}/*&output=json&fl=original&collapse=urlkey&limit={limit}"
    )
    try:
        content, status, _, _ = await client.get(cdx_url)
        if status != 200 or not content:
            return []
        import json
        data = json.loads(content)
        # First row is header ["original"]
        urls = [row[0] for row in data[1:] if row]
        # Filter to JS and interesting paths
        interesting = []
        for u in urls:
            lower = u.lower()
            if any(lower.endswith(ext) for ext in (".js", ".map", ".json", ".env")):
                interesting.append(u)
            elif any(p in lower for p in ("/api/", "/config", "/manifest", "/asset", "/static/")):
                interesting.append(u)
        return deduplicate_urls(interesting)
    except Exception as e:
        logger.debug("Wayback CDX fetch failed for %s: %s", domain, e)
        return []
