"""Collect and fetch JavaScript files from crawl results and framework-specific paths."""

from __future__ import annotations

import asyncio
import json
import logging
import re
from urllib.parse import urljoin, urlparse

from nexa.core.http import HttpClient
from nexa.models import CrawlResult, JSFile
from nexa.utils import deduplicate_urls, normalize_url

logger = logging.getLogger(__name__)

CHUNK_CONCURRENCY = 10

# Regex for sourceMappingURL at end of JS
SOURCEMAP_COMMENT_RE = re.compile(r"//[#@]\s*sourceMappingURL\s*=\s*(\S+)\s*$", re.MULTILINE)


def _extract_source_map_url(content: str, js_url: str) -> str | None:
    """Extract sourceMappingURL from JS content."""
    matches = SOURCEMAP_COMMENT_RE.findall(content)
    if matches:
        sm = matches[-1].strip()
        if sm.startswith("data:"):
            return None  # Inline source maps not handled
        return urljoin(js_url, sm)
    return None


async def _fetch_js_file(client: HttpClient, url: str) -> JSFile | None:
    """Fetch a single JS file."""
    content, status, headers, final_url = await client.get(url)
    if status == 0 or not content:
        logger.debug("Failed to fetch JS: %s (status=%d)", url, status)
        return None
    if status >= 400:
        logger.debug("HTTP %d for JS: %s", status, url)
        return None

    sm_url = _extract_source_map_url(content, final_url or url)
    # Also check response headers
    if not sm_url:
        sm_header = headers.get("sourcemap") or headers.get("x-sourcemap") or headers.get("x-source-map")
        if sm_header:
            sm_url = urljoin(final_url or url, sm_header)

    return JSFile(
        url=url,
        content=content,
        size=len(content),
        source_map_url=sm_url,
        final_url=final_url or url,
        status_code=status,
    )


async def _fetch_build_manifest(client: HttpClient, base_url: str, framework: str) -> list[str]:
    """Try to fetch build manifests to discover chunk URLs."""
    urls_found: list[str] = []
    parsed = urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    manifest_paths: list[str] = []

    if framework == "Next.js" or not framework:
        # Try common Next.js paths
        manifest_paths += [
            "/_next/static/chunks/",
            "/asset-manifest.json",
        ]
        # Build manifest requires buildId — try a known path pattern
        build_manifest_url = f"{origin}/_next/static/development/_buildManifest.js"
        content, status, _, _ = await client.get(build_manifest_url)
        if status == 200 and content:
            # Extract chunk paths
            chunk_matches = re.findall(r'"([^"]+\.js)"', content)
            for c in chunk_matches:
                urls_found.append(urljoin(origin, c if c.startswith("/") else f"/_next/static/{c}"))

    # asset-manifest.json (CRA)
    am_url = f"{origin}/asset-manifest.json"
    content, status, _, _ = await client.get(am_url)
    if status == 200 and content:
        try:
            data = json.loads(content)
            # CRA format
            files = data.get("files", data)
            if isinstance(files, dict):
                for v in files.values():
                    if isinstance(v, str) and v.endswith(".js"):
                        urls_found.append(normalize_url(v, origin))
        except json.JSONDecodeError:
            pass

    # manifest.json (generic/PWA)
    mj_url = f"{origin}/manifest.json"
    content, status, _, _ = await client.get(mj_url)
    if status == 200 and content:
        try:
            data = json.loads(content)
            # Gatsby page-data pattern
            for key in ("src", "href"):
                val = data.get(key)
                if val and isinstance(val, str) and val.endswith(".js"):
                    urls_found.append(normalize_url(val, origin))
        except json.JSONDecodeError:
            pass

    return urls_found


def _collect_js_urls_from_crawl(results: list[CrawlResult], frameworks: list[str]) -> list[str]:
    """Gather all JS URLs from crawl results."""
    urls: list[str] = []
    for result in results:
        urls.extend(result.script_urls)
        urls.extend(result.preload_urls)
        # Manifest URLs may point to JSON with more JS refs
        urls.extend(result.manifest_urls)
    return urls


def _framework_specific_urls(base_url: str, frameworks: list[str]) -> list[str]:
    """Generate known framework-specific JS URL patterns."""
    parsed = urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    urls: list[str] = []

    if "Next.js" in frameworks:
        # Common Next.js chunk names
        for chunk in ("main", "webpack", "framework", "commons", "pages/_app", "pages/index"):
            urls.append(f"{origin}/_next/static/chunks/{chunk}.js")

    if "Nuxt" in frameworks:
        for name in ("app", "vendors~app", "commons~app"):
            urls.append(f"{origin}/_nuxt/{name}.js")

    if "Astro" in frameworks:
        urls.append(f"{origin}/_astro/hoisted.js")

    if "Gatsby" in frameworks:
        for name in ("app", "framework", "webpack-runtime", "commons"):
            urls.append(f"{origin}/static/js/{name}.js")

    if "Create React App" in frameworks or "Webpack" in frameworks:
        for name in ("main", "bundle", "vendors", "chunk"):
            urls.append(f"{origin}/static/js/{name}.js")

    return urls


async def collect_js_files(
    client: HttpClient,
    crawl_results: list[CrawlResult],
    base_url: str,
    frameworks: list[str],
    historical_urls: list[str] | None = None,
    concurrency: int = CHUNK_CONCURRENCY,
) -> list[JSFile]:
    """Collect and fetch all JS files."""
    # Gather URLs from multiple sources
    js_urls: list[str] = []

    # From crawl
    js_urls.extend(_collect_js_urls_from_crawl(crawl_results, frameworks))

    # Framework-specific guesses
    js_urls.extend(_framework_specific_urls(base_url, frameworks))

    # Historical
    if historical_urls:
        for u in historical_urls:
            if u.lower().endswith(".js"):
                js_urls.append(u)

    # Build manifests
    try:
        manifest_urls = await _fetch_build_manifest(client, base_url, frameworks[0] if frameworks else "")
        js_urls.extend(manifest_urls)
    except Exception as e:
        logger.debug("Build manifest fetch failed: %s", e)

    # Handle protocol-relative URLs (//example.com/script.js → https://example.com/script.js)
    resolved_urls: list[str] = []
    for u in js_urls:
        if u and u.startswith("//"):
            u = "https:" + u
        resolved_urls.append(u)
    js_urls = resolved_urls

    # Deduplicate and filter — fix operator precedence with parentheses
    js_urls = deduplicate_urls([u for u in js_urls if u and (u.endswith(".js") or ".js?" in u or ".js#" in u)])
    # More permissive: include any URL with .js in path
    js_urls = deduplicate_urls([u for u in [normalize_url(u, base_url) for u in js_urls] if u])

    logger.info("Collecting %d unique JS files", len(js_urls))

    # Fetch concurrently
    semaphore = asyncio.Semaphore(concurrency)
    js_files: list[JSFile] = []

    async def fetch_with_sem(url: str) -> None:
        async with semaphore:
            js_file = await _fetch_js_file(client, url)
            if js_file:
                js_files.append(js_file)

    await asyncio.gather(*[fetch_with_sem(u) for u in js_urls], return_exceptions=True)
    logger.info("Successfully fetched %d JS files", len(js_files))
    return js_files
