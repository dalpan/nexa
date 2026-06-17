"""Source map detection, fetching, and parsing."""

from __future__ import annotations

import json
import logging
from typing import Optional
from urllib.parse import urljoin

from nexa.core.http import HttpClient
from nexa.models import JSFile, SourceMap

logger = logging.getLogger(__name__)


async def _try_fetch_sourcemap(client: HttpClient, sm_url: str) -> Optional[dict]:
    """Fetch and parse a source map JSON."""
    content, status, _, _ = await client.get(sm_url)
    if status != 200 or not content:
        return None
    content = content.strip()
    # Handle XSSI prefix like )]}' or )]} that Angular/Closure add
    for prefix in (")]}'", ")]}", ")]}'\n", ")]}'\r\n"):
        if content.startswith(prefix):
            content = content[len(prefix):]
            break
    try:
        return json.loads(content)
    except json.JSONDecodeError as e:
        logger.debug("Failed to parse source map JSON from %s: %s", sm_url, e)
        return None


def _parse_sourcemap_data(url: str, data: dict) -> SourceMap:
    """Build a SourceMap object from parsed JSON."""
    sources = data.get("sources", [])
    if not isinstance(sources, list):
        sources = []

    sources_content = data.get("sourcesContent", [])
    if not isinstance(sources_content, list):
        sources_content = []

    # Pad or trim sourcesContent to match sources length
    while len(sources_content) < len(sources):
        sources_content.append(None)

    mappings_present = bool(data.get("mappings"))

    return SourceMap(
        url=url,
        sources=[str(s) for s in sources],
        sources_content=sources_content,
        mappings_present=mappings_present,
        publicly_accessible=True,
        raw=data,
    )


async def fetch_source_map(
    client: HttpClient,
    js_file: JSFile,
) -> Optional[SourceMap]:
    """Attempt to find and fetch a source map for a JS file."""
    candidate_urls: list[str] = []

    # From sourceMappingURL comment
    if js_file.source_map_url:
        candidate_urls.append(js_file.source_map_url)

    # Append .map to JS URL
    base_url = js_file.final_url or js_file.url
    candidate_urls.append(base_url + ".map")

    # Try replacing .js with .js.map
    if base_url.endswith(".js"):
        candidate_urls.append(base_url[:-3] + ".js.map")

    seen: set[str] = set()
    for url in candidate_urls:
        if url in seen:
            continue
        seen.add(url)

        logger.debug("Trying source map at %s", url)
        data = await _try_fetch_sourcemap(client, url)
        if data is not None:
            sm = _parse_sourcemap_data(url, data)
            logger.info(
                "Found source map: %s (%d sources, has_content=%s)",
                url,
                len(sm.sources),
                any(c is not None for c in sm.sources_content),
            )
            return sm

    return None


async def process_source_maps(
    client: HttpClient,
    js_files: list[JSFile],
) -> list[SourceMap]:
    """Process all JS files for source maps."""
    import asyncio
    source_maps: list[SourceMap] = []

    async def process_one(js_file: JSFile) -> None:
        sm = await fetch_source_map(client, js_file)
        if sm:
            source_maps.append(sm)

    await asyncio.gather(*[process_one(f) for f in js_files], return_exceptions=True)
    logger.info("Found %d source maps total", len(source_maps))
    return source_maps
