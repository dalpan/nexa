"""Framework-specific and generic extraction of endpoints, configs, and env objects."""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Optional

from nexa.models import CrawlResult, JSFile, SourceMap

logger = logging.getLogger(__name__)


# ── Regex patterns ─────────────────────────────────────────────────────────────

# Next.js
NEXT_DATA_RE = re.compile(r"<script[^>]*id=[\"']__NEXT_DATA__[\"'][^>]*>(.*?)</script>", re.DOTALL | re.IGNORECASE)
NEXT_PUBLIC_RE = re.compile(r'["\']?(NEXT_PUBLIC_[A-Z0-9_]+)["\']?\s*[:=]\s*["\']([^"\']{1,200})["\']')
NEXT_RUNTIME_CONFIG_RE = re.compile(
    r'(?:publicRuntimeConfig|serverRuntimeConfig)\s*[=:]\s*(\{[^}]{1,2000}\})', re.DOTALL
)
NEXT_API_ROUTE_RE = re.compile(r'["\']/(api/[a-zA-Z0-9/_\-]+)["\']')

# Nuxt
NUXT_DATA_RE = re.compile(r"window\.__NUXT__\s*=\s*(\{.*?\})\s*;", re.DOTALL)
NUXT_PUBLIC_RE = re.compile(r'["\']?(NUXT_PUBLIC_[A-Z0-9_]+)["\']?\s*[:=]\s*["\']([^"\']{1,200})["\']')

# Angular
ANGULAR_ENV_RE = re.compile(
    r'(?:environment|environment\.prod)\s*=\s*(\{[^}]{1,3000}\})', re.DOTALL
)

# Vue / Vite
VITE_ENV_RE = re.compile(r'import\.meta\.env\.([A-Z0-9_]+)\s*=\s*["\']([^"\']{1,200})["\']')
VITE_ENV_BLOCK_RE = re.compile(r'import\.meta\.env\s*=\s*Object\.freeze\((\{[^}]{1,2000}\})\)', re.DOTALL)

# Generic process.env
PROCESS_ENV_RE = re.compile(r'process\.env\.([A-Z_][A-Z0-9_]*)\s*[=:]\s*["\']([^"\']{1,200})["\']')
PROCESS_ENV_ACCESS_RE = re.compile(r'process\.env\[["\'](.*?)["\']\]')

# Config objects
CONFIG_OBJ_PATTERNS = [
    re.compile(r'(?:const|let|var)\s+config\s*=\s*(\{[^}]{10,2000}\})', re.DOTALL),
    re.compile(r'window\.config\s*=\s*(\{[^}]{10,2000}\})', re.DOTALL),
    re.compile(r'APP_CONFIG\s*=\s*(\{[^}]{10,2000}\})', re.DOTALL),
    re.compile(r'__ENV__\s*=\s*(\{[^}]{10,2000}\})', re.DOTALL),
    re.compile(r'window\.__ENV\s*=\s*(\{[^}]{10,2000}\})', re.DOTALL),
    re.compile(r'window\.ENV\s*=\s*(\{[^}]{10,2000}\})', re.DOTALL),
]

# API base URLs
AXIOS_BASE_URL_RE = re.compile(r'axios\.defaults\.baseURL\s*=\s*["\']([^"\']{5,200})["\']')
AXIOS_HEADERS_RE = re.compile(r'axios\.defaults\.headers[^\n]{0,200}')
FETCH_BASE_RE = re.compile(r'(?:baseURL|BASE_URL|apiUrl|API_URL|apiEndpoint)\s*[:=]\s*["\']([^"\']{5,200})["\']')

# Internal network — octets constrained to 0-255 to avoid SVG coordinate false positives
_OCT = r'(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)'
INTERNAL_IP_RE = re.compile(
    r'(?:https?://)?(?:localhost|127\.0\.0\.1|0\.0\.0\.0'
    r'|192\.168\.' + _OCT + r'\.' + _OCT +
    r'|10\.' + _OCT + r'\.' + _OCT + r'\.' + _OCT +
    r'|172\.(?:1[6-9]|2\d|3[01])\.' + _OCT + r'\.' + _OCT + r')'
    r'(?::\d{1,5})?(?:/[^\s\'"">]*)?'
)

ADMIN_PATH_RE = re.compile(
    r'''['""/](admin|dashboard|backoffice|internal|management|ops|devtools)[/'""]''',
    re.IGNORECASE,
)

PRIVATE_API_RE = re.compile(
    r'/api/v\d+/(?:admin|internal|private|system|management)',
    re.IGNORECASE,
)


# ── Helpers ────────────────────────────────────────────────────────────────────

def _safe_json(text: str) -> Optional[Any]:
    """Attempt to parse JSON, returning None on failure."""
    text = text.strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        # Try to fix trailing commas
        text = re.sub(r",\s*([}\]])", r"\1", text)
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return None


def _flatten_dict(obj: Any, prefix: str = "", max_depth: int = 5) -> dict[str, str]:
    """Flatten nested dict to dot-notation key-value pairs."""
    if max_depth <= 0:
        return {}
    result: dict[str, str] = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            key = f"{prefix}.{k}" if prefix else str(k)
            if isinstance(v, (dict, list)):
                result.update(_flatten_dict(v, key, max_depth - 1))
            elif v is not None:
                result[key] = str(v)
    elif isinstance(obj, list):
        for i, item in enumerate(obj[:20]):  # cap list iteration
            key = f"{prefix}[{i}]"
            if isinstance(item, (dict, list)):
                result.update(_flatten_dict(item, key, max_depth - 1))
            elif item is not None:
                result[key] = str(item)
    return result


# ── Extractor functions ────────────────────────────────────────────────────────

class ExtractedData:
    """Container for extracted data from JS/HTML."""

    def __init__(self) -> None:
        self.env_vars: dict[str, str] = {}        # key -> value
        self.config_objects: list[dict[str, Any]] = []
        self.api_endpoints: list[str] = []
        self.internal_urls: list[str] = []
        self.admin_paths: list[str] = []
        self.raw_snippets: list[str] = []         # interesting raw text fragments


# Sensitive keys to specifically extract from Next.js pageProps
SENSITIVE_NEXT_PROPS = (
    "wsApiKey", "wsApiKeyId", "wsApiKeyPassword", "apiKey", "apiSecret",
    "socketUrl", "wsUrl", "clientSecret", "accessToken", "authToken",
    "privateKey", "serviceKey", "encryptionKey",
)


def _extract_sensitive_props(obj: dict, prefix: str = "") -> dict[str, str]:
    """Recursively extract keys matching SENSITIVE_NEXT_PROPS patterns."""
    result: dict[str, str] = {}
    for k, v in obj.items():
        full_key = f"{prefix}.{k}" if prefix else k
        if isinstance(v, dict):
            result.update(_extract_sensitive_props(v, full_key))
        elif isinstance(v, str) and v:
            # Check if key matches any sensitive prop (case-insensitive partial match)
            k_lower = k.lower()
            for sens in SENSITIVE_NEXT_PROPS:
                if sens.lower() in k_lower or k_lower in sens.lower():
                    result[full_key] = v
                    break
    return result


def extract_nextjs(html: str, js_content: str) -> ExtractedData:
    """Extract Next.js specific data."""
    data = ExtractedData()

    # __NEXT_DATA__ JSON
    m = NEXT_DATA_RE.search(html)
    if m:
        raw_json = m.group(1)
        obj = _safe_json(raw_json)
        if isinstance(obj, dict):
            # Flatten all props recursively so detectors can scan key=value pairs
            data.env_vars.update(_flatten_dict(obj.get("props", {})))
            data.env_vars.update(_flatten_dict(obj.get("runtimeConfig", {}), "runtimeConfig"))
            data.env_vars["next.buildId"] = obj.get("buildId", "")
            # Specifically extract sensitive props from pageProps
            page_props = obj.get("props", {}).get("pageProps", {})
            if isinstance(page_props, dict):
                data.env_vars.update(_extract_sensitive_props(page_props, "pageProps"))
            # Store full raw JSON so detectors can scan it with regex
            data.raw_snippets.append(raw_json)

    # NEXT_PUBLIC_ vars in JS
    for m in NEXT_PUBLIC_RE.finditer(js_content):
        data.env_vars[m.group(1)] = m.group(2)

    # publicRuntimeConfig / serverRuntimeConfig
    for m in NEXT_RUNTIME_CONFIG_RE.finditer(js_content):
        obj = _safe_json(m.group(1))
        if isinstance(obj, dict):
            data.config_objects.append(obj)
            data.env_vars.update(_flatten_dict(obj))

    # API routes
    for m in NEXT_API_ROUTE_RE.finditer(js_content):
        data.api_endpoints.append("/" + m.group(1))

    return data


def extract_nuxt(html: str, js_content: str) -> ExtractedData:
    """Extract Nuxt.js specific data."""
    data = ExtractedData()

    m = NUXT_DATA_RE.search(html + js_content)
    if m:
        obj = _safe_json(m.group(1))
        if isinstance(obj, dict):
            config = obj.get("config", {})
            if isinstance(config, dict):
                pub = config.get("public", {})
                data.env_vars.update(_flatten_dict(pub, "public"))
                priv = config.get("private", {})
                if priv:
                    data.env_vars.update(_flatten_dict(priv, "private"))

    for m in NUXT_PUBLIC_RE.finditer(js_content):
        data.env_vars[m.group(1)] = m.group(2)

    return data


def extract_angular(js_content: str) -> ExtractedData:
    """Extract Angular environment objects."""
    data = ExtractedData()

    for m in ANGULAR_ENV_RE.finditer(js_content):
        obj = _safe_json(m.group(1))
        if isinstance(obj, dict):
            data.config_objects.append(obj)
            data.env_vars.update(_flatten_dict(obj, "env"))
        else:
            # Try to extract key=value pairs from the raw text
            snippet = m.group(1)
            kv_re = re.findall(r'(\w+)\s*:\s*["\']([^"\']{1,200})["\']', snippet)
            for k, v in kv_re:
                data.env_vars[f"env.{k}"] = v

    return data


def extract_vue_vite(js_content: str) -> ExtractedData:
    """Extract Vue/Vite env vars."""
    data = ExtractedData()

    for m in VITE_ENV_RE.finditer(js_content):
        data.env_vars[m.group(1)] = m.group(2)

    m = VITE_ENV_BLOCK_RE.search(js_content)
    if m:
        obj = _safe_json(m.group(1))
        if isinstance(obj, dict):
            data.env_vars.update(_flatten_dict(obj))

    return data


def extract_generic(js_content: str) -> ExtractedData:
    """Generic extraction applicable to all JS."""
    data = ExtractedData()

    # process.env assignments
    for m in PROCESS_ENV_RE.finditer(js_content):
        data.env_vars[m.group(1)] = m.group(2)

    # process.env access pattern (keys only)
    for m in PROCESS_ENV_ACCESS_RE.finditer(js_content):
        data.env_vars[m.group(1)] = ""

    # Config objects
    for pattern in CONFIG_OBJ_PATTERNS:
        for m in pattern.finditer(js_content):
            obj = _safe_json(m.group(1))
            if isinstance(obj, dict):
                data.config_objects.append(obj)
                data.env_vars.update(_flatten_dict(obj, "config"))

    # Axios base URL
    for m in AXIOS_BASE_URL_RE.finditer(js_content):
        data.api_endpoints.append(m.group(1))

    for m in FETCH_BASE_RE.finditer(js_content):
        url = m.group(1)
        if url.startswith(("http://", "https://", "/")):
            data.api_endpoints.append(url)

    # Internal IPs / hosts — skip bare localhost/127.0.0.1 (noise in every webpack bundle)
    _TRIVIAL_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0"}
    for m in INTERNAL_IP_RE.finditer(js_content):
        val = m.group(0).strip("/")
        # Strip scheme for comparison
        clean = val.removeprefix("http://").removeprefix("https://").split("/")[0].split(":")[0]
        if clean not in _TRIVIAL_HOSTS:
            data.internal_urls.append(m.group(0))

    # Admin paths
    for m in ADMIN_PATH_RE.finditer(js_content):
        data.admin_paths.append(m.group(0))

    # Private API routes
    for m in PRIVATE_API_RE.finditer(js_content):
        data.admin_paths.append(m.group(0))

    return data


def extract_from_source_map(sm: SourceMap) -> ExtractedData:
    """Extract data from source map source content."""
    data = ExtractedData()
    for content in sm.sources_content:
        if not content:
            continue
        d = extract_generic(content)
        data.env_vars.update(d.env_vars)
        data.api_endpoints.extend(d.api_endpoints)
        data.internal_urls.extend(d.internal_urls)
        data.admin_paths.extend(d.admin_paths)
    return data


def run_all_extractors(
    html: str,
    js_content: str,
    frameworks: list[str],
    source_maps: list[SourceMap] | None = None,
) -> ExtractedData:
    """Run all extractors and merge results."""
    merged = ExtractedData()

    def _merge(other: ExtractedData) -> None:
        merged.env_vars.update(other.env_vars)
        merged.config_objects.extend(other.config_objects)
        merged.api_endpoints.extend(other.api_endpoints)
        merged.internal_urls.extend(other.internal_urls)
        merged.admin_paths.extend(other.admin_paths)
        merged.raw_snippets.extend(other.raw_snippets)

    # Always run Next.js and Nuxt extractors — __NEXT_DATA__ / __NUXT__ may be
    # present even if fingerprinting didn't detect the framework (e.g. when only
    # the bare domain was crawled and no JS was fetched yet).
    _merge(extract_nextjs(html, js_content))
    _merge(extract_nuxt(html, js_content))
    if "Angular" in frameworks:
        _merge(extract_angular(js_content))
    if any(f in frameworks for f in ("Vue", "Vite")):
        _merge(extract_vue_vite(js_content))

    # Always run generic
    _merge(extract_generic(js_content))

    if source_maps:
        for sm in source_maps:
            _merge(extract_from_source_map(sm))

    # Deduplicate lists
    merged.api_endpoints = list(dict.fromkeys(merged.api_endpoints))
    merged.internal_urls = list(dict.fromkeys(merged.internal_urls))
    merged.admin_paths = list(dict.fromkeys(merged.admin_paths))

    return merged
