"""Async HTTP client with retry, rate limiting, and custom UA."""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Optional

import httpx

from nexa.core.waf_bypass import WAFBypassConfig, apply_jitter, build_bypass_headers, detect_waf, get_next_user_agent

logger = logging.getLogger(__name__)

DEFAULT_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/125.0.0.0 Safari/537.36"
)
DEFAULT_TIMEOUT = 20.0
DEFAULT_RETRIES = 3
DEFAULT_RATE_LIMIT = 5.0  # req/s

DEFAULT_HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    # Do NOT set Accept-Encoding manually — httpx manages decompression internally.
    "Accept-Language": "en-US,en;q=0.9",
    "Cache-Control": "no-cache",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Upgrade-Insecure-Requests": "1",
}

FetchResult = tuple[str, int, dict[str, str], str]  # content, status, headers, final_url


class RateLimiter:
    """Token bucket rate limiter."""

    def __init__(self, rate: float) -> None:
        self._rate = rate  # requests per second
        self._tokens = rate
        self._last = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self._last
            self._last = now
            self._tokens = min(self._rate, self._tokens + elapsed * self._rate)
            if self._tokens < 1:
                wait = (1 - self._tokens) / self._rate
                await asyncio.sleep(wait)
                self._tokens = 0
            else:
                self._tokens -= 1


class HttpClient:
    """Async HTTP client with retry, rate limiting, and configurable options."""

    def __init__(
        self,
        timeout: float = DEFAULT_TIMEOUT,
        retries: int = DEFAULT_RETRIES,
        rate_limit: float = DEFAULT_RATE_LIMIT,
        user_agent: str = DEFAULT_UA,
        verify_ssl: bool = False,
        waf_bypass: Optional[WAFBypassConfig] = None,
    ) -> None:
        self._timeout = timeout
        self._retries = retries
        self._rate_limiter = RateLimiter(rate_limit)
        self._user_agent = user_agent
        self._verify_ssl = verify_ssl
        self._client: Optional[httpx.AsyncClient] = None
        self._waf_bypass = waf_bypass or WAFBypassConfig(enabled=False)
        # Detected WAF type (set once detected, reused for all subsequent requests)
        self.detected_waf: Optional[str] = None
        # Cookie jar persistence per domain
        self._cookies: httpx.Cookies = httpx.Cookies()

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            headers = {**DEFAULT_HEADERS, "User-Agent": self._user_agent}
            self._client = httpx.AsyncClient(
                headers=headers,
                timeout=httpx.Timeout(self._timeout),
                follow_redirects=True,
                verify=self._verify_ssl,
                http2=True,
                cookies=self._cookies,
                limits=httpx.Limits(max_keepalive_connections=20, max_connections=50),
            )
        return self._client

    async def get(self, url: str, **kwargs) -> FetchResult:
        """Fetch a URL with retry and rate limiting. Returns (content, status, headers, final_url)."""
        await self._rate_limiter.acquire()

        # WAF bypass: apply jitter before the request
        if self._waf_bypass.enabled:
            await apply_jitter(self._waf_bypass.jitter_ms)

        client = await self._get_client()
        last_exc: Optional[Exception] = None

        for attempt in range(self._retries):
            try:
                # WAF bypass: build per-request bypass headers
                extra_headers: dict[str, str] = {}
                if self._waf_bypass.enabled:
                    ua = get_next_user_agent(self._waf_bypass.strategy)
                    extra_headers = build_bypass_headers(ua, url, self._waf_bypass.strategy)

                resp = await client.get(url, headers=extra_headers if extra_headers else None, **kwargs)
                headers = dict(resp.headers)
                final_url = str(resp.url)
                try:
                    content = resp.text
                except Exception:
                    content = resp.content.decode("utf-8", errors="replace")

                # WAF detection — check first response
                if self._waf_bypass.enabled and self.detected_waf is None:
                    waf = detect_waf(headers, content)
                    if waf:
                        self.detected_waf = waf
                        logger.info("WAF detected: %s at %s", waf, url)

                # Persist cookies for session simulation
                if self._waf_bypass.enabled:
                    self._cookies.update(resp.cookies)

                # If blocked (403/429) and WAF bypass enabled, retry HEAD then GET with new UA
                if resp.status_code in (403, 429) and self._waf_bypass.enabled and attempt < self._retries - 1:
                    logger.debug("Got %d at %s, retrying with different UA", resp.status_code, url)
                    await apply_jitter(self._waf_bypass.jitter_ms)
                    continue

                return content, resp.status_code, headers, final_url

            except httpx.TooManyRedirects:
                logger.debug("Too many redirects for %s", url)
                return "", 0, {}, url

            except httpx.RemoteProtocolError as e:
                # HTTP/2 protocol errors — retry with HTTP/1.1
                logger.debug("HTTP/2 protocol error for %s, retrying with HTTP/1.1: %s", url, e)
                try:
                    tmp_client = httpx.AsyncClient(
                        headers={**DEFAULT_HEADERS, "User-Agent": self._user_agent},
                        timeout=httpx.Timeout(self._timeout),
                        follow_redirects=True,
                        verify=self._verify_ssl,
                        http2=False,
                    )
                    async with tmp_client:
                        resp = await tmp_client.get(url, **kwargs)
                        return resp.text, resp.status_code, dict(resp.headers), str(resp.url)
                except Exception as inner:
                    last_exc = inner
                    if attempt < self._retries - 1:
                        await asyncio.sleep(2 ** attempt)

            except httpx.ConnectError as e:
                err_str = str(e).lower()
                if "ssl" in err_str or "certificate" in err_str or "tls" in err_str:
                    logger.debug("SSL/TLS error for %s, retrying without verification: %s", url, e)
                    try:
                        tmp_client = httpx.AsyncClient(
                            headers={**DEFAULT_HEADERS, "User-Agent": self._user_agent},
                            timeout=httpx.Timeout(self._timeout),
                            follow_redirects=True,
                            verify=False,
                            http2=False,
                        )
                        async with tmp_client:
                            resp = await tmp_client.get(url, **kwargs)
                            return resp.text, resp.status_code, dict(resp.headers), str(resp.url)
                    except Exception as inner:
                        last_exc = inner
                        return "", 0, {}, url
                logger.debug("Connection error for %s: %s", url, e)
                return "", 0, {}, url

            except (httpx.ReadTimeout, httpx.PoolTimeout) as e:
                last_exc = e
                logger.debug("Timeout on %s (attempt %d/%d)", url, attempt + 1, self._retries)
                if attempt < self._retries - 1:
                    await asyncio.sleep(2 ** attempt)

            except httpx.RequestError as e:
                last_exc = e
                logger.debug("Request error for %s: %s", url, e)
                if attempt < self._retries - 1:
                    await asyncio.sleep(2 ** attempt)

            except Exception as e:
                last_exc = e
                logger.debug("Unexpected error for %s: %s", url, e)
                if attempt < self._retries - 1:
                    await asyncio.sleep(2 ** attempt)

        logger.warning("Failed to fetch %s after %d attempts: %s", url, self._retries, last_exc)
        return "", 0, {}, url

    async def head(self, url: str) -> tuple[int, dict[str, str], str]:
        """Send a HEAD request. Returns (status_code, headers, final_url)."""
        await self._rate_limiter.acquire()
        client = await self._get_client()
        try:
            resp = await client.head(url)
            return resp.status_code, dict(resp.headers), str(resp.url)
        except Exception as e:
            logger.debug("HEAD error for %s: %s", url, e)
            return 0, {}, url

    async def close(self) -> None:
        if self._client and not self._client.is_closed:
            await self._client.aclose()

    async def __aenter__(self) -> "HttpClient":
        return self

    async def __aexit__(self, *args) -> None:
        await self.close()
