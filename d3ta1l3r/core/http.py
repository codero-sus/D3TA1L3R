"""HTTP transport: one place where the tool touches the network.

Responsibilities:

* Build every request the same way (honest User-Agent, JSON-ish ``Accept``).
* Follow redirects **manually** so each hop is re-checked by the SSRF guard and
  counted against ``max_redirects``.
* Never read more than ``max_body_bytes`` from a response (a hostile or huge
  page must not be able to exhaust memory).
* Retry only what is worth retrying (429/5xx/timeouts), with exponential
  backoff and honest ``Retry-After`` handling.
* Consult robots.txt before fetching anything, unless explicitly disabled.
* Optionally serve from / write to the on-disk cache.

The transport is injectable (``httpx.AsyncBaseTransport``), which is how the
test-suite exercises the whole engine without a single packet leaving the box.
"""

from __future__ import annotations

import asyncio
import email.utils
import json as jsonlib
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin, urlsplit

import httpx

from ..config import ScanConfig
from ..errors import ForbiddenTargetError, HttpError, SourceError
from .cache import CacheEntry, ResponseCache
from .ratelimit import HostRateLimiter, retry_delay
from .security import assert_public_url

__all__ = ["Fetcher", "HttpResponse"]

_RETRY_STATUSES = frozenset({408, 425, 429, 500, 502, 503, 504, 522, 524})
_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})

_ACCEPT_HTML = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"


@dataclass(slots=True)
class HttpResponse:
    """A bounded, decoded snapshot of one public response."""

    url: str
    final_url: str
    status: int
    headers: dict[str, str]
    text: str
    elapsed_ms: int = 0
    from_cache: bool = False
    redirects: list[str] = field(default_factory=list)
    truncated: bool = False
    attempts: int = 1

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 400

    @property
    def content_length(self) -> int:
        return len(self.text)

    def header(self, name: str, default: str | None = None) -> str | None:
        return self.headers.get(name.lower(), default)

    def json(self) -> Any:
        """Parse the body as JSON, or raise :class:`SourceError`."""
        if not self.text:
            raise SourceError(f"empty body from {self.final_url}")
        try:
            return jsonlib.loads(self.text)
        except jsonlib.JSONDecodeError as exc:
            raise SourceError(f"invalid JSON from {self.final_url}: {exc}") from exc


class Fetcher:
    """Async HTTP client with politeness, robots and safety built in."""

    def __init__(
        self,
        config: ScanConfig,
        *,
        cache: ResponseCache | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
        limiter: HostRateLimiter | None = None,
        robots: Any | None = None,
    ) -> None:
        self.config = config
        self.cache = cache if (cache and config.use_cache) else None
        self.limiter = limiter or HostRateLimiter(
            rps=config.rate.per_host_rps, burst=config.rate.per_host_burst
        )
        self.robots = robots  # RobotsPolicy or None
        self._transport = transport
        self._client: httpx.AsyncClient | None = None
        self._client_lock = asyncio.Lock()

        # metrics
        self.hosts_contacted: set[str] = set()
        self.request_count = 0
        self.bytes_read = 0
        self.cache_hits = 0

    # -- lifecycle -------------------------------------------------------
    async def __aenter__(self) -> Fetcher:
        await self.start()
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self.close()

    async def start(self) -> None:
        if self._client is not None:
            return
        async with self._client_lock:
            if self._client is not None:
                return
            timeout = httpx.Timeout(
                self.config.timeout, connect=self.config.connect_timeout, pool=self.config.timeout
            )
            limits = httpx.Limits(
                max_connections=max(4, self.config.rate.global_concurrency),
                max_keepalive_connections=max(4, self.config.rate.global_concurrency // 2),
            )
            self._client = httpx.AsyncClient(
                timeout=timeout,
                limits=limits,
                follow_redirects=False,  # hop-by-hop checking happens in _fetch
                verify=self.config.verify_tls,
                transport=self._transport,
                headers=self._default_headers(),
                trust_env=True,
            )

    async def close(self) -> None:
        client, self._client = self._client, None
        if client is not None:
            await client.aclose()

    @property
    def client(self) -> httpx.AsyncClient:
        if self._client is None:  # pragma: no cover - programming error
            raise RuntimeError("Fetcher.start() was never awaited")
        return self._client

    def _default_headers(self) -> dict[str, str]:
        return {
            "User-Agent": self.config.user_agent,
            "Accept": _ACCEPT_HTML,
            "Accept-Language": "en-US,en;q=0.8",
            "Cache-Control": "no-cache",
        }

    # -- public API ------------------------------------------------------
    async def fetch(
        self,
        url: str,
        *,
        accept: str | None = None,
        extra_headers: Mapping[str, str] | None = None,
        check_robots: bool = True,
        use_cache: bool | None = None,
    ) -> HttpResponse:
        """robots-aware GET. Raises RobotsDeniedError / ForbiddenTargetError / HttpError."""
        if check_robots and self.config.respect_robots and self.robots is not None:
            await self.robots.check(url)  # raises RobotsDeniedError
            delay = self.robots.crawl_delay(url)
            if delay and self.config.respect_crawl_delay:
                self.limiter.set_min_interval(urlsplit(url).hostname or "", delay)
        return await self.fetch_raw(
            url, accept=accept, extra_headers=extra_headers, use_cache=use_cache
        )

    async def fetch_raw(
        self,
        url: str,
        *,
        method: str = "GET",
        accept: str | None = None,
        extra_headers: Mapping[str, str] | None = None,
        use_cache: bool | None = None,
        check_robots: bool = False,
    ) -> HttpResponse:
        """Low-level fetch. Bypasses robots by default (used *for* robots.txt)."""
        await self.start()
        if check_robots and self.config.respect_robots and self.robots is not None:
            await self.robots.check(url)

        candidate = await self._guard(url)
        cache_enabled = self.config.use_cache if use_cache is None else use_cache
        cache_key = ResponseCache.key_for(candidate, method=method, accept=accept or "")

        if cache_enabled and self.cache is not None:
            entry = self.cache.get(cache_key)
            if entry is not None:
                self.cache_hits += 1
                return _cached_response(entry)

        response = await self._fetch_with_redirects(
            candidate, method=method, accept=accept, extra_headers=extra_headers,
            policy_cache_key=(cache_key if cache_enabled else None),
        )

        if cache_enabled and self.cache is not None and response.status == 200:
            self.cache.set(
                cache_key,
                CacheEntry(
                    url=candidate,
                    status=response.status,
                    headers=response.headers,
                    body=response.text,
                    fetched_at=time.time(),
                    final_url=response.final_url,
                    redirects=response.redirects,
                ),
            )
        return response

    # -- internals -------------------------------------------------------
    async def _guard(self, url: str) -> str:
        """SSRF-check a URL, off the event loop (DNS resolution can block).

        Demo mode keeps every syntactic check but skips DNS: it is defined as
        "never touch the network", and the synthetic demo hostnames famously do
        not resolve.
        """
        resolve = self.config.strict_ssrf and not self.config.demo
        try:
            return await asyncio.to_thread(assert_public_url, url, resolve=resolve)
        except ForbiddenTargetError:
            raise
        except OSError as exc:  # pragma: no cover - transport-level DNS weirdness
            raise ForbiddenTargetError(f"could not validate host for {url}: {exc}") from exc

    async def _fetch_with_redirects(
        self,
        url: str,
        *,
        method: str,
        accept: str | None,
        extra_headers: Mapping[str, str] | None,
        policy_cache_key: str | None,
    ) -> HttpResponse:
        redirects: list[str] = []
        current = url
        attempt = 1
        started = time.perf_counter()

        while True:
            response, attempts_used = await self._request_once(
                current, method=method, accept=accept, extra_headers=extra_headers
            )
            attempt = attempts_used

            location = response.headers.get("location")
            if (
                response.status_code in _REDIRECT_STATUSES
                and location
                and self.config.follow_redirects
                and len(redirects) < self.config.max_redirects
            ):
                target = await self._guard(urljoin(current, location).strip())
                redirects.append(target)
                current = target
                # 303 (and legacy 302 on POST) become GET; we only ever GET anyway.
                continue

            text, truncated, size = await self._read_body(response)
            self.bytes_read += size
            headers = {k.lower(): v for k, v in response.headers.items() if _keep_header(k)}
            return HttpResponse(
                url=url,
                final_url=str(response.url),
                status=response.status_code,
                headers=headers,
                text=text,
                elapsed_ms=int((time.perf_counter() - started) * 1000),
                redirects=redirects,
                truncated=truncated,
                attempts=attempt,
            )

    async def _request_once(
        self,
        url: str,
        *,
        method: str,
        accept: str | None,
        extra_headers: Mapping[str, str] | None,
    ) -> tuple[httpx.Response, int]:
        """One logical request, including retries. Returns (response, attempts)."""
        host = urlsplit(url).hostname or ""
        headers: dict[str, str] = {}
        if accept:
            headers["Accept"] = accept
        if extra_headers:
            headers.update({str(k): str(v) for k, v in extra_headers.items()})

        last_error: Exception | None = None
        attempts = self.config.rate.max_retries + 1
        for attempt in range(1, attempts + 1):
            await self.limiter.acquire(host)
            self.request_count += 1
            self.hosts_contacted.add(host)
            try:
                request = self.client.build_request(method, url, headers=headers)
                response = await self.client.send(request, stream=True)
            except (httpx.TimeoutException, httpx.TransportError) as exc:
                last_error = exc
                if attempt < attempts:
                    await asyncio.sleep(
                        retry_delay(attempt, base=self.config.rate.backoff_base,
                                    maximum=self.config.rate.backoff_max)
                    )
                    continue
                raise HttpError(f"{type(exc).__name__}: {exc}", url=url) from exc

            if response.status_code in _RETRY_STATUSES and attempt < attempts:
                retry_after = _parse_retry_after(
                    response.headers.get("retry-after"), self.config.rate.backoff_max
                )
                response_status = response.status_code
                await response.aclose()
                delay = retry_delay(
                    attempt,
                    base=self.config.rate.backoff_base,
                    maximum=self.config.rate.backoff_max,
                    retry_after=retry_after if self.config.rate.honor_retry_after else None,
                )
                await asyncio.sleep(delay)
                last_error = HttpError(f"HTTP {response_status}", url=url, status=response_status)
                continue

            return response, attempt

        raise HttpError(str(last_error) if last_error else "request failed", url=url)

    async def _read_body(self, response: httpx.Response) -> tuple[str, bool, int]:
        """Stream the body, stopping at ``max_body_bytes``. Returns (text, truncated, bytes)."""
        cap = self.config.max_body_bytes
        chunks: list[bytes] = []
        size = 0
        truncated = False
        try:
            async for chunk in response.aiter_bytes():
                if not chunk:
                    continue
                remaining = cap - size
                if len(chunk) >= remaining:
                    chunks.append(chunk[:remaining])
                    size = cap
                    truncated = True
                    break
                chunks.append(chunk)
                size += len(chunk)
        except (httpx.TimeoutException, httpx.TransportError):
            truncated = True
        finally:
            await response.aclose()

        raw = b"".join(chunks)
        text = raw.decode(_charset_of(response.headers), errors="replace")
        return text, truncated, size


def _charset_of(headers: Any) -> str:
    """Parse the charset out of Content-Type ourselves.

    ``httpx.Response.encoding`` may consult the (possibly unread) body, so a
    streaming reader cannot rely on it; the header is authoritative anyway.
    """
    raw = str(headers.get("content-type", "")) if headers else ""
    for part in raw.split(";")[1:]:
        key, _, value = part.strip().partition("=")
        if key.strip().lower() == "charset" and value.strip():
            candidate = value.strip().strip('"').lower()
            try:
                "".encode(candidate)
            except LookupError:
                continue
            return candidate
    return "utf-8"


def _keep_header(name: str) -> bool:
    """Only keep headers we actually use — keeps evidence compact."""
    return name.lower() in {
        "content-type",
        "content-length",
        "link",
        "location",
        "retry-after",
        "x-ratelimit-remaining",
        "x-ratelimit-limit",
        "x-ratelimit-reset",
        "last-modified",
        "date",
    }


def _cached_response(entry: CacheEntry) -> HttpResponse:
    return HttpResponse(
        url=entry.url,
        final_url=entry.final_url,
        status=entry.status,
        headers={k.lower(): v for k, v in entry.headers.items()},
        text=entry.body,
        elapsed_ms=0,
        from_cache=True,
        redirects=list(entry.redirects),
    )


def _parse_retry_after(value: str | None, maximum: float) -> float | None:
    if not value:
        return None
    raw = value.strip()
    if raw.isdigit():
        return min(float(raw), maximum)
    parsed = email.utils.parsedate_to_datetime(raw) if raw else None
    if parsed is None:
        return None
    import datetime as _dt

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=_dt.timezone.utc)
    delta = (parsed - _dt.datetime.now(_dt.timezone.utc)).total_seconds()
    return max(0.0, min(delta, maximum))
