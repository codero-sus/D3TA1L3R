"""Transport behaviour: caps, redirects, retries, robots, caching, metrics."""

from __future__ import annotations

import httpx
import pytest

from d3ta1l3r.core.cache import ResponseCache
from d3ta1l3r.core.http import Fetcher
from d3ta1l3r.core.ratelimit import HostRateLimiter, retry_delay
from d3ta1l3r.errors import ForbiddenTargetError, HttpError, RobotsDeniedError
from tests.conftest import html, make_config, text


class TestBodyCaps:
    async def test_body_is_truncated_at_max_body_bytes(self, fetcher_factory) -> None:
        payload = "x" * 50_000
        fetcher, _ = await fetcher_factory(
            {"big.example.com": html(payload)}, config=make_config(max_body_bytes=4096)
        )
        response = await fetcher.fetch_raw("https://big.example.com/page")
        assert len(response.text) == 4096
        assert response.truncated is True
        assert fetcher.bytes_read == 4096

    async def test_headers_are_filtered_to_the_ones_we_use(self, fetcher_factory) -> None:
        fetcher, _ = await fetcher_factory({
            "h.example.com": (200, "ok", {
                "content-type": "text/plain",
                "set-cookie": "secret=1",
                "x-internal-thing": "nope",
                "last-modified": "Wed, 01 Jan 2025 00:00:00 GMT",
            }),
        })
        response = await fetcher.fetch_raw("https://h.example.com/")
        assert "set-cookie" not in response.headers
        assert "x-internal-thing" not in response.headers
        assert response.header("last-modified")


class TestRedirects:
    async def test_follows_redirects_and_records_each_hop(self, fetcher_factory) -> None:
        fetcher, table = await fetcher_factory({
            "a.example.com": lambda request: httpx.Response(
                301, headers={"location": "https://b.example.com/final"}, request=request),
            "b.example.com": html("<html>arrived</html>"),
        })
        response = await fetcher.fetch_raw("https://a.example.com/start")
        assert response.status == 200
        assert response.final_url == "https://b.example.com/final"
        assert response.redirects == ["https://b.example.com/final"]
        assert table.count("b.example.com") == 1

    async def test_redirect_loop_is_capped(self, fetcher_factory) -> None:
        def loop(request):
            return httpx.Response(302, headers={"location": "https://loop.example.com/again"},
                                  request=request)

        fetcher, table = await fetcher_factory({"loop.example.com": loop},
                                               config=make_config(max_redirects=3))
        response = await fetcher.fetch_raw("https://loop.example.com/start")
        assert response.status == 302
        assert len(response.redirects) == 3
        assert table.count("loop.example.com") == 4  # initial + 3 hops

    async def test_every_redirect_hop_is_ssrf_checked(self, fetcher_factory) -> None:
        fetcher, _ = await fetcher_factory({
            "public.example.com": lambda request: httpx.Response(
                302, headers={"location": "http://169.254.169.254/latest/meta-data/"}, request=request),
        })
        with pytest.raises(ForbiddenTargetError):
            await fetcher.fetch_raw("https://public.example.com/")

    async def test_redirects_can_be_disabled(self, fetcher_factory) -> None:
        fetcher, _ = await fetcher_factory(
            {"a.example.com": lambda request: httpx.Response(
                302, headers={"location": "https://b.example.com/"}, request=request)},
            config=make_config(follow_redirects=False),
        )
        response = await fetcher.fetch_raw("https://a.example.com/")
        assert response.status == 302
        assert response.redirects == []


class TestRetries:
    async def test_retries_then_succeeds(self, fetcher_factory) -> None:
        attempts = {"n": 0}

        def flaky(request):
            attempts["n"] += 1
            if attempts["n"] == 1:
                return httpx.Response(503, text="try later", request=request)
            return httpx.Response(200, text="ok", request=request)

        fetcher, _ = await fetcher_factory(
            {"flaky.example.com": flaky},
            config=make_config(rate={"max_retries": 2}),
        )
        response = await fetcher.fetch_raw("https://flaky.example.com/")
        assert response.status == 200
        assert response.attempts == 2
        assert attempts["n"] == 2

    async def test_retries_are_bounded(self, fetcher_factory) -> None:
        fetcher, table = await fetcher_factory(
            {"down.example.com": 503}, config=make_config(rate={"max_retries": 2})
        )
        response = await fetcher.fetch_raw("https://down.example.com/")
        assert response.status == 503
        assert table.count("down.example.com") == 3  # 1 + 2 retries

    async def test_4xx_is_not_retried(self, fetcher_factory) -> None:
        fetcher, table = await fetcher_factory({"e.example.com": 404})
        await fetcher.fetch_raw("https://e.example.com/")
        assert table.count("e.example.com") == 1

    async def test_retry_after_header_is_honoured(self, fetcher_factory) -> None:
        calls = {"n": 0}

        def throttled(request):
            calls["n"] += 1
            if calls["n"] == 1:
                return httpx.Response(429, headers={"retry-after": "0"}, request=request)
            return httpx.Response(200, text="ok", request=request)

        fetcher, _ = await fetcher_factory(
            {"t.example.com": throttled}, config=make_config(rate={"max_retries": 1})
        )
        response = await fetcher.fetch_raw("https://t.example.com/")
        assert response.status == 200 and response.attempts == 2

    async def test_transport_errors_become_http_errors(self) -> None:
        def broken(request):
            raise httpx.ConnectError("no route to host", request=request)

        transport = httpx.MockTransport(broken)
        fetcher = Fetcher(make_config(), transport=transport)
        await fetcher.start()
        try:
            with pytest.raises(HttpError):
                await fetcher.fetch_raw("https://nope.example.com/")
        finally:
            await fetcher.close()


class TestRobots:
    async def test_disallow_all_blocks_every_request(self, fetcher_factory) -> None:
        fetcher, table = await fetcher_factory(
            {"r.example.com": html("nope")}, robots_status=200,
            robots_body="User-agent: *\nDisallow: /\n", robots=True,
        )
        with pytest.raises(RobotsDeniedError):
            await fetcher.fetch("https://r.example.com/page")
        assert table.count("/page") == 0

    async def test_specific_disallow_only_blocks_that_path(self, fetcher_factory) -> None:
        fetcher, _ = await fetcher_factory(
            {"r.example.com": html("ok")}, robots_status=200,
            robots_body="User-agent: *\nDisallow: /private\n", robots=True,
        )
        with pytest.raises(RobotsDeniedError):
            await fetcher.fetch("https://r.example.com/private/x")
        response = await fetcher.fetch("https://r.example.com/public/x")
        assert response.status == 200

    async def test_missing_robots_txt_means_allowed(self, fetcher_factory) -> None:
        fetcher, _ = await fetcher_factory({"r.example.com": html("ok")}, robots=True)
        response = await fetcher.fetch("https://r.example.com/anything")
        assert response.status == 200

    async def test_server_error_on_robots_means_disallowed_by_default(
        self, fetcher_factory
    ) -> None:
        fetcher, _ = await fetcher_factory(
            {"r.example.com": html("ok")}, robots_status=503, robots=True
        )
        with pytest.raises(RobotsDeniedError):
            await fetcher.fetch("https://r.example.com/x")

    async def test_fail_open_opt_in(self, fetcher_factory) -> None:
        fetcher, _ = await fetcher_factory(
            {"r.example.com": html("ok")},
            config=make_config(robots_fail_open=True),
            robots_status=503,
            robots=True,
        )
        response = await fetcher.fetch("https://r.example.com/x")
        assert response.status == 200

    async def test_crawl_delay_sets_a_floor(self, fetcher_factory) -> None:
        fetcher, _ = await fetcher_factory(
            {"r.example.com": html("ok")},
            robots_status=200,
            robots_body="User-agent: *\nCrawl-delay: 1\nAllow: /\n",
            robots=True,
        )
        await fetcher.fetch("https://r.example.com/a")
        await fetcher.fetch("https://r.example.com/b")
        bucket = fetcher.limiter._buckets["r.example.com"]
        assert bucket.min_interval == pytest.approx(1.0, abs=0.001)
        # ...and the cap keeps a hostile Crawl-delay from stalling a scan.
        assert bucket.min_interval <= fetcher.config.crawl_delay_cap

    async def test_robots_fetch_itself_is_never_robots_checked(self, fetcher_factory) -> None:
        fetcher, table = await fetcher_factory(
            {"r.example.com": html("ok")}, robots_status=200,
            robots_body="User-agent: *\nDisallow: /robots.txt\n", robots=True,
        )
        await fetcher.fetch("https://r.example.com/x")  # must not recurse/deny forever
        assert table.count("/robots.txt") == 1

    async def test_robots_is_cached_per_origin(self, fetcher_factory) -> None:
        fetcher, table = await fetcher_factory({"r.example.com": html("ok")}, robots=True)
        for path in ("a", "b", "c"):
            await fetcher.fetch(f"https://r.example.com/{path}")
        assert table.count("/robots.txt") == 1


class TestCaching:
    async def test_cache_avoids_the_second_request(self, tmp_path, fetcher_factory) -> None:
        cache = ResponseCache(tmp_path / "cache")
        config = make_config(use_cache=True, cache_dir=tmp_path / "cache")
        fetcher, table = await fetcher_factory({"c.example.com": html("cached body")},
                                               config=config, cache=cache)
        first = await fetcher.fetch_raw("https://c.example.com/page")
        second = await fetcher.fetch_raw("https://c.example.com/page")
        assert first.text == second.text == "cached body"
        assert second.from_cache is True
        assert table.count("/page") == 1
        assert cache.hits == 1

    async def test_cache_respects_ttl(self, tmp_path) -> None:
        import time

        from d3ta1l3r.core.cache import CacheEntry

        cache = ResponseCache(tmp_path / "c", ttl=60)
        fresh = CacheEntry("https://x", 200, {}, "body", time.time(), "https://x", [])
        stale = CacheEntry("https://x", 200, {}, "body", time.time() - 600, "https://x", [])
        cache.set("fresh", fresh)
        cache.set("stale", stale)
        assert cache.get("fresh") is not None
        assert cache.get("stale") is None


class TestRateLimiter:
    async def test_token_bucket_paces_requests_to_one_host(self) -> None:
        import time

        limiter = HostRateLimiter(rps=50.0, burst=1)
        started = time.perf_counter()
        for _ in range(3):
            await limiter.acquire("example.com")
        elapsed = time.perf_counter() - started
        assert elapsed >= 0.03  # burst 1 then ~20ms per extra request

    def test_retry_delay_backs_off_exponentially_and_caps(self) -> None:
        assert retry_delay(1, base=1.0, maximum=10.0, jitter=False) == 1.0
        assert retry_delay(2, base=1.0, maximum=10.0, jitter=False) == 2.0
        assert retry_delay(5, base=1.0, maximum=10.0, jitter=False) == 10.0
        assert retry_delay(1, base=1.0, maximum=10.0, retry_after=0.2) == 0.2


class TestMetrics:
    async def test_counts_requests_hosts_and_bytes(self, fetcher_factory) -> None:
        fetcher, _ = await fetcher_factory({
            "a.example.com": html("aaaa"),
            "b.example.com": text("bbbb"),
        })
        await fetcher.fetch_raw("https://a.example.com/1")
        await fetcher.fetch_raw("https://a.example.com/2")
        await fetcher.fetch_raw("https://b.example.com/1")
        assert fetcher.request_count == 3
        assert fetcher.hosts_contacted == {"a.example.com", "b.example.com"}
        assert fetcher.bytes_read == 12
