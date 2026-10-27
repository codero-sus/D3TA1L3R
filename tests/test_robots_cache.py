"""The robots.txt cache that survives between runs, and what it must not do.

Caching a policy file is a correctness question, not just a speed one. A cache
that remembers "allowed" when the site said "disallowed" would make the tool
less compliant with every run, which is the opposite of what robots.txt is for.
These tests pin the direction of the errors: a cache miss costs a request, a
wrong cache entry costs compliance.
"""

from __future__ import annotations

import asyncio
import time
from pathlib import Path

import pytest

from d3ta1l3r.config import ScanConfig, default_robots_cache_dir
from d3ta1l3r.core.robots_cache import DEFAULT_ROBOTS_TTL, CachedRobots, RobotsDiskCache


class TestDiskCacheBasics:
    def test_a_stored_entry_comes_back(self, tmp_path: Path) -> None:
        cache = RobotsDiskCache(tmp_path)
        cache.put("https://example.com", 200, "User-agent: *\nDisallow: /private")
        entry = cache.get("https://example.com")
        assert entry is not None
        assert entry.status == 200
        assert "Disallow: /private" in entry.text

    def test_an_empty_cache_misses(self, tmp_path: Path) -> None:
        assert RobotsDiskCache(tmp_path).get("https://example.com") is None

    def test_a_different_origin_misses(self, tmp_path: Path) -> None:
        cache = RobotsDiskCache(tmp_path)
        cache.put("https://example.com", 200, "x")
        assert cache.get("https://other.example") is None

    def test_an_expired_entry_misses(self, tmp_path: Path) -> None:
        cache = RobotsDiskCache(tmp_path, ttl=0.0)
        cache.put("https://example.com", 200, "x")
        assert cache.get("https://example.com") is None

    def test_a_stale_schema_is_rejected(self, tmp_path: Path) -> None:
        """An old cache format must be ignored, never guessed at."""
        cache = RobotsDiskCache(tmp_path)
        cache.put("https://example.com", 200, "x")
        path = cache._path_for("https://example.com")
        payload = path.read_text().replace('"schema": 1', '"schema": 99')
        path.write_text(payload)
        assert cache.get("https://example.com") is None

    def test_corrupt_json_is_a_miss_not_a_crash(self, tmp_path: Path) -> None:
        cache = RobotsDiskCache(tmp_path)
        path = cache._path_for("https://example.com")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{not json")
        assert cache.get("https://example.com") is None

    def test_hits_and_misses_are_counted(self, tmp_path: Path) -> None:
        cache = RobotsDiskCache(tmp_path)
        cache.put("https://example.com", 200, "x")
        cache.get("https://example.com")
        cache.get("https://missing.example")
        assert cache.stats()["hits"] == 1 and cache.stats()["misses"] == 1

    def test_clear_removes_entries(self, tmp_path: Path) -> None:
        cache = RobotsDiskCache(tmp_path)
        cache.put("https://example.com", 200, "x")
        assert cache.clear() >= 1
        assert cache.get("https://example.com") is None

    def test_the_directory_is_created_lazily(self, tmp_path: Path) -> None:
        target = tmp_path / "nested" / "robots"
        cache = RobotsDiskCache(target)
        cache.put("https://example.com", 200, "x")
        assert target.is_dir()


class TestSecurityDirection:
    """Which way the cache may err."""

    @pytest.mark.parametrize("status", [401, 403])
    def test_a_refusal_is_remembered_as_a_refusal(self, tmp_path: Path, status: int) -> None:
        """A 401/403 means disallowed. The cache must not soften that."""
        cache = RobotsDiskCache(tmp_path)
        cache.put("https://example.com", status, "")
        assert cache.get("https://example.com").status == status

    def test_a_missing_robots_file_is_remembered_as_allowed(self, tmp_path: Path) -> None:
        cache = RobotsDiskCache(tmp_path)
        cache.put("https://example.com", 404, "")
        assert cache.get("https://example.com").status == 404

    def test_the_default_ttl_follows_the_rfc(self) -> None:
        """RFC 9309 recommends refreshing robots.txt at most once a day."""
        assert DEFAULT_ROBOTS_TTL == 86_400.0


class TestFreshness:
    def test_is_fresh_respects_the_ttl(self) -> None:
        now = time.time()
        assert CachedRobots("o", 200, "", now).is_fresh(60.0) is True
        assert CachedRobots("o", 200, "", now - 120).is_fresh(60.0) is False


class TestConfigWiring:
    def test_a_default_directory_exists(self) -> None:
        path = default_robots_cache_dir()
        assert path is None or isinstance(path, Path)

    def test_the_cache_is_on_by_default(self) -> None:
        assert ScanConfig().robots_cache_enabled is True

    def test_robots_caching_is_independent_of_response_caching(self) -> None:
        """Response caching changes results; robots caching does not.

        They must not share a switch, or turning on a speed optimisation would
        silently start reporting stale findings.
        """
        assert ScanConfig().use_cache is False
        assert ScanConfig().robots_cache_enabled is True

    def test_it_can_be_disabled(self) -> None:
        cfg = ScanConfig(robots_cache_enabled=False)
        assert cfg.robots_cache_enabled is False


class TestSingleFlight:
    """Concurrent sources on one host must fetch robots.txt once."""

    def test_concurrent_checks_share_one_fetch(self) -> None:

        from d3ta1l3r.core.robots import RobotsPolicy

        fetches: list[str] = []

        class FakeFetcher:
            config = ScanConfig()

            async def fetch_raw(self, url, **kwargs):
                fetches.append(url)
                await asyncio.sleep(0.05)

                class R:
                    status = 404
                    text = ""

                return R()

        policy = RobotsPolicy(FakeFetcher())

        async def burst():
            await asyncio.gather(
                *[policy._rules_for(f"https://example.com/{i}") for i in range(10)]
            )

        asyncio.run(burst())
        assert len(fetches) == 1, f"10 concurrent sources, {len(fetches)} robots fetches"
