"""The cross-run host cache, and the one direction it is allowed to err in.

This cache sits next to a security check, so the tests that matter are not about
speed. They are about proving that remembering something can never make the
SSRF guard more permissive than asking again would. A cache that turns "I could
not tell" into "yes" would be a vulnerability that only appears on the second
run — the worst possible place for one.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from d3ta1l3r.config import ScanConfig, default_host_cache_path
from d3ta1l3r.core.host_cache import DEFAULT_HOST_TTL, HostValidationStore
from d3ta1l3r.core.hostguard import HostGuard
from d3ta1l3r.errors import ForbiddenTargetError


class TestStoreBasics:
    def test_a_remembered_host_is_known(self, tmp_path: Path) -> None:
        store = HostValidationStore(tmp_path / "hosts.json")
        store.remember_public("example.com")
        assert store.is_known_public("example.com") is True

    def test_an_unknown_host_is_not(self, tmp_path: Path) -> None:
        assert HostValidationStore(tmp_path / "hosts.json").is_known_public("example.com") is False

    def test_an_expired_entry_is_a_miss(self, tmp_path: Path) -> None:
        store = HostValidationStore(tmp_path / "hosts.json", ttl=0.0)
        store.remember_public("example.com")
        assert store.is_known_public("example.com") is False

    def test_it_survives_a_new_instance(self, tmp_path: Path) -> None:
        """The whole point: another process, another run."""
        first = HostValidationStore(tmp_path / "hosts.json")
        first.remember_public("example.com")
        first.flush()
        assert HostValidationStore(tmp_path / "hosts.json").is_known_public("example.com") is True

    def test_flush_writes_to_disk(self, tmp_path: Path) -> None:
        path = tmp_path / "hosts.json"
        store = HostValidationStore(path)
        store.remember_public("example.com")
        store.flush()
        assert path.exists()

    def test_clear_forgets_everything(self, tmp_path: Path) -> None:
        store = HostValidationStore(tmp_path / "hosts.json")
        store.remember_public("example.com")
        assert store.clear() == 1
        assert store.is_known_public("example.com") is False

    def test_stats_are_counted(self, tmp_path: Path) -> None:
        store = HostValidationStore(tmp_path / "hosts.json")
        store.remember_public("example.com")
        store.is_known_public("example.com")
        store.is_known_public("other.example")
        assert store.stats()["hits"] == 1 and store.stats()["misses"] == 1

    def test_corrupt_json_is_a_miss_not_a_crash(self, tmp_path: Path) -> None:
        path = tmp_path / "hosts.json"
        path.write_text("{not json")
        assert HostValidationStore(path).is_known_public("example.com") is False

    def test_a_stale_schema_is_ignored(self, tmp_path: Path) -> None:
        path = tmp_path / "hosts.json"
        path.write_text('{"schema": 99, "hosts": {"example.com": 1e18}}')
        assert HostValidationStore(path).is_known_public("example.com") is False

    def test_the_default_ttl_is_bounded(self) -> None:
        assert 0 < DEFAULT_HOST_TTL <= 86_400

    def test_a_missing_parent_directory_is_created(self, tmp_path: Path) -> None:
        path = tmp_path / "nested" / "hosts.json"
        store = HostValidationStore(path)
        store.remember_public("example.com")
        store.flush()
        assert path.exists()


class TestOnlyPositiveResultsAreCached:
    """A failed or private resolution must never be remembered."""

    def test_a_failed_resolution_is_not_stored(self, tmp_path: Path) -> None:
        import asyncio

        store = HostValidationStore(tmp_path / "hosts.json")
        guard = HostGuard(resolve=True, resolver=lambda h: False, ttl=0.0, store=store)
        with pytest.raises(ForbiddenTargetError):
            asyncio.run(guard.check("https://example.com/a"))
        store.flush()
        assert store.is_known_public("example.com") is False, (
            "a host that failed to resolve must be re-resolved next run"
        )

    def test_a_successful_resolution_is_stored(self, tmp_path: Path) -> None:
        import asyncio

        store = HostValidationStore(tmp_path / "hosts.json")
        guard = HostGuard(resolve=True, resolver=lambda h: True, ttl=0.0, store=store)
        asyncio.run(guard.check("https://example.com/a"))
        store.flush()
        assert store.is_known_public("example.com") is True

    def test_a_stored_host_still_passes_syntactic_checks(self, tmp_path: Path) -> None:
        """The store answers one question; the rest are re-asked every time."""
        import asyncio

        store = HostValidationStore(tmp_path / "hosts.json")
        store.remember_public("127.0.0.1")
        guard = HostGuard(resolve=True, ttl=60.0, store=store)
        with pytest.raises(ForbiddenTargetError):
            asyncio.run(guard.check("http://127.0.0.1/admin"))

    def test_the_store_cannot_resurrect_a_blocked_suffix(self, tmp_path: Path) -> None:
        import asyncio

        store = HostValidationStore(tmp_path / "hosts.json")
        store.remember_public("mysite.local")
        guard = HostGuard(resolve=True, ttl=60.0, store=store)
        with pytest.raises(ForbiddenTargetError):
            asyncio.run(guard.check("http://mysite.local/x"))


class TestCrossRunSavesALookup:
    def test_the_second_guard_does_not_resolve(self, tmp_path: Path) -> None:
        import asyncio

        path = tmp_path / "hosts.json"
        calls: list[str] = []

        first = HostGuard(resolve=True, resolver=lambda h: calls.append(h) or True,
                          ttl=0.0, store=HostValidationStore(path))
        asyncio.run(first.check("https://example.com/a"))
        first.flush()

        second = HostGuard(resolve=True, resolver=lambda h: calls.append(h) or True,
                           ttl=0.0, store=HostValidationStore(path))
        asyncio.run(second.check("https://example.com/a"))

        assert calls == ["example.com"], "the second run must not resolve again"
        assert second.cross_run_hits == 1


class TestConfigWiring:
    def test_a_default_path_exists(self) -> None:
        path = default_host_cache_path()
        assert path is None or isinstance(path, Path)

    def test_it_is_enabled_by_default(self) -> None:
        assert ScanConfig().host_cache_enabled is True

    def test_it_can_be_disabled(self) -> None:
        assert ScanConfig(host_cache_enabled=False).host_cache_enabled is False

    def test_it_sits_beside_the_robots_cache(self) -> None:
        """One directory for everything the tool remembers between runs."""
        robots = ScanConfig().robots_cache_dir
        hosts = ScanConfig().host_cache_path
        assert robots is not None and hosts is not None
        assert hosts.parent == robots.parent
