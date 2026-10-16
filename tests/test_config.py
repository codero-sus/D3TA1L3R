"""Configuration: impossible values are rejected before a request is ever made.

The point of validating here rather than at the network layer is that a bad
setting should be a clear message at startup, not a confusing failure halfway
through a scan — or worse, a silently degraded one.
"""

from __future__ import annotations

import pytest

from d3ta1l3r.config import (
    MAX_MODE,
    MIN_MODE,
    RateLimitConfig,
    ScanConfig,
)
from d3ta1l3r.errors import ConfigError


class TestRateLimitValidation:
    @pytest.mark.parametrize(
        "field,bad",
        [
            ("per_host_rps", 0),
            ("per_host_rps", -1),
            ("per_host_burst", 0),
            ("global_concurrency", 0),
            ("max_retries", -1),
            ("backoff_base", -0.5),
            ("backoff_max", -1),
        ],
    )
    def test_impossible_values_are_rejected(self, field: str, bad: float) -> None:
        with pytest.raises(ConfigError, match=r"(?i)rate|backoff|concurrency|burst|retries"):
            RateLimitConfig(**{field: bad}).validate()

    def test_a_sane_default_passes(self) -> None:
        RateLimitConfig().validate()


class TestScanConfigValidation:
    def test_the_default_is_valid(self) -> None:
        ScanConfig().validate()

    @pytest.mark.parametrize(
        "field,bad",
        [
            ("timeout", 0),
            ("timeout", -1),
            ("connect_timeout", 0),
            ("max_redirects", -1),
            ("cache_ttl", -1),
            ("max_sites", 0),
        ],
    )
    def test_numeric_bounds_are_enforced(self, field: str, bad: int) -> None:
        with pytest.raises(ConfigError):
            ScanConfig(**{field: bad}).validate()

    def test_a_connect_timeout_longer_than_the_timeout_is_refused(self) -> None:
        """Otherwise every request would time out while connecting."""
        with pytest.raises(ConfigError, match=r"(?i)nonsensical|timeout"):
            ScanConfig(timeout=1.0, connect_timeout=100.0).validate()

    def test_a_body_cap_below_a_kilobyte_is_refused(self) -> None:
        with pytest.raises(ConfigError, match=r"(?i)max_body_bytes"):
            ScanConfig(max_body_bytes=10).validate()

    def test_an_empty_user_agent_is_refused(self) -> None:
        """The User-Agent is how a site owner contacts you; it cannot be blank."""
        with pytest.raises(ConfigError, match=r"(?i)user_agent"):
            ScanConfig(user_agent="   ").validate()

    def test_an_unknown_browser_profile_is_refused(self) -> None:
        with pytest.raises(ConfigError):
            ScanConfig(browser_profile="not-a-browser").validate()

    def test_a_contact_email_must_look_like_an_address(self) -> None:
        with pytest.raises(ConfigError, match=r"(?i)contact_email"):
            ScanConfig(contact_email="not-an-address").validate()
        ScanConfig(contact_email="me@example.com").validate()

    @pytest.mark.parametrize("mode", [MIN_MODE - 1, MAX_MODE + 1, 0, 99])
    def test_mode_is_bounded(self, mode: int) -> None:
        with pytest.raises(ConfigError, match=r"(?i)mode"):
            ScanConfig(mode=mode).validate()

    @pytest.mark.parametrize("mode", [MIN_MODE, 3, MAX_MODE])
    def test_modes_in_range_are_accepted(self, mode: int) -> None:
        ScanConfig(mode=mode).validate()

    def test_an_unknown_identifier_kind_is_refused(self) -> None:
        with pytest.raises(ConfigError, match=r"(?i)unknown kind"):
            ScanConfig(kinds=frozenset({"username", "blood_type"})).validate()

    def test_a_source_cannot_be_both_enabled_and_disabled(self) -> None:
        with pytest.raises(ConfigError, match=r"(?i)both enabled and disabled"):
            ScanConfig(
                enabled_sources=frozenset({"github_user"}),
                disabled_sources=frozenset({"github_user"}),
            ).validate()

    def test_disjoint_enable_and_disable_sets_are_fine(self) -> None:
        ScanConfig(
            enabled_sources=frozenset({"github_user"}),
            disabled_sources=frozenset({"gitlab_user"}),
        ).validate()

    def test_the_rate_limit_is_validated_too(self) -> None:
        """A nested config must not be able to sneak through unchecked."""
        with pytest.raises(ConfigError):
            ScanConfig(rate=RateLimitConfig(per_host_rps=0)).validate()


class TestFromEnv:
    """Environment overrides, including the ones that are easy to typo."""

    def test_numeric_settings_are_read(self, monkeypatch) -> None:
        monkeypatch.setenv("D3TA1L3R_TIMEOUT", "7.5")
        monkeypatch.setenv("D3TA1L3R_RPS", "2")
        monkeypatch.setenv("D3TA1L3R_CONCURRENCY", "3")
        config = ScanConfig.from_env()
        assert config.timeout == 7.5
        assert config.rate.per_host_rps == 2
        assert config.rate.global_concurrency == 3

    def test_a_cache_dir_implies_using_the_cache(self, monkeypatch, tmp_path) -> None:
        monkeypatch.setenv("D3TA1L3R_CACHE_DIR", str(tmp_path))
        config = ScanConfig.from_env()
        assert config.cache_dir == tmp_path
        assert config.use_cache is True

    @pytest.mark.parametrize("raw", ["0", "false", "no", "off", "FALSE"])
    def test_robots_can_be_turned_off(self, monkeypatch, raw: str) -> None:
        monkeypatch.setenv("D3TA1L3R_ROBOTS", raw)
        assert ScanConfig.from_env().respect_robots is False

    @pytest.mark.parametrize("raw", ["1", "true", "yes", "on"])
    def test_robots_stays_on_for_anything_else(self, monkeypatch, raw: str) -> None:
        monkeypatch.setenv("D3TA1L3R_ROBOTS", raw)
        assert ScanConfig.from_env().respect_robots is True

    def test_an_empty_browser_value_means_off(self, monkeypatch) -> None:
        monkeypatch.setenv("D3TA1L3R_BROWSER", "   ")
        assert ScanConfig.from_env().browser_profile == "off"

    def test_the_contact_address_is_read(self, monkeypatch) -> None:
        monkeypatch.setenv("D3TA1L3R_UA_EMAIL", "me@example.com")
        assert ScanConfig.from_env().contact_email == "me@example.com"

    def test_explicit_overrides_win_over_the_environment(self, monkeypatch) -> None:
        monkeypatch.setenv("D3TA1L3R_TIMEOUT", "99")
        assert ScanConfig.from_env(timeout=3.0).timeout == 3.0

    @pytest.mark.parametrize("name,raw", [
        ("D3TA1L3R_TIMEOUT", "not-a-number"),
        ("D3TA1L3R_RPS", "also-not"),
        ("D3TA1L3R_CONCURRENCY", "3.5"),
    ])
    def test_a_malformed_number_is_a_config_error(self, monkeypatch, name: str, raw: str) -> None:
        """A typo'd env var should name itself, not fail deep in the fetcher."""
        monkeypatch.setenv(name, raw)
        with pytest.raises(ConfigError, match=name):
            ScanConfig.from_env()

    def test_no_environment_at_all_gives_the_defaults(self, monkeypatch) -> None:
        for name in ("D3TA1L3R_TIMEOUT", "D3TA1L3R_RPS", "D3TA1L3R_CONCURRENCY",
                     "D3TA1L3R_CACHE_DIR", "D3TA1L3R_ROBOTS", "D3TA1L3R_BROWSER",
                     "D3TA1L3R_UA_EMAIL"):
            monkeypatch.delenv(name, raising=False)
        config = ScanConfig.from_env()
        assert config == ScanConfig()
