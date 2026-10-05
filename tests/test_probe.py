"""The public-page probe detector — every branch, including the ones that say "unknown"."""

from __future__ import annotations

import pytest

from d3ta1l3r.core.robots import RobotsPolicy
from d3ta1l3r.errors import ConfigError
from d3ta1l3r.models import Confidence, ScanStatus, ScanTarget, SourceKind
from d3ta1l3r.sources.probe import SiteSpec, UsernameProbeSource, load_site_specs, specs_from_dicts
from tests.conftest import html, make_config


def spec(**overrides) -> SiteSpec:
    """A valid spec by default; override only what the test is about."""
    base: dict = {
        "id": "demo_site",
        "name": "Demo Site",
        "url": "https://demo.example.com/{username}",
        "category": "demo",
        "detector": "marker",
        "found_marker": "profile-view",
    }
    if overrides.get("detector") == "status":
        # Status-only probes must not claim more than medium confidence.
        base["confidence_found"] = Confidence.MEDIUM
    base.update(overrides)
    return SiteSpec(**base)


class TestSiteSpecValidation:
    def test_requires_a_placeholder(self) -> None:
        with pytest.raises(ConfigError, match="placeholder"):
            spec(url="https://demo.example.com/profile")

    def test_marker_detector_needs_a_marker(self) -> None:
        with pytest.raises(ConfigError):
            spec(detector="marker", found_marker=None, not_found_marker=None)

    def test_status_detector_cannot_claim_high_confidence(self) -> None:
        """A status-code guess must never be dressed up as a strong signal."""
        with pytest.raises(ConfigError, match="confidence"):
            spec(detector="status", confidence_found=Confidence.HIGH)
        assert spec(detector="status", confidence_found=Confidence.MEDIUM)

    def test_absence_detector_needs_a_not_found_phrase(self) -> None:
        with pytest.raises(ConfigError):
            spec(detector="absence")

    def test_unknown_fields_are_rejected(self) -> None:
        with pytest.raises(ConfigError, match="unknown field"):
            specs_from_dicts([{
                "id": "x", "name": "X", "url": "https://x.com/{username}",
                "category": "demo", "detecotr": "status",  # typo on purpose
            }])

    def test_duplicate_ids_are_rejected(self) -> None:
        row = {
            "id": "dup", "name": "D", "url": "https://d.com/{username}", "category": "demo",
            "detector": "status", "confidence_found": "medium",
        }
        with pytest.raises(ConfigError, match="duplicate"):
            specs_from_dicts([row, dict(row)])

    def test_shipped_database_is_valid_and_sane(self) -> None:
        specs = load_site_specs(include_disabled=True)
        assert len(specs) >= 40, "coverage regressed"
        assert len({s.id for s in specs}) == len(specs)
        enabled = [s for s in specs if s.enabled_by_default]
        assert len(enabled) >= 25
        for item in specs:
            assert item.kind is SourceKind.USERNAME
            assert item.category
            if not item.enabled_by_default:
                assert item.notes, f"{item.id} is disabled but does not say why"


class TestDetectorBranches:
    async def test_status_detector_reports_a_hit_with_medium_confidence(
        self, fetcher_factory
    ) -> None:
        fetcher, _ = await fetcher_factory({"demo.example.com": html("<html>hi</html>")})
        source = UsernameProbeSource(
            spec(detector="status", confidence_found=Confidence.MEDIUM)
        ).bind(fetcher)
        outcome = await source.execute(ScanTarget.create(username="alice"))
        assert outcome.status is ScanStatus.FOUND
        assert outcome.findings[0].confidence is Confidence.MEDIUM
        assert "verify by hand" in outcome.findings[0].evidence

    async def test_404_means_absent(self, fetcher_factory) -> None:
        fetcher, _ = await fetcher_factory({"demo.example.com": 404})
        outcome = await UsernameProbeSource(spec(detector="status")).bind(fetcher).execute(
            ScanTarget.create(username="alice")
        )
        assert outcome.status is ScanStatus.NOT_FOUND
        assert outcome.http_status == 404
        assert outcome.findings == []

    async def test_absence_detector_flips_on_the_site_phrase(self, fetcher_factory) -> None:
        site = spec(detector="absence", not_found_marker="The specified profile could not be found.")
        fetcher, _ = await fetcher_factory({
            "demo.example.com": html("<html>The specified profile could not be found.</html>"),
        })
        outcome = await UsernameProbeSource(site).bind(fetcher).execute(
            ScanTarget.create(username="alice")
        )
        assert outcome.status is ScanStatus.NOT_FOUND

        fetcher2, _ = await fetcher_factory({"demo.example.com": html("<html>Alice profile</html>")})
        outcome2 = await UsernameProbeSource(site).bind(fetcher2).execute(
            ScanTarget.create(username="alice")
        )
        assert outcome2.status is ScanStatus.FOUND
        assert outcome2.findings[0].confidence is Confidence.HIGH

    async def test_marker_detector_needs_the_found_phrase(self, fetcher_factory) -> None:
        site = spec(detector="marker", found_marker="data-profile-view", not_found_marker="nope")
        fetcher, _ = await fetcher_factory({"demo.example.com": html("<html>data-profile-view</html>")})
        outcome = await UsernameProbeSource(site).bind(fetcher).execute(
            ScanTarget.create(username="alice")
        )
        assert outcome.status is ScanStatus.FOUND

    async def test_not_found_marker_wins_over_found_marker(self, fetcher_factory) -> None:
        """Conservative ordering: an 'absent' phrase anywhere means absent."""
        site = spec(detector="marker", found_marker="profile-view", not_found_marker="no such user")
        fetcher, _ = await fetcher_factory({
            "demo.example.com": html("<html>profile-view ... no such user</html>"),
        })
        outcome = await UsernameProbeSource(site).bind(fetcher).execute(
            ScanTarget.create(username="alice")
        )
        assert outcome.status is ScanStatus.NOT_FOUND

    async def test_unmatched_signatures_become_an_error_not_a_guess(
        self, fetcher_factory
    ) -> None:
        site = spec(detector="marker", found_marker="expected-marker")
        fetcher, _ = await fetcher_factory({"demo.example.com": html("<html>redesigned page</html>")})
        outcome = await UsernameProbeSource(site).bind(fetcher).execute(
            ScanTarget.create(username="alice")
        )
        assert outcome.status is ScanStatus.ERROR
        assert "ambiguous" in (outcome.error or "")
        assert "calibrate" in (outcome.error or "")

    @pytest.mark.parametrize("status,expected", [
        (401, ScanStatus.BLOCKED),
        (403, ScanStatus.BLOCKED),
        (429, ScanStatus.SKIPPED_RATE_LIMITED),
        (500, ScanStatus.ERROR),
        (503, ScanStatus.ERROR),
    ])
    async def test_http_states_map_to_honest_statuses(
        self, fetcher_factory, status: int, expected: ScanStatus
    ) -> None:
        fetcher, _ = await fetcher_factory({"demo.example.com": status})
        outcome = await UsernameProbeSource(spec(detector="status")).bind(fetcher).execute(
            ScanTarget.create(username="alice")
        )
        assert outcome.status is expected
        assert outcome.status is not ScanStatus.NOT_FOUND

    async def test_sign_in_wall_is_blocked_never_absent(self, fetcher_factory) -> None:
        fetcher, _ = await fetcher_factory({
            "demo.example.com": lambda request: _redirect(request, "https://demo.example.com/accounts/login"),
        })
        site = spec(detector="absence", not_found_marker="no such user",
                    login_redirect_markers=["/accounts/login"])
        outcome = await UsernameProbeSource(site).bind(fetcher).execute(
            ScanTarget.create(username="alice")
        )
        assert outcome.status is ScanStatus.BLOCKED
        assert "sign-in" in (outcome.error or "")

    async def test_absent_redirect_is_not_found(self, fetcher_factory) -> None:
        fetcher, _ = await fetcher_factory({
            "demo.example.com": lambda request: _redirect(request, "https://demo.example.com/404"),
        })
        site = spec(detector="status", absent_redirect_markers=["/404"])
        outcome = await UsernameProbeSource(site).bind(fetcher).execute(
            ScanTarget.create(username="alice")
        )
        assert outcome.status is ScanStatus.NOT_FOUND

    async def test_robots_disallow_is_reported_as_a_skip(self, fetcher_factory) -> None:
        fetcher, _ = await fetcher_factory(
            {"demo.example.com": html("<html>profile</html>")},
            robots_status=200,
            robots_body="User-agent: *\nDisallow: /\n",
        )
        fetcher.robots = RobotsPolicy(fetcher)
        outcome = await UsernameProbeSource(spec(detector="status")).bind(fetcher).execute(
            ScanTarget.create(username="alice")
        )
        assert outcome.status is ScanStatus.SKIPPED_ROBOTS
        assert "robots" in (outcome.skipped_reason or "").lower()

    async def test_missing_identifier_kind_is_skipped_not_queried(self, fetcher_factory) -> None:
        fetcher, table = await fetcher_factory({"demo.example.com": html("x")})
        source = UsernameProbeSource(spec(detector="status")).bind(fetcher)
        outcome = await source.execute(ScanTarget.create(email="a@b.com"))
        assert outcome.status is ScanStatus.SKIPPED_NO_INPUT
        assert table.calls == []

    async def test_identifier_is_url_encoded_into_the_probe(self, fetcher_factory) -> None:
        fetcher, table = await fetcher_factory({"demo.example.com": 404})
        source = UsernameProbeSource(spec(detector="status")).bind(fetcher)
        await source.execute(ScanTarget.create(username="alice"))
        assert "demo.example.com/alice" in table.calls[0]
        assert source.query_url("alice").endswith("/alice")


def _redirect(request, location: str):
    import httpx

    return httpx.Response(302, headers={"location": location}, request=request)


_ = make_config  # imported for symmetry with other test modules
