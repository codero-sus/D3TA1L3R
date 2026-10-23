"""Not-found page detection, and browser-shaped requests.

This is the part of the tool that decides "this account is not yours *because it
is not there*". Getting it wrong in either direction is costly: a missed phrase
turns every unknown profile into a finding, and an over-eager phrase turns a live
account into a false negative. So the tests pin the phrasing that must be caught,
the phrasing that must stay a *gap* because it is genuinely ambiguous, and the
guarantee that a bot check or a private profile never reads as "not found".
"""

from __future__ import annotations

import httpx
import pytest

from d3ta1l3r.config import ScanConfig
from d3ta1l3r.core.browser import BROWSER_PROFILES, resolve_profile
from d3ta1l3r.errors import ConfigError
from d3ta1l3r.models import ScanStatus, ScanTarget, SourceKind
from d3ta1l3r.sources.notfound import (
    AMBIGUOUS_PHRASES,
    GENERIC_NOT_FOUND_PHRASES,
    classify_page,
    find_phrase,
    normalise_text,
    phrase_registry,
)
from d3ta1l3r.sources.probe import SiteSpec, UsernameProbeSource
from tests.conftest import make_config


def html(body: str, status: int = 200) -> tuple[int, str, dict[str, str]]:
    """A route-table spec: (status, body, headers) — see tests/conftest.py."""
    return status, body, {"content-type": "text/html; charset=utf-8"}


class TestPhraseDetection:
    @pytest.mark.parametrize(
        "body",
        [
            "<h1>User Not Found</h1>",
            "<div>user not found</div>",
            "<p>USER NOT FOUND</p>",
            "<h2>Sorry, no such user</h2>",
            "<p>This account doesn't exist</p>",
            "<p>This account doesnt exist</p>",
            "<p>Couldn't find that user</p>",
            "<p>We couldn't find this profile</p>",
            "<p>Nothing to see here — profile not found</p>",
            "<p>Sorry, nobody on Reddit goes by that name</p>",
            "<title>Page not found · Example</title>",
            "<p>The specified profile could not be found.</p>",
        ],
    )
    def test_common_not_found_wording_is_recognised(self, body: str) -> None:
        verdict = classify_page(body)
        assert verdict is not None, body
        assert verdict.kind == "absent", (body, verdict)

    def test_markup_and_whitespace_do_not_hide_a_phrase(self) -> None:
        body = "<div class='empty'><span>User</span>\n\n   <span>Not</span>  <b>Found</b></div>"
        verdict = classify_page(body)
        assert verdict is not None and verdict.certain

    def test_a_script_blob_is_not_scanned_for_phrases(self) -> None:
        """A not-found string in a template or JSON payload is not a missing profile."""
        body = (
            "<html><body><h1>alice_dev</h1>"
            "<script>var i18n = {error: 'user not found'};</script>"
            "</body></html>"
        )
        assert classify_page(body) is None

    @pytest.mark.parametrize(
        "body",
        [
            "<p>This account is private</p>",
            "<p>Account suspended</p>",
            "<p>Checking your browser before accessing…</p>",
            "<p>Access denied</p>",
            "<p>Are you a robot?</p>",
            "<p>Sorry, this content isn't available right now</p>",
        ],
    )
    def test_ambiguous_pages_are_gaps_not_answers(self, body: str) -> None:
        verdict = classify_page(body)
        assert verdict is not None, body
        assert verdict.kind == "ambiguous" and not verdict.certain
        assert "gap, not an answer" in verdict.evidence

    def test_a_sites_own_marker_is_preferred_over_the_generic_table(self) -> None:
        body = "<p>No such user, and also page not found</p>"
        verdict = classify_page(body, markers=("no such user",))
        assert verdict is not None
        assert "site's own not-found signature" in verdict.evidence

    def test_a_live_profile_with_no_phrase_gets_no_verdict(self) -> None:
        body = "<html><body><h1>alice_dev</h1><p>Student. Loves chess.</p></body></html>"
        assert classify_page(body) is None

    def test_a_page_that_merely_mentions_not_found_in_prose_is_ignored(self) -> None:
        """Phrases must appear, not be *about* the topic, hence the narrow list."""
        body = "<p>My previous username is gone. Read: why your profile page can vanish.</p>"
        assert classify_page(body) is None

    def test_the_longest_matching_phrase_wins(self) -> None:
        haystack = normalise_text("<p>the specified profile could not be found</p>")
        assert find_phrase(haystack, GENERIC_NOT_FOUND_PHRASES) == (
            "the specified profile could not be found"
        )

    def test_the_registry_is_small_enough_to_audit(self) -> None:
        registry = phrase_registry()
        assert registry["absent"] == list(GENERIC_NOT_FOUND_PHRASES)
        assert len(GENERIC_NOT_FOUND_PHRASES) < 60
        assert len(AMBIGUOUS_PHRASES) < 40
        for phrase in GENERIC_NOT_FOUND_PHRASES + AMBIGUOUS_PHRASES:
            assert phrase == phrase.lower(), phrase
            assert phrase.strip() == phrase, phrase


class TestProbeIntegration:
    """The detector has to change what the probe reports, not just what it computes."""

    def _spec(self, **overrides: object) -> SiteSpec:
        base = {
            "id": "example_user",
            "name": "Example",
            "url": "https://example.com/{username}",
            "category": "social",
            "detector": "absence",
            "not_found_marker": "no such profile exists here",
            "confidence_found": "medium",
        }
        base.update(overrides)
        return SiteSpec.from_dict(base)

    async def test_a_generic_not_found_page_is_not_found(self, fetcher_factory) -> None:
        fetcher, _ = await fetcher_factory(
            {"https://example.com/alice": html("<h1>User Not Found</h1>")}
        )
        source = UsernameProbeSource(self._spec(), fetcher)
        outcome = await source.run("alice", ScanTarget(username="alice"))
        assert outcome.status is ScanStatus.NOT_FOUND
        assert "user not found" in (outcome.error or "").lower()
        assert outcome.findings == []

    async def test_the_sites_own_marker_still_wins(self, fetcher_factory) -> None:
        fetcher, _ = await fetcher_factory(
            {
                "https://example.com/alice": html(
                    "<p>User Not Found</p><p>No such profile exists here</p>"
                )
            }
        )
        source = UsernameProbeSource(self._spec(), fetcher)
        outcome = await source.run("alice", ScanTarget(username="alice"))
        assert outcome.status is ScanStatus.NOT_FOUND
        assert "not-found signature" in (outcome.error or "")

    async def test_an_ambiguous_page_is_a_gap_not_a_hit_or_a_miss(
        self, fetcher_factory
    ) -> None:
        """Neither "found" nor "not found": the honest answer is "I could not tell"."""
        fetcher, _ = await fetcher_factory(
            {"https://example.com/alice": html("<p>This account is private</p>")}
        )
        source = UsernameProbeSource(self._spec(), fetcher)
        outcome = await source.run("alice", ScanTarget(username="alice"))
        assert outcome.status is ScanStatus.BLOCKED
        assert outcome.skipped_reason == "ambiguous page"
        assert outcome.findings == []

    async def test_a_bot_check_is_a_gap_with_the_phrase_quoted(self, fetcher_factory) -> None:
        fetcher, _ = await fetcher_factory(
            {"https://example.com/alice": html("<p>Checking your browser…</p>")}
        )
        source = UsernameProbeSource(self._spec(), fetcher)
        outcome = await source.run("alice", ScanTarget(username="alice"))
        assert outcome.status is ScanStatus.BLOCKED
        assert "checking your browser" in (outcome.error or "").lower()

    async def test_a_live_profile_is_still_a_hit(self, fetcher_factory) -> None:
        fetcher, _ = await fetcher_factory(
            {"https://example.com/alice": html("<h1>alice</h1><p>Hello!</p>")}
        )
        source = UsernameProbeSource(self._spec(), fetcher)
        outcome = await source.run("alice", ScanTarget(username="alice"))
        assert outcome.status is ScanStatus.FOUND
        assert outcome.findings and outcome.findings[0].kind is SourceKind.USERNAME

    async def test_a_status_only_spec_is_unaffected_by_the_registry(
        self, fetcher_factory
    ) -> None:
        """A 404 stays a 404; the phrase table must not soften it into a gap."""
        fetcher, _ = await fetcher_factory(
            {"https://example.com/alice": html("<h1>what?</h1>", status=404)}
        )
        spec = self._spec(detector="status", not_found_marker=None)
        source = UsernameProbeSource(spec, fetcher)
        outcome = await source.run("alice", ScanTarget(username="alice"))
        assert outcome.status is ScanStatus.NOT_FOUND


class TestBrowserHeaders:
    def test_profiles_are_named_and_resolvable(self) -> None:
        for name in BROWSER_PROFILES:
            assert resolve_profile(name) is BROWSER_PROFILES[name]
        assert resolve_profile("off") is None
        assert resolve_profile(True) is BROWSER_PROFILES["chrome"]
        assert resolve_profile("default") is BROWSER_PROFILES["chrome"]

    def test_an_unknown_profile_is_a_config_error(self) -> None:
        with pytest.raises(ConfigError):
            resolve_profile("netscape")
        with pytest.raises(ConfigError):
            ScanConfig(browser_profile="netscape")

    def test_a_navigation_request_looks_like_a_navigation(self) -> None:
        headers = resolve_profile("chrome").headers(navigate=True, contact="", url="https://x.test/")
        assert headers["Sec-Fetch-Mode"] == "navigate"
        assert headers["Sec-Fetch-Dest"] == "document"
        assert headers["Upgrade-Insecure-Requests"] == "1"
        assert headers["User-Agent"].startswith("Mozilla/5.0")
        assert "From" not in headers, "no contact address configured, no From header"

    def test_a_subresource_request_drops_the_navigation_hints(self) -> None:
        headers = resolve_profile("firefox").headers(navigate=False, referer="https://x.test/a")
        assert "Sec-Fetch-Mode" not in headers or headers["Sec-Fetch-Mode"] == "no-cors"
        assert "Upgrade-Insecure-Requests" not in headers
        assert headers["Referer"] == "https://x.test/a"

    def test_the_contact_address_rides_along_even_under_a_browser_ua(self) -> None:
        """The whole point: the tool is not hiding, it is just being let in."""
        headers = resolve_profile("chrome").headers(contact="me@example.com")
        assert headers["From"] == "me@example.com"

    async def test_the_fetcher_sends_the_profile_when_configured(self) -> None:
        seen: list[dict[str, str]] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append({k.lower(): v for k, v in request.headers.items()})
            return httpx.Response(200, text="<p>hi</p>", request=request)

        from d3ta1l3r.core.http import Fetcher

        config = make_config(browser_profile="chrome", contact_email="me@example.com")
        async with Fetcher(config, transport=httpx.MockTransport(handler)) as fetcher:
            await fetcher.fetch("https://example.com/alice")
            await fetcher.fetch("https://example.com/bob")

        first, second = seen
        assert first["user-agent"].startswith("Mozilla/5.0")
        assert first["from"] == "me@example.com"
        assert first["sec-fetch-mode"] == "navigate"
        assert "referer" not in first, "the first request to a host has nothing to refer to"
        # The second request to the same host is shaped like a click-through.
        assert second["referer"] == "https://example.com/alice"
        assert second["sec-fetch-mode"] == "no-cors"

    async def test_the_default_identifies_the_tool(self) -> None:
        seen: list[dict[str, str]] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append({k.lower(): v for k, v in request.headers.items()})
            return httpx.Response(200, text="ok", request=request)

        from d3ta1l3r.core.http import Fetcher

        async with Fetcher(make_config(), transport=httpx.MockTransport(handler)) as fetcher:
            await fetcher.fetch("https://example.com/alice")
        assert seen[0]["user-agent"].startswith("D3TA1L3R/")
        assert "sec-fetch-mode" not in seen[0]

    def test_the_profile_is_not_randomised_between_calls(self) -> None:
        profile = resolve_profile("safari")
        assert profile.headers()["User-Agent"] == profile.headers()["User-Agent"]
        assert profile.user_agent in profile.headers()["User-Agent"]
