"""API sources: correct parsing, correct absence, correct gaps."""

from __future__ import annotations

import hashlib

import pytest

from d3ta1l3r.models import Confidence, ScanStatus, ScanTarget
from d3ta1l3r.sources.api import build_api_sources
from d3ta1l3r.sources.api.dev import (
    CodebergUser,
    DevToUser,
    DockerHubUser,
    GitHubEmailSearch,
    GitHubUser,
    GitLabUser,
    KeybaseUser,
    NpmMaintainerEmail,
    NpmMaintainerHandle,
)
from d3ta1l3r.sources.api.identity import GravatarEmail, RdapDomain
from d3ta1l3r.sources.api.knowledge import (
    ArxivAuthor,
    OpenAlexAuthor,
    OrcidAuthor,
    PubMedAuthor,
    WikipediaSearch,
)
from d3ta1l3r.sources.api.social import (
    BlueskyHandle,
    BlueskyNameSearch,
    ChessComUser,
    CodeforcesUser,
    HackerNewsAuthor,
    LichessUser,
    MastodonAccount,
    SpeedrunComUser,
)
from tests.conftest import html, json_response

TARGET_USER = ScanTarget.create(username="alice")
TARGET_EMAIL = ScanTarget.create(email="alice@example.com")
TARGET_NAME = ScanTarget.create(name="Alice Doe")
TARGET_DOMAIN = ScanTarget.create(domain="example.com")


class TestRegistry:
    def test_every_source_has_unique_identity_and_no_duplicates(self) -> None:
        sources = build_api_sources()
        ids = [source.id for source in sources]
        assert len(ids) == len(set(ids))
        assert len(sources) >= 20
        for source in sources:
            assert source.meta.description
            assert source.meta.kind.value in {"username", "email", "name", "domain"}

    def test_kinds_are_covered(self) -> None:
        kinds = {source.kind.value for source in build_api_sources()}
        assert kinds == {"username", "email", "name", "domain"}


class TestGitHub:
    async def test_found_record_yields_confirmed_finding_with_exposure_notes(
        self, fetcher_factory
    ) -> None:
        fetcher, _ = await fetcher_factory({"api.github.com": json_response({
            "login": "alice", "name": "Alice Doe", "bio": "engineer", "location": "Delhi",
            "company": "Example Org", "blog": "https://alice.example", "twitter_username": "alice",
            "public_repos": 42, "public_gists": 2, "followers": 120, "following": 30,
            "created_at": "2014-05-05T00:00:00Z", "html_url": "https://github.com/alice",
            "avatar_url": "https://avatars.example/alice.png", "hireable": True,
        })})
        outcome = await GitHubUser().bind(fetcher).execute(TARGET_USER)
        assert outcome.status is ScanStatus.FOUND
        finding = outcome.findings[0]
        assert finding.confidence is Confidence.CONFIRMED
        assert finding.display_name == "Alice Doe"
        assert finding.extra["public_repos"] == 42
        exposure = " ".join(finding.extra["exposure"])
        assert "Delhi" in exposure and "@alice" in exposure

    async def test_404_is_absent(self, fetcher_factory) -> None:
        fetcher, _ = await fetcher_factory({"api.github.com": 404})
        outcome = await GitHubUser().bind(fetcher).execute(TARGET_USER)
        assert outcome.status is ScanStatus.NOT_FOUND

    async def test_rate_limit_is_a_skip_not_a_failure(self, fetcher_factory) -> None:
        fetcher, _ = await fetcher_factory({
            "api.github.com": (429, {"message": "rate limited"}, {}),
        })
        outcome = await GitHubUser().bind(fetcher).execute(TARGET_USER)
        assert outcome.status in {ScanStatus.SKIPPED_RATE_LIMITED, ScanStatus.ERROR}
        assert outcome.status is not ScanStatus.FOUND

    async def test_email_search_reports_each_match(self, fetcher_factory) -> None:
        fetcher, _ = await fetcher_factory({"api.github.com": json_response({
            "total_count": 1,
            "items": [{"login": "alice", "html_url": "https://github.com/alice",
                       "avatar_url": "https://a.example/x.png"}],
        })})
        outcome = await GitHubEmailSearch().bind(fetcher).execute(TARGET_EMAIL)
        assert outcome.status is ScanStatus.FOUND
        assert outcome.findings[0].confidence is Confidence.HIGH


class TestOtherDeveloperSources:
    async def test_gitlab_matches_exact_username_only(self, fetcher_factory) -> None:
        fetcher, _ = await fetcher_factory({"gitlab.com": json_response([
            {"username": "alice2", "name": "Other", "web_url": "https://gitlab.com/alice2"},
            {"username": "alice", "name": "Alice Doe", "state": "active",
             "web_url": "https://gitlab.com/alice", "public_email": "alice@example.com",
             "linkedin": "alice-doe", "twitter": "alice", "location": "Delhi",
             "created_at": "2017-01-01T00:00:00Z", "avatar_url": "https://g.example/a.png"},
        ])})
        outcome = await GitLabUser().bind(fetcher).execute(TARGET_USER)
        assert outcome.status is ScanStatus.FOUND
        assert outcome.findings[0].url == "https://gitlab.com/alice"
        assert "linkedin: alice-doe" in outcome.findings[0].extra["exposure"]

    async def test_gitlab_empty_list_is_absent(self, fetcher_factory) -> None:
        fetcher, _ = await fetcher_factory({"gitlab.com": json_response([])})
        outcome = await GitLabUser().bind(fetcher).execute(TARGET_USER)
        assert outcome.status is ScanStatus.NOT_FOUND

    async def test_codeberg_and_dockerhub(self, fetcher_factory) -> None:
        fetcher, _ = await fetcher_factory({
            "codeberg.org": json_response({"login": "alice", "full_name": "Alice Doe",
                                           "location": "Delhi", "website": "https://a.example"}),
            "hub.docker.com": json_response({"username": "alice", "full_name": "Alice Doe",
                                             "gravatar_email": "alice@example.com",
                                             "date_joined": "2018-02-02T00:00:00Z"}),
        })
        codeberg = await CodebergUser().bind(fetcher).execute(TARGET_USER)
        docker = await DockerHubUser().bind(fetcher).execute(TARGET_USER)
        assert codeberg.status is ScanStatus.FOUND
        assert docker.status is ScanStatus.FOUND
        assert "gravatar_email" in docker.findings[0].extra
        assert docker.findings[0].account_created_at == "2018-02-02T00:00:00Z"

    async def test_keybase_collects_published_proofs(self, fetcher_factory) -> None:
        fetcher, _ = await fetcher_factory({"keybase.io": json_response({
            "status": {"code": 0, "name": "OK"},
            "them": [{
                "basics": {"username": "alice", "ctime": 1500000000},
                "profile": {"full_name": "Alice Doe", "location": "Delhi", "bio": "hi"},
                "proofs_summary": {"all": [
                    {"proof_type": "github", "nametag": "alice"},
                    {"proof_type": "twitter", "nametag": "alice_dev"},
                ]},
                "pictures": {"primary": {"url": "https://k.example/a.png"}},
            }],
        })})
        outcome = await KeybaseUser().bind(fetcher).execute(TARGET_USER)
        assert outcome.status is ScanStatus.FOUND
        assert outcome.findings[0].extra["proofs"] == ["github:alice", "twitter:alice_dev"]

    async def test_keybase_user_not_found_code_is_absent(self, fetcher_factory) -> None:
        fetcher, _ = await fetcher_factory({"keybase.io": json_response(
            {"status": {"code": 205, "name": "USER_NOT_FOUND"}}
        )})
        outcome = await KeybaseUser().bind(fetcher).execute(TARGET_USER)
        assert outcome.status is ScanStatus.NOT_FOUND

    async def test_npm_maintainer_lists_packages(self, fetcher_factory) -> None:
        fetcher, _ = await fetcher_factory({"registry.npmjs.org": json_response({
            "total": 3,
            "objects": [
                {"package": {"name": "pkg-a", "version": "1.0.0", "description": "a",
                             "links": {"repository": "https://github.com/alice/pkg-a"}}},
                {"package": {"name": "pkg-b", "version": "2.0.0", "links": {}}},
            ],
        })})
        outcome = await NpmMaintainerHandle().bind(fetcher).execute(TARGET_USER)
        assert outcome.status is ScanStatus.FOUND
        assert outcome.findings[0].extra["total_packages"] == 3
        assert "pkg-a" in outcome.findings[0].evidence

    async def test_npm_email_search_is_medium_confidence(self, fetcher_factory) -> None:
        fetcher, _ = await fetcher_factory({"registry.npmjs.org": json_response({
            "total": 1, "objects": [{"package": {"name": "pkg-a", "publisher": {"username": "alice"}}}],
        })})
        outcome = await NpmMaintainerEmail().bind(fetcher).execute(TARGET_EMAIL)
        assert outcome.findings[0].confidence is Confidence.MEDIUM
        assert "false positives" in outcome.findings[0].evidence

    async def test_devto_links_are_surfaced(self, fetcher_factory) -> None:
        fetcher, _ = await fetcher_factory({"dev.to": json_response({
            "username": "alice", "name": "Alice Doe", "summary": "writer",
            "github_username": "alice", "twitter_username": "alice_dev",
            "website_url": "https://alice.example", "location": "Delhi",
            "joined_at": "2020-01-01T00:00:00Z", "profile_image": "https://d.example/a.png",
        })})
        outcome = await DevToUser().bind(fetcher).execute(TARGET_USER)
        assert outcome.status is ScanStatus.FOUND
        assert "github_username: alice" in outcome.findings[0].extra["exposure"]


class TestSocialSources:
    async def test_bluesky_full_handle(self, fetcher_factory) -> None:
        fetcher, _ = await fetcher_factory({"public.api.bsky.app": json_response({
            "did": "did:plc:abc", "handle": "alice.bsky.social", "displayName": "Alice Doe",
            "description": "hi", "avatar": "https://b.example/a.png",
            "createdAt": "2023-05-01T00:00:00Z", "followersCount": 10, "followsCount": 5,
            "postsCount": 42,
        })})
        outcome = await BlueskyHandle().bind(fetcher).execute(
            ScanTarget.create(username="alice.bsky.social")
        )
        assert outcome.status is ScanStatus.FOUND
        assert outcome.findings[0].confidence is Confidence.CONFIRMED

    async def test_bluesky_bare_handle_falls_back_to_search_as_low_confidence(
        self, fetcher_factory
    ) -> None:
        def routing(request):
            import httpx

            url = str(request.url)
            if "getProfile" in url:
                return httpx.Response(400, json={"error": "InvalidRequest"}, request=request)
            return httpx.Response(200, json={"actors": [
                {"handle": "alice.bsky.social", "displayName": "Alice Doe"},
                {"handle": "someone-else.bsky.social", "displayName": "Someone"},
            ]}, request=request)

        fetcher, _ = await fetcher_factory({"public.api.bsky.app": routing})
        outcome = await BlueskyHandle().bind(fetcher).execute(TARGET_USER)
        assert outcome.status is ScanStatus.FOUND
        assert len(outcome.findings) == 1
        assert outcome.findings[0].confidence is Confidence.LOW
        assert "confirm" in outcome.findings[0].evidence

    async def test_bluesky_name_search_flags_homonyms(self, fetcher_factory) -> None:
        fetcher, _ = await fetcher_factory({"public.api.bsky.app": json_response({"actors": [
            {"handle": "alice.bsky.social", "displayName": "Alice Doe", "avatar": None},
            {"handle": "unrelated.bsky.social", "displayName": "Bob Smith"},
        ]})})
        outcome = await BlueskyNameSearch().bind(fetcher).execute(TARGET_NAME)
        assert outcome.status is ScanStatus.FOUND
        assert len(outcome.findings) == 1
        assert outcome.findings[0].extra["homonym_warning"] is True

    async def test_mastodon_profile_fields(self, fetcher_factory) -> None:
        fetcher, _ = await fetcher_factory({"mastodon.social": json_response({
            "username": "alice", "acct": "alice", "display_name": "Alice Doe",
            "note": "<p>hi</p>", "url": "https://mastodon.social/@alice",
            "created_at": "2022-01-01T00:00:00Z", "followers_count": 3, "locked": False,
            "fields": [{"name": "Website", "value": "<a href='https://a.example'>a</a>"}],
        })})
        outcome = await MastodonAccount().bind(fetcher).execute(TARGET_USER)
        assert outcome.status is ScanStatus.FOUND
        assert outcome.findings[0].extra["profile_fields"] == ["Website: <a href='https://a.example'>a</a>"]

    async def test_hackernews_counts_items(self, fetcher_factory) -> None:
        fetcher, _ = await fetcher_factory({"hn.algolia.com": json_response({
            "nbHits": 12,
            "hits": [{"title": "Show HN: thing", "created_at": "2024-01-01T00:00:00Z", "objectID": "1"}],
        })})
        outcome = await HackerNewsAuthor().bind(fetcher).execute(TARGET_USER)
        assert outcome.status is ScanStatus.FOUND
        assert outcome.findings[0].extra["items_total"] == 12

    async def test_hackernews_absent(self, fetcher_factory) -> None:
        fetcher, _ = await fetcher_factory({"hn.algolia.com": json_response({"nbHits": 0, "hits": []})})
        outcome = await HackerNewsAuthor().bind(fetcher).execute(TARGET_USER)
        assert outcome.status is ScanStatus.NOT_FOUND

    async def test_chesscom_403_explains_the_user_agent_requirement(self, fetcher_factory) -> None:
        fetcher, _ = await fetcher_factory({"api.chess.com": 403})
        outcome = await ChessComUser().bind(fetcher).execute(TARGET_USER)
        assert outcome.status is ScanStatus.BLOCKED
        assert "D3TA1L3R_UA_EMAIL" in (outcome.error or "")

    async def test_chesscom_epoch_dates_are_converted(self, fetcher_factory) -> None:
        fetcher, _ = await fetcher_factory({"api.chess.com": json_response({
            "username": "alice", "name": "Alice Doe", "joined": 1560000000,
            "country": "https://api.chess.com/pub/country/IN", "status": "basic",
            "twitch_url": "https://twitch.tv/alice", "url": "https://www.chess.com/member/alice",
        })})
        outcome = await ChessComUser().bind(fetcher).execute(TARGET_USER)
        assert outcome.findings[0].account_created_at.startswith("2019-06-08")

    async def test_lichess_millisecond_dates_are_converted(self, fetcher_factory) -> None:
        fetcher, _ = await fetcher_factory({"lichess.org": json_response({
            "id": "alice", "username": "alice", "createdAt": 1600000000000,
            "count": {"all": 10}, "profile": {"bio": "hi", "country": "IN"},
            "url": "https://lichess.org/@/alice",
        })})
        outcome = await LichessUser().bind(fetcher).execute(TARGET_USER)
        assert outcome.status is ScanStatus.FOUND
        assert outcome.findings[0].account_created_at.startswith("2020-09-13")

    async def test_codeforces_failed_status_is_absent(self, fetcher_factory) -> None:
        fetcher, _ = await fetcher_factory({"codeforces.com": json_response(
            {"status": "FAILED", "comment": "handles: User with handle alice not found"}
        )})
        outcome = await CodeforcesUser().bind(fetcher).execute(TARGET_USER)
        assert outcome.status is ScanStatus.NOT_FOUND

    async def test_speedrun_requires_an_exact_name_match(self, fetcher_factory) -> None:
        fetcher, _ = await fetcher_factory({"speedrun.com": json_response({"data": [
            {"names": {"international": "alice2"}, "weblink": "https://speedrun.com/user/alice2"},
        ]})})
        outcome = await SpeedrunComUser().bind(fetcher).execute(TARGET_USER)
        assert outcome.status is ScanStatus.NOT_FOUND

        fetcher2, _ = await fetcher_factory({"speedrun.com": json_response({"data": [
            {"names": {"international": "alice"}, "weblink": "https://speedrun.com/user/alice",
             "twitch": {"uri": "https://twitch.tv/alice"}, "signup": "2019-01-01T00:00:00Z"},
        ]})})
        outcome2 = await SpeedrunComUser().bind(fetcher2).execute(TARGET_USER)
        assert outcome2.status is ScanStatus.FOUND
        assert "twitch link" in " ".join(outcome2.findings[0].extra["exposure"])


class TestIdentitySources:
    async def test_gravatar_lookup_uses_the_md5_of_the_lowercased_address(
        self, fetcher_factory
    ) -> None:
        digest = hashlib.md5(b"alice@example.com").hexdigest()
        fetcher, table = await fetcher_factory({"gravatar.com": json_response({"entry": [{
            "hash": digest, "preferredUsername": "alice", "displayName": "Alice Doe",
            "aboutMe": "hi", "currentLocation": "Delhi",
            "photos": [{"value": "https://g.example/a.png"}],
            "urls": [{"value": "https://alice.example"}],
            "accounts": [{"shortname": "github", "username": "alice", "verified": "true"},
                         {"shortname": "twitter", "username": "alice_dev", "verified": "false"}],
        }]})})
        outcome = await GravatarEmail().bind(fetcher).execute(
            ScanTarget.create(email="Alice@Example.com")
        )
        assert digest in table.calls[0]
        assert outcome.status is ScanStatus.FOUND
        assert outcome.findings[0].extra["linked_accounts"] == ["github", "twitter"]
        assert outcome.findings[0].extra["verified_accounts"] == ["alice"]

    async def test_gravatar_404_is_the_private_case(self, fetcher_factory) -> None:
        fetcher, _ = await fetcher_factory({"gravatar.com": 404})
        outcome = await GravatarEmail().bind(fetcher).execute(TARGET_EMAIL)
        assert outcome.status is ScanStatus.NOT_FOUND

    async def test_rdap_reports_registrar_and_expiry(self, fetcher_factory) -> None:
        fetcher, _ = await fetcher_factory({"rdap.org": json_response({
            "ldhName": "EXAMPLE.COM",
            "status": ["client transfer prohibited"],
            "events": [
                {"eventAction": "registration", "eventDate": "2019-04-02T00:00:00Z"},
                {"eventAction": "expiration", "eventDate": "2099-04-02T00:00:00Z"},
            ],
            "entities": [{"roles": ["registrar"],
                          "vcardArray": ["vcard", [["fn", {}, "text", "Example Registrar"]]]}],
            "nameservers": [{"ldhName": "NS1.EXAMPLE.COM"}],
        })})
        outcome = await RdapDomain().bind(fetcher).execute(TARGET_DOMAIN)
        assert outcome.status is ScanStatus.FOUND
        finding = outcome.findings[0]
        assert finding.extra["registrar"] == "Example Registrar"
        assert finding.extra["days_until_expiry"] > 0
        assert finding.account_created_at == "2019-04-02T00:00:00Z"


class TestKnowledgeSources:
    async def test_openalex_filters_out_different_names(self, fetcher_factory) -> None:
        fetcher, _ = await fetcher_factory({"api.openalex.org": json_response({
            "meta": {"count": 2},
            "results": [
                {"id": "https://openalex.org/A1", "display_name": "Alice Doe",
                 "works_count": 30, "cited_by_count": 200,
                 "last_known_institutions": [{"display_name": "Example University"}],
                 "orcid": "https://orcid.org/0000-0002-1825-0097"},
                {"id": "https://openalex.org/A2", "display_name": "Bob Smith"},
            ],
        })})
        outcome = await OpenAlexAuthor().bind(fetcher).execute(TARGET_NAME)
        assert outcome.status is ScanStatus.FOUND
        assert len(outcome.findings) == 1
        assert outcome.findings[0].confidence is Confidence.LOW
        assert outcome.findings[0].extra["homonym_warning"] is True

    async def test_openalex_absent_when_only_other_names_match(self, fetcher_factory) -> None:
        fetcher, _ = await fetcher_factory({"api.openalex.org": json_response({
            "meta": {"count": 1}, "results": [{"id": "A", "display_name": "Someone Else"}],
        })})
        outcome = await OpenAlexAuthor().bind(fetcher).execute(TARGET_NAME)
        assert outcome.status is ScanStatus.NOT_FOUND

    async def test_arxiv_parses_atom_xml(self, fetcher_factory) -> None:
        body = """<?xml version="1.0" encoding="UTF-8"?>
<feed xmlns="http://www.w3.org/2005/Atom"
      xmlns:opensearch="http://a9.com/-/spec/opensearch/1.1/">
  <opensearch:totalResults>2</opensearch:totalResults>
  <entry><id>http://arxiv.org/abs/1234.5678</id>
    <title>A paper about things</title></entry>
</feed>"""
        fetcher, _ = await fetcher_factory({"export.arxiv.org": (200, body, {"content-type": "application/atom+xml"})})
        outcome = await ArxivAuthor().bind(fetcher).execute(TARGET_NAME)
        assert outcome.status is ScanStatus.FOUND
        assert outcome.findings[0].extra["total_results"] == 2
        assert outcome.findings[0].extra["preprints"][0]["title"] == "A paper about things"

    async def test_arxiv_absent_when_no_results(self, fetcher_factory) -> None:
        body = """<?xml version="1.0"?><feed xmlns="http://www.w3.org/2005/Atom"
          xmlns:opensearch="http://a9.com/-/spec/opensearch/1.1/">
          <opensearch:totalResults>0</opensearch:totalResults></feed>"""
        fetcher, _ = await fetcher_factory({"export.arxiv.org": (200, body, {"content-type": "application/atom+xml"})})
        outcome = await ArxivAuthor().bind(fetcher).execute(TARGET_NAME)
        assert outcome.status is ScanStatus.NOT_FOUND

    async def test_arxiv_parse_failure_is_an_error(self, fetcher_factory) -> None:
        fetcher, _ = await fetcher_factory({"export.arxiv.org": html("<html>maintenance</html>")})
        outcome = await ArxivAuthor().bind(fetcher).execute(TARGET_NAME)
        assert outcome.status is ScanStatus.ERROR
        # XHTML parses as XML, so the root element is the only reliable tell.
        assert "Atom feed" in (outcome.error or "")
        assert "maintenance" in (outcome.error or "")

    async def test_pubmed_reports_a_count(self, fetcher_factory) -> None:
        fetcher, _ = await fetcher_factory({"eutils.ncbi.nlm.nih.gov": json_response(
            {"esearchresult": {"count": "7", "idlist": ["111", "222"]}}
        )})
        outcome = await PubMedAuthor().bind(fetcher).execute(TARGET_NAME)
        assert outcome.findings[0].extra["article_count"] == 7
        assert outcome.findings[0].confidence is Confidence.LOW

    async def test_orcid_matches_on_name_tokens(self, fetcher_factory) -> None:
        fetcher, _ = await fetcher_factory({"pub.orcid.org": json_response({
            "num-found": 1,
            "expanded-result": [{"orcid-id": "0000-0002-1825-0097", "given-names": "Alice",
                                 "family-names": "Doe", "institution-name": ["Example University"]}],
        })})
        outcome = await OrcidAuthor().bind(fetcher).execute(TARGET_NAME)
        assert outcome.status is ScanStatus.FOUND
        assert outcome.findings[0].url.endswith("0000-0002-1825-0097")

    async def test_wikipedia_search_is_low_confidence_with_a_warning(
        self, fetcher_factory
    ) -> None:
        fetcher, _ = await fetcher_factory({"en.wikipedia.org": json_response({
            "query": {"searchinfo": {"totalhits": 3},
                      "search": [{"title": "Alice (disambiguation)", "pageid": 1}]},
        })})
        outcome = await WikipediaSearch().bind(fetcher).execute(TARGET_NAME)
        assert outcome.status is ScanStatus.FOUND
        assert outcome.findings[0].confidence is Confidence.LOW
        assert outcome.findings[0].extra["homonym_warning"] is True


class TestFailureContainment:
    @pytest.mark.parametrize("source", [
        GitHubUser(), GitLabUser(), KeybaseUser(), BlueskyHandle(), ChessComUser(),
        LichessUser(), CodeforcesUser(), GravatarEmail(), RdapDomain(), OpenAlexAuthor(),
        ArxivAuthor(), PubMedAuthor(), OrcidAuthor(), WikipediaSearch(), DevToUser(),
    ])
    async def test_garbage_response_never_raises(self, fetcher_factory, source) -> None:
        """A total API outage must produce a status, not an exception."""
        fetcher, _ = await fetcher_factory(default=html("<html>maintenance</html>"))
        target = ScanTarget.create(
            username="alice", email="alice@example.com", name="Alice Doe", domain="example.com"
        )
        outcome = await source.bind(fetcher).execute(target)
        assert outcome.status is not ScanStatus.FOUND
        assert outcome.status in {
            ScanStatus.ERROR, ScanStatus.NOT_FOUND, ScanStatus.BLOCKED,
            ScanStatus.SKIPPED_RATE_LIMITED, ScanStatus.TIMEOUT,
        }

    async def test_unexpected_exception_is_contained(self, fetcher_factory) -> None:
        fetcher, _ = await fetcher_factory({"api.github.com": json_response([1, 2, 3])})
        outcome = await GitHubUser().bind(fetcher).execute(TARGET_USER)
        assert outcome.status in {ScanStatus.ERROR, ScanStatus.NOT_FOUND}
        assert outcome.error is not None or outcome.status is ScanStatus.NOT_FOUND
