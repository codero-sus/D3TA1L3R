"""Offline demo transport: synthetic, clearly-fake responses for every source.

``--demo`` swaps the real network for this transport so the whole pipeline —
robots handling, retries, detectors, report rendering, the dashboard — can be
exercised (and demonstrated) without contacting a single third party, and
without a scrap of real personal data.

The responses below are **fabricated**. They are emitted only when the operator
explicitly asks for demo mode, every report produced this way is flagged
``demo: true``, and the CLI prints a banner. Never present demo output as a real
audit of a real person.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from typing import Any
from urllib.parse import unquote

import httpx

__all__ = ["DEMO_WARNING", "DemoTransport"]

DEMO_WARNING = (
    "DEMO MODE — every result in this report was generated locally from synthetic "
    "fixtures. No third-party site was contacted and no claim here describes a real "
    "account. Run the same command without --demo for a genuine self-audit."
)

_DEMO_USERNAME = "demo_user"
_DEMO_EMAIL = "demo.user@example.com"
_DEMO_NAME = "Demo User"
_DEMO_DOMAIN = "example.com"

#: Sites that "exist" in demo mode (ids from data/sites.json).
_PRESENT_SITES = {
    "codepen_user",
    "kaggle_user",
    "leetcode_user",
    "hackernews_user",
    "steam_user",
    "letterboxd_user",
    "lastfm_user",
    "dribbble_user",
}
#: Sites that behave like a sign-in wall in demo mode (reported as ``blocked``).
_BLOCKED_SITES = {"instagram_user"}
#: A site whose signature is deliberately broken in demo mode: it claims every
#: handle exists. ``d3ta1l3r calibrate`` (and the dashboard's calibration page)
#: must flag exactly this one as a false positive — that is the offline way to
#: show the detection working instead of asserting it.
_NOISY_SITES = {"codepen_user"}
#: Passwords the synthetic Pwned Passwords endpoint reports as breached, so the
#: k-anonymity flow can be demonstrated end to end without touching the network.
#: Every other password comes back clean, exactly as a real range lookup would.
#: Addresses the synthetic HIBP endpoint reports as breached. They are obvious
#: placeholders: demo mode must never look like it found something real.
_DEMO_BREACHED_ACCOUNTS = {"alice@example.com", "demo@example.com"}

_DEMO_PWNED_PASSWORDS = {
    "demo-password-123": 3,
    "hunter2": 5,
}

#: Hosts that "disallow" automated checks in demo mode, to exercise the robots path.
_ROBOTS_DENIED_HOSTS = ("myanimelist.net",)


def _json(payload: Any, status: int = 200, headers: dict[str, str] | None = None) -> tuple[int, dict, str]:
    return status, {"content-type": "application/json", **(headers or {})}, json.dumps(payload)


def _html(
    body: str, status: int = 200, headers: dict[str, str] | None = None
) -> tuple[int, dict, str]:
    payload = {"content-type": "text/html; charset=utf-8"}
    payload.update(headers or {})
    return status, payload, body


class DemoTransport(httpx.AsyncBaseTransport):
    """A deterministic fake internet, keyed by URL."""

    def __init__(self, *, username: str = _DEMO_USERNAME, email: str = _DEMO_EMAIL,
                 name: str = _DEMO_NAME, domain: str = _DEMO_DOMAIN) -> None:
        self.username = username
        self.email = email
        self.name = name
        self.domain = domain
        self.calls: list[str] = []

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        self.calls.append(url)
        status, headers, body = self._respond(url)
        return httpx.Response(status_code=status, headers=headers, content=body.encode("utf-8"),
                              request=request)

    async def aclose(self) -> None:  # pragma: no cover - nothing to close
        return None

    # -- routing ---------------------------------------------------------
    def _respond(self, url: str) -> tuple[int, dict, str]:
        if url.endswith("/robots.txt"):
            return self._robots(url)
        handler = self._route(url)
        if handler is None:
            return _html("<html><body>demo: no fixture for this URL</body></html>", 404)
        return handler(url)

    def _robots(self, url: str) -> tuple[int, dict, str]:
        # One host in the demo refuses scanning, so the skipped_robots path is visible.
        if any(host in url for host in _ROBOTS_DENIED_HOSTS):
            return _html("User-agent: *\nDisallow: /\n", 200)
        return _html("User-agent: *\nAllow: /\n", 200)

    def _route(self, url: str) -> Callable[[str], tuple[int, dict, str]] | None:
        """Match known API hosts, then fall back to the generic site probe."""
        for prefix, handler in self._routes().items():
            if prefix in url:
                return handler
        return self._generic_probe

    def _routes(self) -> dict[str, Callable[[str], tuple[int, dict, str]]]:
        return {
            # -- structured APIs ------------------------------------------
            "api.github.com/users/": self._github,
            "api.github.com/search/users": lambda url: _json({"total_count": 1, "items": [
                {"login": self.username, "html_url": f"https://github.com/{self.username}",
                 "avatar_url": "https://avatars.example.com/u/1"}]}),
            "gitlab.com/api/v4/users": self._gitlab,
            "codeberg.org/api/v1/users": self._codeberg,
            "hub.docker.com/v2/users/": self._dockerhub,
            "keybase.io/_/api/1.0/user/lookup": self._keybase,
            "registry.npmjs.org/-/v1/search": self._npm,
            "dev.to/api/users/by_username": self._devto,
            "public.api.bsky.app": self._bluesky,
            "mastodon.social/api/v1/accounts/lookup": self._mastodon,
            "hn.algolia.com": self._hackernews,
            "api.chess.com/pub/player/": self._chesscom,
            "lichess.org/api/user/": self._lichess,
            "codeforces.com/api/user.info": self._codeforces,
            "speedrun.com/api/v1/users": self._speedrun,
            "gravatar.com": self._gravatar,
            "rdap.org/domain/": self._rdap,
            # Deliberately "down" so the error path shows up in demo reports.
            "api.openalex.org": lambda url: _json({"error": "service unavailable"}, 503),
            "api.pwnedpasswords.com": self._pwned_passwords,
            "haveibeenpwned.com": self._hibp_breaches,
            "export.arxiv.org": self._arxiv,
            "eutils.ncbi.nlm.nih.gov": self._pubmed,
            "pub.orcid.org": self._orcid,
            "en.wikipedia.org": self._wikipedia,
        }

    # -- fixtures --------------------------------------------------------
    def _github(self, url: str) -> tuple[int, dict, str]:
        return _json({
            "login": self.username, "name": self.name, "bio": "Demo bio (synthetic).",
            "location": "Delhi, IN", "company": "Example Org", "blog": f"https://{self.domain}",
            "twitter_username": "demo_handle", "public_repos": 27, "public_gists": 3,
            "followers": 128, "following": 42, "created_at": "2016-04-01T09:12:00Z",
            "updated_at": "2026-09-30T10:00:00Z",
            "html_url": f"https://github.com/{self.username}",
            "avatar_url": "https://avatars.example.com/u/1", "hireable": True,
            "type": "User", "site_admin": False,
        })

    def _gitlab(self, url: str) -> tuple[int, dict, str]:
        return _json([{
            "id": 4242, "username": self.username, "name": self.name, "state": "active",
            "web_url": f"https://gitlab.com/{self.username}", "created_at": "2018-01-05T10:00:00Z",
            "bio": "Demo bio (synthetic).", "location": "Delhi, IN",
            "public_email": self.email, "linkedin": "demo-linkedin", "twitter": "demo_handle",
            "skype": "", "website_url": f"https://{self.domain}", "job_title": "Engineer",
            "organization": "Example Org", "avatar_url": "https://gitlab.example.com/a.png",
        }])

    def _codeberg(self, url: str) -> tuple[int, dict, str]:
        return _json({
            "id": 77, "login": self.username, "full_name": self.name,
            "description": "Demo bio (synthetic).", "location": "Delhi, IN",
            "website": f"https://{self.domain}", "created": "2021-06-01T00:00:00Z",
            "followers_count": 12, "following_count": 7, "starred_repos_count": 31,
            "visibility": "public", "html_url": f"https://codeberg.org/{self.username}",
            "avatar_url": "https://codeberg.example.com/a.png",
        })

    def _dockerhub(self, url: str) -> tuple[int, dict, str]:
        return _json({
            "username": self.username, "full_name": self.name, "location": "Delhi, IN",
            "company": "Example Org", "profile_url": f"https://hub.docker.com/u/{self.username}",
            "date_joined": "2019-02-11T12:00:00Z", "gravatar_email": self.email,
            "gravatar_url": "https://gravatar.example.com/a.png", "type": "User", "id": "abc123",
        })

    def _keybase(self, url: str) -> tuple[int, dict, str]:
        return _json({
            "status": {"code": 0, "name": "OK"},
            "them": [{
                "id": "demo1", "basics": {"username": self.username, "ctime": 1500000000},
                "profile": {"full_name": self.name, "bio": "Demo bio (synthetic).",
                            "location": "Delhi, IN", "website": f"https://{self.domain}"},
                "proofs_summary": {"all": [
                    {"proof_type": "github", "nametag": self.username,
                     "service_url": "https://gist.github.com/x/y"},
                    {"proof_type": "twitter", "nametag": "demo_handle",
                     "service_url": "https://twitter.com/demo_handle/status/1"},
                ]},
                "pictures": {"primary": {"url": "https://keybase.example.com/a.png"}},
            }],
        })

    def _npm(self, url: str) -> tuple[int, dict, str]:
        if "maintainer-email" in url:
            return _json({"total": 6, "objects": [
                {"package": {"name": f"demo-pkg-{i}", "publisher": {"username": self.username},
                             "links": {"repository": f"https://github.com/{self.username}/demo-{i}"}}}
                for i in range(4)]})
        return _json({"total": 14, "objects": [
            {"package": {"name": f"demo-pkg-{i}", "version": "1.0.0",
                         "description": "Synthetic demo package.",
                         "links": {"repository": f"https://github.com/{self.username}/demo-{i}",
                                   "homepage": f"https://{self.domain}"}}}
            for i in range(4)]})

    def _devto(self, url: str) -> tuple[int, dict, str]:
        return _json({
            "type_of": "user", "id": 999, "username": self.username, "name": self.name,
            "summary": "Demo bio (synthetic).", "twitter_username": "demo_handle",
            "github_username": self.username, "website_url": f"https://{self.domain}",
            "location": "Delhi, IN", "joined_at": "2020-03-03T00:00:00Z",
            "profile_image": "https://dev.to/a.png",
        })

    def _bluesky(self, url: str) -> tuple[int, dict, str]:
        if "searchActors" in url:
            return _json({"actors": [
                {"did": "did:plc:demo1", "handle": f"{self.username}.bsky.social",
                 "displayName": self.name, "description": "Demo bio (synthetic).",
                 "avatar": "https://bsky.example.com/a.png"}]})
        if _looks_missing(url):
            return _json({"error": "InvalidRequest", "message": "Profile not found"}, 400)
        return _json({
            "did": "did:plc:demo1", "handle": f"{self.username}.bsky.social",
            "displayName": self.name, "description": "Demo bio (synthetic).",
            "avatar": "https://bsky.example.com/a.png", "createdAt": "2023-05-01T00:00:00Z",
            "followersCount": 64, "followsCount": 51, "postsCount": 210,
        })

    def _mastodon(self, url: str) -> tuple[int, dict, str]:
        return _json({
            "id": "55", "username": self.username, "acct": self.username,
            "display_name": self.name, "note": "Demo bio (synthetic).",
            "url": f"https://mastodon.social/@{self.username}",
            "avatar": "https://masto.example.com/a.png", "locked": False, "bot": False,
            "created_at": "2022-11-01T00:00:00Z", "followers_count": 33, "following_count": 21,
            "statuses_count": 120,
            "fields": [{"name": "Website", "value": f'<a href="https://{self.domain}">{self.domain}</a>'}],
        })

    def _hackernews(self, url: str) -> tuple[int, dict, str]:
        return _json({"nbHits": 37, "hits": [
            {"title": "Synthetic demo submission", "created_at": "2026-08-01T10:00:00Z",
             "objectID": "1", "url": f"https://{self.domain}/demo"},
            {"story_title": "Synthetic demo comment", "created_at": "2026-07-15T10:00:00Z",
             "objectID": "2"},
        ]})

    def _chesscom(self, url: str) -> tuple[int, dict, str]:
        return _json({
            "username": self.username, "player_id": 12345, "name": self.name,
            "status": "premium", "avatar": "https://chess.example.com/a.png",
            "location": "Delhi", "country": "https://api.chess.com/pub/country/IN",
            "joined": 1560000000, "last_online": 1780000000, "followers": 12,
            "is_streamer": True, "twitch_url": f"https://twitch.tv/{self.username}",
            "verified": False, "league": "Silver",
        })

    def _lichess(self, url: str) -> tuple[int, dict, str]:
        return _json({
            "id": self.username, "username": self.username, "createdAt": 1600000000000,
            "seenAt": 1780000000000, "playTime": {"total": 123456},
            "profile": {"bio": "Demo bio (synthetic).", "country": "IN",
                        "location": "Delhi", "links": f"https://{self.domain}"},
            "count": {"all": 4211, "rated": 3000}, "title": "NM", "patron": True,
            "url": f"https://lichess.org/@/{self.username}",
        })

    def _codeforces(self, url: str) -> tuple[int, dict, str]:
        return _json({"status": "OK", "result": [{
            "handle": self.username, "firstName": "Demo", "lastName": "User",
            "country": "India", "city": "Delhi", "organization": "Example Org",
            "rating": 1712, "maxRating": 1801, "rank": "expert", "maxRank": "expert",
            "registrationTimeSeconds": 1560000000, "friendOfCount": 44,
            "avatar": "https://codeforces.example.com/a.png",
        }]})

    def _speedrun(self, url: str) -> tuple[int, dict, str]:
        return _json({"data": [{
            "id": "demo", "names": {"international": self.username},
            "weblink": f"https://www.speedrun.com/user/{self.username}",
            "role": "user", "signup": "2019-01-01T00:00:00Z",
            "location": {"country": {"names": {"international": "India"}}},
            "twitch": {"uri": f"https://twitch.tv/{self.username}"},
            "youtube": {"uri": f"https://youtube.com/@{self.username}"},
        }]})

    def _gravatar(self, url: str) -> tuple[int, dict, str]:
        if _looks_missing(url):
            return _json({"error": "Not found"}, 404)
        return _json({"entry": [{
            "hash": hashlib.md5(self.email.encode()).hexdigest(),
            "preferredUsername": self.username, "displayName": self.name,
            "aboutMe": "Demo bio (synthetic).", "currentLocation": "Delhi, IN",
            "profileUrl": f"https://gravatar.com/{self.username}",
            "registrationDate": "2015-05-05T00:00:00Z",
            "name": {"givenName": "Demo", "familyName": "User"},
            "photos": [{"value": "https://gravatar.example.com/a.png"}],
            "urls": [{"value": f"https://{self.domain}", "title": "Website"}],
            "accounts": [
                {"shortname": "github", "username": self.username, "verified": "true"},
                {"shortname": "twitter", "username": "demo_handle", "verified": "false"},
            ],
        }]})

    def _rdap(self, url: str) -> tuple[int, dict, str]:
        if _looks_missing(url):
            return _json({"errorCode": 404, "title": "Not Found"}, 404)
        return _json({
            "ldhName": self.domain.upper(),
            "status": ["client transfer prohibited", "client delete prohibited"],
            "events": [
                {"eventAction": "registration", "eventDate": "2019-04-02T00:00:00Z"},
                {"eventAction": "expiration", "eventDate": "2027-04-02T00:00:00Z"},
                {"eventAction": "last changed", "eventDate": "2026-03-11T00:00:00Z"},
            ],
            "entities": [{"roles": ["registrar"], "handle": "DEMO-REGISTRAR",
                          "vcardArray": ["vcard", [["fn", {}, "text", "Demo Registrar Inc."]]]}],
            "nameservers": [{"ldhName": "NS1.DEMO-DNS.COM"}, {"ldhName": "NS2.DEMO-DNS.COM"}],
        })

    def _arxiv(self, url: str) -> tuple[int, dict, str]:
        body = """<?xml version="1.0" encoding="UTF-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <opensearch:totalResults xmlns:opensearch="http://a9.com/-/spec/opensearch/1.1/">2</opensearch:totalResults>
  <entry><id>http://arxiv.org/abs/0000.00001</id>
    <title>Synthetic demo preprint one</title></entry>
  <entry><id>http://arxiv.org/abs/0000.00002</id>
    <title>Synthetic demo preprint two</title></entry>
</feed>"""
        return 200, {"content-type": "application/atom+xml"}, body

    def _pubmed(self, url: str) -> tuple[int, dict, str]:
        return _json({"esearchresult": {"count": "5", "idlist": ["10000001", "10000002"]}})

    def _orcid(self, url: str) -> tuple[int, dict, str]:
        return _json({"num-found": 2, "expanded-result": [{
            "orcid-id": "0000-0002-1825-0097", "given-names": "Demo",
            "family-names": "User", "institution-name": ["Example University"],
        }]})

    def _wikipedia(self, url: str) -> tuple[int, dict, str]:
        return _json({"query": {"searchinfo": {"totalhits": 4}, "search": [
            {"title": "Demo (disambiguation)", "pageid": 1},
            {"title": "Demo User (synthetic)", "pageid": 2},
        ]}})

    def _hibp_breaches(self, url: str) -> tuple[int, dict, str]:
        """Synthetic HIBP account lookup: one demo address is "breached", the rest are not."""
        account = url.split("breachedaccount/", 1)[-1].split("?")[0]
        account = unquote(account).strip().lower()
        if account in _DEMO_BREACHED_ACCOUNTS:
            return 200, {"content-type": "application/json"}, json.dumps(
                [
                    {
                        "Name": "SyntheticFixture",
                        "Title": "Synthetic Fixture Breach",
                        "BreachDate": "2019-03-04",
                        "PwnCount": 3,
                        "DataClasses": ["Email addresses", "Passwords"],
                    },
                    {
                        "Name": "DemoCorpusDump",
                        "Title": "Demo Corpus Dump",
                        "BreachDate": "2021-11-19",
                        "PwnCount": 3,
                        "DataClasses": ["Email addresses"],
                    },
                ]
            )
        return 404, {"content-type": "application/json"}, json.dumps(
            {"statusCode": 404, "message": "No breaches found"}
        )

    def _pwned_passwords(self, url: str) -> tuple[int, dict, str]:
        """Synthetic k-anonymity range response.

        The request only ever carries a five-character hash prefix, so the demo
        endpoint computes the SHA-1 of its known passwords locally and answers
        with the matching suffix — the same shape a real lookup returns.
        """
        prefix = url.rstrip("/").rsplit("/", 1)[-1].upper()
        lines = [
            "0000000000000000000000000000000000A:1",
            "0000000000000000000000000000000000B:2",
        ]
        for password, count in _DEMO_PWNED_PASSWORDS.items():
            digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
            if digest.startswith(prefix):
                lines.append(f"{digest[5:]}:{count}")
        return 200, {"content-type": "text/plain"}, "\r\n".join(lines) + "\r\n"

    def _generic_probe(self, url: str) -> tuple[int, dict, str]:
        site_id = _site_id_for(url)
        if site_id in _BLOCKED_SITES:
            # A real sign-in wall: the site redirects anonymous visitors to its
            # login page. The probe reports "blocked" (unknown), not "absent".
            return _html(
                "<html><body>Redirecting to sign in…</body></html>",
                302,
                {"location": "https://www.instagram.com/accounts/login/?next=/demo_user/"},
            )
        if site_id in _NOISY_SITES:
            # The intentionally broken signature (see _NOISY_SITES).
            return _html(f"<html><body><h1>{self.username}</h1>profile</body></html>")
        if _looks_missing(url):
            # Keeps ``calibrate`` meaningful offline: a certainly-bogus handle
            # must look absent here too, or demo mode would fake its own
            # false-positive rate for every site at once.
            return _html("<html><body>Page not found</body></html>", 404)
        if site_id in _PRESENT_SITES:
            if site_id == "hackernews_user":
                return _html(
                    f"<html><body><table><tr><td>user:</td><td>{self.username}</td></tr>"
                    "<tr><td>created:</td><td>2015-01-01</td></tr></table></body></html>"
                )
            if site_id == "steam_user":
                return _html(f"<html><body><div class='profile_header'>{self.username}</div></body></html>")
            return _html(f"<html><body><h1>{self.username}</h1><p>Demo profile (synthetic).</p></body></html>")
        return _html("<html><body>Page not found</body></html>", 404)


def _looks_missing(url: str) -> bool:
    """Deterministic 'this one is absent' filter so the demo shows misses too.

    ``zzq`` is the prefix ``d3ta1l3r calibrate`` uses for handles that certainly
    do not exist, so recognising it keeps the offline demo's false-positive
    report honest instead of inventing a rate.
    """
    if "does-not-exist" in url or "/zzq" in url or "=zzq" in url or "%3zzq" in url:
        return True
    return hashlib.sha1(url.encode()).hexdigest()[0] in "0123"


def _site_id_for(url: str) -> str:
    from ..sources.probe import load_site_specs

    for spec in load_site_specs():
        needle = spec.url.split("{", 1)[0]
        if needle and needle in url:
            return spec.id
    return ""
