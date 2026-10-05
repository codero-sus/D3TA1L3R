"""Social, community and gaming APIs with public, unauthenticated endpoints.

Two of these deliberately answer with a *candidate* rather than a record:

* the Bluesky handle inference (a bare handle without a domain is not a valid
  Bluesky identifier, so the source looks the string up as a search term and
  labels the result ``MEDIUM`` with the resolved handle shown), and
* the name-based search (names are not unique, so anything found is a lead).

Everything else returns the service's own record for the identifier that was
supplied and earns ``CONFIRMED``.
"""

from __future__ import annotations

from ...models import Confidence, ScanTarget, SourceKind, SourceOutcome
from ..base import SourceMeta
from .base import (
    ApiSource,
    as_list,
    dig,
    first_present,
    iso_from_epoch,
    name_matches,
    require_mapping,
    require_sequence,
    summarise,
)

__all__ = [
    "BlueskyHandle",
    "BlueskyNameSearch",
    "ChessComUser",
    "CodeforcesUser",
    "HackerNewsAuthor",
    "LichessUser",
    "MastodonAccount",
    "SpeedrunComUser",
]


class BlueskyHandle(ApiSource):
    """`app.bsky.actor.getProfile` — the AT Protocol public AppView; no auth needed."""

    record_confidence = Confidence.CONFIRMED

    meta = SourceMeta(
        id="bluesky_api_handle",
        name="Bluesky",
        kind=SourceKind.USERNAME,
        category="social",
        description="Public Bluesky profile record (display name, bio, follower and post counts).",
        docs_url="https://docs.bsky.app/docs/api/app-bsky-actor-get-profile",
        homepage="https://bsky.app",
        weight=30,
    )

    def query_url(self, identifier: str) -> str:
        return (
            "https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile?"
            f"actor={self.quote(identifier)}"
        )

    async def run(self, identifier: str, target: ScanTarget) -> SourceOutcome:
        started = self.now()

        if "." not in identifier:
            # A bare handle is not a Bluesky identifier. Instead of guessing
            # "<handle>.bsky.social", look the string up and report candidates.
            return await self._infer_from_search(identifier, started)

        result = await self.fetch_json(self.query_url(identifier))
        if not result.ok or result.payload is None:
            if result.status in (400, 404):
                return self.outcome_for(
                    result,
                    identifier=identifier,
                    started=started,
                    not_found_reason=(
                        f"Bluesky has no account for '{identifier}' (the AppView answered "
                        f"HTTP {result.status} — note that Bluesky handles look like "
                        "'name.bsky.social')"
                    ),
                )
            return self.outcome_for(result, identifier=identifier, started=started)

        data = require_mapping(result.payload, "Bluesky profile")
        handle = str(dig(data, "handle", default=identifier))
        exposure = [
            f"display name: {summarise(dig(data, 'displayName'))}"
            if dig(data, "displayName")
            else "",
            f"bio: {summarise(dig(data, 'description'))}" if dig(data, "description") else "",
            f"{dig(data, 'followersCount', default=0)} follower(s), "
            f"{dig(data, 'postsCount', default=0)} post(s)",
            f"joined {summarise(dig(data, 'createdAt'))}",
        ]
        labels = [str(dig(label, "val")) for label in as_list(dig(data, "labels", default=[]))]
        if labels:
            exposure.append(f"public labels: {', '.join(labels)}")
        finding = self.record_finding(
            identifier=identifier,
            url=f"https://bsky.app/profile/{handle}",
            evidence=f"Bluesky's public AppView returned the profile record for '{handle}'",
            title=f"Bluesky @{handle}",
            display_name=dig(data, "displayName"),
            bio=dig(data, "description"),
            avatar_url=dig(data, "avatar"),
            account_created_at=dig(data, "createdAt"),
            extra={
                "exposure": [item for item in exposure if item],
                "handle": handle,
                "did": dig(data, "did"),
                "followers": dig(data, "followersCount"),
                "posts": dig(data, "postsCount"),
                "labels": labels,
            },
        )
        return self.outcome_for(result, identifier=identifier, started=started, findings=[finding])

    async def _infer_from_search(self, identifier: str, started: float) -> SourceOutcome:
        """Bare handles: find actors whose handle starts with ``<identifier>.``."""
        url = (
            "https://public.api.bsky.app/xrpc/app.bsky.actor.searchActors?"
            f"q={self.quote(identifier)}&limit=25"
        )
        result = await self.fetch_json(url)
        if not result.ok or result.payload is None:
            return self.outcome_for(result, identifier=identifier, started=started)
        data = require_mapping(result.payload, "Bluesky actor search")
        prefix = identifier.lower() + "."
        candidates = [
            actor
            for actor in as_list(dig(data, "actors", default=[]))
            if isinstance(actor, dict)
            and (
                str(dig(actor, "handle", default="")).lower() == identifier.lower()
                or str(dig(actor, "handle", default="")).lower().startswith(prefix)
            )
        ]
        if not candidates:
            return self.outcome_for(
                result,
                identifier=identifier,
                started=started,
                not_found_reason=(
                    "no Bluesky actor's handle starts with that string; run the scan again "
                    "with a full handle (for example name.bsky.social) to be sure"
                ),
            )
        best = candidates[0]
        handle = str(dig(best, "handle", default=identifier))
        finding = self.record_finding(
            identifier=identifier,
            url=f"https://bsky.app/profile/{handle}",
            confidence=Confidence.LOW,
            evidence=(
                f"'{identifier}' is not a valid Bluesky identifier, so this is only a "
                f"candidate: searchActors returned '{handle}' (its handle starts with "
                f"'{prefix}'). confirm the profile is really yours before acting on it."
            ),
            title=f"Bluesky candidate @{handle}",
            display_name=dig(best, "displayName"),
            bio=dig(best, "description"),
            avatar_url=dig(best, "avatar"),
            extra={
                "inferred": True,
                "candidates": [dig(actor, "handle") for actor in candidates[:10]],
                "exposure": [
                    f"candidate handle: {dig(actor, 'handle')}" for actor in candidates[:5]
                ],
            },
        )
        return self.outcome_for(result, identifier=identifier, started=started, findings=[finding])


class BlueskyNameSearch(ApiSource):
    """`app.bsky.actor.searchActors` by display name — always ``LOW`` confidence."""

    record_confidence = Confidence.LOW

    meta = SourceMeta(
        id="bluesky_api_name_search",
        name="Bluesky (name search)",
        kind=SourceKind.NAME,
        category="social",
        description="Bluesky actors whose display name matches the name you supplied (same-name candidates).",
        docs_url="https://docs.bsky.app/docs/api/app-bsky-actor-search-actors",
        homepage="https://bsky.app",
        weight=32,
    )

    def query_url(self, identifier: str) -> str:
        return (
            "https://public.api.bsky.app/xrpc/app.bsky.actor.searchActors?"
            f"q={self.quote(identifier)}&limit=25"
        )

    async def run(self, identifier: str, target: ScanTarget) -> SourceOutcome:
        started = self.now()
        result = await self.fetch_json(self.query_url(identifier))
        if not result.ok or result.payload is None:
            return self.outcome_for(result, identifier=identifier, started=started)

        data = require_mapping(result.payload, "Bluesky actor search")
        matches = [
            actor
            for actor in as_list(dig(data, "actors", default=[]))
            if isinstance(actor, dict) and name_matches(dig(actor, "displayName"), identifier)
        ]
        if not matches:
            return self.outcome_for(
                result,
                identifier=identifier,
                started=started,
                not_found_reason="no Bluesky display name matches that name closely enough",
            )
        findings = [
            self.record_finding(
                identifier=identifier,
                url=f"https://bsky.app/profile/{dig(actor, 'handle')}",
                evidence=(
                    f"same-name candidate, NOT a confirmed match: Bluesky display name "
                    f"{dig(actor, 'displayName')!r} on @{dig(actor, 'handle')}"
                ),
                title=f"possible Bluesky account: {dig(actor, 'displayName')}",
                display_name=dig(actor, "displayName"),
                bio=dig(actor, "description"),
                avatar_url=dig(actor, "avatar"),
                extra={
                    "homonym_warning": True,
                    "handle": dig(actor, "handle"),
                    "exposure": [f"candidate handle: {dig(actor, 'handle')}"],
                },
            )
            for actor in matches[:5]
        ]
        return self.outcome_for(result, identifier=identifier, started=started, findings=findings)


class MastodonAccount(ApiSource):
    """`/api/v1/accounts/lookup` on mastodon.social (instance-scoped, as Mastodon is)."""

    meta = SourceMeta(
        id="mastodon_api_account",
        name="Mastodon (mastodon.social)",
        kind=SourceKind.USERNAME,
        category="social",
        description="Public account record from the mastodon.social instance's lookup endpoint.",
        docs_url="https://docs.joinmastodon.org/methods/accounts/#lookup",
        homepage="https://mastodon.social",
        weight=34,
        notes=(
            "Mastodon is federated: this checks mastodon.social only. The same handle on "
            "another instance is a different account, so a not-found result here does not "
            "mean the handle is unused on the fediverse."
        ),
    )

    def query_url(self, identifier: str) -> str:
        return (
            "https://mastodon.social/api/v1/accounts/lookup?"
            f"acct={self.quote(identifier)}"
        )

    async def run(self, identifier: str, target: ScanTarget) -> SourceOutcome:
        started = self.now()
        result = await self.fetch_json(self.query_url(identifier))
        if not result.ok or result.payload is None:
            return self.outcome_for(
                result,
                identifier=identifier,
                started=started,
                not_found_reason=(
                    "mastodon.social has no account with that handle. Mastodon is federated, "
                    "so this covers one instance only — the handle may be registered elsewhere."
                ),
            )

        data = require_mapping(result.payload, "Mastodon account")
        acct = str(dig(data, "acct", default=identifier))
        exposure = [
            f"display name: {summarise(dig(data, 'display_name'))}"
            if dig(data, "display_name")
            else "",
            f"bio: {summarise(dig(data, 'note'))}" if dig(data, "note") else "",
            f"{dig(data, 'followers_count', default=0)} follower(s), "
            f"{dig(data, 'statuses_count', default=0)} post(s)",
            f"locked: {dig(data, 'locked')}",
        ]
        fields = [
            f"{summarise(dig(field, 'name'))}: {dig(field, 'value')}"
            for field in as_list(dig(data, "fields", default=[]))
            if isinstance(field, dict)
        ]
        finding = self.record_finding(
            identifier=identifier,
            url=str(dig(data, "url", default=f"https://mastodon.social/@{identifier}")),
            evidence=f"mastodon.social returned the account record for '@{acct}'",
            title=f"Mastodon @{acct}@mastodon.social",
            display_name=dig(data, "display_name"),
            bio=dig(data, "note"),
            avatar_url=dig(data, "avatar"),
            account_created_at=dig(data, "created_at"),
            extra={
                "exposure": [item for item in exposure if item] + fields[:6],
                "profile_fields": fields,
                "instance": "mastodon.social",
                "locked": dig(data, "locked"),
                "bot": dig(data, "bot"),
            },
        )
        return self.outcome_for(result, identifier=identifier, started=started, findings=[finding])


class HackerNewsAuthor(ApiSource):
    """`hn.algolia.com/api/v1/search?tags=author_` — public HN search index."""

    meta = SourceMeta(
        id="hn_api_author",
        name="Hacker News (posts via Algolia)",
        kind=SourceKind.USERNAME,
        category="community",
        description="Public submissions and comments attributed to a Hacker News handle.",
        docs_url="https://hn.algolia.com/api",
        homepage="https://news.ycombinator.com",
        weight=36,
    )

    def query_url(self, identifier: str) -> str:
        return (
            "https://hn.algolia.com/api/v1/search?"
            f"tags=author_{self.quote(identifier)}&hitsPerPage=10"
        )

    async def run(self, identifier: str, target: ScanTarget) -> SourceOutcome:
        started = self.now()
        result = await self.fetch_json(self.query_url(identifier))
        if not result.ok or result.payload is None:
            return self.outcome_for(result, identifier=identifier, started=started)

        data = require_mapping(result.payload, "HN Algolia search")
        hits = [h for h in as_list(dig(data, "hits", default=[])) if isinstance(h, dict)]
        total = dig(data, "nbHits", default=len(hits))
        if not hits:
            return self.outcome_for(
                result,
                identifier=identifier,
                started=started,
                not_found_reason=(
                    "HN's search index attributes no public submission or comment to that handle"
                ),
            )
        titles = [summarise(first_present(h, "title", "story_title"), limit=80) for h in hits[:5]]
        titles = [t for t in titles if t]
        exposure = [f"public post: {title}" for title in titles]
        finding = self.record_finding(
            identifier=identifier,
            url=f"https://news.ycombinator.com/user?id={identifier}",
            evidence=(
                f"HN search API attributes {total} public item(s) to '{identifier}' "
                "(posts and comments, including ones you may have forgotten)"
            ),
            title=f"Hacker News user {identifier}",
            extra={
                "exposure": exposure,
                "items_total": total,
                "recent_titles": titles,
            },
        )
        return self.outcome_for(result, identifier=identifier, started=started, findings=[finding])


class ChessComUser(ApiSource):
    """`api.chess.com/pub/player/{username}` — Chess.com's public player API."""

    meta = SourceMeta(
        id="chesscom_api_user",
        name="Chess.com",
        kind=SourceKind.USERNAME,
        category="gaming",
        description="Public Chess.com player record (title, country, joined, last seen).",
        docs_url="https://www.chess.com/news/view/published-data-api",
        homepage="https://www.chess.com",
        weight=38,
        notes=(
            "Chess.com asks anonymous clients to identify themselves with a contact "
            "address; without D3TA1L3R_UA_EMAIL set, their edge may answer 403 and the "
            "source reports 'blocked' rather than pretending the account is absent."
        ),
    )

    def query_url(self, identifier: str) -> str:
        return f"https://api.chess.com/pub/player/{self.quote(identifier.lower())}"

    async def run(self, identifier: str, target: ScanTarget) -> SourceOutcome:
        started = self.now()
        result = await self.fetch_json(self.query_url(identifier))
        if not result.ok or result.payload is None:
            return self.outcome_for(
                result,
                identifier=identifier,
                started=started,
                error=(
                    "api.chess.com refused the request. Chess.com asks clients to identify "
                    "themselves; set D3TA1L3R_UA_EMAIL=you@example.com and re-run."
                ),
                not_found_reason="api.chess.com has no player with that username",
            )

        data = require_mapping(result.payload, "Chess.com player")
        username = str(dig(data, "username", default=identifier))
        exposure = [
            f"display name: {summarise(dig(data, 'name'))}" if dig(data, "name") else "",
            f"title: {dig(data, 'title')}" if dig(data, "title") else "",
            f"location: {summarise(dig(data, 'location'))}" if dig(data, "location") else "",
            f"status: {dig(data, 'status')}" if dig(data, "status") else "",
            f"joined {iso_from_epoch(dig(data, 'joined')) or 'unknown'}",
            f"last online {iso_from_epoch(dig(data, 'last_online')) or 'unknown'}",
        ]
        finding = self.record_finding(
            identifier=identifier,
            url=str(dig(data, "url", default=f"https://www.chess.com/member/{username}")),
            evidence=f"api.chess.com returned the player record for '{username}'",
            title=f"Chess.com {username}",
            display_name=dig(data, "name"),
            location=dig(data, "location"),
            avatar_url=dig(data, "avatar"),
            account_created_at=iso_from_epoch(dig(data, "joined")),
            extra={
                "exposure": [item for item in exposure if item],
                "title": dig(data, "title"),
                "status": dig(data, "status"),
                "followers": dig(data, "followers"),
                "last_online": iso_from_epoch(dig(data, "last_online")),
            },
        )
        return self.outcome_for(result, identifier=identifier, started=started, findings=[finding])


class LichessUser(ApiSource):
    """`lichess.org/api/user/{username}` — open API, no key, no nonsense."""

    meta = SourceMeta(
        id="lichess_api_user",
        name="Lichess",
        kind=SourceKind.USERNAME,
        category="gaming",
        description="Public Lichess account record (per-game ratings, play time, profile).",
        docs_url="https://lichess.org/api#tag/Users/operation/apiUser",
        homepage="https://lichess.org",
        weight=40,
    )

    def query_url(self, identifier: str) -> str:
        return f"https://lichess.org/api/user/{self.quote(identifier)}"

    async def run(self, identifier: str, target: ScanTarget) -> SourceOutcome:
        started = self.now()
        result = await self.fetch_json(self.query_url(identifier))
        if not result.ok or result.payload is None:
            return self.outcome_for(result, identifier=identifier, started=started)

        data = require_mapping(result.payload, "Lichess user")
        perfs = dig(data, "perfs", default={})
        played = sorted(
            (
                f"{name} {summarise(dig(perf, 'rating'))}"
                for name, perf in (perfs.items() if isinstance(perfs, dict) else [])
                if isinstance(perf, dict) and dig(perf, "games")
            ),
        )[:6]
        exposure = [
            f"display name: {summarise(dig(data, 'profile', 'realName'))}"
            if dig(data, "profile", "realName")
            else "",
            f"bio: {summarise(dig(data, 'profile', 'bio'))}" if dig(data, "profile", "bio") else "",
            f"location: {summarise(dig(data, 'profile', 'location'))}"
            if dig(data, "profile", "location")
            else "",
            f"country flag: {summarise(dig(data, 'profile', 'flag'))}"
            if dig(data, "profile", "flag")
            else "",
            f"rating snapshots: {', '.join(played)}" if played else "",
            f"play time: {int((dig(data, 'playTime', 'total') or 0) / 3600)} hour(s)"
            if dig(data, "playTime", "total")
            else "",
        ]
        finding = self.record_finding(
            identifier=identifier,
            url=str(dig(data, "url", default=f"https://lichess.org/@/{identifier}")),
            evidence=f"lichess.org returned the user record for '{dig(data, 'username', default=identifier)}'",
            title=f"Lichess @{dig(data, 'username', default=identifier)}",
            display_name=dig(data, "profile", "realName"),
            bio=dig(data, "profile", "bio"),
            location=dig(data, "profile", "location"),
            account_created_at=iso_from_epoch(dig(data, "createdAt")),
            extra={
                "exposure": [item for item in exposure if item],
                "seen_at": iso_from_epoch(dig(data, "seenAt")),
                "patron": dig(data, "patron"),
                "verified": dig(data, "verified"),
                "perfs": played,
            },
        )
        return self.outcome_for(result, identifier=identifier, started=started, findings=[finding])


class CodeforcesUser(ApiSource):
    """`user.info?handles=` — Codeforces answers ``status: FAILED`` for unknown handles."""

    meta = SourceMeta(
        id="codeforces_api_user",
        name="Codeforces",
        kind=SourceKind.USERNAME,
        category="gaming",
        description="Public Codeforces user record (rating, rank, organisation, country).",
        docs_url="https://codeforces.com/apiHelp/methods#user.info",
        homepage="https://codeforces.com",
        weight=42,
    )

    def query_url(self, identifier: str) -> str:
        return f"https://codeforces.com/api/user.info?handles={self.quote(identifier)}"

    async def run(self, identifier: str, target: ScanTarget) -> SourceOutcome:
        started = self.now()
        result = await self.fetch_json(self.query_url(identifier))
        if not result.ok or result.payload is None:
            return self.outcome_for(result, identifier=identifier, started=started)

        data = require_mapping(result.payload, "Codeforces response")
        status = str(dig(data, "status", default="")).upper()
        if status != "OK":
            comment = summarise(dig(data, "comment"), limit=160)
            return self.outcome_for(
                result,
                identifier=identifier,
                started=started,
                not_found_reason=(
                    "codeforces.com reports no such handle"
                    + (f" ('{comment}')" if comment else "")
                ),
            )
        users = [u for u in as_list(dig(data, "result", default=[])) if isinstance(u, dict)]
        if not users:
            return self.outcome_for(
                result,
                identifier=identifier,
                started=started,
                not_found_reason="codeforces.com returned an empty result list",
            )
        user = users[0]
        exposure = [
            f"display name: {summarise(first_present(user, 'firstName', 'lastName'), limit=60)}"
            if first_present(user, "firstName", "lastName")
            else "",
            f"organisation: {summarise(dig(user, 'organization'))}"
            if dig(user, "organization")
            else "",
            f"country: {dig(user, 'country')}" if dig(user, "country") else "",
            f"city: {summarise(dig(user, 'city'))}" if dig(user, "city") else "",
            f"rank: {dig(user, 'rank')} ({dig(user, 'rating')})" if dig(user, "rank") else "",
        ]
        finding = self.record_finding(
            identifier=identifier,
            url=f"https://codeforces.com/profile/{dig(user, 'handle', default=identifier)}",
            evidence=f"codeforces.com returned the user record for '{dig(user, 'handle', default=identifier)}'",
            title=f"Codeforces {dig(user, 'handle', default=identifier)}",
            display_name=first_present(user, "firstName", "lastName"),
            location=first_present(user, "city", "country"),
            avatar_url=dig(user, "titlePhoto"),
            extra={
                "exposure": [item for item in exposure if item],
                "rating": dig(user, "rating"),
                "max_rating": dig(user, "maxRating"),
                "rank": dig(user, "rank"),
                "organisation": dig(user, "organization"),
                "contribution": dig(user, "contribution"),
            },
        )
        return self.outcome_for(result, identifier=identifier, started=started, findings=[finding])


class SpeedrunComUser(ApiSource):
    """`speedrun.com/api/v1/users?lookup=` — public, key-free JSON."""

    meta = SourceMeta(
        id="speedruncom_api_user",
        name="speedrun.com",
        kind=SourceKind.USERNAME,
        category="gaming",
        description="Public speedrun.com account record (name, location, signup date, links).",
        docs_url="https://github.com/speedruncomorg/api",
        homepage="https://www.speedrun.com",
        weight=44,
    )

    def query_url(self, identifier: str) -> str:
        return f"https://www.speedrun.com/api/v1/users?lookup={self.quote(identifier)}"

    async def run(self, identifier: str, target: ScanTarget) -> SourceOutcome:
        started = self.now()
        result = await self.fetch_json(self.query_url(identifier))
        if not result.ok or result.payload is None:
            return self.outcome_for(result, identifier=identifier, started=started)

        data = require_mapping(result.payload, "speedrun.com response")
        returned = [
            u
            for u in require_sequence(dig(data, "data", default=[]), "speedrun.com users")
            if isinstance(u, dict)
        ]
        # speedrun.com's ?lookup= is fuzzy; only an exact name is that person.
        users = [
            u
            for u in returned
            if str(dig(u, "names", "international", default="")).lower() == identifier.lower()
            or str(dig(u, "id", default="")).lower() == identifier.lower()
        ]
        if not users:
            return self.outcome_for(
                result,
                identifier=identifier,
                started=started,
                not_found_reason=(
                    "speedrun.com has no user whose name is exactly that"
                    + (
                        f" (its fuzzy lookup returned {len(returned)} similar name(s))"
                        if returned
                        else ""
                    )
                ),
            )
        user = users[0]
        names = dig(user, "names", default={})
        exposure = [
            f"display name: {summarise(dig(names, 'international'))}" if dig(names, "international") else "",
            f"location: {summarise(dig(user, 'location', 'country', 'names', 'international'))}"
            if dig(user, "location", "country")
            else "",
            f"signup {summarise(dig(user, 'signup'))}" if dig(user, "signup") else "",
        ]
        for link in as_list(dig(user, "links", default=[]))[:5]:
            if isinstance(link, dict) and dig(link, "uri"):
                exposure.append(f"{dig(link, 'rel') or 'account'} link: {dig(link, 'uri')}")
        if dig(user, "twitch", "uri"):
            exposure.append(f"twitch link: {dig(user, 'twitch', 'uri')}")
        finding = self.record_finding(
            identifier=identifier,
            url=str(dig(user, "weblink", default=f"https://www.speedrun.com/user/{identifier}")),
            evidence=f"speedrun.com returned the user record for '{dig(user, 'id', default=identifier)}'",
            title=f"speedrun.com {summarise(dig(names, 'international'), limit=60) or identifier}",
            display_name=dig(names, "international"),
            bio=dig(user, "bio"),
            location=summarise(dig(user, "location", "country", "names", "international")),
            account_created_at=dig(user, "signup"),
            extra={
                "exposure": [item for item in exposure if item],
                "links": [dig(link, "uri") for link in as_list(dig(user, "links", default=[]))[:10]],
            },
        )
        return self.outcome_for(result, identifier=identifier, started=started, findings=[finding])


def build() -> list[ApiSource]:
    """Every social/community/gaming API source, in priority order."""
    return [
        BlueskyHandle(),
        BlueskyNameSearch(),
        MastodonAccount(),
        HackerNewsAuthor(),
        ChessComUser(),
        LichessUser(),
        CodeforcesUser(),
        SpeedrunComUser(),
    ]

