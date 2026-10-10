"""Developer-platform APIs: the structured half of a technical footprint.

These endpoints answer with the account record itself („is there a user called
*alice*?"), which is why they earn ``CONFIRMED`` confidence. The email-based
GitHub search is the exception: GitHub removed anonymous email search, so the
source ships disabled with a note rather than pretending to have looked.
"""

from __future__ import annotations

from ...models import Confidence, ScanTarget, SourceKind, SourceOutcome
from ..base import SourceMeta
from .base import ApiSource, as_list, dig, first_present, iso_from_epoch, require_mapping, summarise

__all__ = [
    "CodebergUser",
    "DevToUser",
    "DockerHubUser",
    "GitHubEmailSearch",
    "GitHubUser",
    "GitLabUser",
    "KeybaseUser",
    "NpmMaintainerEmail",
    "NpmMaintainerHandle",
]


class GitHubUser(ApiSource):
    """`GET /users/{username}` — the canonical public profile record."""

    meta = SourceMeta(
        id="github_api_user",
        name="GitHub (REST API)",
        kind=SourceKind.USERNAME,
        category="developer",
        description="Public user record from api.github.com, including name, bio, links and repo count.",
        docs_url="https://docs.github.com/en/rest/users/users#get-a-user",
        homepage="https://github.com",
        weight=10,
    )

    def query_url(self, identifier: str) -> str:
        return f"https://api.github.com/users/{self.quote(identifier)}"

    async def run(self, identifier: str, target: ScanTarget) -> SourceOutcome:
        started = self.now()
        result = await self.fetch_json(self.query_url(identifier))
        if not result.ok or result.payload is None:
            return self.outcome_for(result, identifier=identifier, started=started)

        data = require_mapping(result.payload, "GitHub user")
        login = first_present(data, "login", default=identifier)
        exposure = [
            f"display name: {summarise(dig(data, 'name'))}" if dig(data, "name") else "",
            f"bio: {summarise(dig(data, 'bio'))}" if dig(data, "bio") else "",
            f"location: {summarise(dig(data, 'location'))}" if dig(data, "location") else "",
            f"company: {summarise(dig(data, 'company'))}" if dig(data, "company") else "",
            f"blog: {summarise(dig(data, 'blog'))}" if dig(data, "blog") else "",
            (
                f"public email: {summarise(dig(data, 'email'))}"
                if dig(data, "email")
                else ""
            ),
            f"social: @{dig(data, 'twitter_username')}" if dig(data, "twitter_username") else "",
            f"{dig(data, 'public_repos', default=0)} public repo(s), "
            f"{dig(data, 'followers', default=0)} follower(s)",
        ]
        finding = self.record_finding(
            identifier=identifier,
            url=first_present(data, "html_url", default=self.query_url(str(login))),
            evidence=(
                f"api.github.com returned the user record for '{login}' "
                f"(account id {dig(data, 'id') or 'unknown'})"
            ),
            title=f"GitHub @{login}",
            display_name=dig(data, "name"),
            bio=dig(data, "bio"),
            avatar_url=dig(data, "avatar_url"),
            location=dig(data, "location"),
            account_created_at=dig(data, "created_at"),
            extra={
                "exposure": [item for item in exposure if item],
                "public_repos": dig(data, "public_repos"),
                "public_gists": dig(data, "public_gists"),
                "followers": dig(data, "followers"),
                "following": dig(data, "following"),
                "blog": dig(data, "blog"),
                "company": dig(data, "company"),
                "public_email": dig(data, "email"),
                "twitter": dig(data, "twitter_username"),
                "hireable": dig(data, "hireable"),
                "site_admin": dig(data, "site_admin"),
            },
        )
        return self.outcome_for(result, identifier=identifier, started=started, findings=[finding])


class GitHubEmailSearch(ApiSource):
    """`GET /search/users?q=EMAIL in:email` — disabled: GitHub removed anonymous email search."""

    record_confidence = Confidence.HIGH

    meta = SourceMeta(
        id="github_api_email_search",
        name="GitHub (email search)",
        kind=SourceKind.EMAIL,
        category="developer",
        description="Searches GitHub user profiles that publish an email address.",
        docs_url="https://docs.github.com/en/search-github/searching-on-github/searching-users",
        enabled_by_default=False,
        weight=12,
        notes=(
            "Disabled by default: GitHub requires authentication for the search API and "
            "does not index profile emails for anonymous callers, so this returns HTTP 401 "
            "without a token. D3TA1L3R deliberately ships no token support — use GitHub's "
            "own search while signed in instead."
        ),
    )

    def query_url(self, identifier: str) -> str:
        return f"https://api.github.com/search/users?q={self.quote(identifier)}+in:email"

    async def run(self, identifier: str, target: ScanTarget) -> SourceOutcome:
        started = self.now()
        result = await self.fetch_json(
            self.query_url(identifier),
            headers={"Accept": "application/vnd.github+json"},
        )
        if not result.ok or result.payload is None:
            return self.outcome_for(
                result,
                identifier=identifier,
                started=started,
                error=(
                    "GitHub's user-search API needs authentication for email lookups; "
                    "an anonymous client is refused (HTTP "
                    f"{result.status}). This is unknown, not absent — check "
                    "https://github.com/search?type=users while signed in."
                ),
            )
        data = require_mapping(result.payload, "GitHub search")
        items = as_list(dig(data, "items", default=[]))
        exposure = [f"public GitHub account: {dig(item, 'login')}" for item in items[:5]]
        finding = self.exposure_finding(
            identifier=identifier,
            url="https://github.com/search?q=" + self.quote(identifier) + "&type=users",
            evidence=(
                f"api.github.com search reports {dig(data, 'total_count', default=len(items))} "
                f"account(s) publishing this address"
            ),
            exposure=exposure,
            extra={"candidates": [dig(item, "login") for item in items[:10]]},
        )
        return self.outcome_for(result, identifier=identifier, started=started, findings=[finding])


class GitLabUser(ApiSource):
    """`GET /api/v4/users?username=` — GitLab answers with a JSON array."""

    meta = SourceMeta(
        id="gitlab_api_user",
        name="GitLab (API)",
        kind=SourceKind.USERNAME,
        category="developer",
        description="Public user record from gitlab.com's REST API (name, bio, location, links).",
        docs_url="https://docs.gitlab.com/ee/api/users.html#list-users",
        homepage="https://gitlab.com",
        weight=14,
    )

    def query_url(self, identifier: str) -> str:
        return f"https://gitlab.com/api/v4/users?username={self.quote(identifier)}"

    async def run(self, identifier: str, target: ScanTarget) -> SourceOutcome:
        started = self.now()
        result = await self.fetch_json(self.query_url(identifier))
        if not result.ok or result.payload is None:
            return self.outcome_for(result, identifier=identifier, started=started)

        returned = [u for u in as_list(result.payload) if isinstance(u, dict)]
        # GitLab's ?username= filter is a *search*, not equality: it happily
        # returns "alice2" for "alice". Only an exact match may be reported.
        users = [
            u for u in returned
            if str(dig(u, "username", default="")).lower() == identifier.lower()
        ]
        if not users:
            return self.outcome_for(
                result,
                identifier=identifier,
                started=started,
                not_found_reason=(
                    "gitlab.com has no user with that exact username"
                    + (
                        f" (its search returned {len(returned)} similar name(s), none of them"
                        " an exact match — refusing to report them as you)"
                        if returned
                        else ""
                    )
                ),
            )
        data = users[0]
        exposure = [
            f"display name: {summarise(dig(data, 'name'))}" if dig(data, "name") else "",
            f"bio: {summarise(dig(data, 'bio'))}" if dig(data, "bio") else "",
            f"location: {summarise(dig(data, 'location'))}" if dig(data, "location") else "",
            f"website: {summarise(dig(data, 'website_url'))}" if dig(data, "website_url") else "",
            f"public email: {summarise(dig(data, 'public_email'))}" if dig(data, "public_email") else "",
            f"linkedin: {dig(data, 'linkedin')}" if dig(data, "linkedin") else "",
            f"twitter: {dig(data, 'twitter')}" if dig(data, "twitter") else "",
            f"joined {dig(data, 'created_at')}",
            f"{dig(data, 'public_projects_count') or dig(data, 'public_projects') or '?'} public project(s)",
        ]
        finding = self.record_finding(
            identifier=identifier,
            url=first_present(data, "web_url", default=f"https://gitlab.com/{identifier}"),
            evidence=(
                f"gitlab.com returned {len(users)} user record(s) for '{identifier}' "
                f"(id {dig(data, 'id')})"
            ),
            title=f"GitLab @{dig(data, 'username', default=identifier)}",
            display_name=dig(data, "name"),
            bio=dig(data, "bio"),
            avatar_url=dig(data, "avatar_url"),
            location=dig(data, "location"),
            account_created_at=dig(data, "created_at"),
            extra={"exposure": [item for item in exposure if item]},
        )
        return self.outcome_for(result, identifier=identifier, started=started, findings=[finding])


class CodebergUser(ApiSource):
    """`GET /api/v1/users/{username}` — Gitea instance run by Codeberg."""

    meta = SourceMeta(
        id="codeberg_api_user",
        name="Codeberg (Gitea API)",
        kind=SourceKind.USERNAME,
        category="developer",
        description="Public user record from Codeberg's Gitea API.",
        docs_url="https://forgejo.org/docs/latest/user/api-usage/",
        homepage="https://codeberg.org",
        weight=16,
    )

    def query_url(self, identifier: str) -> str:
        return f"https://codeberg.org/api/v1/users/{self.quote(identifier)}"

    async def run(self, identifier: str, target: ScanTarget) -> SourceOutcome:
        started = self.now()
        result = await self.fetch_json(self.query_url(identifier))
        if not result.ok or result.payload is None:
            return self.outcome_for(result, identifier=identifier, started=started)
        data = require_mapping(result.payload, "Codeberg user")
        exposure = [
            f"display name: {summarise(dig(data, 'full_name'))}" if dig(data, "full_name") else "",
            f"website: {summarise(dig(data, 'website'))}" if dig(data, "website") else "",
            f"location: {summarise(dig(data, 'location'))}" if dig(data, "location") else "",
            f"{dig(data, 'followers_count', default=0)} follower(s)",
        ]
        finding = self.record_finding(
            identifier=identifier,
            url=first_present(data, "html_url", default=f"https://codeberg.org/{identifier}"),
            evidence=f"codeberg.org returned the user record for '{data.get('login', identifier)}'",
            title=f"Codeberg @{dig(data, 'login', default=identifier)}",
            display_name=dig(data, "full_name"),
            bio=dig(data, "description"),
            avatar_url=dig(data, "avatar_url"),
            location=dig(data, "location"),
            account_created_at=iso_from_epoch(dig(data, "created")),
            extra={"exposure": [item for item in exposure if item]},
        )
        return self.outcome_for(result, identifier=identifier, started=started, findings=[finding])


class DockerHubUser(ApiSource):
    """`GET /v2/users/{username}/` — Docker Hub's public account endpoint."""

    meta = SourceMeta(
        id="dockerhub_api_user",
        name="Docker Hub",
        kind=SourceKind.USERNAME,
        category="developer",
        description="Public Docker Hub account record.",
        docs_url="https://docs.docker.com/docker-hub/api/latest/",
        homepage="https://hub.docker.com",
        weight=18,
    )

    def query_url(self, identifier: str) -> str:
        return f"https://hub.docker.com/v2/users/{self.quote(identifier)}/"

    async def run(self, identifier: str, target: ScanTarget) -> SourceOutcome:
        started = self.now()
        result = await self.fetch_json(self.query_url(identifier))
        if not result.ok or result.payload is None:
            return self.outcome_for(result, identifier=identifier, started=started)
        data = require_mapping(result.payload, "Docker Hub user")
        exposure = [
            f"full name: {summarise(dig(data, 'full_name'))}" if dig(data, "full_name") else "",
            f"location: {summarise(dig(data, 'location'))}" if dig(data, "location") else "",
            f"company: {summarise(dig(data, 'company'))}" if dig(data, "company") else "",
            f"joined {dig(data, 'date_joined')}" if dig(data, "date_joined") else "",
        ]
        finding = self.record_finding(
            identifier=identifier,
            url=f"https://hub.docker.com/u/{identifier}",
            evidence=f"hub.docker.com returned the account record for '{data.get('username', identifier)}'",
            title=f"Docker Hub @{dig(data, 'username', default=identifier)}",
            display_name=dig(data, "full_name"),
            location=dig(data, "location"),
            avatar_url=dig(data, "gravatar_url"),
            account_created_at=dig(data, "date_joined"),
            extra={
                "exposure": [item for item in exposure if item],
                "full_name": dig(data, "full_name"),
                "location": dig(data, "location"),
                "company": dig(data, "company"),
                "gravatar_email": dig(data, "gravatar_email"),
                "gravatar_url": dig(data, "gravatar_url"),
                "date_joined": dig(data, "date_joined"),
            },
        )
        return self.outcome_for(result, identifier=identifier, started=started, findings=[finding])


class KeybaseUser(ApiSource):
    """`GET /_/api/1.0/user/lookup.json` — public, and unusually informative.

    Keybase's strongest feature for a self-audit is the ``proofs`` block: the
    accounts *you* told Keybase you own, across other services. It is the one
    public endpoint that hands back a pre-built link between your identities.
    """

    meta = SourceMeta(
        id="keybase_api_user",
        name="Keybase",
        kind=SourceKind.USERNAME,
        category="identity",
        description="Keybase profile plus the public identity proofs it links (other services you claimed).",
        docs_url="https://keybase.io/docs/api/1.0/call/user/lookup",
        homepage="https://keybase.io",
        weight=20,
    )

    def query_url(self, identifier: str) -> str:
        return f"https://keybase.io/_/api/1.0/user/lookup.json?username={self.quote(identifier)}"

    async def run(self, identifier: str, target: ScanTarget) -> SourceOutcome:
        started = self.now()
        result = await self.fetch_json(self.query_url(identifier))
        if not result.ok or result.payload is None:
            return self.outcome_for(result, identifier=identifier, started=started)

        data = require_mapping(result.payload, "Keybase lookup")
        status_name = str(dig(data, "status", "name", default="")).upper()
        code = dig(data, "status", "code")
        if status_name in {"USER_NOT_FOUND", "NOT_FOUND"} or code in (205, 207):
            return self.outcome_for(
                result,
                identifier=identifier,
                started=started,
                not_found_reason=f"keybase.io reports no such user ('{status_name or code}')",
            )
        them = dig(data, "them", default=[])
        profile = them[0] if isinstance(them, list) and them else them
        if not isinstance(profile, dict):
            return self.outcome_for(
                result,
                identifier=identifier,
                started=started,
                error="keybase.io answered without a 'them' profile block",
            )

        proofs = [
            p
            for p in as_list(
                dig(
                    profile,
                    "proofs_summary",
                    "all",
                    default=dig(profile, "proofs", "all", default=[]),
                )
            )
            if isinstance(p, dict)
        ]
        proof_labels = [
            f"{dig(p, 'proof_type', default='service')}:{dig(p, 'nametag')}"
            for p in proofs
            if dig(p, "nametag")
        ]
        exposure = [f"linked {label}" for label in proof_labels[:10]]
        for item in as_list(dig(profile, "profile", "website"))[:3]:
            exposure.append(f"website: {summarise(item)}")

        finding = self.record_finding(
            identifier=identifier,
            url=f"https://keybase.io/{identifier}",
            evidence=(
                f"keybase.io returned the user record for '{identifier}' with "
                f"{len(proofs)} public identity proof(s)"
            ),
            title=f"Keybase @{identifier}",
            display_name=dig(profile, "profile", "full_name"),
            bio=dig(profile, "profile", "bio"),
            location=dig(profile, "profile", "location"),
            account_created_at=iso_from_epoch(
                first_present(dig(profile, "basics", "ctime"), dig(profile, "ctime"))
            ),
            avatar_url=dig(profile, "pictures", "primary", "url"),
            extra={
                "exposure": exposure,
                "proofs": proof_labels,
                "proof_types": sorted(
                    {str(dig(p, "proof_type")) for p in proofs if dig(p, "proof_type")}
                ),
            },
        )
        return self.outcome_for(result, identifier=identifier, started=started, findings=[finding])


class NpmMaintainerHandle(ApiSource):
    """`/v1/search?text=maintainer:` — packages published under a handle."""

    record_confidence = Confidence.HIGH

    meta = SourceMeta(
        id="npm_api_maintainer",
        name="npm (maintainer handle)",
        kind=SourceKind.USERNAME,
        category="developer",
        description="Packages published to npm under this maintainer handle.",
        docs_url="https://github.com/npm/registry/blob/master/docs/REGISTRY-API.md",
        homepage="https://www.npmjs.com",
        weight=22,
    )

    def query_url(self, identifier: str) -> str:
        return f"https://registry.npmjs.org/-/v1/search?text=maintainer:{self.quote(identifier)}&size=20"

    async def run(self, identifier: str, target: ScanTarget) -> SourceOutcome:
        started = self.now()
        result = await self.fetch_json(self.query_url(identifier))
        if not result.ok or result.payload is None:
            return self.outcome_for(result, identifier=identifier, started=started)

        data = require_mapping(result.payload, "npm search")
        objects = [o for o in as_list(dig(data, "objects", default=[])) if isinstance(o, dict)]
        names = [str(dig(o, "package", "name")) for o in objects if dig(o, "package", "name")]
        if not names:
            return self.outcome_for(
                result,
                identifier=identifier,
                started=started,
                not_found_reason="npm has no packages published under that maintainer handle",
            )
        total = dig(data, "total", default=len(names))
        finding = self.record_finding(
            identifier=identifier,
            url=f"https://www.npmjs.com/search?q=maintainer%3A{self.quote(identifier)}",
            evidence=(
                f"registry.npmjs.org reports {total} package(s) maintained by '{identifier}' "
                f"(for example {', '.join(names[:3])})"
            ),
            title=f"npm maintainer @{identifier}",
            extra={
                "exposure": [f"package: {name}" for name in names[:10]],
                "packages": names[:20],
                "total_packages": total,
            },
        )
        return self.outcome_for(result, identifier=identifier, started=started, findings=[finding])


class NpmMaintainerEmail(ApiSource):
    """`/v1/search?text=maintainer-email:` — packages bound to your address."""

    record_confidence = Confidence.MEDIUM

    meta = SourceMeta(
        id="npm_api_maintainer_email",
        name="npm (maintainer email)",
        kind=SourceKind.EMAIL,
        category="developer",
        description="Packages whose published maintainer email matches yours.",
        docs_url="https://github.com/npm/registry/blob/master/docs/REGISTRY-API.md",
        homepage="https://www.npmjs.com",
        weight=24,
    )

    def query_url(self, identifier: str) -> str:
        return (
            "https://registry.npmjs.org/-/v1/search?"
            f"text=maintainer-email:{self.quote(identifier)}&size=20"
        )

    async def run(self, identifier: str, target: ScanTarget) -> SourceOutcome:
        started = self.now()
        result = await self.fetch_json(self.query_url(identifier))
        if not result.ok or result.payload is None:
            return self.outcome_for(result, identifier=identifier, started=started)

        data = require_mapping(result.payload, "npm search")
        objects = [o for o in as_list(dig(data, "objects", default=[])) if isinstance(o, dict)]
        names: list[str] = []
        for entry in objects:
            package = dig(entry, "package", default={})
            maintainers = [str(m).lower() for m in as_list(dig(package, "maintainers", default=[]))]
            if any(identifier.lower() in m for m in maintainers) or not maintainers:
                name = dig(package, "name")
                if name:
                    names.append(str(name))
        if not names:
            return self.outcome_for(
                result,
                identifier=identifier,
                started=started,
                not_found_reason=(
                    "npm's search index has no package whose published maintainer email matches"
                ),
            )
        finding = self.record_finding(
            identifier=identifier,
            url="https://www.npmjs.com/search?q=" + self.quote(f"maintainer-email:{identifier}"),
            evidence=(
                f"registry.npmjs.org's search index lists {len(names)} package(s) whose "
                "published maintainer email matches. This is a search-index match, not an "
                "exact record, so expect some false positives — confirm each package."
            ),
            title="npm packages linked to this email",
            extra={"exposure": [f"package: {name}" for name in names[:10]], "packages": names[:20]},
        )
        return self.outcome_for(result, identifier=identifier, started=started, findings=[finding])


class DevToUser(ApiSource):
    """`GET /api/users/by_username` — dev.to's public user record."""

    meta = SourceMeta(
        id="devto_api_user",
        name="DEV Community (dev.to)",
        kind=SourceKind.USERNAME,
        category="writing",
        description="Public dev.to profile record (name, summary, linked social handles).",
        docs_url="https://developers.forem.com/api/v1",
        homepage="https://dev.to",
        weight=26,
    )

    def query_url(self, identifier: str) -> str:
        return f"https://dev.to/api/users/by_username?url={self.quote(identifier)}"

    async def run(self, identifier: str, target: ScanTarget) -> SourceOutcome:
        started = self.now()
        result = await self.fetch_json(self.query_url(identifier))
        if not result.ok or result.payload is None:
            return self.outcome_for(result, identifier=identifier, started=started)
        data = require_mapping(result.payload, "dev.to user")
        exposure = [
            f"display name: {summarise(dig(data, 'name'))}" if dig(data, "name") else "",
            f"summary: {summarise(dig(data, 'summary'))}" if dig(data, "summary") else "",
            f"location: {summarise(dig(data, 'location'))}" if dig(data, "location") else "",
            f"website: {summarise(dig(data, 'website_url'))}" if dig(data, "website_url") else "",
            f"github_username: {dig(data, 'github_username')}"
            if dig(data, "github_username")
            else "",
            f"twitter_username: {dig(data, 'twitter_username')}"
            if dig(data, "twitter_username")
            else "",
        ]
        finding = self.record_finding(
            identifier=identifier,
            url=f"https://dev.to/{identifier}",
            evidence=f"dev.to returned the user record for '{dig(data, 'username', default=identifier)}'",
            title=f"dev.to @{dig(data, 'username', default=identifier)}",
            display_name=dig(data, "name"),
            bio=dig(data, "summary"),
            avatar_url=dig(data, "profile_image"),
            location=dig(data, "location"),
            account_created_at=dig(data, "joined_at"),
            extra={"exposure": [item for item in exposure if item]},
        )
        return self.outcome_for(result, identifier=identifier, started=started, findings=[finding])


def build() -> list[ApiSource]:
    """Every developer/identity API source, in priority order."""
    return [
        GitHubUser(),
        GitHubEmailSearch(),
        GitLabUser(),
        CodebergUser(),
        DockerHubUser(),
        KeybaseUser(),
        NpmMaintainerHandle(),
        NpmMaintainerEmail(),
        DevToUser(),
    ]
