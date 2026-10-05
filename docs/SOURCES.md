# Sources: how checks are described, and how to add your own

Two kinds of source ship with D3TA1L3R:

| Kind | Where it lives | Confidence ceiling | Example |
| --- | --- | --- | --- |
| **API source** | `d3ta1l3r/sources/api/*.py` | `CONFIRMED` | GitHub `/users/{handle}` returns *the account record* |
| **Probe source** | `d3ta1l3r/data/sites.json` + `sources/probe.py` | `HIGH` | Steam returns HTTP 200 and *"The specified profile could not be found."* only when the account is missing |

A probe is a *heuristic*, so its confidence ceiling is `HIGH` (never
`CONFIRMED`), and a status-code-only probe is capped at `MEDIUM` by a validation
rule that will refuse to load a spec that claims more.

## Detector types

Every probe declares one of three detectors. Choosing the wrong one is the
single most common way a signature-based scanner starts lying, so the three are
kept deliberately narrow:

### `marker` — a phrase that only appears on a real profile

```json
{
  "id": "example_site", "name": "Example", "category": "social",
  "url": "https://example.com/{username}",
  "detector": "marker",
  "found_marker": "data-profile-header",
  "not_found_marker": "no such user",
  "confidence_found": "high"
}
```

Found only if `found_marker` appears. If `not_found_marker` also appears, the
result is `not_found` (conservative ordering: an "absent" phrase anywhere wins).
If neither appears → `error`, because a 200 with an unrecognised body means the
layout changed, not that the account exists.

### `absence` — HTTP 200 plus a known "no such user" phrase

```json
{
  "detector": "absence",
  "not_found_marker": "The specified profile could not be found.",
  "confidence_found": "high"
}
```

The site's error page is a 200 with an error phrase (Steam, Hacker News). The
phrase present ⇒ `not_found`; phrase absent on a 200 ⇒ `found`. This is the most
common real-world shape and the easiest to verify with `calibrate`.

### `status` — 404 means absent, 200 means present

```json
{ "detector": "status", "confidence_found": "medium" }
```

Noisy by nature (SPA shells return 200 for missing profiles), so a spec using it
cannot claim better than `medium`, and the evidence string says "verify by hand".
Prefer `marker`/`absence`, or move the site to a real API.

### Redirect and sign-in handling

- `login_redirect_markers`: paths that mean **a sign-in wall** — reported as
  `blocked` (unknown), never as absent. This is the difference between "you have
  no Instagram account" and "Instagram will not talk to anonymous clients".
- `absent_redirect_markers`: paths that legitimately mean the profile does not
  exist (for example a redirect to `/404`).

## Fields a spec accepts

| Field | Required | Notes |
| --- | --- | --- |
| `id` | yes | lowercase, stable, unique; appears in reports and `--sources` |
| `name` | yes | human label shown in reports |
| `url` | yes | must contain exactly one `{username}` placeholder |
| `category` | yes | used by `--categories` and the dashboard grouping |
| `detector` | no (`marker`) | `marker` \| `absence` \| `status` |
| `found_marker` / `not_found_marker` | per detector | case-insensitive substring match |
| `absent_statuses` | no (`[404, 410]`) | statuses that mean "no such account" |
| `confidence_found` / `confidence_absent` | no (`high`) | ceiling enforced by validation |
| `login_redirect_markers`, `absent_redirect_markers` | no | see above |
| `docs_url` | no | shown in coverage tables |
| `notes` | required when `enabled_by_default: false` | *why* it is off |
| `enabled_by_default` | no (`true`) | `false` for sites that fight automation |
| `verified_on` | no | date you last confirmed the signature by hand |
| `weight` | no (`200`) | lower runs first |

Adding a site is a data change:

```bash
$EDITOR d3ta1l3r/data/sites.json
d3ta1l3r sources --json | grep my_site        # confirm it loaded and validated
d3ta1l3r calibrate --sites my_site            # prove it does not cry wolf
d3ta1l3r scan -u your_handle --sources my_site
```

`calibrate` is not optional in practice. It probes handles that cannot exist and
reports any site that claims to have found them; a signature that has never been
calibrated is a hypothesis, and the report labels it as such.

## Writing an API source

API sources are plain classes. The contract has four rules:

1. **One question, one identifier kind.** Declare `SourceKind` in the metadata;
   if the operator did not supply that identifier, you will never be called.
2. **Never invent identifiers.** Use only the value you are given.
3. **Validate the payload shape** before reading fields
   (`self.require_mapping(...)`).
4. **Return a status; let exceptions fly.** They are contained and recorded.

```python
from d3ta1l3r.models import Confidence, ScanStatus, ScanTarget, SourceKind, SourceOutcome
from d3ta1l3r.sources.base import SourceMeta
from d3ta1l3r.sources.api.base import ApiSource


class ExampleApiUser(ApiSource):
    meta = SourceMeta(
        id="example_api_user",
        name="Example (API)",
        kind=SourceKind.USERNAME,
        category="developer",
        description="Public profile record from api.example.com.",
        docs_url="https://api.example.com/docs",
        weight=45,
    )

    def query_url(self, identifier: str) -> str:
        return f"https://api.example.com/users/{self.quote(identifier)}"

    async def run(self, identifier: str, target: ScanTarget) -> SourceOutcome:
        started = self.now()
        result = await self.fetch_json(self.query_url(identifier))
        if not result.ok:                     # 404 / 403 / 429 / 5xx → correct status
            return self.outcome_for(result, identifier=identifier, started=started)

        data = self.require_mapping(result, "Example user")
        finding = self.finding(
            identifier=identifier,
            url=data.get("html_url", self.query_url(identifier)),
            confidence=Confidence.CONFIRMED,   # the API returned the record itself
            evidence=f"api.example.com returned the user record for '{data.get('username')}'",
            display_name=data.get("name"),
            bio=data.get("bio"),
            account_created_at=data.get("created_at"),
            extra={"followers": data.get("followers")},
        )
        return self.outcome_for(result, identifier=identifier, started=started, findings=[finding])
```

Register it in `d3ta1l3r/sources/api/__init__.py` (or pass `sources=[...]` to
`ScanEngine` for a one-off), and add tests that pin both the happy path and the
absence path — see `tests/test_api_sources.py` for the pattern, including the
"garbage response must not raise" table-driven test every source is expected to
survive.

## What is deliberately not a source

- **People-search brokers** (Whitepages-style aggregators), **breach corpora**,
  **phone/address/relatives lookups** — out of scope; see `docs/SCOPE.md`.
- **Anything requiring a key, OAuth, or a login.** If a site's public API needs
  credentials, the source ships disabled with an explanation instead of asking
  you to paste a token, because a self-audit should not need credentials for
  services you are auditing.
- **Sites that fight automation.** X/Twitter, LinkedIn, Facebook, Reddit,
  TikTok, Threads and Quora all ship `enabled_by_default: false`. The honest
  answer there is "check it yourself while signed in".

## Coverage at a glance

`d3ta1l3r sources` is always the source of truth. At the time of writing there
are 81 sources, 68 enabled by default. Groups:

- `developer` — GitHub, GitLab, Codeberg, Docker Hub, npm (handle + maintainer
  email), PyPI, crates.io, RubyGems, Packagist, CodePen, JSFiddle, Kaggle,
  LeetCode, Codewars, Exercism, Hugging Face, SourceForge, Bitbucket
- `social` / `media` — Bluesky (handle + name search), Mastodon, Hacker News,
  Lobsters, Wikipedia user pages, Instagram, Tumblr, Pinterest, Vimeo, YouTube,
  Letterboxd, MyAnimeList, AniList, Trakt, SoundCloud, Mixcloud, Untappd
- `gaming` — Chess.com, Lichess, Codeforces, speedrun.com, Steam, itch.io, osu!
- `identity` — Gravatar (by email), RDAP (domain registration), Keybase
- `research` — OpenAlex, arXiv, PubMed, ORCID, Wikipedia search
- `design` — Behance, Dribbble, ArtStation, DeviantArt
- `writing` — dev.to, Medium
- `music` — Last.fm, SoundCloud, Mixcloud, Bandcamp
- `community` — Hacker News, Lobsters, Wikipedia user pages
- `learning` / `books` / `lifestyle` — Duolingo, Goodreads, Untappd, Patreon
- `identity` — Gravatar, RDAP, Keybase, about.me
