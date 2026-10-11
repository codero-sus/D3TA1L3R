#!/usr/bin/env python3
"""Regenerate ``d3ta1l3r/data/sites.json``.

Two kinds of source live in that one file, and the difference between them is
the whole point of the tier system:

**curated (tiers 1-3)**
    Written and reviewed by hand for this project. URL templates and
    not-found phrases are chosen deliberately, and the ``notes`` field says what
    a hit actually means when a site is ambiguous.

**catalogue (tiers 4-15)**
    Bulk-converted from a public, community-maintained dataset of profile URLs
    and error signatures. Broad, and *unverified*: nobody from this project
    probed these sites. A status-code-only entry claims ``low`` confidence and
    nothing better, because that is all a 404/200 heuristic deserves.

Tiers are assigned by a documented noise score, then spread evenly across the
tier range so that raising the mode always adds the least-noisy sources first:

    detector      marker 0 | absence 3 | status 6   (how reliable the signal is)
    confidence    high 0 | medium 1 | low 2         (how much the source claims)
    +2  the site needs a non-profile probe URL
    +2  an adult site, where age walls and cloaking make any answer unreliable
    +1  the not-found phrase is short enough to match a real profile
    +3  the source is disabled by default (curated only)

Usage::

    # recompute tiers and rewrite, offline, from what is already in the file
    python scripts/build_catalogue.py

    # fold in a fresh upstream dataset first
    curl -o /tmp/sherlock.json \
      https://raw.githubusercontent.com/sherlock-project/sherlock/master/sherlock_project/resources/data.json
    python scripts/build_catalogue.py --upstream /tmp/sherlock.json

    # report what is in the file without writing
    python scripts/build_catalogue.py --report

The upstream dataset is never fetched by this script: conversion is offline and
auditable, and the generated JSON is what ships.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent.parent
SITES_FILE = ROOT / "d3ta1l3r" / "data" / "sites.json"

CURATED_TIERS = (1, 3)
CATALOGUE_TIERS = (4, 15)

MIN_MARKER_LEN = 12
"""Below this, a not-found phrase is too generic to trust: it would match real
profile pages and quietly turn hits into false negatives."""

_TAGS = re.compile(r"<[^>]+>")
_SPACES = re.compile(r"\s+")

_DETECTOR_NOISE = {"marker": 0, "absence": 3, "status": 6}
_CONF_NOISE = {"high": 0, "medium": 1, "low": 2}


# --------------------------------------------------------------------------- #
# category hints: the upstream dataset carries none, so derive a best guess
# --------------------------------------------------------------------------- #

_ADULT_HINTS: tuple[str, ...] = (
    "porn", "xxx", "nsfw", "adult", "nude", "erotic", "hentai", "fetish", "kink",
    "bdsm", "escort", "sugardaddy", "swinger", "onlyfans", "fansly", "justforfans",
    "fancentro", "stripchat", "chaturbate", "livejasmin", "brazzers", "xvideos",
    "xhamster", "pornhub", "redtube", "youporn", "myfreecams", "hanime", "arsmate",
    "seneporno", "shesfreaky", "muyzorras", "cowboys4angels", "datezone", "tryst.link",
)

_CATEGORY_HINTS: tuple[tuple[str, tuple[str, ...]], ...] = (
    (
        # checked first: adult sites sit behind age walls and cloaking, so any
        # answer they give is unreliable and they belong in the highest tiers
        "adult",
        _ADULT_HINTS,
    ),
    (
        "filesharing",
        ("1337x", "rutracker", "nyaa", "chomikuj", "torrent", "pirate", "uploaded"),
    ),
    (
        "developer",
        (
            "github", "gitlab", "bitbucket", "gitea", "codeberg", "sourceforge", "sr.ht",
            "npm", "pypi", "crates", "rubygems", "nuget", "docker", "codepen", "glitch",
            "replit", "stackblitz", "codesandbox", "observable", "kaggle", "leetcode",
            "hackerrank", "codeforces", "codechef", "atcoder", "topcoder", "kattis",
            "dmoj", "spoj", "codingame", "hackaday", "sourcegraph", "launchpad",
            "savannah", "dev.to", "hashnode", "gist", "paste", "termbin", "wandb",
            "hugging", "compiler", "ide", "sdk", "api",
        ),
    ),
    (
        "gaming",
        (
            "steam", "itch.io", "itch", "speedrun", "osu", "chess", "lichess", "twitch",
            "kongregate", "newgrounds", "roblox", "minecraft", "xbox", "playstation",
            "nintendo", "epic", "gog.com", "game", "gamer", "retro", "arcade",
        ),
    ),
    (
        "music",
        (
            "soundcloud", "bandcamp", "mixcloud", "audiomack", "last.fm", "lastfm",
            "discogs", "reverbnation", "spotify", "genius", "lyric", "music", "radio",
            "beat", "sound", "track", "dj",
        ),
    ),
    (
        "design",
        (
            "behance", "dribbble", "artstation", "deviantart", "unsplash", "500px",
            "cargo", "coroflot", "design", "art", "portfolio", "photo", "flickr",
            "viewbug", "pinterest", "sketch", "figma",
        ),
    ),
    (
        "media",
        (
            "youtube", "vimeo", "dailymotion", "rumble", "odysee", "bitchute", "video",
            "stream", "tv", "tube", "film", "nicovideo", "imgur", "gfycat",
            "filmot", "aniworld", "watchmemore", "watchmyfeed", "unlisted",
            "mydramalist", "smule", "giphy",
        ),
    ),
    (
        "writing",
        (
            "medium", "substack", "wordpress", "blogger", "blogspot", "tumblr",
            "livejournal", "wattpad", "fanfiction", "wikipedia", "wiki", "write",
            "author", "poet", "journal", "essay", "newsletter", "scribd", "issuu",
        ),
    ),
    (
        "community",
        (
            "reddit", "hacker news", "news.ycombinator", "lobsters", "forum", "board",
            "discourse", "discussions", "soylent", "gaiaonline", "scammer",
            "nationstates", "spacehey", "chyoa", "forumprawne", "piekielni",
            "metafilter", "slashdot", "discourse", "lemmy", "myanimelist", "anilist",
            "trakt", "letterboxd", "boardgamegeek", "fandom", "community", "group",
            "meetup",
        ),
    ),
    (
        "social",
        (
            "twitter", "x.com", "instagram", "facebook", "threads", "mastodon",
            "linkedin", "xing", "tiktok", "snapchat", "telegram", "vk.com", "vk",
            "about.me", "linktr.ee", "linktree", "beacons", "social", "profile",
            "keybase", "gravatar",
        ),
    ),
    (
        "shopping",
        (
            "etsy", "ebay", "amazon", "redbubble", "gumroad", "ko-fi", "kofi", "fiverr",
            "upwork", "freelancer", "grailed", "depop", "vinted", "mercari", "stockx",
            "shop", "store", "market", "opensea", "tradingview", "zazzle", "cafepress",
            "cults3d", "google play", "bentbox", "cafecito", "subscribestar",
            "pewex", "okidoki", "biolink", "heylink", "planoly", "myportfolio",
        ),
    ),
    (
        "learning",
        (
            "coursera", "udemy", "edx", "duolingo", "brilliant", "memrise", "skillshare",
            "codecademy", "khan", "learn", "course", "study", "school", "academy",
            "university", "edu", "geeksforgeeks", "librarything",
        ),
    ),
    (
        "lifestyle",
        (
            "strava", "untappd", "vivino", "alltrails", "tripadvisor", "yelp", "airbnb",
            "goodreads", "zomato", "ratebeer", "fitness", "health", "recipe", "travel",
            "beer", "wine", "coffee", "run", "trail", "couchsurfing",
        ),
    ),
    (
        "developer",
        (
            "python.org", "getmonero", "patreon", "nitrotype", "tabletoptournament",
        ),
    ),
    (
        "identity",
        ("orcid", "openstreetmap", "archive.org", "wikidata", "ens", "keybase", " About"),
    ),
)


_WMN_CATEGORIES: dict[str, str] = {
    "social": "social",
    "gaming": "gaming",
    "tech": "developer",
    "coding": "developer",
    "hobby": "lifestyle",
    "music": "music",
    "shopping": "shopping",
    "images": "design",
    "blog": "writing",
    "art": "design",
    "video": "media",
    "dating": "social",
    "political": "community",
    "news": "community",
    "health": "lifestyle",
    "finance": "finance",
    "business": "business",
    "misc": "general",
    "archived": "general",
    "xx NSFW xx": "adult",
}

MIN_FOUND_MARKER_LEN = 8
"""Shorter than this and a "found" phrase is probably a CSS class that appears
on every page, which would make the probe useless rather than wrong."""


# --------------------------------------------------------------------------- #
# hand-authored additions: major platforms the upstream dataset does not cover
# --------------------------------------------------------------------------- #

EXTRA: tuple[tuple[str, str, str], ...] = (
    # (name, url template, category) — all status-only, confidence low: none of
    # these signatures were verified by probing, and the file says so.
    ("Replit", "https://replit.com/@{username}", "developer"),
    ("Glitch", "https://glitch.com/@{username}", "developer"),
    ("Observable", "https://observablehq.com/@{username}", "developer"),
    ("CodeSandbox", "https://codesandbox.io/u/{username}", "developer"),
    ("StackBlitz", "https://stackblitz.com/@{username}", "developer"),
    ("Sourcegraph", "https://sourcegraph.com/users/{username}", "developer"),
    ("npm", "https://www.npmjs.com/~{username}", "developer"),
    ("PyPI", "https://pypi.org/user/{username}/", "developer"),
    ("crates.io", "https://crates.io/users/{username}", "developer"),
    ("RubyGems", "https://rubygems.org/profiles/{username}", "developer"),
    ("NuGet", "https://www.nuget.org/profiles/{username}", "developer"),
    ("Docker Hub", "https://hub.docker.com/u/{username}", "developer"),
    ("Gitea", "https://gitea.com/{username}", "developer"),
    ("SourceHut", "https://git.sr.ht/~{username}", "developer"),
    ("Launchpad", "https://launchpad.net/~{username}", "developer"),
    ("Savannah", "https://savannah.gnu.org/users/{username}", "developer"),
    ("Gogs", "https://try.gogs.io/{username}", "developer"),
    ("Codeforces", "https://codeforces.com/profile/{username}", "developer"),
    ("HackerRank", "https://www.hackerrank.com/{username}", "developer"),
    ("CodeChef", "https://www.codechef.com/users/{username}", "developer"),
    ("AtCoder", "https://atcoder.jp/users/{username}", "developer"),
    ("Topcoder", "https://www.topcoder.com/members/{username}", "developer"),
    ("Kattis", "https://open.kattis.com/users/{username}", "developer"),
    ("DMOJ", "https://dmoj.ca/user/{username}", "developer"),
    ("SPOJ", "https://www.spoj.com/users/{username}/", "developer"),
    ("CodinGame", "https://www.codingame.com/profile/{username}", "developer"),
    ("Hackaday.io", "https://hackaday.io/{username}", "developer"),
    ("Weights & Biases", "https://wandb.ai/{username}", "developer"),
    ("ORCID", "https://orcid.org/{username}", "identity"),
    ("Keybase", "https://keybase.io/{username}", "identity"),
    ("OpenStreetMap", "https://www.openstreetmap.org/user/{username}", "identity"),
    ("Internet Archive", "https://archive.org/details/@{username}", "identity"),
    ("LinkedIn", "https://www.linkedin.com/in/{username}", "social"),
    ("Threads", "https://www.threads.net/@{username}", "social"),
    ("Xing", "https://www.xing.com/profile/{username}", "social"),
    ("Meetup", "https://www.meetup.com/members/{username}/", "social"),
    ("about.me", "https://about.me/{username}", "social"),
    ("Linktree", "https://linktr.ee/{username}", "social"),
    ("Beacons", "https://beacons.ai/{username}", "social"),
    ("Vimeo", "https://vimeo.com/{username}", "media"),
    ("Dailymotion", "https://www.dailymotion.com/{username}", "media"),
    ("Rumble", "https://rumble.com/user/{username}", "media"),
    ("Odysee", "https://odysee.com/@{username}", "media"),
    ("Niconico", "https://www.nicovideo.jp/user/{username}", "media"),
    ("Imgur", "https://imgur.com/user/{username}", "media"),
    ("Unsplash", "https://unsplash.com/@{username}", "design"),
    ("500px", "https://500px.com/p/{username}", "design"),
    ("DeviantArt", "https://www.deviantart.com/{username}", "design"),
    ("ArtStation", "https://www.artstation.com/{username}", "design"),
    ("Behance", "https://www.behance.net/{username}", "design"),
    ("Dribbble", "https://dribbble.com/{username}", "design"),
    ("ViewBug", "https://www.viewbug.com/member/{username}", "design"),
    ("Bandcamp", "https://bandcamp.com/{username}", "music"),
    ("SoundCloud", "https://soundcloud.com/{username}", "music"),
    ("Mixcloud", "https://www.mixcloud.com/{username}/", "music"),
    ("Audiomack", "https://audiomack.com/{username}", "music"),
    ("ReverbNation", "https://www.reverbnation.com/{username}", "music"),
    ("Last.fm", "https://www.last.fm/user/{username}", "music"),
    ("Discogs", "https://www.discogs.com/user/{username}", "music"),
    ("Genius", "https://genius.com/{username}", "music"),
    ("Medium", "https://medium.com/@{username}", "writing"),
    ("dev.to", "https://dev.to/{username}", "writing"),
    ("Wikipedia", "https://en.wikipedia.org/wiki/User:{username}", "writing"),
    ("FanFiction.net", "https://www.fanfiction.net/~{username}", "writing"),
    ("Tumblr", "https://{username}.tumblr.com", "writing"),
    ("LiveJournal", "https://{username}.livejournal.com", "writing"),
    ("SlideShare", "https://www.slideshare.net/{username}", "writing"),
    ("Speaker Deck", "https://speakerdeck.com/{username}", "writing"),
    ("Scribd", "https://www.scribd.com/user/{username}/", "writing"),
    ("Issuu", "https://issuu.com/{username}", "writing"),
    ("Steam", "https://steamcommunity.com/id/{username}", "gaming"),
    ("itch.io", "https://{username}.itch.io/", "gaming"),
    ("Speedrun.com", "https://www.speedrun.com/user/{username}", "gaming"),
    ("osu!", "https://osu.ppy.sh/users/{username}", "gaming"),
    ("Chess.com", "https://www.chess.com/member/{username}", "gaming"),
    ("Lichess", "https://lichess.org/@/{username}", "gaming"),
    ("Kongregate", "https://www.kongregate.com/accounts/{username}", "gaming"),
    ("Newgrounds", "https://{username}.newgrounds.com", "gaming"),
    ("Hacker News", "https://news.ycombinator.com/user?id={username}", "community"),
    ("Lobsters", "https://lobste.rs/u/{username}", "community"),
    ("Metafilter", "https://www.metafilter.com/user/{username}", "community"),
    ("MyAnimeList", "https://myanimelist.net/profile/{username}", "community"),
    ("AniList", "https://anilist.co/user/{username}/", "community"),
    ("Trakt", "https://trakt.tv/users/{username}", "community"),
    ("Letterboxd", "https://letterboxd.com/{username}", "community"),
    ("BoardGameGeek", "https://boardgamegeek.com/user/{username}", "community"),
    ("Etsy", "https://www.etsy.com/shop/{username}", "shopping"),
    ("eBay", "https://www.ebay.com/usr/{username}", "shopping"),
    ("Redbubble", "https://www.redbubble.com/people/{username}", "shopping"),
    ("Gumroad", "https://gumroad.com/{username}", "shopping"),
    ("Ko-fi", "https://ko-fi.com/{username}", "shopping"),
    ("Fiverr", "https://www.fiverr.com/{username}", "shopping"),
    ("Upwork", "https://www.upwork.com/freelancers/~{username}", "shopping"),
    ("Freelancer", "https://www.freelancer.com/u/{username}", "shopping"),
    ("Grailed", "https://www.grailed.com/{username}", "shopping"),
    ("Depop", "https://www.depop.com/{username}", "shopping"),
    ("Vinted", "https://www.vinted.com/members/{username}", "shopping"),
    ("OpenSea", "https://opensea.io/{username}", "shopping"),
    ("TradingView", "https://www.tradingview.com/u/{username}", "shopping"),
    ("Brilliant", "https://brilliant.org/profile/{username}/", "learning"),
    ("Memrise", "https://www.memrise.com/user/{username}/", "learning"),
    ("Untappd", "https://untappd.com/user/{username}", "lifestyle"),
    ("Vivino", "https://www.vivino.com/users/{username}", "lifestyle"),
    ("AllTrails", "https://www.alltrails.com/members/{username}", "lifestyle"),
    ("Tripadvisor", "https://www.tripadvisor.com/members/{username}", "lifestyle"),
    ("RateBeer", "https://www.ratebeer.com/user/{username}/", "lifestyle"),
    ("Pinterest", "https://www.pinterest.com/{username}/", "design"),
    ("Flipboard", "https://flipboard.com/@{username}", "media"),
)


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #


def slugify(name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_")
    return slug or "site"


def host_of(url: str) -> str:
    """Comparable host, minus ``www.``, plus the path when the host is templated."""
    parts = urlsplit(url)
    host = (parts.netloc or parts.path).lower()
    if host.startswith("www."):
        host = host[4:]
    return host


def clean_marker(raw: object) -> str:
    """Strip markup and collapse whitespace: markers match de-tagged text.

    The upstream dataset stores some signatures as raw HTML fragments
    (``<title>404 Not Found</title>``). ``notfound.normalise_text`` removes tags
    before matching, so a marker that still contains them could never match.
    """
    text = _TAGS.sub(" ", str(raw or ""))
    text = text.replace("&nbsp;", " ").replace("&amp;", "&").replace("&#39;", "'")
    text = _SPACES.sub(" ", text).strip().lower()
    return text


def is_adult(name: str, url: str) -> bool:
    """Adult sites are noisier than their detector suggests, so they are flagged
    separately: the upstream ``isNSFW`` flag covers only a fraction of them.

    Age walls, regional blocks and cloaking mean an adult site will answer
    "not found" to almost anything, so its results are the least trustworthy in
    the catalogue regardless of how good its signature looks on paper.
    """
    haystack = f"{name} {url}".lower()
    return any(hint in haystack for hint in _ADULT_HINTS)


def guess_category(name: str, url: str) -> str:
    haystack = f"{name} {url}".lower()
    for category, hints in _CATEGORY_HINTS:
        if any(hint in haystack for hint in hints):
            return category
    return "general"


def noise(site: dict) -> int:
    """How likely this source is to cry wolf. Higher = noisier = higher tier."""
    score = _DETECTOR_NOISE.get(site.get("detector", "status"), 6)
    score += _CONF_NOISE.get(site.get("confidence_found", "low"), 2)
    if site.get("_nsfw"):
        # An age wall swamps everything else: the site may answer "not found" to
        # every request no matter how good its signature looks on paper, so this
        # penalty has to outweigh a strong detector rather than merely nudge it.
        score += 6
    if site.get("_url_probe"):
        score += 2
    if site.get("_weak_marker"):
        score += 1
    if site.get("_protected"):
        score += 2
    if not site.get("enabled_by_default", True):
        score += 3
    return score


def spread(sites: list[dict], low: int, high: int) -> None:
    """Assign tiers across ``low..high``, least-noisy first, evenly."""
    span = high - low + 1
    ordered = sorted(sites, key=lambda site: (noise(site), site["id"]))
    total = len(ordered)
    for index, site in enumerate(ordered):
        site["tier"] = low + (index * span // total) if total else low
        site["weight"] = 400 + site["tier"] * 6


def strip_private(site: dict) -> dict:
    return {key: value for key, value in site.items() if not key.startswith("_")}


# --------------------------------------------------------------------------- #
# conversion
# --------------------------------------------------------------------------- #


def convert_upstream(
    upstream: dict, known_hosts: set[str], known_ids: set[str]
) -> list[dict]:
    """Map the upstream dataset onto this project's site-spec schema."""
    converted: list[dict] = []
    for name, entry in upstream.items():
        if name.startswith("$"):
            continue
        raw_url = (entry.get("url") or "").replace("{}", "{username}")
        if "{username}" not in raw_url:
            continue
        if urlsplit(raw_url).scheme not in ("http", "https"):
            continue

        host = host_of(raw_url)
        site_id = f"{slugify(name)}_user"
        if host in known_hosts or site_id in known_ids:
            continue  # the curated entry wins; it is the reviewed one

        homepage = str(entry.get("urlMain") or raw_url)
        adult = is_adult(name, homepage)

        error_type = entry.get("errorType", "status_code")
        detector = "status"
        confidence = "low"
        not_found_marker = ""
        absent_redirect_markers: list[str] = []
        weak_marker = False

        if error_type == "message":
            marker = clean_marker(entry.get("errorMsg") or "")
            if len(marker) >= MIN_MARKER_LEN:
                detector = "absence"
                confidence = "medium"
                not_found_marker = marker
                weak_marker = len(marker) < 25
            # too-short phrases fall through to status-only: a weak phrase would
            # match real profiles and manufacture false negatives
        elif error_type == "response_url":
            path = urlsplit(str(entry.get("errorUrl") or "")).path
            # a root-level 'no such user' redirect is indistinguishable from a
            # redirect anywhere else, so only a real path is worth recording
            if path and path.strip("/"):
                absent_redirect_markers = [path]

        site: dict = {
            "id": site_id,
            "name": name,
            "url": raw_url,
            "category": "adult" if adult else guess_category(name, homepage),
            "detector": detector,
            "confidence_found": confidence,
            "_nsfw": adult or bool(entry.get("isNSFW")),
            "_url_probe": bool(entry.get("urlProbe")),
            "_weak_marker": weak_marker,
        }
        if not_found_marker:
            site["not_found_marker"] = not_found_marker
        if absent_redirect_markers:
            site["absent_redirect_markers"] = absent_redirect_markers
        note = f"Converted from the public {name} profile-URL dataset; not verified here."
        if site["_nsfw"]:
            note += " Adult site: age walls make every answer unreliable."
        site["notes"] = note
        converted.append(site)
        known_hosts.add(host)
        known_ids.add(site_id)
    return converted


def convert_wmn(
    upstream: dict, known_hosts: set[str], known_ids: set[str]
) -> list[dict]:
    """Map the WhatsMyName dataset onto this project's schema.

    This dataset carries both directions — the phrase a *real* profile shows
    (``e_string``) and the phrase a *missing* one shows (``m_string``) — which
    is what makes a ``marker`` detector possible: the probe can require positive
    evidence instead of inferring from the absence of a negative. When neither
    phrase matches, the source reports an ambiguous error rather than guessing,
    so these entries fail loudly instead of inventing hits.
    """
    converted: list[dict] = []
    for entry in upstream.get("sites", []):
        raw_url = str(entry.get("uri_check") or "").replace("{account}", "{username}")
        if "{username}" not in raw_url:
            continue
        if urlsplit(raw_url).scheme not in ("http", "https"):
            continue

        host = host_of(raw_url)
        name = str(entry.get("name") or "").strip()
        site_id = f"{slugify(name)}_user"
        if not name or host in known_hosts or site_id in known_ids:
            continue

        found_marker = clean_marker(entry.get("e_string") or "")
        missing_marker = clean_marker(entry.get("m_string") or "")
        if len(found_marker) < MIN_FOUND_MARKER_LEN:
            found_marker = ""
        if len(missing_marker) < MIN_MARKER_LEN:
            missing_marker = ""

        if found_marker:
            detector, confidence = "marker", "medium"
        elif missing_marker:
            detector, confidence = "absence", "medium"
        else:
            detector, confidence = "status", "low"

        protection = [str(item) for item in entry.get("protection") or []]
        # the upstream category is incomplete: some adult sites arrive tagged as
        # plain "social", so the name/host check has the last word
        adult = is_adult(name, raw_url)
        category = (
            "adult"
            if adult
            else _WMN_CATEGORIES.get(str(entry.get("cat") or "").strip().lower(), "general")
        )

        site: dict = {
            "id": site_id,
            "name": name,
            "url": raw_url,
            "category": category,
            "detector": detector,
            "confidence_found": confidence,
            "_nsfw": adult,
            "_url_probe": False,
            "_protected": bool(protection),
            "_weak_marker": bool(missing_marker) and len(missing_marker) < 25,
        }
        if found_marker:
            site["found_marker"] = found_marker
        if missing_marker:
            site["not_found_marker"] = missing_marker
        note = "Converted from the public WhatsMyName dataset; not verified here."
        if protection:
            note += f" Site is known to answer with: {', '.join(sorted(set(protection)))}."
        if adult:
            note += " Adult site: age walls make every answer unreliable."
        site["notes"] = note
        converted.append(site)
        known_hosts.add(host)
        known_ids.add(site_id)
    return converted


def convert_any(data: dict, known_hosts: set[str], known_ids: set[str]) -> list[dict]:
    """Dispatch on shape: a list of ``sites`` is WhatsMyName, a keyed dict is not."""
    if isinstance(data.get("sites"), list):
        return convert_wmn(data, known_hosts, known_ids)
    return convert_upstream(data, known_hosts, known_ids)


def convert_extra(known_hosts: set[str], known_ids: set[str]) -> list[dict]:
    """Hand-authored additions, all status-only and all unverified."""
    converted: list[dict] = []
    for name, url, category in EXTRA:
        host = host_of(url)
        site_id = f"{slugify(name)}_user"
        if host in known_hosts or site_id in known_ids:
            continue
        converted.append(
            {
                "id": site_id,
                "name": name,
                "url": url,
                "category": category,
                "detector": "status",
                "confidence_found": "low",
                "notes": (
                    "Hand-authored profile-URL pattern, not verified by probing. "
                    "Status-code-only: a hit means the URL resolves, not that the "
                    "account is real."
                ),
            }
        )
        known_hosts.add(host)
        known_ids.add(site_id)
    return converted


# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def build(upstreams: list[Path]) -> dict:
    current = load(SITES_FILE)
    sites = current.get("sites", [])

    if upstreams:
        # a fresh upstream run replaces the catalogue half, keeps the curated half
        sites = [site for site in sites if site.get("tier", 1) <= CURATED_TIERS[1]]

    curated = [site for site in sites if site.get("tier", 1) <= CURATED_TIERS[1]]
    catalogue = [site for site in sites if site.get("tier", 1) > CURATED_TIERS[1]]

    known_hosts = {host_of(site["url"]) for site in curated + catalogue}
    known_ids = {site["id"] for site in curated + catalogue}

    if upstreams:
        fresh: list[dict] = []
        for path in upstreams:
            data = load(path)
            data.pop("$schema", None)
            fresh += convert_any(data, known_hosts, known_ids)
        # hand-authored additions last, deduped against everything so far
        fresh += convert_extra(known_hosts, known_ids)
        catalogue = fresh

    for site in catalogue:
        site.setdefault("detector", "status")
        site.setdefault("confidence_found", "low")

    spread(curated, *CURATED_TIERS)
    spread(catalogue, *CATALOGUE_TIERS)

    ordered = sorted(curated + catalogue, key=lambda site: (site["tier"], site["id"]))
    ordered = [strip_private(site) for site in ordered]

    provenance = current.get("provenance", {})
    provenance.update(
        {
            "signatures_verified_on": None,
            "catalogue": {
                "curated_tiers": "1-3",
                "catalogue_tiers": "4-15",
                "upstream": "public community-maintained profile-URL dataset (Sherlock)",
                "upstream_url": (
                    "https://github.com/sherlock-project/sherlock/blob/master/"
                    "sherlock_project/resources/data.json"
                ),
                "verified": False,
                "note": (
                    "Curated entries are authored and reviewed by hand. Catalogue "
                    "entries are bulk-converted from the upstream dataset above and "
                    "were NOT verified by probing the sites: their URL templates and "
                    "not-found phrases are believed correct, not known correct. "
                    "Tiers order sources by a documented noise score (detector, "
                    "confidence claim, non-profile probe URL, adult site, weak "
                    "phrase), so a higher mode adds the least noisy sources first."
                ),
            },
        }
    )

    return {
        "schema": current.get("schema", "d3ta1l3r/sites/1"),
        "description": current.get("description", ""),
        "provenance": provenance,
        "sites": ordered,
    }


def report(data: dict) -> str:
    lines = []
    by_tier: dict[int, int] = {}
    for site in data["sites"]:
        by_tier[site["tier"]] = by_tier.get(site["tier"], 0) + 1
    running = 0
    lines.append(f"{'mode':>4}  {'sources':>7}  {'enabled':>7}  what it adds")
    for mode in range(1, 16):
        running += by_tier.get(mode, 0)
        enabled = sum(
            1 for site in data["sites"] if site["tier"] <= mode and site.get("enabled_by_default", True)
        )
        lines.append(f"{mode:>4}  {running:>7}  {enabled:>7}  +{by_tier.get(mode, 0)}")
    lines.append("")
    lines.append(f"total: {len(data['sites'])} sites")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--upstream",
        type=Path,
        action="append",
        default=[],
        help="upstream dataset JSON (repeatable; format detected by shape)",
    )
    parser.add_argument("--out", type=Path, default=SITES_FILE, help="where to write")
    parser.add_argument("--report", action="store_true", help="print the mode table and exit")
    parser.add_argument("--dry-run", action="store_true", help="do not write")
    args = parser.parse_args(argv)

    data = build(args.upstream)
    print(report(data))

    if args.report or args.dry_run:
        return 0
    args.out.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"\nwrote {len(data['sites'])} sites to {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
