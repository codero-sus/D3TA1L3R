"""Recognising a "user not found" page, and refusing to guess about it.

An unknown profile usually still returns ``200 OK`` with an apologetic page:
``User Not Found``, ``This account doesn't exist``, ``Sorry, nobody on Reddit
goes by that name``. Treating every 200 as a hit would make the tool useless, so
the probe detector consults this registry.

The rules, in order:

1. **A site-specific phrase in the spec wins.** ``data/sites.json`` already
   carries ``not_found_marker`` per site; nothing here overrides it.
2. **Otherwise, generic phrasing.** The table below covers the common shapes:
   "user not found", "no such user", "doesn't exist", "couldn't find", "page not
   available", and so on. Matching is case-insensitive and whitespace-tolerant,
   because the same sentence arrives with different markup and spacing.
3. **Anything ambiguous is reported as a gap, not as a hit.** ``Sorry, this
   page isn't available`` also appears on dead posts and suspended accounts, so
   :data:`AMBIGUOUS_PHRASES` yields ``UNKNOWN`` with the phrase quoted in the
   reason — the operator can look at the URL and decide. A tool that silently
   converts "not sure" into "found you!" is worse than one that asks.

Every phrase carries its own evidence line, so a report can say *which* sentence
decided the outcome. The phrase list is data, pinned by tests, and deliberately
short: broad patterns ("error", "oops") would turn false positives into
false negatives without anyone noticing.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Literal

__all__ = [
    "AMBIGUOUS_PHRASES",
    "GENERIC_NOT_FOUND_PHRASES",
    "NotFoundVerdict",
    "classify_page",
    "find_phrase",
    "normalise_text",
    "phrase_registry",
]

Kind = Literal["absent", "ambiguous"]

#: Phrases that mean "this account does not exist" on the sites that use them.
#: Ordered longest-first at match time so the most specific wording is reported.
GENERIC_NOT_FOUND_PHRASES: tuple[str, ...] = (
    "user not found",
    "username not found",
    "profile not found",
    "account not found",
    "user does not exist",
    "user doesn't exist",
    "user doesnt exist",
    "account does not exist",
    "account doesn't exist",
    "account doesnt exist",
    "this account was not found",
    "no such user",
    "no user with that name",
    "no user found",
    "could not find that user",
    "couldn't find that user",
    "couldnt find that user",
    "could not find this user",
    "we couldn't find",
    "we couldnt find",
    "searched for user not found",
    "nobody on reddit goes by that name",
    "this page could not be found",
    "this page isn't available",
    "this page is not available",
    "the page you requested was not found",
    "profile unavailable",
    "member not found",
    "channel not found",
    "player not found",
    "the specified profile could not be found",
    "page not found",
    "404 not found",
)

#: Phrasing that *also* covers deleted content, suspended accounts and private
#: profiles — and sometimes bots. Reported as a gap with the phrase attached.
AMBIGUOUS_PHRASES: tuple[str, ...] = (
    "nothing here",
    "sorry, this content isn't available",
    "this content isn't available right now",
    "this account is private",
    "this profile is private",
    "account suspended",
    "account has been suspended",
    "temporarily unavailable",
    "are you a robot",
    "verify you are human",
    "checking your browser",
    "attention required",
    "access denied",
    "unusual traffic",
)

_WHITESPACE = re.compile(r"\s+")
_TAGS = re.compile(r"<[^>]+>")
_SCRIPTS = re.compile(r"<(script|style)\b.*?</\1>", re.IGNORECASE | re.DOTALL)


def normalise_text(body: str, *, limit: int = 400_000) -> str:
    """Lowercase, de-tag, collapse whitespace so phrases match across markup.

    Script and style blocks are removed first: a not-found phrase inside a JSON
    blob or a template string is common, and matching it would turn a live
    profile into a false negative.
    """
    text = (body or "")[:limit]
    text = _SCRIPTS.sub(" ", text)
    text = _TAGS.sub(" ", text)
    text = text.replace("&nbsp;", " ").replace("&#39;", "'").replace("&amp;", "&")
    return _WHITESPACE.sub(" ", text).lower().strip()


def find_phrase(haystack: str, phrases: tuple[str, ...]) -> str | None:
    """The longest phrase present in ``haystack`` (already normalised), if any."""
    for phrase in sorted(phrases, key=len, reverse=True):
        if phrase in haystack:
            return phrase
    return None


@dataclass(frozen=True, slots=True)
class NotFoundVerdict:
    """What the page said, if anything, and how sure the detector is about it."""

    kind: Kind
    phrase: str
    evidence: str

    @property
    def certain(self) -> bool:
        return self.kind == "absent"

    def to_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "phrase": self.phrase, "evidence": self.evidence}


def classify_page(body: str, *, markers: tuple[str, ...] = ()) -> NotFoundVerdict | None:
    """Classify a page body. ``None`` means "no opinion — keep looking".

    ``markers`` are the site's own phrases from ``sites.json`` and are checked
    first, because a hand-written marker is better evidence than a generic one.
    """
    haystack = normalise_text(body)
    own = find_phrase(haystack, tuple(markers))
    if own:
        return NotFoundVerdict(
            kind="absent",
            phrase=own,
            evidence=f"the page contains the site's own not-found signature {own!r}",
        )
    generic = find_phrase(haystack, GENERIC_NOT_FOUND_PHRASES)
    if generic:
        return NotFoundVerdict(
            kind="absent",
            phrase=generic,
            evidence=f"the page contains the not-found phrase {generic!r}",
        )
    ambiguous = find_phrase(haystack, AMBIGUOUS_PHRASES)
    if ambiguous:
        return NotFoundVerdict(
            kind="ambiguous",
            phrase=ambiguous,
            evidence=(
                f"the page says {ambiguous!r}, which can mean a missing profile, a "
                "suspended account, a private profile or a bot check — this is a gap, "
                "not an answer"
            ),
        )
    return None


def phrase_registry() -> dict[str, list[str]]:
    """The whole table, for `d3ta1l3r sources --not-found-phrases` and the docs."""
    return {
        "absent": list(GENERIC_NOT_FOUND_PHRASES),
        "ambiguous": list(AMBIGUOUS_PHRASES),
    }
