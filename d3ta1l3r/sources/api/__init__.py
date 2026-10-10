"""Typed clients for public, unauthenticated JSON APIs.

These sources are the backbone of the tool's accuracy. Where a site publishes a
public API, the response *is* the account record, which is why API hits can be
labelled ``confirmed`` while HTML-probe hits cannot. No API key is ever
required; endpoints that need OAuth are shipped disabled with a note instead of
being worked around.

Every request in this package:

* goes through the same :class:`~d3ta1l3r.core.http.Fetcher` (robots, rate
  limits, SSRF guard, size caps, retries), and
* reads only fields that the operator's own account page also shows.
"""

from __future__ import annotations

from .base import ApiSource, JsonResult, dig, name_matches, name_tokens, take

__all__ = [
    "ApiSource",
    "JsonResult",
    "build_api_sources",
    "dig",
    "name_matches",
    "name_tokens",
    "take",
]


def build_api_sources() -> list:
    """Instantiate every API source, ordered for the engine."""
    from . import dev, identity, knowledge, social

    sources: list = []
    for module in (dev, identity, social, knowledge):
        sources.extend(module.build())
    return sources
