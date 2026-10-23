"""Source plugins.

A *source* is one place the tool knows how to ask a question about one
identifier. Two flavours ship in the box:

* :class:`~d3ta1l3r.sources.probe.UsernameProbeSource` — a signature-driven
  public-page probe (the "is this handle registered here?" check). The site
  list lives in ``d3ta1l3r/data/sites.json`` and is data, not code.
* :class:`~d3ta1l3r.sources.api.ApiSource` subclasses — typed clients for
  public, unauthenticated JSON APIs that return structured records
  (GitHub, Bluesky, Hacker News, npm, PyPI, …).

Add your own by subclassing the appropriate base and registering it in
:func:`all_sources`.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover
    from .base import BaseSource

__all__ = ["all_sources"]


def all_sources(*, include_disabled: bool = True) -> list[BaseSource]:
    """Instantiate every built-in source (fresh instances, no shared state)."""
    from . import api as api_module
    from .probe import UsernameProbeSource, load_site_specs

    sources: list[BaseSource] = []
    for spec in load_site_specs(include_disabled=include_disabled):
        sources.append(UsernameProbeSource(spec))
    sources.extend(api_module.build_api_sources())
    return sources
