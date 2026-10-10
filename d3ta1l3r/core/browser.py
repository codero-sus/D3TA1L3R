"""A browser-shaped request profile, and what it deliberately does not do.

Many public pages answer a bare HTTP client with a bot wall, a CAPTCHA or a
stripped-down document, while answering a normal navigation request with the
public profile a human would see. :class:`BrowserProfile` sends the headers a
real navigation sends — ``Sec-Fetch-*``, ``Upgrade-Insecure-Requests``,
``Accept-Language``, a compression hint, a keep-alive hint and an
``Origin``/``Referer`` on the second request to a host — so a self-audit sees
what the operator sees in their own browser.

What this is **not**, and what the code enforces:

* **Not a signature forge.** The TLS handshake, HTTP/2 fingerprint and header
  *order* stay whatever httpx produces. Sites that fingerprint at that layer
  still see a script, which is the honest answer to "am I being evaded?".
* **Not identity rotation.** One profile per scan, chosen by name, no random
  re-roll per request, no proxy support, no cookie jar replay, no CAPTCHA
  handling, no login walls (those are reported as ``blocked``).
* **Not anonymous.** The ``From:`` header still carries the contact address from
  ``D3TA1L3R_UA_EMAIL`` when one is configured, so a site operator who looks can
  still tell who is asking and reach them. robots.txt and the rate limiter are
  untouched by this flag: politeness does not depend on which UA string is sent.
* **Written down.** The profile used is recorded in every report
  (``browser_profile``) and named in the console, so a scan cannot quietly be a
  different scan than the one that was asked for.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from ..errors import ConfigError

__all__ = [
    "BROWSER_PROFILES",
    "DEFAULT_PROFILE",
    "BrowserProfile",
    "profile_headers",
    "profile_names",
    "resolve_profile",
]

DEFAULT_PROFILE = "chrome"
_ACCEPT = (
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,"
    "image/webp,*/*;q=0.8"
)
_ACCEPT_LANGUAGE = "en-US,en;q=0.9"


@dataclass(frozen=True, slots=True)
class BrowserProfile:
    """One named, fixed set of navigation headers — never randomised per request."""

    name: str
    user_agent: str
    accept: str = _ACCEPT
    accept_language: str = _ACCEPT_LANGUAGE
    extra: Mapping[str, str] = field(default_factory=dict)

    @property
    def description(self) -> str:
        """A one-line, non-secret summary for reports and logs."""
        return f"{self.name} ({self.user_agent.split(' ')[0]}…)"

    def headers(
        self,
        *,
        url: str | None = None,
        accept: str | None = None,
        contact: str = "",
        navigate: bool = False,
        referer: str = "",
    ) -> dict[str, str]:
        """Headers for one request.

        ``navigate`` marks the first request to a host as a document navigation;
        later requests to the same host drop ``Upgrade-Insecure-Requests`` and
        ``Sec-Fetch-*`` and may carry a ``Referer``, which is what a browser does
        when a page pulls a subresource or a visitor clicks through.
        """
        headers: dict[str, str] = {
            "User-Agent": self.user_agent,
            "Accept": accept or self.accept,
            "Accept-Language": self.accept_language,
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
            "DNT": "1",
        }
        headers.update(self.extra)
        if navigate:
            headers["Upgrade-Insecure-Requests"] = "1"
            headers["Sec-Fetch-Dest"] = "document"
            headers["Sec-Fetch-Mode"] = "navigate"
            headers["Sec-Fetch-Site"] = "none"
            headers["Sec-Fetch-User"] = "?1"
            headers["Priority"] = "u=0, i"
        else:
            headers["Sec-Fetch-Dest"] = "empty"
            headers["Sec-Fetch-Mode"] = "no-cors"
            headers["Sec-Fetch-Site"] = "same-origin"
        if referer:
            headers["Referer"] = referer
        if contact:
            # RFC 9110 §10.1.2: a contact address for the automated client. Kept
            # because the point is to be reachable, not to be unrecognisable.
            headers["From"] = contact
        return headers


BROWSER_PROFILES: dict[str, BrowserProfile] = {
    "chrome": BrowserProfile(
        name="chrome",
        user_agent=(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36"
        ),
        extra={
            "sec-ch-ua": '"Chromium";v="133", "Not(A:Brand";v="24", "Google Chrome";v="133"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
        },
    ),
    "firefox": BrowserProfile(
        name="firefox",
        user_agent=(
            "Mozilla/5.0 (X11; Linux x86_64; rv:135.0) Gecko/20100101 Firefox/135.0"
        ),
        accept="text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        extra={"DNT": "1", "Sec-GPC": "1"},
    ),
    "safari": BrowserProfile(
        name="safari",
        user_agent=(
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
            "(KHTML, like Gecko) Version/18.3 Safari/605.1.15"
        ),
    ),
    "edge": BrowserProfile(
        name="edge",
        user_agent=(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36 Edg/133.0.0.0"
        ),
        extra={
            "sec-ch-ua": '"Chromium";v="133", "Not(A:Brand";v="24", "Microsoft Edge";v="133"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
        },
    ),
}


def profile_names() -> list[str]:
    return sorted(BROWSER_PROFILES)


def resolve_profile(name: str | bool | None) -> BrowserProfile | None:
    """``True``/``"default"`` → Chrome; a name → that profile; off otherwise."""
    if name in (None, False, "", "off"):
        return None
    if name is True or name in ("default", "auto"):
        return BROWSER_PROFILES[DEFAULT_PROFILE]
    key = str(name).strip().lower()
    if key not in BROWSER_PROFILES:
        raise ConfigError(
            f"unknown browser profile {name!r}; choose from {', '.join(profile_names())} or off"
        )
    return BROWSER_PROFILES[key]


def profile_headers(profile: BrowserProfile, **kwargs: Any) -> dict[str, str]:
    """Convenience wrapper so callers do not import the dataclass to use it."""
    return profile.headers(**kwargs)
