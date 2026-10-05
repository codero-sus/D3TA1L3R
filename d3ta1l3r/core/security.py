"""Input validation and SSRF guards.

Two jobs:

1. **Validate identifiers** so a typo cannot turn a self-audit into a malformed
   crawl (and so nothing resembling a URL, a list of people, or a query
   injection ever reaches a template).
2. **Keep every request on the public internet.** A scanner that will happily
   fetch ``http://169.254.169.254/`` or ``http://localhost:8080/`` is an SSRF
   gadget, not a tool. Every URL — including every redirect hop and every
   user-supplied template — is checked against the guard in
   :func:`assert_public_url`.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from urllib.parse import quote, urljoin, urlsplit

from ..errors import ForbiddenTargetError, UsageError

__all__ = [
    "MASKED_EMAIL_RE",
    "assert_public_url",
    "is_public_host",
    "mask_email",
    "redact",
    "registrable_domain",
    "render_template",
    "validate_category",
    "validate_domain",
    "validate_email",
    "validate_location",
    "validate_name",
    "validate_source_id",
    "validate_template",
    "validate_username",
]

USERNAME_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,37}[A-Za-z0-9])?$")
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$")
# The curly apostrophe below is deliberate: real names and places contain it
# (O'Brien, D'Angelo), and copy-paste from a browser keeps the curly form.
NAME_RE = re.compile(r"^[^\W\d_][\w'’.\-]*(?: [^\W\d_][\w'’.\-]*){0,7}$", re.UNICODE)  # noqa: RUF001 - U+2019 is intentional
LOCATION_RE = re.compile(r"^[\w'’.\-]+(?:[ ,]+[\w'’.\-]+){0,7}$", re.UNICODE)  # noqa: RUF001 - U+2019 is intentional
SOURCE_ID_RE = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$")
PUBLIC_SUFFIX_LIKE = re.compile(r"^[a-z0-9-]+(?:\.[a-z0-9-]+)+$")
#: Hosts we are about to contact may contain underscores, because providers
#: build subdomains out of user handles (``demo_user.tumblr.com`` is real and
#: resolves). This is looser than :data:`PUBLIC_SUFFIX_LIKE` on purpose: that
#: one validates a *domain the operator typed*, this one validates a *host we
#: already decided to visit*, where being over-strict silently disables sites.
_HOSTNAME_LIKE = re.compile(r"^[a-z0-9_-]+(?:\.[a-z0-9_-]+)+$")
MASKED_EMAIL_RE = re.compile(r"\b([A-Za-z0-9._%+-]{1,2})[A-Za-z0-9._%+-]*@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b")

#: Hosts that must never be contacted even if someone adds them to a template.
_BLOCKED_SUFFIXES = (
    ".local",
    ".localhost",
    ".internal",
    ".intranet",
    ".home.arpa",
    ".lan",
    ".corp",
    ".test",
    ".invalid",
    ".example",
)
_BLOCKED_EXACT = {
    "localhost",
    "localhost.localdomain",
    "metadata",
    "metadata.google.internal",
    "instance-data",
    "169.254.169.254",
}


# ---------------------------------------------------------------------------
# identifier validation
# ---------------------------------------------------------------------------
def validate_username(value: str) -> str:
    """Normalise and validate a handle.

    Accepts an optional leading ``@`` (people paste handles that way) and
    rejects anything containing characters that could escape a URL path or
    smuggle extra parameters.
    """
    if not isinstance(value, str):
        raise UsageError("username must be a string")
    handle = value.strip()
    if handle.startswith("@"):
        handle = handle[1:]
    if not handle:
        raise UsageError("username is empty")
    if len(handle) > 39:
        raise UsageError("username is longer than 39 characters (not a valid handle)")
    if "/" in handle or "?" in handle or "#" in handle or "\\" in handle or " " in handle:
        raise UsageError(
            "username must be a bare handle: no slashes, spaces, or query characters"
        )
    if handle.startswith(".") or handle.endswith("."):
        raise UsageError("username must not start or end with a dot")
    if ".." in handle:
        raise UsageError("username must not contain consecutive dots")
    if not USERNAME_RE.match(handle):
        raise UsageError(
            "username may only contain letters, digits, '.', '_' and '-', and must "
            "start with a letter or digit"
        )
    return handle


def validate_email(value: str) -> str:
    """Validate an email address; the local part is never treated as a handle."""
    email = value.strip().lower()
    if len(email) > 254:
        raise UsageError("email is longer than 254 characters")
    if not EMAIL_RE.match(email):
        raise UsageError(f"{redact(value)!r} does not look like a valid email address")
    local, _, _domain = email.partition("@")
    if len(local) > 64 or ".." in email:
        raise UsageError(f"{redact(value)!r} does not look like a valid email address")
    return email


def validate_name(value: str) -> str:
    """Validate a personal name used for name-based lookups (never a person list)."""
    name = " ".join(value.split())
    if len(name) < 2:
        raise UsageError("name is too short")
    if len(name) > 80:
        raise UsageError("name is longer than 80 characters")
    if any(ch.isdigit() for ch in name):
        raise UsageError("name must not contain digits")
    if not NAME_RE.match(name):
        raise UsageError("name must be alphabetic words separated by spaces")
    return name


def validate_location(value: str) -> str:
    """Validate a coarse location hint such as ``Delhi, IN``."""
    location = " ".join(value.split())
    if not 1 < len(location) <= 80:
        raise UsageError("location must be between 2 and 80 characters")
    if not LOCATION_RE.match(location):
        raise UsageError("location may contain letters, digits, spaces, commas and hyphens")
    return location


def validate_domain(value: str) -> str:
    """Validate a domain the operator owns, for the RDAP registration check."""
    candidate = value.strip().lower()
    if "://" in candidate:  # tolerate a pasted URL
        candidate = urlsplit(candidate).hostname or ""
    candidate = candidate.strip().rstrip(".")
    if not candidate:
        raise UsageError("domain is empty")
    if len(candidate) > 253:
        raise UsageError("domain is longer than 253 characters")
    if not PUBLIC_SUFFIX_LIKE.match(candidate) or ".." in candidate:
        raise UsageError(f"{value!r} does not look like a registrable domain")
    if _is_ip_literal(candidate):
        raise UsageError("domain lookups need a domain name, not an IP address")
    labels = candidate.split(".")
    if any(not label or label.startswith("-") or label.endswith("-") for label in labels):
        raise UsageError(f"{value!r} does not look like a registrable domain")
    return candidate


def validate_source_id(value: str) -> str:
    source_id = value.strip().lower()
    if not SOURCE_ID_RE.match(source_id):
        raise UsageError(f"invalid source id {value!r}")
    return source_id


def validate_category(value: str) -> str:
    category = value.strip().lower()
    if not SOURCE_ID_RE.match(category):
        raise UsageError(f"invalid category {value!r}")
    return category


# ---------------------------------------------------------------------------
# templates
# ---------------------------------------------------------------------------
_ALLOWED_PLACEHOLDERS = {"username", "email", "name", "domain"}


def validate_template(template: str, identifier: str) -> str:
    """Validate a custom URL template and fill it with one identifier.

    Templates may reference exactly one placeholder (``{username}``,
    ``{email}``, ``{name}`` or ``{domain}``). The placeholder is a single
    scalar — there is no way to smuggle a list of people, a file path, or a
    second query parameter into the request.
    """
    if not isinstance(template, str) or not template.strip():
        raise UsageError("template must be a non-empty string")
    if len(template) > 2000:
        raise UsageError("template is too long")
    found = re.findall(r"\{([A-Za-z_][A-Za-z0-9_]*)\}", template)
    unknown = sorted(set(found) - _ALLOWED_PLACEHOLDERS)
    if unknown:
        raise UsageError(
            "template contains unsupported placeholder(s): " + ", ".join(unknown)
        )
    if not found:
        raise UsageError("template must contain a placeholder such as {username}")
    if len(set(found)) > 1:
        raise UsageError("template may reference only one identifier placeholder")
    if identifier not in found:
        raise UsageError(
            f"template must reference {{{identifier}}} for this identifier type"
        )
    if template.count("{") != template.count("}"):
        raise UsageError("template contains unbalanced braces")
    return render_template(template, **{identifier: ""})  # placeholder sanity check


def render_template(template: str, **values: str) -> str:
    """Percent-encode values, then substitute them into the template."""
    encoded = {key: quote(str(val), safe="") for key, val in values.items() if val is not None}
    try:
        rendered = template.format(**encoded)
    except (KeyError, IndexError, ValueError) as exc:
        raise UsageError(f"template could not be rendered: {exc}") from exc
    if any(ch in rendered for ch in ("\n", "\r", "\x00")):
        raise UsageError("rendered URL contains control characters")
    return rendered


# ---------------------------------------------------------------------------
# host / URL guards
# ---------------------------------------------------------------------------
def registrable_domain(host: str) -> str:
    """Best-effort eTLD+1 without pulling in the public-suffix list.

    Handles the common two-label public suffixes (``co.uk``, ``com.au``, ...)
    which is what matters for "is this the same site" checks.
    """
    host = (host or "").lower().strip(".")
    if not host or _is_ip_literal(host):
        return host
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    two_label_suffixes = {
        "co.uk", "org.uk", "ac.uk", "gov.uk", "co.jp", "co.kr", "com.au", "net.au",
        "org.au", "co.nz", "com.br", "com.mx", "co.in", "com.cn", "com.tr", "co.za",
        "com.sg", "co.il", "com.ar", "co.id", "or.jp", "ne.jp", "com.tw", "com.hk",
    }
    if ".".join(labels[-2:]) in two_label_suffixes and len(labels) >= 3:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return True


def is_public_host(host: str, *, resolve: bool = False) -> bool:
    """Return ``True`` only for hosts that are unambiguously on the public internet.

    With ``resolve=True`` every A/AAAA record is checked too (DNS-rebinding
    defence); unresolvable hosts are treated as non-public.
    """
    host = (host or "").strip().lower().rstrip(".")
    if not host or host in _BLOCKED_EXACT:
        return False
    if any(host == suffix.lstrip(".") or host.endswith(suffix) for suffix in _BLOCKED_SUFFIXES):
        return False
    if _is_ip_literal(host):
        return _is_global_ip(host)

    if "." not in host:
        return False  # single-label names are internal by construction
    if not _HOSTNAME_LIKE.match(host):
        return False

    if not resolve:
        return True
    try:
        infos = socket.getaddrinfo(host, None)
    except (socket.gaierror, UnicodeError, OSError):
        return False
    addresses = {info[4][0] for info in infos}
    return bool(addresses) and all(_is_global_ip(addr) for addr in addresses)


def _is_global_ip(raw: str) -> bool:
    try:
        ip = ipaddress.ip_address(raw.split("%")[0])
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return ip.is_global and not (
        ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved
    )


def assert_public_url(url: str, *, resolve: bool = True, base: str | None = None) -> str:
    """Raise :class:`ForbiddenTargetError` unless ``url`` is public HTTP(S).

    Returns the normalised URL. Call this for *every* URL before it hits the
    network — initial requests, custom templates and each redirect hop.
    """
    candidate = urljoin(base, url) if base else url
    parts = urlsplit(candidate)
    if parts.scheme not in {"http", "https"}:
        raise ForbiddenTargetError(f"refusing non-HTTP(S) URL scheme: {parts.scheme or '(none)'}")
    host = parts.hostname
    if not host:
        raise ForbiddenTargetError(f"refusing URL without a host: {redact(candidate)}")
    if parts.username or parts.password:
        raise ForbiddenTargetError("refusing URL containing embedded credentials")
    if not is_public_host(host, resolve=resolve):
        raise ForbiddenTargetError(
            f"refusing to contact non-public host {host!r} (SSRF guard)"
        )
    return candidate


def redact(value: str, *, keep: int = 2) -> str:
    """Mask an email-looking string; used in messages that may be logged."""
    if not value:
        return ""
    return MASKED_EMAIL_RE.sub(lambda m: f"{m.group(1)[:keep]}***@{m.group(2)}", value)


def mask_email(email: str) -> str:
    local, _, domain = email.partition("@")
    if not domain:
        return "***"
    masked = (local[:2] + "***") if len(local) > 2 else "***"
    return f"{masked}@{domain}"
