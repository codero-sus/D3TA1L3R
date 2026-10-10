"""Identity sources: Gravatar (email) and RDAP (domain).

Both are open, unauthenticated standards-based endpoints. Gravatar is the most
under-appreciated self-audit check there is: an address that was ever used with
WordPress or GitHub may still publish a profile card, complete with linked
accounts and a real photo. It is also the one check a person can *fix*, by
deleting the profile or switching to a generated avatar.
"""

from __future__ import annotations

import datetime as dt
from typing import Any

from ...models import Confidence, ScanTarget, SourceKind, SourceOutcome
from ..base import SourceMeta
from .base import ApiSource, dig, first_present

__all__ = ["build"]

_GRAVATAR_URL = "https://gravatar.com/{md5}.json"
_RDAP_URL = "https://rdap.org/domain/{domain}"


class GravatarEmail(ApiSource):
    meta = SourceMeta(
        id="gravatar_api_email",
        name="Gravatar",
        kind=SourceKind.EMAIL,
        category="identity",
        description=(
            "Gravatar profile bound to an email address: display name, photo, personal links "
            "and the list of accounts the owner linked publicly."
        ),
        docs_url="https://docs.gravatar.com/api/profiles/",
        weight=8,
    )

    def query_url(self, identifier: str) -> str:
        return _GRAVATAR_URL.format(md5=self.md5(identifier.strip().lower()))

    async def run(self, identifier: str, target: ScanTarget) -> SourceOutcome:
        started = self.now()
        url = self.query_url(identifier)
        result = await self.fetch_json(url, headers={"Accept": "application/json"})
        if not result.ok:
            # 404 => no Gravatar profile for this address (the normal, private case).
            return self.outcome_for(result, identifier=identifier, started=started)

        data = self.require_mapping(result, "Gravatar profile")
        entry = dig(data, "entry", default=[]) or []
        record = entry[0] if entry else {}
        accounts = [
            str(dig(acc, "shortname") or dig(acc, "domain") or "account")
            for acc in (dig(record, "accounts", default=[]) or [])
        ]
        urls = [
            str(dig(item, "value"))
            for item in (dig(record, "urls", default=[]) or [])
            if dig(item, "value")
        ]
        photos = [
            str(dig(item, "value"))
            for item in (dig(record, "photos", default=[]) or [])
            if dig(item, "value")
        ]

        exposure = []
        if accounts:
            exposure.append("linked accounts: " + ", ".join(accounts))
        if urls:
            exposure.append("personal URLs published")
        if photos:
            exposure.append("profile photo published")
        if dig(record, "aboutMe"):
            exposure.append("public 'about me' text")
        if dig(record, "name", "familyName") or dig(record, "name", "givenName"):
            exposure.append("real name published on the card")

        finding = self.finding(
            identifier=identifier,
            url=f"https://gravatar.com/{self.md5(identifier.strip().lower())}",
            confidence=Confidence.CONFIRMED,
            evidence=(
                "Gravatar profile API returned a public card for this address's hash"
                + (f" with {len(accounts)} linked account(s)" if accounts else "")
            ),
            title=f"Gravatar card ({dig(record, 'preferredUsername') or 'no username set'})",
            display_name=first_present(
                dig(record, "displayName"),
                " ".join(
                    part
                    for part in (dig(record, "name", "givenName"), dig(record, "name", "familyName"))
                    if part
                )
                or None,
            ),
            bio=dig(record, "aboutMe"),
            avatar_url=photos[0] if photos else None,
            location=dig(record, "currentLocation"),
            account_created_at=dig(record, "registrationDate"),
            extra=self.link_extra(
                {
                    "profile_url": dig(record, "profileUrl"),
                    "preferred_username": dig(record, "preferredUsername"),
                    "linked_accounts": accounts,
                    "urls": urls,
                    "verified_accounts": [
                        str(dig(acc, "username"))
                        for acc in (dig(record, "accounts", default=[]) or [])
                        if dig(acc, "verified") == "true" and dig(acc, "username")
                    ],
                    "exposure": exposure,
                }
            ),
        )
        return self.outcome_for(result, identifier=identifier, started=started, findings=[finding])


class RdapDomain(ApiSource):
    meta = SourceMeta(
        id="rdap_domain",
        name="RDAP (domain registration)",
        kind=SourceKind.DOMAIN,
        category="identity",
        description=(
            "Registrar and lifecycle dates for a domain you own — useful for spotting an "
            "expiry you forgot about, or a look-alike domain registered next to yours."
        ),
        docs_url="https://www.rfc-editor.org/rfc/rfc9083",
        weight=15,
    )

    def query_url(self, identifier: str) -> str:
        return _RDAP_URL.format(domain=self.quote(identifier))

    async def run(self, identifier: str, target: ScanTarget) -> SourceOutcome:
        started = self.now()
        url = self.query_url(identifier)
        result = await self.fetch_json(url, accept="application/rdap+json, application/json")
        if not result.ok:
            return self.outcome_for(result, identifier=identifier, started=started)

        data = self.require_mapping(result, "RDAP domain")
        events = {
            str(dig(event, "eventAction")): dig(event, "eventDate")
            for event in (dig(data, "events", default=[]) or [])
        }
        registrar = None
        for entity in dig(data, "entities", default=[]) or []:
            roles = [str(r).lower() for r in (dig(entity, "roles", default=[]) or [])]
            if "registrar" in roles:
                vcard = dig(entity, "vcardArray", default=[]) or []
                registrar = _vcard_value(vcard, "fn") or dig(entity, "handle")
                break

        statuses = [str(s) for s in (dig(data, "status", default=[]) or [])]
        expires = events.get("expiration")
        days_left = _days_until(expires)
        exposure = []
        if days_left is not None:
            exposure.append(
                f"registration expires in {days_left} days ({expires})"
                if days_left >= 0
                else f"registration expired {abs(days_left)} days ago ({expires})"
            )
        if statuses:
            exposure.append("EPP status: " + ", ".join(statuses))
        if registrar:
            exposure.append(f"registrar: {registrar}")

        finding = self.finding(
            identifier=identifier,
            url=f"https://{identifier}",
            confidence=Confidence.CONFIRMED,
            evidence=(
                f"RDAP returned a registration record (registered {events.get('registration', 'n/a')}, "
                f"expires {expires or 'n/a'}, registrar {registrar or 'n/a'})"
            ),
            title=f"Domain {dig(data, 'ldhName', default=identifier)}",
            account_created_at=events.get("registration"),
            extra=self.link_extra(
                {
                    "registrar": registrar,
                    "events": events,
                    "statuses": statuses,
                    "nameservers": [
                        str(dig(ns, "ldhName"))
                        for ns in (dig(data, "nameservers", default=[]) or [])
                        if dig(ns, "ldhName")
                    ],
                    "days_until_expiry": days_left,
                    "exposure": exposure,
                }
            ),
        )
        return self.outcome_for(result, identifier=identifier, started=started, findings=[finding])


def _vcard_value(vcard: Any, field: str) -> str | None:
    """Pull a value out of a jCard array, e.g. the registrar's formatted name.

    jCard layout is ``["vcard", [ ["fn", {}, "text", "Registrar Inc."], ... ]]``
    — the properties live at index 1, and older payloads omit the wrapper.
    """
    if not isinstance(vcard, list) or not vcard:
        return None
    properties = vcard[1] if len(vcard) > 1 and isinstance(vcard[1], list) else vcard
    for entry in properties:
        if isinstance(entry, list) and entry and entry[0] == field:
            value = entry[3] if len(entry) > 3 else None
            if isinstance(value, (str, int, float)):
                return str(value)
    return None


def _days_until(timestamp: str | None) -> int | None:
    if not timestamp:
        return None
    try:
        parsed = dt.datetime.fromisoformat(str(timestamp).replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return (parsed - dt.datetime.now(dt.timezone.utc)).days


def build() -> list[ApiSource]:
    return [GravatarEmail(), RdapDomain()]
