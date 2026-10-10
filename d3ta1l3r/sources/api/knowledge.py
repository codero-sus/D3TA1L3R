"""Name-based public-record sources: OpenAlex, arXiv, PubMed, ORCID, Wikipedia.

Everything here answers a *different* question from the handle lookups. It asks:
"does my name appear in public records — papers, preprints, indexed articles,
encyclopaedia entries?" That is genuinely useful before you start a job hunt or
publish under your legal name, because these records are indexed, cached and
mirrored long after you change your mind.

The results are heuristics by construction: personal names are not unique, so
every finding from this module is pinned to ``LOW`` confidence, carries a
homonym warning, and lists the matching works so a human can confirm ownership.
Two doctors named the same person are indistinguishable to an API — but not to
you.
"""

from __future__ import annotations

import os
import xml.etree.ElementTree as ET

from ...models import Confidence, ScanStatus, ScanTarget, SourceKind, SourceOutcome
from ..base import SourceMeta
from .base import ApiSource, dig, first_present, name_matches, name_tokens, take

__all__ = ["build"]

_ATOM = "{http://www.w3.org/2005/Atom}"
_OPENSEARCH = "{http://a9.com/-/spec/opensearch/1.1/}"

_HOMONYM_NOTE = (
    "Names are not unique. This is a candidate record for review, not proof that the "
    "individual is you."
)


def _polite_email() -> str | None:
    return os.environ.get("D3TA1L3R_UA_EMAIL") or None


class OpenAlexAuthor(ApiSource):
    meta = SourceMeta(
        id="openalex_api_author",
        name="OpenAlex (author search)",
        kind=SourceKind.NAME,
        category="research",
        description="Scholarly author records matching your name, with works and citation counts.",
        docs_url="https://docs.openalex.org/api-entities/authors",
        weight=300,
    )

    def query_url(self, identifier: str) -> str:
        return f"https://api.openalex.org/authors?filter=display_name.search:{identifier}&per-page=5"

    async def run(self, identifier: str, target: ScanTarget) -> SourceOutcome:
        started = self.now()
        result = await self.fetch_json(
            "https://api.openalex.org/authors",
            params={
                "filter": f"display_name.search:{identifier}",
                "per-page": 5,
                "mailto": _polite_email(),
            },
        )
        if not result.ok:
            return self.outcome_for(result, identifier=identifier, started=started)

        payload = self.require_mapping(result, "OpenAlex authors")
        records = [
            record
            for record in (dig(payload, "results", default=[]) or [])
            if name_matches(dig(record, "display_name"), identifier)
        ]
        if not records:
            return self.outcome_for(result, identifier=identifier, started=started)

        total = dig(payload, "meta", "count", default=len(records))
        findings = []
        for record in take(records, 3):
            institution = dig(record, "last_known_institutions", "0", "display_name")
            findings.append(
                self.finding(
                    identifier=identifier,
                    url=first_present(dig(record, "id"), "https://openalex.org"),
                    confidence=Confidence.LOW,
                    evidence=(
                        f"OpenAlex author '{dig(record, 'display_name')}' with "
                        f"{dig(record, 'works_count', default='?')} works and "
                        f"{dig(record, 'cited_by_count', default='?')} citations. {_HOMONYM_NOTE}"
                    ),
                    title=f"OpenAlex author: {dig(record, 'display_name')}",
                    extra=self.link_extra(
                        {
                            "works_count": dig(record, "works_count"),
                            "cited_by_count": dig(record, "cited_by_count"),
                            "institution": institution,
                            "orcid": dig(record, "orcid"),
                            "openalex_id": dig(record, "id"),
                            "homonym_warning": True,
                            "search_total": total,
                        }
                    ),
                )
            )
        return self.outcome_for(result, identifier=identifier, started=started, findings=findings)


class ArxivAuthor(ApiSource):
    meta = SourceMeta(
        id="arxiv_api_author",
        name="arXiv (author query)",
        kind=SourceKind.NAME,
        category="research",
        description="Preprints whose author field matches your name.",
        docs_url="https://info.arxiv.org/help/api/user-manual.html",
        weight=310,
    )

    def query_url(self, identifier: str) -> str:
        return f'https://export.arxiv.org/api/query?search_query=au:"{identifier}"&max_results=5'

    async def run(self, identifier: str, target: ScanTarget) -> SourceOutcome:
        started = self.now()
        query = f'au:"{identifier}"'
        result = await self.fetch_json(
            "https://export.arxiv.org/api/query",
            params={"search_query": query, "max_results": 5},
            accept="application/atom+xml",
        )
        if not result.ok:
            # arXiv returns Atom XML, so JSON parsing fails by design — read the body instead.
            response = result.response
            if response.status in (200, 201) and response.text.strip():
                return self._parse_atom(identifier, started, response.text, response.status,
                                        response.attempts, result.request_url)
            return self.outcome_for(result, identifier=identifier, started=started)
        return self._parse_atom(identifier, started, result.response.text, result.status,
                                result.response.attempts, result.request_url)

    def _parse_atom(
        self,
        identifier: str,
        started: float,
        body: str,
        status: int,
        attempts: int,
        url: str,
    ) -> SourceOutcome:
        try:
            root = ET.fromstring(body)
        except ET.ParseError as exc:
            return self._outcome(
                ScanStatus.ERROR,
                started,
                http_status=status,
                query_url=url,
                error=f"arXiv returned unparseable Atom XML: {exc}",
            )

        if root.tag != f"{_ATOM}feed":
            # arXiv serves an XHTML maintenance page with HTTP 200; XHTML parses
            # as XML, so the root tag is the only reliable tell.
            return self._outcome(
                ScanStatus.ERROR,
                started,
                http_status=status,
                query_url=url,
                error=(
                    "arXiv did not return an Atom feed "
                    f"(root element {root.tag!r}) — the API is probably in maintenance"
                ),
            )

        total_raw = root.findtext(f"{_OPENSEARCH}totalResults")
        total = int(total_raw) if total_raw and total_raw.isdigit() else 0
        titles = []
        for entry in root.findall(f"{_ATOM}entry")[:5]:
            title = (entry.findtext(f"{_ATOM}title") or "").strip().replace("\n", " ")
            link = entry.findtext(f"{_ATOM}id")
            if title:
                titles.append({"title": " ".join(title.split()), "url": link})
        if total == 0 and not titles:
            return self._outcome(
                ScanStatus.NOT_FOUND,
                started,
                http_status=status,
                query_url=url,
                error="arXiv author query returned no preprints",
            )

        finding = self.finding(
            identifier=identifier,
            url=f"https://arxiv.org/a/{identifier.replace(' ', '_')}",
            confidence=Confidence.LOW,
            evidence=(
                f"arXiv author query matched {total or len(titles)} preprint(s) for this name. "
                f"{_HOMONYM_NOTE}"
            ),
            title="arXiv preprints matching this name",
            extra={
                "total_results": total or len(titles),
                "preprints": titles,
                "homonym_warning": True,
            },
        )
        return self._outcome(
            ScanStatus.FOUND,
            started,
            findings=[finding],
            http_status=status,
            query_url=url,
            attempts=attempts,
        )


class PubMedAuthor(ApiSource):
    meta = SourceMeta(
        id="pubmed_api_author",
        name="PubMed (author query)",
        kind=SourceKind.NAME,
        category="research",
        description="PubMed/NCBI records indexed under your name as an author.",
        docs_url="https://www.ncbi.nlm.nih.gov/books/NBK25501/",
        weight=320,
    )

    def query_url(self, identifier: str) -> str:
        return "https://eutils.ncbi.nlm.nih.gov/entrez/eutils/esearch.fcgi"

    async def run(self, identifier: str, target: ScanTarget) -> SourceOutcome:
        started = self.now()
        result = await self.fetch_json(
            self.query_url(identifier),
            params={
                "db": "pubmed",
                "term": f"{identifier}[Author]",
                "retmode": "json",
                "retmax": 5,
                "tool": "d3ta1l3r",
                "email": _polite_email(),
            },
        )
        if not result.ok:
            return self.outcome_for(result, identifier=identifier, started=started)

        payload = self.require_mapping(result, "PubMed esearch")
        count = int(dig(payload, "esearchresult", "count", default=0) or 0)
        id_list = dig(payload, "esearchresult", "idlist", default=[]) or []
        if count == 0:
            return self.outcome_for(result, identifier=identifier, started=started)

        finding = self.finding(
            identifier=identifier,
            url=f"https://pubmed.ncbi.nlm.nih.gov/?term={self.quote(identifier)}%5BAuthor%5D",
            confidence=Confidence.LOW,
            evidence=(
                f"PubMed indexes {count} article(s) with this name in the author field. "
                f"{_HOMONYM_NOTE}"
            ),
            title="PubMed author records matching this name",
            extra={
                "article_count": count,
                "pmids": [str(pmid) for pmid in take(id_list, 5)],
                "pmid_urls": [f"https://pubmed.ncbi.nlm.nih.gov/{pmid}/" for pmid in take(id_list, 5)],
                "homonym_warning": True,
            },
        )
        return self.outcome_for(result, identifier=identifier, started=started, findings=[finding])


class OrcidAuthor(ApiSource):
    meta = SourceMeta(
        id="orcid_api_author",
        name="ORCID (registry search)",
        kind=SourceKind.NAME,
        category="research",
        description="ORCID researcher records matching your name (ORCID iDs are self-asserted).",
        docs_url="https://info.orcid.org/documentation/api-tutorials/",
        weight=330,
    )

    def query_url(self, identifier: str) -> str:
        return f"https://pub.orcid.org/v3.0/expanded-search/?q={self.quote(self._query(identifier))}"

    @staticmethod
    def _query(name: str) -> str:
        tokens = name_tokens(name)
        if not tokens:
            return f'"{name}"'
        if len(tokens) == 1:
            return f"family-names:{tokens[0]}"
        return f"given-names:{tokens[0]} AND family-name:{' '.join(tokens[1:])}"

    async def run(self, identifier: str, target: ScanTarget) -> SourceOutcome:
        started = self.now()
        result = await self.fetch_json(
            "https://pub.orcid.org/v3.0/expanded-search/",
            params={"q": self._query(identifier), "rows": 5},
            headers={"Accept": "application/json"},
        )
        if not result.ok:
            return self.outcome_for(result, identifier=identifier, started=started)

        payload = self.require_mapping(result, "ORCID search")
        records = [
            record
            for record in (dig(payload, "expanded-result", default=[]) or [])
            if name_matches(
                " ".join(
                    str(x)
                    for x in (dig(record, "given-names"), dig(record, "family-names"))
                    if x
                ),
                identifier,
            )
        ]
        if not records:
            return self.outcome_for(result, identifier=identifier, started=started)

        findings = []
        for record in take(records, 3):
            orcid_id = dig(record, "orcid-id")
            findings.append(
                self.finding(
                    identifier=identifier,
                    url=f"https://orcid.org/{orcid_id}",
                    confidence=Confidence.LOW,
                    evidence=(
                        f"ORCID registry returned "
                        f"'{dig(record, 'given-names')} {dig(record, 'family-names')}'"
                        + (f" at {dig(record, 'institution-name')}" if dig(record, "institution-name") else "")
                        + f". ORCID records are self-asserted. {_HOMONYM_NOTE}"
                    ),
                    title=f"ORCID {orcid_id}",
                    display_name=" ".join(
                        str(x)
                        for x in (dig(record, "given-names"), dig(record, "family-names"))
                        if x
                    ),
                    extra=self.link_extra(
                        {
                            "orcid": orcid_id,
                            "institution": dig(record, "institution-name"),
                            "homonym_warning": True,
                        }
                    ),
                )
            )
        return self.outcome_for(result, identifier=identifier, started=started, findings=findings)


class WikipediaSearch(ApiSource):
    meta = SourceMeta(
        id="wikipedia_api_search",
        name="Wikipedia (article search)",
        kind=SourceKind.NAME,
        category="research",
        description="Wikipedia articles mentioning your name — a same-name person is the likely cause.",
        docs_url="https://www.mediawiki.org/wiki/API:Search",
        weight=340,
    )

    def query_url(self, identifier: str) -> str:
        return (
            "https://en.wikipedia.org/w/api.php?action=query&list=search&format=json"
            f"&srlimit=5&srsearch={self.quote(identifier)}"
        )

    async def run(self, identifier: str, target: ScanTarget) -> SourceOutcome:
        started = self.now()
        result = await self.fetch_json(
            "https://en.wikipedia.org/w/api.php",
            params={
                "action": "query",
                "list": "search",
                "format": "json",
                "srlimit": 5,
                "srsearch": identifier,
            },
        )
        if not result.ok:
            return self.outcome_for(result, identifier=identifier, started=started)

        payload = self.require_mapping(result, "Wikipedia search")
        hits = dig(payload, "query", "search", default=[]) or []
        total = dig(payload, "query", "searchinfo", "totalhits", default=len(hits))
        if not hits:
            return self.outcome_for(result, identifier=identifier, started=started)

        titles = [
            {
                "title": dig(hit, "title"),
                "url": f"https://en.wikipedia.org/?curid={dig(hit, 'pageid')}",
            }
            for hit in take(hits, 5)
        ]
        finding = self.finding(
            identifier=identifier,
            url=f"https://en.wikipedia.org/w/index.php?search={self.quote(identifier)}",
            confidence=Confidence.LOW,
            evidence=(
                f"Wikipedia search returns {total} article(s) mentioning this name; most name "
                f"matches belong to other people. {_HOMONYM_NOTE}"
            ),
            title="Wikipedia mentions of this name",
            extra={"total_hits": total, "articles": titles, "homonym_warning": True},
        )
        return self.outcome_for(result, identifier=identifier, started=started, findings=[finding])


def build() -> list[ApiSource]:
    return [OpenAlexAuthor(), ArxivAuthor(), PubMedAuthor(), OrcidAuthor(), WikipediaSearch()]
