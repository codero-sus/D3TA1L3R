"""The fifteen breadth modes: coverage bought with false positives.

Every source in ``data/sites.json`` carries a **tier** from 1 to 15, and a scan
run at mode ``N`` probes every source whose tier is ``<= N``. That is the whole
mechanism. It exists to make an unavoidable trade-off something the operator
chooses in the open rather than something buried in the data:

* **mode 1** — a small set of curated, high-signal sources. Narrow, and the
  least likely to tell you about a profile that is not yours.
* **mode 3** — the full curated core. This is the default and the historical
  behaviour: every source this project authors and reviews by hand.
* **mode 15** — the entire catalogue, 600+ sites. The widest reach this tool
  has, and by a wide margin the most likely to produce false positives.

The tier numbers are not decoration. Within the curated core (tiers 1-3) and
again within the bulk catalogue (tiers 4-15), sources are ordered by a
documented noise score: how reliable the detector is, how strong its confidence
claim is, whether the site needs a non-profile probe URL, whether its not-found
phrase is weak. Raising the mode therefore always adds the *least* noisy
sources first — mode 4 is not a random slice of the catalogue, it is the
catalogue's best-behaved entries.

Everything at tier 4 and above is unverified. The URL templates and not-found
phrases come from a public, community-maintained dataset rather than from this
project probing the sites, so they are believed correct but are not known
correct, and the confidence claims are set accordingly: a status-code-only
probe claims ``low``, never more.

Verifying what a broad mode dredges up is the other half of the bargain, and it
is where a local model earns its keep — so from :data:`LLM_RECOMMENDED_FROM`
upward this tool recommends handing ambiguous hits to a locally hosted LLM.
Only local: Cortex LLMHoster or Ollama, on your own machine. Never a hosted
API — a tool whose job is to find your accounts has no business describing
them to somebody else's computer.
"""

from __future__ import annotations

from dataclasses import dataclass

__all__ = [
    "DEFAULT_MODE",
    "LLM_RECOMMENDED_FROM",
    "LOCAL_LLMS",
    "MAX_MODE",
    "MIN_MODE",
    "LocalLlm",
    "false_positive_note",
    "includes_tier",
    "llm_recommendation",
    "mode_label",
    "summarise",
]

MIN_MODE = 1
MAX_MODE = 15
DEFAULT_MODE = 3
"""The default: the curated core, i.e. exactly what this tool scanned before
modes existed. Adding breadth is opt-in."""

LLM_RECOMMENDED_FROM = 4
"""The first mode that reaches outside the curated core, and therefore the first
mode where a local LLM is worth recommending to adjudicate the results."""


@dataclass(frozen=True, slots=True)
class LocalLlm:
    """A backend that keeps inference on the operator's own machine."""

    id: str
    name: str
    url: str
    hint: str


LOCAL_LLMS: tuple[LocalLlm, ...] = (
    LocalLlm(
        id="cortex",
        name="Cortex LLMHoster",
        url="https://github.com/codero-sus/Cortex_LLMHoster",
        hint="by codero-sus; serves llama.cpp locally on 127.0.0.1:8624",
    ),
    LocalLlm(
        id="ollama",
        name="Ollama",
        url="https://ollama.com",
        hint="runs models locally on 127.0.0.1:11434",
    ),
)


def mode_label(mode: int) -> str:
    """One-line description of what a mode buys and what it costs."""
    if mode <= 1:
        return "narrowest — curated, high-signal sources only"
    if mode <= 3:
        return "curated core — every hand-reviewed source"
    if mode == LLM_RECOMMENDED_FROM:
        return "first step outside the curated core; unverified sources begin here"
    if mode <= 8:
        return "broad — a large slice of the unverified catalogue"
    if mode <= 12:
        return "very broad — noisy detectors and weak signatures included"
    if mode < MAX_MODE:
        return "nearly everything — status-only probes included"
    return "everything — maximum reach, expect false positives"


def false_positive_note(mode: int) -> str:
    """The honest caveat for a mode, printed in reports and the dashboard."""
    if mode <= 3:
        return (
            "Sources are hand-curated, but signatures are still not live-verified: "
            "treat every hit as a lead to confirm by eye."
        )
    if mode <= 8:
        return (
            "This mode includes unverified catalogue sources. Some return HTTP 200 "
            "with a soft 'not found' page, so a hit may mean 'this URL resolves', "
            "not 'this account exists'. Confirm before you act on it."
        )
    if mode <= 12:
        return (
            "This mode includes the noisier half of the catalogue: status-code-only "
            "probes and sites whose not-found phrase is weak. Expect false positives, "
            "and verify anything you intend to act on."
        )
    return (
        "This mode probes every source in the catalogue, including the least "
        "reliable ones. False positives are expected and are not a malfunction: "
        "a hit is a lead, never a conclusion."
    )


def llm_recommendation(mode: int) -> str | None:
    """Advice to hand the results to a local model, or ``None`` below mode 4.

    Deliberately names only local backends. There is no code path here that
    could suggest a hosted API, and tests pin that.
    """
    if mode < LLM_RECOMMENDED_FROM:
        return None
    names = " or ".join(f"{llm.name} ({llm.url})" for llm in LOCAL_LLMS)
    return (
        f"Mode {mode} reaches outside the curated core. Point a local model at the "
        f"results — {names} — and let it adjudicate ambiguous hits before you "
        "trust them. Local only: never a hosted API."
    )


def includes_tier(tier: int, mode: int) -> bool:
    """Does a scan at ``mode`` probe a source sitting at ``tier``?"""
    return tier <= mode


def summarise(site_specs) -> list[dict[str, object]]:
    """Per-mode row for ``d3ta1l3r modes`` and the dashboard's coverage page.

    ``site_specs`` is any iterable of objects exposing ``tier`` and
    ``enabled_by_default`` (:class:`~d3ta1l3r.sources.probe.SiteSpec`).
    """
    tiers = [spec.tier for spec in site_specs]
    enabled = [spec.tier for spec in site_specs if spec.enabled_by_default]
    rows: list[dict[str, object]] = []
    for mode in range(MIN_MODE, MAX_MODE + 1):
        rows.append(
            {
                "mode": mode,
                "sources": sum(1 for tier in tiers if tier <= mode),
                "enabled": sum(1 for tier in enabled if tier <= mode),
                "label": mode_label(mode),
                "caveat": false_positive_note(mode),
                "llm_recommended": mode >= LLM_RECOMMENDED_FROM,
            }
        )
    return rows
