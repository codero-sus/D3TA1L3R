"""The fifteen breadth modes.

The mode system exists to make one trade-off explicit rather than implicit:
raising the mode buys coverage by paying in false positives. These tests pin the
properties that keep that promise honest — that the noisy sources are the *last*
ones added rather than the first, that a scan at the default mode still means
exactly what it meant before modes existed, and that "use a local model" never
quietly becomes "use somebody's API".
"""

from __future__ import annotations

import itertools
import re
from pathlib import Path

import pytest

from d3ta1l3r.config import ScanConfig
from d3ta1l3r.core.engine import ScanEngine
from d3ta1l3r.errors import ConfigError
from d3ta1l3r.modes import (
    DEFAULT_MODE,
    LLM_RECOMMENDED_FROM,
    LOCAL_LLMS,
    MAX_MODE,
    MIN_MODE,
    false_positive_note,
    includes_tier,
    llm_recommendation,
    summarise,
)
from d3ta1l3r.sources.probe import load_site_specs

ROOT = Path(__file__).resolve().parent.parent

_CLOUD = (
    "openai", "chatgpt", "anthropic", "claude.ai", "gemini.google", "openrouter",
    "groq", "together.xyz", "replicate", "bedrock", "azure openai", "mistral.ai",
    "perplexity", "cohere",
)


@pytest.fixture(scope="module")
def specs():
    return load_site_specs()


def _engine(mode: int) -> ScanEngine:
    return ScanEngine(ScanConfig(mode=mode))


class TestTiersAreWellFormed:
    def test_every_source_has_a_tier_in_range(self, specs) -> None:
        for spec in specs:
            assert MIN_MODE <= spec.tier <= MAX_MODE, spec.id

    def test_every_tier_is_populated(self, specs) -> None:
        """A tier with nothing in it makes its mode a no-op — a broken dial."""
        populated = {spec.tier for spec in specs}
        assert populated == set(range(MIN_MODE, MAX_MODE + 1))

    def test_includes_tier_is_a_plain_ceiling(self) -> None:
        assert includes_tier(1, 1)
        assert includes_tier(15, 15)
        assert not includes_tier(15, 1)
        for mode in range(MIN_MODE, MAX_MODE + 1):
            assert includes_tier(mode, mode)
            assert not includes_tier(mode + 1, mode)


class TestCoverageGrowsWithTheMode:
    def test_source_counts_increase_monotonically(self, specs) -> None:
        counts = [sum(1 for spec in specs if spec.tier <= mode) for mode in range(1, MAX_MODE + 1)]
        assert counts == sorted(counts), counts
        assert all(
            later > earlier for earlier, later in itertools.pairwise(counts)
        ), counts

    def test_mode_one_is_narrow(self, specs) -> None:
        assert sum(1 for spec in specs if spec.tier <= 1) <= 40

    def test_mode_fifteen_reaches_the_whole_catalogue(self, specs) -> None:
        assert sum(1 for spec in specs if spec.tier <= MAX_MODE) == len(specs)
        assert len(specs) >= 600, f"the wide mode should cover 600+ sites, got {len(specs)}"

    def test_the_engine_selects_more_as_the_mode_rises(self) -> None:
        counts = [len(_engine(mode).selected_sources()) for mode in range(1, MAX_MODE + 1)]
        assert counts == sorted(counts), counts
        assert counts[-1] > counts[0]

    def test_a_higher_mode_is_a_superset_of_a_lower_one(self) -> None:
        lower = {source.id for source in _engine(4).selected_sources()}
        higher = {source.id for source in _engine(9).selected_sources()}
        assert lower < higher


class TestTheDefaultIsTheCuratedCore:
    """Opting out of breadth must not change what a plain scan means."""

    def test_the_default_mode_is_three(self) -> None:
        assert ScanConfig().mode == DEFAULT_MODE == 3

    def test_no_catalogue_source_runs_at_the_default(self, specs) -> None:
        """A default scan must not quietly start probing unverified sites."""
        curated = [spec for spec in specs if spec.tier <= DEFAULT_MODE]
        assert curated, "the curated core must not be empty"
        for spec in curated:
            assert "Converted from" not in (spec.notes or ""), spec.id

    def test_the_curated_core_is_the_hand_written_set(self, specs) -> None:
        """Tiers 1-3 hold the reviewed entries; nothing bulk-converted lives there."""
        for spec in specs:
            if spec.tier <= 3:
                assert "Converted from" not in (spec.notes or ""), spec.id


class TestNoisySourcesComeLast:
    """The ordering is the whole point: mode 4 must not be a random sample."""

    def test_the_first_catalogue_tiers_require_positive_evidence(self, specs) -> None:
        for spec in specs:
            if 4 <= spec.tier <= 7:
                assert spec.detector == "marker", (
                    f"{spec.id} at tier {spec.tier} does not require a found-marker, "
                    "so it does not belong in the low-noise end of the catalogue"
                )

    def test_status_only_catalogue_sources_are_high_tier(self, specs) -> None:
        for spec in specs:
            if spec.tier >= 4 and spec.detector == "status":
                assert spec.tier >= 8, f"{spec.id} is status-only at tier {spec.tier}"

    def test_adult_sites_are_never_in_the_low_tiers(self, specs) -> None:
        for spec in specs:
            if spec.category == "adult":
                assert spec.tier >= 10, f"{spec.id} at tier {spec.tier}"

    def test_a_status_only_probe_never_claims_above_medium(self, specs) -> None:
        """The confidence ceiling is enforced at load time; this re-checks the data."""
        for spec in specs:
            if spec.detector == "status":
                assert spec.confidence_found.value in {"low", "medium"}, spec.id


class TestTheCaveatIsHonest:
    def test_every_mode_has_a_caveat(self) -> None:
        for mode in range(MIN_MODE, MAX_MODE + 1):
            note = false_positive_note(mode)
            assert note and len(note) > 40, mode

    def test_the_caveat_gets_sterner_as_the_mode_rises(self) -> None:
        assert "false positives" not in false_positive_note(1).lower()
        assert "false positives" in false_positive_note(MAX_MODE).lower()

    def test_summarise_covers_every_mode(self, specs) -> None:
        rows = summarise(specs)
        assert [row["mode"] for row in rows] == list(range(MIN_MODE, MAX_MODE + 1))
        for row in rows:
            assert row["sources"] >= 1
            assert row["caveat"]


class TestTheLlmAdviceIsLocalOnly:
    def test_no_advice_below_the_threshold(self) -> None:
        for mode in range(MIN_MODE, LLM_RECOMMENDED_FROM):
            assert llm_recommendation(mode) is None, mode

    def test_advice_from_the_threshold_up(self) -> None:
        for mode in range(LLM_RECOMMENDED_FROM, MAX_MODE + 1):
            assert llm_recommendation(mode), mode

    @pytest.mark.parametrize("mode", range(LLM_RECOMMENDED_FROM, MAX_MODE + 1))
    def test_the_advice_names_a_local_backend(self, mode: int) -> None:
        advice = (llm_recommendation(mode) or "").lower()
        assert "cortex" in advice or "ollama" in advice

    @pytest.mark.parametrize("mode", range(LLM_RECOMMENDED_FROM, MAX_MODE + 1))
    def test_the_advice_never_names_a_cloud_provider(self, mode: int) -> None:
        advice = (llm_recommendation(mode) or "").lower()
        for provider in _CLOUD:
            assert provider not in advice, f"mode {mode} suggests {provider}"

    def test_the_module_never_mentions_a_hosted_api(self) -> None:
        source = (ROOT / "d3ta1l3r" / "modes.py").read_text(encoding="utf-8")
        lowered = source.lower()
        for provider in _CLOUD:
            assert provider not in lowered, provider

    def test_only_local_backends_are_advertised(self) -> None:
        assert len(LOCAL_LLMS) >= 2
        ids = {llm.id for llm in LOCAL_LLMS}
        assert {"cortex", "ollama"} <= ids
        for llm in LOCAL_LLMS:
            assert llm.url.startswith("https://")

    def test_cortex_is_credited_to_codero_sus(self) -> None:
        cortex = next(llm for llm in LOCAL_LLMS if llm.id == "cortex")
        assert "codero-sus" in cortex.url


class TestModeValidation:
    @pytest.mark.parametrize("mode", [0, -1, 16, 99])
    def test_an_out_of_range_mode_is_refused(self, mode: int) -> None:
        with pytest.raises(ConfigError):
            ScanConfig(mode=mode)

    @pytest.mark.parametrize("mode", range(MIN_MODE, MAX_MODE + 1))
    def test_every_valid_mode_is_accepted(self, mode: int) -> None:
        assert ScanConfig(mode=mode).mode == mode


class TestTheDashboardExposesTheModes:
    @pytest.fixture
    def client(self, tmp_path: Path):
        pytest.importorskip("fastapi", reason="web extras are optional")
        from fastapi.testclient import TestClient

        from d3ta1l3r.web.app import AppSettings, create_app

        settings = AppSettings(
            output_dir=tmp_path / "scans",
            demo=True,
            config=ScanConfig(demo=True, strict_ssrf=False, timeout=5.0),
        )
        with TestClient(create_app(settings)) as test_client:
            yield test_client

    def test_the_modes_endpoint_lists_every_mode(self, client) -> None:
        body = client.get("/api/modes").json()
        assert [row["mode"] for row in body["modes"]] == list(range(1, MAX_MODE + 1))
        assert body["llm_recommended_from"] == LLM_RECOMMENDED_FROM
        assert body["default"] == DEFAULT_MODE

    def test_the_modes_endpoint_advertises_only_local_backends(self, client) -> None:
        body = client.get("/api/modes").json()
        ids = {llm["id"] for llm in body["llm_backends"]}
        assert {"cortex", "ollama"} <= ids
        blob = str(body).lower()
        for provider in _CLOUD:
            assert provider not in blob

    def test_the_scan_form_ships_a_mode_picker(self, client) -> None:
        page = client.get("/").text
        assert 'id="mode-range"' in page
        assert 'name="mode"' in page
        assert 'id="mode-caveat"' in page

    def test_the_form_carries_a_note_for_every_mode(self, client) -> None:
        page = client.get("/").text
        for mode in range(1, MAX_MODE + 1):
            assert f'data-mode-note="{mode}"' in page, mode
            assert f'data-mode-advice="{mode}"' in page, mode


class TestTheStylesheetIsSelfConsistent:
    def test_every_css_variable_it_uses_is_defined(self) -> None:
        """An undefined var() silently renders as nothing — invisible breakage."""
        css = (ROOT / "d3ta1l3r" / "web" / "static" / "styles.css").read_text(encoding="utf-8")
        defined = set(re.findall(r"(--[a-z0-9-]+)\s*:", css))
        used = set(re.findall(r"var\((--[a-z0-9-]+)", css))
        # --h is deliberate: an animatable height with an `auto` fallback
        assert used - defined <= {"--h"}, sorted(used - defined)
