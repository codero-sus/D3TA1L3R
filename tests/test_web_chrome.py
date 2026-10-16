"""The credit in the footer, and the decorative layer in the browser assets.

The credit is small but it is the author's, so it is pinned. The rest of this
file pins the properties of the animation work that are easy to regress and
invisible in a screenshot: that motion is opt-out, that the reveal effect is
progressive enhancement rather than a dependency on JavaScript, and that none of
it smuggles HTML into the page.
"""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("fastapi", reason="web extras are optional")

from fastapi.testclient import TestClient

from d3ta1l3r import __author__, __author_url__, __author_website__
from d3ta1l3r.config import ScanConfig
from d3ta1l3r.web.app import AppSettings, create_app

ROOT = Path(__file__).resolve().parent.parent
CSS = ROOT / "d3ta1l3r" / "web" / "static" / "styles.css"
JS = ROOT / "d3ta1l3r" / "web" / "static" / "app.js"
BASE = ROOT / "d3ta1l3r" / "web" / "templates" / "base.html"


@pytest.fixture
def client(tmp_path: Path):
    settings = AppSettings(
        output_dir=tmp_path / "scans",
        demo=True,
        config=ScanConfig(demo=True, strict_ssrf=False, timeout=5.0),
    )
    with TestClient(create_app(settings)) as test_client:
        yield test_client


def _text(page: str) -> str:
    """Collapse whitespace: Jinja wraps prose, so exact substrings are fragile."""
    return " ".join(page.split())


class TestFooterCredit:
    def test_the_dashboard_carries_the_credit(self, client: TestClient) -> None:
        page = _text(client.get("/").text)
        assert "made with" in page.lower()
        assert __author__ in page

    def test_the_login_page_carries_it_too(self, client: TestClient) -> None:
        """Signed-out pages should still say who built this."""
        page = _text(client.get("/login").text)
        assert "made with" in page.lower()
        assert __author__ in page

    def test_it_links_to_the_author_and_the_website(self, client: TestClient) -> None:
        page = client.get("/").text
        assert __author_url__ in page
        assert __author_website__ in page

    def test_external_links_do_not_leak_a_window_handle(self) -> None:
        raw = BASE.read_text(encoding="utf-8")
        blank_targets = raw.count('target="_blank"')
        assert blank_targets, "the footer links should open in a new tab"
        assert raw.count('rel="noopener noreferrer"') == blank_targets, (
            "every target=_blank link needs rel=noopener"
        )

    def test_the_credit_comes_from_the_package_not_the_template(self) -> None:
        """Hard-coding it in HTML is how it drifts from pyproject."""
        raw = BASE.read_text(encoding="utf-8")
        assert "codero-sus" not in raw, "the template must render {{ author }}"
        assert "{{ author }}" in raw


class TestMotionIsOptOut:
    def test_reduced_motion_is_respected(self) -> None:
        """Motion can cause real discomfort, and none of it carries information."""
        css = CSS.read_text(encoding="utf-8")
        assert "prefers-reduced-motion" in css

    def test_animations_are_named_and_reused(self) -> None:
        css = CSS.read_text(encoding="utf-8")
        for name in ("d3t-fade-up", "d3t-heartbeat", "d3t-shimmer", "d3t-pulse-ring"):
            assert f"@keyframes {name}" in css, name

    def test_the_heart_has_its_own_animation(self) -> None:
        css = CSS.read_text(encoding="utf-8")
        assert ".heart" in css
        assert "d3t-heartbeat" in css


class TestRevealIsProgressiveEnhancement:
    def test_the_markup_does_not_hide_anything_up_front(self) -> None:
        """If JavaScript never runs, the page must still be readable."""
        for name in ("index.html",):
            raw = (ROOT / "d3ta1l3r" / "web" / "templates" / name).read_text(encoding="utf-8")
            assert "class=\"reveal\"" not in raw, "the hiding class is added by JS"

    def test_javascript_adds_the_class_itself(self) -> None:
        js = JS.read_text(encoding="utf-8")
        assert 'classList.add("reveal")' in js

    def test_it_gives_up_cleanly_when_motion_is_reduced(self) -> None:
        js = JS.read_text(encoding="utf-8")
        assert "prefersReducedMotion" in js
        assert "IntersectionObserver" in js

    def test_a_revealed_element_skips_the_entrance_animation(self) -> None:
        """Two animations fighting over opacity would leave content invisible."""
        css = CSS.read_text(encoding="utf-8")
        assert "[data-reveal].reveal" in css


class TestNoHtmlInjection:
    @pytest.mark.parametrize("needle", ["toast", "wireChrome", "wireReveal"])
    def test_new_code_builds_dom_nodes_not_strings(self, needle: str) -> None:
        js = JS.read_text(encoding="utf-8")
        start = js.index(f"function {needle}")
        chunk = js[start : start + 1500]
        assert "innerHTML" not in chunk, f"{needle} must not parse HTML"
