"""Documentation must stay true to the shipped code.

Docs rot silently, so a handful of the claims made in README.md and docs/ are
pinned here: the CLI surface, the source inventory, and the rules a disabled
source has to explain itself.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

from d3ta1l3r.cli import build_parser
from d3ta1l3r.config import ScanConfig
from d3ta1l3r.core.engine import ScanEngine
from d3ta1l3r.core.security import validate_source_id

ROOT = Path(__file__).resolve().parent.parent


def _read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


class TestReadme:
    def test_required_documents_exist(self) -> None:
        for relative in ("README.md", "LICENSE", "docs/SCOPE.md", "docs/SOURCES.md"):
            assert (ROOT / relative).is_file(), relative

    def test_every_cli_subcommand_is_documented(self) -> None:
        parser = build_parser()
        subparsers = [
            action for action in parser._actions if hasattr(action, "choices") and action.choices
        ]
        commands = set(subparsers[-1].choices)
        assert commands == {"scan", "sources", "calibrate", "diff", "web"}
        readme = _read("README.md")
        for command in commands:
            assert f"d3ta1l3r {command}" in readme, command

    def test_readme_advertises_the_real_extras(self) -> None:
        pyproject = _read("pyproject.toml")
        readme = _read("README.md")
        for extra in ("web", "dev"):
            assert re.search(r"^\[project\.optional-dependencies\]", pyproject, re.M)
            assert f"pip install -e '.[{extra}]'" in readme
            assert re.search(rf"^{extra} = \[", pyproject, re.M), extra

    def test_source_count_claim_matches_the_registry(self) -> None:
        total = len(ScanEngine(ScanConfig()).available_sources())
        enabled = len(ScanEngine(ScanConfig()).selected_sources())
        readme = _read("README.md")
        assert f"**{total} public sources**" in readme, (total, "README.md")
        sources_doc = _read("docs/SOURCES.md")
        assert f"{total} sources, {enabled} enabled by default" in sources_doc

    def test_documented_scope_refusals_match_the_code(self) -> None:
        """The things SCOPE.md promises never happen must not exist in the source tree."""
        forbidden = (
            "haveibeenpwned",
            "hibp",
            "whitepages",
            "spokeo",
            "truepeoplesearch",
            "dehashed",
            "intelx",
        )
        for path in (ROOT / "d3ta1l3r").rglob("*.py"):
            text = path.read_text(encoding="utf-8").lower()
            for needle in forbidden:
                assert needle not in text, f"{needle} referenced in {path.name}"

    def test_license_is_linked(self) -> None:
        assert "[LICENSE](LICENSE)" in _read("README.md")


class TestSourceDatabase:
    def test_ids_are_valid_and_unique(self) -> None:
        sources = ScanEngine(ScanConfig()).available_sources()
        ids = [source.meta.id for source in sources]
        assert len(ids) == len(set(ids))
        for source_id in ids:
            assert validate_source_id(source_id) == source_id

    def test_every_source_explains_itself(self) -> None:
        for source in ScanEngine(ScanConfig()).available_sources():
            meta = source.meta
            assert meta.description, meta.id
            if not meta.enabled_by_default:
                assert meta.notes, f"{meta.id} is disabled without saying why"
            if not meta.docs_url:
                assert meta.notes, f"{meta.id} has neither docs_url nor notes"

    def test_categories_are_documented(self) -> None:
        documented = _read("docs/SOURCES.md")
        categories = {
            source.meta.category for source in ScanEngine(ScanConfig()).available_sources()
        }
        for category in categories:
            assert f"`{category}`" in documented, category

    def test_probe_confidence_claims_are_sane(self) -> None:
        from d3ta1l3r.sources.probe import load_site_specs

        for spec in load_site_specs():
            assert spec.detector in {"marker", "absence", "status"}
            if spec.detector in {"marker", "absence"}:
                assert spec.found_marker or spec.not_found_marker, spec.id
            else:
                assert spec.notes, f"status-only spec {spec.id} must explain itself"
            if spec.detector == "status":
                assert spec.confidence_found.rank <= 1, spec.id  # medium at most


class TestExamples:
    def test_examples_compile(self) -> None:
        for path in sorted((ROOT / "examples").glob("*.py")):
            source = path.read_text(encoding="utf-8")
            compile(source, str(path), "exec")

    def test_demo_mode_only_example_runs_offline(self) -> None:
        proc = subprocess.run(
            [sys.executable, "examples/quickstart.py", "--demo", "-u", "demo_user"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert proc.returncode == 0, proc.stderr
        assert "demo mode" in proc.stdout
        assert "finding(s)" in proc.stdout
