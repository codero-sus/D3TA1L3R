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
        assert commands == {
            "scan",
            "sources",
            "calibrate",
            "diff",
            "vault",
            "breach",
            "web",
            "ask",
            "models",
            "update",
        }
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

    def test_the_chat_is_documented_as_local_only(self) -> None:
        """README and SCOPE must say the model runs here, and where it cannot run."""
        readme = _read("README.md")
        scope = _read("docs/SCOPE.md")
        for text in (readme, scope):
            assert "ask" in text
        assert "d3ta1l3r ask" in readme
        assert "loopback" in scope.lower() or "127.0.0.1" in scope

    def test_no_remote_model_endpoint_appears_in_the_chat_code(self) -> None:
        """A local model feature must not name a hosted model API anywhere."""
        banned = (
            "api.openai.com",
            "openai.com/v1",
            "api.anthropic.com",
            "generativelanguage.googleapis.com",
            "api.mistral.ai",
            "api.groq.com",
            "openrouter.ai",
            "api.together.xyz",
            "huggingface.co/api",
            "cohere.ai",
        )
        chat_files = sorted((ROOT / "d3ta1l3r" / "llm").glob("*.py"))
        assert chat_files, "the llm package must exist for this test to mean anything"
        for path in chat_files:
            body = path.read_text(encoding="utf-8")
            for term in banned:
                assert term not in body, f"{path.name} names a hosted model API: {term}"

    def test_the_chat_says_it_is_not_persisted(self) -> None:
        readme = _read("README.md")
        assert "never written to disk" in readme or "nothing is written to disk" in readme.lower()

    def test_documented_scope_refusals_match_the_code(self) -> None:
        """The services SCOPE.md refuses must not appear in the source tree.

        Breach *checking* is in scope (SCOPE.md §2a), but only through the
        k-anonymity range API, an HIBP key the operator supplies, and corpora the
        operator already has. Broker-style search services never appear at all.
        """
        forbidden = (
            "whitepages",
            "spokeo",
            "truepeoplesearch",
            "dehashed",
            "intelx",
            "beenverified",
            "peoplefinders",
            "snusbase",
            "weleakinfo",
            "leakcheck",
            "breachdirectory",
            "haveibeenpwned.com/api/v3/breaches",  # the "list every breach" endpoint
        )
        for path in (ROOT / "d3ta1l3r").rglob("*.py"):
            text = path.read_text(encoding="utf-8").lower()
            for needle in forbidden:
                assert needle not in text, f"{needle} referenced in {path.name}"

    def test_breach_checking_stays_on_the_documented_side_of_the_line(self) -> None:
        """HIBP may only be reached from breach.py, and only for your own account."""
        text = (ROOT / "d3ta1l3r" / "breach.py").read_text(encoding="utf-8").lower()
        assert "api.pwnedpasswords.com/range/" in text
        assert "hibp" in text
        # No dump acquisition anywhere in the package.
        offenders = []
        for path in (ROOT / "d3ta1l3r").rglob("*.py"):
            body = path.read_text(encoding="utf-8").lower()
            for needle in ("magnet:", "torrent", "pastebin.com/raw", ".sql.gz", "7z"):
                if needle in body:
                    offenders.append(f"{path.name}: {needle}")
        assert not offenders, offenders

    def test_the_breach_stance_is_written_down(self) -> None:
        scope = _read("docs/SCOPE.md").lower()
        assert "k-anonymity" in scope
        assert "five hexadecimal characters" in scope or "5 hex" in scope
        assert "never downloads" in scope or "no corpus" in scope
        readme = _read("README.md").lower()
        assert "breach" in readme and "vault" in readme

    def test_license_is_linked(self) -> None:
        assert "[LICENSE](LICENSE)" in _read("README.md")

    def test_downloads_are_documented_as_user_initiated(self) -> None:
        """The catalogue must be shown, and the licence disclosed, before a fetch."""
        readme = _read("README.md")
        scope = _read("docs/SCOPE.md")
        assert "d3ta1l3r models list" in readme
        assert "d3ta1l3r models pull" in readme
        # the dashboard offers the same list, and asks before fetching
        assert "same catalogue on the main page" in readme
        assert "nothing is fetched by looking at the page" in readme.lower()
        assert "before" in scope.lower() and "licence" in scope.lower()
        for text in (readme, scope):
            lowered = text.lower()
            assert "nothing is downloaded" in lowered or "nothing downloads itself" in lowered
        # the disclosure has to exist in the catalogue itself, not only in prose
        from d3ta1l3r.llm import CATALOG

        assert CATALOG, "an empty catalogue would make the docs a lie"
        for spec in CATALOG:
            assert spec.license, f"{spec.id} is listed without a licence"
            assert spec.repo.count("/") == 1, spec.id

    def test_weights_are_never_bundled_with_the_repository(self) -> None:
        """No .gguf may be committed: the tool downloads them, it does not ship them."""
        stray = [
            str(path.relative_to(ROOT))
            for path in ROOT.rglob("*.gguf")
            if ".git" not in path.parts
        ]
        assert not stray, stray
        ignore = _read(".gitignore")
        assert "*.gguf" in ignore or ".gguf" in ignore

    def test_verification_is_documented_as_a_request_only_opinion(self) -> None:
        readme = _read("README.md")
        scope = _read("docs/SCOPE.md")
        assert "--verify" in readme and "--verify" in scope
        # the dashboard has the same rule, expressed as a checkbox
        assert "Review identity" in readme
        assert "disabled until you tick it" in readme
        for text in (readme, scope):
            lowered = text.lower()
            assert "opt-in" in lowered or "only when you ask" in lowered
            assert "unsure" in lowered
            assert "never evidence" in lowered or "not evidence" in lowered
            assert "proof of ownership" in lowered
        # and the code really does keep the two claims apart
        verify = (ROOT / "d3ta1l3r" / "llm" / "verify.py").read_text(encoding="utf-8")
        assert "confidence = " not in verify.replace("measured_confidence", "")

    def test_the_downloader_is_not_an_inference_client(self) -> None:
        """huggingface.co is a file host here; no question is ever sent to it."""
        for name in ("backends.py", "chat.py", "context.py", "cite.py", "prompt.py"):
            body = (ROOT / "d3ta1l3r" / "llm" / name).read_text(encoding="utf-8").lower()
            assert "huggingface" not in body, name
        # every huggingface.co URL in the package goes through the one constant,
        # so a future change cannot quietly point a backend at a hosted model API
        urls = []
        for path in sorted((ROOT / "d3ta1l3r").rglob("*.py")):
            for number, line in enumerate(
                path.read_text(encoding="utf-8").splitlines(), start=1
            ):
                if "huggingface.co" in line and "HF_HOST = " not in line:
                    urls.append(f"{path.name}:{number}: {line.strip()}")
        assert not urls, urls

    def test_cortex_is_documented_and_stays_local(self) -> None:
        """The third backend must be described, and described as yours."""
        readme = _read("README.md").lower()
        scope = _read("docs/SCOPE.md").lower()
        for text in (readme, scope):
            assert "cortex" in text, "Cortex is a supported backend and must be documented"
            assert "--cortex-host" in text, "naming a LAN host is the opt-in, so it needs saying"
        # a LAN box is allowed on purpose; a public address is not
        assert "192.168" in _read("docs/SCOPE.md")
        assert "refused" in scope

    def test_the_lan_rule_is_rfc1918_and_nothing_broader(self) -> None:
        """`is_private` would also let the documentation ranges through."""
        body = (ROOT / "d3ta1l3r" / "llm" / "backends.py").read_text(encoding="utf-8")
        assert "10.0.0.0/8" in body
        assert "172.16.0.0/12" in body
        assert "192.168.0.0/16" in body
        assert ".is_private" not in body, (
            "use the LAN_NETWORKS table: ipaddress.is_private is broader than RFC1918 "
            "and would also accept the documentation ranges and link-local"
        )

    def test_the_updater_promises_are_documented(self) -> None:
        scope = _read("docs/SCOPE.md").lower()
        readme = _read("README.md").lower()
        for text in (scope, readme):
            assert "d3ta1l3r update" in text
        # the four promises that make it a supply-chain decision, not a convenience
        assert "sys.executable" in scope, "the pip call must target the running interpreter"
        assert "--ff-only" in scope, "git updates must not rewrite history"
        assert "pre-release" in scope, "a pre-release must never install automatically"
        assert "never a shell string" in scope or "not a shell string" in scope

    def test_the_updater_never_executes_a_downloaded_asset(self) -> None:
        """The one thing an updater must not do is fetch code and run it."""
        body = (ROOT / "d3ta1l3r" / "updater.py").read_text(encoding="utf-8")
        assert "curl" not in body
        assert "urlretrieve" not in body
        assert "shell=True" not in body
        # the only thing fetched is JSON metadata: never a release asset
        assert "/releases/latest" in body
        assert "browser_download_url" not in body
        assert "assets" not in body, "release assets must never be read, let alone installed"

    def test_branch_updating_is_documented(self) -> None:
        """A project with no releases must not have a dead updater."""
        readme = _read("README.md")
        scope = _read("docs/SCOPE.md")
        for text in (readme, scope):
            assert "--branch" in text
            assert "D3TA1L3R_UPDATE_BRANCH" in text
        assert "--ff-only" in readme, "the fast-forward must be named in the docs too"
        # the two modes are told apart in the output
        assert '"mode"' in readme or "mode" in scope

    def test_the_updater_wrappers_are_documented(self) -> None:
        readme = _read("README.md")
        scope = _read("docs/SCOPE.md")
        assert "updater.sh" in readme and "updater.bat" in readme
        assert "updater.sh" in scope and "updater.bat" in scope
        assert "wrapper" in scope.lower(), "they must be described as wrappers, not a 2nd impl"

    def test_auto_model_selection_is_documented(self) -> None:
        scope = _read("docs/SCOPE.md")
        assert "auto" in scope
        assert "--ollama-model" in scope and "--cortex-model" in scope


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
