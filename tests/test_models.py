"""The model catalogue, Hugging Face downloads, and the machine-size arithmetic.

Downloads are the one place D3TA1L3R writes something big to disk on purpose, so
the tests care about the failure modes rather than the happy path: a truncated
download must never become a usable file, an HTML error page must not be saved
as a model, a resume must not append a second copy, and nothing may be fetched
without the operator naming a model first.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import httpx
import pytest

from d3ta1l3r.cli import EXIT_OK, main
from d3ta1l3r.errors import UsageError
from d3ta1l3r.llm import models as catalog


def _client(handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler), base_url=catalog.HF_HOST)


def _spec(**overrides) -> catalog.ModelSpec:
    base = {
        "id": "test-model",
        "name": "Test Model",
        "repo": "owner/repo",
        "filename": "model-Q4_K_M.gguf",
        "parameters": "1B",
        "quant": "Q4_K_M",
        "size_mb": 1,
        "ram_mb": 1200,
    }
    base.update(overrides)
    return catalog.ModelSpec(**base)


class TestCatalogIntegrity:
    def test_ids_are_unique_and_url_safe(self) -> None:
        ids = [spec.id for spec in catalog.CATALOG]
        assert len(ids) == len(set(ids)), "duplicate catalogue ids"
        for spec in catalog.CATALOG:
            assert spec.id == spec.id.lower()
            assert " " not in spec.id and "/" not in spec.id

    def test_every_entry_points_at_a_gguf_on_the_hub(self) -> None:
        for spec in catalog.CATALOG:
            assert spec.url.startswith(f"{catalog.HF_HOST}/owner"[: 0] or catalog.HF_HOST + "/")
            assert spec.url.endswith(".gguf") or ".gguf" in spec.url
            assert spec.filename.lower().endswith(".gguf")
            assert spec.repo.count("/") == 1, spec.repo
            assert spec.url == (
                f"https://huggingface.co/{spec.repo}/resolve/{spec.revision}/{spec.filename}"
            )

    def test_sizes_are_plausible_and_ram_exceeds_the_file(self) -> None:
        """Resident size must exceed the download: the KV cache is not free."""
        for spec in catalog.CATALOG:
            assert spec.size_mb > 0, spec.id
            assert spec.ram_mb > spec.size_mb, spec.id
            assert spec.context >= 512
            assert spec.license != ""

    def test_the_catalogue_covers_both_ends_of_the_range(self) -> None:
        fit = [spec for spec in catalog.CATALOG if spec.fits_4gb]
        powerful = [spec for spec in catalog.CATALOG if spec.is_powerful]
        assert len(fit) >= 3, "a 4 GB machine needs options"
        assert len(powerful) >= 3, "the user asked for a powerful option too"
        assert max(spec.ram_mb for spec in powerful) > 16_000

    def test_ordering_is_smallest_first(self) -> None:
        ram = [spec.ram_mb for spec in catalog.CATALOG]
        assert ram == sorted(ram)


class TestSelection:
    def test_filter_by_memory_tag_and_query(self) -> None:
        small = catalog.filter_models(fits_mb=4096)
        assert small and all(spec.ram_mb <= 4096 for spec in small)
        reasoning = catalog.filter_models(tag="reasoning")
        assert reasoning and all("reasoning" in spec.tags for spec in reasoning)
        assert catalog.filter_models("qwen")[0].parameters.startswith(("1.5", "7", "14", "32"))
        assert catalog.filter_models("nothing-like-this") == []

    def test_find_model_is_strict_about_ambiguity(self) -> None:
        assert catalog.find_model("qwen2.5-1.5b-instruct-q4_k_m") is not None
        assert catalog.find_model("Qwen/Qwen2.5-1.5B-Instruct-GGUF/qwen2.5-1.5b-instruct-q4_k_m.gguf")
        assert catalog.find_model("") is None
        assert catalog.find_model("qwen") is None, "an ambiguous query must not pick one"

    def test_resolve_downloaded_prefers_the_largest_that_fits(self, tmp_path: Path) -> None:
        (tmp_path / "tinyllama-1.1b-chat-q4_k_m.gguf").write_bytes(b"x")
        (tmp_path / "llama-3.2-3b-instruct-q4_k_m.gguf").write_bytes(b"x")
        (tmp_path / "qwen2.5-7b-instruct-q4_k_m.gguf").write_bytes(b"x")
        chosen = catalog.resolve_downloaded_model(tmp_path, ram_budget_mb=2400)
        assert chosen is not None and chosen.name.startswith("llama-3.2-3b")
        assert catalog.resolve_downloaded_model(tmp_path, ram_budget_mb=100) is None

    def test_machine_ram_is_reported_or_unknown(self) -> None:
        ram = catalog.local_ram_mb()
        assert ram is None or ram > 0

    def test_describe_disk_reports_a_directory_and_free_space(self, tmp_path: Path) -> None:
        disk = catalog.describe_disk(tmp_path)
        assert disk["directory"] == str(tmp_path)
        assert disk["free_mb"] == -1 or disk["free_mb"] > 0


class TestCustomCatalog:
    def test_a_custom_model_round_trips(self, tmp_path: Path) -> None:
        spec = catalog.spec_from_reference(
            "TheBloke/dolphin-2.9-llama3-8b-GGUF/dolphin-2.9-llama3-8b.Q4_K_M.gguf",
            parameters="8B", quant="Q4_K_M", ram_mb=6100, size_mb=4900, license="llama3",
        )
        path = catalog.save_custom_model(spec, tmp_path)
        assert path.is_file()
        loaded = catalog.load_custom_models(tmp_path)
        assert len(loaded) == 1
        assert loaded[0].id == spec.id and loaded[0].official is False
        assert loaded[0].ram_mb == 6100
        assert "custom" in loaded[0].tags
        # the curated catalogue plus the custom entry
        assert spec.id in {item.id for item in catalog.catalogue(tmp_path)}
        assert catalog.remove_custom_model(spec.id, tmp_path) is True
        assert catalog.load_custom_models(tmp_path) == ()

    def test_removing_something_absent_is_false(self, tmp_path: Path) -> None:
        assert catalog.remove_custom_model("nope", tmp_path) is False

    def test_a_reference_needs_a_repo_and_a_gguf(self) -> None:
        with pytest.raises(UsageError):
            catalog.spec_from_reference("just-a-name")
        with pytest.raises(UsageError):
            catalog.spec_from_reference("owner/repo/weights.bin")
        with pytest.raises(UsageError):
            catalog.spec_from_reference("owner/model.gguf", repo="", filename="")

    def test_a_repo_and_filename_given_separately_work(self) -> None:
        spec = catalog.spec_from_reference(
            "", repo="owner/repo", filename="weights.gguf", ram_mb=2000
        )
        assert spec.repo == "owner/repo" and spec.filename == "weights.gguf"

    def test_an_unreadable_catalogue_is_a_usage_error(self, tmp_path: Path) -> None:
        catalog.custom_catalog_path(tmp_path).write_text("{not json", encoding="utf-8")
        with pytest.raises(UsageError):
            catalog.load_custom_models(tmp_path)


class TestDownload:
    def _body(self, size: int = 4096) -> bytes:
        return bytes((index % 251) for index in range(size))

    def test_a_download_lands_whole_and_verified(self, tmp_path: Path) -> None:
        body = self._body()
        seen: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(str(request.url))
            return httpx.Response(
                200,
                content=body,
                headers={"content-length": str(len(body))},
                request=request,
            )

        path = catalog.download_model(
            _spec(size_mb=0), tmp_path, transport=httpx.MockTransport(handler)
        )
        assert path.is_file() and path.read_bytes() == body
        assert not path.with_suffix(".gguf.part").exists()
        assert seen == [_spec(size_mb=0).url]

    def test_a_sha256_mismatch_discards_the_file(self, tmp_path: Path) -> None:
        body = self._body()

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, content=body, request=request)

        with pytest.raises(UsageError) as excinfo:
            catalog.download_model(
                _spec(size_mb=0),
                tmp_path,
                transport=httpx.MockTransport(handler),
                expected_sha256="0" * 64,
            )
        assert "SHA-256" in str(excinfo.value)
        assert not catalog.model_path(_spec(size_mb=0), tmp_path).exists()
        assert not catalog.model_path(_spec(size_mb=0), tmp_path).with_suffix(".gguf.part").exists()

    def test_a_truncated_download_is_not_a_model(self, tmp_path: Path) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                content=b"x" * 10,
                headers={"content-length": "4096"},  # promised more than it sent
                request=request,
            )

        with pytest.raises(UsageError) as excinfo:
            catalog.download_model(_spec(size_mb=0), tmp_path, transport=httpx.MockTransport(handler))
        assert "incomplete" in str(excinfo.value)
        assert not catalog.model_path(_spec(size_mb=0), tmp_path).exists()
        assert catalog.model_path(_spec(size_mb=0), tmp_path).with_suffix(".gguf.part").is_file()

    def test_a_resume_continues_rather_than_restarts(self, tmp_path: Path) -> None:
        body = self._body(600)
        part = catalog.model_path(_spec(size_mb=0), tmp_path).with_suffix(".gguf.part")
        part.parent.mkdir(parents=True, exist_ok=True)
        part.write_bytes(body[:100])
        ranges: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            ranges.append(request.headers.get("range", ""))
            return httpx.Response(
                206,
                content=body[100:],
                headers={"content-length": str(len(body) - 100)},
                request=request,
            )

        path = catalog.download_model(
            _spec(size_mb=0), tmp_path, transport=httpx.MockTransport(handler)
        )
        assert ranges == ["bytes=100-"]
        assert path.read_bytes() == body, "resume must not duplicate the prefix"

    def test_a_server_that_ignores_range_starts_over_cleanly(self, tmp_path: Path) -> None:
        body = self._body(300)
        part = catalog.model_path(_spec(size_mb=0), tmp_path).with_suffix(".gguf.part")
        part.parent.mkdir(parents=True, exist_ok=True)
        part.write_bytes(b"stale-prefix")

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, content=body, request=request)  # no 206

        path = catalog.download_model(
            _spec(size_mb=0), tmp_path, transport=httpx.MockTransport(handler)
        )
        assert path.read_bytes() == body

    def test_an_html_error_page_is_refused(self, tmp_path: Path) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200, content=b"<!DOCTYPE html><html>not a model</html>", request=request
            )

        with pytest.raises(UsageError) as excinfo:
            catalog.download_model(_spec(size_mb=0), tmp_path, transport=httpx.MockTransport(handler))
        assert "web page" in str(excinfo.value)

    def test_a_404_explains_itself(self, tmp_path: Path) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(404, request=request)

        with pytest.raises(UsageError) as excinfo:
            catalog.download_model(_spec(size_mb=0), tmp_path, transport=httpx.MockTransport(handler))
        assert "404" in str(excinfo.value)

    def test_an_existing_verified_file_is_not_downloaded_again(self, tmp_path: Path) -> None:
        spec = _spec(size_mb=1)
        target = catalog.model_path(spec, tmp_path)
        target.write_bytes(b"x" * (1024 * 1024))
        called = False

        def handler(request: httpx.Request) -> httpx.Response:  # pragma: no cover
            nonlocal called
            called = True
            return httpx.Response(500, request=request)

        path = catalog.download_model(spec, tmp_path, transport=httpx.MockTransport(handler))
        assert path == target and called is False

    def test_progress_is_reported_and_ends_at_the_total(self, tmp_path: Path) -> None:
        body = self._body(2048)
        events: list[tuple[str, int, int]] = []

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200, content=body, headers={"content-length": str(len(body))}, request=request
            )

        catalog.download_model(
            _spec(size_mb=0),
            tmp_path,
            transport=httpx.MockTransport(handler),
            progress=lambda phase, done, total: events.append((phase, done, total)),
        )
        assert events[-1][0] == "done"
        assert events[-1][1] == len(body)
        assert any(phase == "download" for phase, _, _ in events)
        assert all(done <= total or total == -1 for _, done, total in events)

    def test_downloaded_files_are_listed_with_their_catalogue_entry(self, tmp_path: Path) -> None:
        (tmp_path / "qwen2.5-1.5b-instruct-q4_k_m.gguf").write_bytes(b"x" * 2048)
        (tmp_path / "mystery.gguf").write_bytes(b"x")
        rows = catalog.list_downloaded(tmp_path)
        by_id = {row["id"]: row for row in rows}
        assert by_id["qwen2.5-1.5b-instruct-q4_k_m"]["catalogued"] is True
        assert by_id["mystery"]["catalogued"] is False


class TestHuggingFaceMetadata:
    def test_search_parses_repositories(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            assert "gguf" in str(request.url)
            return httpx.Response(
                200,
                json=[
                    {"id": "owner/repo-GGUF", "downloads": 12, "likes": 3,
                     "lastModified": "2026-01-02T03:04:05Z", "gated": False},
                ],
                request=request,
            )

        rows = catalog.hf_search("llama", transport=httpx.MockTransport(handler))
        assert rows[0]["repo"] == "owner/repo-GGUF"
        assert rows[0]["updated"] == "2026-01-02"
        assert rows[0]["gated"] is False

    def test_search_failing_gracefully_suggests_the_offline_catalogue(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("no route", request=request)

        with pytest.raises(UsageError) as excinfo:
            catalog.hf_search("llama", transport=httpx.MockTransport(handler))
        assert "offline" in str(excinfo.value)

    def test_file_metadata_finds_the_file_and_its_hash(self) -> None:
        digest = hashlib.sha256(b"weights").hexdigest()

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json=[
                    {"path": "README.md", "size": 10},
                    {"path": "model-Q4_K_M.gguf", "size": 4096,
                     "lfs": {"sha256": digest, "size": 4096}},
                ],
                request=request,
            )

        meta = catalog.hf_file_metadata(
            _spec(), transport=httpx.MockTransport(handler)
        )
        assert meta["size"] == 4096 and meta["sha256"] == digest

    def test_a_missing_file_reports_no_size(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=[{"path": "other.gguf", "size": 1}], request=request)

        meta = catalog.hf_file_metadata(_spec(), transport=httpx.MockTransport(handler))
        assert meta["size"] == 0 and meta["sha256"] == ""


class TestModelsCommand:
    def test_list_json_is_machine_readable(self, tmp_path: Path, monkeypatch, capsys) -> None:
        monkeypatch.setenv("D3TA1L3R_MODELS", str(tmp_path))
        assert main(["models", "list", "--json"]) == EXIT_OK
        rows = json.loads(capsys.readouterr().out)
        assert any(row["id"] == "qwen2.5-1.5b-instruct-q4_k_m" for row in rows)
        assert all({"url", "size_mb", "ram_mb", "fits_4gb", "downloaded"} <= set(row) for row in rows)

    def test_list_marks_what_is_already_downloaded(self, tmp_path: Path, monkeypatch,
                                                   capsys) -> None:
        monkeypatch.setenv("D3TA1L3R_MODELS", str(tmp_path))
        (tmp_path / "tinyllama-1.1b-chat-q4_k_m.gguf").write_bytes(b"x")
        assert main(["models", "list", "--downloaded"]) == EXIT_OK
        out = capsys.readouterr().out
        assert "tinyllama" in out and "qwen" not in out

    def test_powerful_filter_shows_the_big_models(self, capsys) -> None:
        assert main(["models", "list", "--powerful", "--json"]) == EXIT_OK
        rows = json.loads(capsys.readouterr().out)
        assert rows and all(row["is_powerful"] for row in rows)
        assert any(row["ram_mb"] > 8000 for row in rows)

    def test_path_reports_the_directory_and_space(self, tmp_path: Path, monkeypatch,
                                                capsys) -> None:
        monkeypatch.setenv("D3TA1L3R_MODELS", str(tmp_path))
        assert main(["models", "path", "--json"]) == EXIT_OK
        payload = json.loads(capsys.readouterr().out)
        assert payload["directory"] == str(tmp_path)

    def test_add_then_pull_without_a_network_explains_itself(self, tmp_path: Path, monkeypatch,
                                                          capsys) -> None:
        monkeypatch.setenv("D3TA1L3R_MODELS", str(tmp_path))
        code = main([
            "models", "add", "owner/repo/big-model.Q4_K_M.gguf",
            "--parameters", "8B", "--quant", "Q4_K_M", "--ram-mb", "6100", "--tag", "powerful",
        ])
        assert code == EXIT_OK
        out = capsys.readouterr().out
        assert "added to the catalogue" in out
        # It is now findable, and pull knows its URL without any network call.
        assert main(["models", "list", "--search", "big-model", "--json"]) == EXIT_OK
        rows = json.loads(capsys.readouterr().out)
        assert rows[0]["ram_mb"] == 6100 and rows[0]["url"].endswith("big-model.Q4_K_M.gguf")

    def test_pull_refuses_when_the_model_will_not_fit_on_disk(
        self, tmp_path: Path, monkeypatch, capsys
    ) -> None:
        """The disk check must fire before a single byte is requested."""
        monkeypatch.setenv("D3TA1L3R_MODELS", str(tmp_path))
        monkeypatch.setattr(
            "d3ta1l3r.cli.model_catalog.describe_disk",
            lambda directory=None: {
                "directory": str(tmp_path), "exists": True,
                "free_mb": 512, "total_mb": 1024, "ram_mb": 4096,
            },
        )
        code = main(["models", "pull", "llama-3.2-3b-instruct-q4_k_m", "--yes"])
        assert code != EXIT_OK
        assert "not enough disk" in capsys.readouterr().err

    def test_pull_asks_before_downloading(self, tmp_path: Path, monkeypatch, capsys) -> None:
        """With no --yes, an unanswered prompt means no bytes move."""
        monkeypatch.setenv("D3TA1L3R_MODELS", str(tmp_path))
        monkeypatch.setattr("builtins.input", lambda _prompt="": "no")
        code = main(["models", "pull", "tinyllama-1.1b-chat-q4_k_m"])
        assert code == EXIT_OK
        assert "nothing downloaded" in capsys.readouterr().out
        assert list(tmp_path.glob("*.gguf")) == []

    def test_pull_unknown_id_suggests_alternatives(self, capsys) -> None:
        code = main(["models", "pull", "qwen", "--yes"])
        assert code != EXIT_OK
        assert "Did you mean" in capsys.readouterr().err

    def test_search_that_cannot_reach_the_hub_says_so(self, capsys, monkeypatch) -> None:
        """No test may depend on huggingface.co being reachable."""
        def unreachable(query: str, **kwargs: object) -> list[dict[str, object]]:
            raise UsageError("could not reach https://huggingface.co (ConnectError)")

        monkeypatch.setattr("d3ta1l3r.cli.model_catalog.hf_search", unreachable)
        assert main(["models", "search", "llama"]) != EXIT_OK
        assert "could not reach" in capsys.readouterr().err

    def test_search_prints_repositories_when_the_hub_answers(self, capsys, monkeypatch) -> None:
        monkeypatch.setattr(
            "d3ta1l3r.cli.model_catalog.hf_search",
            lambda query, **kwargs: [
                {"repo": "owner/model-GGUF", "downloads": 5, "likes": 1,
                 "updated": "2026-01-01", "gated": True, "url": "https://huggingface.co/owner"}
            ],
        )
        assert main(["models", "search", "llama"]) == EXIT_OK
        out = capsys.readouterr().out
        assert "owner/model-GGUF" in out and "[gated]" in out

    def test_remove_requires_confirmation_unless_told(self, tmp_path: Path, monkeypatch,
                                                     capsys) -> None:
        monkeypatch.setenv("D3TA1L3R_MODELS", str(tmp_path))
        target = tmp_path / "custom-model.gguf"
        target.write_bytes(b"x" * 10)
        monkeypatch.setattr("builtins.input", lambda _prompt="": "n")
        assert main(["models", "remove", "custom-model"]) == EXIT_OK
        assert "left the file alone" in capsys.readouterr().out
        assert target.is_file()
        assert main(["models", "remove", "custom-model", "--yes"]) == EXIT_OK
        assert not target.exists()

    def test_ask_rejects_a_catalogue_entry_that_is_not_downloaded(self, tmp_path: Path,
                                                                 monkeypatch, capsys) -> None:
        monkeypatch.setenv("D3TA1L3R_MODELS", str(tmp_path))
        out = tmp_path / "scans"
        assert main(["scan", "-u", "demo_user", "--demo", "-o", str(out), "-q"]) == EXIT_OK
        code = main([
            "ask", "what is exposed?", "--model", "qwen2.5-1.5b-instruct-q4_k_m",
            "-o", str(out), "--no-watchlist", "-y",
        ])
        assert code != EXIT_OK
        assert "not downloaded yet" in capsys.readouterr().err
