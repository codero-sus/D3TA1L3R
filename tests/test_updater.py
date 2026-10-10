"""The updater: what it reports, what it refuses, and what it will not run.

The property that matters most is the negative one — an updater that acts before
being shown, or that runs something the user did not see, is worse than no
updater at all. So a good half of these tests assert that nothing happened.
"""

from __future__ import annotations

import json
import subprocess
import sys
from importlib import metadata
from pathlib import Path

import httpx
import pytest

from d3ta1l3r import __version__
from d3ta1l3r.cli import EXIT_FAILURE, EXIT_OK, main
from d3ta1l3r.updater import (
    PROJECT_URL,
    UPDATE_API,
    UpdateInfo,
    apply_update,
    check_branch_updates,
    check_for_update,
    current_branch,
    dumps_json,
    install_kind,
    is_newer,
    parse_version,
    resolve_branch,
    update_command,
)


def _release(
    tag: str = "v9.9.9",
    *,
    body: str = "## Fixed\n- everything",
    prerelease: bool = False,
    published: str = "2026-10-10T00:00:00Z",
) -> dict[str, object]:
    return {
        "tag_name": tag,
        "html_url": f"{PROJECT_URL}/releases/tag/{tag}",
        "published_at": published,
        "body": body,
        "prerelease": prerelease,
    }


def _transport(status: int = 200, payload: object = None, text: str = "") -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url == UPDATE_API, f"asked the wrong URL: {request.url}"
        if text:
            return httpx.Response(status, text=text)
        return httpx.Response(status, json=payload if payload is not None else {})

    return httpx.MockTransport(handler)


# ---------------------------------------------------------------------------
class TestVersionComparison:
    def test_numeric_not_lexical(self) -> None:
        """'0.10.0' < '0.9.0' as text, which would hide two releases."""
        assert is_newer("0.10.0", "0.9.0") is True

    def test_a_leading_v_is_stripped(self) -> None:
        assert parse_version("v0.2.1") == (0, 2, 1)

    def test_equal_is_not_newer(self) -> None:
        assert is_newer("0.1.0", "0.1.0") is False

    def test_older_is_not_newer(self) -> None:
        assert is_newer("0.0.9", "0.1.0") is False

    def test_the_current_version_parses(self) -> None:
        assert parse_version(__version__), f"{__version__} should be comparable"


# ---------------------------------------------------------------------------
class TestInstallKind:
    def test_a_clone_is_detected_by_its_git_directory(self, tmp_path: Path) -> None:
        (tmp_path / ".git").mkdir()
        assert install_kind(tmp_path) == "git"

    def test_an_installed_package_is_pip(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("d3ta1l3r.updater.metadata.version", lambda _name: "0.1.0")
        assert install_kind(tmp_path) == "pip"

    def test_neither_is_unknown(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def missing(_name: str) -> str:
            raise metadata.PackageNotFoundError(_name)

        monkeypatch.setattr("d3ta1l3r.updater.metadata.version", missing)
        assert install_kind(tmp_path) == "unknown"

    def test_a_clone_wins_over_the_package_metadata(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """pip-upgrading a clone would leave the running code untouched."""
        (tmp_path / ".git").mkdir()
        monkeypatch.setattr("d3ta1l3r.updater.metadata.version", lambda _name: "0.1.0")
        assert install_kind(tmp_path) == "git"


class TestUpdateCommand:
    def test_git_uses_fast_forward_only(self, tmp_path: Path) -> None:
        assert update_command("git", tmp_path) == [
            "git", "-C", str(tmp_path), "pull", "--ff-only"
        ]

    def test_pip_targets_the_running_interpreter(self) -> None:
        """`pip` on PATH may belong to another Python; sys.executable cannot."""
        assert update_command("pip") == [
            sys.executable, "-m", "pip", "install", "--upgrade", "d3ta1l3r"
        ]

    def test_an_unknown_install_gets_no_command(self) -> None:
        assert update_command("unknown") == []

    def test_the_command_is_a_list_not_a_shell_string(self) -> None:
        for kind in ("git", "pip"):
            assert isinstance(update_command(kind), list)
            assert all(isinstance(part, str) for part in update_command(kind))


# ---------------------------------------------------------------------------
class TestCheckForUpdate:
    def test_a_newer_release_is_reported(self) -> None:
        info = check_for_update(transport=_transport(200, _release("v9.9.9")), current="0.1.0")
        assert info.available is True
        assert info.latest == "v9.9.9"
        assert info.reachable is True

    def test_being_up_to_date_is_reported(self) -> None:
        info = check_for_update(transport=_transport(200, _release("0.1.0")), current="0.1.0")
        assert info.available is False
        assert "up to date" in info.message

    def test_an_older_release_is_not_an_update(self) -> None:
        info = check_for_update(transport=_transport(200, _release("0.0.1")), current="0.1.0")
        assert info.available is False

    def test_no_releases_yet_is_not_an_error(self) -> None:
        """A project with no releases is normal, not a failure to fix."""
        info = check_for_update(transport=_transport(404, text="Not Found"), current="0.1.0")
        assert info.latest == ""
        assert info.available is False
        assert "no published releases" in info.message

    def test_a_network_failure_is_reported_not_raised(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("refused", request=request)

        info = check_for_update(transport=httpx.MockTransport(handler), current="0.1.0")
        assert info.reachable is False
        assert "could not reach" in info.message
        assert PROJECT_URL in info.message

    def test_rate_limiting_is_explained(self) -> None:
        info = check_for_update(
            transport=_transport(403, text='{"message": "API rate limit exceeded"}'),
            current="0.1.0",
        )
        assert info.reachable is False
        assert "rate-limit" in info.message.lower()

    def test_a_non_json_body_is_handled(self) -> None:
        info = check_for_update(transport=_transport(200, text="<html>"), current="0.1.0")
        assert info.reachable is False
        assert "not JSON" in info.message

    def test_a_pre_release_is_flagged(self) -> None:
        info = check_for_update(
            transport=_transport(200, _release("v1.0.0-rc1", prerelease=True)), current="0.1.0"
        )
        assert info.available is True
        assert info.prerelease is True

    def test_a_hyphenated_tag_counts_as_a_pre_release(self) -> None:
        info = check_for_update(transport=_transport(200, _release("v1.0.0-beta.2")), current="0.1.0")
        assert info.prerelease is True

    def test_a_missing_tag_is_not_an_update(self) -> None:
        info = check_for_update(transport=_transport(200, {"html_url": "x"}), current="0.1.0")
        assert info.available is False
        assert "no version tag" in info.message

    def test_checking_writes_nothing(self, tmp_path: Path) -> None:
        """The whole point of --check: nothing on disk changes."""
        before = sorted(p.name for p in tmp_path.iterdir())
        check_for_update(transport=_transport(200, _release("v9.9.9")), current="0.1.0")
        assert sorted(p.name for p in tmp_path.iterdir()) == before

    def test_the_json_form_is_machine_readable(self) -> None:
        info = check_for_update(transport=_transport(200, _release("v9.9.9")), current="0.1.0")
        payload = json.loads(dumps_json(info))
        assert payload["update_available"] is True
        assert payload["current"] == "0.1.0"


# ---------------------------------------------------------------------------
class TestApplyUpdate:
    def _info(self, **kwargs: object) -> UpdateInfo:
        base = {
            "current": "0.1.0",
            "latest": "v9.9.9",
            "url": f"{PROJECT_URL}/releases/tag/v9.9.9",
            "kind": "pip",
        }
        base.update(kwargs)  # type: ignore[arg-type]
        info = UpdateInfo(**base)  # type: ignore[arg-type]
        info.command = update_command(info.kind)
        return info

    def test_nothing_to_do_does_nothing(self) -> None:
        info = self._info(latest="0.1.0")
        code, _ = apply_update(info)
        assert code == 0

    def test_a_pre_release_is_refused_by_default(self) -> None:
        info = self._info(latest="v9.9.9-rc1", prerelease=True)
        code, message = apply_update(info)
        assert code == 1
        assert "pre-release" in message
        assert "--pre" in message

    def test_a_pre_release_is_allowed_when_asked(self, monkeypatch: pytest.MonkeyPatch) -> None:
        info = self._info(latest="v9.9.9-rc1", prerelease=True)
        monkeypatch.setattr(
            "d3ta1l3r.updater.subprocess.run", lambda *a, **k: subprocess.CompletedProcess(a, 0, "", "")
        )
        code, _ = apply_update(info, allow_prerelease=True)
        assert code == 0

    def test_an_unknown_install_refuses_to_guess(self) -> None:
        info = self._info(kind="unknown")
        info.command = []
        code, message = apply_update(info)
        assert code == 1
        assert "no update command" in message

    def test_the_subprocess_runs_without_a_shell(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """shell=True with attacker-influenced text would be an injection."""
        seen: dict[str, object] = {}

        def fake_run(argv, **kwargs):  # type: ignore[no-untyped-def]
            seen["argv"] = argv
            seen["kwargs"] = kwargs
            return subprocess.CompletedProcess(argv, 0, "ok", "")

        monkeypatch.setattr("d3ta1l3r.updater.subprocess.run", fake_run)
        code, output = apply_update(self._info())
        assert code == 0
        assert "shell" not in seen["kwargs"], "subprocess must never get shell=True"
        assert output == "ok"

    def test_a_failed_command_reports_its_exit_code(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            "d3ta1l3r.updater.subprocess.run",
            lambda *a, **k: subprocess.CompletedProcess(a, 1, "", "permission denied"),
        )
        code, output = apply_update(self._info())
        assert code == 1
        assert "permission denied" in output

    def test_a_missing_interpreter_is_handled(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def boom(*args: object, **kwargs: object) -> object:
            raise OSError("git not found")

        monkeypatch.setattr("d3ta1l3r.updater.subprocess.run", boom)
        code, message = apply_update(self._info())
        assert code == 1
        assert "could not run" in message


# ---------------------------------------------------------------------------
class TestUpdateCommandLine:
    def _stub(
        self,
        monkeypatch: pytest.MonkeyPatch,
        info: UpdateInfo,
        applied: list[UpdateInfo] | None = None,
        *,
        kind: str = "pip",
    ) -> None:
        # This checkout is a clone, so without pinning the install kind these
        # tests would take the branch path instead of the release one.
        monkeypatch.setattr("d3ta1l3r.cli.install_kind", lambda *a, **k: kind)
        monkeypatch.setattr("d3ta1l3r.cli.check_for_update", lambda **_kw: info)
        if applied is not None:
            monkeypatch.setattr(
                "d3ta1l3r.cli.apply_update",
                lambda target, **kw: (applied.append(target), (0, "done"))[1],
            )

    def _available(self) -> UpdateInfo:
        info = UpdateInfo(
            current="0.1.0",
            latest="v9.9.9",
            url=f"{PROJECT_URL}/releases/tag/v9.9.9",
            published_at="2026-10-10T00:00:00Z",
            notes="## Fixed\n- everything",
            kind="pip",
        )
        info.command = update_command("pip")
        return info

    def test_check_reports_without_offering_to_install(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        applied: list[UpdateInfo] = []
        self._stub(monkeypatch, self._available(), applied)
        assert main(["update", "--check"]) == EXIT_OK
        out = capsys.readouterr().out
        assert "v9.9.9" in out
        assert not applied, "--check must never install"

    def test_a_declined_prompt_installs_nothing(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        applied: list[UpdateInfo] = []
        self._stub(monkeypatch, self._available(), applied)
        monkeypatch.setattr("builtins.input", lambda *_: "n")
        assert main(["update"]) == EXIT_OK
        assert not applied, "declining must leave the install alone"
        assert "left it alone" in capsys.readouterr().out

    def test_yes_installs(self, monkeypatch: pytest.MonkeyPatch) -> None:
        applied: list[UpdateInfo] = []
        self._stub(monkeypatch, self._available(), applied)
        assert main(["update", "--yes"]) == EXIT_OK
        assert len(applied) == 1

    def test_an_accepted_prompt_installs(self, monkeypatch: pytest.MonkeyPatch) -> None:
        applied: list[UpdateInfo] = []
        self._stub(monkeypatch, self._available(), applied)
        monkeypatch.setattr("builtins.input", lambda *_: "y")
        assert main(["update"]) == EXIT_OK
        assert len(applied) == 1

    def test_the_command_is_shown_before_the_question(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """You should see what you are authorising before you authorise it."""
        self._stub(monkeypatch, self._available(), None)
        monkeypatch.setattr("builtins.input", lambda *_: "n")
        main(["update"])
        out = capsys.readouterr().out
        assert "would run:" in out
        assert out.index("would run:") < out.index("Install v9.9.9?")

    def test_up_to_date_exits_cleanly(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        info = UpdateInfo(current="0.1.0", latest="0.1.0", kind="pip")
        info.message = "up to date (this is 0.1.0, newest release is 0.1.0)"
        self._stub(monkeypatch, info, [])
        assert main(["update"]) == EXIT_OK
        assert "up to date" in capsys.readouterr().out

    def test_unreachable_is_a_failure(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        info = UpdateInfo(current="0.1.0", kind="pip", reachable=False,
                          message="could not reach the release API (ConnectError).")
        self._stub(monkeypatch, info, [])
        assert main(["update"]) == EXIT_FAILURE

    def test_a_pre_release_is_refused_without_running_anything(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """--yes must not silently move you onto an rc."""
        info = self._available()
        info.latest, info.prerelease = "v9.9.9-rc1", True
        applied: list[UpdateInfo] = []
        self._stub(monkeypatch, info, applied)
        assert main(["update", "--yes"]) == EXIT_FAILURE
        assert not applied, "a pre-release must never install on --yes alone"
        out = capsys.readouterr().out
        assert "pre-release" in out
        assert "--pre" in out
        assert "exited 1" not in out, "nothing ran, so do not report a command failure"

    def test_pre_allows_a_pre_release(self, monkeypatch: pytest.MonkeyPatch) -> None:
        info = self._available()
        info.latest, info.prerelease = "v9.9.9-rc1", True
        applied: list[UpdateInfo] = []
        self._stub(monkeypatch, info, applied)
        assert main(["update", "--yes", "--pre"]) == EXIT_OK
        assert len(applied) == 1

    def test_json_output_is_parseable(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        self._stub(monkeypatch, self._available(), None)
        assert main(["update", "--json"]) == EXIT_OK
        payload = json.loads(capsys.readouterr().out)
        assert payload["update_available"] is True
        assert payload["current"] == "0.1.0"

    def test_a_failed_install_is_reported(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setattr("d3ta1l3r.cli.install_kind", lambda *a, **k: "pip")
        monkeypatch.setattr("d3ta1l3r.cli.check_for_update", lambda **_kw: self._available())
        monkeypatch.setattr("d3ta1l3r.cli.apply_update", lambda target, **kw: (1, "boom"))
        assert main(["update", "--yes"]) == EXIT_FAILURE
        assert "boom" in capsys.readouterr().out


# ---------------------------------------------------------------------------
def _commit(sha: str, message: str = "a change", date: str = "2026-10-10T00:00:00Z") -> dict:
    return {
        "sha": sha,
        "commit": {"message": message, "author": {"date": date}},
    }


def _commits_transport(
    shas: list[str], status: int = 200, text: str = "", payload: object = None
) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path.endswith("/commits"), f"asked the wrong URL: {request.url}"
        assert request.url.params.get("sha") is not None, "the branch must be sent"
        if text:
            return httpx.Response(status, text=text)
        if payload is not None:
            return httpx.Response(status, json=payload)
        return httpx.Response(status, json=[_commit(sha) for sha in shas])

    return httpx.MockTransport(handler)


class TestBranchUpdates:
    """A clone with no releases is compared by commit, not by version."""

    def _root(self, tmp_path: Path, head: str) -> Path:
        """A stand-in checkout whose HEAD we control."""
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / ".git").mkdir()
        (repo / "HEAD").write_text(head)
        return repo

    def _stub_head(self, monkeypatch: pytest.MonkeyPatch, head: str) -> None:
        monkeypatch.setattr("d3ta1l3r.updater.local_head", lambda root=None: head)

    def test_behind_count_comes_from_where_head_sits(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        shas = ["a" * 40, "b" * 40, "c" * 40]
        self._stub_head(monkeypatch, "c" * 40)
        info = check_branch_updates(
            "dev", transport=_commits_transport(shas), package_root=Path("/tmp")
        )
        assert info.mode == "branch"
        assert info.available is True
        assert info.behind == 2, "two commits landed since c"

    def test_up_to_date_is_not_an_update(self, monkeypatch: pytest.MonkeyPatch) -> None:
        shas = ["a" * 40, "b" * 40]
        self._stub_head(monkeypatch, "a" * 40)
        info = check_branch_updates(
            "dev", transport=_commits_transport(shas), package_root=Path("/tmp")
        )
        assert info.available is False
        assert info.behind == 0
        assert "up to date" in info.message

    def test_more_than_a_page_behind_is_still_an_update(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Not finding HEAD in the page means 'at least this many', not 'current'."""
        shas = [f"{i:040x}" for i in range(20)]
        self._stub_head(monkeypatch, "f" * 40)
        info = check_branch_updates(
            "dev", transport=_commits_transport(shas), package_root=Path("/tmp")
        )
        assert info.behind is None
        assert info.available is True
        assert "more than 20" in info.message

    def test_only_the_commits_you_are_missing_are_listed(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        shas = ["a" * 40, "b" * 40, "c" * 40, "d" * 40]
        self._stub_head(monkeypatch, "c" * 40)
        info = check_branch_updates(
            "dev", transport=_commits_transport(shas), package_root=Path("/tmp")
        )
        assert [item["sha"] for item in info.commits] == ["a" * 8, "b" * 8]

    def test_the_command_names_the_remote_and_the_branch(self) -> None:
        command = update_command("git", Path("/repo"), "dev")
        assert command == ["git", "-C", "/repo", "pull", "--ff-only", "origin", "dev"]

    def test_without_a_branch_the_command_is_the_plain_fast_forward(self) -> None:
        """Backwards compatible: an unnamed branch keeps the old argv."""
        assert update_command("git", Path("/repo")) == [
            "git", "-C", "/repo", "pull", "--ff-only"
        ]

    def test_a_missing_branch_is_reported(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._stub_head(monkeypatch, "a" * 40)
        info = check_branch_updates(
            "nope", transport=_commits_transport([], 404, text="Not Found"),
            package_root=Path("/tmp"),
        )
        assert info.reachable is False
        assert "no branch" in info.message

    def test_a_network_failure_is_reported_not_raised(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._stub_head(monkeypatch, "a" * 40)

        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("refused", request=request)

        info = check_branch_updates(
            "dev", transport=httpx.MockTransport(handler), package_root=Path("/tmp")
        )
        assert info.reachable is False
        assert "could not reach" in info.message

    def test_an_unreadable_head_refuses_to_compare(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._stub_head(monkeypatch, "")
        info = check_branch_updates(
            "dev", transport=_commits_transport(["a" * 40]), package_root=Path("/tmp")
        )
        assert info.reachable is False
        assert "cannot read HEAD" in info.message

    def test_checking_writes_nothing(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        before = sorted(p.name for p in tmp_path.iterdir())
        self._stub_head(monkeypatch, "c" * 40)
        check_branch_updates(
            "dev", transport=_commits_transport(["a" * 40, "b" * 40, "c" * 40]),
            package_root=tmp_path,
        )
        assert sorted(p.name for p in tmp_path.iterdir()) == before

    def test_the_json_form_carries_the_branch_detail(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._stub_head(monkeypatch, "b" * 40)
        info = check_branch_updates(
            "dev", transport=_commits_transport(["a" * 40, "b" * 40]),
            package_root=Path("/tmp"),
        )
        payload = json.loads(dumps_json(info))
        assert payload["mode"] == "branch"
        assert payload["branch"] == "dev"
        assert payload["behind"] == 1


class TestBranchCommandLine:
    def _info(self, behind: int | None = 2) -> UpdateInfo:
        info = UpdateInfo(
            current="c" * 12, latest="a" * 12, kind="git", mode="branch", branch="dev",
            behind=behind, url=f"{PROJECT_URL}/commits/dev",
            commits=[
                {"sha": "a" * 8, "date": "2026-10-10", "message": "newest"},
                {"sha": "b" * 8, "date": "2026-10-09", "message": "second"},
            ],
        )
        info.command = update_command("git", Path("/repo"), "dev")
        info.message = f"{behind} commit(s) behind origin/dev"
        return info

    def _stub(
        self,
        monkeypatch: pytest.MonkeyPatch,
        info: UpdateInfo,
        applied: list[UpdateInfo] | None = None,
    ) -> None:
        monkeypatch.setattr("d3ta1l3r.cli.install_kind", lambda *a, **k: "git")
        monkeypatch.setattr("d3ta1l3r.cli.resolve_branch", lambda *a, **k: "dev")
        monkeypatch.setattr("d3ta1l3r.cli.check_branch_updates", lambda *a, **k: info)
        if applied is not None:
            monkeypatch.setattr(
                "d3ta1l3r.cli.apply_update",
                lambda target, **kw: (applied.append(target), (0, "done"))[1],
            )

    def test_the_commits_are_shown_before_the_question(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        self._stub(monkeypatch, self._info(), None)
        monkeypatch.setattr("builtins.input", lambda *_: "n")
        main(["update"])
        out = capsys.readouterr().out
        assert "newest" in out and "second" in out
        assert "origin dev" in out, "the command names remote and branch"
        assert out.index("would run:") < out.index("Fast-forward to")

    def test_check_fetches_nothing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        applied: list[UpdateInfo] = []
        self._stub(monkeypatch, self._info(), applied)
        assert main(["update", "--check"]) == EXIT_OK
        assert not applied

    def test_a_declined_prompt_merges_nothing(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        applied: list[UpdateInfo] = []
        self._stub(monkeypatch, self._info(), applied)
        monkeypatch.setattr("builtins.input", lambda *_: "n")
        main(["update"])
        assert not applied
        assert "left it alone" in capsys.readouterr().out

    def test_yes_fast_forwards(self, monkeypatch: pytest.MonkeyPatch) -> None:
        applied: list[UpdateInfo] = []
        self._stub(monkeypatch, self._info(), applied)
        assert main(["update", "--yes"]) == EXIT_OK
        assert len(applied) == 1

    def test_up_to_date_exits_cleanly(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        info = self._info(behind=0)
        info.message = "up to date with origin/dev"
        self._stub(monkeypatch, info, [])
        assert main(["update"]) == EXIT_OK
        assert "up to date" in capsys.readouterr().out

    def test_a_branch_named_on_the_command_line_reaches_the_check(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        seen: list[str] = []
        monkeypatch.setattr("d3ta1l3r.cli.install_kind", lambda *a, **k: "git")
        # resolve normally, so --branch is what decides it
        monkeypatch.setattr(
            "d3ta1l3r.cli.resolve_branch",
            lambda explicit="", package_root=None: explicit or "default-branch",
        )

        def fake_check(branch: str, **_kw: object) -> UpdateInfo:
            seen.append(branch)
            return UpdateInfo(
                current="c", kind="git", mode="branch", branch=branch,
                message="up to date", behind=0,
            )

        monkeypatch.setattr("d3ta1l3r.cli.check_branch_updates", fake_check)
        assert main(["update", "--branch", "other", "--check"]) == EXIT_OK
        assert seen == ["other"], "the named branch must be the one compared"


class TestBranchResolution:
    def test_the_checked_out_branch_is_the_default(self, tmp_path: Path) -> None:
        monkeypatch_root = tmp_path / "repo"
        (monkeypatch_root / ".git").mkdir(parents=True)
        assert resolve_branch("", monkeypatch_root) == current_branch(monkeypatch_root)

    def test_an_explicit_branch_wins(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("D3TA1L3R_UPDATE_BRANCH", "from-env")
        assert resolve_branch("explicit", tmp_path) == "explicit"
        assert resolve_branch("", tmp_path) == "from-env"

    def test_a_detached_head_is_not_a_branch(self, tmp_path: Path) -> None:
        """`git rev-parse --abbrev-ref HEAD` says "HEAD" when detached."""
        repo = tmp_path / "repo"
        (repo / ".git").mkdir(parents=True)
        assert current_branch(repo) == ""
