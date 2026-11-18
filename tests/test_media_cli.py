"""The ``d3ta1l3r media`` commands, driven through ``main()``.

These assert the parts a script depends on: exit codes, the JSON shape, and the
fact that ``--fail-on`` can stop a release pipeline before a photo with GPS in it
is published.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from d3ta1l3r.cli import (
    EXIT_FAILURE,
    EXIT_NEW_FINDINGS,
    EXIT_OK,
    EXIT_USAGE,
    build_parser,
    main,
)
from tests.test_media import full_exif, id3_with, jpeg_with, mp4_with, png_with, text_frame


def write_photo(tmp_path: Path) -> Path:
    """A JPEG carrying GPS, serial numbers and an owner name."""
    target = tmp_path / "photo.jpg"
    target.write_bytes(jpeg_with(full_exif()))
    return target


class TestParser:
    """The command must be discoverable and its sub-commands required."""

    def test_media_is_a_command(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["media", "formats"])
        assert args.command == "media"
        assert args.media_command == "formats"

    def test_a_sub_command_is_required(self) -> None:
        with pytest.raises(SystemExit):
            build_parser().parse_args(["media"])


class TestFormats:
    """The format table is the map for everything else."""

    def test_table_mentions_the_scrubbable_formats(self, capsys) -> None:
        assert main(["media", "formats"]) == EXIT_OK
        out = capsys.readouterr().out
        assert "jpeg" in out and "webp" in out and "yes" in out

    def test_json_is_machine_readable(self, capsys) -> None:
        assert main(["media", "formats", "--json"]) == EXIT_OK
        payload = json.loads(capsys.readouterr().out)
        by_name = {row["format"]: row for row in payload["formats"]}
        assert by_name["jpeg"]["scrubbable"] is True
        assert by_name["mp4"]["scrubbable"] is False


class TestScan:
    """Human output, JSON output, thresholds and the CI gate."""

    def test_scan_reports_a_score(self, tmp_path, capsys) -> None:
        photo = write_photo(tmp_path)
        assert main(["media", "scan", str(photo)]) == EXIT_OK
        out = capsys.readouterr().out
        assert "score 100/100" in out
        assert "GPS position" in out
        assert "Body serial number" in out

    def test_scan_json_shape(self, tmp_path, capsys) -> None:
        photo = write_photo(tmp_path)
        assert main(["media", "scan", str(photo), "--json"]) == EXIT_OK
        payload = json.loads(capsys.readouterr().out)
        assert payload["summary"]["files"] == 1
        assert payload["files"][0]["coordinates"] is not None
        assert payload["files"][0]["exposures"]

    def test_clean_file_exits_zero(self, tmp_path, capsys) -> None:
        target = tmp_path / "clean.png"
        target.write_bytes(png_with())
        assert main(["media", "scan", str(target), "--json"]) == EXIT_OK
        payload = json.loads(capsys.readouterr().out)
        assert payload["files"][0]["score"] == 0

    def test_fail_on_critical_returns_three(self, tmp_path) -> None:
        photo = write_photo(tmp_path)
        assert main(["media", "scan", str(photo), "--fail-on", "critical"]) == EXIT_NEW_FINDINGS

    def test_fail_on_critical_passes_a_clean_file(self, tmp_path) -> None:
        target = tmp_path / "clean.png"
        target.write_bytes(png_with())
        assert main(["media", "scan", str(target), "--fail-on", "critical"]) == EXIT_OK

    def test_min_severity_hides_but_does_not_change_the_score(self, tmp_path, capsys) -> None:
        photo = write_photo(tmp_path)
        assert main(["media", "scan", str(photo), "--min-severity", "critical"]) == EXIT_OK
        out = capsys.readouterr().out
        assert "score 100/100" in out
        assert "Camera model" not in out
        assert "below the --min-severity threshold" in out

    def test_directory_is_walked(self, tmp_path, capsys) -> None:
        write_photo(tmp_path)
        (tmp_path / "clean.png").write_bytes(png_with())
        assert main(["media", "scan", str(tmp_path)]) == EXIT_OK
        out = capsys.readouterr().out
        assert "2 file(s)" in out

    def test_markdown_report_is_written(self, tmp_path, capsys) -> None:
        photo = write_photo(tmp_path)
        report = tmp_path / "report.md"
        assert main(["media", "scan", str(photo), "--markdown", str(report)]) == EXIT_OK
        assert "# Media metadata" in report.read_text()
        assert "openstreetmap.org" in report.read_text()

    def test_missing_path_is_a_usage_error(self, tmp_path) -> None:
        assert main(["media", "scan", str(tmp_path / "nope.jpg")]) == EXIT_USAGE

    def test_max_bytes_is_honoured(self, tmp_path, capsys) -> None:
        photo = write_photo(tmp_path)
        assert main(["media", "scan", str(photo), "--max-bytes", "16", "--json"]) == EXIT_OK
        payload = json.loads(capsys.readouterr().out)
        assert payload["files"][0]["truncated"] is True


class TestScrub:
    """Scrubbing writes a new file, verifies it, and refuses the impossible."""

    def test_scrub_writes_a_clean_copy(self, tmp_path, capsys) -> None:
        photo = write_photo(tmp_path)
        assert main(["media", "scrub", str(photo)]) == EXIT_OK
        out = capsys.readouterr().out
        assert "residual: score 0/100" in out
        cleaned = tmp_path / "photo.clean.jpg"
        assert cleaned.exists()

        assert main(["media", "scan", str(cleaned), "--json"]) == EXIT_OK
        payload = json.loads(capsys.readouterr().out)
        assert payload["files"][0]["score"] == 0

    def test_out_names_the_destination(self, tmp_path) -> None:
        photo = write_photo(tmp_path)
        target = tmp_path / "safe.jpg"
        assert main(["media", "scrub", str(photo), "--out", str(target)]) == EXIT_OK
        assert target.exists()

    def test_out_with_two_inputs_is_a_usage_error(self, tmp_path) -> None:
        first = write_photo(tmp_path)
        second = tmp_path / "second.jpg"
        second.write_bytes(jpeg_with(full_exif()))
        assert main(["media", "scrub", str(first), str(second), "--out", "x.jpg"]) == EXIT_USAGE

    def test_existing_destination_needs_overwrite(self, tmp_path, capsys) -> None:
        photo = write_photo(tmp_path)
        assert main(["media", "scrub", str(photo)]) == EXIT_OK
        assert main(["media", "scrub", str(photo)]) == EXIT_FAILURE
        assert "already exists" in capsys.readouterr().err
        assert main(["media", "scrub", str(photo), "--overwrite"]) == EXIT_OK

    def test_unsupported_format_explains_itself(self, tmp_path, capsys) -> None:
        video = tmp_path / "clip.mp4"
        video.write_bytes(mp4_with())
        assert main(["media", "scrub", str(video)]) == EXIT_FAILURE
        assert "ffmpeg" in capsys.readouterr().err

    def test_json_output_lists_removed_blocks(self, tmp_path, capsys) -> None:
        photo = write_photo(tmp_path)
        assert main(["media", "scrub", str(photo), "--json"]) == EXIT_OK
        payload = json.loads(capsys.readouterr().out)
        assert payload["problems"] == []
        assert "APP1" in payload["scrubbed"][0]["removed"]
        assert "data" not in payload["scrubbed"][0]

    def test_scrubbing_an_mp3_keeps_the_audio(self, tmp_path, capsys) -> None:
        song = tmp_path / "song.mp3"
        song.write_bytes(id3_with([(b"TPE1", text_frame("Alice"))]) + b"\xff\xfb" + b"\x00" * 32)
        assert main(["media", "scrub", str(song)]) == EXIT_OK
        assert (tmp_path / "song.clean.mp3").read_bytes().startswith(b"\xff\xfb")
