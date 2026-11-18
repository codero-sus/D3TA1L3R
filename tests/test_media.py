"""Tests for :mod:`d3ta1l3r.media`.

Every fixture here is built byte by byte in Python, not copied from a binary
blob in the repository.  That matters for two reasons: a reader can see exactly
which tag a test is asserting on, and a fixture cannot silently contain a real
person's GPS coordinates.

The builders below are deliberately small implementations of the container
specs.  They are the independent second opinion for the parser: if both agree,
the parse is probably right.
"""

from __future__ import annotations

import dataclasses
import datetime
import json
import struct
import zlib
from pathlib import Path

import pytest

from d3ta1l3r.errors import D3ta1l3rError
from d3ta1l3r.media import (
    Exposure,
    MediaFormat,
    MediaReport,
    MetadataField,
    ScrubResult,
    Severity,
    analyze_bytes,
    analyze_path,
    iter_media_files,
    render_markdown,
    scrub_bytes,
    scrub_path,
    sniff_format,
    supported_formats,
)

# ---------------------------------------------------------------------------
# Builders
# ---------------------------------------------------------------------------
_TYPE_WIDTH = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 7: 1, 9: 4, 10: 8}


def _ascii_tag(tag: int, text: str) -> tuple[int, int, int, bytes]:
    raw = text.encode("ascii") + b"\x00"
    return (tag, 2, len(raw), raw)


def _short_tag(tag: int, values: list[int]) -> tuple[int, int, int, bytes]:
    return (tag, 3, len(values), b"".join(struct.pack("<H", v) for v in values))


def _long_tag(tag: int, value: int) -> tuple[int, int, int, bytes]:
    return (tag, 4, 1, struct.pack("<I", value))


def _rational_tag(tag: int, pairs: list[tuple[int, int]], type_id: int = 5):
    raw = b"".join(struct.pack("<II", n, d) for n, d in pairs)
    return (tag, type_id, len(pairs), raw)


def _ifd(entries: list[tuple[int, int, int, bytes]], base: int) -> tuple[bytes, bytes]:
    """Pack one little-endian IFD at absolute ``base``; return (ifd, data)."""
    count = len(entries)
    data_start = base + 2 + 12 * count + 4
    body = b""
    data = b""
    for tag, type_id, value_count, raw in entries:
        if len(raw) <= 4:
            body += struct.pack("<HHI", tag, type_id, value_count) + raw.ljust(4, b"\x00")
        else:
            body += struct.pack("<HHII", tag, type_id, value_count, data_start + len(data))
            data += raw
            if len(data) % 2:
                data += b"\x00"
    return struct.pack("<H", count) + body + struct.pack("<I", 0), data


def build_tiff(
    ifd0: list[tuple[int, int, int, bytes]],
    exif: list[tuple[int, int, int, bytes]] | None = None,
    gps: list[tuple[int, int, int, bytes]] | None = None,
    *,
    next_ifd: list[tuple[int, int, int, bytes]] | None = None,
) -> bytes:
    """Assemble a minimal little-endian TIFF/EXIF blob with sub-IFDs."""
    exif = exif or []
    gps = gps or []
    entries = list(ifd0)
    if exif:
        entries.append(_long_tag(0x8769, 0))
    if gps:
        entries.append(_long_tag(0x8825, 0))

    # Sizes are independent of the base offset, so measure first, then place.
    exif_ifd, exif_data = _ifd(exif, 0) if exif else (b"", b"")
    _gps_ifd, gps_data = _ifd(gps, 0) if gps else (b"", b"")
    shape, ifd0_data = _ifd(entries, 0)

    exif_offset = 8 + len(shape) + len(ifd0_data)
    gps_offset = exif_offset + len(exif_ifd) + len(exif_data)

    patched: list[tuple[int, int, int, bytes]] = []
    for entry in entries:
        if entry[0] == 0x8769:
            patched.append(_long_tag(0x8769, exif_offset))
        elif entry[0] == 0x8825:
            patched.append(_long_tag(0x8825, gps_offset))
        else:
            patched.append(entry)

    ifd0_bytes, ifd0_data = _ifd(patched, 8)
    exif_bytes, exif_data = _ifd(exif, exif_offset) if exif else (b"", b"")
    gps_bytes, gps_data = _ifd(gps, gps_offset) if gps else (b"", b"")

    blob = b"II" + struct.pack("<HI", 42, 8) + ifd0_bytes + ifd0_data
    blob += exif_bytes + exif_data
    blob += gps_bytes + gps_data

    if next_ifd is not None:
        thumb_offset = len(blob)
        thumb_bytes, thumb_data = _ifd(next_ifd, thumb_offset)
        pointer_at = 8 + 2 + 12 * len(patched)
        blob = blob[:pointer_at] + struct.pack("<I", thumb_offset) + blob[pointer_at + 4 :]
        blob += thumb_bytes + thumb_data
    return blob


def jpeg_with(tiff: bytes | None = None, *, comment: bytes | None = None, scan: bytes = b"\x11\x22") -> bytes:
    """A structurally valid JPEG, optionally carrying EXIF and a comment."""
    out = b"\xff\xd8"
    app0 = b"JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
    out += b"\xff\xe0" + struct.pack(">H", len(app0) + 2) + app0
    if tiff is not None:
        payload = b"Exif\x00\x00" + tiff
        out += b"\xff\xe1" + struct.pack(">H", len(payload) + 2) + payload
    if comment is not None:
        out += b"\xff\xfe" + struct.pack(">H", len(comment) + 2) + comment
    sof = b"\x08" + struct.pack(">HH", 2, 3) + b"\x03\x01\x11\x00\x02\x11\x01\x03\x11\x01"
    out += b"\xff\xc0" + struct.pack(">H", len(sof) + 2) + sof
    sos = b"\x03\x01\x00\x02\x11\x03\x11\x00\x3f\x00"
    out += b"\xff\xda" + struct.pack(">H", len(sos) + 2) + sos + scan
    out += b"\xff\xd9"
    return out


def _png_chunk(kind: bytes, payload: bytes) -> bytes:
    return (
        struct.pack(">I", len(payload))
        + kind
        + payload
        + struct.pack(">I", zlib.crc32(kind + payload) & 0xFFFFFFFF)
    )


def png_with(*chunks: tuple[bytes, bytes], width: int = 4, height: int = 3) -> bytes:
    """A PNG with a real IHDR, generated IDAT and arbitrary extra chunks."""
    out = b"\x89PNG\r\n\x1a\n"
    out += _png_chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
    for kind, payload in chunks:
        out += _png_chunk(kind, payload)
    out += _png_chunk(b"IDAT", zlib.compress(b"\x00" * (height * (width * 3 + 1))))
    out += _png_chunk(b"IEND", b"")
    return out


def _box(fourcc: bytes, payload: bytes) -> bytes:
    return struct.pack(">I", len(payload) + 8) + fourcc + payload


def _riff_chunk(kind: bytes, payload: bytes) -> bytes:
    """RIFF chunks use little-endian sizes and pad to an even length."""
    out = kind + struct.pack("<I", len(payload)) + payload
    return out + (b"\x00" if len(payload) % 2 else b"")


def mp4_with(*, created: int = 0, udta: bytes = b"", ilst: bytes = b"") -> bytes:
    """A minimal MP4 with ftyp, moov/mvhd and optional udta/meta/ilst."""
    mvhd = b"\x00\x00\x00\x00" + struct.pack(">IIII", created, 0, 1000, 5000) + b"\x00" * 80
    children = _box(b"mvhd", mvhd)
    if udta:
        children += udta
    if ilst:
        meta = _box(b"meta", b"\x00\x00\x00\x00" + _box(b"ilst", ilst))
        children += meta
    return _box(b"ftyp", b"isom\x00\x00\x02\x00isomiso2") + _box(b"moov", children)


def _syncsafe(value: int) -> bytes:
    return bytes(
        [(value >> 21) & 0x7F, (value >> 14) & 0x7F, (value >> 7) & 0x7F, value & 0x7F]
    )


def id3_with(
    frames: list[tuple[bytes, bytes]], *, version: int = 3, unsync: bool = False
) -> bytes:
    """An ID3v2 tag (v2.3 32-bit frame sizes, v2.4 syncsafe)."""
    body = b""
    for frame_id, payload in frames:
        if version >= 4:
            body += frame_id + _syncsafe(len(payload)) + b"\x00\x00" + payload
        else:
            body += frame_id + struct.pack(">I", len(payload)) + b"\x00\x00" + payload
    flags = 0x80 if unsync else 0
    if unsync:
        body = body.replace(b"\xff", b"\xff\x00")
    return b"ID3" + bytes([version, 0, flags]) + _syncsafe(len(body)) + body


def text_frame(text: str, encoding: int = 0) -> bytes:
    """ID3 text-frame payload in the requested encoding byte."""
    if encoding == 1:
        return b"\x01" + text.encode("utf-16")
    if encoding == 3:
        return b"\x03" + text.encode("utf-8")
    return b"\x00" + text.encode("latin-1")


def flac_with(comments: dict[str, str], *, picture: bool = False) -> bytes:
    """A FLAC stream with STREAMINFO and a Vorbis comment block."""
    packed = (44100 << 44) | (0 << 41) | (15 << 36) | 88200
    streaminfo = struct.pack(">HH", 4096, 4096) + b"\x00" * 3 + struct.pack(">Q", packed)
    streaminfo += b"\x00" * 16
    vendor = b"reference libFLAC"
    items = [f"{key}={value}".encode() for key, value in comments.items()]
    body = struct.pack("<I", len(vendor)) + vendor + struct.pack("<I", len(items))
    for item in items:
        body += struct.pack("<I", len(item)) + item

    def block(btype: int, payload: bytes, last: bool) -> bytes:
        return bytes([btype | (0x80 if last else 0)]) + len(payload).to_bytes(3, "big") + payload

    out = b"fLaC" + block(0, streaminfo, False)
    if picture:
        out += block(4, body, False)
        out += block(6, b"\x00" * 32, True)
    else:
        out += block(4, body, True)
    return out + b"\xff\xf8" + b"\x00" * 64


def ogg_with(vendor: str = "Xiph.Org libVorbis", comments: dict[str, str] | None = None) -> bytes:
    """An Ogg stream carrying a real Vorbis comment header."""
    body = b"\x03vorbis" + struct.pack("<I", len(vendor)) + vendor.encode()
    items = [f"{key}={value}".encode() for key, value in (comments or {}).items()]
    body += struct.pack("<I", len(items))
    for item in items:
        body += struct.pack("<I", len(item)) + item
    return b"OggS" + b"\x00" * 22 + body


def id3_with_extended_header(frames: list[tuple[bytes, bytes]], *, version: int = 3) -> bytes:
    """An ID3v2 tag with an extended header in front of the frames."""
    body = b""
    for frame_id, payload in frames:
        if version >= 4:
            body += frame_id + _syncsafe(len(payload)) + b"\x00\x00" + payload
        else:
            body += frame_id + struct.pack(">I", len(payload)) + b"\x00\x00" + payload
    if version >= 4:
        extended = _syncsafe(6) + b"\x01\x00"
    else:
        extended = struct.pack(">I", 6) + b"\x00\x00" + b"\x00" * 4
    payload = extended + body
    return b"ID3" + bytes([version, 0, 0x40]) + _syncsafe(len(payload)) + payload


def wav_with(info: dict[str, str]) -> bytes:
    """A WAV with a fmt chunk and a LIST/INFO block."""
    payload = struct.pack("<HHIIHH", 1, 1, 44100, 88200, 2, 16)
    chunks = _riff_chunk(b"fmt ", payload)
    info_body = b"INFO"
    for key, value in info.items():
        raw = value.encode("ascii") + b"\x00"
        info_body += key.encode("ascii") + struct.pack("<I", len(raw)) + raw
        if len(raw) % 2:
            info_body += b"\x00"
    chunks += _riff_chunk(b"LIST", info_body)
    return b"RIFF" + struct.pack("<I", len(chunks) + 4) + b"WAVE" + chunks


def webp_with(*, exif: bytes = b"", xmp: bytes = b"", width: int = 8, height: int = 6) -> bytes:
    """A WebP with a VP8X header and optional EXIF/XMP chunks."""
    flags = 0
    if exif:
        flags |= 0x08
    if xmp:
        flags |= 0x04
    vp8x = bytes([flags, 0, 0, 0]) + (width - 1).to_bytes(3, "little")
    vp8x += (height - 1).to_bytes(3, "little")
    chunks = _riff_chunk(b"VP8X", vp8x)
    if exif:
        chunks += _riff_chunk(b"EXIF", exif)
    if xmp:
        chunks += _riff_chunk(b"XMP ", xmp)
    body = b"WEBP" + chunks
    return b"RIFF" + struct.pack("<I", len(body)) + body


# ---------------------------------------------------------------------------
# Reusable metadata
# ---------------------------------------------------------------------------
def full_exif() -> bytes:
    """EXIF carrying one of every kind of identifying field."""
    ifd0 = [
        _ascii_tag(0x010F, "Canon"),
        _ascii_tag(0x0110, "EOS R5"),
        _ascii_tag(0x0131, "Lightroom 13.2"),
        _ascii_tag(0x0132, "2026:03:04 11:22:33"),
        _ascii_tag(0x013B, "Alice Example"),
        _ascii_tag(0x013C, "alice-laptop"),
        _ascii_tag(0x010E, "rooftop at sunset"),
    ]
    exif = [
        _ascii_tag(0x9003, "2026:03:04 11:22:30"),
        _ascii_tag(0x9011, "+05:30"),
        _ascii_tag(0xA430, "Alice Example"),
        _ascii_tag(0xA431, "SN-0123456789"),
        _ascii_tag(0xA435, "LN-987654"),
        _ascii_tag(0xA434, "RF24-70mm F2.8 L IS USM"),
        (0x927C, 7, 16, b"MAKERNOTE-SERIAL"),
        (0x9286, 7, 12, b"shot for me"),
        _short_tag(0xA002, [3]),
        _short_tag(0xA003, [2]),
    ]
    gps = [
        _ascii_tag(0x0001, "N"),
        _rational_tag(0x0002, [(28, 1), (36, 1), (5040, 100)]),  # 28.6100
        _ascii_tag(0x0003, "E"),
        _rational_tag(0x0004, [(77, 1), (12, 1), (3240, 100)]),  # 77.2090
        _rational_tag(0x0006, [(2160, 10)]),  # 216 m
        _rational_tag(0x0007, [(6, 1), (52, 1), (1200, 100)]),
        _ascii_tag(0x001D, "2026:03:04"),
    ]
    return build_tiff(ifd0, exif, gps)


# ---------------------------------------------------------------------------
# Sniffing
# ---------------------------------------------------------------------------
class TestSniffing:
    """Content beats extension: the wrong format is how a scrub fails silently."""

    def test_jpeg(self) -> None:
        assert sniff_format(b"\xff\xd8\xff\xe0....") is MediaFormat.JPEG

    def test_png(self) -> None:
        assert sniff_format(b"\x89PNG\r\n\x1a\nrest") is MediaFormat.PNG

    def test_gif(self) -> None:
        assert sniff_format(b"GIF89a\x01\x00\x01\x00") is MediaFormat.GIF

    def test_webp(self) -> None:
        assert sniff_format(b"RIFF\x00\x00\x00\x00WEBPVP8 ") is MediaFormat.WEBP

    def test_wav_is_not_webp(self) -> None:
        assert sniff_format(b"RIFF\x00\x00\x00\x00WAVEfmt ") is MediaFormat.WAV

    def test_tiff(self) -> None:
        assert sniff_format(b"II*\x00\x08\x00\x00\x00") is MediaFormat.TIFF

    def test_bmp(self) -> None:
        assert sniff_format(b"BM" + b"\x00" * 20) is MediaFormat.BMP

    def test_flac(self) -> None:
        assert sniff_format(b"fLaC\x00\x00\x00\x22") is MediaFormat.FLAC

    def test_ogg(self) -> None:
        assert sniff_format(b"OggS\x00\x02\x00\x00") is MediaFormat.OGG

    def test_mp3_id3(self) -> None:
        assert sniff_format(id3_with([])) is MediaFormat.MP3

    def test_mp3_frame_sync(self) -> None:
        assert sniff_format(b"\xff\xfb\x90\x00rest") is MediaFormat.MP3

    def test_mp4(self) -> None:
        assert sniff_format(mp4_with()) is MediaFormat.MP4

    def test_mov_brand(self) -> None:
        assert sniff_format(_box(b"ftyp", b"qt  \x00\x00\x02\x00") + b"x") is MediaFormat.MOV

    def test_heic(self) -> None:
        assert sniff_format(_box(b"ftyp", b"heic\x00\x00\x00\x00mif1") + b"x") is MediaFormat.HEIC

    def test_avif(self) -> None:
        assert sniff_format(_box(b"ftyp", b"avif\x00\x00\x00\x00mif1") + b"x") is MediaFormat.AVIF

    def test_svg(self) -> None:
        assert sniff_format(b'<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg"/>') is MediaFormat.SVG

    def test_extension_fallback(self) -> None:
        assert sniff_format(b"garbage", "photo.jpeg") is MediaFormat.JPEG

    def test_unknown(self) -> None:
        assert sniff_format(b"garbage", "notes.txt") is MediaFormat.UNKNOWN

    def test_extension_does_not_override_content(self) -> None:
        """A .jpg that is really a PNG must be treated as a PNG."""
        assert sniff_format(png_with(), "lie.jpg") is MediaFormat.PNG


class TestFormatMetadata:
    """The small properties the CLI and dashboard rely on."""

    def test_kinds(self) -> None:
        assert MediaFormat.JPEG.kind == "image"
        assert MediaFormat.MP3.kind == "audio"
        assert MediaFormat.MP4.kind == "video"
        assert MediaFormat.UNKNOWN.kind == "unknown"

    def test_labels(self) -> None:
        assert MediaFormat.HEIC.label == "HEIC/HEIF"
        assert MediaFormat.MOV.label == "QuickTime"

    def test_supported_formats_lists_extensions(self) -> None:
        table = supported_formats()
        assert ".jpg" in table["jpeg"]
        assert ".webp" in table["webp"]
        assert table["unknown"] == []

    def test_severity_ordering(self) -> None:
        assert Severity.CRITICAL.rank > Severity.HIGH.rank > Severity.MEDIUM.rank
        assert Severity.INFO.weight == 0

    def test_severity_colour(self) -> None:
        assert Severity.CRITICAL.colour == "bright_red"


# ---------------------------------------------------------------------------
# EXIF
# ---------------------------------------------------------------------------
class TestExifParsing:
    """What a camera writes, and what it means once the file is public."""

    def test_make_and_model_are_read(self) -> None:
        report = analyze_bytes(jpeg_with(full_exif()), "photo.jpg")
        values = {item.key: item.value for item in report.fields}
        assert values["Make"] == "Canon"
        assert values["Model"] == "EOS R5"

    def test_timestamps_are_normalised(self) -> None:
        report = analyze_bytes(jpeg_with(full_exif()), "photo.jpg")
        values = {item.key: item.value for item in report.fields}
        assert values["DateTimeOriginal"] == "2026-03-04T11:22:30"
        assert values["DateTime"] == "2026-03-04T11:22:33"

    def test_serial_numbers_are_critical(self) -> None:
        report = analyze_bytes(jpeg_with(full_exif()), "photo.jpg")
        keys = {item.key: item for item in report.exposures}
        assert keys["BodySerialNumber"].severity is Severity.CRITICAL
        assert keys["LensSerialNumber"].severity is Severity.CRITICAL

    def test_owner_name_is_critical(self) -> None:
        report = analyze_bytes(jpeg_with(full_exif()), "photo.jpg")
        assert any(
            item.key == "CameraOwnerName" and item.severity is Severity.CRITICAL
            for item in report.exposures
        )

    def test_host_computer_is_reported(self) -> None:
        report = analyze_bytes(jpeg_with(full_exif()), "photo.jpg")
        assert any(item.key == "HostComputer" for item in report.exposures)

    def test_maker_note_is_reported_but_never_dumped(self) -> None:
        report = analyze_bytes(jpeg_with(full_exif()), "photo.jpg")
        note = next(item for item in report.fields if item.key == "MakerNote")
        assert note.binary is True
        assert "MAKERNOTE" not in note.value
        assert any(item.key == "MakerNote" for item in report.exposures)

    def test_gps_decodes_to_decimal_degrees(self) -> None:
        report = analyze_bytes(jpeg_with(full_exif()), "photo.jpg")
        assert report.coordinates is not None
        lat, lon = report.coordinates
        assert lat == pytest.approx(28.614, abs=0.001)
        assert lon == pytest.approx(77.209, abs=0.001)

    def test_gps_exposure_is_critical_and_links_a_map(self) -> None:
        report = analyze_bytes(jpeg_with(full_exif()), "photo.jpg")
        gps = next(item for item in report.exposures if item.key == "GPSLatitude")
        assert gps.severity is Severity.CRITICAL
        assert "openstreetmap.org" in gps.reveals
        assert "28.61" in gps.value

    def test_southern_and_western_hemispheres_are_negative(self) -> None:
        tiff = build_tiff(
            [_ascii_tag(0x010F, "Apple")],
            gps=[
                _ascii_tag(0x0001, "S"),
                _rational_tag(0x0002, [(33, 1), (52, 1), (0, 1)]),
                _ascii_tag(0x0003, "W"),
                _rational_tag(0x0004, [(151, 1), (12, 1), (0, 1)]),
            ],
        )
        report = analyze_bytes(jpeg_with(tiff))
        assert report.coordinates is not None
        assert report.coordinates[0] < 0
        assert report.coordinates[1] < 0

    def test_gps_altitude_and_time(self) -> None:
        report = analyze_bytes(jpeg_with(full_exif()))
        keys = {item.key for item in report.exposures}
        assert "GPSAltitude" in keys
        assert "GPSTimeStamp" in keys

    def test_thumbnail_in_ifd1_is_reported(self) -> None:
        tiff = build_tiff(
            [_ascii_tag(0x010F, "Canon")],
            next_ifd=[_short_tag(0x0100, [160]), _short_tag(0x0101, [120])],
        )
        report = analyze_bytes(jpeg_with(tiff))
        assert any(item.key == "Thumbnail" for item in report.exposures)
        assert any(item.group == "IFD1" for item in report.fields)

    def test_unknown_tags_are_reported_not_dropped(self) -> None:
        tiff = build_tiff([_short_tag(0x1234, [7])])
        report = analyze_bytes(jpeg_with(tiff))
        assert any(item.key == "Tag 0x1234" for item in report.fields)

    def test_a_cyclic_ifd_terminates(self) -> None:
        """A hostile file can point an IFD at itself; the walker must stop."""
        blob = b"II" + struct.pack("<HI", 42, 8)
        blob += struct.pack("<H", 1)
        blob += struct.pack("<HHI", 0x8769, 4, 1) + struct.pack("<I", 8)
        blob += struct.pack("<I", 8)
        report = analyze_bytes(jpeg_with(blob))
        assert report.format is MediaFormat.JPEG
        assert report.score >= 0  # finished at all

    def test_truncated_exif_yields_a_note_not_an_exception(self) -> None:
        report = analyze_bytes(jpeg_with(full_exif()[:60]))
        assert report.format is MediaFormat.JPEG
        assert isinstance(report.notes, list)

    def test_jpeg_comment_is_read(self) -> None:
        report = analyze_bytes(jpeg_with(comment=b"shot at home"))
        assert any(item.key == "COM" and "home" in item.value for item in report.fields)
        assert any(item.key == "COM" for item in report.exposures)

    def test_dimensions_come_from_sof(self) -> None:
        report = analyze_bytes(jpeg_with())
        assert (report.width, report.height) == (3, 2)

    def test_xmp_is_summarised_not_dumped(self) -> None:
        xmp = (
            b'<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF>'
            b'<rdf:Description xmp:CreatorTool="Lightroom" '
            b'photoshop:Credit="Alice"/></rdf:RDF></x:xmpmeta>'
        )
        payload = b"http://ns.adobe.com/xap/1.0/\x00" + xmp
        jpeg = jpeg_with()
        jpeg = (
            jpeg[:2]
            + b"\xff\xe1"
            + struct.pack(">H", len(payload) + 2)
            + payload
            + jpeg[2:]
        )
        report = analyze_bytes(jpeg)
        xmp_field = next(item for item in report.fields if item.key == "XMP")
        assert "CreatorTool=Lightroom" in xmp_field.value
        assert "Credit=Alice" in xmp_field.value
        assert any(item.key == "XMP" for item in report.exposures)


# ---------------------------------------------------------------------------
# PNG / WebP / GIF / BMP / TIFF / SVG / HEIF
# ---------------------------------------------------------------------------
class TestPng:
    """PNG metadata lives in text chunks, and editors love them."""

    def test_dimensions(self) -> None:
        report = analyze_bytes(png_with(width=40, height=30))
        assert (report.width, report.height) == (40, 30)

    def test_text_chunk(self) -> None:
        report = analyze_bytes(png_with((b"tEXt", b"Software\x00GIMP 2.10")))
        assert any(item.value == "GIMP 2.10" for item in report.fields)
        assert any(item.key == "Software" for item in report.exposures)

    def test_author_is_high(self) -> None:
        report = analyze_bytes(png_with((b"tEXt", b"Author\x00Alice")))
        assert any(item.key == "Author" and item.severity is Severity.HIGH for item in report.exposures)

    def test_ztxt_is_decompressed(self) -> None:
        payload = b"Comment\x00\x00" + zlib.compress(b"hidden remark")
        report = analyze_bytes(png_with((b"zTXt", payload)))
        assert any("hidden remark" in item.value for item in report.fields)

    def test_itxt_is_read(self) -> None:
        payload = b"Title\x00\x00\x00en\x00\x00a translated title"
        report = analyze_bytes(png_with((b"iTXt", payload)))
        assert any("translated title" in item.value for item in report.fields)

    def test_exif_chunk_is_parsed(self) -> None:
        report = analyze_bytes(png_with((b"eXIf", full_exif())))
        assert any(item.key == "BodySerialNumber" for item in report.fields)
        assert report.coordinates is not None

    def test_time_chunk(self) -> None:
        payload = struct.pack(">HBBBBB", 2026, 3, 4, 5, 6, 7)
        report = analyze_bytes(png_with((b"tIME", payload)))
        assert any(item.value == "2026-03-04T05:06:07" for item in report.fields)
        assert any(item.key == "tIME" for item in report.exposures)

    def test_iccp_is_low_not_high(self) -> None:
        report = analyze_bytes(png_with((b"iCCP", b"sRGB\x00\x00profile")))
        exposure = next(item for item in report.exposures if item.key == "iCCP")
        assert exposure.severity is Severity.LOW

    def test_absurd_chunk_length_does_not_crash(self) -> None:
        blob = b"\x89PNG\r\n\x1a\n" + struct.pack(">I", 2**31) + b"tEXt" + b"\x00" * 8
        report = analyze_bytes(blob)
        assert report.format is MediaFormat.PNG
        assert report.notes


class TestWebp:
    """WebP keeps EXIF in its own chunk, separate from VP8X flags."""

    def test_canvas_dimensions(self) -> None:
        report = analyze_bytes(webp_with(width=120, height=90))
        assert (report.width, report.height) == (120, 90)

    def test_exif_chunk(self) -> None:
        report = analyze_bytes(webp_with(exif=full_exif()))
        assert report.coordinates is not None
        assert any(item.key == "BodySerialNumber" for item in report.fields)

    def test_xmp_chunk(self) -> None:
        report = analyze_bytes(webp_with(xmp=b'xmp:CreatorTool="GIMP"'))
        assert any(item.key == "XMP" for item in report.exposures)


class TestOtherImages:
    """The formats people forget carry metadata."""

    def test_gif_dimensions_and_comment(self) -> None:
        blob = b"GIF89a" + struct.pack("<HH", 12, 7) + b"\x00\x00\x00" + b"\x21\xfe\x05hello\x00;"
        report = analyze_bytes(blob)
        assert (report.width, report.height) == (12, 7)
        assert any(item.key == "COM" for item in report.fields)

    def test_bmp_dimensions(self) -> None:
        header = b"BM" + b"\x00" * 12 + struct.pack("<I", 40) + struct.pack("<ii", 64, 32)
        report = analyze_bytes(header + b"\x00" * 8)
        assert (report.width, report.height) == (64, 32)

    def test_tiff_container(self) -> None:
        report = analyze_bytes(full_exif())
        assert report.format is MediaFormat.TIFF
        assert report.coordinates is not None

    def test_svg_title_and_description(self) -> None:
        svg = b'<svg xmlns="http://www.w3.org/2000/svg"><title>Home</title><desc>Alice</desc></svg>'
        report = analyze_bytes(svg, "map.svg")
        values = {item.value for item in report.fields}
        assert "Home" in values
        assert "Alice" in values

    def test_svg_embedded_raster_is_flagged(self) -> None:
        svg = b'<svg xmlns="http://www.w3.org/2000/svg"><image xlink:href="data:image/jpeg;base64,AAAA"/></svg>'
        report = analyze_bytes(svg, "x.svg")
        assert any("embeds a full image" in item.value for item in report.fields)

    def test_svg_editor_namespace(self) -> None:
        svg = (
            b'<svg xmlns="http://www.w3.org/2000/svg" '
            b'inkscape:version="1.3" sodipodi:docname="alice-map.svg"/>'
        )
        report = analyze_bytes(svg, "x.svg")
        assert any(item.value == "alice-map.svg" for item in report.fields)

    def test_heic_reports_exif_item_presence(self) -> None:
        blob = _box(b"ftyp", b"heic\x00\x00\x00\x00mif1") + _box(b"meta", b"Exif" + b"\x00" * 16)
        report = analyze_bytes(blob, "photo.heic")
        assert report.format is MediaFormat.HEIC
        assert any(item.key == "eXIf" for item in report.fields)


# ---------------------------------------------------------------------------
# Audio / video
# ---------------------------------------------------------------------------
class TestId3:
    """ID3 tags are small, structured and surprisingly personal."""

    def test_v23_text_frames(self) -> None:
        blob = id3_with(
            [
                (b"TIT2", text_frame("Holiday")),
                (b"TPE1", text_frame("Alice Example")),
                (b"TSSE", text_frame("LAME 3.100")),
                (b"TALB", text_frame("Home")),
            ],
            version=3,
        )
        report = analyze_bytes(blob + b"\xff\xfb" + b"\x00" * 32)
        values = {item.key: item.value for item in report.fields}
        assert values["TPE1"] == "Alice Example"
        assert values["TSSE"] == "LAME 3.100"

    def test_v24_syncsafe_frame_sizes(self) -> None:
        blob = id3_with([(b"TIT2", text_frame("Sync"))], version=4)
        report = analyze_bytes(blob)
        assert any(item.value == "Sync" for item in report.fields)

    def test_utf16_text(self) -> None:
        blob = id3_with([(b"TPE1", text_frame("Ünïcode", encoding=1))])
        report = analyze_bytes(blob)
        assert any("Ünïcode" in item.value for item in report.fields)

    def test_utf8_text(self) -> None:
        blob = id3_with([(b"TPE1", text_frame("日本語", encoding=3))], version=4)
        report = analyze_bytes(blob)
        assert any("日本語" in item.value for item in report.fields)

    def test_unsynchronisation_is_reversed(self) -> None:
        blob = id3_with([(b"COMM", b"\x00eng\x00a\xffcomment")], unsync=True)
        report = analyze_bytes(blob)
        assert any(item.key == "COMM" for item in report.fields)

    def test_apic_presence_is_binary(self) -> None:
        payload = b"\x00image/jpeg\x00\x03cover\x00" + b"\xff\xd8" + b"\x00" * 20
        report = analyze_bytes(id3_with([(b"APIC", payload)]))
        art = next(item for item in report.fields if item.key == "APIC")
        assert art.binary is True
        assert "image/jpeg" in art.value

    def test_id3v1_is_noted(self) -> None:
        report = analyze_bytes(b"\xff\xfb" + b"\x00" * 100 + b"TAG" + b"\x00" * 125)
        assert any("ID3v1" in note for note in report.notes)

    def test_garbage_after_header_does_not_crash(self) -> None:
        report = analyze_bytes(b"ID3\x03\x00\x00\x00\x00\x00\x0a" + b"\xff" * 10)
        assert report.format is MediaFormat.MP3


class TestFlac:
    """FLAC Vorbis comments are plain key=value, and vendors leak editors."""

    def test_streaminfo_and_comments(self) -> None:
        blob = flac_with({"ARTIST": "Alice", "TITLE": "Track", "ENCODER": "ffmpeg"})
        report = analyze_bytes(blob)
        values = {item.key: item.value for item in report.fields}
        assert values["ARTIST"] == "Alice"
        assert values["ENCODER"] == "ffmpeg"

    def test_picture_block(self) -> None:
        report = analyze_bytes(flac_with({"TITLE": "x"}, picture=True))
        assert any(item.key == "PICTURE" for item in report.fields)

    def test_no_user_comments_still_reports_the_encoder(self) -> None:
        """An empty comment block is not a clean file: the vendor string remains."""
        report = analyze_bytes(flac_with({}))
        assert report.format is MediaFormat.FLAC
        assert any(item.key == "ENCODER" for item in report.exposures)


class TestWav:
    """RIFF INFO tags are simple but often carry the author name."""

    def test_info_tags(self) -> None:
        report = analyze_bytes(wav_with({"INAM": "Memo", "ISFT": "Audacity 3.4"}))
        values = {item.key: item.value for item in report.fields}
        assert values["INAM"] == "Memo"
        assert values["ISFT"] == "Audacity 3.4"

    def test_stream_info(self) -> None:
        report = analyze_bytes(wav_with({}))
        assert any(item.key == "fmt" for item in report.fields)


class TestMp4:
    """MP4/QuickTime metadata is easy to overlook and often has GPS."""

    def test_creation_time(self) -> None:
        # 2026-01-01T00:00:00Z minus the 1904 epoch.
        epoch = datetime.datetime(1904, 1, 1, tzinfo=datetime.timezone.utc)
        stamp = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
        seconds = int((stamp - epoch).total_seconds())
        report = analyze_bytes(mp4_with(created=seconds))
        assert any("2026-01-01" in item.value for item in report.fields)

    def test_udta_gps_is_critical(self) -> None:
        udta = _box(b"udta", _box(b"\xa9xyz", b"+28.6139+077.2090/"))
        report = analyze_bytes(mp4_with(udta=udta))
        gps = next(item for item in report.exposures if item.key == "©xyz")
        assert gps.severity is Severity.CRITICAL
        assert "28.6139" in gps.value

    def test_meta_ilst_text(self) -> None:
        entry = _box(b"\xa9nam", _box(b"data", b"\x00\x00\x00\x01\x00\x00\x00\x00Holiday"))
        report = analyze_bytes(mp4_with(ilst=entry))
        assert any("Holiday" in item.value for item in report.fields)

    def test_encoder_tag(self) -> None:
        udta = _box(b"udta", _box(b"\xa9too", b"iPhone 15"))
        report = analyze_bytes(mp4_with(udta=udta))
        assert any(item.key == "©too" for item in report.exposures)


# ---------------------------------------------------------------------------
# Reports, scoring and safety
# ---------------------------------------------------------------------------
class TestReport:
    """The report must be honest about what it did and did not see."""

    def test_clean_file_scores_zero(self) -> None:
        report = analyze_bytes(png_with())
        assert report.score == 0
        assert report.verdict == "nothing identifying found"
        assert report.worst is None

    def test_score_never_exceeds_one_hundred(self) -> None:
        report = analyze_bytes(jpeg_with(full_exif()))
        assert 0 < report.score <= 100

    def test_exposures_are_ordered_by_severity(self) -> None:
        report = analyze_bytes(jpeg_with(full_exif()))
        ranks = [item.severity.rank for item in report.exposures]
        assert ranks == sorted(ranks, reverse=True)

    def test_repeated_keys_are_merged(self) -> None:
        blob = png_with((b"tEXt", b"Comment\x00one"), (b"tEXt", b"Comment\x00two"))
        report = analyze_bytes(blob)
        comments = [item for item in report.exposures if item.key == "Comment"]
        assert len(comments) == 1
        assert "one" in comments[0].value and "two" in comments[0].value

    def test_unknown_format_is_not_called_clean(self) -> None:
        report = analyze_bytes(b"\x00\x01\x02\x03nothing", "blob.bin")
        assert report.format is MediaFormat.UNKNOWN
        assert report.score == 0
        assert any("not a statement that the file is clean" in note for note in report.notes)

    def test_empty_input(self) -> None:
        report = analyze_bytes(b"")
        assert report.format is MediaFormat.UNKNOWN
        assert report.size_bytes == 0

    def test_by_group(self) -> None:
        report = analyze_bytes(jpeg_with(full_exif()))
        groups = report.by_group
        assert "IFD0" in groups and "ExifIFD" in groups and "GPS" in groups

    def test_to_dict_and_json(self) -> None:
        report = analyze_bytes(jpeg_with(full_exif()), "photo.jpg")
        data = report.to_dict()
        assert data["format"] == "jpeg"
        assert data["coordinates"] is not None
        parsed = json.loads(report.to_json())
        assert parsed["score"] == report.score
        assert parsed["exposures"]

    def test_binary_flag_is_optional_in_dict(self) -> None:
        field = MetadataField(key="X", group="g", label="L", value="v")
        assert "binary" not in field.to_dict()
        assert MetadataField(key="X", group="g", label="L", value="v", binary=True).to_dict()["binary"] is True

    def test_exposure_dict(self) -> None:
        exposure = Exposure(
            key="k", label="L", value="v", severity=Severity.HIGH, reveals="r", action="a"
        )
        assert exposure.to_dict()["severity"] == "high"

    def test_markdown_has_the_sections(self) -> None:
        text = render_markdown(analyze_bytes(jpeg_with(full_exif()), "photo.jpg"))
        assert "# Media metadata: photo.jpg" in text
        assert "## What a stranger learns" in text
        assert "### How to remove it" in text
        assert "## Every decoded field" in text
        assert "openstreetmap.org" in text

    def test_markdown_for_a_clean_file(self) -> None:
        text = render_markdown(analyze_bytes(png_with()))
        assert "Nothing identifying was found" in text

    def test_markdown_escapes_pipes(self) -> None:
        blob = png_with((b"tEXt", b"Comment\x00a|b"))
        text = render_markdown(analyze_bytes(blob))
        assert "a\\|b" in text


class TestPaths:
    """File-system behaviour: sizes, truncation, recursion, de-duplication."""

    def test_analyze_path_hash_and_name(self, tmp_path: Path) -> None:
        target = tmp_path / "photo.jpg"
        target.write_bytes(jpeg_with(full_exif()))
        report = analyze_path(target)
        assert report.name.endswith("photo.jpg")
        assert len(report.sha256) == 64
        assert report.coordinates is not None

    def test_analyze_path_truncates_large_files(self, tmp_path: Path) -> None:
        target = tmp_path / "photo.jpg"
        target.write_bytes(jpeg_with(full_exif()))
        report = analyze_path(target, max_bytes=24)
        assert report.truncated is True
        assert any("only the first" in note for note in report.notes)

    def test_analyze_path_rejects_directories(self, tmp_path: Path) -> None:
        with pytest.raises(D3ta1l3rError, match="directory"):
            analyze_path(tmp_path)

    def test_iter_media_files_recursive_and_filtered(self, tmp_path: Path) -> None:
        (tmp_path / "a.jpg").write_bytes(b"x")
        (tmp_path / "notes.txt").write_bytes(b"x")
        nested = tmp_path / "sub"
        nested.mkdir()
        (nested / "b.png").write_bytes(b"x")
        found = [p.name for p in iter_media_files([tmp_path])]
        assert found == ["a.jpg", "b.png"]

    def test_iter_media_files_non_recursive(self, tmp_path: Path) -> None:
        (tmp_path / "a.jpg").write_bytes(b"x")
        nested = tmp_path / "sub"
        nested.mkdir()
        (nested / "b.png").write_bytes(b"x")
        assert [p.name for p in iter_media_files([tmp_path], recursive=False)] == ["a.jpg"]

    def test_iter_media_files_skips_missing_paths(self, tmp_path: Path) -> None:
        assert list(iter_media_files([tmp_path / "nope.png"])) == []

    def test_iter_media_files_deduplicates(self, tmp_path: Path) -> None:
        target = tmp_path / "a.jpg"
        target.write_bytes(b"x")
        assert len(list(iter_media_files([target, target]))) == 1


# ---------------------------------------------------------------------------
# Scrubbing
# ---------------------------------------------------------------------------
class TestScrub:
    """A scrub that leaves metadata behind is worse than none, so it is verified."""

    def test_jpeg_removes_app_segments_and_comment(self) -> None:
        original = jpeg_with(full_exif(), comment=b"secret note")
        result = scrub_bytes(original)
        assert "APP1" in result.removed
        assert "COM" in result.removed
        assert sniff_format(result.data) is MediaFormat.JPEG
        assert b"secret note" not in result.data

    def test_jpeg_keeps_the_image_payload(self) -> None:
        original = jpeg_with(scan=b"\xaa\xbb\xcc")
        result = scrub_bytes(original)
        assert result.data.endswith(b"\xaa\xbb\xcc\xff\xd9")
        assert b"\xff\xc0" in result.data  # SOF preserved

    def test_jpeg_residual_is_zero(self) -> None:
        result = scrub_bytes(jpeg_with(full_exif()))
        assert result.residual_score == 0
        assert result.residual_exposures == 0

    def test_png_removes_text_and_exif(self) -> None:
        blob = png_with(
            (b"tEXt", b"Author\x00Alice"),
            (b"eXIf", full_exif()),
            (b"tIME", struct.pack(">HBBBBB", 2026, 1, 2, 3, 4, 5)),
        )
        result = scrub_bytes(blob)
        assert set(result.removed) >= {"tEXt", "eXIf", "tIME"}
        assert report_has_no(analyze_bytes(result.data), "tEXt")
        assert result.residual_score == 0

    def test_png_keeps_idat_bytes(self) -> None:
        blob = png_with((b"tEXt", b"Comment\x00x"))
        result = scrub_bytes(blob)
        assert b"IDAT" in result.data
        assert analyze_bytes(result.data).width == 4

    def test_webp_removes_exif_and_clears_flags(self) -> None:
        blob = webp_with(exif=full_exif(), xmp=b"<xmp/>")
        result = scrub_bytes(blob)
        assert "EXIF" in result.removed
        assert b"EXIF" not in result.data
        header = result.data[12:]
        assert header[:4] == b"VP8X"
        assert header[8] & 0x08 == 0
        assert analyze_bytes(result.data).coordinates is None

    def test_flac_removes_comments_and_pictures(self) -> None:
        blob = flac_with({"ARTIST": "Alice"}, picture=True)
        result = scrub_bytes(blob)
        assert "VORBIS_COMMENT" in result.removed
        assert analyze_bytes(result.data).score == 0

    def test_mp3_strips_id3v2(self) -> None:
        blob = id3_with([(b"TPE1", text_frame("Alice"))]) + b"\xff\xfb" + b"\x00" * 32
        result = scrub_bytes(blob)
        assert result.data.startswith(b"\xff\xfb")
        assert b"Alice" not in result.data

    def test_mp3_strips_id3v1(self) -> None:
        blob = b"\xff\xfb" + b"\x00" * 64 + b"TAG" + b"A" * 125
        result = scrub_bytes(blob)
        assert not result.data.endswith(b"TAG" + b"A" * 125)
        assert "ID3v1 tag (128 bytes)" in result.removed

    def test_unsupported_format_explains_the_alternative(self) -> None:
        with pytest.raises(D3ta1l3rError, match="ffmpeg"):
            scrub_bytes(mp4_with())

    def test_scrub_result_dict_has_no_bytes(self) -> None:
        result = scrub_bytes(jpeg_with(full_exif()))
        payload = result.to_dict()
        assert "data" not in payload
        assert payload["bytes_saved"] >= 0

    def test_scrub_path_writes_clean_copy(self, tmp_path: Path) -> None:
        source = tmp_path / "photo.jpg"
        source.write_bytes(jpeg_with(full_exif()))
        result, dest = scrub_path(source)
        assert dest.name == "photo.clean.jpg"
        assert dest.read_bytes() == result.data
        assert source.read_bytes() != dest.read_bytes()

    def test_scrub_path_refuses_to_overwrite(self, tmp_path: Path) -> None:
        source = tmp_path / "photo.jpg"
        source.write_bytes(jpeg_with(full_exif()))
        scrub_path(source)
        with pytest.raises(D3ta1l3rError, match="already exists"):
            scrub_path(source)

    def test_scrub_path_overwrite(self, tmp_path: Path) -> None:
        source = tmp_path / "photo.jpg"
        source.write_bytes(jpeg_with(full_exif()))
        _, dest = scrub_path(source)
        again, _ = scrub_path(source, overwrite=True)
        assert dest.read_bytes() == again.data

    def test_scrub_path_explicit_destination(self, tmp_path: Path) -> None:
        source = tmp_path / "photo.jpg"
        source.write_bytes(jpeg_with(full_exif()))
        target = tmp_path / "out" / "safe.jpg"
        _, dest = scrub_path(source, target)
        assert dest == target and target.exists()


def report_has_no(report: MediaReport, key: str) -> bool:
    """True when ``key`` is absent from both fields and exposures."""
    return not any(item.key == key for item in report.fields + report.exposures)


class TestOgg:
    """Ogg keeps its text in a Vorbis comment header after the codec header."""

    def test_vendor_and_comments_are_read(self) -> None:
        blob = ogg_with(
            vendor="Xiph.Org libVorbis I 20200704",
            comments={"ARTIST": "Alice", "TITLE": "Home"},
        )
        report = analyze_bytes(blob)
        values = {item.key: item.value for item in report.fields}
        assert values["ENCODER"] == "Xiph.Org libVorbis I 20200704"
        assert values["ARTIST"] == "Alice"
        assert values["TITLE"] == "Home"

    def test_implausible_vendor_length_is_refused(self) -> None:
        blob = b"OggS" + b"\x00" * 22 + b"\x03vorbis" + struct.pack("<I", 10**7) + b"x"
        report = analyze_bytes(blob)
        assert any("implausible" in note for note in report.notes)


class TestId3EdgeCases:
    """Extended headers and the old 3-character frame layout."""

    def test_v23_extended_header_is_skipped(self) -> None:
        blob = id3_with_extended_header([(b"TPE1", text_frame("Alice"))], version=3)
        report = analyze_bytes(blob)
        assert any(item.value == "Alice" for item in report.fields)

    def test_v24_extended_header_is_skipped(self) -> None:
        blob = id3_with_extended_header([(b"TPE1", text_frame("Alice"))], version=4)
        report = analyze_bytes(blob)
        assert any(item.value == "Alice" for item in report.fields)

    def test_v22_is_reported_as_undecoded(self) -> None:
        blob = b"ID3" + bytes([2, 0, 0]) + _syncsafe(6) + b"TT2" + b"\x00\x03\x00x"
        report = analyze_bytes(blob)
        assert any("v2.2" in note for note in report.notes)


def test_analyze_path_refuses_a_fifo(tmp_path: Path) -> None:
    """A FIFO would block forever; it must be rejected before the read."""
    import os

    if not hasattr(os, "mkfifo"):  # pragma: no cover - Windows
        pytest.skip("mkfifo is not available")
    fifo = tmp_path / "pipe.jpg"
    os.mkfifo(fifo)
    with pytest.raises(D3ta1l3rError, match="not a regular file"):
        analyze_path(fifo)


def test_every_severity_rule_is_documented() -> None:
    """The catalogue in docs/MEDIA.md must list every rule the code applies.

    A rule the documentation does not mention is a severity claim the user has no
    way to check, so the two are kept in step by a test rather than by memory.
    """
    from d3ta1l3r.media import _RULES

    doc = Path("docs/MEDIA.md").read_text(encoding="utf-8")
    missing = [key for key in _RULES if f"`{key}`" not in doc]
    assert not missing, "undocumented metadata rules: " + ", ".join(sorted(missing))


def test_scrub_result_is_frozen() -> None:
    """The result is a value object; mutating it would break the honesty claim."""
    result = ScrubResult(
        format=MediaFormat.JPEG,
        data=b"",
        removed=[],
        size_before=0,
        size_after=0,
        residual_score=0,
        residual_exposures=0,
    )
    with pytest.raises(dataclasses.FrozenInstanceError):
        result.data = b"x"  # type: ignore[misc]
