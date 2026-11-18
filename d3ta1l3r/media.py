"""Read the metadata out of your own photos, audio and video — and explain it.

A photo you are about to post is a *document* as much as an image.  The file
usually carries the camera make and model, sometimes the body serial number, the
exact capture time, the software that last edited it, and — if the camera had a
GPS fix — a latitude and longitude accurate to a few metres.  None of that is
visible in a thumbnail, and sites strip it inconsistently, so the only reliable
check is on the file you still have.

Where a scan asks what public endpoints know about an identifier, this module
asks what a file already says about you before you publish it.  Everything here
is standard library: no Pillow, no exiftool, no network.  A privacy check that
phones home is not a privacy check.

Design rules:

* **Tolerant, never crashy.**  A truncated, malformed or hostile file yields the
  fields that could be recovered plus a note — not a traceback.  Parsing is
  bounded: segment counts, tag counts, IFD recursion depth, decompressed text
  size and input size all have ceilings, and a TIFF IFD cannot be revisited
  (that is how a cyclic EXIF block would otherwise loop forever).
* **Absence is reported as absence.**  ``score == 0`` means "nothing
  identifying was *found*", not "this file is clean"; the report says which
  formats were understood.
* **Every field is traceable.**  Fields carry the group they came from (IFD0,
  ExifIFD, GPS, PNG ``tEXt``, ID3v2.3, ...), so a severity claim can always be
  checked against the bytes.
* **Severity is about disclosure, not intent.**  A GPS fix is critical whether
  or not it is your home: the tool cannot know the address, only that the
  coordinates are in the file and travel with it.

Public API::

    from d3ta1l3r.media import analyze_path, scrub_bytes

    report = analyze_path("holiday.jpg")
    print(report.score, report.verdict)
    clean = scrub_bytes(pathlib.Path("holiday.jpg").read_bytes())
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
import os
import re
import stat
import struct
import zlib
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from .errors import D3ta1l3rError

__all__ = [
    "DEFAULT_MAX_BYTES",
    "MAX_TEXT_BYTES",
    "Exposure",
    "MediaFormat",
    "MediaReport",
    "MetadataField",
    "ScrubResult",
    "Severity",
    "analyze_bytes",
    "analyze_path",
    "iter_media_files",
    "render_markdown",
    "scrub_bytes",
    "scrub_path",
    "supported_formats",
]

#: Refuse to read files larger than this by default.  A self-audit target is a
#: photo or a short video, not a 4 GiB master file; the ceiling keeps a mistyped
#: path from turning into an out-of-memory kill.
DEFAULT_MAX_BYTES = 128 * 1024 * 1024

#: Ceiling for any single decompressed text chunk (PNG ``zTXt``/``iTXt``, ID3
#: frames).  A 1 KiB compressed chunk can otherwise expand to gigabytes.
MAX_TEXT_BYTES = 1 * 1024 * 1024

#: Hard limits that bound the parsers.  These are deliberately generous for
#: real files and tiny for hostile ones.
_MAX_IFD_ENTRIES = 4096
_MAX_IFD_DEPTH = 6
_MAX_JPEG_SEGMENTS = 4096
_MAX_PNG_CHUNKS = 100_000
_MAX_ID3_FRAMES = 4096
_MAX_MP4_BOXES = 20_000
_MAX_FLAC_BLOCKS = 4096
_MAX_TAGS_REPORTED = 400

_EARTH_RADIUS_M = 6_371_008.8


class MediaFormat(str, Enum):
    """A container format the analyser recognises."""

    JPEG = "jpeg"
    PNG = "png"
    GIF = "gif"
    WEBP = "webp"
    TIFF = "tiff"
    BMP = "bmp"
    SVG = "svg"
    HEIC = "heic"
    AVIF = "avif"
    MP3 = "mp3"
    FLAC = "flac"
    OGG = "ogg"
    WAV = "wav"
    MP4 = "mp4"
    MOV = "mov"
    WEBM = "webm"
    MKV = "mkv"
    UNKNOWN = "unknown"

    @property
    def label(self) -> str:
        """Human-facing name used in tables and the dashboard."""
        return _FORMAT_LABELS.get(self, self.value.upper())

    @property
    def kind(self) -> str:
        """One of ``image``, ``audio``, ``video`` or ``unknown``."""
        if self in _IMAGE_FORMATS:
            return "image"
        if self in _AUDIO_FORMATS:
            return "audio"
        if self in _VIDEO_FORMATS:
            return "video"
        return "unknown"


_FORMAT_LABELS: dict[MediaFormat, str] = {
    MediaFormat.JPEG: "JPEG",
    MediaFormat.PNG: "PNG",
    MediaFormat.GIF: "GIF",
    MediaFormat.WEBP: "WebP",
    MediaFormat.TIFF: "TIFF",
    MediaFormat.BMP: "BMP",
    MediaFormat.SVG: "SVG",
    MediaFormat.HEIC: "HEIC/HEIF",
    MediaFormat.AVIF: "AVIF",
    MediaFormat.MP3: "MP3",
    MediaFormat.FLAC: "FLAC",
    MediaFormat.OGG: "Ogg",
    MediaFormat.WAV: "WAV",
    MediaFormat.MP4: "MP4",
    MediaFormat.MOV: "QuickTime",
    MediaFormat.WEBM: "WebM",
    MediaFormat.MKV: "Matroska",
    MediaFormat.UNKNOWN: "unknown",
}

_IMAGE_FORMATS = {
    MediaFormat.JPEG,
    MediaFormat.PNG,
    MediaFormat.GIF,
    MediaFormat.WEBP,
    MediaFormat.TIFF,
    MediaFormat.BMP,
    MediaFormat.SVG,
    MediaFormat.HEIC,
    MediaFormat.AVIF,
}
_AUDIO_FORMATS = {MediaFormat.MP3, MediaFormat.FLAC, MediaFormat.OGG, MediaFormat.WAV}
_VIDEO_FORMATS = {MediaFormat.MP4, MediaFormat.MOV, MediaFormat.WEBM, MediaFormat.MKV}

_MIME: dict[MediaFormat, str] = {
    MediaFormat.JPEG: "image/jpeg",
    MediaFormat.PNG: "image/png",
    MediaFormat.GIF: "image/gif",
    MediaFormat.WEBP: "image/webp",
    MediaFormat.TIFF: "image/tiff",
    MediaFormat.BMP: "image/bmp",
    MediaFormat.SVG: "image/svg+xml",
    MediaFormat.HEIC: "image/heic",
    MediaFormat.AVIF: "image/avif",
    MediaFormat.MP3: "audio/mpeg",
    MediaFormat.FLAC: "audio/flac",
    MediaFormat.OGG: "audio/ogg",
    MediaFormat.WAV: "audio/wav",
    MediaFormat.MP4: "video/mp4",
    MediaFormat.MOV: "video/quicktime",
    MediaFormat.WEBM: "video/webm",
    MediaFormat.MKV: "video/x-matroska",
    MediaFormat.UNKNOWN: "application/octet-stream",
}

_EXTENSIONS: dict[str, MediaFormat] = {
    ".jpg": MediaFormat.JPEG,
    ".jpeg": MediaFormat.JPEG,
    ".jpe": MediaFormat.JPEG,
    ".png": MediaFormat.PNG,
    ".gif": MediaFormat.GIF,
    ".webp": MediaFormat.WEBP,
    ".tif": MediaFormat.TIFF,
    ".tiff": MediaFormat.TIFF,
    ".bmp": MediaFormat.BMP,
    ".svg": MediaFormat.SVG,
    ".heic": MediaFormat.HEIC,
    ".heif": MediaFormat.HEIC,
    ".avif": MediaFormat.AVIF,
    ".mp3": MediaFormat.MP3,
    ".flac": MediaFormat.FLAC,
    ".ogg": MediaFormat.OGG,
    ".oga": MediaFormat.OGG,
    ".opus": MediaFormat.OGG,
    ".wav": MediaFormat.WAV,
    ".mp4": MediaFormat.MP4,
    ".m4v": MediaFormat.MP4,
    ".m4a": MediaFormat.MP4,
    ".mov": MediaFormat.MOV,
    ".webm": MediaFormat.WEBM,
    ".mkv": MediaFormat.MKV,
}


class Severity(str, Enum):
    """How much a single metadata field reveals about its owner.

    ``INFO`` — technical detail with no identifying content (colour space,
    exposure settings, dimensions).

    ``LOW`` — a weak hint (resolution, orientation, an ICC profile).

    ``MEDIUM`` — narrows a person down when combined with other data: capture
    time, editor software, a lens model, an album title.

    ``HIGH`` — identifies directly or fingerprints strongly: camera body,
    artist name, image description, an embedded thumbnail that can show the
    uncropped frame.

    ``CRITICAL`` — one field is enough to locate a person or link devices:
    GPS coordinates, a camera body serial number, an owner name written by the
    camera itself.
    """

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        """Sort key, lowest is least exposing."""
        return _SEVERITY_RANK[self]

    @property
    def weight(self) -> int:
        """Contribution towards the 0–100 exposure score."""
        return _SEVERITY_WEIGHT[self]

    @property
    def colour(self) -> str:
        """ANSI-free colour name the CLI and dashboard map to a style."""
        return _SEVERITY_COLOUR[self]


_SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}
_SEVERITY_WEIGHT = {
    Severity.INFO: 0,
    Severity.LOW: 2,
    Severity.MEDIUM: 7,
    Severity.HIGH: 16,
    Severity.CRITICAL: 40,
}
_SEVERITY_COLOUR = {
    Severity.INFO: "dim",
    Severity.LOW: "blue",
    Severity.MEDIUM: "yellow",
    Severity.HIGH: "red",
    Severity.CRITICAL: "bright_red",
}


@dataclass(frozen=True, slots=True)
class MetadataField:
    """One decoded metadata value, with the group it came from.

    ``group`` is the container-level location (``IFD0``, ``ExifIFD``, ``GPS``,
    ``PNG tEXt``, ``ID3v2.4``, ``MP4 udta``, ...) so a reader can go and check
    the claim in a hex editor or with ``exiftool -v``.
    """

    key: str
    group: str
    label: str
    value: str
    binary: bool = False

    def to_dict(self) -> dict[str, Any]:
        """JSON-ready mapping; omits ``binary`` when false to keep reports small."""
        data: dict[str, Any] = {
            "key": self.key,
            "group": self.group,
            "label": self.label,
            "value": self.value,
        }
        if self.binary:
            data["binary"] = True
        return data


@dataclass(frozen=True, slots=True)
class Exposure:
    """A field that discloses something about its owner, and what to do about it.

    ``reveals`` is written for a person, not a parser: it says what a stranger
    holding the file learns.  ``action`` says what actually removes it.
    """

    key: str
    label: str
    value: str
    severity: Severity
    reveals: str
    action: str

    def to_dict(self) -> dict[str, Any]:
        """JSON-ready mapping."""
        return {
            "key": self.key,
            "label": self.label,
            "value": self.value,
            "severity": self.severity.value,
            "reveals": self.reveals,
            "action": self.action,
        }


@dataclass(frozen=True, slots=True)
class _Rule:
    """Static explanation attached to a known metadata key."""

    severity: Severity
    reveals: str
    action: str


@dataclass
class MediaReport:
    """Everything the analyser could read from one file.

    The report is intentionally lossless about *what was found*: ``fields``
    holds every decoded tag (technical ones included), while ``exposures`` holds
    only the subset with a privacy consequence, ordered most severe first.
    """

    name: str
    size_bytes: int
    sha256: str
    format: MediaFormat
    mime: str
    width: int | None = None
    height: int | None = None
    fields: list[MetadataField] = field(default_factory=list)
    exposures: list[Exposure] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    coordinates: tuple[float, float] | None = None
    score: int = 0
    verdict: str = ""
    truncated: bool = False

    @property
    def kind(self) -> str:
        """``image``, ``audio``, ``video`` or ``unknown``."""
        return self.format.kind

    @property
    def worst(self) -> Severity | None:
        """The highest severity present, or ``None`` when nothing was found."""
        if not self.exposures:
            return None
        return max((item.severity for item in self.exposures), key=lambda s: s.rank)

    @property
    def by_group(self) -> dict[str, list[MetadataField]]:
        """Fields grouped by their container location, insertion-ordered."""
        grouped: dict[str, list[MetadataField]] = {}
        for item in self.fields:
            grouped.setdefault(item.group, []).append(item)
        return grouped

    def to_dict(self) -> dict[str, Any]:
        """JSON-ready mapping.  Stable key order so diffs are readable."""
        return {
            "name": self.name,
            "size_bytes": self.size_bytes,
            "sha256": self.sha256,
            "format": self.format.value,
            "format_label": self.format.label,
            "kind": self.kind,
            "mime": self.mime,
            "width": self.width,
            "height": self.height,
            "score": self.score,
            "verdict": self.verdict,
            "worst": self.worst.value if self.worst else None,
            "coordinates": list(self.coordinates) if self.coordinates else None,
            "exposures": [item.to_dict() for item in self.exposures],
            "fields": [item.to_dict() for item in self.fields],
            "notes": list(self.notes),
            "truncated": self.truncated,
        }

    def to_json(self, *, indent: int | None = 2) -> str:
        """Serialise the report to JSON."""
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)


def supported_formats() -> dict[str, list[str]]:
    """Return every recognised format and the extensions that select it.

    The mapping is keyed by ``MediaFormat.value`` and lists extensions with the
    leading dot, sorted, so the CLI can print a stable table.
    """
    out: dict[str, list[str]] = {}
    for ext, fmt in sorted(_EXTENSIONS.items()):
        out.setdefault(fmt.value, []).append(ext)
    for fmt in MediaFormat:
        out.setdefault(fmt.value, [])
    return {key: sorted(value) for key, value in sorted(out.items())}


# ---------------------------------------------------------------------------
# Rule table — what each known field means
# ---------------------------------------------------------------------------
_RULES: dict[str, _Rule] = {
    # --- IFD0: who made the file -------------------------------------------
    "Make": _Rule(
        Severity.MEDIUM,
        "the manufacturer that built the camera, which starts a device fingerprint",
        "strip EXIF before publishing, or export a copy without metadata",
    ),
    "Model": _Rule(
        Severity.HIGH,
        "the exact device model — combined with anyone else's photo of you, it "
        "lets two files be attributed to the same camera",
        "strip EXIF; most editors have a 'remove location/EXIF' export option",
    ),
    "Software": _Rule(
        Severity.MEDIUM,
        "the last program that wrote the file, including its version — an editor "
        "or a phone OS, which dates the file and hints at your workflow",
        "strip EXIF; re-encoding through an editor that drops tags is enough",
    ),
    "DateTime": _Rule(
        Severity.MEDIUM,
        "when the file was last written, to the second",
        "strip EXIF; note that some sites keep the file's own mtime regardless",
    ),
    "Artist": _Rule(
        Severity.HIGH,
        "a name written into the file itself, often the photographer's real name",
        "remove the Artist/Copyright tags in your editor before exporting",
    ),
    "Copyright": _Rule(
        Severity.MEDIUM,
        "a copyright string, which frequently contains a full legal name or email",
        "remove or genericise the Copyright tag",
    ),
    "ImageDescription": _Rule(
        Severity.MEDIUM,
        "free text someone typed about the image — captions often name people or places",
        "clear the description field",
    ),
    "HostComputer": _Rule(
        Severity.HIGH,
        "the name of the computer that processed the image, which usually matches "
        "a username or a device name",
        "strip EXIF; this tag is written by desktop editors",
    ),
    "XPTitle": _Rule(Severity.HIGH, "a Windows title string that often contains a name",
                     "clear Windows property fields before sharing"),
    "XPComment": _Rule(Severity.HIGH, "a Windows comment string typed by the owner",
                       "clear Windows property fields before sharing"),
    "XPAuthor": _Rule(Severity.CRITICAL, "the Windows account name of the person who saved the file",
                      "clear Windows property fields; this is often a login name"),
    "XPKeywords": _Rule(Severity.MEDIUM, "Windows keywords, which often tag people or places",
                        "clear Windows property fields"),
    "XPSubject": _Rule(Severity.MEDIUM, "a Windows subject line for the file",
                       "clear Windows property fields"),
    "Orientation": _Rule(Severity.INFO, "how the camera was rotated", "nothing — harmless"),
    # --- ExifIFD: when, with what, and by whom -------------------------------
    "DateTimeOriginal": _Rule(
        Severity.HIGH,
        "the exact moment the shutter fired — enough to place you at a time and, "
        "with other photos, to reconstruct a routine",
        "strip EXIF; this is the tag most useful for correlating a set of photos",
    ),
    "DateTimeDigitized": _Rule(
        Severity.HIGH,
        "when the image was digitised, usually the same second as capture",
        "strip EXIF",
    ),
    "OffsetTime": _Rule(Severity.MEDIUM, "the timezone offset of the file's timestamp",
                        "strip EXIF"),
    "OffsetTimeOriginal": _Rule(
        Severity.MEDIUM,
        "the timezone at capture — it narrows a location even without GPS",
        "strip EXIF",
    ),
    "OffsetTimeDigitized": _Rule(Severity.MEDIUM, "the timezone at digitisation", "strip EXIF"),
    "CameraOwnerName": _Rule(
        Severity.CRITICAL,
        "the owner name configured inside the camera — often a full legal name, "
        "and it travels with every photo that camera takes",
        "clear the owner name in the camera menu, then strip EXIF on export",
    ),
    "BodySerialNumber": _Rule(
        Severity.CRITICAL,
        "the camera body's serial number — a permanent identifier that links every "
        "photo ever taken with that body, across sites and accounts",
        "strip EXIF; the serial is also in the MakerNote, so strip that too",
    ),
    "LensSerialNumber": _Rule(
        Severity.CRITICAL,
        "the lens serial number, which links photos taken with the same lens",
        "strip EXIF",
    ),
    "ImageUniqueID": _Rule(
        Severity.HIGH,
        "a per-image unique identifier that can tie copies of the same shot together",
        "strip EXIF",
    ),
    "UserComment": _Rule(
        Severity.HIGH,
        "free text stored by the camera or editor — often a name, a project, or a note",
        "clear the comment field",
    ),
    "MakerNote": _Rule(
        Severity.HIGH,
        "an opaque manufacturer block that commonly repeats the serial number, "
        "shutter count and lens data even when the visible tags were removed",
        "strip EXIF entirely; deleting individual tags leaves the MakerNote behind",
    ),
    "LensModel": _Rule(Severity.MEDIUM, "the lens used, narrowing the camera and the owner",
                       "strip EXIF"),
    "LensMake": _Rule(Severity.LOW, "the lens manufacturer", "strip EXIF"),
    "LensSpecification": _Rule(Severity.LOW, "the lens focal range and aperture", "strip EXIF"),
    "FocalLength": _Rule(Severity.LOW, "the focal length used", "usually harmless"),
    "FocalLengthIn35mmFilm": _Rule(Severity.LOW, "the full-frame equivalent focal length",
                                   "usually harmless"),
    "ExposureTime": _Rule(Severity.INFO, "the shutter speed", "nothing — harmless"),
    "FNumber": _Rule(Severity.INFO, "the aperture", "nothing — harmless"),
    "ISOSpeedRatings": _Rule(Severity.INFO, "the ISO speed", "nothing — harmless"),
    "Flash": _Rule(Severity.INFO, "whether the flash fired", "nothing — harmless"),
    "MeteringMode": _Rule(Severity.INFO, "how the camera metered the scene",
                          "nothing — harmless"),
    "ExposureProgram": _Rule(Severity.INFO, "the exposure mode", "nothing — harmless"),
    "WhiteBalance": _Rule(Severity.INFO, "the white-balance setting", "nothing — harmless"),
    "ColorSpace": _Rule(Severity.INFO, "the colour space", "nothing — harmless"),
    "PixelXDimension": _Rule(Severity.INFO, "the image width in pixels", "nothing — harmless"),
    "PixelYDimension": _Rule(Severity.INFO, "the image height in pixels", "nothing — harmless"),
    "SubSecTimeOriginal": _Rule(Severity.LOW, "sub-second capture time", "strip EXIF"),
    "BrightnessValue": _Rule(Severity.INFO, "scene brightness", "nothing — harmless"),
    "ExposureBiasValue": _Rule(Severity.INFO, "exposure compensation", "nothing — harmless"),
    "MaxApertureValue": _Rule(Severity.INFO, "the lens's maximum aperture",
                              "nothing — harmless"),
    "SceneCaptureType": _Rule(Severity.INFO, "the scene mode", "nothing — harmless"),
    "DigitalZoomRatio": _Rule(Severity.LOW, "whether digital zoom was used", "strip EXIF"),
    "SubjectDistance": _Rule(Severity.INFO, "the focus distance", "nothing — harmless"),
    "SubjectArea": _Rule(Severity.INFO, "the focus point", "nothing — harmless"),
    "SensingMethod": _Rule(Severity.INFO, "the sensor type", "nothing — harmless"),
    "SceneType": _Rule(Severity.INFO, "the scene type", "nothing — harmless"),
    "CustomRendered": _Rule(Severity.INFO, "whether custom processing was applied",
                            "nothing — harmless"),
    "ExposureMode": _Rule(Severity.INFO, "the exposure mode", "nothing — harmless"),
    "GPSLatitude": _Rule(Severity.CRITICAL, "latitude", "strip GPS from the file"),
    "GPSLongitude": _Rule(Severity.CRITICAL, "longitude", "strip GPS from the file"),
    "GPSAltitude": _Rule(Severity.HIGH, "altitude above sea level", "strip GPS from the file"),
    "GPSTimeStamp": _Rule(Severity.HIGH, "the UTC time of the GPS fix", "strip GPS"),
    "GPSDateStamp": _Rule(Severity.HIGH, "the UTC date of the GPS fix", "strip GPS"),
    "GPSProcessingMethod": _Rule(Severity.MEDIUM, "how the position was obtained (GPS, Wi-Fi, cell)",
                                 "strip GPS"),
    "GPSImgDirection": _Rule(Severity.MEDIUM, "which way the camera was pointing", "strip GPS"),
    "GPSSpeed": _Rule(Severity.MEDIUM, "how fast you were moving", "strip GPS"),
    "GPSMapDatum": _Rule(Severity.LOW, "the geodetic datum of the fix", "strip GPS"),
    # --- thumbnails and embedded payloads -----------------------------------
    "Thumbnail": _Rule(
        Severity.MEDIUM,
        "an embedded preview that is often the *uncropped* original — cropping a "
        "photo in an editor does not always update it",
        "re-export the image rather than editing it in place; strip EXIF",
    ),
    # --- PNG / WebP / XMP ---------------------------------------------------
    "tEXt": _Rule(Severity.MEDIUM, "a free-text key/value pair (PNG has no schema)",
                  "strip PNG text chunks"),
    "Author": _Rule(Severity.HIGH, "a named author stored in a PNG text chunk",
                    "strip PNG text chunks"),
    "Comment": _Rule(Severity.MEDIUM, "a free-text comment stored in the file",
                     "strip the comment field"),
    "COM": _Rule(Severity.MEDIUM, "a free-text comment segment straight after the header",
                 "strip the JPEG comment segment"),
    "zTXt": _Rule(Severity.MEDIUM, "a compressed text chunk, same content as tEXt",
                  "strip PNG text chunks"),
    "iTXt": _Rule(Severity.MEDIUM, "an internationalised text chunk, often XMP or a comment",
                  "strip PNG text chunks"),
    "eXIf": _Rule(Severity.HIGH, "a full EXIF block embedded in a PNG",
                  "strip PNG metadata"),
    "XMP": _Rule(
        Severity.HIGH,
        "an XMP packet — usually a full editing history, creator tool and often the "
        "original camera data even after EXIF was removed",
        "strip XMP as well as EXIF; they are separate blocks",
    ),
    "iCCP": _Rule(Severity.LOW, "an embedded colour profile, which can name a device",
                  "strip the ICC profile for a smaller, cleaner file"),
    "pHYs": _Rule(Severity.LOW, "the assumed pixel density", "strip if you want a minimal PNG"),
    "tIME": _Rule(Severity.MEDIUM, "the last-modification time, to the second",
                  "strip PNG metadata"),
    "VP8X": _Rule(Severity.INFO, "the WebP extended header", "nothing — structural"),
    "ICCP": _Rule(Severity.LOW, "an embedded colour profile", "strip the ICC profile"),
    # --- MP4 / QuickTime ----------------------------------------------------
    "creation_time": _Rule(
        Severity.MEDIUM,
        "when the recording was created, in UTC — and some devices write local "
        "time, which leaks the timezone",
        "strip metadata by remuxing (`ffmpeg -map_metadata -1`)",
    ),
    "©xyz": _Rule(Severity.CRITICAL, "GPS coordinates written by the recording device",
                  "strip metadata by remuxing; this tag is easy to miss"),
    "©too": _Rule(Severity.MEDIUM, "the encoder or device that produced the file",
                  "strip metadata by remuxing"),
    "com.apple.quicktime.location.ISO6709": _Rule(
        Severity.CRITICAL, "GPS coordinates written by an Apple device",
        "strip metadata by remuxing",
    ),
    "com.apple.quicktime.make": _Rule(Severity.HIGH, "the recording device's manufacturer",
                                     "strip metadata by remuxing"),
    "com.apple.quicktime.model": _Rule(Severity.HIGH, "the recording device model",
                                       "strip metadata by remuxing"),
    "com.apple.quicktime.software": _Rule(Severity.MEDIUM, "the device OS version",
                                          "strip metadata by remuxing"),
    # --- ID3 / Vorbis -------------------------------------------------------
    "TIT2": _Rule(Severity.MEDIUM, "the track title", "clear the ID3 tag"),
    "TPE1": _Rule(Severity.MEDIUM, "the performing artist", "clear the ID3 tag"),
    "TPE2": _Rule(Severity.MEDIUM, "the album artist", "clear the ID3 tag"),
    "TALB": _Rule(Severity.LOW, "the album name", "clear the ID3 tag"),
    "TCOM": _Rule(Severity.LOW, "the composer", "clear the ID3 tag"),
    "TCON": _Rule(Severity.LOW, "the genre", "clear the ID3 tag"),
    "TDRC": _Rule(Severity.LOW, "the recording date", "clear the ID3 tag"),
    "TSSE": _Rule(Severity.MEDIUM, "the encoder software and version", "clear the ID3 tag"),
    "TENC": _Rule(Severity.MEDIUM, "the person or organisation that encoded the file",
                  "clear the ID3 tag"),
    "COMM": _Rule(Severity.MEDIUM, "a free-text comment", "clear the ID3 tag"),
    "TXXX": _Rule(Severity.MEDIUM, "a user-defined text field", "clear the ID3 tag"),
    "USLT": _Rule(Severity.MEDIUM, "unsynchronised lyrics", "clear the ID3 tag"),
    "WXXX": _Rule(Severity.MEDIUM, "a user-defined URL", "clear the ID3 tag"),
    "PRIV": _Rule(Severity.MEDIUM, "an application-private data blob (player state, IDs)",
                  "clear the ID3 tag"),
    "UFID": _Rule(Severity.HIGH, "a unique file identifier that can link the file to a library",
                  "clear the ID3 tag"),
    "APIC": _Rule(
        Severity.MEDIUM,
        "embedded artwork — the image may carry its own EXIF/GPS",
        "clear the ID3 tag; check the artwork separately if it matters",
    ),
    "GEOB": _Rule(Severity.MEDIUM, "an embedded binary object", "clear the ID3 tag"),
    "ARTIST": _Rule(Severity.MEDIUM, "the artist (Vorbis comment)", "strip Vorbis comments"),
    "ENCODER": _Rule(Severity.MEDIUM, "the encoder software (Vorbis comment)",
                     "strip Vorbis comments"),
    "DESCRIPTION": _Rule(Severity.MEDIUM, "a free-text description", "strip Vorbis comments"),
    "TITLE": _Rule(Severity.LOW, "the title", "strip Vorbis comments"),
    "ALBUM": _Rule(Severity.LOW, "the album", "strip Vorbis comments"),
    "DATE": _Rule(Severity.LOW, "a date", "strip Vorbis comments"),
    "PICTURE": _Rule(Severity.MEDIUM, "embedded cover art, which may carry EXIF",
                     "strip Vorbis comments and pictures"),
    "IART": _Rule(Severity.MEDIUM, "the artist (RIFF INFO)", "clear RIFF INFO tags"),
    "INAM": _Rule(Severity.LOW, "the title (RIFF INFO)", "clear RIFF INFO tags"),
    "ICMT": _Rule(Severity.MEDIUM, "a comment (RIFF INFO)", "clear RIFF INFO tags"),
    "ISFT": _Rule(Severity.MEDIUM, "the software that wrote the file (RIFF INFO)",
                  "clear RIFF INFO tags"),
    "ICRD": _Rule(Severity.LOW, "the creation date (RIFF INFO)", "clear RIFF INFO tags"),
}

#: Labels for the tag ids we decode.  Anything absent is still reported, with a
#: generated label — unknown tags are common and omitting them would hide data.
_LABELS: dict[str, str] = {
    "Make": "Camera make",
    "Model": "Camera model",
    "Software": "Software",
    "DateTime": "File modified",
    "Artist": "Artist",
    "Copyright": "Copyright",
    "ImageDescription": "Description",
    "HostComputer": "Host computer",
    "Orientation": "Orientation",
    "XPTitle": "Windows title",
    "XPComment": "Windows comment",
    "XPAuthor": "Windows author",
    "XPKeywords": "Windows keywords",
    "XPSubject": "Windows subject",
    "DateTimeOriginal": "Captured at",
    "DateTimeDigitized": "Digitised at",
    "OffsetTime": "Timezone offset",
    "OffsetTimeOriginal": "Capture timezone",
    "OffsetTimeDigitized": "Digitisation timezone",
    "CameraOwnerName": "Camera owner",
    "BodySerialNumber": "Body serial number",
    "LensSerialNumber": "Lens serial number",
    "ImageUniqueID": "Image unique id",
    "UserComment": "User comment",
    "MakerNote": "Maker note",
    "LensModel": "Lens model",
    "LensMake": "Lens make",
    "LensSpecification": "Lens specification",
    "FocalLength": "Focal length",
    "FocalLengthIn35mmFilm": "35 mm equivalent",
    "ExposureTime": "Exposure time",
    "FNumber": "Aperture",
    "ISOSpeedRatings": "ISO",
    "Flash": "Flash",
    "MeteringMode": "Metering mode",
    "ExposureProgram": "Exposure program",
    "WhiteBalance": "White balance",
    "ColorSpace": "Colour space",
    "PixelXDimension": "Width (tagged)",
    "PixelYDimension": "Height (tagged)",
    "SubSecTimeOriginal": "Sub-second capture time",
    "BrightnessValue": "Brightness",
    "ExposureBiasValue": "Exposure bias",
    "MaxApertureValue": "Max aperture",
    "SceneCaptureType": "Scene capture type",
    "DigitalZoomRatio": "Digital zoom",
    "SubjectDistance": "Subject distance",
    "SubjectArea": "Subject area",
    "SensingMethod": "Sensing method",
    "SceneType": "Scene type",
    "CustomRendered": "Custom rendered",
    "ExposureMode": "Exposure mode",
    "GPSLatitude": "GPS latitude",
    "GPSLongitude": "GPS longitude",
    "GPSAltitude": "GPS altitude",
    "GPSAltitudeRef": "GPS altitude reference",
    "GPSTimeStamp": "GPS time",
    "GPSDateStamp": "GPS date",
    "GPSProcessingMethod": "GPS processing method",
    "GPSImgDirection": "GPS image direction",
    "GPSSpeed": "GPS speed",
    "GPSMapDatum": "GPS datum",
    "GPSLatitudeRef": "GPS latitude ref",
    "GPSLongitudeRef": "GPS longitude ref",
    "Thumbnail": "Embedded thumbnail",
    "XMP": "XMP packet",
    "eXIf": "Embedded EXIF",
    "iCCP": "ICC profile",
    "pHYs": "Pixel density",
    "tIME": "Modification time",
    "Author": "Author",
    "Comment": "Comment",
    "COM": "Comment",
    "creation_time": "Creation time",
    "©xyz": "GPS position",
    "©too": "Encoder",
    "com.apple.quicktime.location.ISO6709": "Apple GPS position",
    "com.apple.quicktime.make": "Device make",
    "com.apple.quicktime.model": "Device model",
    "com.apple.quicktime.software": "Device software",
    "TIT2": "Title",
    "TPE1": "Artist",
    "TPE2": "Album artist",
    "TALB": "Album",
    "TCOM": "Composer",
    "TCON": "Genre",
    "TDRC": "Recording date",
    "TYER": "Year",
    "TSSE": "Encoder settings",
    "TENC": "Encoded by",
    "COMM": "Comment",
    "TXXX": "User-defined text",
    "USLT": "Lyrics",
    "WXXX": "User-defined URL",
    "PRIV": "Private data",
    "UFID": "Unique file id",
    "APIC": "Embedded artwork",
    "GEOB": "Embedded object",
    "ARTIST": "Artist",
    "ENCODER": "Encoder",
    "DESCRIPTION": "Description",
    "TITLE": "Title",
    "ALBUM": "Album",
    "DATE": "Date",
    "PICTURE": "Embedded picture",
    "IART": "Artist",
    "INAM": "Title",
    "ICMT": "Comment",
    "ISFT": "Software",
    "ICRD": "Creation date",
}


def _label_for(key: str) -> str:
    """Human label for a tag key, falling back to the key itself."""
    return _LABELS.get(key, key.replace("_", " ").capitalize())


def _rule_for(key: str) -> _Rule | None:
    """Explanation + severity for a tag key, or ``None`` if it is unknown."""
    return _RULES.get(key)


# ---------------------------------------------------------------------------
# Tolerant decoding helpers
# ---------------------------------------------------------------------------
def _u16(data: bytes, offset: int, order: str = ">") -> int:
    """Read an unsigned 16-bit integer, or return 0 past the end."""
    if offset < 0 or offset + 2 > len(data):
        return 0
    return struct.unpack_from(order + "H", data, offset)[0]


def _u32(data: bytes, offset: int, order: str = ">") -> int:
    """Read an unsigned 32-bit integer, or return 0 past the end."""
    if offset < 0 or offset + 4 > len(data):
        return 0
    return struct.unpack_from(order + "I", data, offset)[0]


def _u64(data: bytes, offset: int, order: str = ">") -> int:
    """Read an unsigned 64-bit integer, or return 0 past the end."""
    if offset < 0 or offset + 8 > len(data):
        return 0
    return struct.unpack_from(order + "Q", data, offset)[0]


def _printable(raw: str, limit: int = 300) -> str:
    """Make a decoded string safe to print: no controls, no giant blobs."""
    text = raw.replace("\x00", " ").strip()
    text = "".join(ch if ch.isprintable() or ch in "\n\t" else " " for ch in text)
    text = re.sub(r"[ \t]{2,}", " ", text)
    if len(text) > limit:
        return text[:limit] + f"… ({len(text)} chars)"
    return text


def _decode_ascii(raw: bytes) -> str:
    """Decode an ASCII/UTF-8 tag, tolerating broken bytes."""
    return _printable(raw.decode("utf-8", "replace"))


def _hex_preview(raw: bytes, limit: int = 24) -> str:
    """Render an opaque blob as ``<binary, N bytes: hex…>``."""
    head = raw[:limit].hex()
    suffix = "…" if len(raw) > limit else ""
    return f"<binary, {len(raw)} bytes: {head}{suffix}>"


# ---------------------------------------------------------------------------
# EXIF / TIFF — the bulk of identifying image metadata
# ---------------------------------------------------------------------------
#: TIFF field type -> (byte width, struct code).  ``ASCII`` and ``UNDEFINED``
#: are byte strings; the rest are numeric.
_TIFF_TYPES: dict[int, tuple[int, str]] = {
    1: (1, "B"),
    2: (1, None),
    3: (2, "H"),
    4: (4, "I"),
    5: (8, None),
    6: (1, "b"),
    7: (1, None),
    8: (2, "h"),
    9: (4, "i"),
    10: (8, None),
    11: (4, "f"),
    12: (8, "d"),
    13: (4, "I"),
}

#: IFD0 tags we have names for.  Unknown ids are still reported as ``Tag 0x…``.
_IFD0_TAGS: dict[int, str] = {
    0x0100: "ImageWidth",
    0x0101: "ImageLength",
    0x010E: "ImageDescription",
    0x010F: "Make",
    0x0110: "Model",
    0x0112: "Orientation",
    0x011A: "XResolution",
    0x011B: "YResolution",
    0x0128: "ResolutionUnit",
    0x0131: "Software",
    0x0132: "DateTime",
    0x013B: "Artist",
    0x013C: "HostComputer",
    0x0213: "YCbCrPositioning",
    0x8298: "Copyright",
    0x8769: "ExifIFDPointer",
    0x8825: "GPSInfoIFDPointer",
    0x9C9B: "XPTitle",
    0x9C9C: "XPComment",
    0x9C9D: "XPAuthor",
    0x9C9E: "XPKeywords",
    0x9C9F: "XPSubject",
    0xC4A5: "PrintImageMatching",
}

_EXIF_TAGS: dict[int, str] = {
    0x829A: "ExposureTime",
    0x829D: "FNumber",
    0x8822: "ExposureProgram",
    0x8827: "ISOSpeedRatings",
    0x8830: "SensitivityType",
    0x8831: "StandardOutputSensitivity",
    0x8832: "RecommendedExposureIndex",
    0x8833: "ISOSpeed",
    0x9000: "ExifVersion",
    0x9003: "DateTimeOriginal",
    0x9004: "DateTimeDigitized",
    0x9010: "OffsetTime",
    0x9011: "OffsetTimeOriginal",
    0x9012: "OffsetTimeDigitized",
    0x9101: "ComponentsConfiguration",
    0x9102: "CompressedBitsPerPixel",
    0x9201: "ShutterSpeedValue",
    0x9202: "ApertureValue",
    0x9203: "BrightnessValue",
    0x9204: "ExposureBiasValue",
    0x9205: "MaxApertureValue",
    0x9206: "SubjectDistance",
    0x9207: "MeteringMode",
    0x9208: "LightSource",
    0x9209: "Flash",
    0x920A: "FocalLength",
    0x9214: "SubjectArea",
    0x927C: "MakerNote",
    0x9286: "UserComment",
    0x9290: "SubSecTime",
    0x9291: "SubSecTimeOriginal",
    0x9292: "SubSecTimeDigitized",
    0xA000: "FlashpixVersion",
    0xA001: "ColorSpace",
    0xA002: "PixelXDimension",
    0xA003: "PixelYDimension",
    0xA004: "RelatedSoundFile",
    0xA005: "InteroperabilityIFDPointer",
    0xA20E: "FocalPlaneXResolution",
    0xA20F: "FocalPlaneYResolution",
    0xA210: "FocalPlaneResolutionUnit",
    0xA217: "SensingMethod",
    0xA300: "FileSource",
    0xA301: "SceneType",
    0xA401: "CustomRendered",
    0xA402: "ExposureMode",
    0xA403: "WhiteBalance",
    0xA404: "DigitalZoomRatio",
    0xA405: "FocalLengthIn35mmFilm",
    0xA406: "SceneCaptureType",
    0xA407: "GainControl",
    0xA408: "Contrast",
    0xA409: "Saturation",
    0xA40A: "Sharpness",
    0xA40C: "SubjectDistanceRange",
    0xA420: "ImageUniqueID",
    0xA430: "CameraOwnerName",
    0xA431: "BodySerialNumber",
    0xA432: "LensSpecification",
    0xA433: "LensMake",
    0xA434: "LensModel",
    0xA435: "LensSerialNumber",
    0xA460: "CompositeImage",
    0xA461: "SourceImageNumberOfCompositeImage",
    0xA500: "Gamma",
}

_GPS_TAGS: dict[int, str] = {
    0x0000: "GPSVersionID",
    0x0001: "GPSLatitudeRef",
    0x0002: "GPSLatitude",
    0x0003: "GPSLongitudeRef",
    0x0004: "GPSLongitude",
    0x0005: "GPSAltitudeRef",
    0x0006: "GPSAltitude",
    0x0007: "GPSTimeStamp",
    0x0008: "GPSSatellites",
    0x0009: "GPSStatus",
    0x000A: "GPSMeasureMode",
    0x000B: "GPSDOP",
    0x000C: "GPSSpeedRef",
    0x000D: "GPSSpeed",
    0x000E: "GPSTrackRef",
    0x000F: "GPSTrack",
    0x0010: "GPSImgDirectionRef",
    0x0011: "GPSImgDirection",
    0x0012: "GPSMapDatum",
    0x0013: "GPSDestLatitudeRef",
    0x0014: "GPSDestLatitude",
    0x0015: "GPSDestLongitudeRef",
    0x0016: "GPSDestLongitude",
    0x0017: "GPSDestBearingRef",
    0x0018: "GPSDestBearing",
    0x0019: "GPSDestDistanceRef",
    0x001A: "GPSDestDistance",
    0x001B: "GPSProcessingMethod",
    0x001C: "GPSAreaInformation",
    0x001D: "GPSDateStamp",
    0x001E: "GPSDifferential",
    0x001F: "GPSHPositioningError",
}

#: Tags whose value is a ratio and should be rendered as a human unit.
_RATIONAL_UNITS: dict[str, str] = {
    "ExposureTime": "s",
    "FNumber": "",
    "FocalLength": "mm",
    "FocalLengthIn35mmFilm": "mm",
    "SubjectDistance": "m",
    "GPSAltitude": "m",
    "GPSSpeed": "",
    "GPSImgDirection": "°",
    "GPSTrack": "°",
    "DigitalZoomRatio": "×",
}

_TIME_TAGS = {
    "DateTime",
    "DateTimeOriginal",
    "DateTimeDigitized",
    "GPSDateStamp",
}


def _tiff_value(raw: bytes, type_id: int, count: int, order: str) -> tuple[Any, bool]:
    """Decode one TIFF/EXIF value.

    Returns ``(value, is_binary)``.  Raises nothing: a value that does not fit
    the declared type is returned as a hex preview so the caller can still show
    something truthful about it.
    """
    width, code = _TIFF_TYPES.get(type_id, (1, None))
    if type_id == 2:  # ASCII
        return _decode_ascii(raw.split(b"\x00", 1)[0]), False
    if type_id == 7:  # UNDEFINED
        # UNDEFINED is a byte bag, but many cameras put plain text in it
        # (UserComment, ImageDescription).  Decode when it is unambiguously
        # text, keep it binary otherwise — guessing would be worse than a hex
        # preview, because a wrong decode invents content that is not there.
        candidate = bytes(raw).rstrip(b"\x00")
        for charset in (b"ASCII\x00\x00\x00", b"UNICODE\x00", b"JIS\x00\x00\x00\x00\x00"):
            if candidate.startswith(charset):
                candidate = candidate[len(charset):]
                break
        if candidate and all(32 <= byte < 127 or byte in (9, 10, 13) for byte in candidate):
            return candidate.decode("ascii", "replace"), False
        return _hex_preview(bytes(raw)), True
    if code is None:
        return _hex_preview(bytes(raw)), True
    if type_id in (5, 10):  # RATIONAL / SRATIONAL
        values: list[str] = []
        fmt = "II" if type_id == 5 else "ii"
        for index in range(min(count, 8)):
            base = index * 8
            if base + 8 > len(raw):
                break
            numerator, denominator = struct.unpack_from(order + fmt, raw, base)
            if denominator == 0:
                values.append(f"{numerator}/0")
            elif type_id == 10:
                values.append(f"{numerator / denominator:.4g}")
            else:
                values.append(f"{numerator}/{denominator}")
        return ", ".join(values), False
    if code in ("f", "d"):
        size = width
        values_f: list[str] = []
        for index in range(min(count, 8)):
            base = index * size
            if base + size > len(raw):
                break
            values_f.append(f"{struct.unpack_from(order + code, raw, base)[0]:g}")
        return ", ".join(values_f), False
    numbers: list[int] = []
    for index in range(min(count, 8)):
        base = index * width
        if base + width > len(raw):
            break
        numbers.append(struct.unpack_from(order + code, raw, base)[0])
    if not numbers:
        return _hex_preview(bytes(raw)), True
    return ", ".join(str(n) for n in numbers), False


def _rational(raw: bytes, order: str, index: int = 0) -> float | None:
    """Read one RATIONAL at ``index``, or ``None`` if it is absent/zero."""
    base = index * 8
    if base + 8 > len(raw):
        return None
    numerator, denominator = struct.unpack_from(order + "II", raw, base)
    if denominator == 0:
        return None
    return numerator / denominator


def _dms_to_degrees(raw: bytes, order: str) -> float | None:
    """Convert a GPS three-RATIONAL (degrees, minutes, seconds) to degrees."""
    degrees = _rational(raw, order, 0)
    minutes = _rational(raw, order, 1)
    seconds = _rational(raw, order, 2)
    if degrees is None:
        return None
    return degrees + (minutes or 0.0) / 60.0 + (seconds or 0.0) / 3600.0


def _human_value(key: str, value: str) -> str:
    """Add units and friendly phrasing to a decoded rational tag."""
    unit = _RATIONAL_UNITS.get(key)
    if unit is None or unit == "":
        return value
    first = value.split(",", 1)[0].strip()
    return f"{first}{unit}" if first else value


def _parse_ifd(
    data: bytes,
    offset: int,
    order: str,
    tags: dict[int, str],
    group: str,
    *,
    seen: set[int] | None = None,
    depth: int = 0,
) -> tuple[list[MetadataField], dict[str, Any]]:
    """Walk one TIFF IFD and everything it points at.

    ``seen`` holds offsets that have already been visited.  A malformed file can
    point an IFD at itself or into a cycle; without this set the walk would spin
    forever.  ``depth`` bounds sub-IFD nesting for the same reason.

    Returns the decoded fields plus a dictionary of raw values keyed by tag name
    — the caller needs ``GPSLatitude`` as a float, not as display text.
    """
    fields: list[MetadataField] = []
    raw_values: dict[str, Any] = {}
    seen = seen if seen is not None else set()
    if depth > _MAX_IFD_DEPTH or offset <= 0 or offset + 2 > len(data) or offset in seen:
        return fields, raw_values
    seen.add(offset)

    count = _u16(data, offset, order)
    if count == 0 or count > _MAX_IFD_ENTRIES:
        count = min(count, _MAX_IFD_ENTRIES)

    for index in range(count):
        entry = offset + 2 + index * 12
        if entry + 12 > len(data):
            break
        tag = _u16(data, entry, order)
        type_id = _u16(data, entry + 2, order)
        value_count = _u32(data, entry + 4, order)
        width = _TIFF_TYPES.get(type_id, (1, None))[0]
        size = width * value_count
        if size <= 4:
            raw = data[entry + 8 : entry + 8 + size]
        else:
            value_offset = _u32(data, entry + 8, order)
            if value_offset <= 0 or value_offset + size > len(data):
                continue
            raw = data[value_offset : value_offset + size]

        name = tags.get(tag)
        if name is None:
            name = f"Tag 0x{tag:04X}"

        if name in ("ExifIFDPointer", "GPSInfoIFDPointer", "InteroperabilityIFDPointer"):
            sub_offset = _u32(data, entry + 8, order)
            sub_tags, sub_group = {
                "ExifIFDPointer": (_EXIF_TAGS, "ExifIFD"),
                "GPSInfoIFDPointer": (_GPS_TAGS, "GPS"),
                "InteroperabilityIFDPointer": ({}, "InteropIFD"),
            }[name]
            sub_fields, sub_values = _parse_ifd(
                data, sub_offset, order, sub_tags, sub_group, seen=seen, depth=depth + 1
            )
            fields.extend(sub_fields)
            raw_values.update(sub_values)
            continue

        value, is_binary = _tiff_value(raw, type_id, value_count, order)
        if name == "MakerNote":
            # A MakerNote is always a vendor blob.  Decoding it as text would
            # both mislead the reader and defeat the point of showing it as
            # opaque data that survives tag-level deletion.
            value, is_binary = _hex_preview(bytes(raw)), True
        text = str(value)

        if name in _TIME_TAGS and re.fullmatch(r"\d{4}:\d{2}:\d{2} \d{2}:\d{2}:\d{2}", text):
            text = text.replace(":", "-", 2).replace(" ", "T", 1)
        if name.startswith("XP"):
            # Windows XP* tags are UTF-16LE bytes stored with an ASCII type.
            try:
                text = _printable(raw.decode("utf-16-le", "ignore").split("\x00", 1)[0])
                is_binary = False
            except Exception:  # pragma: no cover - defensive
                pass

        if not text.strip():
            continue

        if name in {"GPSLatitude", "GPSLongitude", "GPSAltitude", "GPSTimeStamp"}:
            if name == "GPSAltitude":
                altitude = _rational(raw, order, 0)
                if altitude is not None:
                    raw_values[name] = altitude
            elif name in {"GPSLatitude", "GPSLongitude"}:
                degrees = _dms_to_degrees(raw, order)
                if degrees is not None:
                    raw_values[name] = degrees
            else:
                parts = [_rational(raw, order, i) for i in range(3)]
                if all(part is not None for part in parts):
                    raw_values[name] = tuple(parts)
        elif name in {"GPSLatitudeRef", "GPSLongitudeRef", "GPSDateStamp"}:
            raw_values[name] = text
        elif name in {"Make", "Model", "Software", "Artist", "DateTimeOriginal",
                      "CameraOwnerName", "BodySerialNumber", "LensSerialNumber",
                      "LensModel", "ImageUniqueID"}:
            raw_values.setdefault(name, text)

        fields.append(
            MetadataField(
                key=name,
                group=group,
                label=_label_for(name),
                value=_human_value(name, text),
                binary=is_binary,
            )
        )
        if len(fields) >= _MAX_TAGS_REPORTED:
            break

    return fields, raw_values


def _gps_from_values(values: dict[str, Any]) -> tuple[float, float] | None:
    """Return decimal ``(lat, lon)`` from decoded GPS tags, when both exist."""
    lat = values.get("GPSLatitude")
    lon = values.get("GPSLongitude")
    if not isinstance(lat, (int, float)) or not isinstance(lon, (int, float)):
        return None
    if str(values.get("GPSLatitudeRef", "N")).strip().upper().startswith("S"):
        lat = -lat
    if str(values.get("GPSLongitudeRef", "E")).strip().upper().startswith("W"):
        lon = -lon
    if not (-90.0 <= lat <= 90.0 and -180.0 <= lon <= 180.0):
        return None
    return (lat, lon)


def _parse_tiff(data: bytes, base: int = 0) -> tuple[list[MetadataField], dict[str, Any], list[str]]:
    """Parse a TIFF header and IFD0 (plus Exif/GPS/IFD1) from ``data[base:]``."""
    notes: list[str] = []
    view = data[base:]
    if len(view) < 8:
        return [], {}, ["TIFF header is shorter than 8 bytes"]
    if view[:2] == b"II":
        order = "<"
    elif view[:2] == b"MM":
        order = ">"
    else:
        return [], {}, ["TIFF byte-order marker is neither II nor MM"]
    magic = _u16(view, 2, order)
    if magic != 42:
        return [], {}, [f"TIFF magic is {magic}, expected 42"]
    ifd0 = _u32(view, 4, order)
    fields, values = _parse_ifd(view, ifd0, order, _IFD0_TAGS, "IFD0")

    # IFD1, when present, almost always holds a JPEG thumbnail.  It is worth
    # reporting because a crop performed in-place does not update it.
    if ifd0 + 2 <= len(view):
        count = _u16(view, ifd0, order)
        next_off = _u32(view, ifd0 + 2 + count * 12, order)
        if 0 < next_off < len(view):
            thumb_fields, thumb_values = _parse_ifd(
                view, next_off, order, _IFD0_TAGS, "IFD1", seen={ifd0}
            )
            if thumb_fields:
                fields.append(
                    MetadataField(
                        key="Thumbnail",
                        group="IFD1",
                        label=_label_for("Thumbnail"),
                        value=f"{len(thumb_fields)} tag(s) describing an embedded preview",
                    )
                )
                fields.extend(thumb_fields)
                values.update({k: v for k, v in thumb_values.items() if k not in values})
    return fields, values, notes


# ---------------------------------------------------------------------------
# Image containers
# ---------------------------------------------------------------------------
_MARKER_NAMES = {
    0xE0: "APP0/JFIF",
    0xE1: "APP1/EXIF",
    0xE2: "APP2/ICC",
    0xEC: "APP12",
    0xED: "APP13/IPTC",
    0xEE: "APP14/Adobe",
    0xFE: "COM",
}


def _parse_jpeg(data: bytes) -> tuple[list[MetadataField], dict[str, Any], list[str], int | None, int | None]:
    """Walk JPEG segments: EXIF, XMP, ICC, IPTC, dimensions and comments.

    Returns ``(fields, raw_values, notes, width, height)``.  The entropy-coded
    scan data is never decoded — only its headers matter here.
    """
    fields: list[MetadataField] = []
    values: dict[str, Any] = {}
    notes: list[str] = []
    width: int | None = None
    height: int | None = None
    if not data.startswith(b"\xff\xd8"):
        return fields, values, ["not a JPEG (missing SOI)"], width, height

    index = 2
    seen = 0
    while index < len(data) - 1 and seen < _MAX_JPEG_SEGMENTS:
        seen += 1
        if data[index] != 0xFF:
            notes.append(f"unexpected byte 0x{data[index]:02X} at offset {index}; stopped")
            break
        while index < len(data) and data[index] == 0xFF:
            index += 1
        if index >= len(data):
            break
        marker = data[index]
        index += 1
        if marker == 0xD9:  # EOI
            break
        if marker in (0xD8,) or 0xD0 <= marker <= 0xD7 or marker == 0x01:
            continue  # standalone markers carry no length
        if index + 2 > len(data):
            notes.append("truncated segment length")
            break
        length = _u16(data, index)
        if length < 2 or index + length > len(data):
            notes.append(f"segment 0xFF{marker:02X} claims an impossible length")
            break
        payload = data[index + 2 : index + length]
        index += length

        if marker == 0xDA:  # start of scan: header ends here
            break
        if marker in (0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF):
            if len(payload) >= 5:
                height = _u16(payload, 1)
                width = _u16(payload, 3)
                fields.append(
                    MetadataField(
                        key="FrameSize",
                        group="SOF",
                        label="Frame size",
                        value=f"{width} × {height}",
                    )
                )
            continue
        if marker == 0xFE:
            text = _decode_ascii(payload)
            if text:
                fields.append(
                    MetadataField(
                        key="COM",
                        group="COM",
                        label="JPEG comment",
                        value=text,
                    )
                )
            continue
        if marker == 0xE1 and payload.startswith(b"Exif\x00\x00"):
            exif_fields, exif_values, exif_notes = _parse_tiff(payload, base=6)
            fields.extend(exif_fields)
            values.update(exif_values)
            notes.extend(exif_notes)
            continue
        if marker == 0xE1 and payload.startswith(b"http://ns.adobe.com/xap/1.0/\x00"):
            xmp = _decode_ascii(payload.split(b"\x00", 1)[1])
            fields.append(
                MetadataField(
                    key="XMP",
                    group="APP1/XMP",
                    label=_label_for("XMP"),
                    value=_xmp_summary(xmp),
                )
            )
            values["_xmp"] = xmp
            continue
        if marker == 0xE2 and payload.startswith(b"ICC_PROFILE\x00"):
            fields.append(
                MetadataField(
                    key="iCCP",
                    group="APP2/ICC",
                    label=_label_for("iCCP"),
                    value=f"ICC colour profile, {len(payload)} bytes",
                    binary=True,
                )
            )
            continue
        if marker == 0xED and b"Photoshop 3.0" in payload[:32]:
            for match in re.finditer(rb"(8BIM)([0-9A-Fa-f]{4})", payload):
                resource_id = int(match.group(2), 16)
                name = {0x0404: "IPTC caption", 0x040F: "IPTC keywords", 0x041A: "IPTC byline"}.get(
                    resource_id
                )
                if name:
                    fields.append(
                        MetadataField(
                            key="IPTC",
                            group="APP13/IPTC",
                            label=name,
                            value=f"IPTC resource 0x{resource_id:04X} present",
                            binary=True,
                        )
                    )
            continue
        if marker in _MARKER_NAMES and len(payload) > 0:
            values.setdefault("_segments", []).append(_MARKER_NAMES[marker])

    if width is None or height is None:
        notes.append("no start-of-frame segment: dimensions unknown")
    return fields, values, notes, width, height


def _xmp_summary(xmp: str) -> str:
    """Reduce an XMP packet to the few properties a person cares about."""
    wanted = (
        "xmp:CreatorTool",
        "xmp:CreateDate",
        "xmp:ModifyDate",
        "photoshop:Credit",
        "photoshop:Source",
        "dc:creator",
        "dc:rights",
        "aux:SerialNumber",
        "aux:Lens",
        "tiff:Make",
        "tiff:Model",
        "exif:GPSLatitude",
        "exif:GPSLongitude",
    )
    found: list[str] = []
    for name in wanted:
        pattern = re.compile(rf"{re.escape(name)}\s*[=>]\s*[\"']([^\"']{{1,200}})[\"']")
        match = pattern.search(xmp)
        if match:
            found.append(f"{name.split(':')[-1]}={match.group(1)}")
    if not found:
        return f"XMP packet present, {len(xmp)} chars"
    return "; ".join(found[:8])


_PNG_KEYWORDS = {
    "author": "Author",
    "artist": "Artist",
    "software": "Software",
    "comment": "Comment",
    "copyright": "Copyright",
    "creation time": "tIME",
    "description": "ImageDescription",
    "title": "XPTitle",
    "source": "ImageDescription",
    "disclaimer": "Comment",
    "warning": "Comment",
}


def _png_key(keyword: bytes) -> str:
    """Map a PNG text-chunk keyword to a tag key with a real severity rule."""
    text = keyword.decode("latin-1", "replace").strip().lower()
    return _PNG_KEYWORDS.get(text, "tEXt")


def _parse_png(data: bytes) -> tuple[list[MetadataField], dict[str, Any], list[str], int | None, int | None]:
    """Walk PNG chunks: dimensions, text chunks, eXIf, ICC and timestamps."""
    fields: list[MetadataField] = []
    values: dict[str, Any] = {}
    notes: list[str] = []
    width: int | None = None
    height: int | None = None
    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        return fields, values, ["not a PNG (bad signature)"], width, height

    index = 8
    chunks = 0
    while index + 8 <= len(data) and chunks < _MAX_PNG_CHUNKS:
        chunks += 1
        length = _u32(data, index)
        kind = data[index + 4 : index + 8]
        if length > len(data) - index - 12:
            notes.append(f"chunk {kind!r} claims {length} bytes past end of file")
            break
        payload = data[index + 8 : index + 8 + length]
        index += 12 + length

        if kind == b"IHDR" and len(payload) >= 8:
            width = _u32(payload, 0)
            height = _u32(payload, 4)
            bit_depth = payload[8] if len(payload) > 8 else 0
            colour = payload[9] if len(payload) > 9 else 0
            fields.append(
                MetadataField(
                    key="FrameSize",
                    group="IHDR",
                    label="Frame size",
                    value=f"{width} × {height}, {bit_depth}-bit, colour type {colour}",
                )
            )
        elif kind == b"tEXt":
            keyword, _, text = payload.partition(b"\x00")
            key = _png_key(keyword)
            fields.append(
                MetadataField(
                    key=key,
                    group="PNG tEXt",
                    label=keyword.decode("latin-1", "replace") or "tEXt",
                    value=_decode_ascii(text),
                )
            )
            key = keyword.decode("latin-1", "replace")
            if key.lower() in {"software", "author", "artist", "comment", "creation time",
                               "copyright", "description", "title", "xml:com.adobe.xmp"}:
                values.setdefault(key, _decode_ascii(text))
        elif kind == b"zTXt":
            keyword, _, rest = payload.partition(b"\x00")
            text = ""
            if len(rest) > 1:
                try:
                    text = _decode_ascii(
                        zlib.decompressobj().decompress(rest[1:], MAX_TEXT_BYTES)
                    )
                except zlib.error:
                    notes.append("zTXt chunk did not decompress")
            fields.append(
                MetadataField(
                    key=_png_key(keyword),
                    group="PNG zTXt",
                    label=keyword.decode("latin-1", "replace") or "zTXt",
                    value=text or "<compressed, undecodable>",
                )
            )
        elif kind == b"iTXt":
            parts = payload.split(b"\x00", 5)
            keyword = parts[0].decode("latin-1", "replace")
            text = ""
            if len(parts) >= 6:
                raw_text = parts[5]
                compressed = bool(parts[1]) if parts[1] else False
                if compressed:
                    try:
                        raw_text = zlib.decompressobj().decompress(raw_text, MAX_TEXT_BYTES)
                    except zlib.error:
                        raw_text = b""
                        notes.append("iTXt chunk did not decompress")
                text = _decode_ascii(raw_text)
            fields.append(
                MetadataField(
                    key=_png_key(keyword.encode("latin-1", "replace")),
                    group="PNG iTXt",
                    label=keyword or "iTXt",
                    value=text or "<empty>",
                )
            )
        elif kind == b"eXIf":
            exif_fields, exif_values, exif_notes = _parse_tiff(payload)
            fields.extend(exif_fields)
            values.update(exif_values)
            notes.extend(exif_notes)
            fields.append(
                MetadataField(
                    key="eXIf",
                    group="PNG eXIf",
                    label=_label_for("eXIf"),
                    value=f"{len(exif_fields)} EXIF tag(s)",
                )
            )
        elif kind == b"iCCP":
            name = payload.split(b"\x00", 1)[0].decode("latin-1", "replace")
            fields.append(
                MetadataField(
                    key="iCCP",
                    group="PNG iCCP",
                    label=_label_for("iCCP"),
                    value=f"{name or 'ICC profile'}, {len(payload)} bytes",
                    binary=True,
                )
            )
        elif kind == b"pHYs" and len(payload) >= 9:
            values["_phys"] = True
            fields.append(
                MetadataField(
                    key="pHYs",
                    group="PNG pHYs",
                    label=_label_for("pHYs"),
                    value=f"{_u32(payload, 0)} × {_u32(payload, 4)} per unit "
                    f"({payload[8]})",
                )
            )
        elif kind == b"tIME" and len(payload) >= 7:
            stamp = (
                f"{_u16(payload, 0):04d}-{payload[2]:02d}-{payload[3]:02d}T"
                f"{payload[4]:02d}:{payload[5]:02d}:{payload[6]:02d}"
            )
            values["tIME"] = stamp
            fields.append(
                MetadataField(
                    key="tIME", group="PNG tIME", label=_label_for("tIME"), value=stamp
                )
            )
        elif kind == b"IEND":
            break
    return fields, values, notes, width, height


def _parse_webp(data: bytes) -> tuple[list[MetadataField], dict[str, Any], list[str], int | None, int | None]:
    """Walk a RIFF/WebP container: canvas size, EXIF, XMP, ICC."""
    fields: list[MetadataField] = []
    values: dict[str, Any] = {}
    notes: list[str] = []
    width: int | None = None
    height: int | None = None
    if len(data) < 12 or data[:4] != b"RIFF" or data[8:12] != b"WEBP":
        return fields, values, ["not a WebP (bad RIFF header)"], width, height

    index = 12
    while index + 8 <= len(data):
        fourcc = data[index : index + 4]
        size = _u32(data, index + 4, "<")
        payload = data[index + 8 : index + 8 + size]
        index += 8 + size + (size & 1)
        if fourcc == b"VP8X" and len(payload) >= 10:
            width = 1 + int.from_bytes(payload[4:7], "little")
            height = 1 + int.from_bytes(payload[7:10], "little")
            fields.append(
                MetadataField(
                    key="VP8X",
                    group="VP8X",
                    label=_label_for("VP8X"),
                    value=f"{width} × {height}, flags 0x{payload[0]:02X}",
                )
            )
        elif fourcc == b"VP8 " and len(payload) >= 10:
            if payload[3:6] == b"\x9d\x01\x2a" and width is None:
                width = _u16(payload, 6, "<") & 0x3FFF
                height = _u16(payload, 8, "<") & 0x3FFF
                fields.append(
                    MetadataField(
                        key="FrameSize", group="VP8", label="Frame size",
                        value=f"{width} × {height}",
                    )
                )
        elif fourcc == b"VP8L" and len(payload) >= 5 and payload[0] == 0x2F and width is None:
            bits = int.from_bytes(payload[1:5], "little")
            width = (bits & 0x3FFF) + 1
            height = ((bits >> 14) & 0x3FFF) + 1
            fields.append(
                MetadataField(
                    key="FrameSize", group="VP8L", label="Frame size",
                    value=f"{width} × {height}",
                )
            )
        elif fourcc == b"EXIF":
            exif_fields, exif_values, exif_notes = _parse_tiff(payload)
            fields.extend(exif_fields)
            values.update(exif_values)
            notes.extend(exif_notes)
            fields.append(
                MetadataField(
                    key="eXIf", group="WebP EXIF", label=_label_for("eXIf"),
                    value=f"{len(exif_fields)} EXIF tag(s)",
                )
            )
        elif fourcc == b"XMP ":
            fields.append(
                MetadataField(
                    key="XMP", group="WebP XMP", label=_label_for("XMP"),
                    value=_xmp_summary(_decode_ascii(payload)),
                )
            )
        elif fourcc == b"ICCP":
            fields.append(
                MetadataField(
                    key="iCCP", group="WebP ICCP", label=_label_for("iCCP"),
                    value=f"ICC colour profile, {len(payload)} bytes", binary=True,
                )
            )
    return fields, values, notes, width, height


def _parse_gif(data: bytes) -> tuple[list[MetadataField], dict[str, Any], list[str], int | None, int | None]:
    """Read a GIF's logical screen size and any comment extensions."""
    fields: list[MetadataField] = []
    if len(data) < 10 or data[:6] not in (b"GIF87a", b"GIF89a"):
        return fields, {}, ["not a GIF"], None, None
    width = _u16(data, 6, "<")
    height = _u16(data, 8, "<")
    fields.append(
        MetadataField(key="FrameSize", group="GIF LSD", label="Frame size",
                      value=f"{width} × {height}")
    )
    comment = re.search(rb"\x21\xfe(.)(.*?)\x00", data[:4096], re.S)
    notes: list[str] = []
    if comment:
        fields.append(
            MetadataField(key="COM", group="GIF comment", label="GIF comment",
                          value=_decode_ascii(comment.group(2)))
        )
    return fields, {}, notes, width, height


def _parse_bmp(data: bytes) -> tuple[list[MetadataField], dict[str, Any], list[str], int | None, int | None]:
    """Read a BMP's dimensions from its DIB header."""
    fields: list[MetadataField] = []
    if len(data) < 26 or data[:2] != b"BM":
        return fields, {}, ["not a BMP"], None, None
    header_size = _u32(data, 14, "<")
    width = abs(struct.unpack_from("<i", data, 18)[0]) if len(data) >= 22 else None
    height = abs(struct.unpack_from("<i", data, 22)[0]) if len(data) >= 26 else None
    if width and height:
        fields.append(
            MetadataField(key="FrameSize", group="DIB", label="Frame size",
                          value=f"{width} × {height}, DIB header {header_size} bytes")
        )
    return fields, {}, [], width, height


def _parse_svg(data: bytes) -> tuple[list[MetadataField], dict[str, Any], list[str], int | None, int | None]:
    """Scan an SVG as text for ``<title>``, ``<desc>``, editor namespaces and XMP.

    SVG is XML, and XML parsing of untrusted input is its own hazard; the fields
    that matter here are all literal element/attribute text, so a targeted scan
    is both safer and sufficient.  Embedded ``data:`` images are flagged because
    they can smuggle an entire photo — metadata included — inside the SVG.
    """
    fields: list[MetadataField] = []
    notes: list[str] = []
    text = data[:4 * 1024 * 1024].decode("utf-8", "replace")
    if "<svg" not in text[:2048]:
        return fields, {}, ["not an SVG (no <svg> element)"], None, None

    def _element(name: str) -> str | None:
        match = re.search(rf"<{name}[^>]*>(.*?)</{name}>", text, re.S | re.I)
        return _printable(match.group(1), 300) if match else None

    title = _element("title")
    desc = _element("desc")
    if title:
        fields.append(MetadataField(key="TITLE", group="SVG", label="Title", value=title))
    if desc:
        fields.append(MetadataField(key="DESCRIPTION", group="SVG", label="Description",
                                    value=desc))
    for attr, label in (
        ("inkscape:version", "Inkscape version"),
        ("sodipodi:docname", "Inkscape source filename"),
        ("inkscape:export-filename", "Export path"),
        ("dc:creator", "Creator"),
        ("dc:title", "Dublin Core title"),
        ("xmp:CreatorTool", "Creator tool"),
        ("metadata", "Metadata block"),
    ):
        if attr == "metadata":
            if "<metadata" in text.lower():
                fields.append(MetadataField(key="XMP", group="SVG <metadata>",
                                            label=_label_for("XMP"),
                                            value="an XML/RDF metadata block is embedded"))
            continue
        match = re.search(rf'{re.escape(attr)}\s*=\s*"([^"]{{1,200}})"', text)
        if match:
            key = attr.split(":")[-1].upper()
            fields.append(MetadataField(key=key if key in _RULES else "XMP", group="SVG",
                                        label=label, value=_printable(match.group(1))))
    if re.search(r"xlink:href\s*=\s*[\"']data:", text, re.I):
        fields.append(
            MetadataField(
                key="XMP", group="SVG", label="Embedded raster image",
                value="a data: URI embeds a full image (its own metadata travels with it)",
            )
        )
    return fields, {}, notes, None, None


def _parse_heif(data: bytes) -> tuple[list[MetadataField], dict[str, Any], list[str], int | None, int | None]:
    """Report HEIC/AVIF structure and whether an Exif item is present.

    Full HEIF item decoding is out of scope; what matters for a privacy check is
    *whether* an ``Exif`` item exists, which this reports honestly rather than
    guessing at values.
    """
    fields: list[MetadataField] = []
    notes: list[str] = []
    if len(data) < 12 or data[4:8] != b"ftyp":
        return fields, {}, ["not an ISO-BMFF file (no ftyp box)"], None, None
    brand = data[8:12].decode("latin-1", "replace")
    fields.append(
        MetadataField(key="brand", group="ftyp", label="Brand", value=brand)
    )
    if b"Exif" in data[:65536]:
        fields.append(
            MetadataField(key="eXIf", group="HEIF item", label=_label_for("eXIf"),
                          value="an Exif item is present in the container")
        )
    else:
        notes.append("no Exif item found in the first 64 KiB")
    if b"keys" in data[:65536] and b"ilst" in data[:65536]:
        fields.append(
            MetadataField(key="XMP", group="HEIF meta", label="Metadata keys",
                          value="the container has a keyed metadata table")
        )
    return fields, {}, notes, None, None


# ---------------------------------------------------------------------------
# Audio / video containers
# ---------------------------------------------------------------------------
def _mp4_boxes(data: bytes, start: int, end: int, depth: int = 0) -> Iterator[tuple[bytes, int, int]]:
    """Yield ``(fourcc, payload_start, payload_end)`` for ISO-BMFF boxes.

    Guards against a length of zero (which would loop) and absurd nesting.
    """
    if depth > _MAX_IFD_DEPTH:
        return
    index = start
    boxes = 0
    while index + 8 <= end and boxes < _MAX_MP4_BOXES:
        boxes += 1
        size = _u32(data, index)
        fourcc = data[index + 4 : index + 8]
        header = 8
        if size == 1:
            if index + 16 > end:
                return
            size = _u64(data, index + 8)
            header = 16
        elif size == 0:
            size = end - index
        if size < header or index + size > end:
            return
        yield fourcc, index + header, index + size
        index += size


_MP4_TEXT_KEYS = {
    b"\xa9xyz",
    b"\xa9too",
    b"\xa9nam",
    b"\xa9cmt",
    b"\xa9day",
    b"\xa9ART",
    b"com.apple.quicktime.make",
    b"com.apple.quicktime.model",
    b"com.apple.quicktime.software",
    b"com.apple.quicktime.location.ISO6709",
}


def _parse_mp4(data: bytes, fmt: MediaFormat) -> tuple[list[MetadataField], dict[str, Any], list[str], int | None, int | None]:
    """Walk ISO-BMFF boxes: ``mvhd`` timestamps and ``udta``/``meta`` text keys."""
    fields: list[MetadataField] = []
    values: dict[str, Any] = {}
    notes: list[str] = []
    if len(data) < 12 or data[4:8] != b"ftyp":
        return fields, values, ["not an ISO-BMFF file (no ftyp box)"], None, None

    width: int | None = None
    height: int | None = None

    for fourcc, pstart, pend in _mp4_boxes(data, 0, len(data)):
        if fourcc == b"moov":
            for inner, istart, iend in _mp4_boxes(data, pstart, pend, 1):
                if inner == b"mvhd":
                    version = data[istart] if istart < iend else 0
                    if version == 1 and istart + 20 <= iend:
                        created = _u64(data, istart + 4)
                        scale_at = istart + 20
                    else:
                        created = _u32(data, istart + 4)
                        scale_at = istart + 12
                    if created:
                        epoch = _dt.datetime(1904, 1, 1, tzinfo=_dt.timezone.utc)
                        stamp = epoch + _dt.timedelta(seconds=created)
                        if stamp.year > 1970:
                            values["creation_time"] = stamp
                            fields.append(
                                MetadataField(
                                    key="creation_time", group="mvhd",
                                    label=_label_for("creation_time"),
                                    value=stamp.strftime("%Y-%m-%dT%H:%M:%SZ (UTC)"),
                                )
                            )
                    if scale_at + 8 <= iend:
                        timescale = _u32(data, scale_at)
                        duration = _u32(data, scale_at + 4)
                        if timescale:
                            fields.append(
                                MetadataField(
                                    key="duration", group="mvhd", label="Duration",
                                    value=f"{duration / timescale:.2f} s",
                                )
                            )
                elif inner == b"tkhd" and width is None:
                    # width/height are 16.16 fixed point at the end of tkhd.
                    if iend - istart >= 84:
                        width = int.from_bytes(data[istart + 76 : istart + 80], "big") >> 16
                        height = int.from_bytes(data[istart + 80 : istart + 84], "big") >> 16
                elif inner == b"meta":
                    _walk_mp4_meta(data, istart + 4, iend, fields, values)
                elif inner == b"udta":
                    for key, kstart, kend in _mp4_boxes(data, istart, iend, 2):
                        if key in _MP4_TEXT_KEYS:
                            text = _decode_ascii(data[kstart:kend].rstrip(b"\x00"))
                            if text:
                                name = key.decode("latin-1", "replace")
                                values.setdefault(name, text)
                                fields.append(
                                    MetadataField(
                                        key=name,
                                        group="udta",
                                        label=_label_for(name),
                                        value=text,
                                    )
                                )
                        elif key == b"meta":
                            # 'meta' is a FullBox: 4 bytes of version/flags first.
                            _walk_mp4_meta(data, kstart + 4, kend, fields, values)
    if not fields:
        notes.append("no moov metadata found (the file may be fragmented)")
    return fields, values, notes, width, height


def _walk_mp4_meta(
    data: bytes, start: int, end: int, fields: list[MetadataField], values: dict[str, Any]
) -> None:
    """Read a ``meta`` FullBox's ``ilst`` entries into ``fields`` and ``values``.

    Both ``moov/meta`` and ``udta/meta`` occur in the wild, and the entries are
    the same shape; sharing the walk keeps the two paths from drifting apart.
    """
    for mkey, mstart, mend in _mp4_boxes(data, start, end, 3):
        if mkey not in (b"ilst", b"keys"):
            continue
        for ikey, istart, iend in _mp4_boxes(data, mstart, mend, 4):
            if ikey in (b"keys", b"hdlr"):
                continue
            name = ikey.decode("latin-1", "replace")
            text = _mp4_ilst_value(data, istart, iend)
            if text:
                values.setdefault(name, text)
                fields.append(
                    MetadataField(
                        key=name, group="meta/ilst", label=_label_for(name), value=text
                    )
                )


def _mp4_ilst_value(data: bytes, start: int, end: int) -> str | None:
    """Read the text payload of an ``ilst`` entry's ``data`` box."""
    for fourcc, pstart, pend in _mp4_boxes(data, start, end):
        if fourcc != b"data" or pend - pstart < 8:
            continue
        type_indicator = _u32(data, pstart) & 0xFFFFFF
        payload = data[pstart + 8 : pend]
        if type_indicator == 1:
            return _decode_ascii(payload)
        if type_indicator == 21:
            return str(int.from_bytes(payload, "big")) if payload else None
        if type_indicator == 0:
            return _hex_preview(payload)
    return None


_ID3_TEXT_FRAMES = {
    "TIT2", "TPE1", "TPE2", "TALB", "TCOM", "TCON", "TDRC", "TYER",
    "TSSE", "TENC", "TCOP", "TPUB", "TLAN", "TMED", "TPOS", "TRCK",
}


def _syncsafe(raw: bytes) -> int:
    """Decode an ID3 syncsafe integer (7 bits per byte)."""
    value = 0
    for byte in raw[:4]:
        value = (value << 7) | (byte & 0x7F)
    return value


def _decode_id3_text(payload: bytes) -> str:
    """Decode an ID3 text frame honouring its encoding byte."""
    if not payload:
        return ""
    encoding, body = payload[0], payload[1:]
    try:
        if encoding == 0:
            text = body.decode("latin-1", "replace")
        elif encoding == 1:
            text = body.decode("utf-16", "replace")
        elif encoding == 2:
            text = body.decode("utf-16-be", "replace")
        else:
            text = body.decode("utf-8", "replace")
    except Exception:  # pragma: no cover - defensive
        text = body.decode("latin-1", "replace")
    return _printable(text.split("\x00", 1)[0])


def _parse_mp3(data: bytes) -> tuple[list[MetadataField], dict[str, Any], list[str], int | None, int | None]:
    """Parse an ID3v2 tag (and note ID3v1), without decoding audio."""
    fields: list[MetadataField] = []
    values: dict[str, Any] = {}
    notes: list[str] = []
    if not data.startswith(b"ID3"):
        if data[-128:-125] == b"TAG":
            notes.append("an ID3v1 tag is present at the end of the file")
        else:
            notes.append("no ID3v2 tag found")
        return fields, values, notes, None, None

    if len(data) < 10:
        return fields, values, ["truncated ID3 header"], None, None
    major = data[3]
    size = _syncsafe(data[6:10])
    body = data[10 : 10 + size]
    fields.append(
        MetadataField(key="ID3", group=f"ID3v2.{major}", label="ID3 version",
                      value=f"v2.{major}, tag size {size} bytes")
    )
    if data[5] & 0x80:  # unsynchronisation
        body = body.replace(b"\xff\x00", b"\xff")
        notes.append("tag used unsynchronisation; 0xFF 0x00 pairs were reassembled")

    if major == 2:
        notes.append("ID3v2.2 uses 3-character frame ids and is not decoded")
        return fields, values, notes, None, None

    index = 0
    if data[5] & 0x40 and len(body) >= 4:
        # v2.3's extended-header size excludes the four size bytes; v2.4's
        # syncsafe size includes them.  Reading one as the other shifts every
        # frame boundary, so the two are handled separately.
        skip = _syncsafe(body[:4]) if major >= 4 else _u32(body, 0) + 4
        if 4 <= skip <= len(body):
            index = skip
        else:
            notes.append("extended ID3 header has an impossible size; frames may be missed")
    frames = 0
    while index + 10 <= len(body) and frames < _MAX_ID3_FRAMES:
        frames += 1
        frame_id = body[index : index + 4]
        if not frame_id.strip(b"\x00") or not re.fullmatch(rb"[A-Z0-9]{4}", frame_id):
            break
        frame_size = (
            _syncsafe(body[index + 4 : index + 8]) if major >= 4 else _u32(body, index + 4)
        )
        payload = body[index + 10 : index + 10 + frame_size]
        index += 10 + frame_size
        if frame_size <= 0 or len(payload) < frame_size:
            notes.append(f"frame {frame_id.decode('latin-1')} is truncated")
            break

        name = frame_id.decode("latin-1")
        if name in _ID3_TEXT_FRAMES:
            text = _decode_id3_text(payload)
            if text:
                values.setdefault(name, text)
                fields.append(
                    MetadataField(key=name, group=f"ID3v2.{major}",
                                  label=_label_for(name), value=text)
                )
        elif name in {"COMM", "USLT"}:
            text = _decode_id3_text(payload[4:] if len(payload) > 4 else payload)
            if text:
                fields.append(
                    MetadataField(key=name, group=f"ID3v2.{major}",
                                  label=_label_for(name), value=text)
                )
        elif name == "TXXX":
            text = _decode_id3_text(payload)
            if text:
                fields.append(
                    MetadataField(key="TXXX", group=f"ID3v2.{major}",
                                  label=_label_for("TXXX"), value=text)
                )
        elif name == "WXXX":
            text = _decode_id3_text(payload)
            if text:
                fields.append(
                    MetadataField(key="WXXX", group=f"ID3v2.{major}",
                                  label=_label_for("WXXX"), value=text)
                )
        elif name in {"APIC", "GEOB", "PRIV", "UFID"}:
            detail = f"{frame_size} bytes"
            if name == "APIC" and len(payload) > 4:
                mime = payload[1 : payload.find(b"\x00", 1) if b"\x00" in payload[1:] else 1]
                if mime:
                    detail = f"{mime.decode('latin-1', 'replace')}, {frame_size} bytes"
            fields.append(
                MetadataField(key=name, group=f"ID3v2.{major}",
                              label=_label_for(name), value=detail, binary=True)
            )
    return fields, values, notes, None, None


def _parse_flac(data: bytes) -> tuple[list[MetadataField], dict[str, Any], list[str], int | None, int | None]:
    """Parse FLAC metadata blocks: stream info, Vorbis comments, pictures."""
    fields: list[MetadataField] = []
    values: dict[str, Any] = {}
    notes: list[str] = []
    if not data.startswith(b"fLaC"):
        return fields, values, ["not a FLAC stream"], None, None
    index = 4
    blocks = 0
    last = False
    while index + 4 <= len(data) and not last and blocks < _MAX_FLAC_BLOCKS:
        blocks += 1
        header = data[index]
        last = bool(header & 0x80)
        block_type = header & 0x7F
        length = int.from_bytes(data[index + 1 : index + 4], "big")
        payload = data[index + 4 : index + 4 + length]
        index += 4 + length
        if block_type == 0 and len(payload) >= 18:  # STREAMINFO
            packed = int.from_bytes(payload[10:18], "big")
            sample_rate = (packed >> 44) & 0xFFFFF
            channels = ((packed >> 41) & 0x7) + 1
            bits = ((packed >> 36) & 0x1F) + 1
            total = packed & 0xFFFFFFFFF
            fields.append(
                MetadataField(
                    key="STREAMINFO", group="FLAC", label="Stream info",
                    value=f"{sample_rate} Hz, {channels} channel(s), {bits}-bit, "
                    f"{total / sample_rate:.1f} s" if sample_rate else "stream info",
                )
            )
        elif block_type == 4:  # VORBIS_COMMENT
            vendor_len = _u32(payload, 0, "<")
            cursor = 4 + vendor_len
            vendor = payload[4 : 4 + vendor_len].decode("utf-8", "replace")
            if vendor:
                values["ENCODER"] = vendor
                fields.append(
                    MetadataField(key="ENCODER", group="Vorbis comment",
                                  label=_label_for("ENCODER"), value=vendor)
                )
            count = _u32(payload, cursor, "<") if cursor + 4 <= len(payload) else 0
            cursor += 4
            for _ in range(min(count, 200)):
                if cursor + 4 > len(payload):
                    break
                item_len = _u32(payload, cursor, "<")
                cursor += 4
                item = payload[cursor : cursor + item_len]
                cursor += item_len
                key, _, text = item.decode("utf-8", "replace").partition("=")
                upper = key.strip().upper()
                if upper and text and upper in {
                    "TITLE", "ARTIST", "ALBUM", "DATE", "DESCRIPTION",
                    "COMMENT", "COPYRIGHT", "ENCODER", "ORGANIZATION",
                    "LOCATION", "GENRE",
                }:
                    values.setdefault(upper, text)
                    fields.append(
                        MetadataField(key=upper, group="Vorbis comment",
                                      label=_label_for(upper), value=_printable(text))
                    )
        elif block_type == 6:  # PICTURE
            fields.append(
                MetadataField(key="PICTURE", group="FLAC PICTURE",
                              label=_label_for("PICTURE"),
                              value=f"embedded picture, {length} bytes", binary=True)
            )
        elif block_type == 2:  # APPLICATION
            app_id = payload[:4].decode("latin-1", "replace")
            fields.append(
                MetadataField(key="APPLICATION", group="FLAC APPLICATION",
                              label="Application block", value=f"{app_id}, {length} bytes")
            )
    return fields, values, notes, None, None


def _parse_wav(data: bytes) -> tuple[list[MetadataField], dict[str, Any], list[str], int | None, int | None]:
    """Parse a RIFF/WAVE file: fmt chunk plus ``LIST INFO`` text tags."""
    fields: list[MetadataField] = []
    values: dict[str, Any] = {}
    notes: list[str] = []
    if len(data) < 12 or data[:4] != b"RIFF" or data[8:12] != b"WAVE":
        return fields, values, ["not a WAV (bad RIFF header)"], None, None
    index = 12
    while index + 8 <= len(data):
        fourcc = data[index : index + 4]
        size = _u32(data, index + 4, "<")
        payload = data[index + 8 : index + 8 + size]
        index += 8 + size + (size & 1)
        if fourcc == b"fmt " and len(payload) >= 16:
            channels = _u16(payload, 2, "<")
            rate = _u32(payload, 4, "<")
            bits = _u16(payload, 14, "<")
            fields.append(
                MetadataField(key="fmt", group="WAV", label="Stream info",
                              value=f"{rate} Hz, {channels} channel(s), {bits}-bit")
            )
        elif fourcc == b"LIST" and payload[:4] == b"INFO":
            cursor = 4
            while cursor + 8 <= len(payload):
                key = payload[cursor : cursor + 4].decode("latin-1", "replace")
                length = _u32(payload, cursor + 4, "<")
                text = _decode_ascii(payload[cursor + 8 : cursor + 8 + length])
                cursor += 8 + length + (length & 1)
                if text:
                    values.setdefault(key, text)
                    fields.append(
                        MetadataField(key=key, group="RIFF INFO", label=_label_for(key),
                                      value=text)
                    )
        elif fourcc == b"id3 " or fourcc == b"ID3 ":
            id3_fields, id3_values, id3_notes = _parse_mp3(payload)
            fields.extend(id3_fields)
            values.update(id3_values)
            notes.extend(id3_notes)
    return fields, values, notes, None, None


def _parse_ogg(data: bytes) -> tuple[list[MetadataField], dict[str, Any], list[str], int | None, int | None]:
    """Report an Ogg/Opus stream and read its Vorbis comment header if present."""
    fields: list[MetadataField] = []
    values: dict[str, Any] = {}
    notes: list[str] = []
    if not data.startswith(b"OggS"):
        return fields, values, ["not an Ogg stream"], None, None
    codec = "Ogg"
    if b"OpusHead" in data[:4096]:
        codec = "Ogg/Opus"
    elif b"\x01vorbis" in data[:4096]:
        codec = "Ogg/Vorbis"
    fields.append(MetadataField(key="codec", group="Ogg", label="Codec", value=codec))
    match = re.search(rb"\x03vorbis", data)
    if match is None:
        return fields, values, notes, None, None

    # A Vorbis comment header is: packet type + "vorbis", then the vendor
    # length, the vendor string, the number of comments, and the comments.
    # (The old code skipped seven bytes here that belong to the identification
    # header, which shifted every read and produced garbage vendors.)
    cursor = match.end()
    vendor_len = _u32(data, cursor, "<")
    if vendor_len > 4096:
        notes.append("Vorbis comment vendor length is implausible; skipped")
        return fields, values, notes, None, None
    vendor = data[cursor + 4 : cursor + 4 + vendor_len].decode("utf-8", "replace")
    if vendor:
        values["ENCODER"] = vendor
        fields.append(
            MetadataField(key="ENCODER", group="Vorbis comment",
                          label=_label_for("ENCODER"), value=_printable(vendor))
        )
    cursor += 4 + vendor_len
    count = _u32(data, cursor, "<") if cursor + 4 <= len(data) else 0
    cursor += 4
    for _ in range(min(count, 200)):
        if cursor + 4 > len(data):
            break
        item_len = _u32(data, cursor, "<")
        cursor += 4
        if item_len > MAX_TEXT_BYTES or cursor + item_len > len(data):
            break
        item = data[cursor : cursor + item_len].decode("utf-8", "replace")
        cursor += item_len
        key, _, text = item.partition("=")
        upper = key.strip().upper()
        if upper and text and upper in {"TITLE", "ARTIST", "ALBUM", "DATE", "TRACKNUMBER",
                                        "GENRE", "COMMENT", "COPYRIGHT", "ENCODER"}:
            values.setdefault(upper, text)
            fields.append(
                MetadataField(key=upper, group="Vorbis comment",
                              label=_label_for(upper), value=_printable(text))
            )
    return fields, values, notes, None, None



# ---------------------------------------------------------------------------
# Format sniffing
# ---------------------------------------------------------------------------
_HEIC_BRANDS = {b"heic", b"heix", b"hevc", b"hevx", b"heim", b"heis", b"hevm", b"hevs",
                b"mif1", b"msf1"}
_AVIF_BRANDS = {b"avif", b"avis"}


def sniff_format(data: bytes, name: str = "") -> MediaFormat:
    """Identify a container from its magic bytes, falling back to the extension.

    Content wins over the name: a ``.jpg`` that is really a PNG is reported as
    a PNG, because acting on the wrong format is how a scrub silently fails.
    """
    head = data[:64]
    if head.startswith(b"\xff\xd8\xff"):
        return MediaFormat.JPEG
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return MediaFormat.PNG
    if head[:6] in (b"GIF87a", b"GIF89a"):
        return MediaFormat.GIF
    if head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return MediaFormat.WEBP
    if head[:4] == b"RIFF" and head[8:12] == b"WAVE":
        return MediaFormat.WAV
    if head[:2] in (b"II", b"MM"):
        order = "<" if head[:2] == b"II" else ">"
        if _u16(head, 2, order) == 42:
            return MediaFormat.TIFF
    if head[:2] == b"BM" and len(head) > 14:
        return MediaFormat.BMP
    if head[:4] == b"fLaC":
        return MediaFormat.FLAC
    if head[:4] == b"OggS":
        return MediaFormat.OGG
    if head[:3] == b"ID3":
        return MediaFormat.MP3
    if head[4:8] == b"ftyp" and len(head) >= 12:
        brand = head[8:12]
        if brand in _AVIF_BRANDS:
            return MediaFormat.AVIF
        if brand in _HEIC_BRANDS:
            return MediaFormat.HEIC
        if brand == b"qt  ":
            return MediaFormat.MOV
        return MediaFormat.MP4
    if head[:4] == b"\x1a\x45\xdf\xa3":
        return MediaFormat.WEBM if b"webm" in data[:4096] else MediaFormat.MKV
    if head[:2] == b"\xff\xfb" or head[:2] == b"\xff\xf3" or head[:2] == b"\xff\xf2":
        return MediaFormat.MP3
    stripped = head.lstrip(b"\xef\xbb\xbf \t\r\n")
    if (
        stripped.startswith((b"<?xml", b"<svg"))
        and b"<svg" in data[:8192]
    ):
        return MediaFormat.SVG
    suffix = Path(name).suffix.lower() if name else ""
    return _EXTENSIONS.get(suffix, MediaFormat.UNKNOWN)


_PARSERS = {
    MediaFormat.JPEG: lambda data: _parse_jpeg(data),
    MediaFormat.PNG: lambda data: _parse_png(data),
    MediaFormat.GIF: lambda data: _parse_gif(data),
    MediaFormat.WEBP: lambda data: _parse_webp(data),
    MediaFormat.TIFF: lambda data: _parse_tiff_container(data),
    MediaFormat.BMP: lambda data: _parse_bmp(data),
    MediaFormat.SVG: lambda data: _parse_svg(data),
    MediaFormat.HEIC: lambda data: _parse_heif(data),
    MediaFormat.AVIF: lambda data: _parse_heif(data),
    MediaFormat.MP3: lambda data: _parse_mp3(data),
    MediaFormat.FLAC: lambda data: _parse_flac(data),
    MediaFormat.OGG: lambda data: _parse_ogg(data),
    MediaFormat.WAV: lambda data: _parse_wav(data),
    MediaFormat.MP4: lambda data: _parse_mp4(data, MediaFormat.MP4),
    MediaFormat.MOV: lambda data: _parse_mp4(data, MediaFormat.MOV),
    MediaFormat.WEBM: lambda data: _parse_mp4(data, MediaFormat.WEBM),
    MediaFormat.MKV: lambda data: _parse_mp4(data, MediaFormat.MKV),
}


def _parse_tiff_container(
    data: bytes,
) -> tuple[list[MetadataField], dict[str, Any], list[str], int | None, int | None]:
    """Adapt the EXIF/TIFF walker to the common parser interface.

    A ``.tif`` is the same structure as an EXIF block, so the IFD walker does
    all the work; only the reported group names differ (``IFD0`` rather than
    ``ExifIFD`` is already what it produces).
    """
    fields, values, notes = _parse_tiff(data)
    width = height = None
    for item in fields:
        if item.key in {"ImageWidth", "PixelXDimension"} and item.value.isdigit():
            width = int(item.value)
        elif item.key in {"ImageLength", "PixelYDimension"} and item.value.isdigit():
            height = int(item.value)
    return fields, values, notes, width, height


def _combine(fields: Sequence[MetadataField]) -> list[Exposure]:
    """Turn decoded fields into ordered, de-duplicated privacy exposures.

    Repeated keys (PNG allows many ``tEXt`` chunks, ID3 allows many comments)
    are merged into one row so the score does not count the same disclosure ten
    times, while every distinct value stays visible.
    """
    grouped: dict[str, list[MetadataField]] = {}
    order: list[str] = []
    for item in fields:
        key = item.key if item.key in _RULES else f"{item.key}"
        if key not in grouped:
            order.append(key)
            grouped[key] = []
        grouped[key].append(item)

    exposures: list[Exposure] = []
    for key in order:
        items = grouped[key]
        rule = _rule_for(key)
        if rule is None or rule.severity is Severity.INFO:
            continue
        value = "; ".join(dict.fromkeys(item.value for item in items if item.value))
        label = items[0].label if key not in _LABELS else _label_for(key)
        exposures.append(
            Exposure(
                key=key,
                label=label,
                value=_printable(value, 400),
                severity=rule.severity,
                reveals=rule.reveals,
                action=rule.action,
            )
        )
    return exposures


def _gps_exposures(
    values: dict[str, Any], fields: Sequence[MetadataField]
) -> tuple[list[Exposure], tuple[float, float] | None]:
    """Build the combined GPS exposure and the decimal coordinates, if present."""
    coordinates = _gps_from_values(values)
    exposures: list[Exposure] = []
    if coordinates is None:
        # A GPS block that decoded partially is still worth reporting honestly.
        present = [item for item in fields if item.key.startswith("GPS")]
        if present:
            exposures.append(
                Exposure(
                    key="GPS",
                    label="GPS block (incomplete)",
                    value="; ".join(dict.fromkeys(item.value for item in present))[:300],
                    severity=Severity.HIGH,
                    reveals="a GPS block exists but did not decode to usable coordinates",
                    action="strip GPS from the file rather than trusting a partial decode",
                )
            )
        return exposures, None

    lat, lon = coordinates
    exposures.append(
        Exposure(
            key="GPSLatitude",
            label="GPS position",
            value=f"{lat:.6f}, {lon:.6f}",
            severity=Severity.CRITICAL,
            reveals=(
                "the exact place the photo was taken — typically within a few "
                "metres; open it at "
                f"https://www.openstreetmap.org/?mlat={lat:.6f}&mlon={lon:.6f}"
                "#map=17 to see the spot"
            ),
            action="strip GPS/EXIF before publishing; most editors offer a 'remove location' export",
        )
    )
    altitude = values.get("GPSAltitude")
    if isinstance(altitude, (int, float)):
        exposures.append(
            Exposure(
                key="GPSAltitude",
                label="GPS altitude",
                value=f"{altitude:.1f} m",
                severity=Severity.HIGH,
                reveals="the altitude of the shot, which narrows a location to a floor or hill",
                action="strip GPS",
            )
        )
    stamp = values.get("GPSTimeStamp")
    if isinstance(stamp, tuple):
        hour, minute, second = (part or 0 for part in stamp)
        exposures.append(
            Exposure(
                key="GPSTimeStamp",
                label="GPS time",
                value=f"{int(hour):02d}:{int(minute):02d}:{second:04.1f} UTC",
                severity=Severity.HIGH,
                reveals="the UTC time of the fix, which pins the capture to a moment",
                action="strip GPS",
            )
        )
    return exposures, coordinates


def _score(exposures: Sequence[Exposure]) -> int:
    """Turn exposures into a 0–100 disclosure score.

    The score is a weighted sum capped at 100, then floored at 1 when anything
    was found — a single medium finding must never round down to "clean".
    """
    if not exposures:
        return 0
    total = sum(item.severity.weight for item in exposures)
    return max(1, min(100, total))


def _verdict(score: int, exposures: Sequence[Exposure]) -> str:
    """Short human verdict matching the score."""
    if score == 0:
        return "nothing identifying found"
    worst = max((item.severity for item in exposures), key=lambda s: s.rank)
    if worst is Severity.CRITICAL:
        return "severe — at least one field pinpoints a person or device"
    if score >= 60:
        return "high — several fields combine into a strong fingerprint"
    if score >= 30:
        return "notable — the file tells a stranger more than you would expect"
    if score >= 10:
        return "low — minor hints are present"
    return "minimal — only weak hints are present"


def analyze_bytes(data: bytes, name: str = "<memory>") -> MediaReport:
    """Analyse one in-memory file and return a :class:`MediaReport`.

    Never raises for malformed input: an unreadable container produces a report
    with ``format=UNKNOWN`` and a note, so a batch run can finish and still show
    which files were not understood.
    """
    digest = hashlib.sha256(data).hexdigest()
    fmt = sniff_format(data, name)
    fields: list[MetadataField] = []
    values: dict[str, Any] = {}
    notes: list[str] = []
    width: int | None = None
    height: int | None = None

    if fmt is MediaFormat.UNKNOWN:
        notes.append(
            "format not recognised from its magic bytes — nothing was decoded; "
            "this is not a statement that the file is clean"
        )
    else:
        parser = _PARSERS.get(fmt)
        try:
            if parser is not None:
                fields, values, notes, width, height = parser(data)
        except Exception as exc:  # a bad file must not abort a batch
            notes.append(f"parser stopped early ({type(exc).__name__}: {exc})")

    exposures = _combine(fields)
    gps_exposures, coordinates = _gps_exposures(values, fields)
    exposures = gps_exposures + [item for item in exposures if not item.key.startswith("GPS")]
    exposures.sort(key=lambda item: (-item.severity.rank, item.key.lower()))
    score = _score(exposures)

    if coordinates and fmt in _IMAGE_FORMATS:
        notes.append(
            "coordinates decoded from the file — the openstreetmap link in the "
            "exposure is computed locally and makes no request"
        )
    if len(fields) >= _MAX_TAGS_REPORTED:
        notes.append(f"field list capped at {_MAX_TAGS_REPORTED}; the file has more tags")

    return MediaReport(
        name=name,
        size_bytes=len(data),
        sha256=digest,
        format=fmt,
        mime=_MIME.get(fmt, "application/octet-stream"),
        width=width,
        height=height,
        fields=fields,
        exposures=exposures,
        notes=notes,
        coordinates=coordinates,
        score=score,
        verdict=_verdict(score, exposures),
    )


def analyze_path(path: str | Path, *, max_bytes: int = DEFAULT_MAX_BYTES) -> MediaReport:
    """Read one file from disk and analyse it.

    ``max_bytes`` caps how much is read.  A larger file is analysed from its
    first ``max_bytes`` only and flagged ``truncated`` — the report says so
    rather than pretending the tail was examined.
    """
    target = Path(path)
    if target.is_dir():
        raise D3ta1l3rError(f"{target} is a directory; pass a file or use iter_media_files()")
    status = target.stat()
    if not stat.S_ISREG(status.st_mode):
        raise D3ta1l3rError(
            f"{target} is not a regular file; refusing to read something that may "
            "never end (FIFO, device or socket)"
        )
    size = status.st_size
    with target.open("rb") as handle:
        data = handle.read(max_bytes)
    report = analyze_bytes(data, name=str(target))
    if size > len(data):
        report.truncated = True
        report.notes.append(
            f"only the first {len(data)} of {size} bytes were read (max_bytes={max_bytes})"
        )
    return report


def iter_media_files(
    paths: Iterable[str | Path], *, recursive: bool = True
) -> Iterator[Path]:
    """Yield media files under ``paths`` in deterministic order.

    Directories are walked (recursively by default) and filtered by extension;
    individual files are yielded regardless of extension so a deliberately named
    file can still be checked.  Symlinked duplicates are yielded once, and a
    path that does not exist is skipped rather than aborting the batch.
    """
    seen: set[str] = set()
    for raw in paths:
        path = Path(raw)
        if path.is_dir():
            candidates: Iterable[Path] = path.rglob("*") if recursive else path.glob("*")
            for candidate in sorted(candidates):
                if not candidate.is_file():
                    continue
                if candidate.suffix.lower() not in _EXTENSIONS:
                    continue
                key = str(candidate.resolve())
                if key in seen:
                    continue
                seen.add(key)
                yield candidate
        elif path.is_file():
            key = str(path.resolve())
            if key not in seen:
                seen.add(key)
                yield path


# ---------------------------------------------------------------------------
# Scrubbing
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class ScrubResult:
    """The output of a scrub: cleaned bytes, what was removed, and the residue.

    ``residual_score`` is the disclosure score of the *output* re-analysed with
    the same parser.  A scrub that reports success while leaving EXIF behind
    would be worse than no scrub at all, so the claim is verified rather than
    assumed.
    """

    format: MediaFormat
    data: bytes
    removed: list[str]
    size_before: int
    size_after: int
    residual_score: int
    residual_exposures: int
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        """JSON-ready summary (never includes the bytes themselves)."""
        return {
            "format": self.format.value,
            "removed": list(self.removed),
            "size_before": self.size_before,
            "size_after": self.size_after,
            "bytes_saved": max(0, self.size_before - self.size_after),
            "residual_score": self.residual_score,
            "residual_exposures": self.residual_exposures,
            "note": self.note,
        }


def _scrub_jpeg(data: bytes) -> tuple[bytes, list[str]]:
    """Rebuild a JPEG without APPn/COM segments, copying scan data verbatim."""
    removed: list[str] = []
    if not data.startswith(b"\xff\xd8"):
        raise D3ta1l3rError("not a JPEG (missing SOI)")
    out = bytearray(b"\xff\xd8")
    index = 2
    while index < len(data):
        if data[index] != 0xFF:
            out += data[index:]
            break
        while index < len(data) and data[index] == 0xFF:
            index += 1
        if index >= len(data):
            break
        marker = data[index]
        index += 1
        if marker == 0xD9:
            out += b"\xff\xd9"
            break
        if marker == 0xDA:  # SOS: header then entropy-coded data to EOF
            if index + 2 > len(data):
                out += b"\xff\xda" + data[index:]
                break
            length = _u16(data, index)
            out += b"\xff\xda" + data[index : index + length] + data[index + length :]
            break
        if 0xD0 <= marker <= 0xD7 or marker in (0x01, 0xD8):
            out += bytes((0xFF, marker))
            continue
        if index + 2 > len(data):
            break
        length = _u16(data, index)
        if length < 2 or index + length > len(data):
            raise D3ta1l3rError(f"segment 0xFF{marker:02X} is truncated")
        if 0xE0 <= marker <= 0xEF:
            removed.append(f"APP{marker - 0xE0}")
        elif marker == 0xFE:
            removed.append("COM")
        else:
            out += bytes((0xFF, marker)) + data[index : index + length]
        index += length
    if not out.endswith(b"\xff\xd9") and data.endswith(b"\xff\xd9"):
        out += b"\xff\xd9"
    return bytes(out), removed


def _scrub_png(data: bytes) -> tuple[bytes, list[str]]:
    """Rebuild a PNG dropping textual, EXIF, time and physical-density chunks."""
    drop = {b"tEXt", b"zTXt", b"iTXt", b"eXIf", b"tIME", b"pHYs", b"iCCP"}
    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        raise D3ta1l3rError("not a PNG (bad signature)")
    out = bytearray(b"\x89PNG\r\n\x1a\n")
    removed: list[str] = []
    index = 8
    while index + 8 <= len(data):
        length = _u32(data, index)
        kind = data[index + 4 : index + 8]
        if length > len(data) - index - 12:
            raise D3ta1l3rError(f"PNG chunk {kind!r} is truncated")
        raw = data[index : index + 12 + length]
        if kind in drop:
            removed.append(kind.decode("latin-1"))
        else:
            out += raw
        index += 12 + length
        if kind == b"IEND":
            break
    return bytes(out), removed


def _scrub_webp(data: bytes) -> tuple[bytes, list[str]]:
    """Rebuild a WebP dropping EXIF/XMP/ICC chunks and their VP8X flag bits."""
    if len(data) < 12 or data[:4] != b"RIFF" or data[8:12] != b"WEBP":
        raise D3ta1l3rError("not a WebP (bad RIFF header)")
    removed: list[str] = []
    chunks: list[bytes] = []
    index = 12
    while index + 8 <= len(data):
        fourcc = data[index : index + 4]
        size = _u32(data, index + 4, "<")
        if index + 8 + size > len(data):
            raise D3ta1l3rError(f"WebP chunk {fourcc!r} is truncated")
        payload = bytearray(data[index + 8 : index + 8 + size])
        raw = data[index : index + 8 + size + (size & 1)]
        if fourcc == b"VP8X" and len(payload) >= 1:
            payload[0] &= ~0x2C  # clear EXIF(0x08) | XMP(0x04) | ICCP(0x20)
            raw = fourcc + len(payload).to_bytes(4, "little") + bytes(payload)
            if len(payload) & 1:
                raw += b"\x00"
        elif fourcc in (b"EXIF", b"XMP ", b"ICCP"):
            removed.append(fourcc.decode("latin-1").strip() or fourcc.hex())
            index += 8 + size + (size & 1)
            continue
        chunks.append(raw)
        index += 8 + size + (size & 1)
    body = b"WEBP" + b"".join(chunks)
    return b"RIFF" + len(body).to_bytes(4, "little") + body, removed


def _scrub_flac(data: bytes) -> tuple[bytes, list[str]]:
    """Rebuild FLAC metadata dropping comments, pictures and application blocks."""
    if not data.startswith(b"fLaC"):
        raise D3ta1l3rError("not a FLAC stream")
    drop = {2: "APPLICATION", 4: "VORBIS_COMMENT", 6: "PICTURE"}
    blocks: list[tuple[int, bytes]] = []
    removed: list[str] = []
    index = 4
    audio_start = len(data)
    last = False
    while index + 4 <= len(data) and not last:
        header = data[index]
        last = bool(header & 0x80)
        block_type = header & 0x7F
        length = int.from_bytes(data[index + 1 : index + 4], "big")
        payload = data[index + 4 : index + 4 + length]
        if length > len(data) - index - 4:
            raise D3ta1l3rError("FLAC metadata block is truncated")
        if block_type in drop:
            removed.append(drop[block_type])
        else:
            blocks.append((block_type, payload))
        index += 4 + length
        audio_start = index
    out = bytearray(b"fLaC")
    for position, (block_type, payload) in enumerate(blocks):
        header = block_type | (0x80 if position == len(blocks) - 1 else 0)
        out += bytes((header,)) + len(payload).to_bytes(3, "big") + payload
    out += data[audio_start:]
    return bytes(out), removed


def _scrub_mp3(data: bytes) -> tuple[bytes, list[str]]:
    """Strip an ID3v2 tag from the front and an ID3v1 tag from the end."""
    removed: list[str] = []
    out = data
    if out.startswith(b"ID3") and len(out) >= 10:
        size = _syncsafe(out[6:10])
        end = min(len(out), 10 + size)
        removed.append(f"ID3v2 tag ({end} bytes)")
        out = out[end:]
    if out[-128:-125] == b"TAG":
        removed.append("ID3v1 tag (128 bytes)")
        out = out[:-128]
    if not removed:
        raise D3ta1l3rError("no ID3 tag found — nothing to scrub")
    return out, removed


_SCRUBBERS = {
    MediaFormat.JPEG: _scrub_jpeg,
    MediaFormat.PNG: _scrub_png,
    MediaFormat.WEBP: _scrub_webp,
    MediaFormat.FLAC: _scrub_flac,
    MediaFormat.MP3: _scrub_mp3,
}

#: Formats that have no supported scrubber, with the reason.  Saying so is
#: better than writing a file that looks clean and is not.
SCRUB_UNSUPPORTED: dict[MediaFormat, str] = {
    MediaFormat.TIFF: "TIFF stores metadata in its IFDs; rewriting tags needs a full encoder",
    MediaFormat.GIF: "GIF has no standard metadata block beyond comments",
    MediaFormat.BMP: "BMP carries no metadata beyond its header",
    MediaFormat.HEIC: "HEIF item rewriting needs a full container encoder",
    MediaFormat.AVIF: "AVIF item rewriting needs a full container encoder",
    MediaFormat.MP4: "use `ffmpeg -map_metadata -1 -c copy` to remux without metadata",
    MediaFormat.MOV: "use `ffmpeg -map_metadata -1 -c copy` to remux without metadata",
    MediaFormat.WEBM: "use `ffmpeg -map_metadata -1 -c copy` to remux without metadata",
    MediaFormat.MKV: "use `ffmpeg -map_metadata -1 -c copy` to remux without metadata",
    MediaFormat.WAV: "RIFF INFO tags need the chunk list rewritten; not implemented",
    MediaFormat.OGG: "Ogg pages are interleaved; rewriting the comment header is not implemented",
    MediaFormat.SVG: "SVG is text; edit out <metadata>, <title> and <desc> by hand",
    MediaFormat.UNKNOWN: "format not recognised",
}


def scrub_bytes(data: bytes, *, verify: bool = True) -> ScrubResult:
    """Return the same file with identifying metadata removed.

    Only formats with a lossless, byte-level scrubber are supported (JPEG, PNG,
    WebP, FLAC, MP3); the rest raise :class:`D3ta1l3rError` with the reason and
    an alternative.  With ``verify`` the output is re-analysed and its residual
    score recorded, so the caller can assert the scrub actually worked.
    """
    fmt = sniff_format(data)
    scrubber = _SCRUBBERS.get(fmt)
    if scrubber is None:
        reason = SCRUB_UNSUPPORTED.get(fmt, "no scrubber for this format")
        raise D3ta1l3rError(f"cannot scrub {fmt.label}: {reason}")
    cleaned, removed = scrubber(data)
    residual = analyze_bytes(cleaned, "<scrubbed>") if verify else None
    note = ""
    if residual is not None and residual.score > 0:
        note = (
            "residual metadata remains after scrubbing; inspect "
            "residual_exposures before publishing"
        )
    return ScrubResult(
        format=fmt,
        data=cleaned,
        removed=removed,
        size_before=len(data),
        size_after=len(cleaned),
        residual_score=residual.score if residual else 0,
        residual_exposures=len(residual.exposures) if residual else 0,
        note=note,
    )


def scrub_path(
    source: str | Path, destination: str | Path | None = None, *, overwrite: bool = False
) -> tuple[ScrubResult, Path]:
    """Scrub a file on disk and write the result next to it.

    The default destination is ``<stem>.clean<ext>``.  An existing file is not
    replaced unless ``overwrite=True`` — the original is the only copy of the
    bytes, and a careless default would destroy the evidence.
    """
    src = Path(source)
    data = src.read_bytes()
    result = scrub_bytes(data)
    if destination is None:
        dest = src.with_name(f"{src.stem}.clean{src.suffix}")
    else:
        dest = Path(destination)
    if dest.exists() and not overwrite:
        raise D3ta1l3rError(f"{dest} already exists; pass overwrite=True to replace it")
    dest.parent.mkdir(parents=True, exist_ok=True)
    # Write then rename: an interrupted scrub must not leave a truncated file
    # under the name a caller is about to publish.
    temporary = dest.with_name(dest.name + ".tmp")
    temporary.write_bytes(result.data)
    os.replace(temporary, dest)
    return result, dest


def render_markdown(report: MediaReport) -> str:
    """Render a report as Markdown for the CLI, a file, or a dashboard panel."""
    lines: list[str] = []
    lines.append(f"# Media metadata: {report.name}")
    lines.append("")
    dimensions = (
        f"{report.width} × {report.height}" if report.width and report.height else "unknown"
    )
    lines.append(f"- **Format:** {report.format.label} ({report.mime})")
    lines.append(f"- **Size:** {report.size_bytes:,} bytes")
    lines.append(f"- **Dimensions:** {dimensions}")
    lines.append(f"- **SHA-256:** `{report.sha256}`")
    lines.append(f"- **Disclosure score:** {report.score}/100 — {report.verdict}")
    if report.truncated:
        lines.append("- **Truncated:** only part of the file was read")
    lines.append("")

    if report.exposures:
        lines.append("## What a stranger learns")
        lines.append("")
        lines.append("| Severity | Field | Value | What it reveals |")
        lines.append("|---|---|---|---|")
        for item in report.exposures:
            value = item.value.replace("|", "\\|")
            reveals = item.reveals.replace("|", "\\|")
            lines.append(
                f"| {item.severity.value} | {item.label} | `{value}` | {reveals} |"
            )
        lines.append("")
        lines.append("### How to remove it")
        lines.append("")
        for action in dict.fromkeys(item.action for item in report.exposures):
            lines.append(f"- {action}")
        lines.append("")
    else:
        lines.append("## What a stranger learns")
        lines.append("")
        lines.append("Nothing identifying was found in this file.")
        lines.append("")

    if report.fields:
        lines.append("## Every decoded field")
        lines.append("")
        for group, fields in report.by_group.items():
            lines.append(f"### {group}")
            lines.append("")
            for item in fields:
                lines.append(f"- **{item.label}** (`{item.key}`): {item.value}")
            lines.append("")

    if report.notes:
        lines.append("## Notes")
        lines.append("")
        for note in report.notes:
            lines.append(f"- {note}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"
