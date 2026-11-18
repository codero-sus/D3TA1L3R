# Media metadata: what your own files say about you

A scan asks what public endpoints know about an identifier. `d3ta1l3r media` asks
a different question: **what does a file you are about to publish already say
about you?**

The answer is usually more than people expect. A phone photo commonly carries
the camera model, the exact capture time, the editing software and — if location
services were on — a latitude and longitude good to a few metres. A camera
configured with an owner name repeats that name in every photo it takes. A
screenshot can carry the application, the window title, and the machine's name.
An MP3 can carry the encoder, a user-defined URL, and artwork that has its own
GPS block inside it.

None of this is visible in a thumbnail, and sites strip it inconsistently — some
remove everything, some remove EXIF but keep XMP, some keep the file untouched.
The only reliable check is on the file itself, before you publish it.

`media` runs entirely on your machine. It makes **no network requests**, uploads
nothing, and uses only the Python standard library — no Pillow, no exiftool.

---

## What is read

| Format | Extensions | What is decoded |
|---|---|---|
| JPEG | `.jpg .jpeg .jpe` | APP1 EXIF (IFD0, ExifIFD, GPS, IFD1 thumbnail), APP1 XMP, APP2 ICC, APP13 IPTC resources, COM comments, frame size from SOF |
| PNG | `.png` | `IHDR` dimensions, `tEXt`, `zTXt`, `iTXt`, `eXIf`, `iCCP`, `pHYs`, `tIME` |
| WebP | `.webp` | `VP8X` canvas size, `VP8`/`VP8L` dimensions, `EXIF`, `XMP `, `ICCP` |
| TIFF | `.tif .tiff` | the same IFD walker as EXIF, including GPS and IFD1 |
| HEIC / HEIF | `.heic .heif` | brand and whether an `Exif` item exists in the container |
| AVIF | `.avif` | brand and metadata-table presence |
| GIF | `.gif` | logical screen size, comment extension |
| BMP | `.bmp` | DIB header size and dimensions |
| SVG | `.svg` | `<title>`, `<desc>`, `<metadata>`, Inkscape/Sodipodi namespaces, `data:` embedded rasters |
| MP3 | `.mp3` | ID3v2.3/2.4 text frames, `COMM`, `TXXX`, `WXXX`, `APIC`, `GEOB`, `PRIV`, `UFID`; ID3v1 presence |
| FLAC | `.flac` | `STREAMINFO`, Vorbis comments, `PICTURE`, application blocks |
| WAV | `.wav` | `fmt ` stream info, `LIST/INFO` tags (`INAM`, `IART`, `ISFT`, `ICRD`, …), embedded ID3 |
| Ogg | `.ogg .oga .opus` | codec, Vorbis comment vendor string |
| MP4 / M4A | `.mp4 .m4v .m4a` | `mvhd` creation time and duration, `udta` (`©xyz`, `©too`, `©nam`, …), `meta/ilst` keys |
| QuickTime | `.mov` | as MP4 |
| WebM / Matroska | `.webm .mkv` | container identification and any ISO-BMFF-style metadata |

Content is sniffed from magic bytes and **beats the extension**: a `.jpg` that is
really a PNG is reported — and scrubbed — as a PNG. Acting on the wrong format is
how a scrub silently fails.

## The severity model

Severity describes what a field reveals *on its own*, not whether it is
inconvenient.

| Severity | Meaning | Weight |
|---|---|---|
| `critical` | one field is enough to locate a person or link devices: GPS, a body serial number, an owner name written by the camera | 40 |
| `high` | identifies directly or fingerprints strongly: camera model, artist, capture time, an embedded thumbnail showing the uncropped frame | 16 |
| `medium` | narrows someone down when combined with other data: editor software, timezone, lens, album title | 7 |
| `low` | a weak hint: resolution, ICC profile, pixel density | 2 |
| `info` | technical detail with no identifying content: exposure settings, colour space | 0 |

The disclosure score is the sum of weights, capped at 100, and floored at 1 when
anything at all was found — a single `medium` finding must never round down to
"clean". The verdict line is derived from the worst severity present and the
score.

`score == 0` means **nothing identifying was found**, not that the file is
proven clean. Files whose format could not be recognised say so explicitly in
`notes`; they are never reported as clean.

## Field catalogue

Every key below has a severity, an explanation of what a stranger learns from
it, and the concrete action that removes it. Unknown tags are still reported
(as `Tag 0xNNNN`) — omitting them would hide data the file really contains.

| Key | Severity | What a stranger learns | Remove it by |
|---|---|---|---|
| `BodySerialNumber` | critical | the camera body's serial number — a permanent identifier that links every photo ever taken with that body, across sites and accounts | strip EXIF; the serial is also in the MakerNote, so strip that too |
| `CameraOwnerName` | critical | the owner name configured inside the camera — often a full legal name, and it travels with every photo that camera takes | clear the owner name in the camera menu, then strip EXIF on export |
| `com.apple.quicktime.location.ISO6709` | critical | GPS coordinates written by an Apple device | strip metadata by remuxing |
| `GPSLatitude` | critical | latitude | strip GPS from the file |
| `GPSLongitude` | critical | longitude | strip GPS from the file |
| `LensSerialNumber` | critical | the lens serial number, which links photos taken with the same lens | strip EXIF |
| `XPAuthor` | critical | the Windows account name of the person who saved the file | clear Windows property fields; this is often a login name |
| `©xyz` | critical | GPS coordinates written by the recording device | strip metadata by remuxing; this tag is easy to miss |
| `Artist` | high | a name written into the file itself, often the photographer's real name | remove the Artist/Copyright tags in your editor before exporting |
| `Author` | high | a named author stored in a PNG text chunk | strip PNG text chunks |
| `com.apple.quicktime.make` | high | the recording device's manufacturer | strip metadata by remuxing |
| `com.apple.quicktime.model` | high | the recording device model | strip metadata by remuxing |
| `DateTimeDigitized` | high | when the image was digitised, usually the same second as capture | strip EXIF |
| `DateTimeOriginal` | high | the exact moment the shutter fired — enough to place you at a time and, with other photos, to reconstruct a routine | strip EXIF; this is the tag most useful for correlating a set of photos |
| `eXIf` | high | a full EXIF block embedded in a PNG | strip PNG metadata |
| `GPSAltitude` | high | altitude above sea level | strip GPS from the file |
| `GPSDateStamp` | high | the UTC date of the GPS fix | strip GPS |
| `GPSTimeStamp` | high | the UTC time of the GPS fix | strip GPS |
| `HostComputer` | high | the name of the computer that processed the image, which usually matches a username or a device name | strip EXIF; this tag is written by desktop editors |
| `ImageUniqueID` | high | a per-image unique identifier that can tie copies of the same shot together | strip EXIF |
| `MakerNote` | high | an opaque manufacturer block that commonly repeats the serial number, shutter count and lens data even when the visible tags were removed | strip EXIF entirely; deleting individual tags leaves the MakerNote behind |
| `Model` | high | the exact device model — combined with anyone else's photo of you, it lets two files be attributed to the same camera | strip EXIF; most editors have a 'remove location/EXIF' export option |
| `UFID` | high | a unique file identifier that can link the file to a library | clear the ID3 tag |
| `UserComment` | high | free text stored by the camera or editor — often a name, a project, or a note | clear the comment field |
| `XMP` | high | an XMP packet — usually a full editing history, creator tool and often the original camera data even after EXIF was removed | strip XMP as well as EXIF; they are separate blocks |
| `XPComment` | high | a Windows comment string typed by the owner | clear Windows property fields before sharing |
| `XPTitle` | high | a Windows title string that often contains a name | clear Windows property fields before sharing |
| `APIC` | medium | embedded artwork — the image may carry its own EXIF/GPS | clear the ID3 tag; check the artwork separately if it matters |
| `ARTIST` | medium | the artist (Vorbis comment) | strip Vorbis comments |
| `COM` | medium | a free-text comment segment straight after the header | strip the JPEG comment segment |
| `com.apple.quicktime.software` | medium | the device OS version | strip metadata by remuxing |
| `COMM` | medium | a free-text comment | clear the ID3 tag |
| `Comment` | medium | a free-text comment stored in the file | strip the comment field |
| `Copyright` | medium | a copyright string, which frequently contains a full legal name or email | remove or genericise the Copyright tag |
| `creation_time` | medium | when the recording was created, in UTC — and some devices write local time, which leaks the timezone | strip metadata by remuxing (`ffmpeg -map_metadata -1`) |
| `DateTime` | medium | when the file was last written, to the second | strip EXIF; note that some sites keep the file's own mtime regardless |
| `DESCRIPTION` | medium | a free-text description | strip Vorbis comments |
| `ENCODER` | medium | the encoder software (Vorbis comment) | strip Vorbis comments |
| `GEOB` | medium | an embedded binary object | clear the ID3 tag |
| `GPSImgDirection` | medium | which way the camera was pointing | strip GPS |
| `GPSProcessingMethod` | medium | how the position was obtained (GPS, Wi-Fi, cell) | strip GPS |
| `GPSSpeed` | medium | how fast you were moving | strip GPS |
| `IART` | medium | the artist (RIFF INFO) | clear RIFF INFO tags |
| `ICMT` | medium | a comment (RIFF INFO) | clear RIFF INFO tags |
| `ImageDescription` | medium | free text someone typed about the image — captions often name people or places | clear the description field |
| `ISFT` | medium | the software that wrote the file (RIFF INFO) | clear RIFF INFO tags |
| `iTXt` | medium | an internationalised text chunk, often XMP or a comment | strip PNG text chunks |
| `LensModel` | medium | the lens used, narrowing the camera and the owner | strip EXIF |
| `Make` | medium | the manufacturer that built the camera, which starts a device fingerprint | strip EXIF before publishing, or export a copy without metadata |
| `OffsetTime` | medium | the timezone offset of the file's timestamp | strip EXIF |
| `OffsetTimeDigitized` | medium | the timezone at digitisation | strip EXIF |
| `OffsetTimeOriginal` | medium | the timezone at capture — it narrows a location even without GPS | strip EXIF |
| `PICTURE` | medium | embedded cover art, which may carry EXIF | strip Vorbis comments and pictures |
| `PRIV` | medium | an application-private data blob (player state, IDs) | clear the ID3 tag |
| `Software` | medium | the last program that wrote the file, including its version — an editor or a phone OS, which dates the file and hints at your workflow | strip EXIF; re-encoding through an editor that drops tags is enough |
| `TENC` | medium | the person or organisation that encoded the file | clear the ID3 tag |
| `tEXt` | medium | a free-text key/value pair (PNG has no schema) | strip PNG text chunks |
| `Thumbnail` | medium | an embedded preview that is often the *uncropped* original — cropping a photo in an editor does not always update it | re-export the image rather than editing it in place; strip EXIF |
| `tIME` | medium | the last-modification time, to the second | strip PNG metadata |
| `TIT2` | medium | the track title | clear the ID3 tag |
| `TPE1` | medium | the performing artist | clear the ID3 tag |
| `TPE2` | medium | the album artist | clear the ID3 tag |
| `TSSE` | medium | the encoder software and version | clear the ID3 tag |
| `TXXX` | medium | a user-defined text field | clear the ID3 tag |
| `USLT` | medium | unsynchronised lyrics | clear the ID3 tag |
| `WXXX` | medium | a user-defined URL | clear the ID3 tag |
| `XPKeywords` | medium | Windows keywords, which often tag people or places | clear Windows property fields |
| `XPSubject` | medium | a Windows subject line for the file | clear Windows property fields |
| `zTXt` | medium | a compressed text chunk, same content as tEXt | strip PNG text chunks |
| `©too` | medium | the encoder or device that produced the file | strip metadata by remuxing |
| `ALBUM` | low | the album | strip Vorbis comments |
| `DATE` | low | a date | strip Vorbis comments |
| `DigitalZoomRatio` | low | whether digital zoom was used | strip EXIF |
| `FocalLength` | low | the focal length used | usually harmless |
| `FocalLengthIn35mmFilm` | low | the full-frame equivalent focal length | usually harmless |
| `GPSMapDatum` | low | the geodetic datum of the fix | strip GPS |
| `iCCP` | low | an embedded colour profile, which can name a device | strip the ICC profile for a smaller, cleaner file |
| `ICCP` | low | an embedded colour profile | strip the ICC profile |
| `ICRD` | low | the creation date (RIFF INFO) | clear RIFF INFO tags |
| `INAM` | low | the title (RIFF INFO) | clear RIFF INFO tags |
| `LensMake` | low | the lens manufacturer | strip EXIF |
| `LensSpecification` | low | the lens focal range and aperture | strip EXIF |
| `pHYs` | low | the assumed pixel density | strip if you want a minimal PNG |
| `SubSecTimeOriginal` | low | sub-second capture time | strip EXIF |
| `TALB` | low | the album name | clear the ID3 tag |
| `TCOM` | low | the composer | clear the ID3 tag |
| `TCON` | low | the genre | clear the ID3 tag |
| `TDRC` | low | the recording date | clear the ID3 tag |
| `TITLE` | low | the title | strip Vorbis comments |
| `BrightnessValue` | info | scene brightness | nothing — harmless |
| `ColorSpace` | info | the colour space | nothing — harmless |
| `CustomRendered` | info | whether custom processing was applied | nothing — harmless |
| `ExposureBiasValue` | info | exposure compensation | nothing — harmless |
| `ExposureMode` | info | the exposure mode | nothing — harmless |
| `ExposureProgram` | info | the exposure mode | nothing — harmless |
| `ExposureTime` | info | the shutter speed | nothing — harmless |
| `Flash` | info | whether the flash fired | nothing — harmless |
| `FNumber` | info | the aperture | nothing — harmless |
| `ISOSpeedRatings` | info | the ISO speed | nothing — harmless |
| `MaxApertureValue` | info | the lens's maximum aperture | nothing — harmless |
| `MeteringMode` | info | how the camera metered the scene | nothing — harmless |
| `Orientation` | info | how the camera was rotated | nothing — harmless |
| `PixelXDimension` | info | the image width in pixels | nothing — harmless |
| `PixelYDimension` | info | the image height in pixels | nothing — harmless |
| `SceneCaptureType` | info | the scene mode | nothing — harmless |
| `SceneType` | info | the scene type | nothing — harmless |
| `SensingMethod` | info | the sensor type | nothing — harmless |
| `SubjectArea` | info | the focus point | nothing — harmless |
| `SubjectDistance` | info | the focus distance | nothing — harmless |
| `VP8X` | info | the WebP extended header | nothing — structural |
| `WhiteBalance` | info | the white-balance setting | nothing — harmless |

## Scrubbing

`d3ta1l3r media scrub` writes a copy with the metadata removed, then **re-analyses
its own output** and reports the residual score. A scrub that leaves metadata
behind is worse than no scrub at all, so the claim is verified rather than
assumed.

| Format | What the scrubber removes |
|---|---|
| JPEG | every APPn segment and COM comment; image data, tables and frame headers are copied byte for byte |
| PNG | `tEXt`, `zTXt`, `iTXt`, `eXIf`, `tIME`, `pHYs`, `iCCP`; `IDAT` and the critical chunks are untouched |
| WebP | `EXIF`, `XMP `, `ICCP` chunks, and the corresponding bits are cleared from the `VP8X` flags |
| FLAC | `VORBIS_COMMENT`, `PICTURE`, `APPLICATION`; audio frames untouched |
| MP3 | the whole ID3v2 tag and the ID3v1 trailer; audio untouched |

Formats that would need a full re-encoder (TIFF, HEIC, AVIF, MP4, MOV, WebM, MKV,
WAV, Ogg, SVG) are refused with the reason and an alternative — for video,
`ffmpeg -map_metadata -1 -c copy`. The tool never writes a file that only looks
clean.

The original is never modified. The default destination is
`<name>.clean<ext>`; an existing file is not replaced unless `--overwrite` is
given, because the original is the only copy of the bytes.

## Command line

```bash
d3ta1l3r media formats                     # what is recognised, and what can be scrubbed
d3ta1l3r media scan photo.jpg              # verdict, evidence, and how to fix it
d3ta1l3r media scan ~/Pictures --json      # directories are walked
d3ta1l3r media scan photo.jpg --min-severity high
d3ta1l3r media scan photo.jpg --markdown report.md
d3ta1l3r media scrub photo.jpg             # writes photo.clean.jpg and verifies it
```

Example:

```
photo.jpg
  JPEG · 2,204,331 bytes · 4032 x 3024 · score 100/100 — severe — at least one field pinpoints a person or device
  CRITICAL  GPS position             28.614000, 77.209000
            ↳ the exact place the photo was taken — typically within a few metres; open it at
              https://www.openstreetmap.org/?mlat=28.614000&mlon=77.209000#map=17 to see the spot
  CRITICAL  Body serial number       SN-0123456789
            ↳ the camera body's serial number — a permanent identifier that links every photo
              ever taken with that body, across sites and accounts
  HIGH      Camera model             EOS R5
  HIGH      Captured at              2026-03-04T11:22:30
  To remove:
    - strip GPS/EXIF before publishing; most editors offer a 'remove location' export
    - strip EXIF; the serial is also in the MakerNote, so strip that too
```

`--fail-on` turns the scan into a CI gate: it exits **3** when any file carries
an exposure at or above the named severity. That is how a publishing pipeline
stops before a photo with GPS in it goes out.

| Code | Meaning |
|---|---|
| `0` | success |
| `1` | bad usage (no files found, `--out` with several inputs) |
| `2` | a file could not be read, or a scrub left residual metadata |
| `3` | `--fail-on` threshold reached |

## Dashboard API

| Route | Purpose |
|---|---|
| `POST /api/media` | analyse a base64-encoded file; optionally return a scrubbed copy |
| `GET /api/media/formats` | recognised formats, their extensions, and scrub support |

```jsonc
// POST /api/media
{
  "name": "photo.jpg",
  "data_base64": "...",
  "scrub": true,          // optional: return cleaned bytes
  "include_fields": true  // set false to omit the full tag list
}
```

The response contains `report` — identical in shape to the CLI's `--json` — and,
when `scrub` was requested, `scrub` with `data_base64` of the cleaned file and
the residual score. Bytes are held in memory for the duration of the request;
nothing is written to disk and nothing leaves the process.

## Limits

Parsing untrusted binaries is a safety problem as much as a correctness one.
Every limit below exists because the alternative is a hang or an out-of-memory
kill on a hostile file:

* **Input size** — 128 MiB per file by default (`--max-bytes` to change). A
  larger file is analysed from its head and flagged `truncated`.
* **IFD recursion** — depth 6, at most 4 096 entries per IFD, and an offset may
  be visited only once. A cyclic or self-referential EXIF block terminates.
* **Decompression** — any single compressed text chunk expands to at most 1 MiB.
* **Segment/box counts** — JPEG segments, PNG chunks, MP4 boxes, ID3 frames and
  FLAC blocks all have ceilings, so a file cannot force unbounded looping.
* **Upload size** — 32 MiB per request on the dashboard endpoint.

Parsing is tolerant by design: a malformed file yields whatever could be
recovered, plus a note. It never raises into a batch run.

## What it deliberately does not do

* **No reverse geocoding.** Coordinates are reported, and a map link is
  *computed* — the link is text in the report, not a request. Looking up an
  address would mean sending your location to a third party.
* **No face recognition, no OCR, no object detection.** Those need models, and
  the point of this command is a check you can run before uploading, not another
  thing that reads your photos.
* **No MakerNote decoding.** Vendor blobs are reported as present and opaque.
  Decoding them is a per-manufacturer moving target, and the actionable advice —
  strip the MakerNote along with EXIF — does not depend on the values.
* **No cloud parsing.** Nothing here phones home.

## Library use

```python
from pathlib import Path
from d3ta1l3r.media import analyze_path, scrub_bytes

report = analyze_path("holiday.jpg")
print(report.score, report.verdict)
for exposure in report.exposures:
    print(exposure.severity.value, exposure.label, exposure.value)

cleaned = scrub_bytes(Path("holiday.jpg").read_bytes())
Path("holiday.clean.jpg").write_bytes(cleaned.data)
assert cleaned.residual_score == 0
```
