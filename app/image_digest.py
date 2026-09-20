"""Firmware image content fingerprinting.

The parser turns any Intel HEX text into canonical, address-ordered
contiguous segments plus an optional entry address. This module encodes
that assembled image into an unambiguous byte stream and hashes it with
SHA-256, so the *same logical image* always yields the *same fingerprint*
no matter how its bytes were split across data records or how the gaps
between segments were represented:

* the segment a byte ends up in depends only on its absolute address,
  never on the record that carried it (identical rewrites collapse,
  contiguous records merge);
* every segment is emitted as a self-delimiting frame tagged with its
  absolute start and length, followed by its raw bytes;
* frames are strictly address-ordered, and distinct tag bytes separate
  data frames from the entry/no-entry markers, so no stream of one shape
  can be re-parsed as another.

Canonical stream (all integers big-endian, unsigned 64-bit)::

    MAGIC || frame*

    MAGIC   = b"firmware-image-digest/v1\n"
    segment : 0x01 || start:u64 || length:u64 || data[length]
    entry   : 0x02 || address:u64          (entry present)
    noentry : 0x03                        (entry absent)

The entry frame is appended only when ``include_entry`` is true; an image
without an entry record then gets the explicit ``noentry`` marker so that
"entry absent" cannot be confused with "entry frame omitted".
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from .hex_parser import Segment

CANONICAL_FORMAT = "firmware-image-digest/v1"
HASH_ALGORITHM = "sha256"

MAGIC = b"firmware-image-digest/v1\n"
TAG_SEGMENT = 0x01
TAG_ENTRY = 0x02
TAG_NO_ENTRY = 0x03


@dataclass
class SegmentDigest:
    """Canonical summary of one contiguous segment."""

    index: int
    start: int
    end: int  # exclusive
    size: int
    gap_before: int  # uncovered bytes between the previous segment and this one
    frame: bytes  # the exact canonical frame fed to the image hash
    sha256: str  # SHA-256 of the segment frame (binds address, length and bytes)


@dataclass
class CanonicalFrame:
    """A description of one frame in the hashed canonical stream."""

    kind: str  # "segment" | "entry" | "no_entry"
    index: int | None = None
    start: int | None = None
    end: int | None = None
    size: int | None = None
    sha256: str | None = None
    address: int | None = None  # entry frame only


@dataclass
class CanonicalManifest:
    """Human-readable description of exactly what was hashed."""

    format: str
    hash_algorithm: str
    include_entry: bool
    segment_count: int
    total_bytes: int
    frame_count: int
    canonical_bytes: int  # length of the canonical byte stream
    frames: list[CanonicalFrame] = field(default_factory=list)


@dataclass
class ImageDigest:
    """The fingerprint of an assembled firmware image."""

    segments: list[SegmentDigest]
    entry_address: int | None
    include_entry: bool
    total_bytes: int
    canonical_bytes: bytes
    image_sha256: str
    manifest: CanonicalManifest


def _u64(value: int) -> bytes:
    return value.to_bytes(8, "big")


def _segment_frame(segment: Segment) -> bytes:
    return (
        bytes([TAG_SEGMENT])
        + _u64(segment.start)
        + _u64(len(segment.data))
        + segment.data
    )


def build_image_digest(
    segments: list[Segment],
    entry_address: int | None,
    include_entry: bool = True,
) -> ImageDigest:
    """Encode assembled segments into the canonical stream and hash it.

    Segments are sorted defensively: the parser already returns them in
    ascending address order, but the fingerprint must never depend on
    caller-supplied ordering.
    """
    ordered = sorted(segments, key=lambda s: s.start)

    segment_digests: list[SegmentDigest] = []
    frames_meta: list[CanonicalFrame] = []
    stream = bytearray(MAGIC)
    total_bytes = 0

    for index, segment in enumerate(ordered):
        frame = _segment_frame(segment)
        stream.extend(frame)
        total_bytes += len(segment.data)
        gap_before = 0 if index == 0 else segment.start - ordered[index - 1].end
        digest = SegmentDigest(
            index=index,
            start=segment.start,
            end=segment.end,
            size=len(segment.data),
            gap_before=gap_before,
            frame=bytes(frame),
            sha256=hashlib.sha256(frame).hexdigest(),
        )
        segment_digests.append(digest)
        frames_meta.append(
            CanonicalFrame(
                kind="segment",
                index=index,
                start=segment.start,
                end=segment.end,
                size=len(segment.data),
                sha256=digest.sha256,
            )
        )

    if include_entry:
        if entry_address is None:
            stream.append(TAG_NO_ENTRY)
            frames_meta.append(CanonicalFrame(kind="no_entry"))
        else:
            stream.append(TAG_ENTRY)
            stream.extend(_u64(entry_address))
            frames_meta.append(CanonicalFrame(kind="entry", address=entry_address))

    canonical = bytes(stream)
    manifest = CanonicalManifest(
        format=CANONICAL_FORMAT,
        hash_algorithm=HASH_ALGORITHM,
        include_entry=include_entry,
        segment_count=len(ordered),
        total_bytes=total_bytes,
        frame_count=len(frames_meta),
        canonical_bytes=len(canonical),
        frames=frames_meta,
    )
    return ImageDigest(
        segments=segment_digests,
        entry_address=entry_address,
        include_entry=include_entry,
        total_bytes=total_bytes,
        canonical_bytes=canonical,
        image_sha256=hashlib.sha256(canonical).hexdigest(),
        manifest=manifest,
    )
