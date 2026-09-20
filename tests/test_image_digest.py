"""Tests for the firmware content fingerprint module and /api/v1/image-digest."""

import hashlib

from fastapi.testclient import TestClient

from app.hex_parser import Segment, parse_intel_hex
from app.image_digest import (
    HASH_ALGORITHM,
    MAGIC,
    TAG_ENTRY,
    TAG_NO_ENTRY,
    TAG_SEGMENT,
    build_image_digest,
)
from app.main import app

client = TestClient(app)


def rec(rectype: int, addr: int, data: bytes = b"") -> str:
    """Build a valid Intel HEX record line."""
    body = bytes([len(data), (addr >> 8) & 0xFF, addr & 0xFF, rectype]) + bytes(data)
    checksum = (-sum(body)) & 0xFF
    return ":" + (body + bytes([checksum])).hex().upper()


EOF = rec(0x01, 0)


def data_rec(addr: int, data: bytes) -> str:
    return rec(0x00, addr, data)


def linear_base(value: int) -> str:
    return rec(0x04, 0, value.to_bytes(2, "big"))


def linear_entry(value: int) -> str:
    return rec(0x05, 0, value.to_bytes(4, "big"))


def expected_stream(parts: list[tuple[str, object]]) -> bytes:
    """Rebuild a canonical stream from ("seg", start, data) / ("entry", addr) / "noentry"."""
    out = bytearray(MAGIC)
    for part in parts:
        if part[0] == "seg":
            _, start, data = part
            out.append(TAG_SEGMENT)
            out += int(start).to_bytes(8, "big")
            out += len(data).to_bytes(8, "big")
            out += data
        elif part[0] == "entry":
            out.append(TAG_ENTRY)
            out += int(part[1]).to_bytes(8, "big")
        else:
            out.append(TAG_NO_ENTRY)
    return bytes(out)


# ---------------------------------------------------------------------------
# pure fingerprint logic
# ---------------------------------------------------------------------------

def test_single_segment_frame_and_image_hash():
    segments = [Segment(start=0x1000, data=b"\x01\x02\x03\x04")]
    digest = build_image_digest(segments, entry_address=None, include_entry=True)
    stream = expected_stream([("seg", 0x1000, b"\x01\x02\x03\x04"), "noentry"])
    assert digest.canonical_bytes == stream
    assert digest.image_sha256 == hashlib.sha256(stream).hexdigest()
    frame = bytes([TAG_SEGMENT]) + (0x1000).to_bytes(8, "big") + (4).to_bytes(8, "big") + b"\x01\x02\x03\x04"
    assert digest.segments[0].sha256 == hashlib.sha256(frame).hexdigest()
    assert digest.total_bytes == 4
    assert digest.manifest.canonical_bytes == len(stream)
    assert digest.manifest.hash_algorithm == HASH_ALGORITHM


def test_entry_frame_appended_when_present():
    digest = build_image_digest([], entry_address=0x080001C1, include_entry=True)
    stream = expected_stream([("entry", 0x080001C1)])
    assert digest.canonical_bytes == stream
    assert digest.image_sha256 == hashlib.sha256(stream).hexdigest()
    assert [f.kind for f in digest.manifest.frames] == ["entry"]
    assert digest.manifest.frames[0].address == 0x080001C1


def test_explicit_no_entry_marker_keeps_empty_images_distinct():
    with_entry = build_image_digest([], entry_address=None, include_entry=True)
    without_entry = build_image_digest([], entry_address=None, include_entry=False)
    assert with_entry.canonical_bytes == MAGIC + bytes([TAG_NO_ENTRY])
    assert without_entry.canonical_bytes == MAGIC
    assert with_entry.image_sha256 != without_entry.image_sha256
    assert [f.kind for f in with_entry.manifest.frames] == ["no_entry"]
    assert without_entry.manifest.frames == []


def test_include_entry_false_ignores_entry_even_when_present():
    digest = build_image_digest(
        [Segment(0, b"\xAA")], entry_address=0x08000000, include_entry=False
    )
    stream = expected_stream([("seg", 0, b"\xAA")])
    assert digest.canonical_bytes == stream
    assert digest.include_entry is False
    assert all(f.kind == "segment" for f in digest.manifest.frames)
    # entry address is still reported
    assert digest.entry_address == 0x08000000


def test_segments_are_sorted_and_gaps_only_appear_in_summary():
    digest = build_image_digest(
        [Segment(0x0010, b"\x03"), Segment(0x0000, b"\x01\x02")],
        entry_address=None,
        include_entry=False,
    )
    assert [s.start for s in digest.segments] == [0x0000, 0x0010]
    assert digest.segments[0].gap_before == 0
    assert digest.segments[1].gap_before == 0x0E
    # gaps add no bytes between frames: frames are back to back
    stream = expected_stream(
        [("seg", 0x0000, b"\x01\x02"), ("seg", 0x0010, b"\x03")]
    )
    assert digest.canonical_bytes == stream


def test_address_binding_makes_segments_with_same_bytes_differ():
    a = build_image_digest([Segment(0x0000, b"\x01")], None, False)
    b = build_image_digest([Segment(0x0010, b"\x01")], None, False)
    assert a.image_sha256 != b.image_sha256


def test_same_bytes_at_different_entry_hash_differently():
    segs = [Segment(0, b"\x01")]
    a = build_image_digest(segs, entry_address=0x100, include_entry=True)
    b = build_image_digest(segs, entry_address=0x200, include_entry=True)
    assert a.image_sha256 != b.image_sha256
    # but the per-segment summary is unchanged
    assert a.segments[0].sha256 == b.segments[0].sha256


# ---------------------------------------------------------------------------
# fragmentation / gap invariance through the real parser
# ---------------------------------------------------------------------------

def _fingerprint(text: str, include_entry: bool = True) -> str:
    parsed = parse_intel_hex(text)
    assert parsed.ok
    return build_image_digest(
        parsed.segments, parsed.entry_address, include_entry=include_entry
    ).image_sha256


def test_record_splitting_does_not_change_fingerprint():
    payload = bytes(range(32))
    one_record = "\n".join([
        linear_base(0x0800),
        data_rec(0x0000, payload),
        linear_entry(0x08000100),
        EOF,
    ])
    many_records = "\n".join([
        linear_base(0x0800),
        data_rec(0x0000, payload[:1]),
        data_rec(0x0001, payload[1:7]),
        data_rec(0x0007, payload[7:32]),
        linear_entry(0x08000100),
        EOF,
    ])
    assert _fingerprint(one_record) == _fingerprint(many_records)
    assert _fingerprint(one_record, include_entry=False) == _fingerprint(
        many_records, include_entry=False
    )


def test_identical_rewrites_and_record_order_do_not_change_fingerprint():
    payload = bytes(range(8))
    clean = "\n".join([data_rec(0x0000, payload), EOF])
    # overlapping identical rewrites, emitted out of record order
    rewritten = "\n".join([
        data_rec(0x0004, payload[4:]),
        data_rec(0x0000, payload[:4]),
        data_rec(0x0002, payload[2:6]),  # identical rewrite of 2..5
        EOF,
    ])
    assert _fingerprint(clean) == _fingerprint(rewritten)


def test_different_gap_representation_yields_same_fingerprint():
    # One image describes 0..1 and 0x1000..0x1001 with absolute 0x0800_0000
    # bases; the second splits the same final bytes differently but keeps
    # the exact same absolute placement. Gaps contribute nothing to the
    # stream, so fingerprints match.
    variant_a = "\n".join([
        linear_base(0x0800),
        data_rec(0x0000, b"\x01\x02"),
        linear_base(0x0801),
        data_rec(0x0000, b"\x03\x04"),
        EOF,
    ])
    variant_b = "\n".join([
        linear_base(0x0800),
        data_rec(0x0000, b"\x01"),
        data_rec(0x0001, b"\x02"),
        linear_base(0x0801),
        data_rec(0x0000, b"\x03"),
        data_rec(0x0001, b"\x04"),
        EOF,
    ])
    assert _fingerprint(variant_a) == _fingerprint(variant_b)


def test_different_content_or_placement_changes_fingerprint():
    base = "\n".join([data_rec(0x0000, b"\x01\x02"), EOF])
    changed_byte = "\n".join([data_rec(0x0000, b"\x01\x03"), EOF])
    moved = "\n".join([data_rec(0x0001, b"\x01\x02"), EOF])
    assert _fingerprint(base) != _fingerprint(changed_byte)
    assert _fingerprint(base) != _fingerprint(moved)


def test_entry_changes_default_hash_but_not_bytes_only_hash():
    without = "\n".join([data_rec(0x0000, b"\x01\x02"), EOF])
    with_entry = "\n".join([
        data_rec(0x0000, b"\x01\x02"),
        linear_entry(0x08000100),
        EOF,
    ])
    assert _fingerprint(without) != _fingerprint(with_entry)
    assert _fingerprint(without, include_entry=False) == _fingerprint(
        with_entry, include_entry=False
    )


# ---------------------------------------------------------------------------
# API surface
# ---------------------------------------------------------------------------

def test_api_digest_happy_path():
    text = "\n".join([
        linear_base(0x0800),
        data_rec(0x0000, b"\x01\x02"),
        data_rec(0x0010, b"\x03"),
        linear_entry(0x080001C1),
        EOF,
    ])
    resp = client.post("/api/v1/image-digest", json={"hex_text": text})
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True
    assert body["error_count"] == 0
    assert body["entry_address"] == 0x080001C1
    assert body["include_entry"] is True
    assert body["total_bytes"] == 3

    parsed = parse_intel_hex(text)
    expected = build_image_digest(parsed.segments, parsed.entry_address, True)
    assert body["image_sha256"] == expected.image_sha256
    assert len(body["segments"]) == 2
    assert body["segments"][0]["start"] == 0x08000000
    assert body["segments"][0]["end"] == 0x08000002
    assert body["segments"][0]["size"] == 2
    assert body["segments"][0]["gap_before"] == 0
    assert body["segments"][1]["start"] == 0x08000010
    assert body["segments"][1]["gap_before"] == 0x0E
    assert body["segments"][0]["sha256"] == expected.segments[0].sha256

    manifest = body["manifest"]
    assert manifest["format"] == "firmware-image-digest/v1"
    assert manifest["hash_algorithm"] == "sha256"
    assert manifest["include_entry"] is True
    assert manifest["segment_count"] == 2
    assert manifest["total_bytes"] == 3
    assert manifest["frame_count"] == 3
    assert [f["kind"] for f in manifest["frames"]] == ["segment", "segment", "entry"]
    assert manifest["frames"][-1]["address"] == 0x080001C1
    assert manifest["canonical_bytes"] == len(expected.canonical_bytes)
    assert len(body["diagnostics"]) == 5


def test_api_include_entry_false():
    text = "\n".join([
        data_rec(0x0000, b"\x01\x02"),
        linear_entry(0x08000100),
        EOF,
    ])
    resp = client.post(
        "/api/v1/image-digest", json={"hex_text": text, "include_entry": False}
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True
    assert body["include_entry"] is False
    assert body["entry_address"] == 0x08000100  # still reported
    kinds = [f["kind"] for f in body["manifest"]["frames"]]
    assert kinds == ["segment"]
    parsed = parse_intel_hex(text)
    assert body["image_sha256"] == build_image_digest(
        parsed.segments, parsed.entry_address, False
    ).image_sha256


def test_api_include_entry_defaults_to_true():
    text = "\n".join([data_rec(0x0000, b"\x01"), EOF])
    body = client.post("/api/v1/image-digest", json={"hex_text": text}).json()
    assert body["include_entry"] is True
    assert body["manifest"]["frames"][-1]["kind"] == "no_entry"


def test_api_fragmented_same_image_same_digest():
    payload = bytes(range(16))
    one = "\n".join([linear_base(0x0800), data_rec(0x0000, payload), EOF])
    two = "\n".join([
        linear_base(0x0800),
        data_rec(0x0000, payload[:3]),
        data_rec(0x0003, payload[3:10]),
        data_rec(0x000A, payload[10:]),
        EOF,
    ])
    a = client.post("/api/v1/image-digest", json={"hex_text": one}).json()
    b = client.post("/api/v1/image-digest", json={"hex_text": two}).json()
    assert a["image_sha256"] == b["image_sha256"]
    assert a["manifest"]["canonical_bytes"] == b["manifest"]["canonical_bytes"]


def test_api_parse_failure_returns_only_diagnostics():
    resp = client.post(
        "/api/v1/image-digest", json={"hex_text": ":00000001FE\n"}
    )  # bad checksum, no EOF
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is False
    assert body["error_count"] >= 1
    assert body["image_sha256"] is None
    assert body["manifest"] is None
    assert body["segments"] == []
    assert body["total_bytes"] == 0
    assert body["entry_address"] is None
    assert len(body["diagnostics"]) == body["error_count"] + body["warning_count"]
