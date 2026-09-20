"""Tests for the Intel HEX normalization/export module and /api/v1/export-hex."""

from fastapi.testclient import TestClient

from app.hex_export import export_intel_hex
from app.hex_parser import Segment, parse_intel_hex
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


def segment_base(value: int) -> str:
    return rec(0x02, 0, value.to_bytes(2, "big"))


def linear_entry(value: int) -> str:
    return rec(0x05, 0, value.to_bytes(4, "big"))


def segment_entry(cs: int, ip: int) -> str:
    return rec(0x03, 0, cs.to_bytes(2, "big") + ip.to_bytes(2, "big"))


# ---------------------------------------------------------------------------
# pure export logic
# ---------------------------------------------------------------------------

def test_single_record_round_trips_byte_for_byte():
    payload = bytes(range(16))
    line = data_rec(0x0000, payload)
    exported = export_intel_hex([Segment(0x0000, payload)], None)
    assert exported.hex_text == line + "\n" + EOF + "\n"
    assert exported.record_count == 2
    assert exported.data_record_count == 1
    assert exported.extended_address_record_count == 0
    assert exported.entry_record_count == 0


def test_data_records_are_capped_by_max_data_bytes():
    payload = bytes(range(32))
    exported = export_intel_hex([Segment(0x0000, payload)], None, max_data_bytes=16)
    lines = exported.hex_text.splitlines()
    assert lines == [
        data_rec(0x0000, payload[:16]),
        data_rec(0x0010, payload[16:]),
        EOF,
    ]
    assert exported.data_record_count == 2


def test_max_data_bytes_one_emits_one_byte_per_record():
    exported = export_intel_hex([Segment(0x0000, b"\xAA\xBB\xCC")], None, max_data_bytes=1)
    assert exported.hex_text.splitlines() == [
        data_rec(0x0000, b"\xAA"),
        data_rec(0x0001, b"\xBB"),
        data_rec(0x0002, b"\xCC"),
        EOF,
    ]


def test_window_zero_needs_no_extended_address_record():
    exported = export_intel_hex([Segment(0x0010, b"\x01\x02")], None)
    assert exported.extended_address_record_count == 0
    assert exported.hex_text.splitlines()[0] == data_rec(0x0010, b"\x01\x02")


def test_extended_address_record_emitted_for_high_window():
    exported = export_intel_hex([Segment(0x08000000, b"\x01\x02")], None)
    assert exported.hex_text.splitlines() == [
        linear_base(0x0800),
        data_rec(0x0000, b"\x01\x02"),
        EOF,
    ]
    assert exported.extended_address_record_count == 1


def test_data_record_never_crosses_64kib_window():
    payload = bytes(range(32))
    exported = export_intel_hex([Segment(0xFFF0, payload)], None, max_data_bytes=255)
    lines = exported.hex_text.splitlines()
    assert lines == [
        data_rec(0xFFF0, payload[:16]),   # stops exactly at the window end
        linear_base(0x0001),              # window switch
        data_rec(0x0000, payload[16:]),
        EOF,
    ]
    assert exported.extended_address_record_count == 1


def test_window_switch_splits_even_when_max_data_bytes_is_smaller():
    payload = bytes(range(20))
    exported = export_intel_hex([Segment(0xFFFC, payload)], None, max_data_bytes=8)
    lines = exported.hex_text.splitlines()
    assert lines == [
        data_rec(0xFFFC, payload[:4]),    # only 4 bytes left in window 0
        linear_base(0x0001),
        data_rec(0x0000, payload[4:12]),
        data_rec(0x0008, payload[12:]),
        EOF,
    ]


def test_window_record_not_repeated_within_same_window():
    segments = [Segment(0x08000000, b"\x01"), Segment(0x08000010, b"\x02")]
    exported = export_intel_hex(segments, None)
    assert exported.hex_text.splitlines() == [
        linear_base(0x0800),
        data_rec(0x0000, b"\x01"),
        data_rec(0x0010, b"\x02"),
        EOF,
    ]
    assert exported.extended_address_record_count == 1


def test_segments_are_sorted_before_export():
    segments = [Segment(0x0010, b"\x02"), Segment(0x0000, b"\x01")]
    exported = export_intel_hex(segments, None)
    assert exported.hex_text.splitlines() == [
        data_rec(0x0000, b"\x01"),
        data_rec(0x0010, b"\x02"),
        EOF,
    ]


def test_entry_preserved_as_start_linear_address_record():
    exported = export_intel_hex([Segment(0, b"\x01")], 0x080001C1)
    lines = exported.hex_text.splitlines()
    assert lines == [data_rec(0x0000, b"\x01"), linear_entry(0x080001C1), EOF]
    assert exported.entry_record_count == 1
    assert exported.record_count == 3


def test_include_entry_false_drops_entry_record():
    exported = export_intel_hex([Segment(0, b"\x01")], 0x080001C1, include_entry=False)
    assert exported.hex_text.splitlines() == [data_rec(0x0000, b"\x01"), EOF]
    assert exported.entry_record_count == 0
    assert exported.entry_address == 0x080001C1  # still reported


def test_empty_image_exports_only_eof():
    exported = export_intel_hex([], None)
    assert exported.hex_text == EOF + "\n"
    assert exported.record_count == 1
    assert exported.data_record_count == 0


def test_empty_image_with_entry_exports_entry_and_eof():
    exported = export_intel_hex([], 0x08000000)
    assert exported.hex_text.splitlines() == [linear_entry(0x08000000), EOF]


def test_invalid_max_data_bytes_rejected():
    for bad in (0, 256):
        try:
            export_intel_hex([], None, max_data_bytes=bad)
        except ValueError:
            pass
        else:  # pragma: no cover - must not happen
            raise AssertionError("expected ValueError")


# ---------------------------------------------------------------------------
# normalization through the real parser
# ---------------------------------------------------------------------------

def _export(text: str, max_data_bytes: int = 16, include_entry: bool = True):
    parsed = parse_intel_hex(text)
    assert parsed.ok
    return export_intel_hex(
        parsed.segments,
        parsed.entry_address,
        max_data_bytes=max_data_bytes,
        include_entry=include_entry,
    )


def test_export_reparses_to_the_same_image():
    text = "\n".join([
        linear_base(0x0800),
        data_rec(0x0000, bytes(range(16))),
        data_rec(0x1000, b"\xAA\xBB"),
        linear_entry(0x080001C1),
        EOF,
    ])
    exported = _export(text)
    reparsed = parse_intel_hex(exported.hex_text)
    original = parse_intel_hex(text)
    assert reparsed.ok
    assert reparsed.error_count == 0
    assert [(s.start, s.data) for s in reparsed.segments] == [
        (s.start, s.data) for s in original.segments
    ]
    assert reparsed.entry_address == original.entry_address


def test_export_is_a_fixed_point():
    text = "\n".join([
        linear_base(0x0800),
        data_rec(0x0000, bytes(range(40))),
        linear_entry(0x080001C1),
        EOF,
    ])
    once = _export(text, max_data_bytes=16)
    twice = _export(once.hex_text, max_data_bytes=16)
    assert twice.hex_text == once.hex_text


def test_record_splitting_and_base_style_do_not_change_export():
    payload = bytes(range(24))
    variant_a = "\n".join([
        linear_base(0x0008),  # base = 0x0008_0000
        data_rec(0x0000, payload),
        EOF,
    ])
    # same image: split records, written out of order, 02-style segment base
    variant_b = "\n".join([
        segment_base(0x8000),  # base = 0x8000 << 4 = 0x0008_0000
        data_rec(0x0008, payload[8:]),
        data_rec(0x0000, payload[:8]),
        EOF,
    ])
    assert _export(variant_a).hex_text == _export(variant_b).hex_text


def test_segment_entry_normalized_to_linear_entry_record():
    text = "\n".join([
        data_rec(0x0000, b"\x01"),
        segment_entry(0x0800, 0x01C1),  # entry = 0x0800 << 4 + 0x01C1 = 0x000081C1
        EOF,
    ])
    exported = _export(text)
    assert exported.entry_address == 0x000081C1
    assert exported.hex_text.splitlines() == [
        data_rec(0x0000, b"\x01"),
        linear_entry(0x000081C1),
        EOF,
    ]


def test_checksums_are_recomputed_for_every_record():
    # Input carries a correct checksum; corrupting any exported byte must be
    # detectable, i.e. every exported line sums to 0 mod 256.
    exported = _export("\n".join([
        linear_base(0x1234),
        data_rec(0x00F0, bytes(range(32))),
        linear_entry(0x12340001),
        EOF,
    ]))
    for line in exported.hex_text.splitlines():
        assert sum(bytes.fromhex(line[1:])) & 0xFF == 0


# ---------------------------------------------------------------------------
# API surface
# ---------------------------------------------------------------------------

def test_api_export_happy_path():
    text = "\n".join([
        linear_base(0x0800),
        data_rec(0x0000, bytes(range(16))),
        linear_entry(0x080001C1),
        EOF,
    ])
    resp = client.post("/api/v1/export-hex", json={"hex_text": text})
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True
    assert body["error_count"] == 0
    assert body["entry_address"] == 0x080001C1
    assert body["total_bytes"] == 16
    assert body["max_data_bytes"] == 16
    assert body["include_entry"] is True
    # the canonical example is already normalized: export reproduces it exactly
    assert body["exported_hex"] == text + "\n"
    assert body["record_count"] == 4
    assert body["data_record_count"] == 1
    assert body["extended_address_record_count"] == 1
    assert body["entry_record_count"] == 1
    assert len(body["diagnostics"]) == 4


def test_api_export_chunking_and_window_switch():
    payload = bytes(range(32))
    text = "\n".join([data_rec(0xFFF0, payload), EOF])
    body = client.post(
        "/api/v1/export-hex",
        json={"hex_text": text, "max_data_bytes": 255, "include_entry": False},
    ).json()
    assert body["ok"] is True
    assert body["exported_hex"].splitlines() == [
        data_rec(0xFFF0, payload[:16]),
        linear_base(0x0001),
        data_rec(0x0000, payload[16:]),
        EOF,
    ]
    assert body["record_count"] == 4
    assert body["extended_address_record_count"] == 1
    assert body["entry_record_count"] == 0


def test_api_export_include_entry_false():
    text = "\n".join([
        data_rec(0x0000, b"\x01\x02"),
        linear_entry(0x08000100),
        EOF,
    ])
    body = client.post(
        "/api/v1/export-hex", json={"hex_text": text, "include_entry": False}
    ).json()
    assert body["ok"] is True
    assert body["include_entry"] is False
    assert body["entry_address"] == 0x08000100  # still reported
    assert body["entry_record_count"] == 0
    assert body["exported_hex"].splitlines() == [data_rec(0x0000, b"\x01\x02"), EOF]


def test_api_export_deterministic_across_representations():
    payload = bytes(range(16))
    one = "\n".join([linear_base(0x0800), data_rec(0x0000, payload), EOF])
    two = "\n".join([
        linear_base(0x0800),
        data_rec(0x0000, payload[:3]),
        data_rec(0x0003, payload[3:10]),
        data_rec(0x000A, payload[10:]),
        EOF,
    ])
    a = client.post("/api/v1/export-hex", json={"hex_text": one}).json()
    b = client.post("/api/v1/export-hex", json={"hex_text": two}).json()
    assert a["exported_hex"] == b["exported_hex"]
    assert a["record_count"] == b["record_count"]


def test_api_parse_failure_returns_only_diagnostics():
    resp = client.post(
        "/api/v1/export-hex", json={"hex_text": ":00000001FE\n"}
    )  # bad checksum, no EOF
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is False
    assert body["error_count"] >= 1
    assert body["exported_hex"] is None
    assert body["record_count"] == 0
    assert body["data_record_count"] == 0
    assert body["extended_address_record_count"] == 0
    assert body["entry_record_count"] == 0
    assert body["total_bytes"] == 0
    assert body["entry_address"] is None
    assert len(body["diagnostics"]) == body["error_count"] + body["warning_count"]


def test_api_max_data_bytes_validation():
    text = "\n".join([data_rec(0x0000, b"\x01"), EOF])
    for bad in (0, 256, -1):
        resp = client.post(
            "/api/v1/export-hex", json={"hex_text": text, "max_data_bytes": bad}
        )
        assert resp.status_code == 422
