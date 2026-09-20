"""Tests for the Intel HEX parser and the FastAPI surface."""

import base64

import pytest
from fastapi.testclient import TestClient

from app.hex_parser import parse_intel_hex
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


# ---------------------------------------------------------------------------
# happy path
# ---------------------------------------------------------------------------

def test_single_segment_assembled_and_base64_encoded():
    payload = bytes(range(16))
    text = "\n".join([data_rec(0x0000, payload), EOF])
    result = parse_intel_hex(text)
    assert result.ok
    assert result.error_count == 0
    assert len(result.segments) == 1
    seg = result.segments[0]
    assert seg.start == 0
    assert seg.data == payload
    assert result.total_bytes == 16


def test_extended_linear_address_shifts_base_by_16():
    text = "\n".join([
        rec(0x04, 0, b"\x08\x00"),       # base = 0x0800_0000
        data_rec(0x0010, b"\xAA\xBB"),
        EOF,
    ])
    result = parse_intel_hex(text)
    assert result.ok
    assert result.segments[0].start == 0x08000010
    assert result.segments[0].data == b"\xAA\xBB"


def test_extended_segment_address_shifts_base_by_4():
    text = "\n".join([
        rec(0x02, 0, b"\x12\x34"),       # base = 0x1234 << 4 = 0x12340
        data_rec(0x0005, b"\x01"),
        EOF,
    ])
    result = parse_intel_hex(text)
    assert result.ok
    assert result.segments[0].start == 0x12345


def test_base_applies_until_replaced():
    text = "\n".join([
        rec(0x04, 0, b"\x00\x01"),
        data_rec(0x0000, b"\x01"),
        rec(0x04, 0, b"\x00\x02"),
        data_rec(0x0000, b"\x02"),
        EOF,
    ])
    result = parse_intel_hex(text)
    assert result.ok
    assert [s.start for s in result.segments] == [0x10000, 0x20000]


def test_gaps_reported_between_segments():
    text = "\n".join([
        data_rec(0x0000, b"\x01\x02"),
        data_rec(0x0010, b"\x03"),
        EOF,
    ])
    result = parse_intel_hex(text)
    assert result.ok
    assert len(result.segments) == 2
    assert len(result.gaps) == 1
    gap = result.gaps[0]
    assert (gap.start, gap.end, gap.size) == (0x0002, 0x0010, 0x000E)


def test_contiguous_records_merge_into_one_segment():
    text = "\n".join([
        data_rec(0x0000, b"\x01\x02"),
        data_rec(0x0002, b"\x03\x04"),
        EOF,
    ])
    result = parse_intel_hex(text)
    assert result.ok
    assert len(result.segments) == 1
    assert result.segments[0].data == b"\x01\x02\x03\x04"


# ---------------------------------------------------------------------------
# entry address
# ---------------------------------------------------------------------------

def test_start_linear_address_sets_entry():
    text = "\n".join([rec(0x05, 0, b"\x08\x00\x01\xC1"), data_rec(0, b"\x00"), EOF])
    result = parse_intel_hex(text)
    assert result.ok
    assert result.entry_address == 0x080001C1


def test_start_segment_address_sets_entry_cs_ip():
    # CS=0x1000, IP=0x0200 -> 0x1000*16 + 0x0200 = 0x10200
    text = "\n".join([rec(0x03, 0, b"\x10\x00\x02\x00"), data_rec(0, b"\x00"), EOF])
    result = parse_intel_hex(text)
    assert result.ok
    assert result.entry_address == 0x10200


def test_no_entry_record_gives_none():
    result = parse_intel_hex("\n".join([data_rec(0, b"\x00"), EOF]))
    assert result.ok
    assert result.entry_address is None


# ---------------------------------------------------------------------------
# validation
# ---------------------------------------------------------------------------

def test_checksum_mismatch_rejected():
    good = data_rec(0x0000, b"\x11\x22")
    bad = good[:-2] + "00"  # corrupt checksum
    result = parse_intel_hex("\n".join([bad, EOF]))
    assert not result.ok
    assert any("checksum" in d.message and d.line == 1 for d in result.diagnostics)
    assert result.total_bytes == 0  # corrupt record not applied


def test_byte_count_mismatch_rejected():
    # declares 4 bytes but carries 2; checksum recomputed so only count is wrong
    body = bytes([0x04, 0x00, 0x00, 0x00]) + b"\x01\x02"
    bad = ":" + (body + bytes([(-sum(body)) & 0xFF])).hex().upper()
    result = parse_intel_hex("\n".join([bad, EOF]))
    assert not result.ok
    assert any("byte count" in d.message and d.line == 1 for d in result.diagnostics)


def test_missing_start_code_rejected():
    result = parse_intel_hex("\n".join(["1000000021460136", EOF]))
    assert not result.ok
    assert any("start code" in d.message for d in result.diagnostics)


def test_unsupported_record_type_rejected():
    result = parse_intel_hex("\n".join([rec(0x06, 0, b"\x00\x00"), EOF]))
    assert not result.ok
    assert any("unsupported record type" in d.message for d in result.diagnostics)


# ---------------------------------------------------------------------------
# EOF rules
# ---------------------------------------------------------------------------

def test_missing_eof_is_error():
    result = parse_intel_hex(data_rec(0, b"\x01"))
    assert not result.ok
    assert any("missing end-of-file" in d.message for d in result.diagnostics)


def test_record_after_eof_is_error():
    result = parse_intel_hex("\n".join([EOF, data_rec(0, b"\x01")]))
    assert not result.ok
    assert any("after end-of-file" in d.message and d.line == 2 for d in result.diagnostics)


def test_duplicate_eof_is_error():
    result = parse_intel_hex("\n".join([data_rec(0, b"\x01"), EOF, EOF]))
    assert not result.ok
    assert any("after end-of-file" in d.message and d.line == 3 for d in result.diagnostics)


# ---------------------------------------------------------------------------
# overlapping writes
# ---------------------------------------------------------------------------

def test_identical_rewrite_accepted():
    text = "\n".join([
        data_rec(0x0000, b"\xAA\xBB"),
        data_rec(0x0001, b"\xBB"),   # same value at 0x0001
        EOF,
    ])
    result = parse_intel_hex(text)
    assert result.ok
    assert result.segments[0].data == b"\xAA\xBB"
    assert any("identical rewrite" in d.message for d in result.diagnostics)


def test_conflicting_rewrite_reports_line_and_address():
    text = "\n".join([
        data_rec(0x0000, b"\xAA\xBB"),
        data_rec(0x0001, b"\xCC"),   # conflicts at 0x0001
        EOF,
    ])
    result = parse_intel_hex(text)
    assert not result.ok
    conflict = [d for d in result.diagnostics if d.status == "error" and "conflicts" in d.message]
    assert len(conflict) == 1
    assert conflict[0].line == 2
    assert conflict[0].address == 0x0001
    assert "line 1" in conflict[0].message
    # first value wins
    assert result.segments[0].data == b"\xAA\xBB"


# ---------------------------------------------------------------------------
# API surface
# ---------------------------------------------------------------------------

def test_api_assemble_roundtrip():
    payload = bytes(range(32))
    text = "\n".join([
        rec(0x04, 0, b"\x08\x00"),
        data_rec(0x0000, payload[:16]),
        data_rec(0x0010, payload[16:]),
        rec(0x05, 0, b"\x08\x00\x00\x09"),
        EOF,
    ])
    resp = client.post("/api/v1/assemble", json={"hex_text": text})
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True
    assert body["entry_address"] == 0x08000009
    assert body["segment_count"] == 1
    seg = body["segments"][0]
    assert seg["start"] == 0x08000000
    assert base64.b64decode(seg["data_base64"]) == payload
    assert body["gaps"] == []
    assert len(body["diagnostics"]) == 5


def test_api_raw_text_endpoint():
    text = "\n".join([data_rec(0, b"\x01\x02"), EOF])
    resp = client.post(
        "/api/v1/assemble/raw",
        content=text,
        headers={"Content-Type": "text/plain"},
    )
    assert resp.status_code == 200
    assert resp.json()["ok"] is True


def test_api_reports_errors_with_200_and_ok_false():
    resp = client.post("/api/v1/assemble", json={"hex_text": ":00000001FE\n"})  # bad checksum
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is False
    assert body["error_count"] >= 1


def test_health():
    assert client.get("/health").json() == {"status": "ok"}
