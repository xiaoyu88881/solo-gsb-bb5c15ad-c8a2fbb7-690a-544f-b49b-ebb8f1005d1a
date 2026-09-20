"""Tests for the /api/v1/validate-layout endpoint and layout logic."""

import pytest
from fastapi.testclient import TestClient

from app.hex_parser import parse_intel_hex
from app.layout import Region, validate_layout
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


def entry_rec(addr: int) -> str:
    return rec(0x05, 0, addr.to_bytes(4, "big"))


def region(name, start, end, allow_data=True, allow_entry=False):
    return {
        "name": name,
        "start": start,
        "end": end,
        "allow_data": allow_data,
        "allow_entry": allow_entry,
    }


# ---------------------------------------------------------------------------
# pure layout logic
# ---------------------------------------------------------------------------

def test_segment_split_at_region_boundary_counts_occupancy():
    # 16 bytes at 0x08..0x18, split evenly between A [0x00,0x10) and B [0x10,0x20)
    result = parse_intel_hex("\n".join([data_rec(0x0008, bytes(range(16))), EOF]))
    assert result.ok
    layout = validate_layout(
        result.segments,
        result.entry_address,
        [
            Region("A", 0x00, 0x10),
            Region("B", 0x10, 0x20),
        ],
    )
    assert layout.ok
    assert layout.regions_valid
    by_name = {rep.region.name: rep for rep in layout.reports}
    assert by_name["A"].occupied_bytes == 8
    assert by_name["B"].occupied_bytes == 8
    assert by_name["A"].utilization == 0.5
    assert by_name["B"].utilization == 0.5
    assert layout.violations == []


def test_uncovered_bytes_reported_as_ranges():
    # bytes at 0x00..0x04 and 0x10..0x14, region covers only 0x00..0x04
    result = parse_intel_hex(
        "\n".join([data_rec(0x0000, b"\x01" * 4), data_rec(0x0010, b"\x02" * 4), EOF])
    )
    layout = validate_layout(result.segments, None, [Region("flash", 0x00, 0x08)])
    assert not layout.ok
    uncovered = [v for v in layout.violations if v.kind == "uncovered_data"]
    assert len(uncovered) == 1
    assert (uncovered[0].start, uncovered[0].end) == (0x10, 0x14)
    assert uncovered[0].region is None


def test_gap_between_regions_reported_once():
    # segment 0x00..0x20, regions [0x00,0x08) and [0x18,0x20): hole 0x08..0x18
    result = parse_intel_hex("\n".join([data_rec(0x0000, bytes(32)), EOF]))
    layout = validate_layout(
        result.segments,
        None,
        [Region("lo", 0x00, 0x08), Region("hi", 0x18, 0x20)],
    )
    uncovered = [v for v in layout.violations if v.kind == "uncovered_data"]
    assert [(v.start, v.end) for v in uncovered] == [(0x08, 0x18)]


def test_data_in_no_data_region_is_violation():
    result = parse_intel_hex("\n".join([data_rec(0x0000, b"\xAA" * 4), EOF]))
    layout = validate_layout(
        result.segments, None, [Region("boot", 0x00, 0x10, allow_data=False)]
    )
    assert not layout.ok
    v = layout.violations[0]
    assert v.kind == "data_not_allowed"
    assert (v.start, v.end, v.region) == (0x00, 0x04, "boot")
    # violation is also attached to the region report
    assert layout.reports[0].violations == [v]
    assert layout.reports[0].occupied_bytes == 4


def test_entry_must_land_in_allow_entry_region():
    text = "\n".join([entry_rec(0x0004), data_rec(0x0000, b"\x00" * 8), EOF])
    result = parse_intel_hex(text)
    assert result.entry_address == 0x0004

    ok_layout = validate_layout(
        result.segments, result.entry_address, [Region("flash", 0x00, 0x10, allow_entry=True)]
    )
    assert ok_layout.ok

    bad_layout = validate_layout(
        result.segments, result.entry_address, [Region("flash", 0x00, 0x10)]
    )
    assert not bad_layout.ok
    assert bad_layout.violations[0].kind == "entry_not_allowed"
    assert bad_layout.violations[0].region == "flash"


def test_entry_outside_all_regions_is_violation():
    text = "\n".join([entry_rec(0x9000), data_rec(0x0000, b"\x00"), EOF])
    result = parse_intel_hex(text)
    layout = validate_layout(
        result.segments, result.entry_address, [Region("flash", 0x00, 0x10, allow_entry=True)]
    )
    assert [v.kind for v in layout.violations] == ["entry_uncovered"]


def test_overlapping_regions_rejected_before_placement_check():
    result = parse_intel_hex("\n".join([data_rec(0x0000, b"\x01" * 4), EOF]))
    layout = validate_layout(
        result.segments,
        None,
        [Region("a", 0x00, 0x10), Region("b", 0x08, 0x20)],
    )
    assert not layout.ok
    assert not layout.regions_valid
    assert [v.kind for v in layout.violations] == ["region_overlap"]
    # placement check skipped: no occupancy accounted
    assert all(rep.occupied_bytes == 0 for rep in layout.reports)


def test_touching_regions_do_not_overlap():
    result = parse_intel_hex("\n".join([data_rec(0x0000, b"\x01" * 8), EOF]))
    layout = validate_layout(
        result.segments,
        None,
        [Region("a", 0x00, 0x04), Region("b", 0x04, 0x08)],
    )
    assert layout.ok


def test_empty_region_interval_rejected():
    result = parse_intel_hex("\n".join([data_rec(0x0000, b"\x01"), EOF]))
    layout = validate_layout(result.segments, None, [Region("bad", 0x10, 0x10)])
    assert not layout.ok
    assert not layout.regions_valid
    assert layout.violations[0].kind == "invalid_region"
    assert layout.violations[0].region == "bad"


# ---------------------------------------------------------------------------
# API surface
# ---------------------------------------------------------------------------

def test_api_validate_layout_happy_path():
    text = "\n".join([
        rec(0x04, 0, b"\x08\x00"),                    # base 0x0800_0000
        data_rec(0x0000, bytes(range(16))),
        entry_rec(0x08000001),
        EOF,
    ])
    resp = client.post(
        "/api/v1/validate-layout",
        json={
            "hex_text": text,
            "regions": [
                region("flash", 0x08000000, 0x08040000, allow_entry=True),
                region("config", 0x08040000, 0x08041000),
            ],
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True
    assert body["hex_ok"] is True
    assert body["regions_valid"] is True
    assert body["entry_address"] == 0x08000001
    assert body["total_bytes"] == 16
    assert body["violations"] == []
    flash, config = body["regions"]
    assert flash["occupied_bytes"] == 16
    assert flash["utilization"] == pytest.approx(16 / 0x40000)
    assert config["occupied_bytes"] == 0
    assert config["utilization"] == 0.0
    assert len(body["diagnostics"]) == 4


def test_api_invalid_hex_returns_only_diagnostics():
    resp = client.post(
        "/api/v1/validate-layout",
        json={
            "hex_text": ":00000001FE\n",  # bad checksum
            "regions": [region("flash", 0x00, 0x10, allow_entry=True)],
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is False
    assert body["hex_ok"] is False
    assert body["regions_valid"] is None
    assert body["regions"] == []
    assert body["violations"] == []
    assert body["error_count"] >= 1
    assert any("checksum" in d["message"] for d in body["diagnostics"])


def test_api_reports_uncovered_and_no_data_violations():
    text = "\n".join([
        data_rec(0x0000, b"\x01" * 8),   # inside no-data region
        data_rec(0x0100, b"\x02" * 4),   # outside every region
        EOF,
    ])
    resp = client.post(
        "/api/v1/validate-layout",
        json={
            "hex_text": text,
            "regions": [region("reserved", 0x00, 0x10, allow_data=False)],
        },
    )
    body = resp.json()
    assert body["ok"] is False
    assert body["hex_ok"] is True
    kinds = sorted(v["kind"] for v in body["violations"])
    assert kinds == ["data_not_allowed", "uncovered_data"]
    uncovered = next(v for v in body["violations"] if v["kind"] == "uncovered_data")
    assert (uncovered["start"], uncovered["end"]) == (0x100, 0x104)
    reserved = body["regions"][0]
    assert reserved["occupied_bytes"] == 8
    assert [v["kind"] for v in reserved["violations"]] == ["data_not_allowed"]


def test_api_overlapping_regions_flagged():
    resp = client.post(
        "/api/v1/validate-layout",
        json={
            "hex_text": "\n".join([data_rec(0, b"\x01"), EOF]),
            "regions": [region("a", 0x00, 0x10), region("b", 0x08, 0x20)],
        },
    )
    body = resp.json()
    assert body["ok"] is False
    assert body["regions_valid"] is False
    assert [v["kind"] for v in body["violations"]] == ["region_overlap"]


def test_api_entry_violation_reported():
    text = "\n".join([entry_rec(0x0000), data_rec(0x0000, b"\x00" * 4), EOF])
    resp = client.post(
        "/api/v1/validate-layout",
        json={
            "hex_text": text,
            "regions": [region("flash", 0x00, 0x10)],  # allow_entry defaults to false
        },
    )
    body = resp.json()
    assert body["ok"] is False
    assert [v["kind"] for v in body["violations"]] == ["entry_not_allowed"]
    assert body["regions"][0]["violations"][0]["kind"] == "entry_not_allowed"


def test_api_region_field_validation():
    resp = client.post(
        "/api/v1/validate-layout",
        json={
            "hex_text": "\n".join([data_rec(0, b"\x01"), EOF]),
            "regions": [{"name": "", "start": 0, "end": 16}],
        },
    )
    assert resp.status_code == 422
