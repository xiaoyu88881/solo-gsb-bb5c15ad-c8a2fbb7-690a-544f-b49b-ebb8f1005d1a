"""Tests for the /api/v1/plan-relocation endpoint and relocation logic."""

import pytest
from fastapi.testclient import TestClient

from app.hex_parser import parse_intel_hex
from app.layout import Region
from app.main import app
from app.relocation import plan_relocation

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


def parse(text):
    result = parse_intel_hex(text)
    assert result.ok
    return result


# ---------------------------------------------------------------------------
# pure relocation logic
# ---------------------------------------------------------------------------

def test_delta_zero_when_image_already_placed():
    result = parse("\n".join([data_rec(0x0000, b"\x01" * 8), EOF]))
    plan = plan_relocation(result.segments, None, [Region("flash", 0x00, 0x10)])
    assert plan.regions_valid
    assert plan.feasible
    assert plan.delta == 0
    assert plan.abs_shift == 0
    assert plan.feasible_ranges == [(0, 8)]
    assert [(s.start, s.end) for s in plan.segments] == [(0, 8)]
    assert plan.entry_address is None


def test_minimal_shift_upward_chosen():
    # segment at 0x00..0x08, region 0x10..0x20 -> only positive deltas
    result = parse("\n".join([data_rec(0x0000, b"\x01" * 8), EOF]))
    plan = plan_relocation(result.segments, None, [Region("flash", 0x10, 0x20)])
    assert plan.feasible
    assert plan.delta == 0x10
    assert plan.abs_shift == 0x10
    assert plan.feasible_ranges == [(0x10, 0x18)]
    assert [(s.start, s.end) for s in plan.segments] == [(0x10, 0x18)]


def test_minimal_shift_downward_chosen():
    result = parse("\n".join([data_rec(0x1000, b"\x01" * 8), EOF]))
    plan = plan_relocation(result.segments, None, [Region("flash", 0x10, 0x20)])
    assert plan.feasible
    # region deltas [-0xFF0, -0xFE8]; 32-bit bound (>= -0x1000) is looser
    assert plan.feasible_ranges == [(-0xFF0, -0xFE8)]
    assert plan.delta == 0x18 - 0x1000  # segment end aligns to region end
    assert plan.abs_shift == 0xFE8
    assert plan.segments[0].start == 0x18


def test_equal_distance_tie_prefers_negative_delta():
    # segment 0x10..0x18; two regions equidistant from its placement,
    # at [0x00,0x10) (needs delta -16..-8) and [0x20,0x28) (delta +16);
    # the nearest deltas -8 and +16 differ in |delta|, so -8 wins.
    result = parse("\n".join([data_rec(0x0010, b"\x01" * 8), EOF]))
    plan = plan_relocation(
        result.segments,
        None,
        [Region("lo", 0x00, 0x10), Region("hi", 0x20, 0x28)],
    )
    assert plan.feasible
    assert plan.delta == -8
    assert plan.feasible_ranges == [(-16, -8), (16, 16)]


def test_exactly_equidistant_tie_prefers_negative_delta():
    # segment 0x10..0x14 has two singleton choices delta = +/-4, both
    # inside the 32-bit space; the negative one must win
    result = parse("\n".join([data_rec(0x0010, b"\x01" * 4), EOF]))
    plan = plan_relocation(
        result.segments,
        None,
        [Region("neg", 0x0C, 0x10), Region("pos", 0x14, 0x18)],
    )
    assert plan.feasible
    assert plan.feasible_ranges == [(-4, -4), (4, 4)]
    assert plan.delta == -4
    assert plan.segments[0].start == 0x0C


def test_segment_must_fit_whole_inside_region():
    # segment 0x00..0x08; two adjacent regions each 4 bytes -> no placement
    result = parse("\n".join([data_rec(0x0000, b"\x01" * 8), EOF]))
    plan = plan_relocation(
        result.segments,
        None,
        [Region("a", 0x00, 0x04), Region("b", 0x04, 0x08)],
    )
    assert plan.regions_valid
    assert not plan.feasible
    assert plan.delta is None
    assert plan.feasible_ranges == []
    assert plan.segments == []


def test_adjacent_region_intervals_merge_for_single_byte_segment():
    # 1-byte segment at 0x10; adjacent regions [0,1) and [1,2):
    # deltas {-16} and {-15} are consecutive integers -> one merged range
    result = parse("\n".join([data_rec(0x0010, b"\x01"), EOF]))
    plan = plan_relocation(
        result.segments,
        None,
        [Region("a", 0x00, 0x01), Region("b", 0x01, 0x02)],
    )
    assert plan.feasible
    assert plan.feasible_ranges == [(-16, -15)]
    assert plan.delta == -15  # |-15| < |-16|


def test_adjacent_regions_do_not_help_when_segment_straddles():
    # 8-byte segment; adjacent 8-byte regions: only exact fits at
    # delta 0 and delta 8 remain, as disjoint singleton ranges
    result = parse("\n".join([data_rec(0x0000, b"\x01" * 8), EOF]))
    plan = plan_relocation(
        result.segments,
        None,
        [Region("a", 0x00, 0x08), Region("b", 0x08, 0x10)],
    )
    assert plan.feasible
    assert plan.delta == 0
    assert plan.feasible_ranges == [(0, 0), (8, 8)]


def test_disjoint_region_intervals_stay_disjoint_and_pick_nearest():
    # segment 0x10..0x14; regions [0x00,0x08) -> delta [-0x10,-0xC],
    # [0x20,0x28) -> delta [0x10,0x14]; nearest to 0 is -12
    result = parse("\n".join([data_rec(0x0010, b"\x01" * 4), EOF]))
    plan = plan_relocation(
        result.segments,
        None,
        [Region("lo", 0x00, 0x08), Region("hi", 0x20, 0x28)],
    )
    assert plan.feasible
    assert plan.delta == -12
    assert plan.feasible_ranges == [(-16, -12), (16, 20)]

def test_allow_data_false_region_ignored():
    result = parse("\n".join([data_rec(0x0000, b"\x01" * 4), EOF]))
    plan = plan_relocation(
        result.segments,
        None,
        [Region("ro", 0x00, 0x10, allow_data=False), Region("ram", 0x100, 0x110)],
    )
    assert plan.feasible
    assert plan.delta == 0x100


def test_entry_constraint_intersected_with_data():
    # 1 data byte at 0x0F and entry at 0x1F, with adjacent non-overlapping
    # regions: data-only [0x10,0x20), entry-only [0x20,0x30).
    # data deltas [1,16]; entry deltas [1,16]; intersection [1,16],
    # so the smallest shift delta=1 moves the byte to 0x10, entry to 0x20.
    text = "\n".join([data_rec(0x000F, b"\x01"), entry_rec(0x001F), EOF])
    result = parse(text)
    plan = plan_relocation(
        result.segments,
        result.entry_address,
        [
            Region("flash", 0x10, 0x20, allow_data=True, allow_entry=False),
            Region("vector", 0x20, 0x30, allow_data=False, allow_entry=True),
        ],
    )
    assert plan.feasible
    assert plan.feasible_ranges == [(1, 16)]
    assert plan.delta == 1
    assert plan.entry_address == 0x20
    assert [(s.start, s.end) for s in plan.segments] == [(0x10, 0x11)]


def test_entry_must_land_in_allow_entry_region():
    text = "\n".join([data_rec(0x0000, b"\x01" * 4), entry_rec(0x0000), EOF])
    result = parse(text)
    plan = plan_relocation(
        result.segments,
        result.entry_address,
        [Region("flash", 0x00, 0x20)],  # allow_entry defaults false
    )
    assert not plan.feasible


def test_entry_half_open_boundary():
    # entry point may occupy region end - 1 but not region end
    text = "\n".join([data_rec(0x0000, b"\x01"), entry_rec(0x0000), EOF])
    result = parse(text)
    plan = plan_relocation(
        result.segments,
        result.entry_address,
        [Region("r", 0x00, 0x10, allow_data=True, allow_entry=True)],
    )
    # segment delta [-0, 0x0F]; entry delta [0, 0x0F] -> [0, 0x0F]
    assert plan.feasible_ranges == [(0, 0x0F)]


def test_max_abs_shift_clips_feasible_ranges():
    result = parse("\n".join([data_rec(0x0000, b"\x01" * 4), EOF]))
    plan = plan_relocation(
        result.segments, None, [Region("flash", 0x00, 0x100)], max_abs_shift=2
    )
    assert plan.feasible
    assert plan.feasible_ranges == [(0, 2)]
    assert plan.delta == 0


def test_max_abs_shift_excludes_zero():
    # image at 0x00; only target region at 0x100..0x110 -> min shift 0x100
    result = parse("\n".join([data_rec(0x0000, b"\x01" * 4), EOF]))
    plan = plan_relocation(
        result.segments, None, [Region("flash", 0x100, 0x110)], max_abs_shift=0x10
    )
    assert not plan.feasible
    assert plan.delta is None


def test_max_abs_shift_boundary_value_is_inclusive():
    result = parse("\n".join([data_rec(0x0000, b"\x01"), EOF]))
    # region 0x08..0x10 -> deltas [0x08, 0x0F]; cap exactly at 0x08
    plan = plan_relocation(
        result.segments, None, [Region("flash", 0x08, 0x10)], max_abs_shift=8
    )
    assert plan.feasible
    assert plan.delta == 8
    assert plan.feasible_ranges == [(8, 8)]


def test_32bit_lower_bound_prevents_negative_addresses():
    # segment at 0x02..0x03; region [0x00,0x10) allows delta [-2, 13];
    # delta 0 is feasible and chosen; the lower bound -2 reaches address 0
    result = parse("\n".join([data_rec(0x0002, b"\x01"), EOF]))
    plan = plan_relocation(result.segments, None, [Region("flash", 0x00, 0x10)])
    assert plan.delta == 0
    assert plan.segments[0].start == 0x02
    assert plan.feasible_ranges == [(-2, 13)]
    # force the lower edge: a 2-byte region leaves only [-2,-1], so -1 wins
    result2 = parse("\n".join([data_rec(0x0002, b"\x01"), EOF]))
    plan = plan_relocation(result2.segments, None, [Region("flash", 0x00, 0x02)])
    assert plan.feasible_ranges == [(-2, -1)]
    assert plan.delta == -1
    assert plan.segments[0].start == 1


def test_32bit_upper_bound_prevents_overflow():
    # segment right at the 32-bit ceiling: 0xFFFFFFF8..0x100000000 (8 bytes)
    result = parse(
        "\n".join(
            [
                rec(0x04, 0, b"\xFF\xFF"),
                data_rec(0xFFF8, b"\x01" * 8),
                EOF,
            ]
        )
    )
    assert result.segments[0].end == 0x100000000
    # broad region would allow positive shifts, but the address space caps at 0
    plan = plan_relocation(
        result.segments,
        None,
        [Region("flash", 0xFFFFFFF0, 0x100001000)],
    )
    assert plan.feasible
    assert plan.feasible_ranges == [(-8, 0)]
    assert plan.delta == 0
    assert plan.segments[0].end == 0x100000000
    assert all(0 <= s.start and s.end <= 0x100000000 for s in plan.segments)
    # make positive deltas the only geometrically valid ones: region starts
    # above the segment; then the 32-bit cap removes them all
    plan = plan_relocation(
        result.segments,
        None,
        [Region("flash", 0xFFFFFFFE, 0x100001000)],
    )
    assert not plan.feasible


def test_32bit_overflow_makes_relocation_infeasible():
    # 3-byte segment ending at 0x100000002. Geometrically a region starting
    # at 0xFFFFFFFF would host it (delta -1..); but the 32-bit ceiling only
    # permits delta <= -2, so no placement remains.
    result = parse(
        "\n".join([rec(0x04, 0, b"\xFF\xFF"), data_rec(0xFFFF, b"\x01" * 3), EOF])
    )
    assert result.segments[0].start == 0xFFFFFFFF
    assert result.segments[0].end == 0x100000002
    plan = plan_relocation(
        result.segments, None, [Region("flash", 0xFFFFFFFF, 0x100001000)]
    )
    assert not plan.feasible
    # a lower region start (-2) is still geometrically reachable...
    plan2 = plan_relocation(
        result.segments, None, [Region("flash", 0xFFFFFFFD, 0x100001000)]
    )
    assert plan2.feasible
    assert plan2.delta == -2
    assert plan2.segments[0].end == 0x100000000


def test_entry_32bit_boundary():
    # byte and entry both at 0x08 in region [0,0x10): feasible deltas
    # are [-8, 7]; delta 0 is feasible and chosen.
    text = "\n".join([data_rec(0x0008, b"\x01"), entry_rec(0x0008), EOF])
    result = parse(text)
    plan = plan_relocation(
        result.segments,
        result.entry_address,
        [Region("r", 0x00, 0x10, allow_data=True, allow_entry=True)],
    )
    assert plan.delta == 0
    assert plan.entry_address == 0x08
    assert plan.feasible_ranges == [(-8, 7)]

    # move the image into a region that only accepts it below its origin:
    # byte/entry at 0x10 shifted into [0x08,0x10) permits [-8,-1]; -8 is
    # the 32-bit-neutral smallest |delta| and lands the entry at 0x08
    result2 = parse("\n".join([data_rec(0x0010, b"\x01"), entry_rec(0x0010), EOF]))
    plan2 = plan_relocation(
        result2.segments,
        result2.entry_address,
        [Region("r", 0x08, 0x10, allow_data=True, allow_entry=True)],
    )
    assert plan2.feasible_ranges == [(-8, -1)]
    assert plan2.delta == -1
    assert plan2.entry_address == 0x0F
    assert plan2.segments[0].start == 0x0F


def test_multiple_segments_share_one_delta_and_keep_distance():
    result = parse(
        "\n".join(
            [
                data_rec(0x0000, b"\x01" * 4),
                data_rec(0x0100, b"\x02" * 4),
                EOF,
            ]
        )
    )
    plan = plan_relocation(
        result.segments,
        None,
        [
            Region("a", 0x1000, 0x1004),
            Region("b", 0x1100, 0x1104),
        ],
    )
    assert plan.feasible
    assert plan.delta == 0x1000
    assert [(s.start, s.end) for s in plan.segments] == [
        (0x1000, 0x1004),
        (0x1100, 0x1104),
    ]
    # inter-segment distance preserved
    assert plan.segments[1].start - plan.segments[0].start == 0x100


def test_multiple_segments_conflicting_needs_are_infeasible():
    # first segment can only move to [0x1000..], second only to [0x00..]
    result = parse(
        "\n".join(
            [
                data_rec(0x0000, b"\x01" * 4),
                data_rec(0x0100, b"\x02" * 4),
                EOF,
            ]
        )
    )
    plan = plan_relocation(
        result.segments,
        None,
        [
            Region("a", 0x1000, 0x1010),
            Region("b", 0x0000, 0x0010),
        ],
    )
    assert not plan.feasible


def test_invalid_region_definitions_block_planning():
    result = parse("\n".join([data_rec(0x0000, b"\x01" * 4), EOF]))
    plan = plan_relocation(
        result.segments,
        None,
        [Region("a", 0x00, 0x10), Region("b", 0x08, 0x20)],
    )
    assert not plan.regions_valid
    assert not plan.feasible
    assert [v.kind for v in plan.region_violations] == ["region_overlap"]


def test_empty_image_is_feasible_with_delta_zero():
    result = parse(EOF)
    plan = plan_relocation(result.segments, None, [Region("flash", 0x100, 0x200)])
    assert plan.feasible
    assert plan.delta == 0
    assert plan.feasible_ranges == []
    assert plan.segments == []


def test_segment_bytes_are_preserved():
    payload = bytes(range(16))
    result = parse("\n".join([data_rec(0x0000, payload), EOF]))
    plan = plan_relocation(result.segments, None, [Region("flash", 0x1000, 0x1100)])
    assert plan.segments[0].data == payload


# ---------------------------------------------------------------------------
# API surface
# ---------------------------------------------------------------------------

def test_api_happy_path_relocation():
    text = "\n".join([
        rec(0x04, 0, b"\x08\x00"),                    # base 0x0800_0000
        data_rec(0x0000, bytes(range(16))),
        entry_rec(0x08000001),
        EOF,
    ])
    resp = client.post(
        "/api/v1/plan-relocation",
        json={
            "hex_text": text,
            "regions": [
                # same place fits, so delta 0 must be picked
                region("flash", 0x08000000, 0x08010000, allow_entry=True),
            ],
            "max_abs_shift": 0x10000,
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True
    assert body["hex_ok"] is True
    assert body["regions_valid"] is True
    assert body["feasible"] is True
    assert body["delta"] == 0
    assert body["abs_shift"] == 0
    # region alone allows [0, 65520] (entry stops at the region's last
    # address); max_abs_shift=0x10000 does not clip that range
    assert body["feasible_ranges"] == [
        {"min_delta": 0, "max_delta": 65520}
    ]
    assert body["relocated_entry_address"] == 0x08000001
    seg = body["relocated_segments"][0]
    assert (seg["start"], seg["end"], seg["size"]) == (0x08000000, 0x08000010, 16)
    assert body["violations"] == []


def test_api_returns_relocated_image_with_positive_delta():
    text = "\n".join([
        data_rec(0x0000, b"\x01" * 16),
        entry_rec(0x0004),
        EOF,
    ])
    resp = client.post(
        "/api/v1/plan-relocation",
        json={
            "hex_text": text,
            "regions": [region("slot", 0x1000, 0x1100, allow_entry=True)],
            "max_abs_shift": 0x10000,
        },
    )
    body = resp.json()
    assert body["feasible"] is True
    assert body["delta"] == 0x1000
    seg = body["relocated_segments"][0]
    assert seg["start"] == 0x1000
    assert seg["end"] == 0x1010
    assert body["relocated_entry_address"] == 0x1004
    assert body["entry_address"] == 0x0004  # original entry echoed


def test_api_infeasible_omits_relocated_image():
    text = "\n".join([data_rec(0x0000, b"\x01" * 8), EOF])
    resp = client.post(
        "/api/v1/plan-relocation",
        json={
            "hex_text": text,
            "regions": [region("slot", 0x100, 0x104)],  # 4-byte slot for 8 bytes
        },
    )
    body = resp.json()
    assert body["ok"] is True
    assert body["feasible"] is False
    assert body["delta"] is None
    assert body["abs_shift"] is None
    assert body["feasible_ranges"] == []
    assert body["relocated_segments"] == []
    assert body["relocated_entry_address"] is None


def test_api_invalid_hex_returns_diagnostics_and_no_planning():
    resp = client.post(
        "/api/v1/plan-relocation",
        json={
            "hex_text": ":00000001FE\n",  # bad checksum
            "regions": [region("flash", 0x00, 0x10)],
        },
    )
    body = resp.json()
    assert body["ok"] is False
    assert body["hex_ok"] is False
    assert body["regions_valid"] is None
    assert body["feasible"] is False
    assert body["feasible_ranges"] == []
    assert body["violations"] == []
    assert any("checksum" in d["message"] for d in body["diagnostics"])


def test_api_invalid_regions_return_violations_and_no_planning():
    text = "\n".join([data_rec(0x0000, b"\x01"), EOF])
    resp = client.post(
        "/api/v1/plan-relocation",
        json={
            "hex_text": text,
            "regions": [region("a", 0x00, 0x10), region("b", 0x08, 0x20)],
        },
    )
    body = resp.json()
    assert body["ok"] is False
    assert body["hex_ok"] is True
    assert body["regions_valid"] is False
    assert body["feasible"] is False
    assert [v["kind"] for v in body["violations"]] == ["region_overlap"]
    assert body["relocated_segments"] == []


def test_api_max_abs_shift_validation():
    text = "\n".join([data_rec(0x0000, b"\x01"), EOF])
    resp = client.post(
        "/api/v1/plan-relocation",
        json={
            "hex_text": text,
            "regions": [region("flash", 0, 0x10)],
            "max_abs_shift": -1,
        },
    )
    assert resp.status_code == 422


def test_api_max_abs_shift_echoed():
    text = "\n".join([data_rec(0x0000, b"\x01"), EOF])
    resp = client.post(
        "/api/v1/plan-relocation",
        json={
            "hex_text": text,
            "regions": [region("flash", 0, 0x10)],
            "max_abs_shift": 0,
        },
    )
    body = resp.json()
    assert body["max_abs_shift"] == 0
    # delta 0 is feasible and within the cap
    assert body["feasible"] is True
    assert body["delta"] == 0
