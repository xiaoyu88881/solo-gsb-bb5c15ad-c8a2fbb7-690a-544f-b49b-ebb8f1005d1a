"""Tests for the /api/v1/validate-vector-table endpoint and vector-table logic."""

from fastapi.testclient import TestClient

from app.hex_parser import parse_intel_hex
from app.main import app
from app.vector_table import VectorRegion, validate_vector_table

client = TestClient(app)


def rec(rectype: int, addr: int, data: bytes = b"") -> str:
    """Build a valid Intel HEX record line."""
    body = bytes([len(data), (addr >> 8) & 0xFF, addr & 0xFF, rectype]) + bytes(data)
    checksum = (-sum(body)) & 0xFF
    return ":" + (body + bytes([checksum])).hex().upper()


EOF = rec(0x01, 0)

TABLE_START = 0x08000000
FLASH = VectorRegion("flash", 0x08000000, 0x08040000, executable=True)
RAM = VectorRegion("ram", 0x20000000, 0x20020000, ram=True)


def data_rec(addr: int, data: bytes) -> str:
    return rec(0x00, addr, data)


def vectors_hex(vectors: list[int], table_start: int = TABLE_START) -> str:
    """Build HEX text holding the given 32-bit words at ``table_start``."""
    payload = b"".join(v.to_bytes(4, "little") for v in vectors)
    return "\n".join([
        rec(0x04, 0, (table_start >> 16).to_bytes(2, "big")),
        data_rec(table_start & 0xFFFF, payload),
        EOF,
    ])


def region(name, start, end, ram=False, executable=False):
    return {
        "name": name,
        "start": start,
        "end": end,
        "ram": ram,
        "executable": executable,
    }


def validate(vectors: list[int], regions=None, table_start: int = TABLE_START):
    result = parse_intel_hex(vectors_hex(vectors, table_start))
    assert result.ok
    return validate_vector_table(
        result.segments,
        table_start,
        len(vectors),
        regions if regions is not None else [FLASH, RAM],
    )


# ---------------------------------------------------------------------------
# pure vector-table logic
# ---------------------------------------------------------------------------

def test_happy_path_all_entry_kinds():
    result = validate([0x20020000, 0x08000101, 0, 0x08000201])
    assert result.ok
    assert result.regions_valid
    assert result.violations == []
    assert [e.status for e in result.entries] == ["ok", "ok", "empty", "ok"]
    assert [e.role for e in result.entries] == ["initial_sp", "reset", "handler", "handler"]
    sp, reset, empty, handler = result.entries
    assert sp.value == 0x20020000
    assert sp.target_address is None
    assert reset.value == 0x08000101
    assert reset.target_address == 0x08000100  # Thumb bit cleared
    assert empty.value == 0
    assert handler.target_address == 0x08000200
    assert [e.address for e in result.entries] == [
        TABLE_START + 4 * i for i in range(4)
    ]


def test_initial_sp_may_equal_ram_end():
    assert validate([0x20020000, 0x08000101]).ok  # exactly RAM end
    assert validate([0x20000000, 0x08000101]).ok  # exactly RAM start


def test_initial_sp_must_be_8_byte_aligned():
    result = validate([0x20000004, 0x08000101])
    assert not result.ok
    assert result.entries[0].status == "error"
    assert result.entries[0].value == 0x20000004
    v = result.violations[0]
    assert v.kind == "stack_misaligned"
    assert v.index == 0
    assert v.address == 0x20000004


def test_initial_sp_must_land_in_ram():
    result = validate([0x20020008, 0x08000101])  # aligned but past RAM end
    assert not result.ok
    assert [v.kind for v in result.violations] == ["stack_outside_ram"]
    assert result.violations[0].index == 0
    assert result.violations[0].address == 0x20020008


def test_misaligned_sp_outside_ram_reports_both():
    result = validate([0x08000005, 0x08000101])  # misaligned and not in RAM
    kinds = sorted(v.kind for v in result.violations)
    assert kinds == ["stack_misaligned", "stack_outside_ram"]
    assert result.entries[0].status == "error"


def test_reset_vector_must_be_non_zero():
    result = validate([0x20020000, 0])
    assert not result.ok
    assert result.entries[1].status == "error"
    v = result.violations[0]
    assert v.kind == "reset_vector_zero"
    assert v.index == 1
    assert v.address == TABLE_START + 4


def test_zero_handler_is_an_empty_slot():
    result = validate([0x20020000, 0x08000101, 0, 0])
    assert result.ok
    assert [e.status for e in result.entries[2:]] == ["empty", "empty"]
    assert all(e.value == 0 for e in result.entries[2:])


def test_handler_must_carry_thumb_bit():
    result = validate([0x20020000, 0x08000101, 0x08000200])  # even address
    assert not result.ok
    assert result.entries[2].status == "error"
    v = result.violations[0]
    assert v.kind == "thumb_bit_missing"
    assert v.index == 2
    assert v.address == 0x08000200


def test_handler_target_must_be_executable():
    result = validate([0x20020000, 0x08000101, 0x08040101])  # past flash end
    assert not result.ok
    entry = result.entries[2]
    assert entry.status == "error"
    assert entry.target_address == 0x08040100
    v = result.violations[0]
    assert v.kind == "address_not_executable"
    assert v.index == 2
    assert v.address == 0x08040100


def test_reset_vector_is_a_processor_address_too():
    result = validate([0x20020000, 0x08000100])  # reset without Thumb bit
    assert not result.ok
    assert [v.kind for v in result.violations] == ["thumb_bit_missing"]
    assert result.violations[0].index == 1


def test_handler_may_target_second_executable_region():
    regions = [
        FLASH,
        RAM,
        VectorRegion("itcm", 0x00000000, 0x00010000, executable=True),
    ]
    assert validate([0x20020000, 0x00000101], regions).ok


def test_missing_bytes_locate_entry_and_address():
    # image covers entries 0..1 fully and only 2 bytes of entry 2
    text = "\n".join([
        rec(0x04, 0, b"\x08\x00"),
        data_rec(0x0000, b"\x00" * 10),
        EOF,
    ])
    parsed = parse_intel_hex(text)
    assert parsed.ok
    result = validate_vector_table(parsed.segments, TABLE_START, 4, [FLASH, RAM])
    assert not result.ok
    entry2 = result.entries[2]
    assert entry2.status == "error"
    assert entry2.value is None
    assert entry2.missing_bytes == [TABLE_START + 10, TABLE_START + 11]
    entry3 = result.entries[3]
    assert entry3.missing_bytes == [TABLE_START + 12 + i for i in range(4)]
    missing = [v for v in result.violations if v.kind == "missing_vector_bytes"]
    assert [(v.index, v.address) for v in missing] == [
        (2, TABLE_START + 10),
        (3, TABLE_START + 12),
    ]


def test_table_outside_image_reports_every_entry():
    result = parse_intel_hex("\n".join([data_rec(0x0000, b"\x01"), EOF]))
    assert result.ok
    table = validate_vector_table(result.segments, 0x1000, 3, [FLASH, RAM])
    assert not table.ok
    assert [e.status for e in table.entries] == ["error"] * 3
    assert [v.index for v in table.violations] == [0, 1, 2]
    assert all(v.kind == "missing_vector_bytes" for v in table.violations)


def test_invalid_region_definition_skips_table_read():
    result = parse_intel_hex(vectors_hex([0x20020000, 0x08000101]))
    table = validate_vector_table(
        result.segments, TABLE_START, 2, [VectorRegion("bad", 0x10, 0x10)]
    )
    assert not table.ok
    assert not table.regions_valid
    assert table.entries == []
    assert [v.kind for v in table.violations] == ["invalid_region"]
    assert table.violations[0].region == "bad"


def test_overlapping_regions_skip_table_read():
    result = parse_intel_hex(vectors_hex([0x20020000, 0x08000101]))
    table = validate_vector_table(
        result.segments,
        TABLE_START,
        2,
        [
            VectorRegion("a", 0x08000000, 0x08020000, executable=True),
            VectorRegion("b", 0x08010000, 0x08030000, executable=True),
        ],
    )
    assert not table.regions_valid
    assert table.entries == []
    assert [v.kind for v in table.violations] == ["region_overlap"]


def test_touching_regions_do_not_overlap():
    regions = [
        VectorRegion("flash", 0x08000000, 0x08020000, executable=True),
        VectorRegion("otp", 0x08020000, 0x08040000, executable=True),
        RAM,
    ]
    assert validate([0x20020000, 0x08000101], regions).ok


# ---------------------------------------------------------------------------
# API surface
# ---------------------------------------------------------------------------

def post(hex_text, vector_count=4, table_start=TABLE_START, regions=None):
    return client.post(
        "/api/v1/validate-vector-table",
        json={
            "hex_text": hex_text,
            "vector_table_start": table_start,
            "vector_count": vector_count,
            "regions": regions
            if regions is not None
            else [
                region("flash", 0x08000000, 0x08040000, executable=True),
                region("ram", 0x20000000, 0x20020000, ram=True),
            ],
        },
    )


def test_api_happy_path():
    resp = post(vectors_hex([0x20020000, 0x08000101, 0, 0x08000201]))
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True
    assert body["hex_ok"] is True
    assert body["regions_valid"] is True
    assert body["vector_table_start"] == TABLE_START
    assert body["vector_count"] == 4
    assert body["total_bytes"] == 16
    assert body["violations"] == []
    assert [v["status"] for v in body["vectors"]] == ["ok", "ok", "empty", "ok"]
    reset = body["vectors"][1]
    assert reset["value"] == 0x08000101
    assert reset["target_address"] == 0x08000100
    assert reset["missing_bytes"] == []
    assert len(body["diagnostics"]) == 3


def test_api_invalid_hex_returns_only_diagnostics():
    resp = post(":00000001FE\n")  # bad checksum
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is False
    assert body["hex_ok"] is False
    assert body["regions_valid"] is None
    assert body["vectors"] == []
    assert body["violations"] == []
    assert body["error_count"] >= 1
    assert any("checksum" in d["message"] for d in body["diagnostics"])


def test_api_invalid_regions_skip_validation():
    resp = post(
        vectors_hex([0x20020000, 0x08000101]),
        vector_count=2,
        regions=[
            region("a", 0x08000000, 0x08020000, executable=True),
            region("b", 0x08010000, 0x08030000, executable=True),
        ],
    )
    body = resp.json()
    assert body["ok"] is False
    assert body["hex_ok"] is True
    assert body["regions_valid"] is False
    assert body["vectors"] == []
    assert [v["kind"] for v in body["violations"]] == ["region_overlap"]


def test_api_reports_vector_violations():
    resp = post(vectors_hex([0x20000004, 0, 0x08000200, 0x20000101]))
    body = resp.json()
    assert body["ok"] is False
    assert body["hex_ok"] is True
    assert body["regions_valid"] is True
    kinds = [v["kind"] for v in body["violations"]]
    assert kinds == [
        "stack_misaligned",
        "reset_vector_zero",
        "thumb_bit_missing",
        "address_not_executable",  # 0x20000100 targets RAM, not flash
    ]
    assert [v["index"] for v in body["violations"]] == [0, 1, 2, 3]
    assert [v["status"] for v in body["vectors"]] == ["error"] * 4


def test_api_missing_bytes_reported_per_entry():
    text = "\n".join([
        rec(0x04, 0, b"\x08\x00"),
        data_rec(0x0000, (0x20020000).to_bytes(4, "little") + (0x08000101).to_bytes(4, "little")),
        EOF,
    ])
    resp = post(text, vector_count=3)
    body = resp.json()
    assert body["ok"] is False
    assert [v["status"] for v in body["vectors"]] == ["ok", "ok", "error"]
    entry = body["vectors"][2]
    assert entry["value"] is None
    assert entry["missing_bytes"] == [TABLE_START + 8 + i for i in range(4)]
    v = body["violations"][0]
    assert v["kind"] == "missing_vector_bytes"
    assert v["index"] == 2
    assert v["address"] == TABLE_START + 8


def test_api_vector_count_must_cover_reset():
    resp = post(vectors_hex([0x20020000, 0x08000101]), vector_count=1)
    assert resp.status_code == 422


def test_api_region_field_validation():
    resp = post(
        vectors_hex([0x20020000, 0x08000101]),
        vector_count=2,
        regions=[{"name": "", "start": 0, "end": 16}],
    )
    assert resp.status_code == 422
