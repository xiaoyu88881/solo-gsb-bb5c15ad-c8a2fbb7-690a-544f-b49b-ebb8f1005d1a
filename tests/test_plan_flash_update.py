"""Tests for the /api/v1/plan-flash-update endpoint and flash-update logic."""

import base64

from fastapi.testclient import TestClient

from app.hex_parser import Segment
from app.main import app
from app.flash_update import plan_flash_update

client = TestClient(app)


def rec(rectype: int, addr: int, data: bytes = b"") -> str:
    """Build a valid Intel HEX record line."""
    body = bytes([len(data), (addr >> 8) & 0xFF, addr & 0xFF, rectype]) + bytes(data)
    checksum = (-sum(body)) & 0xFF
    return ":" + (body + bytes([checksum])).hex().upper()


EOF = rec(0x01, 0)


def data_rec(addr: int, data: bytes) -> str:
    return rec(0x00, addr, data)


def seg(start: int, data: bytes) -> Segment:
    return Segment(start=start, data=data)


def plan(current, target, start=0, end=0x100, block=0x40, max_write=0x10):
    return plan_flash_update(current, target, start, end, block, max_write)


# ---------------------------------------------------------------------------
# pure flash-update logic
# ---------------------------------------------------------------------------

def test_identical_images_need_no_operations():
    result = plan([seg(0, bytes(range(16)))], [seg(0, bytes(range(16)))])
    assert result.ok
    assert result.params_valid
    assert result.blocks == []
    assert result.operations == []
    assert (
        result.erase_count,
        result.erase_bytes,
        result.write_count,
        result.write_bytes,
        result.changed_bytes,
    ) == (0, 0, 0, 0, 0)


def test_empty_images_need_no_operations():
    result = plan([], [])
    assert result.ok
    assert result.operations == []
    assert result.affected_block_count == 0


def test_one_to_zero_bits_write_without_erase():
    # 0xFF -> 0x00 only pulls bits down: no erase, one changed byte write
    result = plan([seg(0x00, b"\xFF")], [seg(0x00, b"\x00")])
    assert result.ok
    assert result.blocks[0].erase is False
    assert result.blocks[0].erase_size is None
    assert result.erase_count == 0
    assert result.write_count == 1
    op = result.operations[0]
    assert (op.kind, op.address, op.size, op.data) == ("write", 0x00, 1, b"\x00")
    assert result.changed_bytes == 1
    assert result.zero_to_one_bytes == 0


def test_zero_to_one_byte_forces_block_erase_and_rewrite():
    # 0x00 -> 0xFF restores bits: the whole block is erased; the erased
    # target byte is 0xFF itself, so nothing is written back.
    result = plan([seg(0x00, b"\x00")], [seg(0x00, b"\xFF")])
    assert result.ok
    block = result.blocks[0]
    assert block.erase is True
    assert block.erase_size == 0x40
    assert block.write_bytes == 0
    assert result.erase_count == 1
    assert result.erase_bytes == 0x40
    assert result.write_count == 0
    assert result.write_bytes == 0
    assert result.zero_to_one_bytes == 1
    assert result.operations[0].kind == "erase"
    assert result.operations[0].address == 0x00


def test_any_single_zero_to_one_bit_requires_erase():
    # 0xFE (1111 1110) -> 0xFF (1111 1111): one 0->1 bit, still an erase
    result = plan([seg(0x00, b"\xFE")], [seg(0x00, b"\xFF")])
    assert result.blocks[0].erase is True
    assert result.zero_to_one_bytes == 1


def test_erased_block_rewrites_every_non_ff_target_byte():
    # addr 0x00 forces an erase; addr 0x01 is unchanged 0x41 and must
    # still be rewritten; addr 0x02 changes 1->0 and is written too;
    # addr 0x03 targets 0xFF and is skipped after the erase. Pending
    # bytes 0x01..0x02 are contiguous, so they merge into one write.
    current = [seg(0x00, bytes([0x00, 0x41, 0xFF, 0x05]))]
    target = [seg(0x00, bytes([0xFF, 0x41, 0x00, 0xFF]))]
    result = plan(current, target)
    assert result.blocks[0].erase is True
    writes = [op for op in result.operations if op.kind == "write"]
    assert [(w.address, w.data) for w in writes] == [
        (0x01, b"\x41\x00"),
    ]
    # changed bytes: 0x00, 0x02, 0x03; zero_to_one: 0x00 and 0x03
    assert result.changed_bytes == 3
    assert result.zero_to_one_bytes == 2
    assert result.write_bytes == 2


def test_missing_addresses_read_as_ff_missing_target_releases_block():
    # current defines 0x00 = 0x00; target defines nothing there: the
    # implicit 0x00 -> 0xFF transition erases the block.
    result = plan([seg(0x00, b"\x00")], [])
    assert result.blocks[0].erase is True
    assert result.blocks[0].write_bytes == 0


def test_missing_current_address_treated_as_erased_ff():
    # nothing in current; target adds 0x0A -> writing 0xFF -> 0x0A is a
    # plain bit-clearing write, no erase
    result = plan([], [seg(0x0A, b"\x0A")])
    block = result.blocks[0]
    assert block.erase is False
    assert block.changed_bytes == 1
    op = result.operations[0]
    assert (op.kind, op.address, op.size, op.data) == ("write", 0x0A, 1, b"\x0A")


def test_changed_bytes_merge_into_one_contiguous_run():
    # bytes 0x10 and 0x12 change, 0x11 unchanged -> gap means two runs
    current = [seg(0x10, b"\xFF\x00\xFF")]
    target = [seg(0x10, b"\x00\x00\x00")]
    result = plan(current, target, max_write=0x10)
    writes = [op for op in result.operations if op.kind == "write"]
    assert [(w.address, w.size, w.data) for w in writes] == [
        (0x10, 1, b"\x00"),
        (0x12, 1, b"\x00"),
    ]

    # same but 0x11 also changes 1->0 only (0xFF -> 0x7F): one run,
    # still no erase
    current = [seg(0x10, b"\xFF\xFF\xFF")]
    target = [seg(0x10, b"\x00\x7F\x00")]
    result = plan(current, target, max_write=0x10)
    writes = [op for op in result.operations if op.kind == "write"]
    assert [(w.address, w.size, w.data) for w in writes] == [
        (0x10, 3, b"\x00\x7F\x00"),
    ]
    assert result.blocks[0].erase is False


def test_writes_split_at_max_write_size():
    current = [seg(0x00, b"\xFF" * 10)]
    target = [seg(0x00, bytes(range(10)))]
    result = plan(current, target, max_write=4)
    writes = [op for op in result.operations if op.kind == "write"]
    assert [(w.address, w.size) for w in writes] == [(0, 4), (4, 4), (8, 2)]
    assert all(w.size <= 4 for w in writes)
    assert b"".join(w.data for w in writes) == bytes(range(10))
    assert result.write_count == 3
    assert result.write_bytes == 10


def test_writes_never_cross_erase_blocks():
    # no erase needed (all transitions are 1->0); changed bytes
    # straddle the 0x40 block boundary
    current = [seg(0x3C, b"\xFF" * 8)]
    target = [seg(0x3C, bytes([0x55] * 8))]
    result = plan(current, target, block=0x40, max_write=0x100)
    writes = [op for op in result.operations if op.kind == "write"]
    assert [(w.address, w.size, hex(w.block)) for w in writes] == [
        (0x3C, 4, "0x0"),
        (0x40, 4, "0x40"),
    ]
    # two affected blocks, neither erased
    assert [b.address for b in result.blocks] == [0x00, 0x40]
    assert all(not b.erase for b in result.blocks)


def test_max_write_size_split_inside_block():
    current = [seg(0x00, b"\x00\x00")]
    target = [seg(0x00, b"\xFF\x01")]  # first byte forces erase
    # after erase both non-FF target bytes (0x01) are rewritten contiguously
    result = plan(current, target, block=0x40, max_write=1)
    writes = [op for op in result.operations if op.kind == "write"]
    assert [(w.address, w.size) for w in writes] == [(1, 1)]
    assert result.blocks[0].write_bytes == 1


def test_max_write_size_larger_than_block_still_splits_at_boundary():
    # contiguous 1->0 changes cover 0x3E..0x45; max_write_size is huge,
    # yet the block boundary at 0x40 must sever the run
    current = [seg(0x3E, b"\xFF" * 8)]
    target = [seg(0x3E, b"\x00" * 8)]
    result = plan(current, target, block=0x40, max_write=0x10000)
    writes = [op for op in result.operations if op.kind == "write"]
    assert [(w.address, w.size) for w in writes] == [(0x3E, 2), (0x40, 6)]
    assert b"".join(w.data for w in writes) == b"\x00" * 8


def test_multiple_blocks_erase_independently():
    current = [seg(0x00, b"\x00"), seg(0x80, b"\x0F")]
    target = [seg(0x00, b"\xFF"), seg(0x80, b"\x00")]
    result = plan(current, target, block=0x40, max_write=0x10)
    assert [b.address for b in result.blocks] == [0x00, 0x80]
    assert result.blocks[0].erase is True
    assert result.blocks[1].erase is False  # 0x0F -> 0x00 only clears bits
    assert result.erase_count == 1
    assert result.erase_bytes == 0x40
    kinds = [(op.kind, op.address) for op in result.operations]
    assert kinds == [("erase", 0x00), ("write", 0x80)]


def test_erase_before_writes_in_same_block_ordering():
    current = [seg(0x00, b"\x00"), seg(0x10, b"\xFF")]
    target = [seg(0x00, b"\xFF"), seg(0x10, b"\x00")]
    result = plan(current, target, block=0x40)
    ops = result.operations
    assert ops[0].kind == "erase"
    assert ops[0].address == 0x00
    assert (ops[1].kind, ops[1].address) == ("write", 0x10)


def test_aligned_window_with_nonzero_base():
    result = plan(
        [seg(0x100, b"\x00")],
        [seg(0x100, b"\xFF")],
        start=0x100,
        end=0x200,
        block=0x40,
    )
    assert result.ok
    assert result.blocks[0].address == 0x100
    assert (result.operations[0].kind, result.operations[0].address) == ("erase", 0x100)


# ---------------------------------------------------------------------------
# parameter validation (pure logic)
# ---------------------------------------------------------------------------

def test_empty_flash_range_rejected():
    result = plan([seg(0, b"\x01")], [seg(0, b"\x02")], start=0x10, end=0x10)
    assert not result.ok
    assert not result.params_valid
    assert [e.kind for e in result.param_errors] == ["invalid_flash_range"]
    assert result.operations == []
    assert result.blocks == []


def test_reversed_flash_range_rejected():
    result = plan([], [], start=0x20, end=0x10)
    assert [e.kind for e in result.param_errors] == ["invalid_flash_range"]


def test_unaligned_flash_start_rejected():
    result = plan([], [], start=0x01, end=0x40, block=0x40)
    assert [e.kind for e in result.param_errors] == ["erase_block_unaligned"]


def test_unaligned_flash_end_rejected():
    result = plan([], [], start=0x00, end=0x41, block=0x40)
    assert [e.kind for e in result.param_errors] == ["erase_block_unaligned"]


def test_flash_range_above_32bit_rejected():
    result = plan([], [], start=0xFFFFFFF0, end=0x100000010, block=0x10)
    assert [e.kind for e in result.param_errors] == ["invalid_flash_range"]


def test_flash_end_at_32bit_ceiling_accepted():
    result = plan(
        [seg(0xFFFFFFF0, b"\x01")],
        [seg(0xFFFFFFF0, b"\x02")],
        start=0xFFFFFFF0,
        end=0x100000000,
        block=0x10,
    )
    assert result.ok
    assert result.params_valid


def test_non_positive_block_and_write_sizes_rejected():
    result = plan_flash_update([], [], 0, 0x40, 0, 0)
    kinds = {e.kind for e in result.param_errors}
    assert kinds == {"erase_block_unaligned", "invalid_max_write_size"}


def test_current_image_outside_flash_reported_with_range():
    result = plan([seg(0, b"\x01" * 8)], [], start=0x40, end=0x80)
    errors = result.param_errors
    assert [e.kind for e in errors] == ["image_outside_flash"]
    assert (errors[0].start, errors[0].end) == (0x00, 0x08)
    assert "current" in errors[0].message
    assert not result.ok
    assert result.operations == []


def test_segment_exactly_ending_at_flash_end_is_accepted():
    # 0x48 + 8 = 0x50, but the window must be block aligned: use a
    # segment ending exactly at flash_end 0x80
    result = plan([], [seg(0x78, b"\x01" * 8)], start=0x40, end=0x80)
    assert result.ok
    assert result.param_errors == []


def test_target_image_protruding_above_flash_end():
    result = plan([], [seg(0x7C, b"\x01" * 8)], start=0x40, end=0x80)
    errors = result.param_errors
    assert len(errors) == 1
    assert errors[0].kind == "image_outside_flash"
    assert (errors[0].start, errors[0].end) == (0x80, 0x84)
    assert "target" in errors[0].message


# ---------------------------------------------------------------------------
# API surface
# ---------------------------------------------------------------------------

def test_api_happy_path_no_erase():
    current = "\n".join([data_rec(0x0000, b"\xFF\xFF"), EOF])
    target = "\n".join([data_rec(0x0000, b"\x12\x34"), EOF])
    resp = client.post(
        "/api/v1/plan-flash-update",
        json={
            "current_hex": current,
            "target_hex": target,
            "flash_start": 0,
            "flash_end": 256,
            "erase_block_size": 64,
            "max_write_size": 16,
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True
    assert body["current_hex_ok"] is True
    assert body["target_hex_ok"] is True
    assert body["params_valid"] is True
    assert body["param_errors"] == []
    assert body["affected_blocks"][0]["erase"] is False
    write = body["operations"][0]
    assert write["kind"] == "write"
    assert write["address"] == 0
    assert write["end"] == 2
    assert base64.b64decode(write["data_base64"]) == b"\x12\x34"
    assert body["write_bytes"] == 2
    assert body["erase_count"] == 0
    assert body["current_diagnostics"]
    assert body["target_diagnostics"]


def test_api_erase_rewrite_path():
    current = "\n".join([data_rec(0x0000, b"\x00\x01\x02"), EOF])
    target = "\n".join([data_rec(0x0000, b"\xFF\x01\x03"), EOF])
    resp = client.post(
        "/api/v1/plan-flash-update",
        json={
            "current_hex": current,
            "target_hex": target,
            "flash_start": 0,
            "flash_end": 0x100,
            "erase_block_size": 0x40,
            "max_write_size": 0x10,
        },
    )
    body = resp.json()
    assert body["ok"] is True
    assert body["erase_count"] == 1
    assert body["erase_bytes"] == 0x40
    block = body["affected_blocks"][0]
    assert block["erase"] is True
    assert block["erase_size"] == 0x40
    # erased block: 0x01 unchanged but rewritten, 0x02 changed; 0xFF skipped.
    # pending bytes 0x01..0x02 are contiguous -> one merged write
    writes = [(o["address"], base64.b64decode(o["data_base64"])) for o in body["operations"] if o["kind"] == "write"]
    assert writes == [(1, b"\x01\x03")]
    assert body["zero_to_one_bytes"] == 2  # 0x00 -> 0xFF and bit0 of 0x02 -> 0x03
    assert body["changed_bytes"] == 2


def test_api_write_split_and_block_boundary():
    current = "\n".join([data_rec(0x3E, b"\xFF" * 6), EOF])
    target = "\n".join([data_rec(0x3E, b"\x00" * 6), EOF])
    resp = client.post(
        "/api/v1/plan-flash-update",
        json={
            "current_hex": current,
            "target_hex": target,
            "flash_start": 0,
            "flash_end": 0x100,
            "erase_block_size": 0x40,
            "max_write_size": 4,
        },
    )
    body = resp.json()
    writes = body["operations"]
    assert [(w["address"], w["size"], w["block"]) for w in writes] == [
        (0x3E, 2, 0x00),
        (0x40, 4, 0x40),
    ]
    assert all(w["address"] // 0x40 * 0x40 == w["block"] for w in writes)
    assert body["affected_block_count"] == 2


def test_api_invalid_current_hex_returns_diagnostics_no_plan():
    good = "\n".join([data_rec(0x0000, b"\x01"), EOF])
    resp = client.post(
        "/api/v1/plan-flash-update",
        json={
            "current_hex": ":00000001FE\n",  # bad checksum
            "target_hex": good,
            "flash_start": 0,
            "flash_end": 256,
            "erase_block_size": 64,
            "max_write_size": 16,
        },
    )
    body = resp.json()
    assert body["ok"] is False
    assert body["current_hex_ok"] is False
    assert body["target_hex_ok"] is True
    assert body["params_valid"] is None
    assert body["operations"] == []
    assert body["affected_blocks"] == []
    assert body["param_errors"] == []
    assert any("checksum" in d["message"] for d in body["current_diagnostics"])
    assert body["error_count"] >= 1


def test_api_invalid_target_hex_returns_diagnostics_no_plan():
    good = "\n".join([data_rec(0x0000, b"\x01"), EOF])
    resp = client.post(
        "/api/v1/plan-flash-update",
        json={
            "current_hex": good,
            "target_hex": "not a hex file\n",
            "flash_start": 0,
            "flash_end": 256,
            "erase_block_size": 64,
            "max_write_size": 16,
        },
    )
    body = resp.json()
    assert body["ok"] is False
    assert body["current_hex_ok"] is True
    assert body["target_hex_ok"] is False
    assert body["params_valid"] is None
    assert body["operations"] == []
    assert any(d["line"] == 0 and "end-of-file" in d["message"] for d in body["target_diagnostics"])


def test_api_unaligned_range_returns_param_error():
    hex_text = "\n".join([data_rec(0x0000, b"\x01"), EOF])
    resp = client.post(
        "/api/v1/plan-flash-update",
        json={
            "current_hex": hex_text,
            "target_hex": hex_text,
            "flash_start": 1,
            "flash_end": 65,
            "erase_block_size": 64,
            "max_write_size": 16,
        },
    )
    body = resp.json()
    assert body["ok"] is False
    assert body["current_hex_ok"] is True
    assert body["target_hex_ok"] is True
    assert body["params_valid"] is False
    assert [e["kind"] for e in body["param_errors"]] == ["erase_block_unaligned"]
    assert body["operations"] == []


def test_api_image_outside_flash_returns_param_error():
    current = "\n".join([data_rec(0x0000, b"\x01"), EOF])
    target = "\n".join([data_rec(0x0000, b"\x02"), EOF])
    resp = client.post(
        "/api/v1/plan-flash-update",
        json={
            "current_hex": current,
            "target_hex": target,
            "flash_start": 0x100,
            "flash_end": 0x200,
            "erase_block_size": 64,
            "max_write_size": 16,
        },
    )
    body = resp.json()
    assert body["ok"] is False
    assert body["params_valid"] is False
    kinds = {e["kind"] for e in body["param_errors"]}
    assert kinds == {"image_outside_flash"}


def test_api_non_positive_sizes_are_422():
    hex_text = "\n".join([data_rec(0x0000, b"\x01"), EOF])
    resp = client.post(
        "/api/v1/plan-flash-update",
        json={
            "current_hex": hex_text,
            "target_hex": hex_text,
            "flash_start": 0,
            "flash_end": 64,
            "erase_block_size": 0,
            "max_write_size": 0,
        },
    )
    assert resp.status_code == 422


def test_api_identical_images_return_empty_plan():
    hex_text = "\n".join([data_rec(0x0000, bytes(range(8))), EOF])
    resp = client.post(
        "/api/v1/plan-flash-update",
        json={
            "current_hex": hex_text,
            "target_hex": hex_text,
            "flash_start": 0,
            "flash_end": 256,
            "erase_block_size": 64,
            "max_write_size": 16,
        },
    )
    body = resp.json()
    assert body["ok"] is True
    assert body["operations"] == []
    assert body["affected_blocks"] == []
    assert body["affected_block_count"] == 0
    assert body["write_bytes"] == 0


def test_api_extended_linear_address_records_supported():
    current = "\n".join(
        [
            rec(0x04, 0, b"\x08\x00"),
            data_rec(0x0000, b"\x00"),
            EOF,
        ]
    )
    target = "\n".join(
        [
            rec(0x04, 0, b"\x08\x00"),
            data_rec(0x0000, b"\xFF"),
            EOF,
        ]
    )
    resp = client.post(
        "/api/v1/plan-flash-update",
        json={
            "current_hex": current,
            "target_hex": target,
            "flash_start": 0x08000000,
            "flash_end": 0x08010000,
            "erase_block_size": 0x1000,
            "max_write_size": 256,
        },
    )
    body = resp.json()
    assert body["ok"] is True
    assert body["erase_count"] == 1
    assert body["affected_blocks"][0]["address"] == 0x08000000
