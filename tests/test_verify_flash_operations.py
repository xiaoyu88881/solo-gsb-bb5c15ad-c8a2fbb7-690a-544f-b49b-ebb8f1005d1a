"""Tests for the /api/v1/verify-flash-operations endpoint and replay logic."""

import base64

from fastapi.testclient import TestClient

from app.hex_parser import Segment
from app.main import app
from app.flash_update import plan_flash_update
from app.flash_verify import BAD_WRITE_DATA, VerifyOperation, verify_flash_operations

client = TestClient(app)


def rec(rectype: int, addr: int, data: bytes = b"") -> str:
    """Build a valid Intel HEX record line."""
    body = bytes([len(data), (addr >> 8) & 0xFF, addr & 0xFF, rectype]) + bytes(data)
    checksum = (-sum(body)) & 0xFF
    return ":" + (body + bytes([checksum])).hex().upper()


EOF_REC = rec(0x01, 0)


def data_rec(addr: int, data: bytes) -> str:
    return rec(0x00, addr, data)


def seg(start: int, data: bytes) -> Segment:
    return Segment(start=start, data=data)


def erase(address: int, size: int) -> VerifyOperation:
    return VerifyOperation(kind="erase", address=address, size=size)


def write(address: int, data: bytes) -> VerifyOperation:
    return VerifyOperation(
        kind="write", address=address, size=len(data), data=data
    )


def verify(current, target, operations, start=0, end=0x100, block=0x40, max_write=0x10):
    return verify_flash_operations(
        current, target, start, end, block, max_write, operations
    )


# ---------------------------------------------------------------------------
# pure replay logic — happy paths
# ---------------------------------------------------------------------------

def test_empty_operations_match_when_images_equal():
    result = verify([seg(0, b"\x01\x02")], [seg(0, b"\x01\x02")], [])
    assert result.ok
    assert result.params_valid
    assert result.operations_valid
    assert result.matches_target
    assert result.executed_count == 0
    assert result.diffs == []


def test_empty_operations_detect_difference():
    result = verify([seg(0, b"\x01")], [seg(0, b"\x02")], [])
    assert not result.ok
    assert result.operations_valid
    assert not result.matches_target
    assert [(d.start, d.end, d.size) for d in result.diffs] == [(0, 1, 1)]
    assert result.diff_byte_count == 1


def test_erase_then_rewrite_reaches_target():
    current = [seg(0x00, bytes(range(16)))]
    target = [seg(0x00, bytes([0xFF, *range(1, 16)]))]
    result = verify(
        current,
        target,
        [erase(0x00, 0x40), write(0x01, bytes(range(1, 16)))],
    )
    assert result.ok, result.error
    assert result.matches_target
    assert result.executed_count == 2
    assert result.diffs == []


def test_write_may_only_clear_bits():
    # 0x0F -> 0x03 clears bits: legal without erase
    result = verify([seg(0, b"\x0F")], [seg(0, b"\x03")], [write(0, b"\x03")])
    assert result.ok


def test_chained_writes_clear_incrementally():
    result = verify(
        [seg(0, b"\x0F")],
        [seg(0, b"\x01")],
        [write(0, b"\x07"), write(0, b"\x03"), write(0, b"\x01")],
    )
    assert result.ok


def test_erase_resets_whole_block_and_implicit_ff():
    # current writes 0x00 in two blocks; one aligned double-block erase
    # (whole-block multiple) leaves both reading as undefined (0xFF),
    # and the empty target matches.
    result = verify(
        [seg(0x00, b"\x00"), seg(0x40, b"\x00")],
        [],
        [erase(0x00, 0x80)],
    )
    assert result.ok
    assert result.executed_count == 1


def test_planner_generated_operations_always_verify():
    current = [seg(0x00, bytes([0x00, 0x01, 0x02, 0x03]))]
    target = [seg(0x00, bytes([0xFF, 0x01, 0x03, 0x03]))]
    plan = plan_flash_update(current, target, 0, 0x100, 0x40, 0x10)
    operations = [
        VerifyOperation(
            kind=op.kind,
            address=op.address,
            size=op.size,
            data=None if op.kind == "erase" else op.data,
        )
        for op in plan.operations
    ]
    result = verify(current, target, operations)
    assert result.ok, (result.error, result.diffs)
    assert result.matches_target


def test_missing_target_bytes_compared_as_ff():
    # current has 0x00; the single write clears nothing but forgets the
    # erase: difference at the undefined target byte is reported.
    result = verify([seg(0, b"\x00")], [], [write(0, b"\x00")])
    assert not result.ok
    assert result.operations_valid
    assert [(d.start, d.end) for d in result.diffs] == [(0, 1)]


# ---------------------------------------------------------------------------
# pure replay logic — first illegal operation stops the replay
# ---------------------------------------------------------------------------

def test_zero_to_one_write_is_illegal_with_index():
    result = verify(
        [seg(0, b"\x00")],
        [seg(0, b"\x01")],
        [write(0, b"\x01")],
    )
    assert not result.ok
    assert result.error is not None
    assert result.error.kind == "write_zero_to_one"
    assert result.error.index == 0
    assert result.error.start == 0
    assert result.executed_count == 0


def test_replay_stops_at_first_illegal_operation():
    # op 0 is legal (FF -> 00), op 1 tries to restore a bit (0x0F -> FF)
    operations = [write(0x00, b"\x00"), write(0x01, b"\xFF")]
    result = verify(
        [seg(0x00, b"\xFF\x0F")],
        [seg(0x00, b"\x00\x00")],
        operations,
    )
    assert result.error is not None
    assert result.error.kind == "write_zero_to_one"
    assert result.error.index == 1
    assert result.executed_count == 1
    assert result.operation_count == 2
    # replay stopped: no diffs are produced
    assert result.diffs == []


def test_unaligned_erase_address_rejected():
    result = verify([], [], [erase(0x01, 0x40)])
    assert result.error.kind == "erase_not_block_aligned"
    assert result.error.index == 0
    assert result.error.start == 0x01


def test_erase_size_not_whole_block_multiple_rejected():
    result = verify([], [], [erase(0x00, 0x20)])
    assert result.error.kind == "erase_not_block_aligned"
    assert result.error.index == 0


def test_operation_outside_flash_reported():
    result = verify([], [], [write(0x100, b"\x00")])
    assert result.error.kind == "operation_outside_flash"
    result = verify([], [], [erase(0xC0, 0x80)])
    assert result.error.kind == "operation_outside_flash"


def test_erase_outside_takes_precedence_over_alignment():
    # unaligned end beyond the window: range check fires first
    result = verify([], [], [erase(0xC0, 0x80)], end=0x100)
    assert result.error.kind == "operation_outside_flash"


def test_write_crossing_block_rejected():
    result = verify(
        [seg(0x3E, b"\xFF" * 6)],
        [seg(0x3E, b"\x00" * 6)],
        [write(0x3E, b"\x00" * 6)],
    )
    assert result.error.kind == "write_crosses_block"
    assert result.error.index == 0


def test_write_longer_than_max_rejected():
    result = verify(
        [seg(0, b"\xFF" * 5)],
        [seg(0, b"\x00" * 5)],
        [write(0, b"\x00" * 5)],
        max_write=4,
    )
    assert result.error.kind == "write_too_long"


def test_write_data_size_mismatch_rejected():
    result = verify(
        [seg(0, b"\xFF")],
        [seg(0, b"\x00")],
        [VerifyOperation(kind="write", address=0, size=1, data=b"\x00\x01")],
    )
    assert result.error.kind == "write_data_size_mismatch"


def test_write_invalid_payload_rejected():
    result = verify(
        [],
        [seg(0, b"\x00")],
        [VerifyOperation(kind="write", address=0, size=1, data=BAD_WRITE_DATA)],
    )
    assert result.error.kind == "write_data_invalid"

    result = verify(
        [],
        [seg(0, b"\x00")],
        [VerifyOperation(kind="write", address=0, size=1, data=None)],
    )
    assert result.error.kind == "write_data_invalid"


def test_unknown_operation_kind_rejected():
    result = verify([], [], [VerifyOperation(kind="nuke", address=0, size=1)])
    assert result.error.kind == "unknown_operation_kind"
    assert result.error.index == 0


# ---------------------------------------------------------------------------
# diff merging
# ---------------------------------------------------------------------------

def test_diffs_merge_into_contiguous_runs():
    # writes land at 0 and 2..3; bytes 1 and 4..5 stay wrong
    result = verify(
        [seg(0x00, b"\xFF" * 6)],
        [seg(0x00, b"\x00" * 6)],
        [write(0x00, b"\x00"), write(0x02, b"\x00\x00")],
    )
    assert result.operations_valid
    assert not result.matches_target
    assert [(d.start, d.end) for d in result.diffs] == [(0x01, 0x02), (0x04, 0x06)]
    assert result.diff_byte_count == 3
    assert sum(d.size for d in result.diffs) == 3


def test_extra_written_byte_becomes_diff():
    # target defines nothing at 1; an unnecessary 1->0 write leaves 0x00 != 0xFF
    result = verify(
        [seg(0, b"\xFF\xFF")],
        [seg(0, b"\x00")],
        [write(0x00, b"\x00\x00")],
    )
    assert [(d.start, d.end) for d in result.diffs] == [(1, 2)]


# ---------------------------------------------------------------------------
# parameter validation is shared with the planner
# ---------------------------------------------------------------------------

def test_unaligned_flash_window_reported_as_param_error():
    result = verify([], [], [erase(0, 0x40)], start=1, end=0x41)
    assert not result.ok
    assert result.params_valid is False
    assert [e.kind for e in result.param_errors] == ["erase_block_unaligned"]
    assert result.error is None
    assert result.executed_count == 0


def test_image_outside_flash_reported_as_param_error():
    result = verify([seg(0x100, b"\x00")], [], [])
    assert result.params_valid is False
    assert [e.kind for e in result.param_errors] == ["image_outside_flash"]


# ---------------------------------------------------------------------------
# API surface
# ---------------------------------------------------------------------------

def payload(current_hex, target_hex, operations, **overrides):
    body = {
        "current_hex": current_hex,
        "target_hex": target_hex,
        "flash_start": 0,
        "flash_end": 256,
        "erase_block_size": 64,
        "max_write_size": 16,
        "operations": operations,
    }
    body.update(overrides)
    return body


def api_write(address: int, data: bytes):
    return {
        "kind": "write",
        "address": address,
        "size": len(data),
        "data_base64": base64.b64encode(data).decode("ascii"),
    }


def api_erase(address: int, size: int):
    return {"kind": "erase", "address": address, "size": size, "data_base64": None}


def test_api_erase_rewrite_happy_path():
    current = "\n".join([data_rec(0x0000, bytes(range(16))), EOF_REC])
    target = "\n".join(
        [data_rec(0x0000, bytes([0xFF, *range(1, 16)])), EOF_REC]
    )
    resp = client.post(
        "/api/v1/verify-flash-operations",
        json=payload(
            current,
            target,
            [api_erase(0, 64), api_write(1, bytes(range(1, 16)))],
        ),
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True
    assert body["current_hex_ok"] is True
    assert body["target_hex_ok"] is True
    assert body["params_valid"] is True
    assert body["operations_valid"] is True
    assert body["matches_target"] is True
    assert body["illegal_index"] is None
    assert body["error_code"] is None
    assert body["operation_error"] is None
    assert body["diffs"] == []
    assert body["diff_byte_count"] == 0
    assert body["executed_count"] == 2
    assert body["operation_count"] == 2
    assert body["current_diagnostics"]
    assert body["target_diagnostics"]


def test_api_first_illegal_operation_reports_index_and_code():
    current = "\n".join([data_rec(0x0000, b"\x00\x0F"), EOF_REC])
    target = "\n".join([data_rec(0x0000, b"\x00\x00"), EOF_REC])
    operations = [
        api_write(0, b"\x00"),       # legal no-op-ish clear
        api_write(1, b"\xFF"),       # illegal 0 -> 1
        api_erase(0, 64),            # never reached
    ]
    resp = client.post(
        "/api/v1/verify-flash-operations",
        json=payload(current, target, operations),
    )
    body = resp.json()
    assert body["ok"] is False
    assert body["operations_valid"] is False
    assert body["matches_target"] is False
    assert body["illegal_index"] == 1
    assert body["error_code"] == "write_zero_to_one"
    assert body["operation_error"]["kind"] == "write_zero_to_one"
    assert body["operation_error"]["index"] == 1
    assert body["operation_error"]["start"] == 1
    assert body["executed_count"] == 1
    assert body["operation_count"] == 3
    assert body["diffs"] == []


def test_api_legal_ops_but_diffs_returns_merged_runs():
    current = "\n".join([data_rec(0x0000, b"\xFF" * 6), EOF_REC])
    target = "\n".join([data_rec(0x0000, b"\x00" * 6), EOF_REC])
    operations = [api_write(0, b"\x00"), api_write(2, b"\x00\x00")]
    resp = client.post(
        "/api/v1/verify-flash-operations",
        json=payload(current, target, operations),
    )
    body = resp.json()
    assert body["ok"] is False
    assert body["operations_valid"] is True
    assert body["matches_target"] is False
    assert body["illegal_index"] is None
    assert body["error_code"] is None
    assert body["executed_count"] == 2
    assert [(d["start"], d["end"], d["size"]) for d in body["diffs"]] == [
        (1, 2, 1),
        (4, 6, 2),
    ]
    assert body["diff_byte_count"] == 3


def test_api_unaligned_erase_rejected():
    hex_text = "\n".join([data_rec(0x0000, b"\x01"), EOF_REC])
    resp = client.post(
        "/api/v1/verify-flash-operations",
        json=payload(hex_text, hex_text, [api_erase(1, 64)]),
    )
    body = resp.json()
    assert body["ok"] is False
    assert body["illegal_index"] == 0
    assert body["error_code"] == "erase_not_block_aligned"
    assert body["executed_count"] == 0


def test_api_write_crossing_block_rejected():
    current = "\n".join([data_rec(0x003E, b"\xFF" * 6), EOF_REC])
    target = "\n".join([data_rec(0x003E, b"\x00" * 6), EOF_REC])
    resp = client.post(
        "/api/v1/verify-flash-operations",
        json=payload(current, target, [api_write(0x3E, b"\x00" * 6)]),
    )
    body = resp.json()
    assert body["error_code"] == "write_crosses_block"
    assert body["illegal_index"] == 0


def test_api_invalid_base64_payload_rejected():
    current = "\n".join([data_rec(0x0000, b"\xFF"), EOF_REC])
    target = "\n".join([data_rec(0x0000, b"\x00"), EOF_REC])
    operations = [
        {"kind": "write", "address": 0, "size": 1, "data_base64": "!!!not-b64"}
    ]
    resp = client.post(
        "/api/v1/verify-flash-operations",
        json=payload(current, target, operations),
    )
    body = resp.json()
    assert body["error_code"] == "write_data_invalid"
    assert body["illegal_index"] == 0


def test_api_payload_length_mismatch_rejected():
    current = "\n".join([data_rec(0x0000, b"\xFF\xFF"), EOF_REC])
    target = "\n".join([data_rec(0x0000, b"\x00\x00"), EOF_REC])
    operations = [
        {"kind": "write", "address": 0, "size": 2, "data_base64": "AA=="}
    ]
    resp = client.post(
        "/api/v1/verify-flash-operations",
        json=payload(current, target, operations),
    )
    body = resp.json()
    assert body["error_code"] == "write_data_size_mismatch"


def test_api_invalid_hex_returns_diagnostics_without_running():
    good = "\n".join([data_rec(0x0000, b"\x01"), EOF_REC])
    resp = client.post(
        "/api/v1/verify-flash-operations",
        json=payload(
            ":00000001FE\n",
            good,
            [api_erase(0, 64)],
        ),
    )
    body = resp.json()
    assert body["ok"] is False
    assert body["current_hex_ok"] is False
    assert body["target_hex_ok"] is True
    assert body["params_valid"] is None
    assert body["operations_valid"] is False
    assert body["executed_count"] == 0
    assert body["illegal_index"] is None
    assert body["operation_count"] == 1
    assert any("checksum" in d["message"] for d in body["current_diagnostics"])


def test_api_bad_params_return_param_errors_no_replay():
    hex_text = "\n".join([data_rec(0x0000, b"\x01"), EOF_REC])
    resp = client.post(
        "/api/v1/verify-flash-operations",
        json=payload(
            hex_text,
            hex_text,
            [api_erase(0, 64)],
            flash_start=1,
            flash_end=65,
        ),
    )
    body = resp.json()
    assert body["ok"] is False
    assert body["params_valid"] is False
    assert [e["kind"] for e in body["param_errors"]] == ["erase_block_unaligned"]
    assert body["illegal_index"] is None
    assert body["executed_count"] == 0


def test_api_planner_plan_round_trip():
    current_hex = "\n".join([data_rec(0x0000, b"\x00\x01\x02"), EOF_REC])
    target_hex = "\n".join([data_rec(0x0000, b"\xFF\x01\x03"), EOF_REC])
    planned = client.post(
        "/api/v1/plan-flash-update",
        json=payload(current_hex, target_hex, []),
    ).json()
    assert planned["ok"] is True
    resp = client.post(
        "/api/v1/verify-flash-operations",
        json=payload(current_hex, target_hex, planned["operations"]),
    )
    body = resp.json()
    assert body["ok"] is True
    assert body["matches_target"] is True
    assert body["diffs"] == []


def test_api_zero_size_returns_operation_error_not_422():
    hex_text = "\n".join([data_rec(0x0000, b"\x01"), EOF_REC])
    resp = client.post(
        "/api/v1/verify-flash-operations",
        json=payload(hex_text, hex_text, [{"kind": "erase", "address": 0, "size": 0}]),
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["error_code"] == "operation_outside_flash"
    assert body["illegal_index"] == 0


def test_api_missing_required_field_is_422():
    hex_text = "\n".join([data_rec(0x0000, b"\x01"), EOF_REC])
    resp = client.post(
        "/api/v1/verify-flash-operations",
        json={
            "current_hex": hex_text,
            "target_hex": hex_text,
            "flash_start": 0,
            "flash_end": 256,
            "erase_block_size": 64,
            "max_write_size": 16,
            # operations omitted
        },
    )
    assert resp.status_code == 422
