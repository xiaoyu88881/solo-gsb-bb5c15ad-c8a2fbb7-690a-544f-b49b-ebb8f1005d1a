"""Tests for the chunk Merkle manifest module and /api/v1/image-merkle-manifest."""

import hashlib

import pytest
from fastapi.testclient import TestClient

from app.hex_parser import Segment, parse_intel_hex
from app.image_merkle import (
    HASH_ALGORITHM,
    LEAF_TAG,
    MAX_CHUNKS,
    PARENT_TAG,
    build_merkle_manifest,
    leaf_hash,
    validate_merkle_params,
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


def independent_leaf(chunk_start: int, data: bytes) -> bytes:
    return hashlib.sha256(
        bytes([LEAF_TAG]) + chunk_start.to_bytes(4, "big") + data
    ).digest()


def fold_proof(leaf: bytes, steps) -> str:
    """Independently fold a directional sibling path up to the root."""
    running = leaf
    for step in steps:
        sibling = bytes.fromhex(
            step.sibling_sha256 if hasattr(step, "sibling_sha256") else step["sibling_sha256"]
        )
        direction = step.direction if hasattr(step, "direction") else step["direction"]
        if direction == "left":
            running = hashlib.sha256(bytes([PARENT_TAG]) + sibling + running).digest()
        else:
            running = hashlib.sha256(bytes([PARENT_TAG]) + running + sibling).digest()
    return running.hex()


def build_root_independent(leaves: list[bytes]) -> str:
    """Build the same duplicated-last-node tree from leaf hashes."""
    level = leaves
    while len(level) > 1:
        if len(level) % 2:
            level = level + [level[-1]]
        level = [
            hashlib.sha256(bytes([PARENT_TAG]) + level[i] + level[i + 1]).digest()
            for i in range(0, len(level), 2)
        ]
    return level[0].hex()


# ---------------------------------------------------------------------------
# parameter validation
# ---------------------------------------------------------------------------

def test_valid_params_have_no_errors():
    assert validate_merkle_params(0, 16, 16, [0, 15]) == []


def test_range_must_be_non_empty_half_open_interval():
    errors = validate_merkle_params(16, 16, 4, [])
    assert [e.kind for e in errors] == ["invalid_range"]
    errors = validate_merkle_params(32, 16, 4, [])
    assert [e.kind for e in errors] == ["invalid_range"]


def test_range_end_may_not_leave_32_bit_space():
    errors = validate_merkle_params(0, 1 << 33, 1 << 32, [])
    assert [e.kind for e in errors] == ["invalid_range"]
    # the very end of the 32-bit space is allowed when aligned
    assert validate_merkle_params(0, 1 << 32, 1 << 32, []) == []


def test_both_endpoints_must_be_chunk_aligned():
    errors = validate_merkle_params(1, 16, 4, [])
    assert len(errors) == 1 and errors[0].kind == "range_unaligned"
    errors = validate_merkle_params(0, 18, 4, [])
    assert [e.kind for e in errors] == ["range_unaligned"]
    errors = validate_merkle_params(2, 17, 4, [])
    assert [e.kind for e in errors] == ["range_unaligned"]


def test_chunk_count_is_capped_at_4096():
    assert validate_merkle_params(0, MAX_CHUNKS, 1, []) == []
    errors = validate_merkle_params(0, MAX_CHUNKS + 1, 1, [])
    assert len(errors) == 1
    assert errors[0].kind == "too_many_chunks"
    assert str(MAX_CHUNKS) in errors[0].message


def test_proof_addresses_must_lie_inside_the_range():
    errors = validate_merkle_params(16, 32, 4, [15, 32, 40, -1])
    kinds = [(e.kind, e.address) for e in errors]
    assert kinds == [
        ("proof_address_out_of_range", 15),
        ("proof_address_out_of_range", 32),
        ("proof_address_out_of_range", 40),
        ("proof_address_out_of_range", -1),
    ]
    # the last valid address is range_end - 1
    assert validate_merkle_params(16, 32, 4, [31]) == []


def test_several_error_classes_are_reported_together():
    errors = validate_merkle_params(1, 16, 4, [16])
    assert {e.kind for e in errors} == {"range_unaligned", "proof_address_out_of_range"}


# ---------------------------------------------------------------------------
# leaf / tree semantics (pure logic)
# ---------------------------------------------------------------------------

def test_leaf_hash_binds_u32be_start_and_bytes():
    data = b"\xAA" * 8
    expected = hashlib.sha256(
        bytes([LEAF_TAG]) + (0x08000000).to_bytes(4, "big") + data
    ).digest()
    assert leaf_hash(0x08000000, data) == expected
    # identical bytes at another address hash differently
    assert leaf_hash(0x08000001, data) != expected


def test_missing_bytes_are_materialized_as_ff():
    manifest = build_merkle_manifest(
        [Segment(4, b"\x01\x02")], 0, 12, 4, []
    )
    assert manifest.ok
    assert manifest.chunks[0].sha256 == independent_leaf(0, b"\xff" * 4).hex()
    assert manifest.chunks[1].sha256 == independent_leaf(4, b"\x01\x02\xff\xff").hex()
    assert manifest.chunks[2].sha256 == independent_leaf(8, b"\xff" * 4).hex()
    assert [c.present_bytes for c in manifest.chunks] == [0, 2, 0]
    assert manifest.root_sha256 == build_root_independent(
        [bytes.fromhex(c.sha256) for c in manifest.chunks]
    )


def test_image_bytes_outside_the_range_are_clipped():
    # segment starts before and extends past the range; only in-range bytes count
    manifest = build_merkle_manifest(
        [Segment(0x08000000, b"\x00\x01\x02\x03\x04\x05\x06\x07")],
        0x08000002,
        0x08000006,
        2,
        [],
    )
    assert manifest.ok
    assert manifest.chunks[0].sha256 == independent_leaf(0x08000002, b"\x02\x03").hex()
    assert manifest.chunks[1].sha256 == independent_leaf(0x08000004, b"\x04\x05").hex()
    assert [c.present_bytes for c in manifest.chunks] == [2, 2]


def test_single_chunk_root_is_the_leaf():
    manifest = build_merkle_manifest([], 0, 16, 16, [0])
    assert manifest.chunk_count == 1
    assert manifest.root_sha256 == manifest.chunks[0].sha256
    proof = manifest.proofs[0]
    assert proof.steps == []
    assert proof.leaf_sha256 == manifest.root_sha256
    assert proof.chunk_index == 0 and proof.offset == 0


def test_two_chunk_proof_directions():
    manifest = build_merkle_manifest([], 0, 8, 4, [0, 7])
    assert manifest.chunk_count == 2
    assert manifest.chunks[1].start == 4
    left_proof, right_proof = manifest.proofs
    assert [s.direction for s in left_proof.steps] == ["right"]
    assert [s.direction for s in right_proof.steps] == ["left"]
    assert all(not s.duplicated for p in manifest.proofs for s in p.steps)
    for proof in manifest.proofs:
        assert fold_proof(bytes.fromhex(proof.leaf_sha256), proof.steps) == manifest.root_sha256


def test_odd_levels_duplicate_the_last_node_and_all_proofs_verify():
    chunk_size = 4
    manifest = build_merkle_manifest([], 0, 5 * chunk_size, chunk_size, list(range(0, 20, 3)))
    assert manifest.chunk_count == 5
    # independently recompute the root from the exported leaf hashes
    leaves = [bytes.fromhex(c.sha256) for c in manifest.chunks]
    assert manifest.root_sha256 == build_root_independent(leaves)

    by_addr = {p.address: p for p in manifest.proofs}
    last = by_addr[18]  # address 18 -> chunk 4, the duplicated leaf twice on the way up
    assert [s.direction for s in last.steps] == ["right", "right", "left"]
    assert [s.duplicated for s in last.steps] == [True, True, False]
    assert [s.sibling_index for s in last.steps] == [4, 2, 0]

    middle = by_addr[6]  # chunk 1 -> node 0 at level 1 (pairs with node 1), right sibling
    assert [s.direction for s in middle.steps] == ["left", "right", "right"]
    assert [s.duplicated for s in middle.steps] == [False, False, False]
    assert [s.sibling_index for s in middle.steps] == [0, 1, 1]

    for proof in manifest.proofs:
        assert proof.steps[0].level == 0
        assert [s.level for s in proof.steps] == list(range(len(proof.steps)))
        assert fold_proof(bytes.fromhex(proof.leaf_sha256), proof.steps) == manifest.root_sha256


def test_addresses_in_the_same_chunk_share_the_same_path():
    manifest = build_merkle_manifest([], 0, 16, 8, [1, 7])
    p0, p1 = manifest.proofs
    assert p0.chunk_index == p1.chunk_index == 0
    assert p0.offset == 1 and p1.offset == 7
    assert [s.sibling_sha256 for s in p0.steps] == [s.sibling_sha256 for s in p1.steps]


def test_u32_range_edge_chunk_start_uses_four_bytes():
    # last possible 16-byte chunk of the 32-bit space
    manifest = build_merkle_manifest([], 0xFFFFFFF0, 0x100000000, 16, [0xFFFFFFFF])
    assert manifest.ok
    proof = manifest.proofs[0]
    assert proof.chunk_start == 0xFFFFFFF0 and proof.offset == 15
    assert proof.leaf_sha256 == hashlib.sha256(
        bytes([LEAF_TAG]) + b"\xff\xff\xff\xf0" + b"\xff" * 16
    ).hexdigest()


def test_param_failure_builds_no_tree():
    manifest = build_merkle_manifest([], 3, 16, 4, [20])
    assert not manifest.ok
    assert manifest.params_valid is False
    assert manifest.root_sha256 is None
    assert manifest.chunks == []
    assert manifest.proofs == []
    assert {e.kind for e in manifest.param_errors} == {
        "range_unaligned",
        "proof_address_out_of_range",
    }


def test_chunk_size_cap_accepts_exactly_4096_chunks():
    manifest = build_merkle_manifest([], 0, 4096, 1, [4095])
    assert manifest.ok and manifest.chunk_count == 4096
    proof = manifest.proofs[0]
    assert fold_proof(bytes.fromhex(proof.leaf_sha256), proof.steps) == manifest.root_sha256


# ---------------------------------------------------------------------------
# API surface
# ---------------------------------------------------------------------------

def test_api_happy_path_sparse_range_and_proofs():
    text = "\n".join([
        linear_base(0x0800),
        data_rec(0x0000, b"\x01\x02\x03\x04\x05\x06\x07\x08"),
        EOF,
    ])
    resp = client.post(
        "/api/v1/image-merkle-manifest",
        json={
            "hex_text": text,
            "range_start": 0x08000000,
            "range_end": 0x08000020,
            "chunk_size": 16,
            "proof_addresses": [0x08000002, 0x08000010],
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True
    assert body["hex_ok"] is True
    assert body["params_valid"] is True
    assert body["error_count"] == 0
    assert body["range_start"] == 0x08000000
    assert body["range_end"] == 0x08000020
    assert body["chunk_size"] == 16
    assert body["chunk_count"] == 2
    assert body["max_chunks"] == MAX_CHUNKS
    assert body["param_errors"] == []

    chunks = body["chunks"]
    assert [c["index"] for c in chunks] == [0, 1]
    assert chunks[0]["start"] == 0x08000000 and chunks[0]["end"] == 0x08000010
    assert chunks[0]["size"] == 16 and chunks[0]["present_bytes"] == 8
    assert chunks[1]["present_bytes"] == 0
    expected_leaf_0 = independent_leaf(
        0x08000000, b"\x01\x02\x03\x04\x05\x06\x07\x08" + b"\xff" * 8
    ).hex()
    assert chunks[0]["sha256"] == expected_leaf_0
    expected_leaf_1 = independent_leaf(0x08000010, b"\xff" * 16).hex()
    assert chunks[1]["sha256"] == expected_leaf_1

    expected_root = hashlib.sha256(
        bytes([PARENT_TAG]) + bytes.fromhex(expected_leaf_0) + bytes.fromhex(expected_leaf_1)
    ).hexdigest()
    assert body["root_sha256"] == expected_root

    proofs = body["proofs"]
    assert [p["address"] for p in proofs] == [0x08000002, 0x08000010]
    p0, p1 = proofs
    assert p0["chunk_index"] == 0 and p0["offset"] == 2
    assert p0["chunk_start"] == 0x08000000 and p0["chunk_end"] == 0x08000010
    assert p0["leaf_sha256"] == expected_leaf_0
    assert [s["direction"] for s in p0["steps"]] == ["right"]
    assert p0["steps"][0]["sibling_sha256"] == expected_leaf_1
    assert p0["steps"][0]["duplicated"] is False
    assert p1["chunk_index"] == 1 and p1["offset"] == 0
    assert [s["direction"] for s in p1["steps"]] == ["left"]
    for proof in proofs:
        assert fold_proof(bytes.fromhex(proof["leaf_sha256"]), proof["steps"]) == expected_root

    # parse diagnostics of the shared parser are preserved
    assert any(d["record_type"] == "extended_linear_address" for d in body["diagnostics"])


def test_api_proofs_verify_for_five_chunks_with_duplication():
    text = "\n".join([EOF])
    resp = client.post(
        "/api/v1/image-merkle-manifest",
        json={
            "hex_text": text,
            "range_start": 0,
            "range_end": 20,
            "chunk_size": 4,
            "proof_addresses": [0, 4, 8, 12, 16, 19],
        },
    )
    body = resp.json()
    assert body["ok"] is True and body["chunk_count"] == 5
    root = body["root_sha256"]
    leaves = {c["index"]: c["sha256"] for c in body["chunks"]}
    for proof in body["proofs"]:
        assert proof["leaf_sha256"] == leaves[proof["chunk_index"]]
        assert fold_proof(bytes.fromhex(proof["leaf_sha256"]), proof["steps"]) == root


def test_api_invalid_hex_does_not_validate_params_or_build_tree():
    resp = client.post(
        "/api/v1/image-merkle-manifest",
        json={
            "hex_text": ":00000001FE\n",  # bad checksum, no EOF
            "range_start": 0,
            "range_end": 16,
            "chunk_size": 16,
            "proof_addresses": [0],
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is False
    assert body["hex_ok"] is False
    assert body["params_valid"] is None
    assert body["root_sha256"] is None
    assert body["chunks"] == []
    assert body["proofs"] == []
    assert body["param_errors"] == []
    assert body["chunk_count"] == 0
    assert body["error_count"] >= 1


def test_api_unaligned_range_and_out_of_range_proof():
    text = "\n".join([data_rec(0x0000, b"\x01"), EOF])
    resp = client.post(
        "/api/v1/image-merkle-manifest",
        json={
            "hex_text": text,
            "range_start": 1,
            "range_end": 16,
            "chunk_size": 4,
            "proof_addresses": [16],
        },
    )
    body = resp.json()
    assert body["ok"] is False
    assert body["hex_ok"] is True
    assert body["params_valid"] is False
    assert body["root_sha256"] is None
    assert body["chunks"] == [] and body["proofs"] == []
    kinds = {e["kind"] for e in body["param_errors"]}
    assert kinds == {"range_unaligned", "proof_address_out_of_range"}
    err = next(e for e in body["param_errors"] if e["kind"] == "proof_address_out_of_range")
    assert err["address"] == 16
    assert err["start"] == 1 and err["end"] == 16


def test_api_empty_or_excessive_range():
    text = "\n".join([EOF])
    body = client.post(
        "/api/v1/image-merkle-manifest",
        json={
            "hex_text": text,
            "range_start": 16,
            "range_end": 16,
            "chunk_size": 4,
            "proof_addresses": [],
        },
    ).json()
    assert body["params_valid"] is False
    assert [e["kind"] for e in body["param_errors"]] == ["invalid_range"]

    body = client.post(
        "/api/v1/image-merkle-manifest",
        json={
            "hex_text": text,
            "range_start": 0,
            "range_end": 0x100000001,
            "chunk_size": 0x100000000,
            "proof_addresses": [],
        },
    ).json()
    assert [e["kind"] for e in body["param_errors"]] == ["invalid_range"]


def test_api_too_many_chunks():
    text = "\n".join([EOF])
    body = client.post(
        "/api/v1/image-merkle-manifest",
        json={
            "hex_text": text,
            "range_start": 0,
            "range_end": MAX_CHUNKS + 1,
            "chunk_size": 1,
            "proof_addresses": [],
        },
    ).json()
    assert body["ok"] is False
    assert body["params_valid"] is False
    assert [e["kind"] for e in body["param_errors"]] == ["too_many_chunks"]
    assert body["chunk_count"] == MAX_CHUNKS + 1
    assert body["root_sha256"] is None


def test_api_negative_proof_address_is_a_param_error_not_422():
    text = "\n".join([EOF])
    body = client.post(
        "/api/v1/image-merkle-manifest",
        json={
            "hex_text": text,
            "range_start": 0,
            "range_end": 16,
            "chunk_size": 4,
            "proof_addresses": [-4],
        },
    ).json()
    assert [e["kind"] for e in body["param_errors"]] == ["proof_address_out_of_range"]


@pytest.mark.parametrize(
    "payload",
    [
        {"chunk_size": 0},
        {"chunk_size": -1},
        {"range_start": -1},
        {"range_end": -1},
        {"proof_addresses": [None]},
        {"hex_text": 123},
    ],
)
def test_api_schema_rejects_bad_types_and_non_positive_chunk_size(payload):
    request = {
        "hex_text": "\n".join([EOF]),
        "range_start": 0,
        "range_end": 16,
        "chunk_size": 4,
        "proof_addresses": [],
    }
    request.update(payload)
    resp = client.post("/api/v1/image-merkle-manifest", json=request)
    assert resp.status_code == 422


def test_api_root_is_stable_across_record_splitting():
    payload = bytes(range(8))
    one = "\n".join([linear_base(0x0800), data_rec(0x0000, payload), EOF])
    many = "\n".join([
        linear_base(0x0800),
        data_rec(0x0000, payload[:3]),
        data_rec(0x0003, payload[3:]),
        EOF,
    ])
    request = {
        "range_start": 0x08000000,
        "range_end": 0x08000010,
        "chunk_size": 16,
        "proof_addresses": [0x08000007],
    }
    a = client.post("/api/v1/image-merkle-manifest", json={**request, "hex_text": one}).json()
    b = client.post("/api/v1/image-merkle-manifest", json={**request, "hex_text": many}).json()
    assert a["root_sha256"] == b["root_sha256"]
    assert [c["sha256"] for c in a["chunks"]] == [c["sha256"] for c in b["chunks"]]
    parsed = parse_intel_hex(one)
    manifest = build_merkle_manifest(
        parsed.segments, 0x08000000, 0x08000010, 16, [0x08000007]
    )
    assert a["root_sha256"] == manifest.root_sha256


def test_api_entry_address_is_echoed():
    text = "\n".join([
        linear_base(0x0800),
        data_rec(0x0000, b"\x01"),
        rec(0x05, 0, (0x080001C1).to_bytes(4, "big")),
        EOF,
    ])
    body = client.post(
        "/api/v1/image-merkle-manifest",
        json={
            "hex_text": text,
            "range_start": 0x08000000,
            "range_end": 0x08000010,
            "chunk_size": 16,
            "proof_addresses": [],
        },
    ).json()
    assert body["entry_address"] == 0x080001C1
    assert body["proofs"] == []
