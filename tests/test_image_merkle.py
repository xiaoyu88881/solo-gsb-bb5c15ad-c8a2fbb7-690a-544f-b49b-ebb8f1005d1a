"""Tests for the chunked Merkle manifest module and /api/v1/image-merkle-manifest."""

import hashlib

import pytest
from fastapi.testclient import TestClient

from app.hex_parser import Segment, parse_intel_hex
from app.image_merkle import (
    ADDR_SPAN,
    MAX_CHUNKS,
    PARENT_TAG,
    build_image_merkle,
)
from app.main import app

client = TestClient(app)


def rec(rectype: int, addr: int, data: bytes = b"") -> str:
    """Build a valid Intel HEX record line."""
    body = bytes([len(data), (addr >> 8) & 0xFF, addr & 0xFF, rectype]) + bytes(data)
    checksum = (-sum(body)) & 0xFF
    return ":" + (body + bytes([checksum])).hex().upper()


EOF_REC = rec(0x01, 0)


def data_rec(addr: int, data: bytes) -> str:
    return rec(0x00, addr, data)


def linear_base(value: int) -> str:
    return rec(0x04, 0, value.to_bytes(2, "big"))


def leaf_hash(chunk_start: int, data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + (chunk_start & 0xFFFFFFFF).to_bytes(4, "big") + data).digest()


def parent_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(bytes([PARENT_TAG]) + left + right).digest()


def verify_proof(leaf: bytes, path: list[tuple[str, bytes]]) -> bytes:
    """Recompute the root from a leaf and a list of (direction, sibling) steps."""
    node = leaf
    for direction, sibling in path:
        node = (
            parent_hash(sibling, node)
            if direction == "left"
            else parent_hash(node, sibling)
        )
    return node


# A two-chunk image at 0x08000000: first chunk fully given, second all absent (0xFF).
HEX_TWO_CHUNKS = "\n".join([
    linear_base(0x0800),
    data_rec(0x0000, bytes(range(1, 9))),
    EOF_REC,
])
RANGE_START = 0x08000000
RANGE_END = 0x08000010
CHUNK_SIZE = 8


# ---------------------------------------------------------------------------
# pure tree logic
# ---------------------------------------------------------------------------

def test_leaves_bind_data_and_start_address():
    segments = [Segment(RANGE_START, bytes(range(1, 9)))]
    manifest = build_image_merkle(segments, RANGE_START, RANGE_END, CHUNK_SIZE, [])
    assert manifest.ok
    assert [c.start for c in manifest.chunks] == [0x08000000, 0x08000008]
    assert manifest.chunks[0].digest == leaf_hash(0x08000000, bytes(range(1, 9)))
    # Missing bytes materialize as 0xFF.
    assert manifest.chunks[1].digest == leaf_hash(0x08000008, b"\xff" * 8)


def test_two_chunk_root_is_parent_of_leaves():
    segments = [Segment(RANGE_START, bytes(range(1, 9)))]
    manifest = build_image_merkle(segments, RANGE_START, RANGE_END, CHUNK_SIZE, [])
    expected_root = parent_hash(manifest.chunks[0].digest, manifest.chunks[1].digest)
    assert manifest.root == expected_root
    assert manifest.chunk_count == 2


def test_single_chunk_root_is_leaf_and_proof_is_empty():
    segments = [Segment(RANGE_START, bytes(range(1, 9)))]
    manifest = build_image_merkle(
        segments, RANGE_START, RANGE_START + CHUNK_SIZE, CHUNK_SIZE, [RANGE_START]
    )
    assert manifest.chunk_count == 1
    assert manifest.root == manifest.chunks[0].digest
    proof = manifest.proofs[0]
    assert proof.leaf == manifest.root
    assert proof.path == []


def test_odd_level_duplicates_last_node():
    # Three chunks: leaves L0 L1 L2, level 1 = H(L0,L1) H(L2,L2), root pairs those.
    segments = [Segment(RANGE_START, bytes(range(1, 9)))]
    manifest = build_image_merkle(
        segments, RANGE_START, RANGE_START + 3 * CHUNK_SIZE, CHUNK_SIZE, []
    )
    leaves = [c.digest for c in manifest.chunks]
    expected_root = parent_hash(
        parent_hash(leaves[0], leaves[1]),
        parent_hash(leaves[2], leaves[2]),
    )
    assert manifest.root == expected_root


def test_proofs_verify_for_every_leaf_position():
    segments = [Segment(RANGE_START, bytes(range(1, 9)))]
    range_end = RANGE_START + 5 * CHUNK_SIZE  # 5 leaves -> 3 -> 2 -> 1
    addresses = [RANGE_START + i * CHUNK_SIZE + 3 for i in range(5)]
    manifest = build_image_merkle(segments, RANGE_START, range_end, CHUNK_SIZE, addresses)
    assert len(manifest.proofs) == 5
    for proof in manifest.proofs:
        assert proof.address in addresses
        recomputed = verify_proof(
            proof.leaf, [(step.direction, step.digest) for step in proof.path]
        )
        assert recomputed == manifest.root
        # Direction sanity: steps alternate by level, and the sibling at each
        # level is the node immediately beside the current index.
        assert all(step.direction in ("left", "right") for step in proof.path)


def test_proof_chunk_contains_address_and_path_order():
    segments = [Segment(RANGE_START, bytes(range(1, 9)))]
    manifest = build_image_merkle(
        segments,
        RANGE_START,
        RANGE_START + 3 * CHUNK_SIZE,
        CHUNK_SIZE,
        [RANGE_START + 2 * CHUNK_SIZE + 7],
    )
    proof = manifest.proofs[0]
    assert proof.chunk_index == 2
    assert proof.chunk_start == RANGE_START + 16
    assert proof.chunk_end == RANGE_START + 24
    # Leaf 2 (even index) first pairs with its duplicated self ("right"
    # sibling), then the resulting node is the right child ("left" sibling).
    assert [step.direction for step in proof.path] == ["right", "left"]


def test_partial_segment_spanning_chunks_is_mapped_per_byte():
    # Four explicit bytes starting at offset 6: 2 in chunk 0, 2 in chunk 1;
    # everything else materializes as 0xFF.
    segments = [Segment(RANGE_START + 6, b"\x01\x02\x03\x04")]
    manifest = build_image_merkle(segments, RANGE_START, RANGE_END, CHUNK_SIZE, [])
    chunk0 = b"\xff" * 6 + b"\x01\x02"
    chunk1 = b"\x03\x04" + b"\xff" * 6
    assert manifest.chunks[0].digest == leaf_hash(RANGE_START, chunk0)
    assert manifest.chunks[1].digest == leaf_hash(RANGE_START + 8, chunk1)


def test_identical_content_at_different_address_hashes_differ():
    data = b"\x00" * CHUNK_SIZE
    a = build_image_merkle([Segment(0, data)], 0, CHUNK_SIZE, CHUNK_SIZE, [])
    b = build_image_merkle(
        [Segment(CHUNK_SIZE, data)], CHUNK_SIZE, 2 * CHUNK_SIZE, CHUNK_SIZE, []
    )
    assert a.root != b.root


def test_fragmentation_does_not_change_tree():
    one = [Segment(RANGE_START, bytes(range(1, 9)))]
    many = [
        Segment(RANGE_START, bytes(range(1, 4))),
        Segment(RANGE_START + 3, bytes(range(4, 9))),
        Segment(RANGE_START + 1, bytes(range(2, 4))),  # identical rewrite
    ]
    a = build_image_merkle(one, RANGE_START, RANGE_END, CHUNK_SIZE, [])
    b = build_image_merkle(many, RANGE_START, RANGE_END, CHUNK_SIZE, [])
    assert a.root == b.root
    assert [c.digest for c in a.chunks] == [c.digest for c in b.chunks]


# ---------------------------------------------------------------------------
# parameter validation (pure logic)
# ---------------------------------------------------------------------------

def test_invalid_range_reported_before_other_checks():
    for start, end in ((0, 0), (100, 50), (-1, 8), (0, ADDR_SPAN + 1)):
        manifest = build_image_merkle([], start, end, CHUNK_SIZE, [])
        assert manifest.params_valid is False
        assert manifest.root is None
        kinds = {e.kind for e in manifest.param_errors}
        assert "invalid_range" in kinds


def test_unaligned_range_ends_are_rejected():
    manifest = build_image_merkle(
        [], RANGE_START, RANGE_END - 1, CHUNK_SIZE, []
    )
    assert manifest.params_valid is False
    assert {e.kind for e in manifest.param_errors} == {"range_not_aligned"}
    error = manifest.param_errors[0]
    assert error.start == RANGE_START
    assert error.end == RANGE_END - 1
    assert error.chunk_size == CHUNK_SIZE


def test_aligned_range_start_unaligned_end_only_reports_end():
    manifest = build_image_merkle([], 0x10, 0x17, 8, [])
    assert manifest.params_valid is False
    assert manifest.param_errors[0].kind == "range_not_aligned"


def test_non_positive_chunk_size_rejected():
    manifest = build_image_merkle([], 0, 16, 0, [])
    assert manifest.params_valid is False
    assert manifest.param_errors[0].kind == "invalid_chunk_size"


def test_too_many_chunks_rejected():
    # One chunk over the cap must not build a tree.
    manifest = build_image_merkle(
        [],
        0,
        (MAX_CHUNKS + 1) * CHUNK_SIZE,
        CHUNK_SIZE,
        [],
    )
    assert manifest.params_valid is False
    error = manifest.param_errors[0]
    assert error.kind == "too_many_chunks"
    assert error.chunk_count == MAX_CHUNKS + 1


def test_exactly_max_chunks_allowed():
    manifest = build_image_merkle([], 0, MAX_CHUNKS, 1, [])
    assert manifest.params_valid is True
    assert manifest.chunk_count == MAX_CHUNKS


def test_image_bytes_outside_range_rejected():
    segments = [Segment(RANGE_END - 2, b"\x01\x02\x03")]  # 1 byte past end
    manifest = build_image_merkle(segments, RANGE_START, RANGE_END, CHUNK_SIZE, [])
    assert manifest.params_valid is False
    error = manifest.param_errors[0]
    assert error.kind == "image_outside_range"
    assert (error.start, error.end) == (RANGE_END, RANGE_END + 1)
    assert manifest.root is None
    assert manifest.chunks == []


def test_image_bytes_below_range_start_rejected():
    segments = [Segment(RANGE_START - 1, b"\x01\x02")]
    manifest = build_image_merkle(segments, RANGE_START, RANGE_END, CHUNK_SIZE, [])
    assert manifest.params_valid is False
    error = manifest.param_errors[0]
    assert error.kind == "image_outside_range"
    assert (error.start, error.end) == (RANGE_START - 1, RANGE_START)


def test_proof_address_outside_range_rejected():
    manifest = build_image_merkle(
        [], RANGE_START, RANGE_END, CHUNK_SIZE, [RANGE_START + 1, RANGE_END]
    )
    assert manifest.params_valid is False
    error = manifest.param_errors[0]
    assert error.kind == "proof_outside_range"
    assert error.address == RANGE_END
    assert error.proof_index == 1


def test_range_end_address_is_not_inside_half_open_window():
    manifest = build_image_merkle(
        [], RANGE_START, RANGE_END, CHUNK_SIZE, [RANGE_END - 1, RANGE_END]
    )
    kinds = {e.kind for e in manifest.param_errors}
    assert kinds == {"proof_outside_range"}


# ---------------------------------------------------------------------------
# API surface
# ---------------------------------------------------------------------------

def test_api_happy_path_returns_root_chunks_and_proofs():
    resp = client.post(
        "/api/v1/image-merkle-manifest",
        json={
            "hex_text": HEX_TWO_CHUNKS,
            "range_start": RANGE_START,
            "range_end": RANGE_END,
            "chunk_size": CHUNK_SIZE,
            "proof_addresses": [0x08000002],
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True
    assert body["hex_ok"] is True
    assert body["params_valid"] is True
    assert body["chunk_count"] == 2
    assert body["max_chunks"] == MAX_CHUNKS
    assert body["range_start"] == RANGE_START
    assert body["range_end"] == RANGE_END
    assert body["chunk_size"] == CHUNK_SIZE
    assert body["param_errors"] == []

    parsed = parse_intel_hex(HEX_TWO_CHUNKS)
    expected = build_image_merkle(
        parsed.segments, RANGE_START, RANGE_END, CHUNK_SIZE, [0x08000002]
    )
    assert body["root"] == expected.root.hex()
    assert len(body["chunks"]) == 2
    assert body["chunks"][0] == {
        "index": 0,
        "start": 0x08000000,
        "end": 0x08000008,
        "digest": expected.chunks[0].digest.hex(),
    }
    assert body["chunks"][1]["digest"] == expected.chunks[1].digest.hex()

    proof = body["proofs"][0]
    assert proof["address"] == 0x08000002
    assert proof["chunk_index"] == 0
    assert proof["chunk_start"] == 0x08000000
    assert proof["chunk_end"] == 0x08000008
    assert proof["leaf"] == expected.chunks[0].digest.hex()
    assert proof["path"] == [
        {"direction": "right", "digest": expected.chunks[1].digest.hex()}
    ]
    # Path from the API must verify against the API root.
    recomputed = verify_proof(
        bytes.fromhex(proof["leaf"]),
        [(s["direction"], bytes.fromhex(s["digest"])) for s in proof["path"]],
    )
    assert recomputed.hex() == body["root"]
    assert body["error_count"] == 0


def test_api_proof_for_missing_bytes_uses_ff_materialization():
    resp = client.post(
        "/api/v1/image-merkle-manifest",
        json={
            "hex_text": HEX_TWO_CHUNKS,
            "range_start": RANGE_START,
            "range_end": RANGE_END,
            "chunk_size": CHUNK_SIZE,
            "proof_addresses": [0x0800000F],
        },
    )
    body = resp.json()
    assert body["ok"] is True
    proof = body["proofs"][0]
    assert proof["chunk_index"] == 1
    assert proof["leaf"] == leaf_hash(0x08000008, b"\xff" * 8).hex()
    recomputed = verify_proof(
        bytes.fromhex(proof["leaf"]),
        [(s["direction"], bytes.fromhex(s["digest"])) for s in proof["path"]],
    )
    assert recomputed.hex() == body["root"]


def test_api_proof_addresses_default_to_empty_list():
    body = client.post(
        "/api/v1/image-merkle-manifest",
        json={
            "hex_text": HEX_TWO_CHUNKS,
            "range_start": RANGE_START,
            "range_end": RANGE_END,
            "chunk_size": CHUNK_SIZE,
        },
    ).json()
    assert body["ok"] is True
    assert body["proofs"] == []


def test_api_invalid_hex_does_not_build_tree():
    resp = client.post(
        "/api/v1/image-merkle-manifest",
        json={
            "hex_text": ":00000001FE\n",  # bad checksum, no EOF
            "range_start": RANGE_START,
            "range_end": RANGE_END,
            "chunk_size": CHUNK_SIZE,
            "proof_addresses": [RANGE_START],
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is False
    assert body["hex_ok"] is False
    assert body["params_valid"] is None
    assert body["error_count"] >= 1
    assert body["root"] is None
    assert body["chunks"] == []
    assert body["proofs"] == []
    assert body["chunk_count"] == 0
    assert body["param_errors"] == []
    assert len(body["diagnostics"]) == body["error_count"] + body["warning_count"]


def test_api_unaligned_range_returns_diagnostic():
    resp = client.post(
        "/api/v1/image-merkle-manifest",
        json={
            "hex_text": HEX_TWO_CHUNKS,
            "range_start": RANGE_START,
            "range_end": RANGE_END - 1,
            "chunk_size": CHUNK_SIZE,
            "proof_addresses": [],
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is False
    assert body["hex_ok"] is True
    assert body["params_valid"] is False
    assert body["root"] is None
    assert body["chunks"] == []
    error = body["param_errors"][0]
    assert error["kind"] == "range_not_aligned"
    assert error["start"] == RANGE_START
    assert error["end"] == RANGE_END - 1
    assert "aligned" in error["message"]


def test_api_out_of_range_image_rejected():
    # Data bytes at 0x0800000E..0x08000010; the last byte is past the window end.
    hex_text = "\n".join([
        linear_base(0x0800),
        data_rec(0x000E, b"\x01\x02\x03"),
        EOF_REC,
    ])
    body = client.post(
        "/api/v1/image-merkle-manifest",
        json={
            "hex_text": hex_text,
            "range_start": RANGE_START,
            "range_end": RANGE_END,
            "chunk_size": CHUNK_SIZE,
            "proof_addresses": [],
        },
    ).json()
    assert body["ok"] is False
    assert body["params_valid"] is False
    assert {e["kind"] for e in body["param_errors"]} == {"image_outside_range"}
    assert body["root"] is None


def test_api_proof_outside_range_rejected_with_index():
    body = client.post(
        "/api/v1/image-merkle-manifest",
        json={
            "hex_text": HEX_TWO_CHUNKS,
            "range_start": RANGE_START,
            "range_end": RANGE_END,
            "chunk_size": CHUNK_SIZE,
            "proof_addresses": [RANGE_END + 5],
        },
    ).json()
    assert body["ok"] is False
    assert body["params_valid"] is False
    error = body["param_errors"][0]
    assert error["kind"] == "proof_outside_range"
    assert error["address"] == RANGE_END + 5
    assert error["proof_index"] == 0
    assert body["proofs"] == []


def test_api_too_many_chunks_rejected():
    body = client.post(
        "/api/v1/image-merkle-manifest",
        json={
            "hex_text": HEX_TWO_CHUNKS,
            "range_start": 0,
            "range_end": (MAX_CHUNKS + 1) * 8,
            "chunk_size": 8,
            "proof_addresses": [],
        },
    ).json()
    assert body["ok"] is False
    assert body["params_valid"] is False
    assert body["param_errors"][0]["kind"] == "too_many_chunks"
    assert body["root"] is None


@pytest.mark.parametrize(
    "payload",
    [
        {"range_start": -1, "range_end": 8, "chunk_size": 8},
        {"range_start": 0, "range_end": -8, "chunk_size": 8},
        {"range_start": 0, "range_end": 8, "chunk_size": 0},
        {"range_start": 0, "range_end": 8, "chunk_size": -1},
    ],
)
def test_api_schema_level_constraints_return_422(payload):
    payload["hex_text"] = HEX_TWO_CHUNKS
    resp = client.post("/api/v1/image-merkle-manifest", json=payload)
    assert resp.status_code == 422


def test_api_negative_proof_address_returns_logic_diagnostic_not_422():
    # Proof addresses are range-checked by the manifest logic, so a negative
    # value surfaces as proof_outside_range rather than a schema error.
    body = client.post(
        "/api/v1/image-merkle-manifest",
        json={
            "hex_text": HEX_TWO_CHUNKS,
            "range_start": RANGE_START,
            "range_end": RANGE_END,
            "chunk_size": CHUNK_SIZE,
            "proof_addresses": [-1],
        },
    ).json()
    assert body["ok"] is False
    assert body["params_valid"] is False
    assert body["param_errors"][0]["kind"] == "proof_outside_range"
    assert body["param_errors"][0]["address"] == -1


def test_api_proofs_returned_in_request_order_for_odd_tree():
    addresses = [0x08000012, 0x08000000, 0x0800000A]  # chunks 2, 0, 1
    body = client.post(
        "/api/v1/image-merkle-manifest",
        json={
            "hex_text": HEX_TWO_CHUNKS,
            "range_start": RANGE_START,
            "range_end": RANGE_START + 3 * CHUNK_SIZE,
            "chunk_size": CHUNK_SIZE,
            "proof_addresses": addresses,
        },
    ).json()
    assert body["ok"] is True
    assert [p["address"] for p in body["proofs"]] == addresses
    root = bytes.fromhex(body["root"])
    for proof in body["proofs"]:
        recomputed = verify_proof(
            bytes.fromhex(proof["leaf"]),
            [(s["direction"], bytes.fromhex(s["digest"])) for s in proof["path"]],
        )
        assert recomputed == root


def test_api_record_splitting_gives_same_root():
    one = "\n".join([
        linear_base(0x0800),
        data_rec(0x0000, bytes(range(1, 9))),
        EOF_REC,
    ])
    two = "\n".join([
        linear_base(0x0800),
        data_rec(0x0000, bytes(range(1, 4))),
        data_rec(0x0003, bytes(range(4, 9))),
        EOF_REC,
    ])
    payload = {
        "range_start": RANGE_START,
        "range_end": RANGE_END,
        "chunk_size": CHUNK_SIZE,
        "proof_addresses": [0x08000005],
    }
    a = client.post(
        "/api/v1/image-merkle-manifest", json={**payload, "hex_text": one}
    ).json()
    b = client.post(
        "/api/v1/image-merkle-manifest", json={**payload, "hex_text": two}
    ).json()
    assert a["root"] == b["root"]
    assert [c["digest"] for c in a["chunks"]] == [c["digest"] for c in b["chunks"]]
