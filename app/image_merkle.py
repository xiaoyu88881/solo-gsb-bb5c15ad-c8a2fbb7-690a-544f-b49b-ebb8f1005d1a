"""Merkle manifest over a chunk-aligned firmware address range.

The parser turns Intel HEX text into sparse, address-ordered segments.
This module lays a fixed grid of equal-sized chunks over an explicit
half-open address range ``[range_start, range_end)``, materializes every
chunk to exactly ``chunk_size`` bytes (addresses absent from the image
are filled with ``0xFF``, the NOR-flash erased value), and builds a
binary SHA-256 Merkle tree over the chunks:

* leaf   = SHA256(0x00 || chunk_start:u32be || chunk_data[chunk_size])
* parent = SHA256(0x01 || left_hash || right_hash)

The four-byte big-endian chunk start binds every leaf to its absolute
address: identical data at a different address hashes differently.
When a level carries an odd number of nodes its last node is duplicated
for pairing, so a tree over any (non-zero) number of chunks is well
defined. At most ``MAX_CHUNKS`` (4096) chunks are permitted.

Besides the root and one digest per chunk, a bottom-up, *directional*
sibling path is returned for every requested proof address (one proof
per address; several addresses may share a chunk and hence a path):

* a step with ``direction == "left"`` means the sibling is the left
  child, so the verifier combines
  ``SHA256(0x01 || sibling || running_hash)``;
* ``direction == "right"`` means
  ``SHA256(0x01 || running_hash || sibling)``.

Walking the steps in order starting from the leaf hash must reproduce
the root. A step whose sibling is the duplicated last node is flagged.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from .hex_parser import Segment

ADDR_SPAN = 1 << 32  # exclusive upper bound of the 32-bit address space

LEAF_TAG = 0x00
PARENT_TAG = 0x01
FILLER_BYTE = 0xFF
HASH_ALGORITHM = "sha256"
MAX_CHUNKS = 4096

LEFT = "left"
RIGHT = "right"


@dataclass
class MerkleParamError:
    """A parameter-level problem that prevents the tree from being built.

    ``kind`` is one of ``invalid_range``, ``range_unaligned``,
    ``too_many_chunks`` or ``proof_address_out_of_range``.
    """

    kind: str
    message: str
    start: int | None = None
    end: int | None = None
    address: int | None = None


@dataclass
class ChunkDigest:
    """Per-chunk summary; the materialized chunk bytes are not retained."""

    index: int
    start: int
    end: int  # exclusive
    size: int  # always chunk_size
    present_bytes: int  # bytes explicitly supplied by the image (rest are 0xFF)
    sha256: str


@dataclass
class ProofStep:
    """One directional sibling on the bottom-up path to the root."""

    level: int  # level whose nodes are paired; 0 = leaf level
    direction: str  # "left" | "right": the sibling's side
    sibling_index: int  # index of the node supplying the sibling hash
    sibling_sha256: str
    duplicated: bool  # True when the sibling is the copied last node


@dataclass
class ProofPath:
    """Membership path for one requested address."""

    address: int
    chunk_index: int
    chunk_start: int
    chunk_end: int  # exclusive
    offset: int  # address - chunk_start
    leaf_sha256: str
    steps: list[ProofStep] = field(default_factory=list)


@dataclass
class MerkleManifest:
    """The Merkle manifest; hashes/chunks/proofs are empty on failure."""

    ok: bool
    params_valid: bool
    param_errors: list[MerkleParamError]
    range_start: int
    range_end: int
    chunk_size: int
    chunk_count: int
    root_sha256: str | None
    chunks: list[ChunkDigest]
    proofs: list[ProofPath]


def _fmt(addr: int) -> str:
    return f"0x{addr:08X}"


def validate_merkle_params(
    range_start: int,
    range_end: int,
    chunk_size: int,
    proof_addresses: list[int],
) -> list[MerkleParamError]:
    """Validate the range, alignment, chunk cap and proof addresses.

    Returns every error found; an empty list means the tree may be
    built. ``chunk_size`` is expected to be a positive integer already
    (enforced at the request schema level).
    """
    errors: list[MerkleParamError] = []

    range_ok = (
        0 <= range_start < range_end <= ADDR_SPAN
    )
    if not range_ok:
        if range_start < 0 or range_end < 0:
            message = (
                f"range endpoints must be non-negative: "
                f"[{_fmt(range_start)}, {_fmt(range_end)})"
            )
        elif range_end > ADDR_SPAN:
            message = (
                f"range exceeds the 32-bit address space: "
                f"[{_fmt(range_start)}, {_fmt(range_end)}), end must be <= 0x100000000"
            )
        else:
            message = (
                f"range must be a non-empty half-open interval with "
                f"range_start < range_end: [{_fmt(range_start)}, {_fmt(range_end)})"
            )
        errors.append(
            MerkleParamError(
                kind="invalid_range",
                message=message,
                start=range_start,
                end=range_end,
            )
        )

    aligned = False
    if range_ok and chunk_size > 0:
        aligned = range_start % chunk_size == 0 and range_end % chunk_size == 0
        if not aligned:
            bad_start = range_start % chunk_size
            bad_end = range_end % chunk_size
            detail = []
            if bad_start:
                detail.append(
                    f"range_start {_fmt(range_start)} is {bad_start} byte(s) past a "
                    f"chunk_size={chunk_size} boundary"
                )
            if bad_end:
                detail.append(
                    f"range_end {_fmt(range_end)} is {bad_end} byte(s) past a "
                    f"chunk_size={chunk_size} boundary"
                )
            errors.append(
                MerkleParamError(
                    kind="range_unaligned",
                    message=(
                        "both range endpoints must be aligned to chunk_size="
                        f"{chunk_size}: " + "; ".join(detail)
                    ),
                    start=range_start,
                    end=range_end,
                )
            )

    if range_ok and aligned:
        chunk_count = (range_end - range_start) // chunk_size
        if chunk_count > MAX_CHUNKS:
            errors.append(
                MerkleParamError(
                    kind="too_many_chunks",
                    message=(
                        f"range requires {chunk_count} chunk(s) of {chunk_size} byte(s); "
                        f"at most {MAX_CHUNKS} chunks are allowed "
                        f"(widen chunk_size or shrink the range)"
                    ),
                    start=range_start,
                    end=range_end,
                )
            )

    for address in proof_addresses:
        if not (range_start <= address < range_end):
            errors.append(
                MerkleParamError(
                    kind="proof_address_out_of_range",
                    message=(
                        f"proof address {_fmt(address)} is outside the chunk range "
                        f"[{_fmt(range_start)}, {_fmt(range_end)})"
                    ),
                    start=range_start,
                    end=range_end,
                    address=address,
                )
            )

    return errors


def _memory_in_range(
    segments: list[Segment], range_start: int, range_end: int
) -> dict[int, int]:
    """Flatten segments, clipping every byte to the manifest range."""
    memory: dict[int, int] = {}
    for segment in sorted(segments, key=lambda s: s.start):
        start = max(segment.start, range_start)
        end = min(segment.end, range_end)
        for address in range(start, end):
            memory[address] = segment.data[address - segment.start]
    return memory


def leaf_hash(chunk_start: int, data: bytes) -> bytes:
    """SHA256(0x00 || chunk_start:u32 big-endian || chunk data)."""
    digest = hashlib.sha256()
    digest.update(bytes([LEAF_TAG]))
    digest.update(chunk_start.to_bytes(4, "big"))
    digest.update(data)
    return digest.digest()


def _parent_hash(left: bytes, right: bytes) -> bytes:
    """SHA256(0x01 || left hash || right hash)."""
    digest = hashlib.sha256()
    digest.update(bytes([PARENT_TAG]))
    digest.update(left)
    digest.update(right)
    return digest.digest()


def _build_levels(leaves: list[bytes]) -> list[list[bytes]]:
    """Build all tree levels bottom-up, duplicating the odd last node."""
    levels = [leaves]
    while len(levels[-1]) > 1:
        nodes = levels[-1]
        if len(nodes) % 2:
            nodes = nodes + [nodes[-1]]
        levels.append(
            [
                _parent_hash(nodes[index], nodes[index + 1])
                for index in range(0, len(nodes), 2)
            ]
        )
    return levels


def _proof_for_index(levels: list[list[bytes]], index: int) -> list[ProofStep]:
    """Collect the directional sibling path for one leaf index."""
    steps: list[ProofStep] = []
    current = index
    for level, nodes in enumerate(levels[:-1]):
        odd_level = len(nodes) % 2 == 1
        paired = nodes + [nodes[-1]] if odd_level else nodes
        if current % 2 == 0:
            sibling_position = current + 1
            direction = RIGHT
        else:
            sibling_position = current - 1
            direction = LEFT
        # When the level was odd, its last (even-indexed) node is paired
        # with a copy of itself; the sibling hash then comes from that
        # same last real node.
        duplicated = odd_level and current == len(nodes) - 1
        sibling_source = len(nodes) - 1 if duplicated else sibling_position
        steps.append(
            ProofStep(
                level=level,
                direction=direction,
                sibling_index=sibling_source,
                sibling_sha256=paired[sibling_position].hex(),
                duplicated=duplicated,
            )
        )
        current //= 2
    return steps


def build_merkle_manifest(
    segments: list[Segment],
    range_start: int,
    range_end: int,
    chunk_size: int,
    proof_addresses: list[int],
) -> MerkleManifest:
    """Validate parameters and build the chunk Merkle manifest.

    On any parameter error no tree is constructed: ``root_sha256`` is
    null and ``chunks``/``proofs`` are empty.
    """
    errors = validate_merkle_params(
        range_start, range_end, chunk_size, proof_addresses
    )
    chunk_count = (
        (range_end - range_start) // chunk_size
        if range_start >= 0 and range_end >= range_start and chunk_size > 0
        else 0
    )
    if errors:
        return MerkleManifest(
            ok=False,
            params_valid=False,
            param_errors=errors,
            range_start=range_start,
            range_end=range_end,
            chunk_size=chunk_size,
            chunk_count=chunk_count,
            root_sha256=None,
            chunks=[],
            proofs=[],
        )

    memory = _memory_in_range(segments, range_start, range_end)

    leaves: list[bytes] = []
    chunks: list[ChunkDigest] = []
    for index in range(chunk_count):
        start = range_start + index * chunk_size
        end = start + chunk_size
        data = bytes(memory.get(address, FILLER_BYTE) for address in range(start, end))
        digest = leaf_hash(start, data)
        leaves.append(digest)
        chunks.append(
            ChunkDigest(
                index=index,
                start=start,
                end=end,
                size=chunk_size,
                present_bytes=sum(1 for address in range(start, end) if address in memory),
                sha256=digest.hex(),
            )
        )

    levels = _build_levels(leaves)
    root = levels[-1][0]

    proofs: list[ProofPath] = []
    for address in proof_addresses:
        index = (address - range_start) // chunk_size
        chunk_start = range_start + index * chunk_size
        proofs.append(
            ProofPath(
                address=address,
                chunk_index=index,
                chunk_start=chunk_start,
                chunk_end=chunk_start + chunk_size,
                offset=address - chunk_start,
                leaf_sha256=leaves[index].hex(),
                steps=_proof_for_index(levels, index),
            )
        )

    return MerkleManifest(
        ok=True,
        params_valid=True,
        param_errors=[],
        range_start=range_start,
        range_end=range_end,
        chunk_size=chunk_size,
        chunk_count=chunk_count,
        root_sha256=root.hex(),
        chunks=chunks,
        proofs=proofs,
    )
