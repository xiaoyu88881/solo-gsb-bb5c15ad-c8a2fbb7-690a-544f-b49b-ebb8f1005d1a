"""Content-addressed Merkle manifest over a chunk-aligned firmware window.

The assembled Intel HEX image is sparse: only explicitly written bytes
exist. This module lays a fixed, chunk-aligned half-open window
``[range_start, range_end)`` over that image, materializes every byte the
image does not supply as ``0xFF`` (the erased-flash value), and builds a
binary SHA-256 Merkle tree over the resulting fixed-size chunks:

* leaf ``i`` (chunk starting at ``start_i``)::

      SHA256(0x00 || start_i:u32-be || chunk_bytes[chunk_size])

  the 4-byte big-endian absolute chunk start binds every leaf to its
  placement, so identical content at another address hashes differently;
* every inner node is::

      SHA256(0x01 || left_digest || right_digest)

* when a level carries an odd number of nodes, its last node is
  duplicated before pairing (so the duplicated node is paired with
  itself); the root of a single-chunk window is the leaf digest itself.

For every address the caller wants to prove, the owning chunk and the
directed sibling path from that leaf to the root are returned, letting a
verifier recompute the root from the leaf alone.

The window must be a non-empty 32-bit interval whose ends are aligned to
``chunk_size``; at most ``MAX_CHUNKS`` chunks are allowed; every image
byte must lie inside the window (nothing spills outside); and every proof
address must fall inside it. Any such problem aborts tree construction.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from .hex_parser import Segment

ADDR_SPAN = 1 << 32  # exclusive upper bound of the 32-bit address space
MAX_CHUNKS = 4096

LEAF_TAG = 0x00
PARENT_TAG = 0x01
FILL_BYTE = 0xFF

LEFT = "left"
RIGHT = "right"


@dataclass
class ParamError:
    """A parameter-level problem that prevents the tree from being built.

    ``kind`` is one of:

    * ``invalid_range`` — window is not a non-empty 32-bit half-open interval;
    * ``range_not_aligned`` — either window end is unaligned to ``chunk_size``;
    * ``invalid_chunk_size`` — ``chunk_size`` is not a positive integer;
    * ``too_many_chunks`` — the window covers more than ``MAX_CHUNKS`` chunks;
    * ``image_outside_range`` — image bytes lie outside the window;
    * ``proof_outside_range`` — a requested proof address is outside it.
    """

    kind: str
    message: str
    start: int | None = None
    end: int | None = None
    address: int | None = None  # offending proof address
    chunk_size: int | None = None
    chunk_count: int | None = None
    proof_index: int | None = None  # 0-based position among requested proofs


@dataclass
class ChunkDigest:
    """Leaf summary of one materialized chunk."""

    index: int
    start: int
    end: int  # exclusive
    digest: bytes  # raw 32-byte leaf digest


@dataclass
class ProofStep:
    """One directed sibling on the leaf-to-root path.

    ``direction`` states where the sibling sits relative to the current
    node: ``left`` means the verifier must prepend the sibling,
    ``right`` means it must append it.
    """

    direction: str  # "left" | "right"
    digest: bytes  # raw 32-byte sibling digest


@dataclass
class MerkleProof:
    """Membership proof for one requested address."""

    address: int
    chunk_index: int
    chunk_start: int
    chunk_end: int
    leaf: bytes
    path: list[ProofStep] = field(default_factory=list)


@dataclass
class MerkleManifest:
    """The built tree: root, per-chunk leaves and per-address proofs."""

    ok: bool
    params_valid: bool
    param_errors: list[ParamError]
    range_start: int
    range_end: int
    chunk_size: int
    chunk_count: int
    root: bytes | None
    chunks: list[ChunkDigest]
    proofs: list[MerkleProof]


def _fmt(addr: int) -> str:
    return f"0x{addr:08X}"


def validate_merkle_parameters(
    segments: list[Segment],
    range_start: int,
    range_end: int,
    chunk_size: int,
    proof_addresses: list[int],
) -> list[ParamError]:
    """Validate the window, granularity, image placement and proof addresses.

    Structural window problems are reported before placement/proof
    problems, which only make sense for a sound window. Returns every
    error found; an empty list means the tree may be built.
    """
    errors: list[ParamError] = []

    if chunk_size <= 0:
        errors.append(
            ParamError(
                kind="invalid_chunk_size",
                message=f"chunk_size must be a positive integer, got {chunk_size}",
                chunk_size=chunk_size,
            )
        )

    range_ok = 0 <= range_start < range_end <= ADDR_SPAN
    if not range_ok:
        errors.append(
            ParamError(
                kind="invalid_range",
                message=(
                    "range must be a non-empty half-open interval within "
                    f"[0, {_fmt(ADDR_SPAN)}): got [{_fmt(range_start)}, {_fmt(range_end)})"
                ),
                start=range_start if range_start >= 0 else None,
                end=range_end if range_end >= 0 else None,
            )
        )

    chunk_count = 0
    if range_ok and chunk_size > 0:
        if range_start % chunk_size or range_end % chunk_size:
            errors.append(
                ParamError(
                    kind="range_not_aligned",
                    message=(
                        "range_start and range_end must both be aligned to "
                        f"chunk_size {chunk_size}: {_fmt(range_start)} % {chunk_size} = "
                        f"{range_start % chunk_size}, {_fmt(range_end)} % {chunk_size} = "
                        f"{range_end % chunk_size}"
                    ),
                    start=range_start,
                    end=range_end,
                    chunk_size=chunk_size,
                )
            )
        else:
            chunk_count = (range_end - range_start) // chunk_size
            if chunk_count > MAX_CHUNKS:
                errors.append(
                    ParamError(
                        kind="too_many_chunks",
                        message=(
                            f"range covers {chunk_count} chunk(s) of {chunk_size} byte(s); "
                            f"at most {MAX_CHUNKS} chunks are allowed"
                        ),
                        start=range_start,
                        end=range_end,
                        chunk_size=chunk_size,
                        chunk_count=chunk_count,
                    )
                )

    # Placement/proof checks need a sound, aligned window.
    if errors:
        return errors

    for seg in segments:
        if seg.start < range_start:
            lo = seg.start
            hi = min(seg.end, range_start)
            errors.append(
                ParamError(
                    kind="image_outside_range",
                    message=(
                        f"image: {hi - lo} byte(s) at [{_fmt(lo)}, {_fmt(hi)}) lie below "
                        f"range_start {_fmt(range_start)}"
                    ),
                    start=lo,
                    end=hi,
                )
            )
        if seg.end > range_end:
            lo = max(seg.start, range_end)
            hi = seg.end
            errors.append(
                ParamError(
                    kind="image_outside_range",
                    message=(
                        f"image: {hi - lo} byte(s) at [{_fmt(lo)}, {_fmt(hi)}) lie above "
                        f"range_end {_fmt(range_end)}"
                    ),
                    start=lo,
                    end=hi,
                )
            )

    for proof_index, address in enumerate(proof_addresses):
        if not (range_start <= address < range_end):
            errors.append(
                ParamError(
                    kind="proof_outside_range",
                    message=(
                        f"proof address {_fmt(address)} at index {proof_index} is outside "
                        f"the manifest range [{_fmt(range_start)}, {_fmt(range_end)})"
                    ),
                    address=address,
                    start=range_start,
                    end=range_end,
                    proof_index=proof_index,
                )
            )

    return errors


def _leaf_digest(chunk_start: int, data: bytes) -> bytes:
    preimage = (
        bytes([LEAF_TAG])
        + (chunk_start & 0xFFFFFFFF).to_bytes(4, "big")
        + data
    )
    return hashlib.sha256(preimage).digest()


def _parent_digest(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(bytes([PARENT_TAG]) + left + right).digest()


def _materialize_chunks(
    segments: list[Segment],
    range_start: int,
    chunk_count: int,
    chunk_size: int,
) -> list[ChunkDigest]:
    """Read every chunk, filling bytes absent from the image with 0xFF.

    Segments are scanned with a monotonically advancing pointer instead
    of materializing the (potentially large) whole window up front.
    """
    ordered = sorted(segments, key=lambda s: s.start)
    fill = bytes([FILL_BYTE])
    chunks: list[ChunkDigest] = []
    seg_index = 0
    for index in range(chunk_count):
        chunk_start = range_start + index * chunk_size
        chunk_end = chunk_start + chunk_size
        data = bytearray(fill * chunk_size)
        while seg_index < len(ordered) and ordered[seg_index].end <= chunk_start:
            seg_index += 1
        cursor = seg_index
        while cursor < len(ordered) and ordered[cursor].start < chunk_end:
            seg = ordered[cursor]
            lo = max(seg.start, chunk_start)
            hi = min(seg.end, chunk_end)
            data[lo - chunk_start : hi - chunk_start] = seg.data[
                lo - seg.start : hi - seg.start
            ]
            cursor += 1
        chunks.append(
            ChunkDigest(
                index=index,
                start=chunk_start,
                end=chunk_end,
                digest=_leaf_digest(chunk_start, bytes(data)),
            )
        )
    return chunks


def _build_levels(leaves: list[bytes]) -> list[list[bytes]]:
    """Pair nodes level by level, duplicating the last node when odd."""
    levels = [list(leaves)]
    while len(levels[-1]) > 1:
        nodes = levels[-1]
        paired = nodes + [nodes[-1]] if len(nodes) % 2 else nodes
        levels.append(
            [
                _parent_digest(paired[i], paired[i + 1])
                for i in range(0, len(paired), 2)
            ]
        )
    return levels


def _proof_for_leaf(
    levels: list[list[bytes]],
    address: int,
    chunk: ChunkDigest,
) -> MerkleProof:
    """Collect the directed siblings from ``chunk``'s leaf up to the root."""
    index = chunk.index
    path: list[ProofStep] = []
    for level in range(len(levels) - 1):
        nodes = levels[level]
        if index % 2 == 0:
            # The current node is the left child; an odd last level pairs
            # it with a duplicate of itself, so clamp to its own digest.
            sibling_index = index + 1 if index + 1 < len(nodes) else index
            path.append(ProofStep(direction=RIGHT, digest=nodes[sibling_index]))
        else:
            path.append(ProofStep(direction=LEFT, digest=nodes[index - 1]))
        index //= 2
    return MerkleProof(
        address=address,
        chunk_index=chunk.index,
        chunk_start=chunk.start,
        chunk_end=chunk.end,
        leaf=chunk.digest,
        path=path,
    )


def build_image_merkle(
    segments: list[Segment],
    range_start: int,
    range_end: int,
    chunk_size: int,
    proof_addresses: list[int],
) -> MerkleManifest:
    """Validate parameters and build the chunk Merkle manifest.

    On any parameter error no tree is constructed: ``root`` is null and
    ``chunks``/``proofs`` are empty.
    """
    errors = validate_merkle_parameters(
        segments, range_start, range_end, chunk_size, proof_addresses
    )
    if errors:
        return MerkleManifest(
            ok=False,
            params_valid=False,
            param_errors=errors,
            range_start=range_start,
            range_end=range_end,
            chunk_size=chunk_size,
            chunk_count=0,
            root=None,
            chunks=[],
            proofs=[],
        )

    chunk_count = (range_end - range_start) // chunk_size
    chunks = _materialize_chunks(segments, range_start, chunk_count, chunk_size)
    levels = _build_levels([chunk.digest for chunk in chunks])
    root = levels[-1][0]

    proofs: list[MerkleProof] = []
    for address in proof_addresses:
        chunk_index = (address - range_start) // chunk_size
        proofs.append(_proof_for_leaf(levels, address, chunks[chunk_index]))

    return MerkleManifest(
        ok=True,
        params_valid=True,
        param_errors=[],
        range_start=range_start,
        range_end=range_end,
        chunk_size=chunk_size,
        chunk_count=chunk_count,
        root=root,
        chunks=chunks,
        proofs=proofs,
    )
