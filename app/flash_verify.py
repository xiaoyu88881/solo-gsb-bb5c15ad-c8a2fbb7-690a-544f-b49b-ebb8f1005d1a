"""Replay and verification of user-supplied NOR flash erase/write steps.

Given the *current* and *target* firmware images (both assembled from
Intel HEX), a flash window ``[flash_start, flash_end)`` split into
uniform ``erase_block_size`` sectors, a ``max_write_size`` bound and an
ordered list of erase/write operations, the verifier replays the NOR
flash state operation by operation:

* an ``erase`` fills one or more whole erase blocks with ``0xFF``; its
  address must be block aligned and its size a positive whole-block
  multiple;
* a ``write`` must stay inside the flash window and inside a single
  erase block, carry at most ``max_write_size`` bytes and may only pull
  bits ``1 -> 0`` (the usual NOR constraint; bits return to ``1`` only
  through an erase).

The first illegal operation stops the replay immediately and is reported
by its index and an error code. When every operation is legal the replay
result is compared with the target image (addresses absent from either
side read as ``0xFF``); the differing addresses are merged into maximal
contiguous runs, and verification succeeds only when there are none.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .hex_parser import Segment
from .flash_update import ERASE, WRITE, validate_flash_parameters

ADDR_SPAN = 1 << 32  # exclusive upper bound of the 32-bit address space
ERASED = 0xFF

# Sentinel for a payload that failed Base64 decoding at the API edge; the
# replay reports it as a write_data_invalid operation error.
BAD_WRITE_DATA = object()


@dataclass
class VerifyOperation:
    """One user-supplied erase or write step, in replay order."""

    kind: str  # erase | write
    address: int
    size: int
    data: object = None  # payload bytes for a write op, or BAD_WRITE_DATA


@dataclass
class OperationError:
    """The first illegal operation found during replay."""

    # unknown_operation_kind | operation_outside_flash |
    # erase_not_block_aligned | write_crosses_block |
    # write_too_long | write_data_invalid | write_data_size_mismatch |
    # write_zero_to_one
    kind: str
    index: int
    message: str
    start: int | None = None
    end: int | None = None


@dataclass
class DiffRange:
    """A maximal contiguous run of addresses differing from the target."""

    start: int
    end: int

    @property
    def size(self) -> int:
        return self.end - self.start


@dataclass
class FlashVerification:
    ok: bool
    params_valid: bool
    param_errors: list  # list[flash_update.ParamError]
    executed_count: int = 0
    operation_count: int = 0
    error: OperationError | None = None
    diffs: list[DiffRange] = field(default_factory=list)
    diff_byte_count: int = 0

    @property
    def operations_valid(self) -> bool:
        """True when the replay ran through every supplied operation."""
        return self.error is None

    @property
    def matches_target(self) -> bool:
        """True when the replayed image is byte-identical to the target."""
        return self.error is None and not self.diffs


def _fmt(addr: int) -> str:
    return f"0x{addr:08X}"


def _to_map(segments: list[Segment]) -> dict[int, int]:
    """Flatten assembled segments into an ``address -> byte`` mapping."""
    memory: dict[int, int] = {}
    for seg in segments:
        for i, value in enumerate(seg.data):
            memory[seg.start + i] = value
    return memory


def verify_flash_operations(
    current_segments: list[Segment],
    target_segments: list[Segment],
    flash_start: int,
    flash_end: int,
    erase_block_size: int,
    max_write_size: int,
    operations: list[VerifyOperation],
) -> FlashVerification:
    """Replay ``operations`` over the current image and compare with target.

    Parameter validation is identical to :func:`plan_flash_update`; any
    parameter error aborts before replay. Otherwise operations are
    applied in order and the first illegal one ends the replay.
    """
    param_errors = validate_flash_parameters(
        current_segments,
        target_segments,
        flash_start,
        flash_end,
        erase_block_size,
        max_write_size,
    )
    if param_errors:
        return FlashVerification(
            ok=False,
            params_valid=False,
            param_errors=param_errors,
            operation_count=len(operations),
        )

    state = _to_map(current_segments)

    for index, op in enumerate(operations):
        error = _apply_operation(
            index,
            op,
            state,
            flash_start,
            flash_end,
            erase_block_size,
            max_write_size,
        )
        if error is not None:
            return FlashVerification(
                ok=False,
                params_valid=True,
                param_errors=[],
                executed_count=index,
                operation_count=len(operations),
                error=error,
            )

    # Every address defined by the replayed state or the target image is
    # compared; an absent address reads as the erased value 0xFF.
    target = _to_map(target_segments)
    differing = sorted(
        addr
        for addr in state.keys() | target.keys()
        if state.get(addr, ERASED) != target.get(addr, ERASED)
    )
    diffs = _merge_diffs(differing)
    return FlashVerification(
        ok=not diffs,
        params_valid=True,
        param_errors=[],
        executed_count=len(operations),
        operation_count=len(operations),
        error=None,
        diffs=diffs,
        diff_byte_count=len(differing),
    )


def _apply_operation(
    index: int,
    op: VerifyOperation,
    state: dict[int, int],
    flash_start: int,
    flash_end: int,
    erase_block_size: int,
    max_write_size: int,
) -> OperationError | None:
    """Validate and apply one operation; return the first problem found."""
    if op.kind not in (ERASE, WRITE):
        return OperationError(
            kind="unknown_operation_kind",
            index=index,
            message=(
                f"operation {index}: kind must be 'erase' or 'write', "
                f"got {op.kind!r}"
            ),
        )

    address = op.address
    size = op.size
    if address < 0 or size <= 0 or address >= ADDR_SPAN:
        return OperationError(
            kind="operation_outside_flash",
            index=index,
            message=(
                f"{op.kind} operation {index}: address must be a non-negative "
                f"32-bit value and size positive; got address {_fmt(address)} "
                f"and size {size}"
            ),
            start=address if address >= 0 else None,
        )

    end = address + size  # big ints: cannot wrap around
    if address < flash_start or end > flash_end or end > ADDR_SPAN:
        return OperationError(
            kind="operation_outside_flash",
            index=index,
            message=(
                f"{op.kind} operation {index}: [{_fmt(address)}, {_fmt(end)}) "
                f"is not fully inside the flash window "
                f"[{_fmt(flash_start)}, {_fmt(flash_end)})"
            ),
            start=address,
            end=end,
        )

    if op.kind == ERASE:
        if address % erase_block_size or size % erase_block_size:
            return OperationError(
                kind="erase_not_block_aligned",
                index=index,
                message=(
                    f"erase operation {index}: address {_fmt(address)} must be "
                    f"aligned to erase_block_size {erase_block_size} and size "
                    f"{size} must be a whole-block multiple "
                    f"(address % {erase_block_size} = {address % erase_block_size}, "
                    f"size % {erase_block_size} = {size % erase_block_size})"
                ),
                start=address,
                end=end,
            )
        # Erased bytes read 0xFF; drop sparse entries so implicit erased
        # bytes and explicit ones are indistinguishable.
        for addr in range(address, end):
            state.pop(addr, None)
        return None

    # write-specific shape checks
    if address // erase_block_size != (end - 1) // erase_block_size:
        first_boundary = (
            address - (address % erase_block_size) + erase_block_size
        )
        return OperationError(
            kind="write_crosses_block",
            index=index,
            message=(
                f"write operation {index}: [{_fmt(address)}, {_fmt(end)}) "
                f"crosses the erase-block boundary at {_fmt(first_boundary)} "
                f"(erase_block_size {erase_block_size})"
            ),
            start=address,
            end=end,
        )
    if size > max_write_size:
        return OperationError(
            kind="write_too_long",
            index=index,
            message=(
                f"write operation {index}: size {size} exceeds max_write_size "
                f"{max_write_size}"
            ),
            start=address,
            end=end,
        )
    if op.data is None or op.data is BAD_WRITE_DATA:
        return OperationError(
            kind="write_data_invalid",
            index=index,
            message=(
                f"write operation {index}: missing or undecodable data payload"
            ),
            start=address,
            end=end,
        )
    if not isinstance(op.data, (bytes, bytearray)):
        return OperationError(
            kind="write_data_invalid",
            index=index,
            message=(
                f"write operation {index}: data payload must decode to raw bytes"
            ),
            start=address,
            end=end,
        )
    if len(op.data) != size:
        return OperationError(
            kind="write_data_size_mismatch",
            index=index,
            message=(
                f"write operation {index}: data carries {len(op.data)} byte(s) "
                f"but address/size declare {size}"
            ),
            start=address,
            end=end,
        )

    # NOR flash: a write may only clear bits (1 -> 0). A set bit (0 -> 1)
    # without an intervening erase is illegal.
    for offset, value in enumerate(op.data):
        addr = address + offset
        current = state.get(addr, ERASED)
        if (~current) & value & 0xFF:
            return OperationError(
                kind="write_zero_to_one",
                index=index,
                message=(
                    f"write operation {index}: byte at {_fmt(addr)} would set "
                    f"a 0 bit back to 1 (0x{current:02X} -> 0x{value:02X}); "
                    "erase the block first"
                ),
                start=addr,
                end=addr + 1,
            )
        state[addr] = value
    return None


def _merge_diffs(addresses: list[int]) -> list[DiffRange]:
    """Merge differing addresses into maximal contiguous half-open runs."""
    ranges: list[DiffRange] = []
    for addr in addresses:
        if ranges and addr == ranges[-1].end:
            ranges[-1].end = addr + 1
        else:
            ranges.append(DiffRange(start=addr, end=addr + 1))
    return ranges
