"""Flash update planning for NOR-style byte-addressable memory.

Given the *current* and *target* firmware images (both assembled from
Intel HEX) and a flash window ``[flash_start, flash_end)`` split into
uniform ``erase_block_size`` sectors, the planner derives the erase/write
operations needed to turn current into target.

NOR flash semantics drive the comparison: bits can only be pulled
``1 -> 0`` by a write and restored ``0 -> 1`` by erasing a whole sector
(an erased byte reads ``0xFF``). Addresses absent from either image are
treated as ``0xFF``.

For each erase block touching image data:

* if **any** byte needs a ``0 -> 1`` bit transition, the whole block is
  erased first and every non-``0xFF`` byte of the target image inside the
  block is rewritten (bytes already equal to target included, since the
  erase reset them);
* otherwise only the bytes that actually differ are written.

Pending bytes are merged into contiguous runs and split so that no write
exceeds ``max_write_size`` and no write crosses an erase-block boundary.
"""

from __future__ import annotations

from dataclasses import dataclass

from .hex_parser import Segment

ADDR_SPAN = 1 << 32  # exclusive upper bound of the 32-bit address space

ERASE = "erase"
WRITE = "write"


@dataclass
class ParamError:
    """A parameter-level problem that prevents a plan from being made."""

    # invalid_flash_range | erase_block_unaligned |
    # invalid_max_write_size | image_outside_flash
    kind: str
    message: str
    start: int | None = None
    end: int | None = None


@dataclass
class FlashOperation:
    """One erase or write step, in address order."""

    kind: str  # erase | write
    address: int
    size: int
    block: int  # start address of the owning erase block
    data: bytes = b""  # target bytes carried by a write op

    @property
    def end(self) -> int:
        return self.address + self.size


@dataclass
class BlockPlan:
    """Per-block outcome for a block affected by the update."""

    address: int  # block start
    size: int  # always erase_block_size
    erase: bool
    erase_size: int | None  # erase_block_size when erased, else None
    write_bytes: int
    changed_bytes: int
    zero_to_one_bytes: int


@dataclass
class FlashUpdatePlan:
    ok: bool
    params_valid: bool
    param_errors: list[ParamError]
    blocks: list[BlockPlan]
    operations: list[FlashOperation]
    erase_count: int = 0
    erase_bytes: int = 0
    write_count: int = 0
    write_bytes: int = 0
    changed_bytes: int = 0
    zero_to_one_bytes: int = 0

    @property
    def affected_block_count(self) -> int:
        return len(self.blocks)


def _fmt(addr: int) -> str:
    return f"0x{addr:08X}"


def _to_map(segments: list[Segment]) -> dict[int, int]:
    """Flatten assembled segments into an ``address -> byte`` mapping."""
    memory: dict[int, int] = {}
    for seg in segments:
        for i, value in enumerate(seg.data):
            memory[seg.start + i] = value
    return memory


def validate_flash_parameters(
    current_segments: list[Segment],
    target_segments: list[Segment],
    flash_start: int,
    flash_end: int,
    erase_block_size: int,
    max_write_size: int,
) -> list[ParamError]:
    """Validate the flash window, granularities and image placement.

    Returns every parameter error found; an empty list means planning or
    replay may proceed. Range/size/alignment problems are reported before
    image-placement problems.
    """
    errors: list[ParamError] = []

    if erase_block_size <= 0:
        errors.append(
            ParamError(
                kind="erase_block_unaligned",
                message=f"erase_block_size must be a positive integer, got {erase_block_size}",
            )
        )
    if max_write_size <= 0:
        errors.append(
            ParamError(
                kind="invalid_max_write_size",
                message=f"max_write_size must be a positive integer, got {max_write_size}",
            )
        )
    range_ok = 0 <= flash_start < flash_end <= ADDR_SPAN
    if not range_ok:
        errors.append(
            ParamError(
                kind="invalid_flash_range",
                message=(
                    "flash range must be a non-empty half-open interval within "
                    f"[0, {_fmt(ADDR_SPAN)}): got [{_fmt(flash_start)}, {_fmt(flash_end)})"
                ),
                start=flash_start if flash_start >= 0 else None,
                end=flash_end if flash_end >= 0 else None,
            )
        )
    if range_ok and erase_block_size > 0:
        if flash_start % erase_block_size or flash_end % erase_block_size:
            errors.append(
                ParamError(
                    kind="erase_block_unaligned",
                    message=(
                        "flash_start and flash_end must both be aligned to "
                        f"erase_block_size {erase_block_size}: "
                        f"{_fmt(flash_start)} % {erase_block_size} = "
                        f"{flash_start % erase_block_size}, "
                        f"{_fmt(flash_end)} % {erase_block_size} = "
                        f"{flash_end % erase_block_size}"
                    ),
                    start=flash_start,
                    end=flash_end,
                )
            )
    if errors:
        return errors

    for label, segments in (("current", current_segments), ("target", target_segments)):
        for seg in segments:
            if seg.start < flash_start:
                lo = seg.start
                hi = min(seg.end, flash_start)
                errors.append(
                    ParamError(
                        kind="image_outside_flash",
                        message=(
                            f"{label} image: {hi - lo} byte(s) at "
                            f"[{_fmt(lo)}, {_fmt(hi)}) lie below flash_start "
                            f"{_fmt(flash_start)}"
                        ),
                        start=lo,
                        end=hi,
                    )
                )
            if seg.end > flash_end:
                lo = max(seg.start, flash_end)
                hi = seg.end
                errors.append(
                    ParamError(
                        kind="image_outside_flash",
                        message=(
                            f"{label} image: {hi - lo} byte(s) at "
                            f"[{_fmt(lo)}, {_fmt(hi)}) lie above flash_end "
                            f"{_fmt(flash_end)}"
                        ),
                        start=lo,
                        end=hi,
                    )
                )
    return errors


def plan_flash_update(
    current_segments: list[Segment],
    target_segments: list[Segment],
    flash_start: int,
    flash_end: int,
    erase_block_size: int,
    max_write_size: int,
) -> FlashUpdatePlan:
    """Plan the erase/write steps that turn the current image into target.

    Flash-range and erase-block alignment parameters are validated
    first, then both images must lie wholly inside the flash window;
    on any problem the corresponding ``param_errors`` are returned and
    no operations are generated.
    """
    errors = validate_flash_parameters(
        current_segments,
        target_segments,
        flash_start,
        flash_end,
        erase_block_size,
        max_write_size,
    )
    if errors:
        return FlashUpdatePlan(
            ok=False,
            params_valid=False,
            param_errors=errors,
            blocks=[],
            operations=[],
        )

    current = _to_map(current_segments)
    target = _to_map(target_segments)

    # Compare every address defined by either image; undefined bytes
    # read as the erased value 0xFF. Addresses are visited once, in
    # address order, and grouped by their erase block.
    blocks: dict[int, dict] = {}
    block_addrs: dict[int, list[int]] = {}
    for addr in sorted(current.keys() | target.keys()):
        block_start = addr - (addr % erase_block_size)
        entry = blocks.get(block_start)
        if entry is None:
            entry = {"erase": False, "changed": 0, "zero_to_one": 0}
            blocks[block_start] = entry
            block_addrs[block_start] = []
        block_addrs[block_start].append(addr)
        cur = current.get(addr, 0xFF)
        tgt = target.get(addr, 0xFF)
        if cur == tgt:
            continue
        entry["changed"] += 1
        if (~cur) & tgt & 0xFF:
            entry["zero_to_one"] += 1
            entry["erase"] = True

    block_plans: list[BlockPlan] = []
    operations: list[FlashOperation] = []
    pending: list[tuple[int, int]] = []  # (address, target byte), address order
    totals = {"erase": 0, "write": 0, "changed": 0, "zero_to_one": 0}

    for block_start in sorted(blocks):
        entry = blocks[block_start]
        if entry["changed"] == 0 and not entry["erase"]:
            continue  # both images agree on every defined byte here
        erased = entry["erase"]
        writes: list[tuple[int, int]] = []
        # block_addrs was populated in address order above.
        for addr in block_addrs[block_start]:
            tgt = target.get(addr, 0xFF)
            if erased:
                # The whole block reads 0xFF after erasing: rewrite every
                # target byte that is not itself 0xFF, unchanged ones too.
                if tgt != 0xFF:
                    writes.append((addr, tgt))
            elif current.get(addr, 0xFF) != tgt:
                writes.append((addr, tgt))

        plan = BlockPlan(
            address=block_start,
            size=erase_block_size,
            erase=erased,
            erase_size=erase_block_size if erased else None,
            write_bytes=len(writes),
            changed_bytes=entry["changed"],
            zero_to_one_bytes=entry["zero_to_one"],
        )
        block_plans.append(plan)
        totals["erase"] += int(erased)
        totals["write"] += len(writes)
        totals["changed"] += entry["changed"]
        totals["zero_to_one"] += entry["zero_to_one"]
        if erased:
            operations.append(
                FlashOperation(
                    kind=ERASE,
                    address=block_start,
                    size=erase_block_size,
                    block=block_start,
                )
            )
        pending.extend(writes)

    operations.extend(
        _split_writes(pending, erase_block_size, max_write_size)
    )
    operations.sort(key=lambda op: (op.address, 0 if op.kind == ERASE else 1))

    return FlashUpdatePlan(
        ok=True,
        params_valid=True,
        param_errors=[],
        blocks=block_plans,
        operations=operations,
        erase_count=totals["erase"],
        erase_bytes=totals["erase"] * erase_block_size,
        write_count=sum(1 for op in operations if op.kind == WRITE),
        write_bytes=totals["write"],
        changed_bytes=totals["changed"],
        zero_to_one_bytes=totals["zero_to_one"],
    )


def _split_writes(
    writes: list[tuple[int, int]],
    erase_block_size: int,
    max_write_size: int,
) -> list[FlashOperation]:
    """Merge pending bytes into contiguous runs and cut write operations.

    Runs never span an erase-block boundary and every write is at most
    ``max_write_size`` bytes.
    """
    operations: list[FlashOperation] = []
    run: list[tuple[int, int]] = []

    def flush(run: list[tuple[int, int]]) -> None:
        if not run:
            return
        pos = 0
        while pos < len(run):
            start = run[pos][0]
            block_start = start - (start % erase_block_size)
            block_end = block_start + erase_block_size
            limit = min(max_write_size, block_end - start)
            part = run[pos : pos + limit]
            data = bytes(value for _, value in part)
            operations.append(
                FlashOperation(
                    kind=WRITE,
                    address=start,
                    size=len(data),
                    block=block_start,
                    data=data,
                )
            )
            pos += len(part)

    for addr, value in writes:
        if run:
            prev_addr = run[-1][0]
            same_block = (addr - addr % erase_block_size) == (
                prev_addr - prev_addr % erase_block_size
            )
            if addr != prev_addr + 1 or not same_block:
                flush(run)
                run = []
        run.append((addr, value))
    flush(run)
    return operations
