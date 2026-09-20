"""Cortex-M vector table validation.

The table is read as ``vector_count`` little-endian 32-bit words starting
at ``vector_table_start`` from the assembled firmware image:

* entry 0 — initial main stack pointer: must be 8-byte aligned and lie
  inside a ``ram`` region; the RAM end address itself is allowed because
  the initial SP is conventionally set one past the last RAM word;
* entry 1 — reset handler: must be non-zero;
* entries 2+ — exception/IRQ handlers: a zero word marks an empty slot
  and is accepted as-is.

Every non-zero processor address (all entries from index 1 on) must carry
the Thumb bit (bit 0 set), and the address with that bit cleared must
fall inside an ``executable`` region (half-open interval).

Region definitions are validated first (non-empty, non-overlapping
half-open intervals); the table itself is only read when every region
definition is sound.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .hex_parser import Segment


@dataclass
class VectorRegion:
    """A half-open address window ``[start, end)`` with usage attributes."""

    name: str
    start: int  # inclusive
    end: int  # exclusive
    ram: bool = False
    executable: bool = False

    @property
    def size(self) -> int:
        return self.end - self.start


@dataclass
class VectorViolation:
    """A single vector-table or region-definition problem."""

    # invalid_region | region_overlap | missing_vector_bytes |
    # stack_misaligned | stack_outside_ram | reset_vector_zero |
    # thumb_bit_missing | address_not_executable
    kind: str
    message: str
    index: int | None = None  # vector entry the violation is tied to, if any
    address: int | None = None  # address the violation refers to, if any
    region: str | None = None


@dataclass
class VectorEntry:
    """Per-entry outcome for one 32-bit vector."""

    index: int
    address: int  # absolute address of the entry in the image
    role: str  # initial_sp | reset | handler
    status: str  # ok | empty | error
    value: int | None  # parsed little-endian word; None when bytes are missing
    target_address: int | None  # value with the Thumb bit cleared (non-zero handlers)
    missing_bytes: list[int] = field(default_factory=list)
    message: str = ""


@dataclass
class VectorTableResult:
    ok: bool
    regions_valid: bool
    entries: list[VectorEntry]
    violations: list[VectorViolation]


def _fmt(addr: int) -> str:
    return f"0x{addr:08X}"


def validate_vector_table(
    segments: list[Segment],
    table_start: int,
    vector_count: int,
    regions: list[VectorRegion],
) -> VectorTableResult:
    """Validate the Cortex-M vector table against the memory ``regions``.

    Region definitions are verified first; the table is only read when
    every definition is sound.
    """
    violations: list[VectorViolation] = []
    _check_region_definitions(regions, violations)
    regions_valid = not violations

    entries: list[VectorEntry] = []
    if regions_valid:
        memory = _to_map(segments)
        ram_regions = [r for r in regions if r.ram]
        exec_regions = [r for r in regions if r.executable]
        for index in range(vector_count):
            entries.append(
                _check_vector(
                    index,
                    table_start + 4 * index,
                    memory,
                    ram_regions,
                    exec_regions,
                    violations,
                )
            )

    return VectorTableResult(
        ok=not violations,
        regions_valid=regions_valid,
        entries=entries,
        violations=violations,
    )


def _check_region_definitions(
    regions: list[VectorRegion], violations: list[VectorViolation]
) -> None:
    """Regions must be non-empty half-open intervals that never overlap."""
    for region in regions:
        if region.start >= region.end:
            violations.append(
                VectorViolation(
                    kind="invalid_region",
                    message=(
                        f"region '{region.name}': start {_fmt(region.start)} must be "
                        f"less than end {_fmt(region.end)} (half-open interval)"
                    ),
                    region=region.name,
                )
            )

    # Sorted by start, adjacent pairs suffice to detect overlaps.
    ordered = sorted(regions, key=lambda r: (r.start, r.end))
    for a, b in zip(ordered, ordered[1:]):
        if a.start < a.end and b.start < b.end and b.start < a.end:
            violations.append(
                VectorViolation(
                    kind="region_overlap",
                    message=(
                        f"regions '{a.name}' and '{b.name}' overlap: "
                        f"[{_fmt(a.start)}, {_fmt(a.end)}) vs "
                        f"[{_fmt(b.start)}, {_fmt(b.end)})"
                    ),
                    address=b.start,
                )
            )


def _to_map(segments: list[Segment]) -> dict[int, int]:
    """Flatten assembled segments into an ``address -> byte`` mapping."""
    memory: dict[int, int] = {}
    for seg in segments:
        for i, value in enumerate(seg.data):
            memory[seg.start + i] = value
    return memory


def _check_vector(
    index: int,
    address: int,
    memory: dict[int, int],
    ram_regions: list[VectorRegion],
    exec_regions: list[VectorRegion],
    violations: list[VectorViolation],
) -> VectorEntry:
    """Read and validate one 32-bit vector, appending any violations."""
    if index == 0:
        role = "initial_sp"
    elif index == 1:
        role = "reset"
    else:
        role = "handler"

    missing = [addr for addr in range(address, address + 4) if addr not in memory]
    if missing:
        violations.append(
            VectorViolation(
                kind="missing_vector_bytes",
                message=(
                    f"vector {index} ({role}): {len(missing)} byte(s) missing at "
                    + ", ".join(_fmt(addr) for addr in missing)
                ),
                index=index,
                address=missing[0],
            )
        )
        return VectorEntry(
            index=index,
            address=address,
            role=role,
            status="error",
            value=None,
            target_address=None,
            missing_bytes=missing,
            message=f"{len(missing)} of 4 byte(s) not present in the image",
        )

    value = int.from_bytes(
        bytes(memory[addr] for addr in range(address, address + 4)), "little"
    )

    if index == 0:
        return _check_initial_sp(value, address, ram_regions, violations)
    if value == 0:
        if index == 1:
            violations.append(
                VectorViolation(
                    kind="reset_vector_zero",
                    message="reset vector must be non-zero",
                    index=1,
                    address=address,
                )
            )
            return VectorEntry(
                index=index,
                address=address,
                role=role,
                status="error",
                value=value,
                target_address=None,
                message="reset vector is zero",
            )
        return VectorEntry(
            index=index,
            address=address,
            role=role,
            status="empty",
            value=value,
            target_address=None,
            message="empty slot (zero vector)",
        )
    return _check_handler(index, value, address, role, exec_regions, violations)


def _check_initial_sp(
    value: int,
    address: int,
    ram_regions: list[VectorRegion],
    violations: list[VectorViolation],
) -> VectorEntry:
    """Entry 0: 8-byte aligned and inside a RAM region (end inclusive)."""
    problems: list[str] = []
    if value % 8:
        problems.append("not 8-byte aligned")
        violations.append(
            VectorViolation(
                kind="stack_misaligned",
                message=f"initial SP {_fmt(value)} is not 8-byte aligned",
                index=0,
                address=value,
            )
        )
    ram = next((r for r in ram_regions if r.start <= value <= r.end), None)
    if ram is None:
        problems.append("outside every RAM region")
        violations.append(
            VectorViolation(
                kind="stack_outside_ram",
                message=f"initial SP {_fmt(value)} does not fall inside any RAM region",
                index=0,
                address=value,
            )
        )
    if problems:
        return VectorEntry(
            index=0,
            address=address,
            role="initial_sp",
            status="error",
            value=value,
            target_address=None,
            message="; ".join(problems),
        )
    return VectorEntry(
        index=0,
        address=address,
        role="initial_sp",
        status="ok",
        value=value,
        target_address=None,
        message=f"initial SP {_fmt(value)} inside RAM region '{ram.name}'",
    )


def _check_handler(
    index: int,
    value: int,
    address: int,
    role: str,
    exec_regions: list[VectorRegion],
    violations: list[VectorViolation],
) -> VectorEntry:
    """Non-zero processor address: Thumb bit set, target executable."""
    target = value & ~1  # Thumb bit cleared
    problems: list[str] = []
    if not value & 1:
        problems.append("Thumb bit not set")
        violations.append(
            VectorViolation(
                kind="thumb_bit_missing",
                message=(
                    f"vector {index} ({role}): processor address {_fmt(value)} "
                    "lacks the Thumb bit (bit 0)"
                ),
                index=index,
                address=value,
            )
        )
    executable = next((r for r in exec_regions if r.start <= target < r.end), None)
    if executable is None:
        problems.append(f"target {_fmt(target)} not executable")
        violations.append(
            VectorViolation(
                kind="address_not_executable",
                message=(
                    f"vector {index} ({role}): address {_fmt(target)} "
                    "(Thumb bit cleared) does not fall inside any executable region"
                ),
                index=index,
                address=target,
            )
        )
    if problems:
        return VectorEntry(
            index=index,
            address=address,
            role=role,
            status="error",
            value=value,
            target_address=target,
            message="; ".join(problems),
        )
    return VectorEntry(
        index=index,
        address=address,
        role=role,
        status="ok",
        value=value,
        target_address=target,
        message=f"{role} -> {_fmt(target)} in executable region '{executable.name}'",
    )
