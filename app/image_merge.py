"""Overlay merge of several independently assembled Intel HEX images.

Each input image has already been parsed and validated with the shared
``parse_intel_hex`` parser; merging never runs when any source is
invalid. Valid images are overlaid at their **absolute addresses**
(base-address records 02/04 are therefore already resolved):

* an address written by one image, or by several images with the same
  byte value, is merged; every contributing source is recorded, so an
  identical overlap carries the full set of source names;
* an address on which the sources disagree starts a *conflict run*:
  maximal runs of contiguous conflicting addresses are reported, each
  with the per-source values as contiguous chunks, and no merged image
  is produced;
* entry addresses (the last 03/05 record of each source) must either be
  absent from every source or agree whenever they are present: distinct
  non-null values are an ``entry_conflict`` (sources without an entry
  are ignored, so a single non-null entry is simply adopted);

The merged bytes are assembled into contiguous segments which are
further split whenever the contributing source set changes, so each
returned segment carries one stable, address-ordered source set.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .hex_parser import ParseResult


@dataclass
class MergeSource:
    """One validated input image, keyed by its unique request name."""

    name: str
    parsed: ParseResult


@dataclass
class MergedSegment:
    """Contiguous merged bytes with one stable set of contributors."""

    start: int
    data: bytes
    sources: list[str] = field(default_factory=list)

    @property
    def end(self) -> int:
        """Exclusive end address."""
        return self.start + len(self.data)


@dataclass
class ConflictChunk:
    """One source's contiguous values inside a conflict run."""

    source: str
    start: int
    data: bytes

    @property
    def end(self) -> int:
        """Exclusive end address."""
        return self.start + len(self.data)


@dataclass
class ByteConflict:
    """A maximal run of contiguous addresses with disagreeing bytes."""

    start: int
    length: int
    message: str
    chunks: list[ConflictChunk] = field(default_factory=list)

    @property
    def end(self) -> int:
        """Exclusive end address of the run."""
        return self.start + self.length


@dataclass
class EntryConflict:
    """Conflicting entry addresses: at least two distinct non-null values."""

    message: str
    entries: list[tuple[str, int]] = field(default_factory=list)
    """(source name, entry address) for every source defining an entry."""


@dataclass
class MergeResult:
    ok: bool
    total_bytes: int
    entry_address: int | None
    segments: list[MergedSegment]
    conflicts: list[ByteConflict]
    entry_conflict: EntryConflict | None


def _fmt(addr: int) -> str:
    return f"0x{addr:08X}"


def _to_map(parsed: ParseResult) -> dict[int, int]:
    """Flatten assembled segments into an ``address -> byte`` mapping."""
    memory: dict[int, int] = {}
    for seg in parsed.segments:
        for i, value in enumerate(seg.data):
            memory[seg.start + i] = value
    return memory


def _build_conflicts(
    conflict_addresses: list[int], source_maps: list[tuple[str, dict[int, int]]]
) -> list[ByteConflict]:
    """Group conflicting addresses into contiguous runs with per-source values."""
    conflicts: list[ByteConflict] = []
    run: list[int] = []
    for addr in sorted(conflict_addresses):
        if run and addr != run[-1] + 1:
            conflicts.append(_build_one_conflict(run, source_maps))
            run = []
        run.append(addr)
    if run:
        conflicts.append(_build_one_conflict(run, source_maps))
    return conflicts


def _build_one_conflict(
    run: list[int], source_maps: list[tuple[str, dict[int, int]]]
) -> ByteConflict:
    start = run[0]
    end = run[-1] + 1
    chunks: list[ConflictChunk] = []
    for name, memory in source_maps:
        part: list[int] = []
        for addr in run:
            if addr in memory:
                part.append(addr)
        subrun: list[int] = []
        for addr in part:
            if subrun and addr != subrun[-1] + 1:
                chunks.append(
                    ConflictChunk(
                        source=name,
                        start=subrun[0],
                        data=bytes(memory[a] for a in subrun),
                    )
                )
                subrun = []
            subrun.append(addr)
        if subrun:
            chunks.append(
                ConflictChunk(
                    source=name,
                    start=subrun[0],
                    data=bytes(memory[a] for a in subrun),
                )
            )
    return ByteConflict(
        start=start,
        length=len(run),
        message=(
            f"conflicting byte(s) at [{_fmt(start)}, {_fmt(end)}): "
            f"{len(chunks)} source chunk(s) disagree"
        ),
        chunks=chunks,
    )


def _build_segments(
    memory: dict[int, int], owners: dict[int, list[str]]
) -> list[MergedSegment]:
    """Merge bytes into contiguous runs split when the source set changes."""
    segments: list[MergedSegment] = []
    if not memory:
        return segments
    blob = bytearray()
    start = 0
    prev = 0
    sources: tuple[str, ...] = ()

    def flush() -> None:
        if blob:
            segments.append(
                MergedSegment(start=start, data=bytes(blob), sources=list(sources))
            )

    for pos, addr in enumerate(sorted(memory)):
        current_sources = tuple(owners[addr])
        if pos == 0:
            start = addr
            sources = current_sources
        elif addr != prev + 1 or current_sources != sources:
            flush()
            blob = bytearray()
            start = addr
            sources = current_sources
        blob.append(memory[addr])
        prev = addr
    flush()
    return segments


def merge_images(sources: list[MergeSource]) -> MergeResult:
    """Overlay valid, uniquely named parsed images at absolute addresses.

    Callers must pass only sources whose ``parsed.ok`` is true; on any
    invalid source the route aborts before calling this function.
    """
    source_maps: list[tuple[str, dict[int, int]]] = [
        (source.name, _to_map(source.parsed)) for source in sources
    ]

    memory: dict[int, int] = {}  # address -> first written value
    owners: dict[int, list[str]] = {}  # address -> every defining source, in request order
    conflict_addresses: list[int] = []
    for name, source_memory in source_maps:
        for addr, value in source_memory.items():
            if addr not in memory:
                memory[addr] = value
                owners[addr] = [name]
            else:
                owners[addr].append(name)
                if memory[addr] != value and addr not in conflict_addresses:
                    conflict_addresses.append(addr)

    # Entry addresses: every source may omit one; when present all
    # non-null values must be identical.
    entries: list[tuple[str, int]] = [
        (source.name, source.parsed.entry_address)
        for source in sources
        if source.parsed.entry_address is not None
    ]
    distinct_entries = {value for _, value in entries}
    entry_conflict: EntryConflict | None = None
    if len(distinct_entries) > 1:
        detail = ", ".join(f"{name}={_fmt(value)}" for name, value in entries)
        entry_conflict = EntryConflict(
            message=(
                "entry address conflict: sources with an entry must agree "
                f"(or all omit it); got {detail}"
            ),
            entries=list(entries),
        )

    conflicts = _build_conflicts(conflict_addresses, source_maps)

    if conflicts or entry_conflict is not None:
        return MergeResult(
            ok=False,
            total_bytes=len(memory),
            entry_address=None,
            segments=[],
            conflicts=conflicts,
            entry_conflict=entry_conflict,
        )

    entry_address = next(iter(distinct_entries), None)
    segments = _build_segments(memory, owners)
    return MergeResult(
        ok=True,
        total_bytes=len(memory),
        entry_address=entry_address,
        segments=segments,
        conflicts=[],
        entry_conflict=None,
    )
