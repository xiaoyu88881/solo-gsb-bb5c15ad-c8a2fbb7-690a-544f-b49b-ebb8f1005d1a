"""Memory-layout validation for assembled firmware images.

A layout is a set of named, non-overlapping half-open address regions
``[start, end)``. Contiguous firmware segments are split at region
boundaries; every byte must be covered by a region that allows data,
and the entry address (if any) must land in a region that allows entry.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .hex_parser import Segment


@dataclass
class Region:
    """A half-open address window ``[start, end)`` with usage permissions."""

    name: str
    start: int  # inclusive
    end: int  # exclusive
    allow_data: bool = True
    allow_entry: bool = False

    @property
    def size(self) -> int:
        return self.end - self.start


@dataclass
class Violation:
    """A single layout problem. ``start``/``end`` delimit the affected bytes."""

    kind: str
    message: str
    start: int | None = None
    end: int | None = None
    region: str | None = None


@dataclass
class RegionReport:
    region: Region
    occupied_bytes: int = 0
    violations: list[Violation] = field(default_factory=list)

    @property
    def utilization(self) -> float:
        """Occupied fraction of the region; 0.0 for empty/invalid regions."""
        if self.region.size <= 0:
            return 0.0
        return self.occupied_bytes / self.region.size


@dataclass
class LayoutResult:
    ok: bool
    regions_valid: bool
    reports: list[RegionReport]
    violations: list[Violation]  # all violations, including uncovered ranges


def _fmt(addr: int) -> str:
    return f"0x{addr:04X}"


def validate_layout(
    segments: list[Segment],
    entry_address: int | None,
    regions: list[Region],
) -> LayoutResult:
    """Check assembled firmware ``segments`` against the memory ``regions``.

    Region definitions are verified first (non-empty, non-overlapping
    half-open intervals); the byte-level placement check only runs when
    every region definition is sound.
    """
    reports = [RegionReport(region=r) for r in regions]
    violations: list[Violation] = []

    def add(violation: Violation, report: RegionReport | None = None) -> None:
        violations.append(violation)
        if report is not None:
            report.violations.append(violation)

    for region, report in zip(regions, reports):
        if region.start >= region.end:
            add(
                Violation(
                    kind="invalid_region",
                    message=(
                        f"region '{region.name}': start {_fmt(region.start)} must be "
                        f"less than end {_fmt(region.end)} (half-open interval)"
                    ),
                    start=region.start,
                    end=region.end,
                    region=region.name,
                ),
                report,
            )

    # Sorted by start, adjacent pairs suffice to detect overlaps.
    indexed = sorted(enumerate(regions), key=lambda t: (t[1].start, t[1].end))
    for (_, a), (_, b) in zip(indexed, indexed[1:]):
        if a.start < a.end and b.start < b.end and b.start < a.end:
            add(
                Violation(
                    kind="region_overlap",
                    message=(
                        f"regions '{a.name}' and '{b.name}' overlap: "
                        f"[{_fmt(a.start)}, {_fmt(a.end)}) vs "
                        f"[{_fmt(b.start)}, {_fmt(b.end)})"
                    ),
                    start=b.start,
                    end=min(a.end, b.end),
                )
            )

    regions_valid = not violations
    if regions_valid:
        _check_data_placement(segments, indexed, reports, add)
        _check_entry(entry_address, indexed, reports, add)

    return LayoutResult(
        ok=not violations,
        regions_valid=regions_valid,
        reports=reports,
        violations=violations,
    )


def _check_data_placement(segments, indexed, reports, add) -> None:
    """Split each contiguous segment at region boundaries and account for it."""
    for seg in segments:
        cursor = seg.start
        for orig_idx, region in indexed:
            if region.end <= seg.start or region.start >= seg.end:
                continue
            if region.start > cursor:
                add(
                    Violation(
                        kind="uncovered_data",
                        message=(
                            f"{min(region.start, seg.end) - cursor} byte(s) at "
                            f"{_fmt(cursor)} not covered by any region"
                        ),
                        start=cursor,
                        end=min(region.start, seg.end),
                    )
                )
            lo = max(seg.start, region.start)
            hi = min(seg.end, region.end)
            reports[orig_idx].occupied_bytes += hi - lo
            if not region.allow_data:
                add(
                    Violation(
                        kind="data_not_allowed",
                        message=(
                            f"{hi - lo} byte(s) at {_fmt(lo)} fall in region "
                            f"'{region.name}' (allow_data=false)"
                        ),
                        start=lo,
                        end=hi,
                        region=region.name,
                    ),
                    reports[orig_idx],
                )
            cursor = max(cursor, region.end)
        if cursor < seg.end:
            add(
                Violation(
                    kind="uncovered_data",
                    message=(
                        f"{seg.end - cursor} byte(s) at {_fmt(cursor)} "
                        "not covered by any region"
                    ),
                    start=cursor,
                    end=seg.end,
                )
            )


def _check_entry(entry_address, indexed, reports, add) -> None:
    """The entry address, when present, must land in an allow_entry region."""
    if entry_address is None:
        return
    for orig_idx, region in indexed:
        if region.start <= entry_address < region.end:
            if not region.allow_entry:
                add(
                    Violation(
                        kind="entry_not_allowed",
                        message=(
                            f"entry address {_fmt(entry_address)} falls in region "
                            f"'{region.name}' (allow_entry=false)"
                        ),
                        start=entry_address,
                        end=entry_address + 1,
                        region=region.name,
                    ),
                    reports[orig_idx],
                )
            return
    add(
        Violation(
            kind="entry_uncovered",
            message=f"entry address {_fmt(entry_address)} is not covered by any region",
            start=entry_address,
            end=entry_address + 1,
        )
    )
