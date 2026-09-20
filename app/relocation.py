"""Whole-image relocation planning.

The assembled firmware image is relocated by applying one identical
integer ``delta`` to every contiguous segment *and* the entry address,
so inter-segment distances (and segment contents) are preserved. A
delta is feasible when:

* every segment falls **wholly** inside a region with
  ``allow_data=true`` (one region per segment; a segment may not straddle
  region boundaries);
* the entry address, when the HEX defines one, lands in a region with
  ``allow_entry=true``;
* every relocated address stays in the 32-bit range
  ``[0, 0xFFFFFFFF]``;
* ``|delta| <= max_abs_shift`` when that limit is supplied.

Each constraint yields a union of closed integer delta intervals; the
feasible set is the intersection of all unions, merged into disjoint
closed intervals. The chosen delta minimizes ``|delta|``, breaking ties
towards the numerically smaller (negative) value.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .hex_parser import Segment
from .layout import Region, Violation, validate_layout

ADDR_MIN = 0
ADDR_MAX = 0xFFFFFFFF
ADDR_SPAN = 1 << 32  # exclusive upper bound: segment end + delta <= this


@dataclass
class RelocationPlan:
    feasible: bool
    regions_valid: bool
    feasible_ranges: list[tuple[int, int]] = field(default_factory=list)
    delta: int | None = None
    abs_shift: int | None = None
    segments: list[Segment] = field(default_factory=list)
    entry_address: int | None = None
    region_violations: list[Violation] = field(default_factory=list)


def plan_relocation(
    segments: list[Segment],
    entry_address: int | None,
    regions: list[Region],
    max_abs_shift: int | None = None,
) -> RelocationPlan:
    """Compute the feasible-delta set for a whole-image relocation.

    Region definitions are validated first with the shared layout
    validator; when they are unsound no planning runs and the definition
    violations are returned.
    """
    layout = validate_layout(segments, entry_address, regions)
    if not layout.regions_valid:
        return RelocationPlan(
            feasible=False,
            regions_valid=False,
            region_violations=layout.violations,
        )

    data_regions = [r for r in regions if r.allow_data]
    entry_regions = [r for r in regions if r.allow_entry]

    # Seed the feasible set with the |delta| cap, then intersect every
    # structural constraint. ``None`` stands for the unbounded universe.
    feasible: list[tuple[int, int]] | None
    if max_abs_shift is None:
        feasible = None
    else:
        feasible = [(-max_abs_shift, max_abs_shift)]
    constrained = max_abs_shift is not None

    bounds32 = _address_space_interval(segments, entry_address)
    if bounds32 is not None:
        feasible = _intersect(feasible, [bounds32])
        constrained = True

    for seg in segments:
        feasible = _intersect(feasible, _segment_intervals(seg, data_regions))
        constrained = True
        if not feasible:
            return RelocationPlan(feasible=False, regions_valid=True, feasible_ranges=[])

    if entry_address is not None:
        feasible = _intersect(feasible, _entry_intervals(entry_address, entry_regions))
        constrained = True

    # With no data, entry or shift cap the feasible set is unbounded:
    # report no finite interval and pick delta 0. An empty set after at
    # least one structural constraint is genuinely infeasible.
    if not constrained or feasible is None:
        delta = 0
        ranges: list[tuple[int, int]] = []
    else:
        if not feasible:
            return RelocationPlan(feasible=False, regions_valid=True, feasible_ranges=[])
        ranges = _merge(feasible)
        delta = _pick_delta(ranges)

    shifted_segments = [Segment(start=s.start + delta, data=s.data) for s in segments]
    shifted_entry = None if entry_address is None else entry_address + delta
    return RelocationPlan(
        feasible=True,
        regions_valid=True,
        feasible_ranges=ranges,
        delta=delta,
        abs_shift=abs(delta),
        segments=shifted_segments,
        entry_address=shifted_entry,
    )


def _segment_intervals(seg: Segment, regions: list[Region]) -> list[tuple[int, int]]:
    """Deltas for which ``seg`` lies wholly inside one allow_data region."""
    intervals: list[tuple[int, int]] = []
    for region in regions:
        # region.start <= seg.start + d  and  seg.end + d <= region.end
        lo = region.start - seg.start
        hi = region.end - seg.end
        if lo <= hi:
            intervals.append((lo, hi))
    return _merge(intervals)


def _entry_intervals(entry: int, regions: list[Region]) -> list[tuple[int, int]]:
    """Deltas for which the entry point lands in one allow_entry region."""
    intervals: list[tuple[int, int]] = []
    for region in regions:
        lo = region.start - entry
        hi = region.end - 1 - entry
        if lo <= hi:
            intervals.append((lo, hi))
    return _merge(intervals)


def _address_space_interval(
    segments: list[Segment], entry_address: int | None
) -> tuple[int, int] | None:
    """Deltas keeping every relocated address in [0, 2**32)."""
    lowers = [-s.start for s in segments]
    uppers = [ADDR_SPAN - s.end for s in segments]
    if entry_address is not None:
        lowers.append(-entry_address)
        uppers.append(ADDR_MAX - entry_address)
    if not lowers:
        return None
    return max(lowers), min(uppers)


def _merge(intervals: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """Merge sorted closed integer intervals; touching ranges join."""
    if not intervals:
        return []
    ordered = sorted(intervals)
    merged: list[tuple[int, int]] = [ordered[0]]
    for lo, hi in ordered[1:]:
        cur_lo, cur_hi = merged[-1]
        if lo <= cur_hi + 1:  # adjacent integer intervals cover a continuous run
            merged[-1] = (cur_lo, max(cur_hi, hi))
        else:
            merged.append((lo, hi))
    return merged


def _intersect(
    a: list[tuple[int, int]] | None, b: list[tuple[int, int]]
) -> list[tuple[int, int]]:
    """Intersect two unions of closed intervals; ``None`` is the universe."""
    if a is None:
        return list(b)
    out: list[tuple[int, int]] = []
    i = j = 0
    while i < len(a) and j < len(b):
        lo = max(a[i][0], b[j][0])
        hi = min(a[i][1], b[j][1])
        if lo <= hi:
            out.append((lo, hi))
        if a[i][1] < b[j][1]:
            i += 1
        elif b[j][1] < a[i][1]:
            j += 1
        else:
            i += 1
            j += 1
    return _merge(out)


def _pick_delta(ranges: list[tuple[int, int]]) -> int:
    """Smallest |delta|, then numerically smallest delta."""
    best: int | None = None
    for lo, hi in ranges:
        candidate = min(max(lo, 0), hi)  # point of the interval closest to 0
        if best is None or (abs(candidate), candidate) < (abs(best), best):
            best = candidate
    assert best is not None
    return best
