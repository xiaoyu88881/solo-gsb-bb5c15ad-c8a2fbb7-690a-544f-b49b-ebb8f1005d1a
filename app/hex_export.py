"""Deterministic Intel HEX normalization and export.

The parser assembles any valid Intel HEX text into canonical,
address-ordered contiguous segments plus an optional entry address.
This module re-emits that assembled image as a fresh, normalized Intel
HEX text:

* data records carry at most ``max_data_bytes`` bytes each and never
  cross a 64 KiB address window boundary (a window is
  ``address >> 16``);
* linear addressing only: whenever the next data record falls into a
  different window than the current one, an extended linear address
  record (type 04) is emitted first (the implicit initial window 0
  needs no record);
* every record's two's-complement checksum is recomputed;
* the entry address, when present and requested, is preserved as a
  start linear address record (type 05);
* exactly one end-of-file record terminates the output.

Because the input is the assembled image rather than the original
records, the output is fully determined by the image content and
``max_data_bytes``/``include_entry``: record splitting, gap
representation or base-record style (02 vs 04) of the input do not
affect it, and re-exporting an exported text is a fixed point.
"""

from __future__ import annotations

from dataclasses import dataclass

from .hex_parser import Segment

WINDOW_SIZE = 0x10000  # 64 KiB window covered by one extended linear address record
MAX_DATA_BYTES = 0xFF  # the byte-count field is a single byte
DEFAULT_DATA_BYTES = 16


@dataclass
class HexExport:
    """Result of normalizing an assembled image back into Intel HEX text."""

    hex_text: str
    record_count: int  # all emitted records, including the EOF record
    data_record_count: int
    extended_address_record_count: int
    entry_record_count: int  # 0 or 1
    entry_address: int | None
    include_entry: bool
    max_data_bytes: int


def _record(rectype: int, offset: int, data: bytes = b"") -> str:
    """Serialize one record with a recomputed two's-complement checksum."""
    body = bytes([len(data), (offset >> 8) & 0xFF, offset & 0xFF, rectype]) + data
    checksum = (-sum(body)) & 0xFF
    return ":" + (body + bytes([checksum])).hex().upper()


def export_intel_hex(
    segments: list[Segment],
    entry_address: int | None,
    max_data_bytes: int = DEFAULT_DATA_BYTES,
    include_entry: bool = True,
) -> HexExport:
    """Re-emit assembled segments as normalized Intel HEX text.

    ``max_data_bytes`` must fit the one-byte count field (1..255).
    Segments are sorted defensively: the parser already returns them in
    ascending address order, but the export must never depend on
    caller-supplied ordering.
    """
    if not 1 <= max_data_bytes <= MAX_DATA_BYTES:
        raise ValueError(f"max_data_bytes must be within 1..{MAX_DATA_BYTES}")

    ordered = sorted(segments, key=lambda s: s.start)
    lines: list[str] = []
    data_records = 0
    ela_records = 0
    active_window = 0  # Intel HEX starts with an implicit base of 0

    for segment in ordered:
        address = segment.start
        remaining = segment.data
        while remaining:
            window = address >> 16
            if window != active_window:
                lines.append(_record(0x04, 0, window.to_bytes(2, "big")))
                ela_records += 1
                active_window = window
            room = WINDOW_SIZE - (address & 0xFFFF)  # bytes left in this window
            take = min(len(remaining), max_data_bytes, room)
            lines.append(_record(0x00, address & 0xFFFF, remaining[:take]))
            data_records += 1
            address += take
            remaining = remaining[take:]

    entry_records = 0
    if include_entry and entry_address is not None:
        lines.append(_record(0x05, 0, entry_address.to_bytes(4, "big")))
        entry_records = 1

    lines.append(_record(0x01, 0))
    hex_text = "\n".join(lines) + "\n"

    return HexExport(
        hex_text=hex_text,
        record_count=len(lines),
        data_record_count=data_records,
        extended_address_record_count=ela_records,
        entry_record_count=entry_records,
        entry_address=entry_address,
        include_entry=include_entry,
        max_data_bytes=max_data_bytes,
    )
