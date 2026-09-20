"""Intel HEX parsing and firmware image assembly.

Supported record types:

* ``00`` — data; stored at ``base + record offset``
* ``01`` — end of file; must appear exactly once, as the last record
* ``02`` — extended segment address; ``base = value << 4``
* ``03`` — start segment address (CS:IP); entry = ``CS << 4 + IP``
* ``04`` — extended linear address; ``base = value << 16``
* ``05`` — start linear address; entry = 32-bit value

Every record is validated for byte-count and two's-complement checksum.
Rewriting an address with an identical byte is accepted; a conflicting
byte is reported with its line number and address, and the first value
written is kept.
"""

from __future__ import annotations

from dataclasses import dataclass

RECORD_TYPE_NAMES = {
    0x00: "data",
    0x01: "eof",
    0x02: "extended_segment_address",
    0x03: "start_segment_address",
    0x04: "extended_linear_address",
    0x05: "start_linear_address",
}

# Mandatory data payload length for non-data record types.
EXPECTED_PAYLOAD = {0x01: 0, 0x02: 2, 0x03: 4, 0x04: 2, 0x05: 4}


@dataclass
class LineDiagnostic:
    """Per-line outcome. ``line`` is 1-based; 0 means a file-level issue."""

    line: int
    status: str  # "ok" | "warning" | "error"
    record_type: str | None = None
    address: int | None = None
    byte_count: int | None = None
    message: str = ""


@dataclass
class Segment:
    start: int
    data: bytes

    @property
    def end(self) -> int:
        """Exclusive end address."""
        return self.start + len(self.data)


@dataclass
class Gap:
    start: int  # inclusive
    end: int  # exclusive

    @property
    def size(self) -> int:
        return self.end - self.start


@dataclass
class ParseResult:
    ok: bool
    segments: list[Segment]
    gaps: list[Gap]
    entry_address: int | None
    diagnostics: list[LineDiagnostic]
    total_bytes: int
    error_count: int
    warning_count: int


def _fmt(addr: int) -> str:
    return f"0x{addr:04X}"


def parse_intel_hex(text: str) -> ParseResult:
    """Parse Intel HEX text and assemble the firmware image."""
    diagnostics: list[LineDiagnostic] = []
    memory: dict[int, tuple[int, int]] = {}  # address -> (value, source line)
    base = 0
    entry_address: int | None = None
    eof_seen = False

    def diag(line_no: int, status: str, message: str, **kw) -> None:
        diagnostics.append(LineDiagnostic(line=line_no, status=status, message=message, **kw))

    lines = text.splitlines()
    for line_no, raw in enumerate(lines, start=1):
        line = raw.strip()
        if not line:
            diag(line_no, "warning", "empty line ignored")
            continue
        if eof_seen:
            diag(line_no, "error", "record after end-of-file record: EOF must be unique and on the last line")
            continue
        if not line.startswith(":"):
            diag(line_no, "error", "missing ':' start code")
            continue
        payload = line[1:]
        if len(payload) % 2:
            diag(line_no, "error", "odd number of hex digits")
            continue
        try:
            record = bytes.fromhex(payload)
        except ValueError:
            diag(line_no, "error", "invalid hexadecimal characters")
            continue
        if len(record) < 5:
            diag(line_no, "error", "record too short: need count, address, type and checksum")
            continue

        byte_count = record[0]
        offset = (record[1] << 8) | record[2]
        rectype = record[3]
        data = record[4:-1]
        type_name = RECORD_TYPE_NAMES.get(rectype)

        if type_name is None:
            diag(line_no, "error", f"unsupported record type 0x{rectype:02X}", record_type=f"0x{rectype:02X}")
            continue
        if byte_count != len(data):
            diag(
                line_no,
                "error",
                f"byte count mismatch: header declares {byte_count} byte(s), record carries {len(data)}",
                record_type=type_name,
                byte_count=byte_count,
            )
            continue
        if sum(record) & 0xFF:
            diag(
                line_no,
                "error",
                "checksum mismatch: bytes do not sum to 0 mod 256 (two's-complement check)",
                record_type=type_name,
                byte_count=byte_count,
            )
            continue
        expected = EXPECTED_PAYLOAD.get(rectype)
        if expected is not None and byte_count != expected:
            diag(
                line_no,
                "error",
                f"{type_name} record must carry exactly {expected} data byte(s), got {byte_count}",
                record_type=type_name,
                byte_count=byte_count,
            )
            continue

        if rectype == 0x00:
            address = base + offset
            duplicates = 0
            conflicts = 0
            for i, value in enumerate(data):
                addr = address + i
                prev = memory.get(addr)
                if prev is None:
                    memory[addr] = (value, line_no)
                elif prev[0] == value:
                    duplicates += 1
                else:
                    conflicts += 1
                    diag(
                        line_no,
                        "error",
                        f"address {_fmt(addr)}: value 0x{value:02X} conflicts with "
                        f"0x{prev[0]:02X} written at line {prev[1]}",
                        record_type=type_name,
                        address=addr,
                        byte_count=byte_count,
                    )
            if conflicts == 0:
                message = f"data: {byte_count} byte(s) at {_fmt(address)}"
                if duplicates:
                    message += f" ({duplicates} identical rewrite(s) accepted)"
                diag(line_no, "ok", message, record_type=type_name, address=address, byte_count=byte_count)
        elif rectype == 0x01:
            eof_seen = True
            diag(line_no, "ok", "end of file", record_type=type_name, byte_count=0)
        elif rectype == 0x02:
            base = int.from_bytes(data, "big") << 4
            diag(line_no, "ok", f"segment base set to {_fmt(base)}", record_type=type_name, address=base)
        elif rectype == 0x04:
            base = int.from_bytes(data, "big") << 16
            diag(line_no, "ok", f"linear base set to {_fmt(base)}", record_type=type_name, address=base)
        elif rectype == 0x03:
            cs = int.from_bytes(data[:2], "big")
            ip = int.from_bytes(data[2:], "big")
            new_entry = (cs << 4) + ip
            status = "ok"
            message = f"start segment address CS={_fmt(cs)} IP={_fmt(ip)} -> entry {_fmt(new_entry)}"
            if entry_address is not None and entry_address != new_entry:
                status = "warning"
                message += f" (overrides previous entry {_fmt(entry_address)})"
            entry_address = new_entry
            diag(line_no, status, message, record_type=type_name, address=new_entry)
        elif rectype == 0x05:
            new_entry = int.from_bytes(data, "big")
            status = "ok"
            message = f"start linear address -> entry {_fmt(new_entry)}"
            if entry_address is not None and entry_address != new_entry:
                status = "warning"
                message += f" (overrides previous entry {_fmt(entry_address)})"
            entry_address = new_entry
            diag(line_no, status, message, record_type=type_name, address=new_entry)

    if not eof_seen:
        diag(0, "error", "missing end-of-file record: EOF must appear exactly once, on the last line")

    segments = _build_segments(memory)
    gaps = [Gap(start=a.end, end=b.start) for a, b in zip(segments, segments[1:])]
    error_count = sum(1 for d in diagnostics if d.status == "error")
    warning_count = sum(1 for d in diagnostics if d.status == "warning")

    return ParseResult(
        ok=error_count == 0,
        segments=segments,
        gaps=gaps,
        entry_address=entry_address,
        diagnostics=diagnostics,
        total_bytes=sum(len(s.data) for s in segments),
        error_count=error_count,
        warning_count=warning_count,
    )


def _build_segments(memory: dict[int, tuple[int, int]]) -> list[Segment]:
    """Merge sparse bytes into contiguous, address-ordered segments."""
    segments: list[Segment] = []
    if not memory:
        return segments
    ordered = sorted(memory)
    start = ordered[0]
    blob = bytearray([memory[start][0]])
    prev = start
    for addr in ordered[1:]:
        if addr == prev + 1:
            blob.append(memory[addr][0])
        else:
            segments.append(Segment(start=start, data=bytes(blob)))
            start = addr
            blob = bytearray([memory[addr][0]])
        prev = addr
    segments.append(Segment(start=start, data=bytes(blob)))
    return segments
