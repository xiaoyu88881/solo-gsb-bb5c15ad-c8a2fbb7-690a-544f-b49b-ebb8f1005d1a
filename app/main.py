"""FastAPI firmware image assembly service."""

from __future__ import annotations

import base64
import binascii

from fastapi import Body, FastAPI
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, Field, model_validator

from .hex_export import export_intel_hex
from .hex_parser import ParseResult, parse_intel_hex
from .image_digest import build_image_digest
from .image_merge import MergeSource, merge_images
from .layout import Region, validate_layout
from .relocation import plan_relocation
from .flash_update import plan_flash_update
from .flash_verify import (
    BAD_WRITE_DATA,
    VerifyOperation,
    verify_flash_operations,
)
from .vector_table import VectorRegion, validate_vector_table

app = FastAPI(
    title="Firmware Image Assembly Service",
    version="1.0.0",
    description=(
        "Accepts Intel HEX text, validates every record (byte count and "
        "two's-complement checksum; record types 00/01/02/03/04/05), assembles "
        "the firmware image and returns contiguous Base64 segments, "
        "inter-segment gaps, the entry address and per-line diagnostics. "
        "The assembled image can also be validated against a set of named, "
        "non-overlapping memory regions (data/entry permissions, per-region "
        "occupancy and utilization), relocated as a whole by one integer "
        "delta whose feasible range is computed against those regions, "
        "diffed against another image to plan NOR-flash erase/write steps, "
        "replayed from a user-supplied ordered erase/write sequence to verify "
        "it reaches that target, read as a Cortex-M vector table checked "
        "against ram/executable memory regions, or fingerprinted with a "
        "canonical whole-image SHA-256 that is stable across record "
        "splitting and gap representations. The assembled image can also "
        "be re-emitted as a normalized Intel HEX text: deterministic "
        "data-record layout bounded by a configurable byte count, no "
        "record crossing a 64 KiB address window, extended linear "
        "address records on window switches, recomputed checksums and "
        "optional entry-address preservation."
    ),
)


class AssembleRequest(BaseModel):
    hex_text: str = Field(..., description="Intel HEX text, one record per line")

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "hex_text": (
                        ":020000040800F2\n"
                        ":10000000214601360121470136007EFE09D2190141\n"
                        ":04000005080001C12D\n"
                        ":00000001FF\n"
                    )
                }
            ]
        }
    }


class DiagnosticOut(BaseModel):
    line: int = Field(..., description="1-based line number; 0 marks a file-level issue")
    status: str = Field(..., description="ok | warning | error")
    record_type: str | None = None
    address: int | None = Field(None, description="Absolute address the record refers to, if any")
    byte_count: int | None = None
    message: str


class SegmentOut(BaseModel):
    start: int = Field(..., description="Absolute start address")
    end: int = Field(..., description="Exclusive end address")
    size: int
    data_base64: str = Field(..., description="Base64-encoded contiguous bytes")


class GapOut(BaseModel):
    start: int = Field(..., description="First unwritten address after the previous segment")
    end: int = Field(..., description="Start address of the next segment (exclusive)")
    size: int


class AssembleResponse(BaseModel):
    ok: bool = Field(..., description="True when no error-level diagnostic was raised")
    error_count: int
    warning_count: int
    entry_address: int | None = Field(None, description="From the last 03/05 record, if present")
    total_bytes: int
    segment_count: int
    segments: list[SegmentOut]
    gaps: list[GapOut]
    diagnostics: list[DiagnosticOut]


class RegionIn(BaseModel):
    name: str = Field(..., min_length=1, description="Region label")
    start: int = Field(..., ge=0, description="Inclusive start address")
    end: int = Field(..., ge=0, description="Exclusive end address (half-open interval)")
    allow_data: bool = Field(True, description="Whether firmware bytes may occupy this region")
    allow_entry: bool = Field(False, description="Whether the entry address may land in this region")


class ValidateLayoutRequest(BaseModel):
    hex_text: str = Field(..., description="Intel HEX text, one record per line")
    regions: list[RegionIn] = Field(
        ..., description="Memory regions; must be non-empty, non-overlapping half-open intervals"
    )

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "hex_text": (
                        ":020000040800F2\n"
                        ":10000000214601360121470136007EFE09D2190141\n"
                        ":04000005080001C12D\n"
                        ":00000001FF\n"
                    ),
                    "regions": [
                        {
                            "name": "flash",
                            "start": 134217728,
                            "end": 134479872,
                            "allow_data": True,
                            "allow_entry": True,
                        },
                        {
                            "name": "config",
                            "start": 134479872,
                            "end": 134484992,
                            "allow_data": True,
                            "allow_entry": False,
                        },
                    ],
                }
            ]
        }
    }


class FeasibleRangeOut(BaseModel):
    min_delta: int = Field(..., description="Most negative feasible delta (inclusive)")
    max_delta: int = Field(..., description="Most positive feasible delta (inclusive)")


class PlanRelocationRequest(BaseModel):
    hex_text: str = Field(..., description="Intel HEX text, one record per line")
    regions: list[RegionIn] = Field(
        ..., description="Memory regions; must be non-empty, non-overlapping half-open intervals"
    )
    max_abs_shift: int | None = Field(
        None,
        ge=0,
        description="Optional upper bound on |delta|; omitted means unconstrained",
    )

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "hex_text": (
                        ":020000040800F2\n"
                        ":10000000214601360121470136007EFE09D2190141\n"
                        ":04000005080001C12D\n"
                        ":00000001FF\n"
                    ),
                    "regions": [
                        {
                            "name": "flash",
                            "start": 134217728,
                            "end": 134610944,
                            "allow_data": True,
                            "allow_entry": True,
                        }
                    ],
                    "max_abs_shift": 262144,
                }
            ]
        }
    }


class PlanRelocationResponse(BaseModel):
    ok: bool = Field(..., description="True when the HEX is valid and no region-definition error exists")
    hex_ok: bool = Field(..., description="True when the Intel HEX text passed validation")
    regions_valid: bool | None = Field(
        ...,
        description="True when region definitions are non-empty and non-overlapping; "
        "null when the check did not run (invalid HEX)",
    )
    error_count: int
    warning_count: int
    entry_address: int | None = Field(
        None, description="Original entry from the last 03/05 record, if present"
    )
    total_bytes: int
    max_abs_shift: int | None = Field(None, description="The requested |delta| cap, if any")
    feasible: bool = Field(..., description="True when at least one delta satisfies every constraint")
    delta: int | None = Field(
        None, description="Chosen signed shift: smallest |delta|, ties towards the smaller value"
    )
    abs_shift: int | None = Field(None, description="|delta| of the chosen relocation")
    feasible_ranges: list[FeasibleRangeOut] = Field(
        ..., description="Merged closed integer intervals of every feasible delta"
    )
    relocated_entry_address: int | None = Field(
        None, description="Entry after applying delta, when feasible"
    )
    relocated_segments: list[SegmentOut] = Field(
        ..., description="Segments after applying delta, when feasible; empty otherwise"
    )
    violations: list[ViolationOut] = Field(
        ..., description="Region-definition violations (invalid_region / region_overlap), if any"
    )
    diagnostics: list[DiagnosticOut]


class ViolationOut(BaseModel):
    kind: str = Field(
        ...,
        description=(
            "uncovered_data | data_not_allowed | entry_uncovered | "
            "entry_not_allowed | invalid_region | region_overlap"
        ),
    )
    message: str
    start: int | None = Field(None, description="First affected address, if applicable")
    end: int | None = Field(None, description="Exclusive end of the affected range, if applicable")
    region: str | None = Field(None, description="Region the violation is tied to, if any")


class RegionReportOut(BaseModel):
    name: str
    start: int
    end: int
    size: int
    allow_data: bool
    allow_entry: bool
    occupied_bytes: int = Field(..., description="Firmware bytes that fall inside this region")
    utilization: float = Field(..., description="occupied_bytes / size (0 for empty regions)")
    violations: list[ViolationOut]


class ValidateLayoutResponse(BaseModel):
    ok: bool = Field(..., description="True when the HEX is valid and no layout violation was found")
    hex_ok: bool = Field(..., description="True when the Intel HEX text passed validation")
    regions_valid: bool | None = Field(
        ...,
        description="True when region definitions are non-empty and non-overlapping; "
        "null when the layout check did not run (invalid HEX)",
    )
    error_count: int
    warning_count: int
    entry_address: int | None = Field(None, description="From the last 03/05 record, if present")
    total_bytes: int
    regions: list[RegionReportOut]
    violations: list[ViolationOut] = Field(
        ..., description="Every violation, including uncovered ranges (region = null)"
    )
    diagnostics: list[DiagnosticOut]


class PlanFlashUpdateRequest(BaseModel):
    current_hex: str = Field(..., description="Intel HEX text of the image currently in flash")
    target_hex: str = Field(..., description="Intel HEX text of the image to reach")
    flash_start: int = Field(..., ge=0, description="Inclusive start of the flash window")
    flash_end: int = Field(..., ge=0, description="Exclusive end of the flash window")
    erase_block_size: int = Field(
        ..., ge=1, description="Uniform erase-sector size in bytes; flash_start/end must align to it"
    )
    max_write_size: int = Field(
        ..., ge=1, description="Maximum bytes per write; writes never cross an erase block"
    )

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "current_hex": ":10000000000102030405060708090A0B0C0D0E0F78\n:00000001FF\n",
                    "target_hex": ":10000000FF0102030405060708090A0B0C0D0E0F79\n:00000001FF\n",
                    "flash_start": 0,
                    "flash_end": 256,
                    "erase_block_size": 64,
                    "max_write_size": 16,
                }
            ]
        }
    }


class FlashParamErrorOut(BaseModel):
    kind: str = Field(
        ...,
        description="invalid_flash_range | erase_block_unaligned | "
        "invalid_max_write_size | image_outside_flash",
    )
    message: str
    start: int | None = Field(None, description="First affected address, if applicable")
    end: int | None = Field(None, description="Exclusive end of the affected range, if applicable")


class FlashBlockOut(BaseModel):
    address: int = Field(..., description="Erase-block start address")
    size: int = Field(..., description="Always erase_block_size")
    erase: bool = Field(..., description="Whether the block must be erased")
    erase_size: int | None = Field(None, description="erase_block_size when erased, else null")
    write_bytes: int = Field(..., description="Bytes written inside this block")
    changed_bytes: int = Field(..., description="Addresses whose target differs from current")
    zero_to_one_bytes: int = Field(
        ..., description="Changed addresses with at least one 0 -> 1 bit transition"
    )


class FlashOperationOut(BaseModel):
    kind: str = Field(..., description="erase | write")
    address: int = Field(..., description="Operation start address (erase == block start)")
    end: int = Field(..., description="Exclusive end address")
    size: int
    block: int = Field(..., description="Start address of the owning erase block")
    data_base64: str | None = Field(
        None, description="Target bytes for a write op; null for erase ops"
    )


class PlanFlashUpdateResponse(BaseModel):
    ok: bool = Field(
        ..., description="True when both HEX images and every parameter are valid and a plan exists"
    )
    current_hex_ok: bool = Field(..., description="True when current_hex passed validation")
    target_hex_ok: bool = Field(..., description="True when target_hex passed validation")
    params_valid: bool | None = Field(
        ...,
        description="True when the flash window/alignment parameters and image placement are "
        "valid; null when the parameter check did not run (either HEX invalid)",
    )
    flash_start: int
    flash_end: int
    erase_block_size: int
    max_write_size: int
    error_count: int = Field(..., description="Error diagnostics across both HEX texts")
    warning_count: int = Field(..., description="Warning diagnostics across both HEX texts")
    current_diagnostics: list[DiagnosticOut]
    target_diagnostics: list[DiagnosticOut]
    param_errors: list[FlashParamErrorOut] = Field(
        ..., description="Parameter-level problems; non-empty only when params_valid is false"
    )
    affected_blocks: list[FlashBlockOut] = Field(..., description="Blocks changed by the update")
    operations: list[FlashOperationOut] = Field(
        ..., description="Ordered erase/write steps: address order, erase before writes in a block"
    )
    affected_block_count: int
    erase_count: int
    erase_bytes: int
    write_count: int
    write_bytes: int = Field(..., description="Sum of bytes carried by write operations")
    changed_bytes: int = Field(..., description="Addresses where current and target differ")
    zero_to_one_bytes: int = Field(
        ..., description="Changed addresses requiring erase (any 0 -> 1 bit transition)"
    )


class FlashOperationIn(BaseModel):
    kind: str = Field(..., description="erase | write")
    address: int = Field(
        ..., description="Operation start address (erase == block start)"
    )
    size: int = Field(..., description="Bytes covered by the operation (>= 1)")
    data_base64: str | None = Field(
        None, description="Payload bytes for a write op (Base64); null for erase ops"
    )


class VerifyFlashOperationsRequest(BaseModel):
    current_hex: str = Field(..., description="Intel HEX text of the image currently in flash")
    target_hex: str = Field(..., description="Intel HEX text of the image to reach")
    flash_start: int = Field(..., ge=0, description="Inclusive start of the flash window")
    flash_end: int = Field(..., ge=0, description="Exclusive end of the flash window")
    erase_block_size: int = Field(
        ..., ge=1, description="Uniform erase-sector size in bytes; flash_start/end must align to it"
    )
    max_write_size: int = Field(
        ..., ge=1, description="Maximum bytes per write; writes never cross an erase block"
    )
    operations: list[FlashOperationIn] = Field(
        ..., description="Ordered erase/write steps replayed exactly as given"
    )

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "current_hex": ":10000000000102030405060708090A0B0C0D0E0F78\n:00000001FF\n",
                    "target_hex": ":10000000FF0102030405060708090A0B0C0D0E0F79\n:00000001FF\n",
                    "flash_start": 0,
                    "flash_end": 256,
                    "erase_block_size": 64,
                    "max_write_size": 16,
                    "operations": [
                        {"kind": "erase", "address": 0, "size": 64, "data_base64": None},
                        {
                            "kind": "write",
                            "address": 1,
                            "size": 15,
                            "data_base64": "AQIDBAUGBwgJCgsMDQ4P",
                        },
                    ],
                }
            ]
        }
    }


class FlashOperationErrorOut(BaseModel):
    kind: str = Field(
        ...,
        description=(
            "unknown_operation_kind | operation_outside_flash | "
            "erase_not_block_aligned | write_crosses_block | "
            "write_too_long | write_data_invalid | write_data_size_mismatch | "
            "write_zero_to_one"
        ),
    )
    index: int = Field(..., description="Index of the first illegal operation (0-based)")
    message: str
    start: int | None = Field(None, description="First affected address, if applicable")
    end: int | None = Field(None, description="Exclusive end of the affected range, if applicable")


class FlashDiffRangeOut(BaseModel):
    start: int = Field(..., description="First address of a contiguous differing run")
    end: int = Field(..., description="Exclusive end address of the run")
    size: int


class VerifyFlashOperationsResponse(BaseModel):
    ok: bool = Field(
        ...,
        description="True when HEX/params/operations are all valid and replay matches target exactly",
    )
    current_hex_ok: bool = Field(..., description="True when current_hex passed validation")
    target_hex_ok: bool = Field(..., description="True when target_hex passed validation")
    params_valid: bool | None = Field(
        ...,
        description="True when the flash window/alignment parameters and image placement are "
        "valid; null when the parameter check did not run (either HEX invalid)",
    )
    operations_valid: bool = Field(
        ..., description="True when every supplied operation is legal and replayed without error"
    )
    matches_target: bool = Field(
        ..., description="True when the replayed image is byte-identical to the target"
    )
    flash_start: int
    flash_end: int
    erase_block_size: int
    max_write_size: int
    error_count: int = Field(..., description="Error diagnostics across both HEX texts")
    warning_count: int = Field(..., description="Warning diagnostics across both HEX texts")
    current_diagnostics: list[DiagnosticOut]
    target_diagnostics: list[DiagnosticOut]
    param_errors: list[FlashParamErrorOut] = Field(
        ..., description="Parameter-level problems; non-empty only when params_valid is false"
    )
    operation_count: int = Field(..., description="Number of operations supplied")
    executed_count: int = Field(
        ..., description="Operations applied before replay stopped (all of them when legal)"
    )
    illegal_index: int | None = Field(
        None, description="Index of the first illegal operation, null when all are legal"
    )
    error_code: str | None = Field(
        None, description="Error kind of the first illegal operation, null when all are legal"
    )
    operation_error: FlashOperationErrorOut | None = Field(
        None, description="Full detail of the first illegal operation, null when all are legal"
    )
    diffs: list[FlashDiffRangeOut] = Field(
        ..., description="Contiguous runs differing from target (empty when operations stopped)"
    )
    diff_byte_count: int = Field(..., description="Total addresses differing from target")


class VectorRegionIn(BaseModel):
    name: str = Field(..., min_length=1, description="Region label")
    start: int = Field(..., ge=0, description="Inclusive start address")
    end: int = Field(..., ge=0, description="Exclusive end address (half-open interval)")
    ram: bool = Field(False, description="Whether this region is RAM (initial SP must land in one)")
    executable: bool = Field(
        False, description="Whether vector targets may execute from this region"
    )


class ValidateVectorTableRequest(BaseModel):
    hex_text: str = Field(..., description="Intel HEX text, one record per line")
    vector_table_start: int = Field(..., ge=0, description="Absolute address of vector 0")
    vector_count: int = Field(
        ..., ge=2, description="Number of 32-bit vectors; at least initial SP + reset"
    )
    regions: list[VectorRegionIn] = Field(
        ...,
        description="Memory regions with ram/executable attributes; "
        "non-overlapping half-open intervals",
    )

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "hex_text": (
                        ":020000040800F2\n"
                        ":1000000000000220010100080000000001020008B9\n"
                        ":00000001FF\n"
                    ),
                    "vector_table_start": 134217728,
                    "vector_count": 4,
                    "regions": [
                        {
                            "name": "flash",
                            "start": 134217728,
                            "end": 134479872,
                            "ram": False,
                            "executable": True,
                        },
                        {
                            "name": "ram",
                            "start": 536870912,
                            "end": 537001984,
                            "ram": True,
                            "executable": False,
                        },
                    ],
                }
            ]
        }
    }


class VectorEntryOut(BaseModel):
    index: int = Field(..., description="Vector number (0 = initial SP, 1 = reset)")
    address: int = Field(..., description="Absolute address of this entry in the image")
    role: str = Field(..., description="initial_sp | reset | handler")
    status: str = Field(..., description="ok | empty | error")
    value: int | None = Field(
        None, description="Parsed little-endian 32-bit word; null when bytes are missing"
    )
    target_address: int | None = Field(
        None, description="value with the Thumb bit cleared (non-zero handlers)"
    )
    missing_bytes: list[int] = Field(
        ..., description="Absolute addresses of the bytes absent from the image"
    )
    message: str


class VectorViolationOut(BaseModel):
    kind: str = Field(
        ...,
        description=(
            "invalid_region | region_overlap | missing_vector_bytes | "
            "stack_misaligned | stack_outside_ram | reset_vector_zero | "
            "thumb_bit_missing | address_not_executable"
        ),
    )
    message: str
    index: int | None = Field(None, description="Vector entry the violation is tied to, if any")
    address: int | None = Field(None, description="Address the violation refers to, if any")
    region: str | None = Field(None, description="Region the violation is tied to, if any")


class ValidateVectorTableResponse(BaseModel):
    ok: bool = Field(
        ..., description="True when the HEX and regions are valid and no vector violation was found"
    )
    hex_ok: bool = Field(..., description="True when the Intel HEX text passed validation")
    regions_valid: bool | None = Field(
        ...,
        description="True when region definitions are non-empty and non-overlapping; "
        "null when the check did not run (invalid HEX)",
    )
    error_count: int
    warning_count: int
    entry_address: int | None = Field(None, description="From the last 03/05 record, if present")
    total_bytes: int
    vector_table_start: int
    vector_count: int
    vectors: list[VectorEntryOut] = Field(
        ..., description="Per-entry status and parsed value; empty when validation did not run"
    )
    violations: list[VectorViolationOut] = Field(
        ..., description="Every violation: region-definition problems and per-vector failures"
    )
    diagnostics: list[DiagnosticOut]


class MergeImageIn(BaseModel):
    name: str = Field(..., min_length=1, description="Unique label identifying this source")
    hex_text: str = Field(..., description="Intel HEX text of this source, one record per line")


class MergeImagesRequest(BaseModel):
    images: list[MergeImageIn] = Field(
        ...,
        min_length=1,
        description="Images to overlay; every name must be unique",
    )

    @model_validator(mode="after")
    def _require_unique_names(self) -> MergeImagesRequest:
        seen: set[str] = set()
        duplicates = [img.name for img in self.images if img.name in seen or seen.add(img.name)]
        if duplicates:
            raise ValueError(
                "image names must be unique; duplicate name(s): "
                + ", ".join(sorted(set(duplicates)))
            )
        return self

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "images": [
                        {
                            "name": "bootloader",
                            "hex_text": (
                                ":020000040800F2\n"
                                ":10000000214601360121470136007EFE09D2190141\n"
                                ":00000001FF\n"
                            ),
                        },
                        {
                            "name": "application",
                            "hex_text": (
                                ":020000040800F2\n"
                                ":0400100001020304F0\n"
                                ":00000001FF\n"
                            ),
                        },
                    ]
                }
            ]
        }
    }


class MergeSourceOut(BaseModel):
    name: str = Field(..., description="Source name as given in the request")
    ok: bool = Field(..., description="True when this source passed HEX validation")
    error_count: int
    warning_count: int
    diagnostics: list[DiagnosticOut] = Field(
        ..., description="The source's original per-line parse diagnostics"
    )


class MergedSegmentOut(BaseModel):
    start: int = Field(..., description="Absolute start address")
    end: int = Field(..., description="Exclusive end address")
    size: int
    data_base64: str = Field(..., description="Base64-encoded contiguous merged bytes")
    sources: list[str] = Field(
        ..., description="Contributing sources for every byte of this segment (request order)"
    )


class ConflictChunkOut(BaseModel):
    source: str = Field(..., description="Source contributing this chunk")
    start: int = Field(..., description="Absolute start address of the chunk")
    end: int = Field(..., description="Exclusive end address of the chunk")
    size: int
    data_base64: str = Field(..., description="This source's bytes over the chunk")


class ByteConflictOut(BaseModel):
    start: int = Field(..., description="First conflicting address of the contiguous run")
    end: int = Field(..., description="Exclusive end address of the run")
    size: int = Field(..., description="Number of conflicting bytes in the run")
    message: str
    chunks: list[ConflictChunkOut] = Field(
        ..., description="Per-source contiguous value chunks covering this run"
    )


class EntryConflictOut(BaseModel):
    message: str
    entries: dict[str, int] = Field(
        ..., description="Entry address given by every source that defines one"
    )


class MergeImagesResponse(BaseModel):
    ok: bool = Field(
        ..., description="True when every source parses and no conflict prevents the merge"
    )
    sources: list[MergeSourceOut] = Field(
        ..., description="Per-source parse status and original diagnostics"
    )
    entry_address: int | None = Field(
        None, description="Agreed entry address; null when absent or when no merge was produced"
    )
    total_bytes: int = Field(
        ..., description="Distinct addresses covered by the sources (0 when a source is invalid)"
    )
    merged_segments: list[MergedSegmentOut] | None = Field(
        None,
        description="Contiguous merged segments; omitted entirely when sources are invalid "
        "or any conflict prevents the merge",
    )
    conflicts: list[ByteConflictOut] = Field(
        ..., description="Contiguous runs of bytes whose sources disagree"
    )
    entry_conflict: EntryConflictOut | None = Field(
        None, description="Set when sources define different non-null entry addresses"
    )


class ImageDigestRequest(BaseModel):
    hex_text: str = Field(..., description="Intel HEX text, one record per line")
    include_entry: bool = Field(
        True,
        description=(
            "Whether the entry address participates in the whole-image hash "
            "(default true; false hashes bytes and placement only)"
        ),
    )

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "hex_text": (
                        ":020000040800F2\n"
                        ":10000000214601360121470136007EFE09D2190141\n"
                        ":04000005080001C12D\n"
                        ":00000001FF\n"
                    ),
                    "include_entry": True,
                }
            ]
        }
    }


class SegmentDigestOut(BaseModel):
    index: int = Field(..., description="Zero-based position in address order")
    start: int = Field(..., description="Absolute start address")
    end: int = Field(..., description="Exclusive end address")
    size: int
    gap_before: int = Field(
        ...,
        description="Uncovered bytes between the previous segment and this one (0 for index 0)",
    )
    sha256: str = Field(
        ...,
        description="SHA-256 of this segment's canonical frame (tag + start + length + bytes)",
    )


class CanonicalFrameOut(BaseModel):
    kind: str = Field(..., description="segment | entry | no_entry")
    index: int | None = Field(None, description="Segment index for segment frames")
    start: int | None = Field(None, description="Segment start for segment frames")
    end: int | None = Field(None, description="Exclusive segment end for segment frames")
    size: int | None = Field(None, description="Segment byte count for segment frames")
    sha256: str | None = Field(None, description="Frame SHA-256 for segment frames")
    address: int | None = Field(None, description="Entry address for the entry frame")


class CanonicalManifestOut(BaseModel):
    format: str = Field(..., description="Canonical encoding format identifier")
    hash_algorithm: str
    include_entry: bool = Field(..., description="Whether the entry frame is part of the stream")
    segment_count: int
    total_bytes: int
    frame_count: int = Field(..., description="Number of frames listed and fed to the hash")
    canonical_bytes: int = Field(
        ..., description="Total byte length of the canonical stream that was hashed"
    )
    frames: list[CanonicalFrameOut] = Field(
        ..., description="Frames in hashing order (segments ascending, then entry marker)"
    )


class ImageDigestResponse(BaseModel):
    ok: bool = Field(..., description="True when no error-level diagnostic was raised")
    error_count: int
    warning_count: int
    entry_address: int | None = Field(
        None, description="From the last 03/05 record, if present; null when parsing failed"
    )
    include_entry: bool = Field(
        ..., description="Echoes the request; when false no entry frame entered the hash"
    )
    total_bytes: int = Field(..., description="Sum of segment byte counts (0 when parsing failed)")
    image_sha256: str | None = Field(
        None,
        description="Whole-image SHA-256 over the canonical stream; null when parsing failed",
    )
    segments: list[SegmentDigestOut] = Field(
        ..., description="Per-segment summaries in address order; empty when parsing failed"
    )
    manifest: CanonicalManifestOut | None = Field(
        None, description="Normalized description of exactly what was hashed; null on failure"
    )
    diagnostics: list[DiagnosticOut]


class ExportHexRequest(BaseModel):
    hex_text: str = Field(..., description="Intel HEX text, one record per line")
    max_data_bytes: int = Field(
        16,
        ge=1,
        le=255,
        description="Maximum payload bytes per emitted data record (the count field is one byte)",
    )
    include_entry: bool = Field(
        True,
        description=(
            "Whether a start linear address record (type 05) preserving the "
            "entry address is appended before the EOF record (default true)"
        ),
    )

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "hex_text": (
                        ":020000040800F2\n"
                        ":10000000214601360121470136007EFE09D2190141\n"
                        ":04000005080001C12D\n"
                        ":00000001FF\n"
                    ),
                    "max_data_bytes": 16,
                    "include_entry": True,
                }
            ]
        }
    }


class ExportHexResponse(BaseModel):
    ok: bool = Field(..., description="True when no error-level diagnostic was raised")
    error_count: int
    warning_count: int
    entry_address: int | None = Field(
        None, description="From the last 03/05 record, if present; null when parsing failed"
    )
    total_bytes: int = Field(..., description="Sum of segment byte counts (0 when parsing failed)")
    max_data_bytes: int = Field(..., description="Echoes the requested data-record byte cap")
    include_entry: bool = Field(..., description="Echoes the request")
    exported_hex: str | None = Field(
        None, description="Normalized Intel HEX text; null when parsing failed"
    )
    record_count: int = Field(
        ..., description="Total emitted records including EOF (0 when parsing failed)"
    )
    data_record_count: int = Field(..., description="Emitted type 00 records")
    extended_address_record_count: int = Field(
        ..., description="Emitted type 04 records (one per 64 KiB window switch)"
    )
    entry_record_count: int = Field(..., description="Emitted type 05 records (0 or 1)")
    diagnostics: list[DiagnosticOut]


def _build_response(result: ParseResult) -> AssembleResponse:
    return AssembleResponse(
        ok=result.ok,
        error_count=result.error_count,
        warning_count=result.warning_count,
        entry_address=result.entry_address,
        total_bytes=result.total_bytes,
        segment_count=len(result.segments),
        segments=[
            SegmentOut(
                start=s.start,
                end=s.end,
                size=len(s.data),
                data_base64=base64.b64encode(s.data).decode("ascii"),
            )
            for s in result.segments
        ],
        gaps=[GapOut(start=g.start, end=g.end, size=g.size) for g in result.gaps],
        diagnostics=[DiagnosticOut(**vars(d)) for d in result.diagnostics],
    )


@app.get("/", include_in_schema=False)
def root() -> RedirectResponse:
    return RedirectResponse(url="/docs")


@app.get("/health", tags=["meta"])
def health() -> dict:
    return {"status": "ok"}


@app.post("/api/v1/assemble", response_model=AssembleResponse, tags=["assemble"])
def assemble(request: AssembleRequest) -> AssembleResponse:
    """Assemble a firmware image from Intel HEX text sent as JSON."""
    return _build_response(parse_intel_hex(request.hex_text))


@app.post("/api/v1/assemble/raw", response_model=AssembleResponse, tags=["assemble"])
def assemble_raw(hex_text: str = Body(..., media_type="text/plain")) -> AssembleResponse:
    """Assemble a firmware image from a raw Intel HEX text body (text/plain)."""
    return _build_response(parse_intel_hex(hex_text))


@app.post("/api/v1/image-digest", response_model=ImageDigestResponse, tags=["digest"])
def image_digest_route(request: ImageDigestRequest) -> ImageDigestResponse:
    """Fingerprint an assembled firmware image with a canonical SHA-256.

    The HEX text is parsed with the shared validator and the same
    diagnostics are returned. When parsing fails no digest is produced:
    ``image_sha256``/``manifest`` are null and ``segments`` is empty.
    Otherwise the sparse, address-ordered segments are encoded as
    explicit self-delimiting frames (segment tag, 64-bit absolute start,
    64-bit length, raw bytes), optionally followed by an entry frame
    (``include_entry``, default true), and the resulting canonical
    stream is hashed with SHA-256. Because only absolute placement and
    byte content enter the stream, different record splitting or gap
    representations of the same image hash identically. Per-segment
    frame hashes, total byte count, the entry address and a normalized
    manifest of every hashed frame are returned as well.
    """
    parsed = parse_intel_hex(request.hex_text)
    diagnostics = [DiagnosticOut(**vars(d)) for d in parsed.diagnostics]
    if not parsed.ok:
        return ImageDigestResponse(
            ok=False,
            error_count=parsed.error_count,
            warning_count=parsed.warning_count,
            entry_address=None,
            include_entry=request.include_entry,
            total_bytes=0,
            image_sha256=None,
            segments=[],
            manifest=None,
            diagnostics=diagnostics,
        )

    digest = build_image_digest(
        parsed.segments,
        parsed.entry_address,
        include_entry=request.include_entry,
    )
    return ImageDigestResponse(
        ok=True,
        error_count=parsed.error_count,
        warning_count=parsed.warning_count,
        entry_address=digest.entry_address,
        include_entry=digest.include_entry,
        total_bytes=digest.total_bytes,
        image_sha256=digest.image_sha256,
        segments=[
            SegmentDigestOut(
                index=segment.index,
                start=segment.start,
                end=segment.end,
                size=segment.size,
                gap_before=segment.gap_before,
                sha256=segment.sha256,
            )
            for segment in digest.segments
        ],
        manifest=CanonicalManifestOut(
            format=digest.manifest.format,
            hash_algorithm=digest.manifest.hash_algorithm,
            include_entry=digest.manifest.include_entry,
            segment_count=digest.manifest.segment_count,
            total_bytes=digest.manifest.total_bytes,
            frame_count=digest.manifest.frame_count,
            canonical_bytes=digest.manifest.canonical_bytes,
            frames=[
                CanonicalFrameOut(
                    kind=frame.kind,
                    index=frame.index,
                    start=frame.start,
                    end=frame.end,
                    size=frame.size,
                    sha256=frame.sha256,
                    address=frame.address,
                )
                for frame in digest.manifest.frames
            ],
        ),
        diagnostics=diagnostics,
    )


@app.post("/api/v1/validate-layout", response_model=ValidateLayoutResponse, tags=["layout"])
def validate_layout_route(request: ValidateLayoutRequest) -> ValidateLayoutResponse:
    """Validate an Intel HEX image against named memory regions.

    When the HEX text fails validation only parse diagnostics are returned
    (``regions``/``violations`` empty, ``regions_valid`` null). Otherwise the
    contiguous firmware segments are split at region boundaries and checked
    for coverage, ``allow_data``/``allow_entry`` permissions, and per-region
    occupancy is reported.
    """
    parsed = parse_intel_hex(request.hex_text)
    diagnostics = [DiagnosticOut(**vars(d)) for d in parsed.diagnostics]
    parse_fields = dict(
        error_count=parsed.error_count,
        warning_count=parsed.warning_count,
        entry_address=parsed.entry_address,
        total_bytes=parsed.total_bytes,
        diagnostics=diagnostics,
    )
    if not parsed.ok:
        return ValidateLayoutResponse(
            ok=False,
            hex_ok=False,
            regions_valid=None,
            regions=[],
            violations=[],
            **parse_fields,
        )

    layout = validate_layout(
        parsed.segments,
        parsed.entry_address,
        [
            Region(
                name=r.name,
                start=r.start,
                end=r.end,
                allow_data=r.allow_data,
                allow_entry=r.allow_entry,
            )
            for r in request.regions
        ],
    )
    return ValidateLayoutResponse(
        ok=layout.ok,
        hex_ok=True,
        regions_valid=layout.regions_valid,
        regions=[
            RegionReportOut(
                name=rep.region.name,
                start=rep.region.start,
                end=rep.region.end,
                size=rep.region.size,
                allow_data=rep.region.allow_data,
                allow_entry=rep.region.allow_entry,
                occupied_bytes=rep.occupied_bytes,
                utilization=rep.utilization,
                violations=[ViolationOut(**vars(v)) for v in rep.violations],
            )
            for rep in layout.reports
        ],
        violations=[ViolationOut(**vars(v)) for v in layout.violations],
        **parse_fields,
    )


@app.post("/api/v1/plan-relocation", response_model=PlanRelocationResponse, tags=["layout"])
def plan_relocation_route(request: PlanRelocationRequest) -> PlanRelocationResponse:
    """Plan a whole-image relocation by a single integer ``delta``.

    The HEX text is parsed and the region definitions are validated
    exactly as for ``/api/v1/validate-layout``; if either fails only the
    corresponding diagnostics/violations are returned and no planning
    runs. Otherwise every feasible delta is found: each firmware segment
    must fall wholly inside an ``allow_data`` region, the entry (if any)
    inside an ``allow_entry`` region, relocated addresses must remain
    32-bit, and ``|delta|`` must not exceed ``max_abs_shift`` when given.
    The returned ``delta`` minimizes ``|delta|`` and breaks ties towards
    the numerically smaller value; when no delta exists ``feasible`` is
    false and the relocated image is omitted.
    """
    parsed = parse_intel_hex(request.hex_text)
    diagnostics = [DiagnosticOut(**vars(d)) for d in parsed.diagnostics]
    parse_fields = dict(
        error_count=parsed.error_count,
        warning_count=parsed.warning_count,
        entry_address=parsed.entry_address,
        total_bytes=parsed.total_bytes,
        diagnostics=diagnostics,
    )
    if not parsed.ok:
        return PlanRelocationResponse(
            ok=False,
            hex_ok=False,
            regions_valid=None,
            feasible=False,
            feasible_ranges=[],
            relocated_segments=[],
            violations=[],
            max_abs_shift=request.max_abs_shift,
            **parse_fields,
        )

    regions = [
        Region(
            name=r.name,
            start=r.start,
            end=r.end,
            allow_data=r.allow_data,
            allow_entry=r.allow_entry,
        )
        for r in request.regions
    ]
    plan = plan_relocation(
        parsed.segments,
        parsed.entry_address,
        regions,
        request.max_abs_shift,
    )
    if not plan.regions_valid:
        return PlanRelocationResponse(
            ok=False,
            hex_ok=True,
            regions_valid=False,
            feasible=False,
            feasible_ranges=[],
            relocated_segments=[],
            violations=[ViolationOut(**vars(v)) for v in plan.region_violations],
            max_abs_shift=request.max_abs_shift,
            **parse_fields,
        )

    return PlanRelocationResponse(
        ok=True,
        hex_ok=True,
        regions_valid=True,
        feasible=plan.feasible,
        feasible_ranges=[
            FeasibleRangeOut(min_delta=lo, max_delta=hi) for lo, hi in plan.feasible_ranges
        ],
        delta=plan.delta,
        abs_shift=plan.abs_shift,
        relocated_entry_address=plan.entry_address,
        relocated_segments=[
            SegmentOut(
                start=s.start,
                end=s.end,
                size=len(s.data),
                data_base64=base64.b64encode(s.data).decode("ascii"),
            )
            for s in plan.segments
        ],
        violations=[],
        max_abs_shift=request.max_abs_shift,
        **parse_fields,
    )


@app.post("/api/v1/plan-flash-update", response_model=PlanFlashUpdateResponse, tags=["layout"])
def plan_flash_update_route(request: PlanFlashUpdateRequest) -> PlanFlashUpdateResponse:
    """Plan erase/write operations turning ``current_hex`` into ``target_hex``.

    Both Intel HEX texts are parsed with the shared validator; when
    either fails, its diagnostics are returned and no plan is made.
    Otherwise the flash window must be a non-empty 32-bit half-open
    interval whose start and end are aligned to ``erase_block_size``,
    and both images must lie wholly inside it. Missing addresses read
    as ``0xFF``. Blocks containing any byte with a ``0 -> 1`` bit
    transition are erased and rewritten with every non-``0xFF`` target
    byte; other blocks receive only the changed bytes. Pending writes
    are merged into contiguous runs and split at ``max_write_size`` and
    at erase-block boundaries.
    """
    current = parse_intel_hex(request.current_hex)
    target = parse_intel_hex(request.target_hex)
    error_count = current.error_count + target.error_count
    warning_count = current.warning_count + target.warning_count

    base_fields = dict(
        flash_start=request.flash_start,
        flash_end=request.flash_end,
        erase_block_size=request.erase_block_size,
        max_write_size=request.max_write_size,
        error_count=error_count,
        warning_count=warning_count,
        current_diagnostics=[DiagnosticOut(**vars(d)) for d in current.diagnostics],
        target_diagnostics=[DiagnosticOut(**vars(d)) for d in target.diagnostics],
    )

    if not (current.ok and target.ok):
        return PlanFlashUpdateResponse(
            ok=False,
            current_hex_ok=current.ok,
            target_hex_ok=target.ok,
            params_valid=None,
            param_errors=[],
            affected_blocks=[],
            operations=[],
            affected_block_count=0,
            erase_count=0,
            erase_bytes=0,
            write_count=0,
            write_bytes=0,
            changed_bytes=0,
            zero_to_one_bytes=0,
            **base_fields,
        )

    plan = plan_flash_update(
        current.segments,
        target.segments,
        request.flash_start,
        request.flash_end,
        request.erase_block_size,
        request.max_write_size,
    )
    if not plan.params_valid:
        return PlanFlashUpdateResponse(
            ok=False,
            current_hex_ok=True,
            target_hex_ok=True,
            params_valid=False,
            param_errors=[FlashParamErrorOut(**vars(e)) for e in plan.param_errors],
            affected_blocks=[],
            operations=[],
            affected_block_count=0,
            erase_count=0,
            erase_bytes=0,
            write_count=0,
            write_bytes=0,
            changed_bytes=0,
            zero_to_one_bytes=0,
            **base_fields,
        )

    return PlanFlashUpdateResponse(
        ok=True,
        current_hex_ok=True,
        target_hex_ok=True,
        params_valid=True,
        param_errors=[],
        affected_blocks=[
            FlashBlockOut(
                address=b.address,
                size=b.size,
                erase=b.erase,
                erase_size=b.erase_size,
                write_bytes=b.write_bytes,
                changed_bytes=b.changed_bytes,
                zero_to_one_bytes=b.zero_to_one_bytes,
            )
            for b in plan.blocks
        ],
        operations=[
            FlashOperationOut(
                kind=op.kind,
                address=op.address,
                end=op.end,
                size=op.size,
                block=op.block,
                data_base64=(
                    None
                    if op.kind == "erase"
                    else base64.b64encode(op.data).decode("ascii")
                ),
            )
            for op in plan.operations
        ],
        affected_block_count=plan.affected_block_count,
        erase_count=plan.erase_count,
        erase_bytes=plan.erase_bytes,
        write_count=plan.write_count,
        write_bytes=plan.write_bytes,
        changed_bytes=plan.changed_bytes,
        zero_to_one_bytes=plan.zero_to_one_bytes,
        **base_fields,
    )


@app.post(
    "/api/v1/verify-flash-operations",
    response_model=VerifyFlashOperationsResponse,
    tags=["layout"],
)
def verify_flash_operations_route(
    request: VerifyFlashOperationsRequest,
) -> VerifyFlashOperationsResponse:
    """Replay an ordered erase/write sequence and verify it reaches target.

    Both Intel HEX texts are parsed with the shared validator; when
    either fails, its diagnostics are returned and no operation is
    replayed. The flash window, ``erase_block_size`` alignment,
    ``max_write_size`` and image placement are validated exactly as for
    ``/api/v1/plan-flash-update``. Otherwise the supplied operations are
    replayed in order over the current image: an erase must be aligned to
    a whole erase block (its size a whole-block multiple), a write must
    stay inside the flash window and inside one erase block, carry at
    most ``max_write_size`` bytes with a matching Base64 payload, and may
    only clear bits (``1 -> 0``). The first illegal operation stops the
    replay and is reported by its index and error code. When every
    operation is legal the replay result is compared with the target
    (undefined bytes read as ``0xFF``); differing addresses are merged
    into maximal contiguous runs, and ``ok`` is true only with no diff.
    """
    current = parse_intel_hex(request.current_hex)
    target = parse_intel_hex(request.target_hex)
    error_count = current.error_count + target.error_count
    warning_count = current.warning_count + target.warning_count

    base_fields = dict(
        flash_start=request.flash_start,
        flash_end=request.flash_end,
        erase_block_size=request.erase_block_size,
        max_write_size=request.max_write_size,
        error_count=error_count,
        warning_count=warning_count,
        current_diagnostics=[DiagnosticOut(**vars(d)) for d in current.diagnostics],
        target_diagnostics=[DiagnosticOut(**vars(d)) for d in target.diagnostics],
    )

    if not (current.ok and target.ok):
        return VerifyFlashOperationsResponse(
            ok=False,
            current_hex_ok=current.ok,
            target_hex_ok=target.ok,
            params_valid=None,
            operations_valid=False,
            matches_target=False,
            param_errors=[],
            operation_count=len(request.operations),
            executed_count=0,
            illegal_index=None,
            error_code=None,
            operation_error=None,
            diffs=[],
            diff_byte_count=0,
            **base_fields,
        )

    operations: list[VerifyOperation] = []
    for op in request.operations:
        data: object = None
        if op.kind == "write":
            if op.data_base64 is None:
                data = BAD_WRITE_DATA
            else:
                try:
                    data = base64.b64decode(op.data_base64, validate=True)
                except (binascii.Error, ValueError):
                    data = BAD_WRITE_DATA
        operations.append(
            VerifyOperation(kind=op.kind, address=op.address, size=op.size, data=data)
        )

    result = verify_flash_operations(
        current.segments,
        target.segments,
        request.flash_start,
        request.flash_end,
        request.erase_block_size,
        request.max_write_size,
        operations,
    )
    if not result.params_valid:
        return VerifyFlashOperationsResponse(
            ok=False,
            current_hex_ok=True,
            target_hex_ok=True,
            params_valid=False,
            operations_valid=False,
            matches_target=False,
            param_errors=[FlashParamErrorOut(**vars(e)) for e in result.param_errors],
            operation_count=result.operation_count,
            executed_count=0,
            illegal_index=None,
            error_code=None,
            operation_error=None,
            diffs=[],
            diff_byte_count=0,
            **base_fields,
        )

    operation_error = (
        None
        if result.error is None
        else FlashOperationErrorOut(
            kind=result.error.kind,
            index=result.error.index,
            message=result.error.message,
            start=result.error.start,
            end=result.error.end,
        )
    )
    return VerifyFlashOperationsResponse(
        ok=result.ok,
        current_hex_ok=True,
        target_hex_ok=True,
        params_valid=True,
        operations_valid=result.operations_valid,
        matches_target=result.matches_target,
        param_errors=[],
        operation_count=result.operation_count,
        executed_count=result.executed_count,
        illegal_index=None if result.error is None else result.error.index,
        error_code=None if result.error is None else result.error.kind,
        operation_error=operation_error,
        diffs=[
            FlashDiffRangeOut(start=d.start, end=d.end, size=d.size) for d in result.diffs
        ],
        diff_byte_count=result.diff_byte_count,
        **base_fields,
    )


@app.post(
    "/api/v1/validate-vector-table",
    response_model=ValidateVectorTableResponse,
    tags=["vector-table"],
)
def validate_vector_table_route(
    request: ValidateVectorTableRequest,
) -> ValidateVectorTableResponse:
    """Validate a Cortex-M vector table read from the assembled image.

    The HEX text is parsed with the shared validator; when it fails only
    parse diagnostics are returned (``vectors``/``violations`` empty,
    ``regions_valid`` null). Region definitions must be non-empty,
    non-overlapping half-open intervals; unsound definitions abort the
    check as well. Otherwise ``vector_count`` little-endian 32-bit words
    are read from ``vector_table_start``: any missing byte is reported
    with its entry index and address; entry 0 (initial SP) must be
    8-byte aligned and land in a ``ram`` region (the RAM end address
    itself is allowed); entry 1 (reset) must be non-zero; other zero
    vectors are accepted as empty slots. Every non-zero processor
    address must carry the Thumb bit, and the address with that bit
    cleared must fall inside an ``executable`` region.
    """
    parsed = parse_intel_hex(request.hex_text)
    diagnostics = [DiagnosticOut(**vars(d)) for d in parsed.diagnostics]
    parse_fields = dict(
        error_count=parsed.error_count,
        warning_count=parsed.warning_count,
        entry_address=parsed.entry_address,
        total_bytes=parsed.total_bytes,
        vector_table_start=request.vector_table_start,
        vector_count=request.vector_count,
        diagnostics=diagnostics,
    )
    if not parsed.ok:
        return ValidateVectorTableResponse(
            ok=False,
            hex_ok=False,
            regions_valid=None,
            vectors=[],
            violations=[],
            **parse_fields,
        )

    result = validate_vector_table(
        parsed.segments,
        request.vector_table_start,
        request.vector_count,
        [
            VectorRegion(
                name=r.name,
                start=r.start,
                end=r.end,
                ram=r.ram,
                executable=r.executable,
            )
            for r in request.regions
        ],
    )
    return ValidateVectorTableResponse(
        ok=result.ok,
        hex_ok=True,
        regions_valid=result.regions_valid,
        vectors=[VectorEntryOut(**vars(e)) for e in result.entries],
        violations=[VectorViolationOut(**vars(v)) for v in result.violations],
        **parse_fields,
    )


@app.post(
    "/api/v1/merge-images",
    responses={200: {"model": MergeImagesResponse}},
    tags=["merge"],
)
def merge_images_route(request: MergeImagesRequest) -> dict:
    """Merge several Intel HEX images by overlaying them at absolute addresses.

    Every image is parsed with the shared validator. If any source is
    invalid, its name and original diagnostics are returned and no
    merging happens. Otherwise the images are overlaid: identical bytes
    at overlapping addresses merge and keep every contributing source;
    disagreeing bytes are reported as maximal contiguous conflict runs
    with each source's values, and differing/mixed entry addresses as an
    ``entry_conflict``. On success (all entries absent, or the same
    non-null entry) contiguous Base64 segments are returned, each with
    the set of sources contributing its bytes; segments also split when
    that source set changes.
    """
    parsed_sources = [
        MergeSource(name=image.name, parsed=parse_intel_hex(image.hex_text))
        for image in request.images
    ]
    source_reports = [
        MergeSourceOut(
            name=source.name,
            ok=source.parsed.ok,
            error_count=source.parsed.error_count,
            warning_count=source.parsed.warning_count,
            diagnostics=[DiagnosticOut(**vars(d)) for d in source.parsed.diagnostics],
        )
        for source in parsed_sources
    ]

    invalid = any(not source.parsed.ok for source in parsed_sources)
    if invalid:
        # No merge was attempted: omit merged_segments entirely.
        return {
            "ok": False,
            "sources": source_reports,
            "entry_address": None,
            "total_bytes": 0,
            "conflicts": [],
            "entry_conflict": None,
        }

    result = merge_images(parsed_sources)
    payload: dict = {
        "ok": result.ok,
        "sources": source_reports,
        "entry_address": result.entry_address,
        "total_bytes": result.total_bytes,
        "conflicts": [
            ByteConflictOut(
                start=c.start,
                end=c.end,
                size=c.length,
                message=c.message,
                chunks=[
                    ConflictChunkOut(
                        source=chunk.source,
                        start=chunk.start,
                        end=chunk.end,
                        size=len(chunk.data),
                        data_base64=base64.b64encode(chunk.data).decode("ascii"),
                    )
                    for chunk in c.chunks
                ],
            )
            for c in result.conflicts
        ],
        "entry_conflict": None
        if result.entry_conflict is None
        else EntryConflictOut(
            message=result.entry_conflict.message,
            entries=dict(result.entry_conflict.entries),
        ),
    }
    if result.ok:
        payload["merged_segments"] = [
            MergedSegmentOut(
                start=s.start,
                end=s.end,
                size=len(s.data),
                data_base64=base64.b64encode(s.data).decode("ascii"),
                sources=s.sources,
            )
            for s in result.segments
        ]
    return payload


@app.post("/api/v1/export-hex", response_model=ExportHexResponse, tags=["export"])
def export_hex_route(request: ExportHexRequest) -> ExportHexResponse:
    """Re-emit an assembled firmware image as normalized Intel HEX text.

    The HEX text is parsed with the shared validator and the same
    diagnostics are returned. When parsing fails no text is produced:
    ``exported_hex`` is null and every record count is 0. Otherwise the
    contiguous image is re-emitted deterministically: data records
    carry at most ``max_data_bytes`` bytes and never cross a 64 KiB
    address window, an extended linear address record (type 04) is
    emitted whenever the window switches, every checksum is recomputed,
    and the entry address (if any) is preserved as a start linear
    address record (type 05) unless ``include_entry`` is false. The
    output depends only on the assembled image, so re-exporting an
    exported text reproduces it byte for byte.
    """
    parsed = parse_intel_hex(request.hex_text)
    diagnostics = [DiagnosticOut(**vars(d)) for d in parsed.diagnostics]
    base_fields = dict(
        error_count=parsed.error_count,
        warning_count=parsed.warning_count,
        max_data_bytes=request.max_data_bytes,
        include_entry=request.include_entry,
        diagnostics=diagnostics,
    )
    if not parsed.ok:
        return ExportHexResponse(
            ok=False,
            entry_address=None,
            total_bytes=0,
            exported_hex=None,
            record_count=0,
            data_record_count=0,
            extended_address_record_count=0,
            entry_record_count=0,
            **base_fields,
        )

    exported = export_intel_hex(
        parsed.segments,
        parsed.entry_address,
        max_data_bytes=request.max_data_bytes,
        include_entry=request.include_entry,
    )
    return ExportHexResponse(
        ok=True,
        entry_address=exported.entry_address,
        total_bytes=parsed.total_bytes,
        exported_hex=exported.hex_text,
        record_count=exported.record_count,
        data_record_count=exported.data_record_count,
        extended_address_record_count=exported.extended_address_record_count,
        entry_record_count=exported.entry_record_count,
        **base_fields,
    )
