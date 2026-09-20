"""Tests for the /api/v1/merge-images endpoint and overlay-merge logic."""

import base64

from fastapi.testclient import TestClient

from app.hex_parser import parse_intel_hex
from app.image_merge import MergeSource, merge_images
from app.main import app

client = TestClient(app)


def rec(rectype: int, addr: int, data: bytes = b"") -> str:
    """Build a valid Intel HEX record line."""
    body = bytes([len(data), (addr >> 8) & 0xFF, addr & 0xFF, rectype]) + bytes(data)
    checksum = (-sum(body)) & 0xFF
    return ":" + (body + bytes([checksum])).hex().upper()


EOF = rec(0x01, 0)


def data_rec(addr: int, data: bytes) -> str:
    return rec(0x00, addr, data)


def linear_base(value: int) -> str:
    return rec(0x04, 0, value.to_bytes(2, "big"))


def linear_entry(value: int) -> str:
    return rec(0x05, 0, value.to_bytes(4, "big"))


def source(name: str, text: str) -> MergeSource:
    parsed = parse_intel_hex(text)
    assert parsed.ok, f"test fixture {name!r} must parse"
    return MergeSource(name=name, parsed=parsed)


# ---------------------------------------------------------------------------
# pure merge logic
# ---------------------------------------------------------------------------

def test_disjoint_images_merge_with_sources_per_segment():
    result = merge_images([
        source("a", "\n".join([data_rec(0x0000, b"\x01\x02"), EOF])),
        source("b", "\n".join([data_rec(0x0010, b"\x03"), EOF])),
    ])
    assert result.ok
    assert result.entry_address is None
    assert result.total_bytes == 3
    assert [(s.start, s.end, s.sources) for s in result.segments] == [
        (0x0000, 0x0002, ["a"]),
        (0x0010, 0x0011, ["b"]),
    ]


def test_identical_overlap_merges_and_records_all_sources():
    result = merge_images([
        source("a", "\n".join([data_rec(0x0000, b"\xAA\xBB"), EOF])),
        source("b", "\n".join([data_rec(0x0001, b"\xBB\xCC"), EOF])),
    ])
    assert result.ok
    assert result.conflicts == []
    # one contiguous physical run, split where the source set changes
    assert [(s.start, s.data, s.sources) for s in result.segments] == [
        (0x0000, b"\xAA", ["a"]),
        (0x0001, b"\xBB", ["a", "b"]),
        (0x0002, b"\xCC", ["b"]),
    ]
    assert result.total_bytes == 3


def test_three_way_identical_overlap():
    text = "\n".join([data_rec(0x0000, b"\x7F"), EOF])
    result = merge_images([source("a", text), source("b", text), source("c", text)])
    assert result.ok
    assert result.segments[0].data == b"\x7F"
    assert result.segments[0].sources == ["a", "b", "c"]


def test_conflict_run_reports_contiguous_range_and_source_values():
    result = merge_images([
        source("a", "\n".join([data_rec(0x0000, b"\x01\x02\x03"), EOF])),
        source("b", "\n".join([data_rec(0x0001, b"\x09\x08"), EOF])),
    ])
    assert not result.ok
    assert len(result.conflicts) == 1
    conflict = result.conflicts[0]
    assert (conflict.start, conflict.end, conflict.length) == (0x0001, 0x0003, 2)
    by_source = {c.source: (c.start, c.end, c.data) for c in conflict.chunks}
    assert by_source["a"] == (0x0001, 0x0003, b"\x02\x03")
    assert by_source["b"] == (0x0001, 0x0003, b"\x09\x08")
    assert result.segments == []


def test_separated_conflicting_bytes_become_separate_runs():
    result = merge_images([
        source("a", "\n".join([data_rec(0x0000, b"\x01\x02\x03"), EOF])),
        source("b", "\n".join([data_rec(0x0000, b"\x09\x02\x0A"), EOF])),
    ])
    assert not result.ok
    assert [(c.start, c.end) for c in result.conflicts] == [(0, 1), (2, 3)]


def test_non_overlapping_conflicts_become_separate_chunks():
    # a defines 0..4; b only disagrees at the isolated addresses 1 and 3.
    result = merge_images([
        source("a", "\n".join([data_rec(0x0000, b"\x01\x02\x03\x04\x05"), EOF])),
        source(
            "b",
            "\n".join([data_rec(0x0001, b"\x09"), data_rec(0x0003, b"\x0A"), EOF]),
        ),
    ])
    assert not result.ok
    assert [(c.start, c.end) for c in result.conflicts] == [(1, 2), (3, 4)]
    first, second = result.conflicts
    assert [c.source for c in first.chunks] == ["a", "b"]
    assert first.chunks[1].data == b"\x09"
    assert second.chunks[1].data == b"\x0A"


def test_agreeing_nonnull_entries_merge_to_that_entry():
    text_a = "\n".join([data_rec(0, b"\x01"), linear_entry(0x08000100), EOF])
    text_b = "\n".join([data_rec(0x10, b"\x02"), linear_entry(0x08000100), EOF])
    result = merge_images([source("a", text_a), source("b", text_b)])
    assert result.ok
    assert result.entry_address == 0x08000100


def test_all_entries_absent_is_allowed():
    result = merge_images([
        source("a", "\n".join([data_rec(0, b"\x01"), EOF])),
        source("b", "\n".join([data_rec(0x10, b"\x02"), EOF])),
    ])
    assert result.ok
    assert result.entry_address is None


def test_single_nonnull_entry_with_other_sources_absent_is_accepted():
    text_a = "\n".join([data_rec(0, b"\x01"), linear_entry(0x08000100), EOF])
    text_b = "\n".join([data_rec(0x10, b"\x02"), EOF])
    result = merge_images([source("a", text_a), source("b", text_b)])
    assert result.ok
    assert result.entry_conflict is None
    assert result.entry_address == 0x08000100


def test_distinct_nonnull_entries_is_entry_conflict():
    text_a = "\n".join([data_rec(0, b"\x01"), linear_entry(0x08000100), EOF])
    text_b = "\n".join([data_rec(0x10, b"\x02"), linear_entry(0x08000200), EOF])
    result = merge_images([source("a", text_a), source("b", text_b)])
    assert not result.ok
    assert result.entry_conflict is not None
    assert dict(result.entry_conflict.entries) == {
        "a": 0x08000100,
        "b": 0x08000200,
    }


def test_absolute_addresses_from_base_records_are_used():
    result = merge_images([
        source(
            "a",
            "\n".join([linear_base(0x0800), data_rec(0x0000, b"\xAA"), EOF]),
        ),
        source(
            "b",
            "\n".join([linear_base(0x0800), data_rec(0x0001, b"\xBB"), EOF]),
        ),
    ])
    assert result.ok
    assert [(s.start, s.data) for s in result.segments] == [
        (0x08000000, b"\xAA"),
        (0x08000001, b"\xBB"),
    ]


# ---------------------------------------------------------------------------
# API surface
# ---------------------------------------------------------------------------

def test_api_merge_disjoint_success():
    resp = client.post(
        "/api/v1/merge-images",
        json={
            "images": [
                {"name": "a", "hex_text": "\n".join([data_rec(0x0000, b"\x01\x02"), EOF])},
                {"name": "b", "hex_text": "\n".join([data_rec(0x0010, b"\x03"), EOF])},
            ]
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True
    assert "merged_segments" in body
    segments = body["merged_segments"]
    assert len(segments) == 2
    assert segments[0]["start"] == 0
    assert base64.b64decode(segments[0]["data_base64"]) == b"\x01\x02"
    assert segments[0]["sources"] == ["a"]
    assert segments[1]["sources"] == ["b"]
    assert body["entry_address"] is None
    assert body["total_bytes"] == 3
    assert body["conflicts"] == []
    assert body["entry_conflict"] is None
    assert [s["name"] for s in body["sources"]] == ["a", "b"]
    assert all(s["ok"] for s in body["sources"])


def test_api_identical_overlap_carries_all_sources_in_base64():
    resp = client.post(
        "/api/v1/merge-images",
        json={
            "images": [
                {"name": "a", "hex_text": "\n".join([data_rec(0, b"\xAA\xBB"), EOF])},
                {"name": "b", "hex_text": "\n".join([data_rec(1, b"\xBB\xCC"), EOF])},
            ]
        },
    )
    body = resp.json()
    assert body["ok"] is True
    middle = body["merged_segments"][1]
    assert base64.b64decode(middle["data_base64"]) == b"\xBB"
    assert middle["sources"] == ["a", "b"]


def test_api_invalid_source_returns_its_name_and_original_diagnostics_and_no_merge():
    bad = data_rec(0, b"\x01")[:-2] + "00"  # corrupt checksum, also missing EOF
    resp = client.post(
        "/api/v1/merge-images",
        json={
            "images": [
                {"name": "good", "hex_text": "\n".join([data_rec(0x10, b"\x02"), EOF])},
                {"name": "bad", "hex_text": bad},
            ]
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is False
    assert "merged_segments" not in body
    assert body["total_bytes"] == 0
    reports = {s["name"]: s for s in body["sources"]}
    assert reports["good"]["ok"] is True
    assert reports["bad"]["ok"] is False
    assert reports["bad"]["error_count"] >= 2
    messages = " ".join(d["message"] for d in reports["bad"]["diagnostics"])
    assert "checksum" in messages
    assert "end-of-file" in messages
    # original diagnostics line numbers are preserved
    assert any(d["line"] == 1 and d["status"] == "error" for d in reports["bad"]["diagnostics"])


def test_api_byte_conflict_response_shape():
    resp = client.post(
        "/api/v1/merge-images",
        json={
            "images": [
                {"name": "a", "hex_text": "\n".join([data_rec(0, b"\x01\x02"), EOF])},
                {"name": "b", "hex_text": "\n".join([data_rec(0, b"\x01\x09"), EOF])},
            ]
        },
    )
    body = resp.json()
    assert body["ok"] is False
    assert "merged_segments" not in body
    assert len(body["conflicts"]) == 1
    conflict = body["conflicts"][0]
    assert (conflict["start"], conflict["end"], conflict["size"]) == (1, 2, 1)
    values = {
        c["source"]: base64.b64decode(c["data_base64"]) for c in conflict["chunks"]
    }
    assert values == {"a": b"\x02", "b": b"\x09"}


def test_api_single_entry_with_other_absent_merges_to_that_entry():
    resp = client.post(
        "/api/v1/merge-images",
        json={
            "images": [
                {
                    "name": "a",
                    "hex_text": "\n".join(
                        [data_rec(0, b"\x01"), linear_entry(0x08000100), EOF]
                    ),
                },
                {"name": "b", "hex_text": "\n".join([data_rec(0x10, b"\x02"), EOF])},
            ]
        },
    )
    body = resp.json()
    assert body["ok"] is True
    assert body["entry_address"] == 0x08000100
    assert "merged_segments" in body


def test_api_entry_conflict_reports_values_per_source():
    resp = client.post(
        "/api/v1/merge-images",
        json={
            "images": [
                {
                    "name": "a",
                    "hex_text": "\n".join(
                        [data_rec(0, b"\x01"), linear_entry(0x08000100), EOF]
                    ),
                },
                {
                    "name": "b",
                    "hex_text": "\n".join(
                        [data_rec(0x10, b"\x02"), linear_entry(0x08000200), EOF]
                    ),
                },
            ]
        },
    )
    body = resp.json()
    assert body["ok"] is False
    assert "merged_segments" not in body
    assert body["entry_conflict"]["entries"] == {
        "a": 0x08000100,
        "b": 0x08000200,
    }


def test_api_agreeing_entries_return_entry_address():
    resp = client.post(
        "/api/v1/merge-images",
        json={
            "images": [
                {
                    "name": "a",
                    "hex_text": "\n".join(
                        [data_rec(0, b"\x01"), linear_entry(0x08000100), EOF]
                    ),
                },
                {
                    "name": "b",
                    "hex_text": "\n".join(
                        [data_rec(0x10, b"\x02"), linear_entry(0x08000100), EOF]
                    ),
                },
            ]
        },
    )
    body = resp.json()
    assert body["ok"] is True
    assert body["entry_address"] == 0x08000100


def test_api_duplicate_names_rejected_with_422():
    payload = {
        "images": [
            {"name": "x", "hex_text": "\n".join([data_rec(0, b"\x01"), EOF])},
            {"name": "x", "hex_text": "\n".join([data_rec(0x10, b"\x02"), EOF])},
        ]
    }
    resp = client.post("/api/v1/merge-images", json=payload)
    assert resp.status_code == 422
    assert "unique" in resp.text


def test_api_empty_image_list_rejected_with_422():
    resp = client.post("/api/v1/merge-images", json={"images": []})
    assert resp.status_code == 422
