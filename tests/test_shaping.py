from __future__ import annotations

import datetime as dt

from sna_mcp.client import _extract_list, utc_window
from sna_mcp.shaping import DEFAULT_MAX_ITEMS, shape_list


def test_shape_list_caps_and_reports_truncation() -> None:
    out = shape_list(list(range(DEFAULT_MAX_ITEMS + 5)))
    assert out["total"] == DEFAULT_MAX_ITEMS + 5
    assert out["returned"] == DEFAULT_MAX_ITEMS
    assert out["truncated"] is True


def test_shape_list_unbounded_with_negative_cap() -> None:
    out = shape_list([1, 2, 3], max_items=-1)
    assert out == {"total": 3, "returned": 3, "truncated": False, "items": [1, 2, 3]}


def test_shape_list_projects_dot_paths() -> None:
    items = [{"peer": {"ipAddress": "192.0.2.1"}, "tags": [{"name": "a"}], "drop": 1}]
    out = shape_list(items, fields=["peer.ipAddress", "tags.0.name", "missing.path"])
    assert out["items"] == [
        {"peer.ipAddress": "192.0.2.1", "tags.0.name": "a", "missing.path": None}
    ]


def test_shape_list_passes_non_lists_through() -> None:
    assert shape_list({"not": "a list"}) == {"not": "a list"}


def test_extract_list_shapes() -> None:
    assert _extract_list([{"a": 1}]) == [{"a": 1}]
    assert _extract_list({"data": [{"a": 1}]}) == [{"a": 1}]
    assert _extract_list({"data": {"tags": [{"id": 1}]}}) == [{"id": 1}]
    assert _extract_list({"data": {"id": 1}}) == [{"id": 1}]
    assert _extract_list(None) == []


def test_utc_window_formats() -> None:
    start, end = utc_window(60)
    assert start.endswith("Z") and end.endswith("Z")
    fmt = "%Y-%m-%dT%H:%M:%SZ"
    delta = dt.datetime.strptime(end, fmt) - dt.datetime.strptime(start, fmt)
    assert delta == dt.timedelta(minutes=60)

    start_ms, _ = utc_window(5, microseconds=True)
    assert start_ms.endswith(".000")
