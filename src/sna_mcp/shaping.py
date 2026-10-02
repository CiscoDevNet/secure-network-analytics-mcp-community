"""Response-shaping helpers to keep tool outputs bounded and readable.

Large SNA result sets (flows, top-N reports, host-group traffic) can be huge.
These helpers cap the number of returned items, report the true total, and
optionally project just the fields you care about (supporting dot-paths for
nested values like ``peer.ipAddress`` or ``statistics.byteCount``).
"""

from __future__ import annotations

from typing import Any

# Default cap applied to list results so a single call can't dump thousands of
# rows into the model context.
DEFAULT_MAX_ITEMS = 50


def _get_path(obj: Any, path: str) -> Any:
    """Resolve a dot-separated path within nested dicts/lists.

    Supports numeric indices for lists, e.g. ``users.0.name``.
    Returns ``None`` if any segment is missing.
    """
    cur = obj
    for part in path.split("."):
        if isinstance(cur, dict):
            if part not in cur:
                return None
            cur = cur[part]
        elif isinstance(cur, list):
            try:
                cur = cur[int(part)]
            except (ValueError, IndexError):
                return None
        else:
            return None
    return cur


def _project(item: Any, fields: list[str]) -> Any:
    """Return a new dict containing only ``fields`` (dot-paths) from ``item``."""
    if not isinstance(item, dict):
        return item
    return {f: _get_path(item, f) for f in fields}


def shape_list(
    items: Any,
    max_items: int | None = DEFAULT_MAX_ITEMS,
    fields: list[str] | None = None,
) -> Any:
    """Wrap a list result in a bounded envelope.

    Args:
        items: The raw list (non-lists are returned unchanged).
        max_items: Maximum items to include. ``None`` or a negative value
            returns everything (use with care).
        fields: Optional dot-path field names to project on each item.

    Returns:
        ``{"total", "returned", "truncated", "items"}`` for lists, else the
        original value untouched.
    """
    if not isinstance(items, list):
        return items

    total = len(items)
    if max_items is None or max_items < 0:
        sliced = items
    else:
        sliced = items[:max_items]

    if fields:
        sliced = [_project(it, fields) for it in sliced]

    return {
        "total": total,
        "returned": len(sliced),
        "truncated": total > len(sliced),
        "items": sliced,
    }
