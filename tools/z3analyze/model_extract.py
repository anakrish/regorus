# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Extract a concrete JSON input from a Z3 model and path registry.

Port of ``src/rvm/analysis/model_extract.rs``.
"""

from __future__ import annotations

import re
from typing import Any, Optional

import z3

from .path_registry import PathRegistry
from .types import ValueSort


def extract_input(model: z3.ModelRef, registry: PathRegistry) -> dict:
    """Walk the registry and build a nested JSON object from the model."""
    root: dict = {}
    for path, entry in registry.items():
        if not path.startswith("input."):
            continue
        # Check definedness
        d_val = model.eval(entry.defined, model_completion=True)
        if z3.is_false(d_val):
            continue

        val = _extract_value_for_entry(model, entry)
        if val is None:
            continue

        suffix = path[len("input."):]
        segments = _split_segments(suffix)
        _set_nested(root, segments, val)
    return root


def _extract_value_for_entry(model: z3.ModelRef, entry) -> Any:
    sort = entry.sort
    if sort == ValueSort.Bool and entry._bool_var is not None:
        v = model.eval(entry._bool_var, model_completion=True)
        return bool(z3.is_true(v))
    if sort == ValueSort.Int and entry._int_var is not None:
        v = model.eval(entry._int_var, model_completion=True)
        try:
            return v.as_long()
        except (AttributeError, ValueError):
            return int(str(v))
    if sort == ValueSort.Real and entry._real_var is not None:
        v = model.eval(entry._real_var, model_completion=True)
        try:
            num = v.numerator_as_long()
            den = v.denominator_as_long()
            return num / den if den != 0 else 0
        except (AttributeError, ValueError):
            return float(str(v))
    if sort == ValueSort.String and entry._str_var is not None:
        v = model.eval(entry._str_var, model_completion=True)
        s = str(v)
        # Strip surrounding quotes
        if len(s) >= 2 and s[0] == '"' and s[-1] == '"':
            s = s[1:-1]
        return s
    # Unknown sort — try all
    if entry._str_var is not None:
        v = model.eval(entry._str_var, model_completion=True)
        s = str(v)
        if len(s) >= 2 and s[0] == '"' and s[-1] == '"':
            s = s[1:-1]
        return s
    if entry._int_var is not None:
        v = model.eval(entry._int_var, model_completion=True)
        try:
            return v.as_long()
        except (AttributeError, ValueError):
            return int(str(v))
    if entry._bool_var is not None:
        v = model.eval(entry._bool_var, model_completion=True)
        return bool(z3.is_true(v))
    return None


# ---- Path segment parsing ----

_ARRAY_INDEX_RE = re.compile(r'^(.*)\[(\d+)\]$')


def _parse_segment(segment: str) -> tuple[str, Optional[int]]:
    """Parse ``"servers[2]"`` → ``("servers", 2)``; ``"name"`` → ``("name", None)``."""
    m = _ARRAY_INDEX_RE.match(segment)
    if m:
        return m.group(1), int(m.group(2))
    return segment, None


def _split_segments(suffix: str) -> list[str]:
    """Split ``"a.b.c[0].d"`` into ``["a", "b", "c[0]", "d"]``."""
    return suffix.split(".")


def _set_nested(obj: dict, segments: list[str], value: Any):
    """Set a deeply nested value, creating intermediate dicts/lists as needed."""
    current: Any = obj
    for i, seg in enumerate(segments):
        name, idx = _parse_segment(seg)
        is_last = i == len(segments) - 1

        # Ensure the dict key for `name` exists
        if isinstance(current, dict):
            if idx is not None:
                if name not in current or not isinstance(current[name], list):
                    current[name] = []
                arr = current[name]
                while len(arr) <= idx:
                    arr.append(None)
                if is_last:
                    arr[idx] = value
                else:
                    if arr[idx] is None or not isinstance(arr[idx], dict):
                        arr[idx] = {}
                    current = arr[idx]
            else:
                if is_last:
                    current[name] = value
                else:
                    if name not in current or not isinstance(current[name], dict):
                        current[name] = {}
                    current = current[name]
        elif isinstance(current, list):
            if is_last and idx is not None:
                while len(current) <= idx:
                    current.append(None)
                current[idx] = value
            elif name and isinstance(current, list):
                # Shouldn't normally happen
                break
