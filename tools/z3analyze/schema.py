# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Apply JSON Schema constraints to the Z3 path registry.

Port of ``src/rvm/analysis/schema_constraints.rs``.
"""

from __future__ import annotations

from typing import Any

import z3

from .path_registry import PathRegistry
from .types import ValueSort


def apply_schema_constraints(
    schema: dict,
    registry: PathRegistry,
    prefix: str = "input",
) -> list[z3.BoolRef]:
    """Walk a JSON Schema and return Z3 constraints for known paths."""
    constraints: list[z3.BoolRef] = []
    _walk_schema(schema, prefix, registry, constraints)
    return constraints


def _walk_schema(
    schema: dict,
    path: str,
    registry: PathRegistry,
    constraints: list[z3.BoolRef],
):
    if not isinstance(schema, dict):
        return

    # 'type' constraint
    schema_type = schema.get("type")
    if schema_type:
        _apply_type(schema_type, path, registry, constraints)

    # 'properties' (object)
    props = schema.get("properties")
    if isinstance(props, dict):
        for prop_name, prop_schema in props.items():
            child_path = f"{path}.{prop_name}"
            _walk_schema(prop_schema, child_path, registry, constraints)

    # 'required'
    required = schema.get("required")
    if isinstance(required, list):
        for field_name in required:
            child_path = f"{path}.{field_name}"
            entry = registry.get(child_path)
            if entry is not None:
                constraints.append(entry.defined)

    # 'items' (array)
    items = schema.get("items")
    if isinstance(items, dict):
        min_items = schema.get("minItems", 0)
        max_items = schema.get("maxItems", max(min_items, 5))
        for i in range(max_items):
            child_path = f"{path}[{i}]"
            _walk_schema(items, child_path, registry, constraints)

    # 'minLength' (string)
    min_length = schema.get("minLength")
    if isinstance(min_length, int) and min_length > 0:
        entry = registry.get(path)
        if entry and entry._str_var is not None:
            constraints.append(z3.Length(entry._str_var) >= min_length)

    # 'enum'
    enum_vals = schema.get("enum")
    if isinstance(enum_vals, list) and enum_vals:
        entry = registry.get(path)
        if entry is not None:
            _apply_enum(entry, enum_vals, constraints)

    # 'x-unique' (custom: list of field names that must be pairwise distinct)
    x_unique = schema.get("x-unique")
    if isinstance(x_unique, list):
        _apply_uniqueness(x_unique, path, registry, constraints, schema)

    # 'uniqueItems'
    unique_items = schema.get("uniqueItems")
    if unique_items and isinstance(items, dict):
        min_items = schema.get("minItems", 0)
        max_items = schema.get("maxItems", max(min_items, 5))
        _apply_unique_items(path, max_items, registry, constraints)


def _apply_type(schema_type: str, path: str, registry: PathRegistry,
                constraints: list[z3.BoolRef]):
    sort_map = {
        "string": ValueSort.String,
        "integer": ValueSort.Int,
        "number": ValueSort.Int,
        "boolean": ValueSort.Bool,
    }
    sort = sort_map.get(schema_type)
    if sort is not None:
        registry.get_or_create(path, sort, True, -1)


def _apply_enum(entry, enum_vals: list, constraints: list[z3.BoolRef]):
    sort = entry.sort
    disjs = []
    for v in enum_vals:
        if sort == ValueSort.String and isinstance(v, str) and entry._str_var is not None:
            disjs.append(entry._str_var == z3.StringVal(v))
        elif sort == ValueSort.Int and isinstance(v, int) and entry._int_var is not None:
            disjs.append(entry._int_var == z3.IntVal(v))
        elif sort == ValueSort.Bool and isinstance(v, bool) and entry._bool_var is not None:
            disjs.append(entry._bool_var == z3.BoolVal(v))
    if disjs:
        constraints.append(z3.Implies(entry.defined, z3.Or(*disjs)))


def _apply_uniqueness(fields: list, path: str, registry: PathRegistry,
                      constraints: list[z3.BoolRef], schema: dict):
    items = schema.get("items")
    if not isinstance(items, dict):
        return
    min_items = schema.get("minItems", 0)
    max_items = schema.get("maxItems", max(min_items, 5))
    for field_name in fields:
        field_paths = []
        for i in range(max_items):
            fp = f"{path}[{i}].{field_name}"
            entry = registry.get(fp)
            if entry:
                field_paths.append((fp, entry))
        # Pairwise distinctness
        for i in range(len(field_paths)):
            for j in range(i + 1, len(field_paths)):
                pi_path, pi_entry = field_paths[i]
                pj_path, pj_entry = field_paths[j]
                both_def = z3.And(pi_entry.defined, pj_entry.defined)
                neq = _values_not_equal(pi_entry, pj_entry)
                if neq is not None:
                    constraints.append(z3.Implies(both_def, neq))


def _apply_unique_items(path: str, max_items: int, registry: PathRegistry,
                        constraints: list[z3.BoolRef]):
    entries = []
    for i in range(max_items):
        child_path = f"{path}[{i}]"
        entry = registry.get(child_path)
        if entry:
            entries.append(entry)
    for i in range(len(entries)):
        for j in range(i + 1, len(entries)):
            both_def = z3.And(entries[i].defined, entries[j].defined)
            neq = _values_not_equal(entries[i], entries[j])
            if neq is not None:
                constraints.append(z3.Implies(both_def, neq))


def _values_not_equal(a, b):
    if a.sort == b.sort:
        if a.sort == ValueSort.String and a._str_var is not None and b._str_var is not None:
            return a._str_var != b._str_var
        if a.sort == ValueSort.Int and a._int_var is not None and b._int_var is not None:
            return a._int_var != b._int_var
        if a.sort == ValueSort.Bool and a._bool_var is not None and b._bool_var is not None:
            return a._bool_var != b._bool_var
        if a.sort == ValueSort.Real and a._real_var is not None and b._real_var is not None:
            return a._real_var != b._real_var
    return None
