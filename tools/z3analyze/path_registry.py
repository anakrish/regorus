# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Path registry: flat map of input paths → Z3 variables with lazy creation."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, Iterator

import z3

from .types import ValueSort, SymValue, sort_from_value


# ---------------------------------------------------------------------------
# PathEntry
# ---------------------------------------------------------------------------

@dataclass
class PathEntry:
    """One entry in the path registry — a single input path like 'input.user.role'."""

    defined: z3.BoolRef  # Z3 bool: is this path present?
    sort: ValueSort = ValueSort.Unknown
    is_static: bool = True
    access_pcs: list[int] = field(default_factory=list)

    # Lazily-created Z3 variables (one per sort)
    _bool_var: Optional[z3.BoolRef] = field(default=None, repr=False)
    _int_var: Optional[z3.ArithRef] = field(default=None, repr=False)
    _real_var: Optional[z3.ArithRef] = field(default=None, repr=False)
    _str_var: Optional[z3.SeqRef] = field(default=None, repr=False)


# ---------------------------------------------------------------------------
# PathRegistry
# ---------------------------------------------------------------------------

class PathRegistry:
    """
    Flat map of path strings to PathEntry.

    Paths like ``input.user.role`` or ``input.servers[0].id`` each get:
    - a ``defined`` Z3 Bool (created eagerly)
    - typed Z3 variables (created lazily on first access)
    """

    def __init__(self):
        self._paths: dict[str, PathEntry] = {}
        self._next_id: int = 0

    # ----- core access -----

    def get_or_create(
        self,
        path: str,
        sort: ValueSort = ValueSort.Unknown,
        is_static: bool = True,
        pc: int = 0,
    ) -> PathEntry:
        """Get or create a PathEntry for *path*, refining sort if needed."""
        entry = self._paths.get(path)
        if entry is not None:
            entry.access_pcs.append(pc)
            # refine sort: Unknown → concrete, but never overwrite concrete
            if entry.sort == ValueSort.Unknown and sort != ValueSort.Unknown:
                entry.sort = sort
            return entry

        # new entry
        self._next_id += 1
        defined_var = z3.Bool(f"defined_{path}")
        entry = PathEntry(defined=defined_var, sort=sort, is_static=is_static, access_pcs=[pc])
        self._paths[path] = entry
        return entry

    def get(self, path: str) -> Optional[PathEntry]:
        return self._paths.get(path)

    def __contains__(self, path: str) -> bool:
        return path in self._paths

    def __len__(self) -> int:
        return len(self._paths)

    def items(self) -> Iterator[tuple[str, PathEntry]]:
        return iter(self._paths.items())

    # ----- typed Z3 variable accessors (lazy creation) -----

    def get_bool(self, path: str) -> z3.BoolRef:
        entry = self.get_or_create(path, ValueSort.Bool)
        if entry._bool_var is None:
            entry._bool_var = z3.Bool(path)
            entry.sort = ValueSort.Bool
        return entry._bool_var

    def get_int(self, path: str) -> z3.ArithRef:
        entry = self.get_or_create(path, ValueSort.Int)
        if entry._int_var is None:
            entry._int_var = z3.Int(path)
            entry.sort = ValueSort.Int
        return entry._int_var

    def get_real(self, path: str) -> z3.ArithRef:
        entry = self.get_or_create(path, ValueSort.Real)
        if entry._real_var is None:
            entry._real_var = z3.Real(path)
            entry.sort = ValueSort.Real
        return entry._real_var

    def get_string(self, path: str) -> z3.SeqRef:
        entry = self.get_or_create(path, ValueSort.String)
        if entry._str_var is None:
            entry._str_var = z3.String(path)
            entry.sort = ValueSort.String
        return entry._str_var

    def get_var_for_sort(self, path: str, sort: ValueSort) -> Optional[SymValue]:
        """Return a SymValue wrapping the Z3 variable for the given sort, or None."""
        if sort == ValueSort.Bool:
            return SymValue.from_z3_bool(self.get_bool(path))
        if sort == ValueSort.Int:
            return SymValue.from_z3_int(self.get_int(path))
        if sort == ValueSort.Real:
            return SymValue.from_z3_real(self.get_real(path))
        if sort == ValueSort.String:
            return SymValue.from_z3_string(self.get_string(path))
        return None

    def refine_sort(self, path: str, sort: ValueSort):
        entry = self._paths.get(path)
        if entry and entry.sort == ValueSort.Unknown:
            entry.sort = sort

    def get_sort(self, path: str) -> Optional[ValueSort]:
        entry = self._paths.get(path)
        return entry.sort if entry else None

    # ----- seeding from a concrete JSON value -----

    def seed_sorts_from_value(self, prefix: str, value, max_elements: int = 4):
        """
        Recursively walk a concrete value (parsed JSON) to pre-populate
        the registry with correct sorts before symbolic translation.
        """
        if isinstance(value, dict):
            for k, v in value.items():
                self.seed_sorts_from_value(f"{prefix}.{k}", v, max_elements)
        elif isinstance(value, list):
            if not value:
                return
            for idx in range(max_elements):
                elem = value[idx % len(value)]
                self.seed_sorts_from_value(f"{prefix}[{idx}]", elem, max_elements)
        elif isinstance(value, bool):
            self.get_bool(prefix)
        elif isinstance(value, int):
            self.get_int(prefix)
        elif isinstance(value, float):
            self.get_real(prefix)
        elif isinstance(value, str):
            self.get_string(prefix)
        # None and other types: skip
