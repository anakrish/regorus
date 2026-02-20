# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Core symbolic types: ValueSort, Definedness, SymValue, SymRegister."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional, Union

import z3


# ---------------------------------------------------------------------------
# Value sort — tracks the Z3 theory a path variable belongs to
# ---------------------------------------------------------------------------

class ValueSort(Enum):
    Bool = auto()
    Int = auto()
    Real = auto()
    String = auto()
    Unknown = auto()


def sort_from_value(v) -> ValueSort:
    """Infer a ValueSort from a Python/JSON literal value."""
    if isinstance(v, bool):
        return ValueSort.Bool
    if isinstance(v, int):
        return ValueSort.Int
    if isinstance(v, float):
        return ValueSort.Real
    if isinstance(v, str):
        return ValueSort.String
    return ValueSort.Unknown


# ---------------------------------------------------------------------------
# Definedness — models Rego's "undefined propagation"
# ---------------------------------------------------------------------------

class Definedness:
    """
    Tracks whether a register is defined.
      - Defined     → statically known present (Python True)
      - Undefined   → statically known absent  (Python False)
      - Symbolic(b) → governed by a Z3 Bool variable
    """

    __slots__ = ("_val",)

    # Singleton sentinels
    _DEFINED: Definedness
    _UNDEFINED: Definedness

    def __init__(self, val: Union[bool, z3.BoolRef]):
        self._val = val

    @staticmethod
    def defined() -> Definedness:
        return Definedness._DEFINED

    @staticmethod
    def undefined() -> Definedness:
        return Definedness._UNDEFINED

    @staticmethod
    def symbolic(b: z3.BoolRef) -> Definedness:
        return Definedness(b)

    @property
    def is_defined(self) -> bool:
        return self._val is True

    @property
    def is_undefined(self) -> bool:
        return self._val is False

    @property
    def is_symbolic(self) -> bool:
        return isinstance(self._val, z3.BoolRef)

    def to_z3(self) -> z3.BoolRef:
        """Convert to a Z3 Bool expression."""
        if self._val is True:
            return z3.BoolVal(True)
        if self._val is False:
            return z3.BoolVal(False)
        return self._val

    @staticmethod
    def and_(a: Definedness, b: Definedness) -> Definedness:
        """Both must be defined."""
        if a.is_undefined or b.is_undefined:
            return Definedness.undefined()
        if a.is_defined:
            return b
        if b.is_defined:
            return a
        return Definedness.symbolic(z3.And(a.to_z3(), b.to_z3()))

    def __repr__(self):
        if self._val is True:
            return "Defined"
        if self._val is False:
            return "Undefined"
        return f"Symbolic({self._val})"


# Create singletons after class is defined
Definedness._DEFINED = Definedness(True)
Definedness._UNDEFINED = Definedness(False)


# ---------------------------------------------------------------------------
# SymValue — symbolic or concrete value in a register
# ---------------------------------------------------------------------------

# Sentinel for undefined
_UNDEFINED = object()


@dataclass
class SymSetElement:
    """One element in a symbolic set, with the path condition under which it exists."""
    condition: z3.BoolRef
    element_path: str  # access path like "input.servers[0]"
    key_path: str  # access path of the set key like "input.servers[0].id"
    element_sort: ValueSort


@dataclass
class SymValue:
    """
    A register value: either concrete (Python object) or symbolic (Z3 expression).
    """

    # Exactly one of these is set:
    concrete: object = _UNDEFINED  # Python value (bool/int/float/str/list/dict/None/_UNDEFINED)
    z3_expr: Optional[z3.ExprRef] = None  # Z3 Bool/Int/Real/String
    sort: ValueSort = ValueSort.Unknown

    # For SymbolicSet support
    sym_set_elements: Optional[list[SymSetElement]] = None
    sym_set_cardinality: Optional[z3.ArithRef] = None  # Z3 Int for |set|

    @staticmethod
    def from_concrete(v) -> SymValue:
        """Wrap a Python/JSON value as concrete."""
        return SymValue(concrete=v, sort=sort_from_value(v))

    @staticmethod
    def undefined() -> SymValue:
        return SymValue(concrete=_UNDEFINED)

    @staticmethod
    def from_z3_bool(e: z3.BoolRef) -> SymValue:
        return SymValue(z3_expr=e, sort=ValueSort.Bool, concrete=_UNDEFINED)

    @staticmethod
    def from_z3_int(e: z3.ArithRef) -> SymValue:
        return SymValue(z3_expr=e, sort=ValueSort.Int, concrete=_UNDEFINED)

    @staticmethod
    def from_z3_real(e: z3.ArithRef) -> SymValue:
        return SymValue(z3_expr=e, sort=ValueSort.Real, concrete=_UNDEFINED)

    @staticmethod
    def from_z3_string(e: z3.SeqRef) -> SymValue:
        return SymValue(z3_expr=e, sort=ValueSort.String, concrete=_UNDEFINED)

    @staticmethod
    def symbolic_set(cardinality: z3.ArithRef, elements: list[SymSetElement]) -> SymValue:
        return SymValue(
            concrete=_UNDEFINED,
            sort=ValueSort.Int,  # cardinality is Int
            sym_set_cardinality=cardinality,
            sym_set_elements=elements,
        )

    @property
    def is_concrete(self) -> bool:
        return self.concrete is not _UNDEFINED

    @property
    def is_undefined(self) -> bool:
        return self.concrete is _UNDEFINED and self.z3_expr is None and self.sym_set_elements is None

    @property
    def is_symbolic(self) -> bool:
        return self.z3_expr is not None

    @property
    def is_symbolic_set(self) -> bool:
        return self.sym_set_elements is not None

    def to_z3_bool(self) -> z3.BoolRef:
        """Convert to a Z3 Bool, promoting if needed."""
        if self.z3_expr is not None and self.sort == ValueSort.Bool:
            return self.z3_expr
        if self.is_concrete:
            if isinstance(self.concrete, bool):
                return z3.BoolVal(self.concrete)
            raise ValueError(f"Cannot promote concrete {type(self.concrete)} to Z3 Bool")
        raise ValueError(f"Cannot convert {self} to Z3 Bool")

    def to_z3_int(self) -> z3.ArithRef:
        """Convert to a Z3 Int, promoting if needed."""
        if self.z3_expr is not None and self.sort == ValueSort.Int:
            return self.z3_expr
        if self.is_concrete and isinstance(self.concrete, (int, bool)):
            return z3.IntVal(int(self.concrete))
        raise ValueError(f"Cannot convert {self} to Z3 Int")

    def to_z3_real(self) -> z3.ArithRef:
        """Convert to a Z3 Real, promoting if needed."""
        if self.z3_expr is not None and self.sort == ValueSort.Real:
            return self.z3_expr
        if self.z3_expr is not None and self.sort == ValueSort.Int:
            return z3.ToReal(self.z3_expr)
        if self.is_concrete:
            if isinstance(self.concrete, float):
                # Approximate: use rational
                from fractions import Fraction
                frac = Fraction(self.concrete).limit_denominator(10**15)
                return z3.RealVal(f"{frac.numerator}/{frac.denominator}")
            if isinstance(self.concrete, int):
                return z3.RealVal(self.concrete)
        raise ValueError(f"Cannot convert {self} to Z3 Real")

    def to_z3_string(self) -> z3.SeqRef:
        """Convert to a Z3 String, promoting if needed."""
        if self.z3_expr is not None and self.sort == ValueSort.String:
            return self.z3_expr
        if self.is_concrete and isinstance(self.concrete, str):
            return z3.StringVal(self.concrete)
        raise ValueError(f"Cannot convert {self} to Z3 String")

    def equals_value(self, desired) -> z3.BoolRef:
        """Build a Z3 constraint: self == desired (a Python literal)."""
        if isinstance(desired, bool):
            return self.to_z3_bool() == z3.BoolVal(desired)
        if isinstance(desired, int):
            if self.sort == ValueSort.Bool:
                # Cedar: to_number produces Int from Bool ITE
                return self.to_z3_int() == z3.IntVal(desired)
            return self.to_z3_int() == z3.IntVal(desired)
        if isinstance(desired, float):
            return self.to_z3_real() == z3.RealVal(desired)
        if isinstance(desired, str):
            return self.to_z3_string() == z3.StringVal(desired)
        raise ValueError(f"Cannot compare symbolic value to {type(desired)}: {desired}")


# ---------------------------------------------------------------------------
# SymRegister — what lives in a register slot
# ---------------------------------------------------------------------------

@dataclass
class SymRegister:
    """A register: value + definedness + optional source path."""
    value: SymValue
    defined: Definedness
    source_path: Optional[str] = None  # e.g. "input.foo.bar"

    @staticmethod
    def undefined() -> SymRegister:
        return SymRegister(
            value=SymValue.undefined(),
            defined=Definedness.undefined(),
        )

    @staticmethod
    def concrete(v) -> SymRegister:
        if v is _UNDEFINED or v is None:
            return SymRegister.undefined()
        return SymRegister(
            value=SymValue.from_concrete(v),
            defined=Definedness.defined(),
        )


# ---------------------------------------------------------------------------
# ComprehensionYieldEntry
# ---------------------------------------------------------------------------

@dataclass
class ComprehensionYieldEntry:
    value: SymRegister
    key: Optional[SymRegister]
    condition: z3.BoolRef


@dataclass
class ComprehensionAccumulator:
    mode: str  # "Set", "Array", "Object"
    result_reg: int
    yields: list[ComprehensionYieldEntry] = field(default_factory=list)
