# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Symbolic translator: walks RVM bytecode and builds Z3 constraints.

This is the Python port of ``src/rvm/analysis/translator.rs``.
"""

from __future__ import annotations

import copy
from collections import deque
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Optional

import z3

from .program import (
    ArrayCreateParams,
    BuiltinCallParams,
    ChainedIndexParams,
    ComprehensionBeginParams,
    ComprehensionMode,
    FunctionCallParams,
    Instruction,
    LoopMode,
    LoopStartParams,
    ObjectCreateParams,
    Program,
    RuleType,
    SetCreateParams,
    VirtualDataDocumentLookupParams,
)
from .path_registry import PathEntry, PathRegistry
from .types import (
    ComprehensionAccumulator,
    ComprehensionYieldEntry,
    Definedness,
    SymRegister,
    SymSetElement,
    SymValue,
    ValueSort,
    _UNDEFINED,
    sort_from_value,
)


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

@dataclass
class AnalysisConfig:
    max_loop_depth: int = 5
    max_rule_depth: int = 3
    timeout_ms: int = 30_000
    dump_smt: bool = False
    dump_model: bool = False
    example_input: Any = None  # JSON-like dict
    input_schema: Any = None  # JSON Schema dict
    concrete_input: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Internal enums
# ---------------------------------------------------------------------------

class _Action(Enum):
    Continue = auto()
    Return = auto()
    Jump = auto()


@dataclass
class InstructionAction:
    kind: _Action
    value: Optional[SymValue] = None
    target: int = 0

    @staticmethod
    def cont():
        return InstructionAction(_Action.Continue)

    @staticmethod
    def ret(v: SymValue):
        return InstructionAction(_Action.Return, value=v)

    @staticmethod
    def jump(target: int):
        return InstructionAction(_Action.Jump, target=target)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _value_to_path_segment(v) -> str:
    if isinstance(v, str):
        return v
    if isinstance(v, bool):
        return str(v).lower()
    if isinstance(v, (int, float)):
        return str(v)
    return repr(v)


def _is_concrete(v):
    """Check if a SymValue is concrete (not _UNDEFINED, not z3_expr, not symbolic set)."""
    return v.is_concrete


def _json_index(container, key):
    """Index a JSON value by a key (like Rego's container[key])."""
    if container is None or container is _UNDEFINED:
        return None
    if isinstance(container, dict):
        if isinstance(key, str) and key in container:
            return container[key]
        return None
    if isinstance(container, list):
        if isinstance(key, int) and 0 <= key < len(container):
            return container[key]
        return None
    return None


# ---------------------------------------------------------------------------
# Translator
# ---------------------------------------------------------------------------

class Translator:
    """Symbolic translator: mirrors the Rust ``Translator`` struct."""

    def __init__(
        self,
        program: Program,
        data: Any,
        registry: PathRegistry,
        config: AnalysisConfig,
    ):
        self.program = program
        self.data = data if data is not None else {}
        self.registry = registry
        self.config = config

        num_regs = max(program.dispatch_window_size, program.max_rule_window_size, 16)
        self.registers: list[SymRegister] = [SymRegister.undefined() for _ in range(num_regs)]

        self.path_condition: z3.BoolRef = z3.BoolVal(True)
        self.constraints: list[z3.BoolRef] = []
        self.pc: int = 0
        self.pc_path_conditions: dict[int, z3.BoolRef] = {}
        self.caller_path_condition: z3.BoolRef = z3.BoolVal(True)
        self.warnings: list[str] = []
        self.rule_cache: dict[int, tuple[SymValue, Definedness]] = {}
        self.rule_depth: int = 0
        self.fresh_counter: int = 0

        # Partial-set element tracking
        self.is_in_partial_set_body: bool = False
        self.partial_set_main_value_reg: Optional[int] = None
        self.partial_set_elements: list[SymSetElement] = []

        # Comprehension stack
        self.comprehension_stack: list[ComprehensionAccumulator] = []

    # === Entry point ===

    def translate_entry_point(self, entry_pc: int) -> SymValue:
        return self.translate_block(entry_pc)

    def translate_block(self, start_pc: int) -> SymValue:
        self.pc = start_pc
        while self.pc < len(self.program.instructions):
            instr = self.program.instructions[self.pc]
            current_pc = self.pc
            action = self._translate_instruction(instr)
            if action.kind == _Action.Continue:
                full_cond = z3.And(self.caller_path_condition, self.path_condition)
                self.pc_path_conditions[current_pc] = full_cond
                self.pc += 1
            elif action.kind == _Action.Return:
                return action.value
            elif action.kind == _Action.Jump:
                self.pc = action.target
        # fell off end
        return self.registers[0].value

    # === Register helpers ===

    def _get_reg(self, r: int) -> SymRegister:
        if r < len(self.registers):
            return self.registers[r]
        return SymRegister.undefined()

    def _set_reg_concrete(self, r: int, v):
        while r >= len(self.registers):
            self.registers.append(SymRegister.undefined())
        self.registers[r] = SymRegister.concrete(v)

    def _set_reg_sym(self, r: int, value: SymValue, defined: Definedness,
                     source_path: Optional[str] = None):
        while r >= len(self.registers):
            self.registers.append(SymRegister.undefined())
        self.registers[r] = SymRegister(value=value, defined=defined, source_path=source_path)

    def _fresh_name(self, prefix: str) -> str:
        n = self.fresh_counter
        self.fresh_counter += 1
        return f"{prefix}_{n}"

    # === Path register ===

    def _create_path_register(self, dest: int, path: str,
                              sort: ValueSort = ValueSort.Unknown) -> InstructionAction:
        # Concrete input override
        if path.startswith("input."):
            suffix = path[len("input."):]
            if "." not in suffix and suffix in self.config.concrete_input:
                self._set_reg_concrete(dest, self.config.concrete_input[suffix])
                return InstructionAction.cont()

        self.registry.get_or_create(path, sort, True, self.pc)
        entry = self.registry.get(path)
        defined = entry.defined
        self._set_reg_sym(
            dest,
            SymValue.undefined(),  # placeholder
            Definedness.symbolic(defined),
            source_path=path,
        )
        return InstructionAction.cont()

    # === Sort promotion ===

    def _promote_path_registers(self, left: int, right: int):
        l_sort = self.registers[left].value.sort
        r_sort = self.registers[right].value.sort
        l_path = self.registers[left].source_path is not None
        r_path = self.registers[right].source_path is not None

        if l_path and l_sort == ValueSort.Unknown and r_sort != ValueSort.Unknown:
            self._ensure_register_sort(left, r_sort)
        if r_path and r_sort == ValueSort.Unknown and l_sort != ValueSort.Unknown:
            self._ensure_register_sort(right, l_sort)

        # Both unknown paths → default to String
        if (l_path and r_path
                and self.registers[left].value.sort == ValueSort.Unknown
                and self.registers[right].value.sort == ValueSort.Unknown):
            self._ensure_register_sort(left, ValueSort.String)
            self._ensure_register_sort(right, ValueSort.String)

    def _promote_path_register_to_sort(self, reg: int, sort: ValueSort):
        if (reg < len(self.registers)
                and self.registers[reg].source_path is not None
                and self.registers[reg].value.sort == ValueSort.Unknown):
            self._ensure_register_sort(reg, sort)

    def _ensure_register_sort(self, reg: int, sort: ValueSort):
        r = self.registers[reg]
        if r.source_path is not None:
            path = r.source_path
            self.registry.refine_sort(path, sort)
            sym_val = self.registry.get_var_for_sort(path, sort)
            if sym_val is not None:
                self.registers[reg] = SymRegister(
                    value=sym_val,
                    defined=r.defined,
                    source_path=r.source_path,
                )

    # === Resolve helpers ===

    def _resolve_arg_as_z3_string(self, reg: int):
        r = self._get_reg(reg)
        try:
            return r.value.to_z3_string()
        except (ValueError, TypeError):
            pass
        if r.source_path:
            sort = self.registry.get_sort(r.source_path)
            if sort in (ValueSort.String, None, ValueSort.Unknown):
                return self.registry.get_string(r.source_path)
        return None

    def _resolve_arg_as_z3_int(self, reg: int):
        r = self._get_reg(reg)
        try:
            return r.value.to_z3_int()
        except (ValueError, TypeError):
            pass
        if r.source_path:
            sort = self.registry.get_sort(r.source_path)
            if sort in (ValueSort.Int, None, ValueSort.Unknown):
                return self.registry.get_int(r.source_path)
        return None

    # =======================================================================
    # Per-instruction dispatch
    # =======================================================================

    def _translate_instruction(self, instr: Instruction) -> InstructionAction:
        op = instr.opcode
        f = instr.fields

        # -- Loads --
        if op == "Load":
            self._set_reg_concrete(f["dest"], self.program.literals[f["literal_idx"]])
            return InstructionAction.cont()
        if op == "LoadTrue":
            self._set_reg_concrete(f["dest"], True)
            return InstructionAction.cont()
        if op == "LoadFalse":
            self._set_reg_concrete(f["dest"], False)
            return InstructionAction.cont()
        if op == "LoadNull":
            self._set_reg_concrete(f["dest"], None)
            return InstructionAction.cont()
        if op == "LoadBool":
            self._set_reg_concrete(f["dest"], f["value"])
            return InstructionAction.cont()
        if op == "LoadData":
            self._set_reg_concrete(f["dest"], copy.deepcopy(self.data))
            return InstructionAction.cont()
        if op == "LoadInput":
            self._set_reg_sym(
                f["dest"],
                SymValue.from_concrete({}),
                Definedness.defined(),
                source_path="input",
            )
            return InstructionAction.cont()
        if op == "Move":
            src = copy.copy(self._get_reg(f["src"]))
            self.registers[f["dest"]] = src
            return InstructionAction.cont()

        # -- Arithmetic --
        if op in ("Add", "Sub", "Mul", "Div", "Mod"):
            return self._translate_arithmetic(f["dest"], f["left"], f["right"], op)

        # -- Comparisons --
        if op in ("Eq", "Ne", "Lt", "Le", "Gt", "Ge"):
            return self._translate_comparison(f["dest"], f["left"], f["right"], op)

        # -- Logical --
        if op == "And":
            return self._translate_logical_and(f["dest"], f["left"], f["right"])
        if op == "Or":
            return self._translate_logical_or(f["dest"], f["left"], f["right"])
        if op == "Not":
            return self._translate_logical_not(f["dest"], f["operand"])

        # -- Assertions --
        if op == "AssertCondition":
            return self._translate_assert_condition(f["condition"])
        if op == "AssertNotUndefined":
            return self._translate_assert_not_undefined(f["register"])

        # -- Indexing --
        if op == "Index":
            return self._translate_index(f["dest"], f["container"], f["key"])
        if op == "IndexLiteral":
            return self._translate_index_literal(f["dest"], f["container"], f["literal_idx"])
        if op == "ChainedIndex":
            return self._translate_chained_index(f["params_index"])

        # -- Rule calls --
        if op == "CallRule":
            return self._translate_call_rule(f["dest"], f["rule_index"])
        if op == "RuleInit":
            self._set_reg_sym(f["result_reg"], SymValue.undefined(), Definedness.undefined())
            return InstructionAction.cont()
        if op == "RuleReturn":
            return InstructionAction.ret(self.registers[0].value)
        if op == "DestructuringSuccess":
            return InstructionAction.ret(self.registers[0].value)
        if op == "Return":
            reg = self._get_reg(f["value"])
            def_cond = reg.defined.to_z3()
            self.path_condition = z3.And(self.path_condition, def_cond)
            return InstructionAction.ret(reg.value)
        if op == "Halt":
            return InstructionAction.ret(self.registers[0].value)

        # -- Collections --
        if op == "ArrayNew":
            self._set_reg_concrete(f["dest"], [])
            return InstructionAction.cont()
        if op == "SetNew":
            self._set_reg_concrete(f["dest"], set())
            return InstructionAction.cont()
        if op == "ObjectCreate":
            return self._translate_object_create(f["params_index"])
        if op == "ArrayCreate":
            return self._translate_array_create(f["params_index"])
        if op == "SetCreate":
            return self._translate_set_create(f["params_index"])
        if op == "ObjectSet":
            return self._translate_object_set(f["obj"], f["key"], f["value"])
        if op == "ArrayPush":
            return self._translate_array_push(f["arr"], f["value"])
        if op == "SetAdd":
            return self._translate_set_add(f["set"], f["value"])
        if op == "Contains":
            return self._translate_contains(f["dest"], f["collection"], f["value"])
        if op == "Count":
            return self._translate_count(f["dest"], f["collection"])

        # -- Loops --
        if op == "LoopStart":
            return self._translate_loop_start(f["params_index"])
        if op == "LoopNext":
            return InstructionAction.cont()  # no-op; unrolled in LoopStart

        # -- Builtins --
        if op == "BuiltinCall":
            return self._translate_builtin_call(f["params_index"])

        # -- Function calls --
        if op == "FunctionCall":
            return self._translate_function_call(f["params_index"])

        # -- Virtual data document --
        if op == "VirtualDataDocumentLookup":
            return self._translate_virtual_data_lookup(f["params_index"])

        # -- Comprehensions --
        if op == "ComprehensionBegin":
            return self._translate_comprehension(f["params_index"])
        if op == "ComprehensionYield":
            return self._translate_comprehension_yield(f["value_reg"], f.get("key_reg"))
        if op == "ComprehensionEnd":
            if self.comprehension_stack:
                return InstructionAction.ret(SymValue.undefined())
            return InstructionAction.cont()

        # -- HostAwait --
        if op == "HostAwait":
            self.warnings.append(f"PC {self.pc}: HostAwait modeled as unconstrained String")
            v = z3.String(f"host_await_{self.pc}")
            self._set_reg_sym(f["dest"], SymValue.from_z3_string(v), Definedness.defined())
            return InstructionAction.cont()

        # -- Unknown opcode --
        self.warnings.append(f"PC {self.pc}: Unknown opcode '{op}'")
        return InstructionAction.cont()

    # =======================================================================
    # Arithmetic
    # =======================================================================

    def _translate_arithmetic(self, dest: int, left: int, right: int,
                              op: str) -> InstructionAction:
        self._promote_path_register_to_sort(left, ValueSort.Int)
        self._promote_path_register_to_sort(right, ValueSort.Int)
        a = self._get_reg(left)
        b = self._get_reg(right)
        if a.defined.is_undefined or b.defined.is_undefined:
            self._set_reg_sym(dest, SymValue.undefined(), Definedness.undefined())
            return InstructionAction.cont()

        # Both concrete
        if a.value.is_concrete and b.value.is_concrete and a.source_path is None and b.source_path is None:
            va, vb = a.value.concrete, b.value.concrete
            if isinstance(va, (int, float)) and isinstance(vb, (int, float)):
                try:
                    if op == "Add": r = va + vb
                    elif op == "Sub": r = va - vb
                    elif op == "Mul": r = va * vb
                    elif op == "Div":
                        if vb == 0:
                            self._set_reg_sym(dest, SymValue.undefined(), Definedness.undefined())
                            return InstructionAction.cont()
                        r = va // vb if isinstance(va, int) and isinstance(vb, int) else va / vb
                    elif op == "Mod":
                        if vb == 0:
                            self._set_reg_sym(dest, SymValue.undefined(), Definedness.undefined())
                            return InstructionAction.cont()
                        r = va % vb
                    else:
                        r = va
                    self._set_reg_concrete(dest, r)
                    return InstructionAction.cont()
                except Exception:
                    self._set_reg_sym(dest, SymValue.undefined(), Definedness.undefined())
                    return InstructionAction.cont()

        # Symbolic
        za = a.value.to_z3_int()
        zb = b.value.to_z3_int()
        if op == "Add": result = za + zb
        elif op == "Sub": result = za - zb
        elif op == "Mul": result = za * zb
        elif op == "Div":
            self.constraints.append(zb != z3.IntVal(0))
            result = za / zb
        elif op == "Mod":
            self.constraints.append(zb != z3.IntVal(0))
            result = za % zb
        else:
            result = za
        defined = Definedness.and_(a.defined, b.defined)
        self._set_reg_sym(dest, SymValue.from_z3_int(result), defined)
        return InstructionAction.cont()

    # =======================================================================
    # Comparisons
    # =======================================================================

    def _translate_comparison(self, dest: int, left: int, right: int,
                              op: str) -> InstructionAction:
        self._promote_path_registers(left, right)
        a = self._get_reg(left)
        b = self._get_reg(right)
        if a.defined.is_undefined or b.defined.is_undefined:
            self._set_reg_sym(dest, SymValue.undefined(), Definedness.undefined())
            return InstructionAction.cont()

        # Both concrete (non-path-placeholder)
        if (a.value.is_concrete and b.value.is_concrete
                and a.source_path is None and b.source_path is None):
            va, vb = a.value.concrete, b.value.concrete
            if op == "Eq": r = va == vb
            elif op == "Ne": r = va != vb
            elif op == "Lt": r = va < vb
            elif op == "Le": r = va <= vb
            elif op == "Gt": r = va > vb
            elif op == "Ge": r = va >= vb
            else: r = False
            self._set_reg_concrete(dest, r)
            return InstructionAction.cont()

        result_bool = self._make_comparison(a.value, b.value, op)
        defined = Definedness.and_(a.defined, b.defined)
        self._set_reg_sym(dest, SymValue.from_z3_bool(result_bool), defined)
        return InstructionAction.cont()

    def _make_comparison(self, a: SymValue, b: SymValue, op: str) -> z3.BoolRef:
        s_a, s_b = a.sort, b.sort
        if s_a == ValueSort.Unknown:
            csort = s_b
        elif s_b == ValueSort.Unknown:
            csort = s_a
        elif s_a == s_b:
            csort = s_a
        elif {s_a, s_b} == {ValueSort.Int, ValueSort.Real}:
            csort = ValueSort.Real
        else:
            csort = ValueSort.String  # fallback

        if csort == ValueSort.Bool:
            za, zb = a.to_z3_bool(), b.to_z3_bool()
            if op == "Eq": return za == zb
            if op == "Ne": return za != zb
            return z3.BoolVal(False)  # ordering on bools unsupported
        if csort == ValueSort.Int:
            za, zb = a.to_z3_int(), b.to_z3_int()
        elif csort == ValueSort.Real:
            za, zb = a.to_z3_real(), b.to_z3_real()
        elif csort in (ValueSort.String, ValueSort.Unknown):
            za, zb = a.to_z3_string(), b.to_z3_string()
            if op == "Eq": return za == zb
            if op == "Ne": return za != zb
            # String ordering approximated
            self.warnings.append(f"PC {self.pc}: String ordering comparison approximated")
            return z3.Bool(f"str_cmp_{self.pc}")
        else:
            za, zb = a.to_z3_string(), b.to_z3_string()
            if op == "Eq": return za == zb
            return za != zb

        if op == "Eq": return za == zb
        if op == "Ne": return za != zb
        if op == "Lt": return za < zb
        if op == "Le": return za <= zb
        if op == "Gt": return za > zb
        if op == "Ge": return za >= zb
        return z3.BoolVal(False)

    # =======================================================================
    # Logical
    # =======================================================================

    def _translate_logical_and(self, dest: int, left: int, right: int) -> InstructionAction:
        a, b = self._get_reg(left), self._get_reg(right)
        if a.defined.is_undefined or b.defined.is_undefined:
            self._set_reg_sym(dest, SymValue.undefined(), Definedness.undefined())
            return InstructionAction.cont()
        za, zb = a.value.to_z3_bool(), b.value.to_z3_bool()
        result = z3.And(za, zb)
        defined = Definedness.and_(a.defined, b.defined)
        self._set_reg_sym(dest, SymValue.from_z3_bool(result), defined)
        return InstructionAction.cont()

    def _translate_logical_or(self, dest: int, left: int, right: int) -> InstructionAction:
        a, b = self._get_reg(left), self._get_reg(right)
        if a.defined.is_undefined or b.defined.is_undefined:
            self._set_reg_sym(dest, SymValue.undefined(), Definedness.undefined())
            return InstructionAction.cont()
        za, zb = a.value.to_z3_bool(), b.value.to_z3_bool()
        result = z3.Or(za, zb)
        defined = Definedness.and_(a.defined, b.defined)
        self._set_reg_sym(dest, SymValue.from_z3_bool(result), defined)
        return InstructionAction.cont()

    def _translate_logical_not(self, dest: int, operand: int) -> InstructionAction:
        self._promote_path_register_to_sort(operand, ValueSort.Bool)
        a = self._get_reg(operand)
        if a.defined.is_undefined:
            self._set_reg_concrete(dest, True)  # not undefined → true
            return InstructionAction.cont()
        if a.defined.is_symbolic:
            def_bool = a.defined.to_z3()
            if a.value.sort == ValueSort.Bool and a.value.z3_expr is not None:
                result = z3.Not(z3.And(def_bool, a.value.z3_expr))
            elif a.value.is_undefined:
                self._set_reg_concrete(dest, True)
                return InstructionAction.cont()
            else:
                try:
                    val = a.value.to_z3_bool()
                    result = z3.If(def_bool, z3.Not(val), z3.BoolVal(True))
                except (ValueError, TypeError):
                    result = z3.Not(def_bool)
            self._set_reg_sym(dest, SymValue.from_z3_bool(result), Definedness.defined())
            return InstructionAction.cont()
        # Defined
        val = a.value.to_z3_bool()
        self._set_reg_sym(dest, SymValue.from_z3_bool(z3.Not(val)), Definedness.defined())
        return InstructionAction.cont()

    # =======================================================================
    # Assertions
    # =======================================================================

    def _translate_assert_condition(self, condition: int) -> InstructionAction:
        reg = self._get_reg(condition)
        # Path register → promote to Bool
        if reg.source_path is not None:
            self._ensure_register_sort(condition, ValueSort.Bool)
            reg = self._get_reg(condition)
            bool_val = reg.value.to_z3_bool()
            def_z3 = reg.defined.to_z3()
            cond = z3.And(def_z3, bool_val)
            self.path_condition = z3.And(self.path_condition, cond)
            return InstructionAction.cont()

        if reg.value.is_concrete:
            v = reg.value.concrete
            if isinstance(v, bool):
                if reg.defined.is_defined:
                    cond = z3.BoolVal(v)
                elif reg.defined.is_undefined:
                    cond = z3.BoolVal(False)
                else:  # symbolic definedness
                    def_z3 = reg.defined.to_z3()
                    cond = def_z3 if v else z3.BoolVal(False)
            elif v is None or v is _UNDEFINED:
                cond = z3.BoolVal(False)
            else:
                cond = reg.defined.to_z3()
        elif reg.value.sort == ValueSort.Bool and reg.value.z3_expr is not None:
            b = reg.value.z3_expr
            if reg.defined.is_defined:
                cond = b
            elif reg.defined.is_undefined:
                cond = z3.BoolVal(False)
            else:
                cond = z3.And(reg.defined.to_z3(), b)
        else:
            cond = reg.defined.to_z3()

        self.path_condition = z3.And(self.path_condition, cond)
        return InstructionAction.cont()

    def _translate_assert_not_undefined(self, register: int) -> InstructionAction:
        reg = self._get_reg(register)
        def_z3 = reg.defined.to_z3()
        self.path_condition = z3.And(self.path_condition, def_z3)
        return InstructionAction.cont()

    # =======================================================================
    # Indexing
    # =======================================================================

    def _translate_index(self, dest: int, container: int, key: int) -> InstructionAction:
        c_reg = self._get_reg(container)
        k_reg = self._get_reg(key)
        if c_reg.source_path is not None and k_reg.value.is_concrete:
            seg = _value_to_path_segment(k_reg.value.concrete)
            new_path = f"{c_reg.source_path}.{seg}"
            return self._create_path_register(dest, new_path)
        if c_reg.value.is_concrete and k_reg.value.is_concrete:
            result = _json_index(c_reg.value.concrete, k_reg.value.concrete)
            self._set_reg_concrete(dest, result)
            return InstructionAction.cont()
        self.warnings.append(f"PC {self.pc}: Dynamic index → unconstrained String")
        v = z3.String(f"dyn_idx_{self.pc}")
        self._set_reg_sym(dest, SymValue.from_z3_string(v), Definedness.defined())
        return InstructionAction.cont()

    def _translate_index_literal(self, dest: int, container: int,
                                 literal_idx: int) -> InstructionAction:
        key_val = self.program.literals[literal_idx]
        c_reg = self._get_reg(container)
        if c_reg.source_path is not None:
            seg = _value_to_path_segment(key_val)
            new_path = f"{c_reg.source_path}.{seg}"
            return self._create_path_register(dest, new_path)
        if c_reg.value.is_concrete:
            result = _json_index(c_reg.value.concrete, key_val)
            self._set_reg_concrete(dest, result)
            return InstructionAction.cont()
        self.warnings.append(f"PC {self.pc}: IndexLiteral on symbolic container")
        v = z3.String(f"idx_lit_{self.pc}")
        self._set_reg_sym(dest, SymValue.from_z3_string(v), Definedness.defined())
        return InstructionAction.cont()

    def _translate_chained_index(self, params_index: int) -> InstructionAction:
        params: ChainedIndexParams = self.program.instruction_data.chained_index_params[params_index]
        root_reg = self._get_reg(params.root)
        current_path = root_reg.source_path

        for comp in params.path_components:
            if isinstance(comp, dict):
                if "Literal" in comp:
                    key = self.program.literals[comp["Literal"]]
                    seg = _value_to_path_segment(key)
                    if current_path is not None:
                        current_path = f"{current_path}.{seg}"
                elif "Register" in comp:
                    r = self._get_reg(comp["Register"])
                    if r.source_path is not None:
                        current_path = r.source_path
                    elif r.value.is_concrete:
                        seg = _value_to_path_segment(r.value.concrete)
                        if current_path is not None:
                            current_path = f"{current_path}[{seg}]"
                    else:
                        current_path = None

        if current_path is not None:
            return self._create_path_register(params.dest, current_path)

        # Concrete evaluation
        if root_reg.value.is_concrete:
            cv = root_reg.value.concrete
            for comp in params.path_components:
                if isinstance(comp, dict):
                    if "Literal" in comp:
                        key = self.program.literals[comp["Literal"]]
                    elif "Register" in comp:
                        r = self._get_reg(comp["Register"])
                        if r.value.is_concrete:
                            key = r.value.concrete
                        else:
                            break
                    else:
                        break
                    cv = _json_index(cv, key)
            self._set_reg_concrete(params.dest, cv)
            return InstructionAction.cont()

        self.warnings.append(f"PC {self.pc}: ChainedIndex on fully symbolic container")
        v = z3.String(f"chain_idx_{self.pc}")
        self._set_reg_sym(params.dest, SymValue.from_z3_string(v), Definedness.defined())
        return InstructionAction.cont()

    # =======================================================================
    # Rule calls
    # =======================================================================

    def _translate_call_rule(self, dest: int, rule_index: int) -> InstructionAction:
        if rule_index in self.rule_cache:
            cv, cd = self.rule_cache[rule_index]
            self._set_reg_sym(dest, cv, cd)
            return InstructionAction.cont()

        if self.rule_depth >= self.config.max_rule_depth:
            self.warnings.append(
                f"PC {self.pc}: Max rule depth ({self.config.max_rule_depth}) for rule {rule_index}")
            self._set_reg_sym(dest, SymValue.undefined(), Definedness.undefined())
            return InstructionAction.cont()

        ri = self.program.rule_infos[rule_index]
        is_function = ri.function_info is not None
        is_partial_set = ri.rule_type == RuleType.PartialSet

        # Save state
        saved_pc = self.pc
        saved_path_cond = self.path_condition
        saved_registers = [copy.copy(r) for r in self.registers]
        saved_caller_path_cond = self.caller_path_condition
        saved_is_in_ps = self.is_in_partial_set_body
        saved_ps_value_reg = self.partial_set_main_value_reg
        saved_ps_elements = self.partial_set_elements[:]

        self.caller_path_condition = z3.And(self.caller_path_condition, self.path_condition)
        self.rule_depth += 1

        num_regs = ri.num_registers
        while len(self.registers) < num_regs:
            self.registers.append(SymRegister.undefined())
        for i in range(num_regs):
            self.registers[i] = SymRegister.undefined()

        if is_partial_set:
            self.is_in_partial_set_body = True
            self.partial_set_main_value_reg = None
            self.partial_set_elements = []

        body_results = []
        for def_idx, bodies in enumerate(ri.definitions):
            for body_pc in bodies:
                self.path_condition = z3.BoolVal(True)
                for i in range(num_regs):
                    self.registers[i] = SymRegister.undefined()
                if is_partial_set:
                    self.partial_set_main_value_reg = None

                # Destructuring
                if def_idx < len(ri.destructuring_blocks) and ri.destructuring_blocks[def_idx] is not None:
                    self.translate_block(ri.destructuring_blocks[def_idx])

                self.translate_block(body_pc)
                result_value = self._get_reg(ri.result_reg)
                body_path_cond = self.path_condition

                if is_partial_set:
                    body_succeeded = body_path_cond
                else:
                    result_defined = result_value.defined.to_z3()
                    body_succeeded = z3.And(body_path_cond, result_defined)

                body_results.append((body_succeeded, copy.copy(result_value.value)))
                if not is_partial_set:
                    break

        self.rule_depth -= 1
        collected_ps_elements = self.partial_set_elements[:] if is_partial_set else []

        # Restore state
        self.registers = saved_registers
        self.pc = saved_pc
        self.path_condition = saved_path_cond
        self.caller_path_condition = saved_caller_path_cond
        self.is_in_partial_set_body = saved_is_in_ps
        self.partial_set_main_value_reg = saved_ps_value_reg
        self.partial_set_elements = saved_ps_elements

        # Build result
        if is_partial_set:
            return self._build_partial_set_result(
                dest, rule_index, is_function, body_results, collected_ps_elements)

        return self._build_complete_rule_result(dest, rule_index, ri, is_function, body_results)

    def _build_partial_set_result(self, dest, rule_index, is_function,
                                  body_results, elements):
        if elements:
            # Group by key_path
            groups: dict[str, list[z3.BoolRef]] = {}
            for elem in elements:
                groups.setdefault(elem.key_path, []).append(elem.condition)

            card = z3.IntVal(0)
            group_info = []
            for key, conds in groups.items():
                any_succ = conds[0] if len(conds) == 1 else z3.Or(*conds)
                card = card + z3.If(any_succ, z3.IntVal(1), z3.IntVal(0))
                group_info.append((key, any_succ))

            # Pairwise distinctness
            for i in range(len(group_info)):
                for j in range(i + 1, len(group_info)):
                    pi, ci = group_info[i]
                    pj, cj = group_info[j]
                    si = self.registry.get_sort(pi)
                    sj = self.registry.get_sort(pj)
                    both = z3.And(ci, cj)
                    if si == sj and si in (ValueSort.String, ValueSort.Int, ValueSort.Bool, ValueSort.Real):
                        if si == ValueSort.String:
                            vi, vj = self.registry.get_string(pi), self.registry.get_string(pj)
                        elif si == ValueSort.Int:
                            vi, vj = self.registry.get_int(pi), self.registry.get_int(pj)
                        elif si == ValueSort.Bool:
                            vi, vj = self.registry.get_bool(pi), self.registry.get_bool(pj)
                        else:
                            vi, vj = self.registry.get_real(pi), self.registry.get_real(pj)
                        self.constraints.append(z3.Implies(both, vi != vj))

            result = SymValue.symbolic_set(card, elements)
        elif body_results:
            card = z3.IntVal(0)
            for cond, _ in body_results:
                card = card + z3.If(cond, z3.IntVal(1), z3.IntVal(0))
            self.constraints.append(card >= z3.IntVal(0))
            result = SymValue(concrete=_UNDEFINED, sort=ValueSort.Int, sym_set_cardinality=card)
        else:
            card = z3.IntVal(0)
            result = SymValue(concrete=_UNDEFINED, sort=ValueSort.Int, sym_set_cardinality=card)

        if not is_function:
            self.rule_cache[rule_index] = (result, Definedness.defined())
        self._set_reg_sym(dest, result, Definedness.defined())
        return InstructionAction.cont()

    def _build_complete_rule_result(self, dest, rule_index, ri, is_function, body_results):
        if not body_results:
            fv, fd = SymValue.undefined(), Definedness.undefined()
        elif len(body_results) == 1:
            cond, val = body_results[0]
            fv, fd = val, Definedness.symbolic(cond)
        else:
            cond, val = body_results[-1]
            fv, fd = val, Definedness.symbolic(cond)

        # Default value
        if ri.default_literal_index is not None:
            default_val = self.program.literals[ri.default_literal_index]
            if fd.is_undefined:
                fv, fd = SymValue.from_concrete(default_val), Definedness.defined()
            elif fd.is_symbolic:
                def_bool = fd.to_z3()
                if isinstance(default_val, bool) and fv.sort == ValueSort.Bool:
                    try:
                        rule_z3 = fv.to_z3_bool()
                        def_z3 = z3.BoolVal(default_val)
                        fv = SymValue.from_z3_bool(z3.If(def_bool, rule_z3, def_z3))
                        fd = Definedness.defined()
                    except (ValueError, TypeError):
                        pass
                elif fv.is_concrete and isinstance(fv.concrete, bool) and isinstance(default_val, bool):
                    rule_z3 = z3.BoolVal(fv.concrete)
                    def_z3 = z3.BoolVal(default_val)
                    fv = SymValue.from_z3_bool(z3.If(def_bool, rule_z3, def_z3))
                    fd = Definedness.defined()
        else:
            if ri.rule_type == RuleType.PartialSet and fd.is_undefined:
                fv, fd = SymValue.from_concrete(set()), Definedness.defined()
            elif ri.rule_type == RuleType.PartialObject and fd.is_undefined:
                fv, fd = SymValue.from_concrete({}), Definedness.defined()

        if not is_function:
            self.rule_cache[rule_index] = (fv, fd)
        self._set_reg_sym(dest, fv, fd)
        return InstructionAction.cont()

    # =======================================================================
    # Collections
    # =======================================================================

    def _translate_object_create(self, params_index: int) -> InstructionAction:
        params: ObjectCreateParams = self.program.instruction_data.object_create_params[params_index]
        obj = {}
        for lit_key_idx, val_reg in params.literal_key_fields:
            key = self.program.literals[lit_key_idx]
            r = self._get_reg(val_reg)
            if r.value.is_concrete and r.source_path is None:
                obj[key] = r.value.concrete
            else:
                obj[key] = None
        for key_reg, val_reg in params.fields:
            kr = self._get_reg(key_reg)
            vr = self._get_reg(val_reg)
            if kr.value.is_concrete and vr.value.is_concrete:
                obj[kr.value.concrete] = vr.value.concrete
        self._set_reg_concrete(params.dest, obj)
        return InstructionAction.cont()

    def _translate_array_create(self, params_index: int) -> InstructionAction:
        params: ArrayCreateParams = self.program.instruction_data.array_create_params[params_index]
        all_concrete = all(
            self._get_reg(r).value.is_concrete and self._get_reg(r).source_path is None
            for r in params.elements
        )
        if all_concrete:
            arr = [self._get_reg(r).value.concrete for r in params.elements]
            self._set_reg_concrete(params.dest, arr)
        else:
            elements = self._build_sym_set_elements(params.elements)
            card = z3.IntVal(0)
            for e in elements:
                card = card + z3.If(e.condition, z3.IntVal(1), z3.IntVal(0))
            self._set_reg_sym(params.dest, SymValue.symbolic_set(card, elements),
                              Definedness.defined())
        return InstructionAction.cont()

    def _translate_set_create(self, params_index: int) -> InstructionAction:
        params: SetCreateParams = self.program.instruction_data.set_create_params[params_index]
        all_concrete = all(
            self._get_reg(r).value.is_concrete and self._get_reg(r).source_path is None
            for r in params.elements
        )
        if all_concrete:
            s = set()
            for r in params.elements:
                v = self._get_reg(r).value.concrete
                if isinstance(v, (str, int, float, bool)):
                    s.add(v)
            self._set_reg_concrete(params.dest, s)
        else:
            elements = self._build_sym_set_elements(params.elements)
            card = z3.IntVal(0)
            for e in elements:
                card = card + z3.If(e.condition, z3.IntVal(1), z3.IntVal(0))
            self._set_reg_sym(params.dest, SymValue.symbolic_set(card, elements),
                              Definedness.defined())
        return InstructionAction.cont()

    def _build_sym_set_elements(self, reg_indices) -> list[SymSetElement]:
        elements = []
        for i, reg_idx in enumerate(reg_indices):
            r = self._get_reg(reg_idx)
            ep = r.source_path or f"sym_elem_{self.pc}_{i}"
            es = (self.registry.get(ep).sort
                  if r.source_path and self.registry.get(ep) else r.value.sort)
            cond = r.defined.to_z3()
            elements.append(SymSetElement(
                condition=cond, element_path=ep, key_path=ep, element_sort=es))
        return elements

    def _translate_object_set(self, obj: int, key: int, value: int) -> InstructionAction:
        o = self._get_reg(obj)
        k = self._get_reg(key)
        v = self._get_reg(value)
        if (o.value.is_concrete and isinstance(o.value.concrete, dict)
                and k.value.is_concrete and k.source_path is None):
            new_obj = dict(o.value.concrete)
            if v.value.is_concrete and v.source_path is None:
                new_obj[k.value.concrete] = v.value.concrete
            else:
                new_obj[k.value.concrete] = None
            self._set_reg_concrete(obj, new_obj)
        return InstructionAction.cont()

    def _translate_array_push(self, arr: int, value: int) -> InstructionAction:
        a = self._get_reg(arr)
        v = self._get_reg(value)
        if a.value.is_concrete and isinstance(a.value.concrete, list):
            new_arr = list(a.value.concrete)
            if v.value.is_concrete and v.source_path is None:
                new_arr.append(v.value.concrete)
            else:
                new_arr.append(None)
            self._set_reg_concrete(arr, new_arr)
        return InstructionAction.cont()

    def _translate_set_add(self, set_reg: int, value: int) -> InstructionAction:
        if self.is_in_partial_set_body:
            v = self._get_reg(value)
            cond = z3.And(self.path_condition, v.defined.to_z3())
            val_reg_idx = self.partial_set_main_value_reg
            elem_path = v.source_path or (
                self._get_reg(val_reg_idx).source_path if val_reg_idx is not None else None
            ) or f"set_elem_{self.pc}"
            key_path = v.source_path or elem_path
            es = v.value.sort
            if v.source_path and self.registry.get(v.source_path):
                es = self.registry.get(v.source_path).sort
            self.partial_set_elements.append(
                SymSetElement(condition=cond, element_path=elem_path,
                              key_path=key_path, element_sort=es))
            return InstructionAction.cont()

        s = self._get_reg(set_reg)
        v = self._get_reg(value)
        if s.value.is_concrete and isinstance(s.value.concrete, set) and v.value.is_concrete:
            new_s = set(s.value.concrete)
            vc = v.value.concrete
            if isinstance(vc, (str, int, float, bool)):
                new_s.add(vc)
            self._set_reg_concrete(set_reg, new_s)
        return InstructionAction.cont()

    def _translate_contains(self, dest: int, collection: int, value: int) -> InstructionAction:
        coll = self._get_reg(collection)
        val = self._get_reg(value)
        result_defined = Definedness.and_(coll.defined, val.defined)

        is_path_placeholder = (coll.value.is_undefined and coll.source_path is not None)

        if not is_path_placeholder:
            if coll.value.is_concrete and val.value.is_concrete:
                cv, vv = coll.value.concrete, val.value.concrete
                if isinstance(cv, (list, set)):
                    self._set_reg_concrete(dest, vv in cv)
                elif isinstance(cv, dict):
                    self._set_reg_concrete(dest, vv in cv or vv in cv.values())
                else:
                    self._set_reg_concrete(dest, False)
                return InstructionAction.cont()

        # Path collection
        if coll.source_path:
            prefix = f"{coll.source_path}["
            child_paths = [
                (p, e.sort) for p, e in self.registry.items()
                if p.startswith(prefix) and p.endswith("]") and "." not in p[len(prefix):]
            ]
            if child_paths:
                return self._contains_from_children(dest, child_paths, val, result_defined)

        # SymbolicSet
        if val.value.is_symbolic_set:
            pass  # collection is the one we check
        if coll.value.sym_set_elements:
            elems = coll.value.sym_set_elements
            return self._contains_from_sym_elements(dest, elems, val, result_defined)

        self.warnings.append(f"PC {self.pc}: Contains with symbolic values → unconstrained")
        v = z3.Bool(f"contains_{self.pc}")
        self._set_reg_sym(dest, SymValue.from_z3_bool(v), result_defined)
        return InstructionAction.cont()

    def _contains_from_children(self, dest, child_paths, val, result_defined):
        val_sort = val.value.sort
        child_sort = next((s for _, s in child_paths if s != ValueSort.Unknown), ValueSort.String)
        cmp_sort = val_sort if val_sort != ValueSort.Unknown else child_sort
        val_z3 = self._get_z3_for_contains(val, cmp_sort)
        disjs = []
        for cp, _ in child_paths:
            entry = self.registry.get(cp)
            cd = entry.defined if entry else z3.BoolVal(False)
            eq = self._build_path_equality(cp, cmp_sort, val_z3)
            disjs.append(z3.And(cd, eq))
        result = z3.Or(*disjs) if disjs else z3.BoolVal(False)
        self._set_reg_sym(dest, SymValue.from_z3_bool(result), result_defined)
        return InstructionAction.cont()

    def _contains_from_sym_elements(self, dest, elems, val, result_defined):
        val_sort = val.value.sort
        elem_sort = next((e.element_sort for e in elems if e.element_sort != ValueSort.Unknown),
                         ValueSort.String)
        cmp_sort = val_sort if val_sort != ValueSort.Unknown else elem_sort
        val_z3 = self._get_z3_for_contains(val, cmp_sort)
        disjs = []
        for elem in elems:
            eq = self._build_path_equality(elem.key_path, cmp_sort, val_z3)
            disjs.append(z3.And(elem.condition, eq))
        result = z3.Or(*disjs) if disjs else z3.BoolVal(False)
        self._set_reg_sym(dest, SymValue.from_z3_bool(result), result_defined)
        return InstructionAction.cont()

    def _get_z3_for_contains(self, reg: SymRegister, sort: ValueSort):
        """Get Z3 expression for a Contains operand."""
        if reg.source_path:
            self.registry.refine_sort(reg.source_path, sort)
            return self.registry.get_var_for_sort(reg.source_path, sort)
        if reg.value.is_concrete:
            v = reg.value.concrete
            if sort == ValueSort.String:
                return SymValue.from_z3_string(z3.StringVal(str(v) if v is not None else ""))
            if sort == ValueSort.Int and isinstance(v, (int, float)):
                return SymValue.from_z3_int(z3.IntVal(int(v)))
            if sort == ValueSort.Bool and isinstance(v, bool):
                return SymValue.from_z3_bool(z3.BoolVal(v))
        if reg.value.z3_expr is not None:
            return reg.value
        return SymValue.from_z3_string(z3.String(f"contains_val_{self.pc}"))

    def _build_path_equality(self, path: str, sort: ValueSort, val_z3: SymValue):
        if sort in (ValueSort.String, ValueSort.Unknown):
            cv = self.registry.get_string(path)
            try:
                return cv == val_z3.to_z3_string()
            except (ValueError, TypeError):
                return z3.BoolVal(False)
        if sort == ValueSort.Int:
            cv = self.registry.get_int(path)
            try:
                return cv == val_z3.to_z3_int()
            except (ValueError, TypeError):
                return z3.BoolVal(False)
        if sort == ValueSort.Bool:
            cv = self.registry.get_bool(path)
            try:
                return cv == val_z3.to_z3_bool()
            except (ValueError, TypeError):
                return z3.BoolVal(False)
        if sort == ValueSort.Real:
            cv = self.registry.get_real(path)
            try:
                return cv == val_z3.to_z3_real()
            except (ValueError, TypeError):
                return z3.BoolVal(False)
        return z3.BoolVal(False)

    def _translate_count(self, dest: int, collection: int) -> InstructionAction:
        coll = self._get_reg(collection)
        if coll.value.sym_set_cardinality is not None:
            self._set_reg_sym(dest, SymValue.from_z3_int(coll.value.sym_set_cardinality),
                              Definedness.defined())
            return InstructionAction.cont()
        if coll.value.is_concrete:
            cv = coll.value.concrete
            if isinstance(cv, (list, dict, set, str)):
                self._set_reg_concrete(dest, len(cv))
                return InstructionAction.cont()
        self._set_reg_sym(dest, SymValue.undefined(), Definedness.undefined())
        return InstructionAction.cont()

    # =======================================================================
    # Loops (bounded unrolling)
    # =======================================================================

    def _translate_loop_start(self, params_index: int) -> InstructionAction:
        params: LoopStartParams = self.program.instruction_data.loop_params[params_index]
        coll = self._get_reg(params.collection)
        is_sym_path = coll.source_path is not None

        # Concrete collection
        if not is_sym_path and coll.value.is_concrete:
            cv = coll.value.concrete
            if isinstance(cv, list):
                elements = [(i, v) for i, v in enumerate(cv)]
            elif isinstance(cv, dict):
                elements = [(k, v) for k, v in cv.items()]
            elif isinstance(cv, set):
                elements = [(v, v) for v in cv]
            else:
                return InstructionAction.jump(params.loop_end)

            if not elements:
                if params.mode == LoopMode.Every:
                    self._set_reg_concrete(params.result_reg, True)
                else:
                    self._set_reg_concrete(params.result_reg, False)
                return InstructionAction.jump(params.loop_end)

            self._set_reg_concrete(params.result_reg, False)
            saved_path_cond = self.path_condition
            success_conds = []
            for key, val in elements:
                self._set_reg_concrete(params.key_reg, key)
                self._set_reg_concrete(params.value_reg, val)
                self.path_condition = saved_path_cond
                saved_pc = self.pc
                self.translate_block(params.body_start)
                self.pc = saved_pc
                success_conds.append(self.path_condition)

            loop_result = self._combine_loop_result(params.mode, success_conds)
            self.path_condition = saved_path_cond
            self._set_reg_sym(params.result_reg, SymValue.from_z3_bool(loop_result),
                              Definedness.defined())
            return InstructionAction.jump(params.loop_end)

        # SymbolicSet collection
        if coll.value.sym_set_elements:
            elements = coll.value.sym_set_elements
            saved_path_cond = self.path_condition
            if self.is_in_partial_set_body and self.partial_set_main_value_reg is None:
                self.partial_set_main_value_reg = params.value_reg
            success_conds = []
            for elem in elements:
                self._create_path_register(params.key_reg, elem.element_path, elem.element_sort)
                self._create_path_register(params.value_reg, elem.element_path, elem.element_sort)
                self.path_condition = z3.And(saved_path_cond, elem.condition)
                saved_pc = self.pc
                self.translate_block(params.body_start)
                self.pc = saved_pc
                success_conds.append(self.path_condition)

            loop_result = self._combine_loop_result(params.mode, success_conds)
            self.path_condition = z3.And(saved_path_cond, loop_result)
            self._set_reg_sym(params.result_reg, SymValue.from_z3_bool(loop_result),
                              Definedness.defined())
            return InstructionAction.jump(params.loop_end)

        # Symbolic path collection → bounded witnesses
        coll_path = coll.source_path
        saved_path_cond = self.path_condition
        success_conds = []
        for wi in range(self.config.max_loop_depth):
            witness_base = f"{coll_path}[{wi}]" if coll_path else f"sym_coll_{self.pc}_{wi}"
            self._set_reg_concrete(params.key_reg, wi)
            self._create_path_register(params.value_reg, witness_base, ValueSort.Unknown)
            if self.is_in_partial_set_body and self.partial_set_main_value_reg is None:
                self.partial_set_main_value_reg = params.value_reg
            self.path_condition = saved_path_cond
            saved_pc = self.pc
            self.translate_block(params.body_start)
            self.pc = saved_pc
            success_conds.append(self.path_condition)

        loop_result = self._combine_loop_result(params.mode, success_conds)
        self.path_condition = z3.And(saved_path_cond, loop_result)
        self._set_reg_sym(params.result_reg, SymValue.from_z3_bool(loop_result),
                          Definedness.defined())
        return InstructionAction.jump(params.loop_end)

    def _combine_loop_result(self, mode: LoopMode, conds: list) -> z3.BoolRef:
        if not conds:
            return z3.BoolVal(True) if mode == LoopMode.Every else z3.BoolVal(False)
        if mode in (LoopMode.Any, LoopMode.ForEach):
            return z3.Or(*conds)
        return z3.And(*conds)  # Every

    # =======================================================================
    # Comprehensions
    # =======================================================================

    def _translate_comprehension(self, params_index: int) -> InstructionAction:
        params: ComprehensionBeginParams = \
            self.program.instruction_data.comprehension_begin_params[params_index]
        self.comprehension_stack.append(ComprehensionAccumulator(
            mode=params.mode.name, result_reg=params.result_reg))
        saved_path_cond = self.path_condition
        self.translate_block(params.body_start)
        acc = self.comprehension_stack.pop()
        self.path_condition = saved_path_cond

        if params.mode == ComprehensionMode.Set:
            self._build_set_comprehension_result(params.result_reg, acc)
        elif params.mode == ComprehensionMode.Array:
            self._build_array_comprehension_result(params.result_reg, acc)
        elif params.mode == ComprehensionMode.Object:
            self._build_object_comprehension_result(params.result_reg, acc)

        return InstructionAction.jump(params.comprehension_end)

    def _translate_comprehension_yield(self, value_reg: int,
                                       key_reg: Optional[int]) -> InstructionAction:
        if self.comprehension_stack:
            acc = self.comprehension_stack[-1]
            v = copy.copy(self._get_reg(value_reg))
            k = copy.copy(self._get_reg(key_reg)) if key_reg is not None else None
            acc.yields.append(ComprehensionYieldEntry(
                value=v, key=k, condition=self.path_condition))
        return InstructionAction.cont()

    def _build_set_comprehension_result(self, result_reg, acc):
        if not acc.yields:
            self._set_reg_concrete(result_reg, set())
            return
        all_concrete = all(
            y.value.value.is_concrete and y.value.source_path is None for y in acc.yields)
        if all_concrete:
            s = set()
            for y in acc.yields:
                v = y.value.value.concrete
                if v is not None and v is not _UNDEFINED and isinstance(v, (str, int, float, bool)):
                    s.add(v)
            self._set_reg_concrete(result_reg, s)
            return
        self._build_symbolic_comprehension_result(result_reg, acc)

    def _build_array_comprehension_result(self, result_reg, acc):
        if not acc.yields:
            self._set_reg_concrete(result_reg, [])
            return
        all_concrete = all(
            y.value.value.is_concrete and y.value.source_path is None for y in acc.yields)
        if all_concrete:
            arr = [y.value.value.concrete for y in acc.yields
                   if y.value.value.concrete is not _UNDEFINED]
            self._set_reg_concrete(result_reg, arr)
            return
        self._build_symbolic_comprehension_result(result_reg, acc)

    def _build_object_comprehension_result(self, result_reg, acc):
        if not acc.yields:
            self._set_reg_concrete(result_reg, {})
            return
        all_concrete = all(
            y.value.value.is_concrete and y.value.source_path is None
            and y.key is not None and y.key.value.is_concrete and y.key.source_path is None
            for y in acc.yields)
        if all_concrete:
            obj = {}
            for y in acc.yields:
                k = y.key.value.concrete if y.key else None
                v = y.value.value.concrete
                if k is not None and v is not _UNDEFINED:
                    obj[k] = v
            self._set_reg_concrete(result_reg, obj)
            return
        self._build_symbolic_comprehension_result(result_reg, acc)

    def _build_symbolic_comprehension_result(self, result_reg, acc):
        elements = []
        for i, y in enumerate(acc.yields):
            ep = y.value.source_path or f"compr_{self.pc}_{i}"
            es = (self.registry.get(ep).sort
                  if y.value.source_path and self.registry.get(ep) else y.value.value.sort)
            elements.append(SymSetElement(
                condition=y.condition, element_path=ep, key_path=ep, element_sort=es))
        card = z3.IntVal(0)
        for e in elements:
            card = card + z3.If(e.condition, z3.IntVal(1), z3.IntVal(0))
        self._set_reg_sym(result_reg, SymValue.symbolic_set(card, elements), Definedness.defined())

    # =======================================================================
    # Function calls
    # =======================================================================

    def _translate_function_call(self, params_index: int) -> InstructionAction:
        params: FunctionCallParams = self.program.instruction_data.function_call_params[params_index]
        return self._translate_call_rule(params.dest, params.func_rule_index)

    # =======================================================================
    # Virtual data document lookup
    # =======================================================================

    def _translate_virtual_data_lookup(self, params_index: int) -> InstructionAction:
        params: VirtualDataDocumentLookupParams = \
            self.program.instruction_data.virtual_data_document_lookup_params[params_index]

        path_parts = ["data"]
        all_concrete = True
        for comp in params.path_components:
            if isinstance(comp, dict):
                if "Literal" in comp:
                    key = self.program.literals[comp["Literal"]]
                    path_parts.append(_value_to_path_segment(key))
                elif "Register" in comp:
                    r = self._get_reg(comp["Register"])
                    if r.value.is_concrete:
                        path_parts.append(_value_to_path_segment(r.value.concrete))
                    else:
                        all_concrete = False
                        break

        if not all_concrete:
            self.warnings.append(f"PC {self.pc}: VDDL with symbolic path component")
            v = z3.String(f"vddl_{self.pc}")
            self._set_reg_sym(params.dest, SymValue.from_z3_string(v), Definedness.defined())
            return InstructionAction.cont()

        # Walk rule_tree
        node = self.program.rule_tree
        if isinstance(node, dict):
            node = node.get("data", node)
        for part in path_parts[1:]:
            if isinstance(node, dict):
                node = node.get(part, None)
            else:
                node = None
                break

        if isinstance(node, (int, float)) and not isinstance(node, bool):
            # Rule index
            return self._translate_call_rule(params.dest, int(node))
        if isinstance(node, dict):
            # Subtree — look up in concrete data
            result = self.data
            for part in path_parts[1:]:
                result = _json_index(result, part)
            self._set_reg_concrete(params.dest, result)
        else:
            result = self.data
            for part in path_parts[1:]:
                result = _json_index(result, part)
            self._set_reg_concrete(params.dest, result)
        return InstructionAction.cont()

    # =======================================================================
    # Builtins
    # =======================================================================

    def _translate_builtin_call(self, params_index: int) -> InstructionAction:
        params: BuiltinCallParams = self.program.instruction_data.builtin_call_params[params_index]
        bi = self.program.builtin_info_table[params.builtin_index]
        name = bi.name
        args = params.args[:params.num_args]

        if name == "count":
            self._builtin_count(params, args)
        elif name == "trace":
            self._set_reg_concrete(params.dest, True)
        elif name in ("startswith", "endswith", "contains"):
            self._builtin_string_bool(params, name, args)
        elif name == "indexof":
            self._builtin_indexof(params, args)
        elif name == "replace":
            self._builtin_replace(params, args)
        elif name == "substring":
            self._builtin_substring(params, args)
        elif name == "trim_prefix":
            self._builtin_trim_prefix(params, args)
        elif name == "trim_suffix":
            self._builtin_trim_suffix(params, args)
        elif name == "abs":
            self._builtin_abs(params, args)
        elif name == "is_string":
            self._builtin_is_type(params, args, ValueSort.String)
        elif name == "is_boolean":
            self._builtin_is_type(params, args, ValueSort.Bool)
        elif name == "is_number":
            self._builtin_is_number(params, args)
        elif name in ("is_array", "is_set", "is_object", "is_null"):
            self._builtin_is_collection_type(params, name, args)
        elif name in ("bits.and", "bits.or", "bits.xor", "bits.lsh", "bits.rsh"):
            self._builtin_bitwise_binop(params, name, args)
        elif name == "bits.negate":
            self._builtin_bitwise_unop(params, args)
        elif name == "to_number":
            self._builtin_to_number(params, args)
        elif name == "cedar.like":
            self._builtin_cedar_like(params, args)
        elif name == "cedar.is":
            self._builtin_cedar_is(params, args)
        elif name == "cedar.in":
            self._builtin_cedar_in(params, args)
        elif name == "cedar.in_set":
            self._builtin_cedar_in_set(params, args)
        elif name == "cedar.has":
            self._builtin_cedar_has(params, args)
        elif name == "cedar.attr":
            self._builtin_cedar_attr(params, args)
        elif name.startswith("regex.") or name.startswith("io.jwt."):
            vn = f"builtin_{name.replace('.', '_')}_{self.pc}"
            self._set_reg_sym(params.dest, SymValue.from_z3_bool(z3.Bool(vn)),
                              Definedness.defined())
        elif name in ("sum", "product", "min", "max", "ceil", "floor", "round"):
            vn = f"builtin_{name}_{self.pc}"
            self._set_reg_sym(params.dest, SymValue.from_z3_int(z3.Int(vn)),
                              Definedness.defined())
        else:
            self.warnings.append(f"PC {self.pc}: Builtin '{name}' uninterpreted (String)")
            vn = f"builtin_{name.replace('.', '_')}_{self.pc}"
            self._set_reg_sym(params.dest, SymValue.from_z3_string(z3.String(vn)),
                              Definedness.defined())
        return InstructionAction.cont()

    # --- Builtin implementations ---

    def _builtin_count(self, params, args):
        if args:
            a = self._get_reg(args[0])
            if a.value.sym_set_cardinality is not None:
                self._set_reg_sym(params.dest,
                                  SymValue.from_z3_int(a.value.sym_set_cardinality),
                                  Definedness.defined())
                return
            if a.value.is_concrete:
                cv = a.value.concrete
                if isinstance(cv, (list, dict, set, str)):
                    self._set_reg_concrete(params.dest, len(cv))
                    return
            try:
                zs = a.value.to_z3_string()
                self._set_reg_sym(params.dest,
                                  SymValue.from_z3_int(z3.Length(zs)), Definedness.defined())
                return
            except (ValueError, TypeError):
                pass
            if a.source_path:
                sort = self.registry.get_sort(a.source_path)
                if sort == ValueSort.String:
                    zs = self.registry.get_string(a.source_path)
                    self._set_reg_sym(params.dest,
                                      SymValue.from_z3_int(z3.Length(zs)), Definedness.defined())
                    return
        vn = f"builtin_count_{self.pc}"
        v = z3.Int(vn)
        self.constraints.append(v >= 0)
        self._set_reg_sym(params.dest, SymValue.from_z3_int(v), Definedness.defined())

    def _builtin_string_bool(self, params, name, args):
        if len(args) >= 2:
            a0, a1 = self._get_reg(args[0]), self._get_reg(args[1])
            if (a0.value.is_concrete and isinstance(a0.value.concrete, str)
                    and a1.value.is_concrete and isinstance(a1.value.concrete, str)):
                s0, s1 = a0.value.concrete, a1.value.concrete
                if name == "startswith": r = s0.startswith(s1)
                elif name == "endswith": r = s0.endswith(s1)
                elif name == "contains": r = s1 in s0
                else: r = False
                self._set_reg_concrete(params.dest, r)
                return
            z0 = self._resolve_arg_as_z3_string(args[0])
            z1 = self._resolve_arg_as_z3_string(args[1])
            if z0 is not None and z1 is not None:
                if name == "startswith":
                    result = z3.PrefixOf(z1, z0)
                elif name == "endswith":
                    result = z3.SuffixOf(z1, z0)
                elif name == "contains":
                    result = z3.Contains(z0, z1)
                else:
                    result = z3.BoolVal(False)
                defined = Definedness.and_(a0.defined, a1.defined)
                self._set_reg_sym(params.dest, SymValue.from_z3_bool(result), defined)
                return
        vn = f"builtin_{name}_{self.pc}"
        self._set_reg_sym(params.dest, SymValue.from_z3_bool(z3.Bool(vn)), Definedness.defined())

    def _builtin_indexof(self, params, args):
        if len(args) >= 2:
            a0, a1 = self._get_reg(args[0]), self._get_reg(args[1])
            if (a0.value.is_concrete and isinstance(a0.value.concrete, str)
                    and a1.value.is_concrete and isinstance(a1.value.concrete, str)):
                idx = a0.value.concrete.find(a1.value.concrete)
                self._set_reg_concrete(params.dest, idx)
                return
            z0 = self._resolve_arg_as_z3_string(args[0])
            z1 = self._resolve_arg_as_z3_string(args[1])
            if z0 is not None and z1 is not None:
                result = z3.IndexOf(z0, z1, z3.IntVal(0))
                self._set_reg_sym(params.dest, SymValue.from_z3_int(result), Definedness.defined())
                return
        vn = f"builtin_indexof_{self.pc}"
        self._set_reg_sym(params.dest, SymValue.from_z3_int(z3.Int(vn)), Definedness.defined())

    def _builtin_replace(self, params, args):
        if len(args) >= 3:
            z0 = self._resolve_arg_as_z3_string(args[0])
            z1 = self._resolve_arg_as_z3_string(args[1])
            z2 = self._resolve_arg_as_z3_string(args[2])
            if z0 is not None and z1 is not None and z2 is not None:
                result = z3.Replace(z0, z1, z2)
                self._set_reg_sym(params.dest, SymValue.from_z3_string(result),
                                  Definedness.defined())
                return
        vn = f"builtin_replace_{self.pc}"
        self._set_reg_sym(params.dest, SymValue.from_z3_string(z3.String(vn)),
                          Definedness.defined())

    def _builtin_substring(self, params, args):
        if len(args) >= 3:
            z0 = self._resolve_arg_as_z3_string(args[0])
            z1 = self._resolve_arg_as_z3_int(args[1])
            z2 = self._resolve_arg_as_z3_int(args[2])
            if z0 is not None and z1 is not None and z2 is not None:
                eff_len = z3.If(z2 < 0, z3.Length(z0) - z1, z2)
                result = z3.SubString(z0, z1, eff_len)
                self._set_reg_sym(params.dest, SymValue.from_z3_string(result),
                                  Definedness.defined())
                return
        vn = f"builtin_substring_{self.pc}"
        self._set_reg_sym(params.dest, SymValue.from_z3_string(z3.String(vn)),
                          Definedness.defined())

    def _builtin_trim_prefix(self, params, args):
        if len(args) >= 2:
            z0 = self._resolve_arg_as_z3_string(args[0])
            z1 = self._resolve_arg_as_z3_string(args[1])
            if z0 is not None and z1 is not None:
                has_prefix = z3.PrefixOf(z1, z0)
                trimmed = z3.SubString(z0, z3.Length(z1), z3.Length(z0) - z3.Length(z1))
                result = z3.If(has_prefix, trimmed, z0)
                self._set_reg_sym(params.dest, SymValue.from_z3_string(result),
                                  Definedness.defined())
                return
        vn = f"builtin_trim_prefix_{self.pc}"
        self._set_reg_sym(params.dest, SymValue.from_z3_string(z3.String(vn)),
                          Definedness.defined())

    def _builtin_trim_suffix(self, params, args):
        if len(args) >= 2:
            z0 = self._resolve_arg_as_z3_string(args[0])
            z1 = self._resolve_arg_as_z3_string(args[1])
            if z0 is not None and z1 is not None:
                has_suffix = z3.SuffixOf(z1, z0)
                trimmed = z3.SubString(z0, z3.IntVal(0), z3.Length(z0) - z3.Length(z1))
                result = z3.If(has_suffix, trimmed, z0)
                self._set_reg_sym(params.dest, SymValue.from_z3_string(result),
                                  Definedness.defined())
                return
        vn = f"builtin_trim_suffix_{self.pc}"
        self._set_reg_sym(params.dest, SymValue.from_z3_string(z3.String(vn)),
                          Definedness.defined())

    def _builtin_abs(self, params, args):
        if args:
            a0 = self._get_reg(args[0])
            if a0.value.is_concrete and isinstance(a0.value.concrete, (int, float)):
                self._set_reg_concrete(params.dest, abs(a0.value.concrete))
                return
            zi = self._resolve_arg_as_z3_int(args[0])
            if zi is not None:
                result = z3.If(zi >= 0, zi, -zi)
                self._set_reg_sym(params.dest, SymValue.from_z3_int(result), Definedness.defined())
                return
        vn = f"builtin_abs_{self.pc}"
        v = z3.Int(vn)
        self.constraints.append(v >= 0)
        self._set_reg_sym(params.dest, SymValue.from_z3_int(v), Definedness.defined())

    def _builtin_is_type(self, params, args, expected_sort):
        if args:
            a = self._get_reg(args[0])
            ks = a.value.sort
            if ks != ValueSort.Unknown:
                self._set_reg_concrete(params.dest, ks == expected_sort)
                return
            if a.source_path:
                ps = self.registry.get_sort(a.source_path)
                if ps and ps != ValueSort.Unknown:
                    self._set_reg_concrete(params.dest, ps == expected_sort)
                    return
        vn = f"builtin_is_type_{self.pc}"
        self._set_reg_sym(params.dest, SymValue.from_z3_bool(z3.Bool(vn)), Definedness.defined())

    def _builtin_is_number(self, params, args):
        if args:
            a = self._get_reg(args[0])
            ks = a.value.sort
            if ks in (ValueSort.Int, ValueSort.Real):
                self._set_reg_concrete(params.dest, True)
                return
            if ks in (ValueSort.Bool, ValueSort.String):
                self._set_reg_concrete(params.dest, False)
                return
        vn = f"builtin_is_number_{self.pc}"
        self._set_reg_sym(params.dest, SymValue.from_z3_bool(z3.Bool(vn)), Definedness.defined())

    def _builtin_is_collection_type(self, params, name, args):
        if args:
            a = self._get_reg(args[0])
            if a.value.is_concrete:
                cv = a.value.concrete
                if name == "is_array": r = isinstance(cv, list)
                elif name == "is_set": r = isinstance(cv, set)
                elif name == "is_object": r = isinstance(cv, dict)
                elif name == "is_null": r = cv is None
                else: r = False
                self._set_reg_concrete(params.dest, r)
                return
            ks = a.value.sort
            if ks in (ValueSort.String, ValueSort.Bool, ValueSort.Int, ValueSort.Real):
                self._set_reg_concrete(params.dest, False)
                return
        vn = f"builtin_{name}_{self.pc}"
        self._set_reg_sym(params.dest, SymValue.from_z3_bool(z3.Bool(vn)), Definedness.defined())

    def _builtin_bitwise_binop(self, params, name, args):
        if len(args) >= 2:
            a0, a1 = self._get_reg(args[0]), self._get_reg(args[1])
            if (a0.value.is_concrete and isinstance(a0.value.concrete, int)
                    and a1.value.is_concrete and isinstance(a1.value.concrete, int)):
                i0, i1 = a0.value.concrete, a1.value.concrete
                if name == "bits.and": r = i0 & i1
                elif name == "bits.or": r = i0 | i1
                elif name == "bits.xor": r = i0 ^ i1
                elif name == "bits.lsh": r = i0 << (i1 & 63)
                elif name == "bits.rsh": r = i0 >> (i1 & 63)
                else: r = i0
                self._set_reg_concrete(params.dest, r)
                return
            z0 = self._resolve_arg_as_z3_int(args[0])
            z1 = self._resolve_arg_as_z3_int(args[1])
            if z0 is not None and z1 is not None:
                bv0 = z3.Int2BV(z0, 64)
                bv1 = z3.Int2BV(z1, 64)
                if name == "bits.and": bvr = bv0 & bv1
                elif name == "bits.or": bvr = bv0 | bv1
                elif name == "bits.xor": bvr = bv0 ^ bv1
                elif name == "bits.lsh": bvr = bv0 << bv1
                elif name == "bits.rsh": bvr = z3.LShR(bv0, bv1)
                else: bvr = bv0
                result = z3.BV2Int(bvr, is_signed=True)
                self._set_reg_sym(params.dest, SymValue.from_z3_int(result), Definedness.defined())
                return
        vn = f"builtin_{name.replace('.', '_')}_{self.pc}"
        self._set_reg_sym(params.dest, SymValue.from_z3_int(z3.Int(vn)), Definedness.defined())

    def _builtin_bitwise_unop(self, params, args):
        if args:
            a0 = self._get_reg(args[0])
            if a0.value.is_concrete and isinstance(a0.value.concrete, int):
                self._set_reg_concrete(params.dest, ~a0.value.concrete)
                return
            zi = self._resolve_arg_as_z3_int(args[0])
            if zi is not None:
                bv = z3.Int2BV(zi, 64)
                result = z3.BV2Int(~bv, is_signed=True)
                self._set_reg_sym(params.dest, SymValue.from_z3_int(result), Definedness.defined())
                return
        vn = f"builtin_bits_negate_{self.pc}"
        self._set_reg_sym(params.dest, SymValue.from_z3_int(z3.Int(vn)), Definedness.defined())

    def _builtin_to_number(self, params, args):
        if args:
            a0 = self._get_reg(args[0])
            a0_def = a0.defined
            cv = a0.value
            if cv.is_concrete:
                v = cv.concrete
                if isinstance(v, bool):
                    self._set_reg_concrete(params.dest, 1 if v else 0)
                    return
                if isinstance(v, (int, float)):
                    self._set_reg_concrete(params.dest, v)
                    return
                if isinstance(v, str):
                    try:
                        self._set_reg_concrete(params.dest, int(v))
                        return
                    except ValueError:
                        pass
            # Z3 Bool → ite(b, 1, 0)
            try:
                zb = cv.to_z3_bool()
                result = z3.If(zb, z3.IntVal(1), z3.IntVal(0))
                self._set_reg_sym(params.dest, SymValue.from_z3_int(result), a0_def)
                return
            except (ValueError, TypeError):
                pass
            try:
                zi = cv.to_z3_int()
                self._set_reg_sym(params.dest, SymValue.from_z3_int(zi), a0_def)
                return
            except (ValueError, TypeError):
                pass
        vn = f"builtin_to_number_{self.pc}"
        self._set_reg_sym(params.dest, SymValue.from_z3_int(z3.Int(vn)), Definedness.defined())

    # --- Cedar builtins ---

    def _builtin_cedar_like(self, params, args):
        if len(args) >= 2:
            a0, a1 = self._get_reg(args[0]), self._get_reg(args[1])
            a0_def = a0.defined
            if (a0.value.is_concrete and isinstance(a0.value.concrete, str)
                    and a1.value.is_concrete and isinstance(a1.value.concrete, str)):
                r = _cedar_wildcard_match(a0.value.concrete, a1.value.concrete)
                self._set_reg_concrete(params.dest, r)
                return
            if a1.value.is_concrete and isinstance(a1.value.concrete, str):
                z0 = self._resolve_arg_as_z3_string(args[0])
                if z0 is not None:
                    regex = _cedar_pattern_to_z3_re(a1.value.concrete)
                    result = z3.InRe(z0, regex)
                    self._set_reg_sym(params.dest, SymValue.from_z3_bool(result), a0_def)
                    return
        vn = f"builtin_cedar_like_{self.pc}"
        self._set_reg_sym(params.dest, SymValue.from_z3_bool(z3.Bool(vn)), Definedness.defined())

    def _builtin_cedar_is(self, params, args):
        if len(args) >= 2:
            a0, a1 = self._get_reg(args[0]), self._get_reg(args[1])
            a0_def = a0.defined
            if a1.value.is_concrete and isinstance(a1.value.concrete, str):
                type_name = a1.value.concrete
                if a0.value.is_concrete and isinstance(a0.value.concrete, str) and a0.source_path is None:
                    etype = a0.value.concrete.split("::")[0]
                    self._set_reg_concrete(params.dest, etype == type_name)
                    return
                z0 = self._resolve_arg_as_z3_string(args[0])
                if z0 is not None:
                    prefix = z3.StringVal(f"{type_name}::")
                    result = z3.PrefixOf(prefix, z0)
                    self._set_reg_sym(params.dest, SymValue.from_z3_bool(result), a0_def)
                    return
        vn = f"builtin_cedar_is_{self.pc}"
        self._set_reg_sym(params.dest, SymValue.from_z3_bool(z3.Bool(vn)), Definedness.defined())

    def _builtin_cedar_in(self, params, args):
        if len(args) >= 3:
            a0 = self._get_reg(args[0])
            a0_def = a0.defined
            a1 = self._get_reg(args[1])
            a2 = self._get_reg(args[2])
            entities = a2.value.concrete if a2.value.is_concrete and isinstance(a2.value.concrete, dict) else None
            target = a1.value.concrete if a1.value.is_concrete else None
            if entities is not None and target is not None:
                if a0.value.is_concrete and a0.source_path is None and a0.value.concrete is not None:
                    r = _concrete_cedar_in(a0.value.concrete, target, entities)
                    self._set_reg_concrete(params.dest, r)
                    return
                keys = _enumerate_cedar_in_keys(target, entities)
                z0 = self._resolve_arg_as_z3_string(args[0])
                if z0 is not None:
                    if not keys:
                        self._set_reg_concrete(params.dest, False)
                    else:
                        disjs = [z0 == z3.StringVal(k) for k in keys]
                        self._set_reg_sym(params.dest,
                                          SymValue.from_z3_bool(z3.Or(*disjs)), a0_def)
                    return
        vn = f"builtin_cedar_in_{self.pc}"
        self._set_reg_sym(params.dest, SymValue.from_z3_bool(z3.Bool(vn)), Definedness.defined())

    def _builtin_cedar_in_set(self, params, args):
        if len(args) >= 3:
            a0 = self._get_reg(args[0])
            a0_def = a0.defined
            a1 = self._get_reg(args[1])
            a2 = self._get_reg(args[2])
            entities = a2.value.concrete if a2.value.is_concrete and isinstance(a2.value.concrete, dict) else None
            targets = a1.value.concrete if a1.value.is_concrete and isinstance(a1.value.concrete, list) else None
            if entities is not None and targets is not None:
                if a0.value.is_concrete and a0.source_path is None:
                    r = any(_concrete_cedar_in(a0.value.concrete, t, entities) for t in targets)
                    self._set_reg_concrete(params.dest, r)
                    return
                all_keys = set()
                for t in targets:
                    all_keys.update(_enumerate_cedar_in_keys(t, entities))
                z0 = self._resolve_arg_as_z3_string(args[0])
                if z0 is not None:
                    if not all_keys:
                        self._set_reg_concrete(params.dest, False)
                    else:
                        disjs = [z0 == z3.StringVal(k) for k in all_keys]
                        self._set_reg_sym(params.dest,
                                          SymValue.from_z3_bool(z3.Or(*disjs)), a0_def)
                    return
        vn = f"builtin_cedar_in_set_{self.pc}"
        self._set_reg_sym(params.dest, SymValue.from_z3_bool(z3.Bool(vn)), Definedness.defined())

    def _builtin_cedar_has(self, params, args):
        if len(args) >= 3:
            a0 = self._get_reg(args[0])
            a0_def = a0.defined
            a1 = self._get_reg(args[1])
            a2 = self._get_reg(args[2])
            entities = a2.value.concrete if a2.value.is_concrete and isinstance(a2.value.concrete, dict) else None
            attr = a1.value.concrete if a1.value.is_concrete and isinstance(a1.value.concrete, str) else None
            if entities is not None and attr is not None:
                if a0.value.is_concrete and a0.source_path is None:
                    r = _concrete_cedar_has(a0.value.concrete, attr, entities)
                    self._set_reg_concrete(params.dest, r)
                    return
                keys = _enumerate_cedar_has_keys(attr, entities)
                z0 = self._resolve_arg_as_z3_string(args[0])
                if z0 is not None:
                    if not keys:
                        self._set_reg_concrete(params.dest, False)
                    else:
                        disjs = [z0 == z3.StringVal(k) for k in keys]
                        self._set_reg_sym(params.dest,
                                          SymValue.from_z3_bool(z3.Or(*disjs)), a0_def)
                    return
        vn = f"builtin_cedar_has_{self.pc}"
        self._set_reg_sym(params.dest, SymValue.from_z3_bool(z3.Bool(vn)), Definedness.defined())

    def _builtin_cedar_attr(self, params, args):
        if len(args) >= 3:
            a0 = self._get_reg(args[0])
            a0_def = a0.defined
            a1 = self._get_reg(args[1])
            a2 = self._get_reg(args[2])
            entities = a2.value.concrete if a2.value.is_concrete and isinstance(a2.value.concrete, dict) else None
            attr = a1.value.concrete if a1.value.is_concrete and isinstance(a1.value.concrete, str) else None
            if entities is not None and attr is not None:
                if a0.value.is_concrete and a0.source_path is None:
                    r = _concrete_cedar_attr(a0.value.concrete, attr, entities)
                    self._set_reg_concrete(params.dest, r)
                    return
                attr_map = _enumerate_cedar_attr_values(attr, entities)
                if attr_map:
                    z0 = self._resolve_arg_as_z3_string(args[0])
                    if z0 is not None:
                        first_val = attr_map[0][1]
                        if isinstance(first_val, str):
                            result = z3.StringVal("")
                            for key, val in reversed(attr_map):
                                cond = z0 == z3.StringVal(key)
                                vs = z3.StringVal(str(val))
                                result = z3.If(cond, vs, result)
                            self._set_reg_sym(params.dest, SymValue.from_z3_string(result),
                                              a0_def)
                            return
                        if len(attr_map) == 1:
                            self._set_reg_concrete(params.dest, attr_map[0][1])
                            return
                if a0.source_path:
                    sub_path = f"{a0.source_path}.{attr}"
                    return self._create_path_register(params.dest, sub_path)
        vn = f"builtin_cedar_attr_{self.pc}"
        self._set_reg_sym(params.dest, SymValue.from_z3_string(z3.String(vn)),
                          Definedness.defined())


# ============================================================================
# Cedar helper functions (free functions)
# ============================================================================

def _cedar_pattern_to_z3_re(pattern: str):
    """Convert a Cedar ``like`` wildcard pattern to a z3 regex."""
    segments = pattern.split("*")
    if len(segments) == 1:
        return z3.Re(z3.StringVal(pattern))
    parts = []
    for i, seg in enumerate(segments):
        if seg:
            parts.append(z3.Re(z3.StringVal(seg)))
        if i < len(segments) - 1:
            parts.append(z3.Full(z3.ReSort(z3.StringSort())))
    if len(parts) == 1:
        return parts[0]
    return z3.Concat(*parts)


def _cedar_wildcard_match(inp: str, pattern: str) -> bool:
    i = p = 0
    star_idx = None
    match_idx = 0
    while i < len(inp):
        if p < len(pattern) and (pattern[p] == "?" or pattern[p] == inp[i]):
            i += 1
            p += 1
        elif p < len(pattern) and pattern[p] == "*":
            star_idx = p
            match_idx = i
            p += 1
        elif star_idx is not None:
            p = star_idx + 1
            match_idx += 1
            i = match_idx
        else:
            return False
    while p < len(pattern) and pattern[p] == "*":
        p += 1
    return p == len(pattern)


def _concrete_entity_key(v) -> str:
    if isinstance(v, str):
        return v
    if isinstance(v, dict):
        t = v.get("type", "")
        eid = v.get("id", "")
        if t or eid:
            return f"{t}::{eid}"
    return str(v)


def _concrete_cedar_in(entity, target, entities: dict) -> bool:
    ek = _concrete_entity_key(entity)
    tk = _concrete_entity_key(target)
    if ek == tk:
        return True
    queue = deque([ek])
    visited = {ek}
    while queue:
        current = queue.popleft()
        if current == tk:
            return True
        node = entities.get(current)
        if not isinstance(node, dict):
            continue
        parents = node.get("parents", [])
        if not isinstance(parents, list):
            continue
        for parent in parents:
            pk = _concrete_entity_key(parent)
            if pk not in visited:
                visited.add(pk)
                queue.append(pk)
    return False


def _concrete_cedar_has(entity, attr: str, entities: dict) -> bool:
    if isinstance(entity, dict):
        return attr in entity
    ek = _concrete_entity_key(entity)
    rec = entities.get(ek)
    if not isinstance(rec, dict):
        return False
    if attr in rec:
        return True
    attrs = rec.get("attrs", {})
    return isinstance(attrs, dict) and attr in attrs


def _concrete_cedar_attr(entity, attr: str, entities: dict):
    if isinstance(entity, dict):
        if attr in entity:
            return entity[attr]
        attrs = entity.get("attrs", {})
        if isinstance(attrs, dict) and attr in attrs:
            return attrs[attr]
        return None
    ek = _concrete_entity_key(entity)
    rec = entities.get(ek)
    if not isinstance(rec, dict):
        return None
    if attr in rec:
        return rec[attr]
    attrs = rec.get("attrs", {})
    if isinstance(attrs, dict) and attr in attrs:
        return attrs[attr]
    return None


def _enumerate_cedar_in_keys(target, entities: dict) -> list[str]:
    tk = _concrete_entity_key(target)
    result = []
    if isinstance(tk, str):
        result.append(tk)
    for ek in entities:
        if isinstance(ek, str) and ek != tk:
            if _concrete_cedar_in(ek, tk, entities):
                result.append(ek)
    return result


def _enumerate_cedar_has_keys(attr: str, entities: dict) -> list[str]:
    return [k for k in entities if isinstance(k, str) and _concrete_cedar_has(k, attr, entities)]


def _enumerate_cedar_attr_values(attr: str, entities: dict) -> list[tuple[str, Any]]:
    result = []
    for k in entities:
        if isinstance(k, str):
            v = _concrete_cedar_attr(k, attr, entities)
            if v is not None:
                result.append((k, v))
    return result
