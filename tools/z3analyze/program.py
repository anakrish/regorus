# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""RVM bytecode program loader — reads the JSON produced by `regorus compile`."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class LoopMode(Enum):
    Any = auto()
    Every = auto()
    ForEach = auto()


class ComprehensionMode(Enum):
    Set = auto()
    Array = auto()
    Object = auto()


class RuleType(Enum):
    Complete = auto()
    PartialSet = auto()
    PartialObject = auto()


class BuiltinKind(Enum):
    Standard = auto()
    Contexted = auto()


# ---------------------------------------------------------------------------
# Instruction parameter structs
# ---------------------------------------------------------------------------

@dataclass
class LoopStartParams:
    mode: LoopMode
    collection: int
    key_reg: int
    value_reg: int
    result_reg: int
    body_start: int
    loop_end: int


@dataclass
class BuiltinCallParams:
    dest: int
    builtin_index: int
    num_args: int
    args: list[int]


@dataclass
class FunctionCallParams:
    dest: int
    func_rule_index: int
    num_args: int
    args: list[int]


@dataclass
class ObjectCreateParams:
    dest: int
    template_literal_idx: int
    literal_key_fields: list[tuple[int, int]]  # (literal_key_idx, value_reg)
    fields: list[tuple[int, int]]  # (key_reg, value_reg)


@dataclass
class ArrayCreateParams:
    dest: int
    elements: list[int]


@dataclass
class SetCreateParams:
    dest: int
    elements: list[int]


@dataclass
class ChainedIndexParams:
    dest: int
    root: int
    path_components: list  # each is {"Literal": idx} or {"Register": reg}


@dataclass
class ComprehensionBeginParams:
    mode: ComprehensionMode
    collection_reg: int
    result_reg: int
    key_reg: int
    value_reg: int
    body_start: int
    comprehension_end: int


@dataclass
class VirtualDataDocumentLookupParams:
    dest: int
    path_components: list  # each is {"Literal": idx} or {"Register": reg}


# ---------------------------------------------------------------------------
# Instruction data (side tables)
# ---------------------------------------------------------------------------

@dataclass
class InstructionData:
    loop_params: list[LoopStartParams] = field(default_factory=list)
    builtin_call_params: list[BuiltinCallParams] = field(default_factory=list)
    function_call_params: list[FunctionCallParams] = field(default_factory=list)
    object_create_params: list[ObjectCreateParams] = field(default_factory=list)
    array_create_params: list[ArrayCreateParams] = field(default_factory=list)
    set_create_params: list[SetCreateParams] = field(default_factory=list)
    chained_index_params: list[ChainedIndexParams] = field(default_factory=list)
    comprehension_begin_params: list[ComprehensionBeginParams] = field(default_factory=list)
    virtual_data_document_lookup_params: list[VirtualDataDocumentLookupParams] = field(
        default_factory=list
    )


# ---------------------------------------------------------------------------
# Instruction
# ---------------------------------------------------------------------------

@dataclass
class Instruction:
    """A single RVM instruction, decoded from the tagged JSON representation."""
    opcode: str
    fields: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Source / span info
# ---------------------------------------------------------------------------

@dataclass
class SourceFile:
    name: str
    content: str


@dataclass
class SpanInfo:
    source_index: int
    line: int
    column: int
    length: int


# ---------------------------------------------------------------------------
# Rule info
# ---------------------------------------------------------------------------

@dataclass
class FunctionInfo:
    param_names: list[str]
    num_params: int


@dataclass
class RuleInfo:
    name: str
    rule_type: RuleType
    definitions: list[list[int]]  # list of PC lists per definition body
    function_info: Optional[FunctionInfo]
    default_literal_index: Optional[int]
    result_reg: int
    num_registers: int
    destructuring_blocks: list[Optional[int]]


# ---------------------------------------------------------------------------
# Builtin info
# ---------------------------------------------------------------------------

@dataclass
class BuiltinInfo:
    name: str
    num_args: int
    kind: BuiltinKind


# ---------------------------------------------------------------------------
# Program
# ---------------------------------------------------------------------------

@dataclass
class Program:
    instructions: list[Instruction]
    instruction_data: InstructionData
    literals: list  # raw JSON values
    builtin_info_table: list[BuiltinInfo]
    entry_points: dict[str, int]  # name → PC
    sources: list[SourceFile]
    rule_infos: list[RuleInfo]
    instruction_spans: list[Optional[SpanInfo]]
    rule_tree: Any  # hierarchical rule lookup dict
    main_entry_point: int
    max_rule_window_size: int
    dispatch_window_size: int


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------

def _parse_loop_mode(s: str) -> LoopMode:
    return LoopMode[s]


def _parse_comp_mode(s: str) -> ComprehensionMode:
    return ComprehensionMode[s]


def _parse_rule_type(s: str) -> RuleType:
    return RuleType[s]


def _parse_instruction(raw: dict) -> Instruction:
    """Parse one tagged-enum JSON instruction like {"Load": {"dest": 0, "literal_idx": 3}}."""
    if isinstance(raw, str):
        # Nullary instructions like "Halt", "RuleReturn", "DestructuringSuccess"
        return Instruction(opcode=raw)
    assert isinstance(raw, dict) and len(raw) == 1, f"bad instruction: {raw}"
    opcode = next(iter(raw))
    fields = raw[opcode]
    if fields is None:
        fields = {}
    if isinstance(fields, dict):
        return Instruction(opcode=opcode, fields=fields)
    # Some opcodes have a single non-dict field
    return Instruction(opcode=opcode, fields={"value": fields})


def _parse_loop_params(raw: dict) -> LoopStartParams:
    return LoopStartParams(
        mode=_parse_loop_mode(raw["mode"]),
        collection=raw["collection"],
        key_reg=raw["key_reg"],
        value_reg=raw["value_reg"],
        result_reg=raw["result_reg"],
        body_start=raw["body_start"],
        loop_end=raw["loop_end"],
    )


def _parse_builtin_call_params(raw: dict) -> BuiltinCallParams:
    return BuiltinCallParams(
        dest=raw["dest"],
        builtin_index=raw["builtin_index"],
        num_args=raw["num_args"],
        args=raw["args"],
    )


def _parse_function_call_params(raw: dict) -> FunctionCallParams:
    return FunctionCallParams(
        dest=raw["dest"],
        func_rule_index=raw["func_rule_index"],
        num_args=raw["num_args"],
        args=raw["args"],
    )


def _parse_object_create_params(raw: dict) -> ObjectCreateParams:
    return ObjectCreateParams(
        dest=raw["dest"],
        template_literal_idx=raw.get("template_literal_idx", 0),
        literal_key_fields=[(f[0], f[1]) for f in raw.get("literal_key_fields", [])],
        fields=[(f[0], f[1]) for f in raw.get("fields", [])],
    )


def _parse_array_create_params(raw: dict) -> ArrayCreateParams:
    return ArrayCreateParams(dest=raw["dest"], elements=raw.get("elements", []))


def _parse_set_create_params(raw: dict) -> SetCreateParams:
    return SetCreateParams(dest=raw["dest"], elements=raw.get("elements", []))


def _parse_chained_index_params(raw: dict) -> ChainedIndexParams:
    return ChainedIndexParams(
        dest=raw["dest"],
        root=raw["root"],
        path_components=raw.get("path_components", []),
    )


def _parse_comprehension_begin_params(raw: dict) -> ComprehensionBeginParams:
    return ComprehensionBeginParams(
        mode=_parse_comp_mode(raw["mode"]),
        collection_reg=raw["collection_reg"],
        result_reg=raw["result_reg"],
        key_reg=raw["key_reg"],
        value_reg=raw["value_reg"],
        body_start=raw["body_start"],
        comprehension_end=raw["comprehension_end"],
    )


def _parse_vddl_params(raw: dict) -> VirtualDataDocumentLookupParams:
    return VirtualDataDocumentLookupParams(
        dest=raw["dest"],
        path_components=raw.get("path_components", []),
    )


def _parse_instruction_data(raw: dict) -> InstructionData:
    return InstructionData(
        loop_params=[_parse_loop_params(p) for p in raw.get("loop_params", [])],
        builtin_call_params=[
            _parse_builtin_call_params(p) for p in raw.get("builtin_call_params", [])
        ],
        function_call_params=[
            _parse_function_call_params(p) for p in raw.get("function_call_params", [])
        ],
        object_create_params=[
            _parse_object_create_params(p) for p in raw.get("object_create_params", [])
        ],
        array_create_params=[
            _parse_array_create_params(p) for p in raw.get("array_create_params", [])
        ],
        set_create_params=[
            _parse_set_create_params(p) for p in raw.get("set_create_params", [])
        ],
        chained_index_params=[
            _parse_chained_index_params(p) for p in raw.get("chained_index_params", [])
        ],
        comprehension_begin_params=[
            _parse_comprehension_begin_params(p)
            for p in raw.get("comprehension_begin_params", [])
        ],
        virtual_data_document_lookup_params=[
            _parse_vddl_params(p)
            for p in raw.get("virtual_data_document_lookup_params", [])
        ],
    )


def _parse_span(raw: Optional[dict]) -> Optional[SpanInfo]:
    if raw is None:
        return None
    return SpanInfo(
        source_index=raw["source_index"],
        line=raw["line"],
        column=raw["column"],
        length=raw["length"],
    )


def _parse_rule_info(raw: dict) -> RuleInfo:
    fi = raw.get("function_info")
    return RuleInfo(
        name=raw["name"],
        rule_type=_parse_rule_type(raw["rule_type"]),
        definitions=raw["definitions"],
        function_info=(
            FunctionInfo(fi["param_names"], fi["num_params"]) if fi else None
        ),
        default_literal_index=raw.get("default_literal_index"),
        result_reg=raw["result_reg"],
        num_registers=raw["num_registers"],
        destructuring_blocks=raw.get("destructuring_blocks", []),
    )


def _parse_builtin_info(raw: dict) -> BuiltinInfo:
    return BuiltinInfo(
        name=raw["name"],
        num_args=raw["num_args"],
        kind=BuiltinKind[raw.get("kind", "Standard")],
    )


def load_program(path: str) -> Program:
    """Load an RVM program from a JSON file produced by `regorus compile -o`."""
    with open(path) as f:
        data = json.load(f)

    ps = data.get("program_structure", {})

    return Program(
        instructions=[_parse_instruction(i) for i in data["instructions"]],
        instruction_data=_parse_instruction_data(data.get("instruction_data", {})),
        literals=data.get("literals", []),
        builtin_info_table=[_parse_builtin_info(b) for b in data.get("builtin_info_table", [])],
        entry_points=data.get("entry_points", {}),
        sources=[
            SourceFile(s["name"], s.get("content", "")) for s in data.get("sources", [])
        ],
        rule_infos=[_parse_rule_info(r) for r in data.get("rule_infos", [])],
        instruction_spans=[_parse_span(s) for s in data.get("instruction_spans", [])],
        rule_tree=data.get("rule_tree"),
        main_entry_point=ps.get("main_entry_point", 0),
        max_rule_window_size=ps.get("max_rule_window_size", 16),
        dispatch_window_size=ps.get("dispatch_window_size", 4),
    )
