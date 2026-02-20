# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""CLI entry point: ``python -m z3analyze <program.json> [options]``

Port of the Rust ``analyze`` sub-command.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from typing import Any, Optional

import z3

from .model_extract import extract_input
from .path_registry import PathRegistry
from .program import load_program, Program
from .schema import apply_schema_constraints
from .translator import AnalysisConfig, Translator
from .types import SymValue, ValueSort


# ---------------------------------------------------------------------------
# Result
# ---------------------------------------------------------------------------

@dataclass
class AnalysisResult:
    satisfiable: bool
    input: Optional[dict] = None
    warnings: list[str] = field(default_factory=list)
    solver_smt: Optional[str] = None
    model_string: Optional[str] = None


# ---------------------------------------------------------------------------
# Core analysis routines
# ---------------------------------------------------------------------------

def generate_input(
    program: Program,
    data: Any,
    desired_output: Any,
    entry_point: str,
    config: AnalysisConfig,
) -> AnalysisResult:
    """Find an input that makes *entry_point* produce *desired_output*."""
    solver = z3.Solver()
    if config.timeout_ms > 0:
        solver.set("timeout", config.timeout_ms)

    registry = PathRegistry()

    if config.example_input is not None:
        registry.seed_sorts_from_value("input", config.example_input,
                                       config.max_loop_depth)

    schema_constraints = []
    if config.input_schema is not None:
        schema_constraints = apply_schema_constraints(
            config.input_schema, registry, "input")

    translator = Translator(program, data, registry, config)

    entry_pc = program.entry_points.get(entry_point)
    if entry_pc is None:
        raise ValueError(f"Entry point '{entry_point}' not found")

    result = translator.translate_entry_point(entry_pc)
    constraints = translator.constraints
    path_condition = translator.path_condition
    warnings = translator.warnings

    for c in constraints:
        solver.add(c)
    for c in schema_constraints:
        solver.add(c)
    solver.add(path_condition)

    output_constraint = _output_constraint(result, desired_output)
    solver.add(output_constraint)

    return _solve(solver, registry, warnings, config)


def generate_input_for_goal(
    program: Program,
    data: Any,
    entry_point: str,
    expected_output: Any = None,
    cover_lines: list[tuple[str, int]] = None,
    avoid_lines: list[tuple[str, int]] = None,
    config: AnalysisConfig = None,
) -> AnalysisResult:
    """Most flexible entry point: subsumes generate_input + line coverage."""
    if config is None:
        config = AnalysisConfig()

    solver = z3.Solver()
    if config.timeout_ms > 0:
        solver.set("timeout", config.timeout_ms)

    registry = PathRegistry()

    if config.example_input is not None:
        registry.seed_sorts_from_value("input", config.example_input,
                                       config.max_loop_depth)

    schema_constraints = []
    if config.input_schema is not None:
        schema_constraints = apply_schema_constraints(
            config.input_schema, registry, "input")

    translator = Translator(program, data, registry, config)

    entry_pc = program.entry_points.get(entry_point)
    if entry_pc is None:
        raise ValueError(f"Entry point '{entry_point}' not found")

    result = translator.translate_entry_point(entry_pc)
    constraints = translator.constraints
    path_condition = translator.path_condition
    pc_path_conditions = translator.pc_path_conditions
    warnings = list(translator.warnings)

    for c in constraints:
        solver.add(c)
    for c in schema_constraints:
        solver.add(c)
    solver.add(path_condition)

    if expected_output is not None:
        solver.add(_output_constraint(result, expected_output))
    else:
        # Require the result to be defined
        defc = result.defined_z3()
        if defc is not None:
            solver.add(defc)

    # Line coverage
    if cover_lines:
        for lc in _lines_to_constraints(program, cover_lines, pc_path_conditions, warnings):
            solver.add(lc)
    if avoid_lines:
        for lc in _lines_to_constraints(program, avoid_lines, pc_path_conditions, warnings):
            solver.add(z3.Not(lc))

    return _solve(solver, registry, warnings, config)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _output_constraint(result: SymValue, desired) -> z3.BoolRef:
    return result.equals_value(desired)


def _solve(solver, registry, warnings, config) -> AnalysisResult:
    solver_smt = str(solver) if config.dump_smt else None

    check = solver.check()
    if check == z3.sat:
        model = solver.model()
        model_string = str(model) if config.dump_model else None
        inp = extract_input(model, registry)
        return AnalysisResult(
            satisfiable=True, input=inp, warnings=warnings,
            solver_smt=solver_smt, model_string=model_string)
    if check == z3.unsat:
        return AnalysisResult(
            satisfiable=False, warnings=warnings, solver_smt=solver_smt)
    # Unknown
    reason = solver.reason_unknown()
    warnings.append(f"Z3 returned Unknown: {reason}")
    return AnalysisResult(satisfiable=False, warnings=warnings, solver_smt=solver_smt)


def _lines_to_constraints(
    program: Program,
    lines: list[tuple[str, int]],
    pc_path_conditions: dict[int, z3.BoolRef],
    warnings: list[str],
) -> list[z3.BoolRef]:
    constraints = []
    for file, line in lines:
        source_idx = None
        for i, src in enumerate(program.sources):
            if src.name == file or src.name.endswith(file) or file.endswith(src.name):
                source_idx = i
                break
        if source_idx is None:
            warnings.append(f"CoverLines: source file '{file}' not found")
            continue
        last_cond = None
        for pc, span in enumerate(program.instruction_spans):
            if span is not None and span.source_index == source_idx and span.line == line:
                if pc in pc_path_conditions:
                    last_cond = pc_path_conditions[pc]
        if last_cond is not None:
            constraints.append(last_cond)
        else:
            warnings.append(f"CoverLines: no instructions for {file}:{line}")
    return constraints


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        prog="z3analyze",
        description="Symbolic analysis of RVM bytecode via Z3 (Python port)")
    parser.add_argument("program", help="Path to JSON program from `regorus compile -o`")
    parser.add_argument("-e", "--entrypoint", required=True,
                        help="Entry point name, e.g. 'data.policy.allow'")
    parser.add_argument("-o", "--output", default="true",
                        help="Desired output value (JSON, default: true)")
    parser.add_argument("-d", "--data", default=None,
                        help="Path to data JSON file")
    parser.add_argument("--example-input", default=None,
                        help="Path to example input JSON (seeds sort info)")
    parser.add_argument("--schema", default=None,
                        help="Path to JSON Schema for input")
    parser.add_argument("--concrete-input", nargs=2, action="append", default=[],
                        metavar=("KEY", "FILE"),
                        help="Concrete input: --concrete-input entities entities.json")
    parser.add_argument("--cover-line", nargs=2, action="append", default=[],
                        metavar=("FILE", "LINE"),
                        help="Force coverage of a source line")
    parser.add_argument("--avoid-line", nargs=2, action="append", default=[],
                        metavar=("FILE", "LINE"),
                        help="Avoid a source line")
    parser.add_argument("--max-loop-depth", type=int, default=5)
    parser.add_argument("--max-rule-depth", type=int, default=3)
    parser.add_argument("--timeout", type=int, default=30000,
                        help="Z3 timeout in ms (default: 30000)")
    parser.add_argument("--dump-smt", action="store_true",
                        help="Print SMT-LIB2 assertions")
    parser.add_argument("--dump-model", action="store_true",
                        help="Print Z3 model when SAT")
    parser.add_argument("--sat-check", action="store_true",
                        help="Just check satisfiability (no desired output)")

    args = parser.parse_args()

    # Load program
    program = load_program(args.program)

    # Load data
    data = {}
    if args.data:
        with open(args.data) as f:
            data = json.load(f)

    # Config
    config = AnalysisConfig(
        max_loop_depth=args.max_loop_depth,
        max_rule_depth=args.max_rule_depth,
        timeout_ms=args.timeout,
        dump_smt=args.dump_smt,
        dump_model=args.dump_model,
    )

    if args.example_input:
        with open(args.example_input) as f:
            config.example_input = json.load(f)

    if args.schema:
        with open(args.schema) as f:
            config.input_schema = json.load(f)

    for key, filepath in args.concrete_input:
        with open(filepath) as f:
            config.concrete_input[key] = json.load(f)

    # Parse cover/avoid lines
    cover_lines = [(f, int(l)) for f, l in args.cover_line]
    avoid_lines = [(f, int(l)) for f, l in args.avoid_line]

    # Parse desired output
    desired_output = json.loads(args.output) if not args.sat_check else None

    # Run analysis
    if cover_lines or avoid_lines or args.sat_check:
        result = generate_input_for_goal(
            program, data, args.entrypoint,
            expected_output=desired_output,
            cover_lines=cover_lines or None,
            avoid_lines=avoid_lines or None,
            config=config,
        )
    else:
        result = generate_input(
            program, data, desired_output, args.entrypoint, config)

    # Output
    if result.warnings:
        for w in result.warnings:
            print(f"WARNING: {w}", file=sys.stderr)

    if result.solver_smt:
        print("=== SMT-LIB2 ===")
        print(result.solver_smt)

    if result.model_string:
        print("=== Z3 Model ===")
        print(result.model_string)

    if result.satisfiable:
        print("Result: SAT")
        print(json.dumps(result.input, indent=2))
    else:
        print("Result: UNSAT")


if __name__ == "__main__":
    main()
