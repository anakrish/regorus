#!/usr/bin/env python3
"""Rewrite src/rvm/analysis/mod.rs: Z3 -> SmtExpr/SmtProblem."""

import re

FILE = "src/rvm/analysis/mod.rs"

with open(FILE, "r") as f:
    code = f.read()

original = code

# ── Phase 1: Imports and exports ──────────────────────────────────────
# Update model_extract export
code = code.replace(
    "pub use model_extract::extract_input;",
    "pub use model_extract::{extract_input, register_extractions, PathExtraction};",
)

# Add regorus_smt imports after the existing use statements
code = code.replace(
    "use crate::rvm::program::Program;\nuse crate::value::Value;",
    "use crate::rvm::program::Program;\nuse crate::value::Value;\n\nuse regorus_smt::expr::SmtExpr;\nuse regorus_smt::problem::{SmtCheckResult, SmtProblem, SmtStatus};",
)

# ── Phase 2: Remove z3::Config / z3::Context / z3::Solver creation ───
# Pattern: let z3_cfg = z3::Config::new();\n    let ctx = z3::Context::new(&z3_cfg);\n    let solver = z3::Solver::new(&ctx);
code = re.sub(
    r'    let z3_cfg = z3::Config::new\(\);\n'
    r'    let ctx = z3::Context::new\(&z3_cfg\);\n'
    r'    let solver = z3::Solver::new\(&ctx\);\n',
    '',
    code,
)

# Remove timeout setup blocks
code = re.sub(
    r'    if config\.timeout_ms > 0 \{\n'
    r'        let mut params = z3::Params::new\(&ctx\);\n'
    r'        params\.set_u32\("timeout", config\.timeout_ms\);\n'
    r'        solver\.set_params\(&params\);\n'
    r'    \}\n',
    '',
    code,
)

# ── Phase 3: PathRegistry::new(&ctx) → PathRegistry::new() ───────────
code = code.replace("PathRegistry::new(&ctx)", "PathRegistry::new()")

# ── Phase 4: Translator::new(&ctx, ...) → Translator::new(...) ───────
code = code.replace("Translator::new(&ctx, ", "Translator::new(")

# ── Phase 5: apply_schema_constraints(&ctx, ...) → apply_schema_constraints(...)
code = code.replace("apply_schema_constraints(&ctx, ", "apply_schema_constraints(")

# ── Phase 6: result.equals_value(&ctx, ...) → result.equals_value(...)
code = re.sub(r'\.equals_value\(&ctx,\s*', '.equals_value(', code)

# ── Phase 7: result.is_defined(&ctx) → result.is_defined() ───────────
code = code.replace(".is_defined(&ctx)", ".is_defined()")

# ── Phase 8: result.is_non_default(&ctx) → result.is_non_default() ──
code = code.replace(".is_non_default(&ctx)", ".is_non_default()")

# ── Phase 9: Remove solver.assert calls (to be replaced manually) ────
# We'll mark these for manual replacement later
# Actually let's convert them to SmtExpr vec building

# ── Phase 10: lines_to_constraints - remove lifetime and z3 types ────
code = code.replace(
    "fn lines_to_constraints<'ctx>(",
    "fn lines_to_constraints(",
)
code = code.replace(
    "pc_path_conditions: &std::collections::HashMap<usize, z3::ast::Bool<'ctx>>,",
    "pc_path_conditions: &std::collections::HashMap<usize, SmtExpr>,",
)
code = code.replace(
    "_ctx: &'ctx z3::Context,",
    "",
)
code = code.replace(
    ") -> Vec<z3::ast::Bool<'ctx>> {",
    ") -> Vec<SmtExpr> {",
)
code = code.replace(
    "use z3::ast::Bool as Z3Bool;\n",
    "",
)
code = code.replace(
    "let mut last_pc_cond: Option<&Z3Bool<'ctx>> = None;",
    "let mut last_pc_cond: Option<&SmtExpr> = None;",
)
# Fix the double comma from removing _ctx parameter (", ," -> ",")
code = re.sub(r',\s*\n\s*\n\s*warnings', ',\n        warnings', code)

# ── Phase 11: ConditionRecord lifetime ──────────────────────────────
code = code.replace(
    "Vec<&translator::ConditionRecord<'_>>",
    "Vec<&translator::ConditionRecord>",
)

# ── Phase 12: z3::ast::Bool::and / or / xor / not ───────────────────
# z3::ast::Bool::and(&ctx, &[&path_cond1, &r1_result_matches])
code = re.sub(
    r'z3::ast::Bool::and\(&ctx,\s*&\[&(\w+),\s*&(\w+)\]\)',
    r'SmtExpr::and2(\1.clone(), \2.clone())',
    code,
)
# z3::ast::Bool::xor
code = re.sub(
    r'z3::ast::Bool::xor\(&(\w+),\s*&(\w+)\)',
    r'SmtExpr::xor(\1, \2)',
    code,
)

# ── Phase 13: solver.assert / solver.check patterns ─────────────────
# These are too varied to handle with simple regex; we'll handle them
# in the manual pass below. For now, mark them.

# ── Phase 14: model.eval patterns ────────────────────────────────────
# model.eval(&thing, true) → SmtExpr-based extraction
# These need manual rewrite.

# ── Phase 15: Remove z3 mentions from doc comments ──────────────────
code = code.replace("Z3 SMT constraints", "SMT constraints")
code = code.replace("Z3 constraints", "SMT constraints")
code = code.replace("RVM-to-Z3 symbolic analysis engine", "RVM symbolic analysis engine")
code = code.replace(
    "Translates compiled RVM bytecode into Z3 SMT constraints",
    "Translates compiled RVM bytecode into SMT constraints",
)
code = code.replace("Z3 solver timeout", "SMT solver timeout")
code = code.replace("Z3 found the constraints", "the solver found the constraints")
code = code.replace(
    "Z3 sort instead of staying",
    "SMT sort instead of staying",
)
code = code.replace(
    "so\n/// Z3 reasons symboli",
    "so\n/// the solver reasons symboli",
)
code = code.replace(
    "Z3 constraints\n/// are generated",
    "SMT constraints\n/// are generated",
)
code = code.replace("Z3 model (variable", "SMT model (variable")
code = code.replace("the Z3 model", "the SMT model")

# ── Phase 16: line_conditions map type ───────────────────────────────
code = code.replace(
    "std::collections::BTreeMap<(String, usize), z3::ast::Bool<'_>>",
    "std::collections::BTreeMap<(String, usize), SmtExpr>",
)

# ── Phase 17: z3::SatResult → SmtStatus (will need manual fixup) ────
# Mark but don't fully replace since the control flow changes significantly


with open(FILE, "w") as f:
    f.write(code)

# Verify no z3:: references remain (excluding comments)
remaining = []
for i, line in enumerate(code.split('\n'), 1):
    stripped = line.lstrip()
    if stripped.startswith("//") or stripped.startswith("///") or stripped.startswith("*"):
        continue
    if "z3::" in line or "z3::ast" in line:
        remaining.append((i, line.rstrip()))

print(f"Remaining z3:: references in code: {len(remaining)}")
for line_no, line in remaining[:30]:
    print(f"  L{line_no}: {line}")
