#!/usr/bin/env python3
"""Rewrite schema_constraints.rs from Z3 to SmtExpr."""
import re, sys

path = 'src/rvm/analysis/schema_constraints.rs'
with open(path, 'r') as f:
    content = f.read()

# Replace imports
content = content.replace(
    "use z3::ast::{Ast, Bool as Z3Bool, Int as Z3Int};",
    "use regorus_smt::SmtExpr;"
)

# Remove 'ctx lifetime params and Z3 type refs throughout
content = content.replace("<'ctx>", "")
content = content.replace("'ctx ", "")

# Fix function signatures: remove ctx parameters
# apply_schema_constraints
content = content.replace(
    "pub fn apply_schema_constraints(\n    ctx: &z3::Context,\n    registry: &mut PathRegistry,",
    "pub fn apply_schema_constraints(\n    registry: &mut PathRegistry,"
)

# walk_schema
content = content.replace(
    "fn walk_schema(\n    ctx: &z3::Context,\n    registry: &mut PathRegistry,",
    "fn walk_schema(\n    registry: &mut PathRegistry,"
)

# apply_min_items_defined
content = content.replace(
    "fn apply_min_items_defined(\n    _ctx: &z3::Context,\n    registry: &mut PathRegistry,",
    "fn apply_min_items_defined(\n    registry: &mut PathRegistry,"
)

# assert_element_undefined
content = content.replace(
    "fn assert_element_undefined(\n    ctx: &z3::Context,\n    registry: &mut PathRegistry,",
    "fn assert_element_undefined(\n    registry: &mut PathRegistry,"
)

# apply_unique_items
content = content.replace(
    "fn apply_unique_items(\n    ctx: &z3::Context,\n    registry: &mut PathRegistry,",
    "fn apply_unique_items(\n    registry: &mut PathRegistry,"
)

# apply_x_unique
content = content.replace(
    "fn apply_x_unique(\n    ctx: &z3::Context,\n    registry: &mut PathRegistry,",
    "fn apply_x_unique(\n    registry: &mut PathRegistry,"
)

# value_equals_json
content = content.replace(
    "fn value_equals_json(\n    ctx: &z3::Context,\n    registry: &mut PathRegistry,",
    "fn value_equals_json(\n    registry: &mut PathRegistry,"
)

# Return type replacements
content = content.replace("Vec<Z3Bool>", "Vec<SmtExpr>")
content = content.replace("Option<Z3Bool>", "Option<SmtExpr>")
content = content.replace("&mut Vec<Z3Bool>", "&mut Vec<SmtExpr>")

# Remove ctx from call sites
content = content.replace("walk_schema(\n        ctx,\n        registry,", "walk_schema(\n        registry,")
content = content.replace("walk_schema(\n                    ctx,\n                    registry,", "walk_schema(\n                    registry,")
content = content.replace("apply_min_items_defined(ctx, registry,", "apply_min_items_defined(registry,")
content = content.replace("apply_x_unique(ctx, registry,", "apply_x_unique(registry,")
content = content.replace("apply_unique_items(ctx, registry,", "apply_unique_items(registry,")
content = content.replace("assert_element_undefined(\n                        ctx,\n                        registry,", "assert_element_undefined(\n                        registry,")
content = content.replace("assert_element_undefined(\n                    ctx,\n                    registry,", "assert_element_undefined(\n                    registry,")
content = content.replace("value_equals_json(ctx, registry,", "value_equals_json(registry,")

# Replace the unsafe z3_sys string-length block
old_unsafe = """            // The z3 crate doesn't expose a `length()` method on String, nor
            // does it make `Context::z3_ctx` public.  We extract the raw
            // context pointer from the single-field `Context` struct in order
            // to call `Z3_mk_seq_length` directly.
            #[allow(unsafe_code)]
            let str_len = unsafe {
                let ctx_ptr: *const z3::Context = ctx;
                let raw_ctx: z3_sys::Z3_context = *(ctx_ptr as *const z3_sys::Z3_context);
                let len_ast = z3_sys::Z3_mk_seq_length(raw_ctx, str_var.get_z3_ast());
                Z3Int::wrap(ctx, len_ast)
            };
            let min_val = Z3Int::from_i64(ctx, min_len as i64);
            let ge = str_len.ge(&min_val);"""
new_unsafe = """            let str_len = SmtExpr::SeqLength(Box::new(str_var));
            let min_val = SmtExpr::IntLit(min_len as i64);
            let ge = SmtExpr::ge(str_len, min_val);"""
content = content.replace(old_unsafe, new_unsafe)

# Replace enum block - Z3Bool::or
old_enum = """        if !disj.is_empty() {
            let refs: Vec<&Z3Bool> = disj.iter().collect();
            let or = Z3Bool::or(ctx, &refs);
            constraints.push(or);
        }"""
new_enum = """        if !disj.is_empty() {
            constraints.push(SmtExpr::Or(disj));
        }"""
content = content.replace(old_enum, new_enum)

# Replace _eq / not / and / implies patterns
content = re.sub(
    r'let neq = vi\._eq\(&vj\)\.not\(\);',
    'let neq = SmtExpr::not(SmtExpr::eq(vi.clone(), vj.clone()));',
    content
)
content = re.sub(
    r'let both_def = Z3Bool::and\(ctx, &\[&di, &dj\]\);',
    'let both_def = SmtExpr::and2(di, dj);',
    content
)
content = re.sub(
    r'constraints\.push\(Z3Bool::implies\(&both_def, &neq\)\);',
    'constraints.push(SmtExpr::implies(both_def, neq));',
    content
)

# entry.defined.clone().not() -> SmtExpr::not(entry.defined.clone())
content = content.replace(
    "constraints.push(entry.defined.clone().not());",
    "constraints.push(SmtExpr::not(entry.defined.clone()));"
)

# value_equals_json body replacements
content = content.replace(
    'let lit = z3::ast::String::from_str(ctx, s).unwrap();\n            Some(var._eq(&lit))',
    'let lit = SmtExpr::StringLit(s.clone());\n            Some(SmtExpr::eq(var, lit))'
)
content = content.replace(
    'let lit = Z3Bool::from_bool(ctx, *b);\n            Some(var._eq(&lit))',
    'let lit = SmtExpr::bool_lit(*b);\n            Some(SmtExpr::eq(var, lit))'
)
# Z3Int::from_i64 patterns
content = content.replace(
    'let lit = Z3Int::from_i64(ctx, i);\n                Some(var._eq(&lit))',
    'let lit = SmtExpr::IntLit(i);\n                Some(SmtExpr::eq(var, lit))'
)
content = content.replace(
    'let lit = Z3Int::from_i64(ctx, f as i64);\n                Some(var._eq(&lit))',
    'let lit = SmtExpr::IntLit(f as i64);\n                Some(SmtExpr::eq(var, lit))'
)

# Update doc comments
content = content.replace("JSON Schema \u2192 Z3 constraint generator", "JSON Schema \u2192 SMT constraint generator")
content = content.replace("Returns a vector of Z3 constraints", "Returns a vector of SMT constraints")
content = content.replace("Build a Z3 equality constraint", "Build an SMT equality constraint")
content = content.replace("emits Z3 constraints", "emits SMT constraints")

with open(path, 'w') as f:
    f.write(content)

# Verify no Z3 references remain
remaining = []
for i, line in enumerate(content.split('\n'), 1):
    if any(pat in line for pat in ['z3::', 'Z3Bool', 'Z3Int', 'Z3Real', 'z3_sys', "'ctx"]):
        remaining.append(f"  L{i}: {line.strip()}")

if remaining:
    print(f"WARNING: {len(remaining)} Z3 references remain:")
    for r in remaining[:20]:
        print(r)
else:
    print("OK - no Z3 references remain")
