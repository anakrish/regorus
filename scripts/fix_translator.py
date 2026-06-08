#!/usr/bin/env python3
"""Rewrite translator.rs from Z3 to SmtExpr.

This script performs mechanical replacements. Some complex cases
may need manual fixup after running.
"""
import re
import sys

path = 'src/rvm/analysis/translator.rs'
with open(path, 'r') as f:
    content = f.read()

# ============================================================
# Phase 1: Imports
# ============================================================
content = content.replace(
    """use z3::ast::{
    Ast, Bool as Z3Bool, Int as Z3Int, Real as Z3Real, Regexp as Z3Regexp, String as Z3String,
    BV as Z3BV,
};""",
    "use regorus_smt::{SmtDecl, SmtExpr, SmtSort};"
)

# ============================================================
# Phase 2: Lifetime removal — <'ctx> and 'ctx
# ============================================================
# Remove <'ctx, 'a> → <'a>,  <'ctx> → nothing
content = content.replace("<'ctx, 'a>", "<'a>")
content = content.replace("<'ctx>", "")
# Remove bare 'ctx in type positions (e.g. &'ctx z3::Context)
# but NOT in string literals like "'ctx"
content = re.sub(r"&'ctx z3::Context", "&_REMOVED_CTX_", content)
content = re.sub(r"'ctx ", "", content)
content = content.replace("&_REMOVED_CTX_", "")  # delete

# ============================================================
# Phase 3: Struct & field removal
# ============================================================
# Remove `ctx: ,` field in Translator struct and new()
content = content.replace("    ctx: ,\n", "")
# In Self { ... } initializer:
content = content.replace("            ctx,\n", "")

# ============================================================
# Phase 4: Z3 type names → SmtExpr
# ============================================================
for z3type in ['Z3Bool', 'Z3Int', 'Z3Real', 'Z3String', 'Z3Regexp', 'Z3BV']:
    content = content.replace(z3type, 'SmtExpr')

# Also fix z3::ast::String references
content = content.replace('z3::ast::String', 'SmtExpr')

# ============================================================
# Phase 5: Z3 constructor replacements
# ============================================================
# SmtExpr::from_bool(self.ctx, true) → SmtExpr::True
content = content.replace("SmtExpr::from_bool(self.ctx, true)", "SmtExpr::True")
content = content.replace("SmtExpr::from_bool(self.ctx, false)", "SmtExpr::False")
# SmtExpr::from_bool(ctx, true/false)
content = content.replace("SmtExpr::from_bool(ctx, true)", "SmtExpr::True")
content = content.replace("SmtExpr::from_bool(ctx, false)", "SmtExpr::False")
# SmtExpr::from_bool(self.ctx, EXPR) → SmtExpr::bool_lit(EXPR)
content = re.sub(r'SmtExpr::from_bool\(self\.ctx, (.+?)\)', r'SmtExpr::bool_lit(\1)', content)
content = re.sub(r'SmtExpr::from_bool\(ctx, (.+?)\)', r'SmtExpr::bool_lit(\1)', content)

# SmtExpr::from_i64(self.ctx, EXPR) → SmtExpr::IntLit(EXPR)
content = re.sub(r'SmtExpr::from_i64\(self\.ctx, (.+?)\)', r'SmtExpr::IntLit(\1)', content)

# SmtExpr::from_str(self.ctx, (.+?))\.unwrap\(\) → SmtExpr::StringLit(X.to_string())
content = re.sub(
    r'SmtExpr::from_str\(self\.ctx, (.+?)\)\.unwrap\(\)',
    r'SmtExpr::StringLit(\1.to_string())',
    content
)

# SmtExpr::from_real(self.ctx, N, D) → SmtExpr::RealLit(N as i64, D as i64)
content = re.sub(
    r'SmtExpr::from_real\(self\.ctx, (.+?), (.+?)\)',
    r'SmtExpr::RealLit(\1 as i64, \2 as i64)',
    content
)

# SmtExpr::from_int(&X) → SmtExpr::Int2Real(Box::new(X.clone()))
content = re.sub(
    r'SmtExpr::from_int\(&(\w+)\)',
    r'SmtExpr::Int2Real(Box::new(\1.clone()))',
    content
)
content = re.sub(
    r'SmtExpr::from_int\((\w+)\)',
    r'SmtExpr::Int2Real(Box::new(\1.clone()))',
    content
)

# ============================================================
# Phase 6: new_const → registry.alloc_const
# ============================================================
# SmtExpr::new_const(self.ctx, NAME) → self.registry.alloc_const(NAME, SmtSort::TYPE)
# We need context to determine the sort, so we'll replace based on surrounding code.
# Pattern: let var = SmtExpr::new_const(self.ctx, NAME);
# where var is later used as Bool/Int/String/etc.
# Since we replaced all types to SmtExpr, we can't distinguish. Use a helper.
# Let's replace with a fresh_const method and add it to the translator.
content = re.sub(
    r'SmtExpr::new_const\(self\.ctx, (.+?)\)',
    r'self.fresh_const(\1)',
    content
)

# ============================================================
# Phase 7: Z3Bool::and / Z3Bool::or → SmtExpr
# ============================================================
# SmtExpr::and(self.ctx, &[&a, &b]) → SmtExpr::and2(a.clone(), b.clone())
content = re.sub(
    r'SmtExpr::and\(self\.ctx, &\[&(\w+), &(\w+)\]\)',
    r'SmtExpr::and2(\1.clone(), \2.clone())',
    content
)
# SmtExpr::and(self.ctx, &[def, b]) — without & on elements (rare)
content = re.sub(
    r'SmtExpr::and\(self\.ctx, &\[(\w+), (\w+)\]\)',
    r'SmtExpr::and2(\1.clone(), \2.clone())',
    content
)
# SmtExpr::and(self.ctx, &[&a, &b, &c]) — 3 args
content = re.sub(
    r'SmtExpr::and\(self\.ctx, &\[&(\w+), &(\w+), &(\w+)\]\)',
    r'SmtExpr::And(vec![\1.clone(), \2.clone(), \3.clone()])',
    content
)
# SmtExpr::and(ctx, &[&a, &b]) — with plain ctx
content = re.sub(
    r'SmtExpr::and\(ctx, &\[&(\w+), &(\w+)\]\)',
    r'SmtExpr::and2(\1.clone(), \2.clone())',
    content
)

# SmtExpr::or(self.ctx, &[&a, &b]) → SmtExpr::or2(a.clone(), b.clone())
content = re.sub(
    r'SmtExpr::or\(self\.ctx, &\[&(\w+), &(\w+)\]\)',
    r'SmtExpr::or2(\1.clone(), \2.clone())',
    content
)

# SmtExpr::add(self.ctx, &[&a, &b]) → SmtExpr::Add(vec![a.clone(), b.clone()])
content = re.sub(
    r'SmtExpr::add\(self\.ctx, &\[&(\w+), &(\w+)\]\)',
    r'SmtExpr::Add(vec![\1.clone(), \2.clone()])',
    content
)
# SmtExpr::sub(self.ctx, &[&a, &b]) → SmtExpr::Sub(vec![a.clone(), b.clone()])
content = re.sub(
    r'SmtExpr::sub\(self\.ctx, &\[&(\w+), &(\w+)\]\)',
    r'SmtExpr::Sub(vec![\1.clone(), \2.clone()])',
    content
)

# SmtExpr::or(self.ctx, &refs) → SmtExpr::Or(refs.iter().cloned().collect())
# This handles the N-arg case where refs is a variable holding Vec<&SmtExpr>
content = re.sub(
    r'SmtExpr::or\(self\.ctx, &(\w+)\)',
    r'SmtExpr::Or(\1.into_iter().cloned().collect())',
    content
)

# Multiline patterns for Z3Bool::and (from grep):
# Z3Bool::and(\n ... self.ctx, ...
# These were already caught by the regex above if on one line.
# For multiline, handle specifically:
content = re.sub(
    r'SmtExpr::and\(\n\s+self\.ctx, &\[&(\w+), &(\w+)\]\)',
    r'SmtExpr::and2(\1.clone(), \2.clone())',
    content
)
content = re.sub(
    r'SmtExpr::and\(\n\s+self\.ctx,\n\s+&\[&self\.(\w+), &(\w+)\],?\n\s*\)',
    r'SmtExpr::and2(self.\1.clone(), \2.clone())',
    content
)

# ============================================================
# Phase 8: Method call replacements (on SmtExpr values)
# ============================================================
# a._eq(&b) → SmtExpr::eq(a.clone(), b.clone())
# Match patterns like: IDENT._eq(&IDENT)
content = re.sub(
    r'(\w+)\._eq\(&(\w+)\)',
    r'SmtExpr::eq(\1.clone(), \2.clone())',
    content
)

# a.not() → SmtExpr::not(a.clone())
# Be careful not to match string methods like contains().not() — only Z3 bool vars
content = re.sub(
    r'(\w+)\.not\(\)',
    r'SmtExpr::not(\1.clone())',
    content
)

# a.ite(&b, &c) → SmtExpr::ite(a.clone(), b.clone(), c.clone())
content = re.sub(
    r'(\w+)\.ite\(&(\w+), &(\w+)\)',
    r'SmtExpr::ite(\1.clone(), \2.clone(), \3.clone())',
    content
)
# Handle ite with more complex args (e.g., &SmtExpr::True)
content = re.sub(
    r'(\w+)\.ite\(&(\w+), &(SmtExpr::\w+)\)',
    r'SmtExpr::ite(\1.clone(), \2.clone(), \3)',
    content
)
# a.ite(&b.clone(), &c) — already cloned
content = re.sub(
    r'(\w+)\.ite\(&(\w+)\.clone\(\), &(\w+)\)',
    r'SmtExpr::ite(\1.clone(), \2.clone(), \3.clone())',
    content
)

# a.ge(&b) → SmtExpr::ge(a.clone(), b.clone())
content = re.sub(r'(\w+)\.ge\(&(\w+)\)', r'SmtExpr::ge(\1.clone(), \2.clone())', content)
# a.gt(&b) → SmtExpr::gt(a.clone(), b.clone())
content = re.sub(r'(\w+)\.gt\(&(\w+)\)', r'SmtExpr::gt(\1.clone(), \2.clone())', content)
# a.le(&b) → SmtExpr::le(a.clone(), b.clone())
content = re.sub(r'(\w+)\.le\(&(\w+)\)', r'SmtExpr::le(\1.clone(), \2.clone())', content)
# a.lt(&b) → SmtExpr::lt(a.clone(), b.clone())
content = re.sub(r'(\w+)\.lt\(&(\w+)\)', r'SmtExpr::lt(\1.clone(), \2.clone())', content)

# a.implies(&b_expr) → SmtExpr::implies(a.clone(), b_expr)
# The implies argument can be complex (e.g. &v_i._eq(...).not())
# Since _eq and not are already replaced, the pattern changes.
# Let's handle the simple case first:
content = re.sub(
    r'(\w+)\.implies\(&(\w+)\)',
    r'SmtExpr::implies(\1.clone(), \2.clone())',
    content
)

# ============================================================
# Phase 9: Z3 FFI helpers → SmtExpr constructors
# ============================================================
# Replace the z3_sys FFI helper methods entirely.
# z3_string_length → SmtExpr::SeqLength
# z3_string_indexof → SmtExpr::SeqIndex
# z3_string_replace → SmtExpr::SeqReplace
# z3_string_extract → SmtExpr::SeqExtract
# z3_string_concat → SmtExpr::SeqConcat
# z3_int_to_string → SmtExpr::IntToStr

# Replace call sites:
content = re.sub(
    r'self\.z3_string_length\(&(\w+)\)',
    r'SmtExpr::SeqLength(Box::new(\1.clone()))',
    content
)
content = re.sub(
    r'self\.z3_string_indexof\(&(\w+), &(\w+), &(\w+)\)',
    r'SmtExpr::SeqIndex(Box::new(\1.clone()), Box::new(\2.clone()), Box::new(\3.clone()))',
    content
)
content = re.sub(
    r'self\.z3_string_replace\(&(\w+), &(\w+), &(\w+)\)',
    r'SmtExpr::SeqReplace(Box::new(\1.clone()), Box::new(\2.clone()), Box::new(\3.clone()))',
    content
)
content = re.sub(
    r'self\.z3_string_extract\(&(\w+), &(\w+), &(\w+)\)',
    r'SmtExpr::SeqExtract(Box::new(\1.clone()), Box::new(\2.clone()), Box::new(\3.clone()))',
    content
)
content = re.sub(
    r'self\.z3_string_concat\(&(\w+)\)',
    r'SmtExpr::SeqConcat(\1.to_vec())',
    content
)
content = re.sub(
    r'self\.z3_int_to_string\(&?(\w+)\)',
    r'SmtExpr::IntToStr(Box::new(\1.clone()))',
    content
)

# Delete the z3_sys helper method definitions entirely
# Find the block from "// Z3 string theory FFI helpers" to the next "// -------"
content = re.sub(
    r'    // =+\n    // Z3 string theory FFI helpers\n    // =+\n.*?(?=    // -{5,})',
    '',
    content,
    flags=re.DOTALL
)

# ============================================================
# Phase 10: BV operations
# ============================================================
# SmtExpr::from_int(&i0, 64) → SmtExpr::Int2BV(Box::new(i0.clone()), 64)
content = re.sub(
    r'SmtExpr::Int2Real\(Box::new\((\w+)\.clone\(\)\)\), 64\)',
    r'SmtExpr::Int2BV(Box::new(\1.clone()), 64)',
    content
)
# Wait, the BV patterns are:
# Z3BV::from_int(&i0, 64) -- this became SmtExpr::from_int(&i0, 64) after Phase 4
# But Phase 5's from_int replacement converted it to SmtExpr::Int2Real(Box::new(i0.clone()))
# That's wrong. Let me fix this.
# Actually, Z3BV::from_int(&i0, 64) takes 2 args. Let me handle specifically.
# After Phase 4, it became SmtExpr::from_int(&i0, 64)
# After Phase 5's from_int regex, it became... let's check:
# The regex was: r'SmtExpr::from_int\(&(\w+)\)' → Int2Real
# But SmtExpr::from_int(&i0, 64) has TWO args, so the regex wouldn't match
# (the close paren is after 64, not after i0).
# So SmtExpr::from_int(&i0, 64) survived Phase 5. Good.
# Replace it now:
content = re.sub(
    r'SmtExpr::from_int\(&(\w+), (\d+)\)',
    r'SmtExpr::Int2BV(Box::new(\1.clone()), \2)',
    content
)

# bv_result.to_int(true) → SmtExpr::BV2Int(Box::new(bv_result.clone()), true)
content = re.sub(
    r'(\w+)\.to_int\(true\)',
    r'SmtExpr::BV2Int(Box::new(\1.clone()), true)',
    content
)

# a.bvand(&b) → SmtExpr::BVAnd(Box::new(a), Box::new(b))
content = re.sub(r'(\w+)\.bvand\(&(\w+)\)', r'SmtExpr::BVAnd(Box::new(\1), Box::new(\2))', content)
content = re.sub(r'(\w+)\.bvor\(&(\w+)\)', r'SmtExpr::BVOr(Box::new(\1), Box::new(\2))', content)
content = re.sub(r'(\w+)\.bvxor\(&(\w+)\)', r'SmtExpr::BVXor(Box::new(\1), Box::new(\2))', content)
content = re.sub(r'(\w+)\.bvshl\(&(\w+)\)', r'SmtExpr::BVShl(Box::new(\1), Box::new(\2))', content)
content = re.sub(r'(\w+)\.bvlshr\(&(\w+)\)', r'SmtExpr::BVLshr(Box::new(\1), Box::new(\2))', content)

# ============================================================
# Phase 11: Regexp operations (Cedar)
# ============================================================
# SmtExpr::literal(ctx, pattern) → SmtExpr::Re(SmtExpr::StringLit(pattern.to_string()))
content = re.sub(
    r'SmtExpr::literal\(ctx, (\w+)\)',
    r'SmtExpr::ReLiteral(Box::new(SmtExpr::StringLit(\1.to_string())))',
    content
)
# SmtExpr::full(ctx) → SmtExpr::ReFull
content = re.sub(r'SmtExpr::full\(ctx\)', 'SmtExpr::ReFull', content)
# SmtExpr::concat(ctx, &refs) → SmtExpr::ReConcat(refs.iter().map(...).collect())
content = re.sub(
    r'SmtExpr::concat\(ctx, &(\w+)\)',
    r'SmtExpr::ReConcat(\1.into_iter().cloned().collect())',
    content
)

# ============================================================
# Phase 12: Remove self.ctx from remaining function signatures
# ============================================================
# In fn definitions with ctx as parameter
content = re.sub(r',?\s*ctx: ,', '', content)

# Remove remaining self.ctx references
# self.ctx is no longer a field; replace remaining uses with a dummy
# These should all be caught above, but just in case:
# NOT doing this — any remaining self.ctx will cause compile errors
# which we can then fix manually.

# ============================================================
# Phase 13: Method signature cleanup - remove ctx param
# ============================================================
# to_z3_bool(self.ctx) → to_z3_bool()
content = content.replace('.to_z3_bool(self.ctx)', '.to_z3_bool()')
content = content.replace('.to_z3_int(self.ctx)', '.to_z3_int()')
content = content.replace('.to_z3_real(self.ctx)', '.to_z3_real()')
content = content.replace('.to_z3_string(self.ctx)', '.to_z3_string()')
content = content.replace('.is_non_default(self.ctx)', '.is_non_default()')
content = content.replace('.is_defined(self.ctx)', '.is_defined()')
content = content.replace('.equals_value(self.ctx, ', '.equals_value(')
content = content.replace('.to_z3_bool(ctx)', '.to_z3_bool()')

# Definedness::and(self.ctx, &a, &b) → Definedness::and(&a, &b)
content = re.sub(
    r'Definedness::and\(self\.ctx, ',
    'Definedness::and(',
    content
)

# PathRegistry::new(ctx) → PathRegistry::new()
content = content.replace('PathRegistry::new(ctx)', 'PathRegistry::new()')
content = content.replace('PathRegistry::new(self.ctx)', 'PathRegistry::new()')

# ============================================================
# Phase 14: Fix .not() false positives — Rust's ! operator
# ============================================================
# The .not() replacement may have caught some false positives like:
# "true.not()" or booleans that aren't Z3.
# We need to be careful. The biggest risk is `true.not()` from 
# SmtExpr::not(true.clone()) which doesn't make sense.
# Also `false.not()` etc.
# Let's fix known false positives:
content = content.replace('SmtExpr::not(true.clone())', '!true')
content = content.replace('SmtExpr::not(false.clone())', '!false')

# ============================================================
# Phase 15: Fix cedar_pattern_to_z3_regexp signature
# ============================================================
content = content.replace(
    'fn cedar_pattern_to_z3_regexp(ctx: , pattern: &str)',
    'fn cedar_pattern_to_z3_regexp(pattern: &str)'
)
content = content.replace(
    'cedar_pattern_to_z3_regexp(self.ctx, ',
    'cedar_pattern_to_z3_regexp('
)
content = content.replace(
    'cedar_pattern_to_z3_regexp(ctx, ',
    'cedar_pattern_to_z3_regexp('
)

# ============================================================
# Phase 16: Fix remaining patterns
# ============================================================
# get_z3_ast() — doesn't exist on SmtExpr; these should have been
# removed with the FFI helpers but let's be safe:
# (these are in the deleted FFI blocks, so should be gone)

# Fix Translator::new signature — remove ctx parameter
content = content.replace(
    """    pub fn new(
        program: &'a Program,
        data: &'a Value,
        registry: &'a mut PathRegistry,
        config: &'a AnalysisConfig,""",
    """    pub fn new(
        program: &'a Program,
        data: &'a Value,
        registry: &'a mut PathRegistry,
        config: &'a AnalysisConfig,"""
)

# Make sure self.fresh_const exists by NOT relying on it yet — 
# we'll handle later. For now all new_const calls became self.fresh_const.

with open(path, 'w') as f:
    f.write(content)

# ============================================================
# Verification
# ============================================================
remaining = []
for i, line in enumerate(content.split('\n'), 1):
    for pat in ["z3::", "z3_sys", "Z3Bool", "Z3Int", "Z3Real", "Z3String", "Z3Regexp", "Z3BV",
                "get_z3_ast", "z3::Context", ".bvand(", ".bvor(", ".bvxor("]:
        if pat in line and not line.strip().startswith("//"):
            remaining.append(f"  L{i}: {line.strip()}")
            break

if remaining:
    print(f"WARNING: {len(remaining)} Z3 references remain in code (not comments):")
    for r in remaining[:40]:
        print(r)
else:
    print("OK - no Z3 code references remain (comments may still mention Z3)")
