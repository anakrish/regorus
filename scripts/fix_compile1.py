#!/usr/bin/env python3
"""Fix phase-1 compile errors across all analysis files."""
import re

def fix_file(path, fixers):
    with open(path, 'r') as f:
        content = f.read()
    original = content
    for name, fixer in fixers:
        content = fixer(content)
    if content != original:
        with open(path, 'w') as f:
            f.write(content)
        print(f"  Fixed {path}")
    else:
        print(f"  No changes needed: {path}")

# ── schema_constraints.rs fixes ──────────────────────────────────────────────

def fix_schema_add_box_import(content):
    """Add alloc::boxed::Box import."""
    if 'alloc::boxed::Box' not in content:
        content = content.replace(
            'use alloc::vec::Vec;',
            'use alloc::boxed::Box;\nuse alloc::vec::Vec;'
        )
    return content

def fix_schema_remove_ctx(content):
    """Remove leftover ctx references in schema_constraints.rs."""
    # Pattern: ctx,\n on its own line
    content = re.sub(r'\n\s+ctx,\n', '\n', content)
    return content

# ── translator.rs fixes ─────────────────────────────────────────────────────

def fix_translator_add_box_import(content):
    """Add alloc::boxed::Box import."""
    if 'alloc::boxed::Box' not in content:
        content = content.replace(
            'use alloc::vec::Vec;',
            'use alloc::boxed::Box;\nuse alloc::vec::Vec;'
        )
    return content

def fix_elem_smt_ite(content):
    """Fix elem.SmtExpr::ite(condition, one, zero) -> SmtExpr::ite(elem, condition, one, zero)
    
    But actually ite signature is SmtExpr::ite(c, t, e) — condition, then, else.
    The pattern is counting: ite(is_defined, 1, 0) where elem is the bool condition.
    So: SmtExpr::ite(elem.clone(), one.clone(), zero.clone())
    Actually looking at the original: let contrib = elem.ite(&condition, &one, &zero)
    In Z3, Bool::ite(&self, condition, then, else) - no, that's wrong.
    elem.ite(&one, &zero) — the elem IS the condition for Z3 Bool.
    Actually z3::ast::Bool::ite(self, t, e) - self is condition, t/e are then/else branches.
    
    So the pattern is:
      elem.SmtExpr::ite(condition.clone(), one.clone(), zero.clone())
    Actually, looking at it more carefully, the original Z3 code was likely:
      let contrib = elem.ite(&one, &zero);
    where elem is a Z3 Bool (the condition). But the regex conversion turned it into:
      elem.SmtExpr::ite(condition.clone(), one.clone(), zero.clone())
    
    Hmm, let me just look at the actual line.
    """
    # Pattern: X.SmtExpr::ite(A, B, C)
    # -> SmtExpr::ite(X, A, B) ... no wait, ite takes 3 args: condition, then, else
    # The original Z3 was: elem.ite(&one, &zero) where elem is Bool (condition)
    # The mechanical conversion confused it. Let me just fix to SmtExpr::ite(elem, one, zero)
    # But need to understand what condition vs one vs zero are.
    # Actually from the error output, the line is:
    #   let contrib = elem.SmtExpr::ite(condition.clone(), one.clone(), zero.clone());
    # This has 3 args + a receiver. The original Z3 was probably:
    #   let contrib = elem.ite(&condition, &one, &zero)
    # Z3 Dynamic::ite takes condition, then, else. But elem might be the main value...
    # Actually in Z3, Bool::ite(cond, then_val, else_val) - the Bool is the condition.
    # So elem is the condition, condition is the then_val, one and zero...
    # 
    # Wait, let me just look at the actual line more carefully.
    pass
    return content

def fix_method_to_function(content):
    """Fix x.method(args) patterns that should be SmtExpr::Variant(Box::new(x), ...).
    
    Patterns to fix:
    - x.not() -> SmtExpr::not(x)
    - x._eq(y) -> SmtExpr::eq(x, y)
    - x.implies(y) -> SmtExpr::implies(x, y)
    - x.ite(a, b) -> SmtExpr::ite(x, a, b)
    - x.prefix(y) -> SmtExpr::SeqPrefix(Box::new(x), Box::new(y))
    - x.suffix(y) -> SmtExpr::SeqSuffix(Box::new(x), Box::new(y))
    - x.contains(y) -> SmtExpr::SeqContains(Box::new(x), Box::new(y))
    - x.unary_minus() -> SmtExpr::Neg(Box::new(x))
    - x.rem(y) -> SmtExpr::Rem(Box::new(x), Box::new(y))
    - x.bvnot() -> SmtExpr::BvNot(Box::new(x))
    - x.regex_matches(y) -> SmtExpr::SeqInRe(Box::new(x), Box::new(y))
    
    Also arithmetic operators:
    - x + y -> SmtExpr::Add(vec![x, y])
    - x - y -> SmtExpr::Sub(vec![x, y])
    - x * y -> SmtExpr::Mul(vec![x, y])
    - x / y -> SmtExpr::Div(Box::new(x), Box::new(y))
    """
    # These are too complex for simple regex. Let me handle them with targeted replacements.
    pass
    return content

# ── model_extract.rs fixes ───────────────────────────────────────────────────

def fix_model_extract_add_import(content):
    """Add SmtExpr import if missing."""
    if 'use regorus_smt::SmtExpr;' not in content and 'SmtExpr' in content:
        # Add after the last use statement
        content = content.replace(
            'use regorus_smt::SmtSort;',
            'use regorus_smt::{SmtExpr, SmtSort};'
        )
    return content

# ── mod.rs fixes ─────────────────────────────────────────────────────────────

def fix_mod_private_modules(content):
    """Fix regorus_smt::expr:: and regorus_smt::problem:: to regorus_smt::."""
    content = content.replace('regorus_smt::expr::', 'regorus_smt::')
    content = content.replace('regorus_smt::problem::', 'regorus_smt::')
    return content

# ── Run fixes ────────────────────────────────────────────────────────────────

base = 'src/rvm/analysis/'

print("Fixing schema_constraints.rs...")
fix_file(base + 'schema_constraints.rs', [
    ('add Box import', fix_schema_add_box_import),
    ('remove ctx', fix_schema_remove_ctx),
])

print("Fixing translator.rs...")
fix_file(base + 'translator.rs', [
    ('add Box import', fix_translator_add_box_import),
])

print("Fixing model_extract.rs...")
fix_file(base + 'model_extract.rs', [
    ('add SmtExpr import', fix_model_extract_add_import),
])

print("Fixing mod.rs...")
fix_file(base + 'mod.rs', [
    ('fix private modules', fix_mod_private_modules),
])

print("Done with phase 1 fixes.")
