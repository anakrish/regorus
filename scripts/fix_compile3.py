#!/usr/bin/env python3
"""Fix phase-3 compile errors — remaining mismatched types, moved values, operators."""
import re

def fix_file(path, fixers):
    with open(path, 'r') as f:
        content = f.read()
    original = content
    for name, fixer in fixers:
        old = content
        content = fixer(content)
        if content != old:
            print(f"  Applied: {name}")
    if content != original:
        with open(path, 'w') as f:
            f.write(content)
    else:
        print(f"  No changes: {path}")

base = 'src/rvm/analysis/'

# ── types.rs ─────────────────────────────────────────────────────────────────

def types_add_box_import(c):
    if 'use alloc::boxed::Box' not in c:
        c = c.replace('use alloc::vec::Vec;', 'use alloc::boxed::Box;\nuse alloc::vec::Vec;')
    return c

def types_add_tostring_import(c):
    if 'use alloc::string::ToString' not in c:
        if 'use alloc::string::String' in c:
            c = c.replace('use alloc::string::String;', 'use alloc::string::String;\nuse alloc::string::ToString;')
        else:
            c = c.replace('use alloc::vec::Vec;', 'use alloc::string::ToString;\nuse alloc::vec::Vec;')
    return c

print("Fixing types.rs...")
fix_file(base + 'types.rs', [
    ('add Box import', types_add_box_import),
    ('add ToString import', types_add_tostring_import),
])

# ── model_extract.rs ─────────────────────────────────────────────────────────

def me_fix_private_imports(c):
    c = c.replace(
        'use regorus_smt::problem::{SmtCheckResult, SmtValue};',
        'use regorus_smt::{SmtCheckResult, SmtValue};'
    )
    return c

print("Fixing model_extract.rs...")
fix_file(base + 'model_extract.rs', [
    ('fix private module imports', me_fix_private_imports),
])

# ── translator.rs ─────────────────────────────────────────────────────────────

def tr_fix_arithmetic_ops(c):
    """Fix za + zb → SmtExpr::Add(vec![za, zb]) etc at lines 837-844."""
    c = c.replace(
        '            ArithOp::Add => za + zb,\n'
        '            ArithOp::Sub => za - zb,\n'
        '            ArithOp::Mul => za * zb,\n'
        '            ArithOp::Div => {\n'
        '                // Guard against division by zero.\n'
        '                let zero = SmtExpr::IntLit(0);\n'
        '                self.constraints.push(SmtExpr::not(SmtExpr::eq(zb.clone(), zero.clone())));\n'
        '                za / zb\n'
        '            }',
        '            ArithOp::Add => SmtExpr::Add(vec![za, zb]),\n'
        '            ArithOp::Sub => SmtExpr::Sub(vec![za, zb]),\n'
        '            ArithOp::Mul => SmtExpr::Mul(vec![za, zb]),\n'
        '            ArithOp::Div => {\n'
        '                // Guard against division by zero.\n'
        '                let zero = SmtExpr::IntLit(0);\n'
        '                self.constraints.push(SmtExpr::not(SmtExpr::eq(zb.clone(), zero.clone())));\n'
        '                SmtExpr::Div(Box::new(za), Box::new(zb))\n'
        '            }'
    )
    return c

def tr_fix_ite_line5114(c):
    """Fix broken ite at lines 5114-5116."""
    c = c.replace(
        '                let effective_len = i_length\n'
        '                    SmtExpr::lt(, zero)\n'
        '                    SmtExpr::ite(, SmtExpr::Sub(vec![str_len.clone(), i_offset.clone()]), i_length);',
        '                let effective_len = SmtExpr::ite(\n'
        '                    SmtExpr::lt(i_length.clone(), zero),\n'
        '                    SmtExpr::Sub(vec![str_len.clone(), i_offset.clone()]),\n'
        '                    i_length.clone(),\n'
        '                );'
    )
    return c

def tr_fix_not_ref(c):
    """Fix SmtExpr::not(&SmtExpr::eq(...)) → SmtExpr::not(SmtExpr::eq(...))"""
    c = c.replace('SmtExpr::not(&SmtExpr::eq(', 'SmtExpr::not(SmtExpr::eq(')
    return c

def tr_fix_ite_ref_cond(c):
    """Fix SmtExpr::ite(cond, ...) where cond is &SmtExpr from iter."""
    # Lines 1703, 1779: for (cond, val) in new_branches.iter() — cond is &SmtExpr
    c = c.replace(
        'result = SmtExpr::ite(cond, SmtExpr::bool_lit(b), result);',
        'result = SmtExpr::ite(cond.clone(), SmtExpr::bool_lit(b), result);'
    )
    return c

def tr_fix_ite_def_bool(c):
    """Fix SmtExpr::ite(def_bool, ...) at line 2435 where def_bool and rule_bool are refs."""
    c = c.replace(
        'let result = SmtExpr::ite(def_bool, rule_bool, def_z3);',
        'let result = SmtExpr::ite(def_bool.clone(), rule_bool.clone(), def_z3);'
    )
    return c

def tr_fix_or_conds(c):
    """Fix SmtExpr::Or(conds) where conds contains references."""
    # Line 2249: (*conds[0]).clone() suggests conds is Vec<&SmtExpr>
    c = c.replace(
        '                    let any_succeeded = if conds.len() == 1 {\n'
        '                        (*conds[0]).clone()\n'
        '                    } else {\n'
        '                        SmtExpr::Or(conds)\n'
        '                    };',
        '                    let any_succeeded = if conds.len() == 1 {\n'
        '                        (*conds[0]).clone()\n'
        '                    } else {\n'
        '                        SmtExpr::Or(conds.into_iter().cloned().collect())\n'
        '                    };'
    )
    return c

def tr_fix_concrete_contains(c):
    """Fix line 2790 where concrete Set/Array/Object check wrongly uses SmtExpr."""
    c = c.replace(
        "                let result = match cv {\n"
        "                    Value::Set(s) => SmtExpr::SeqContains(Box::new(s), Box::new(vv)),\n"
        "                    Value::Array(a) => a.contains(vv),\n"
        "                    Value::Object(o) => o.contains_key(vv) || o.values().any(|v| v == vv),\n"
        "                    _ => false,\n"
        "                };",
        "                let result = match cv {\n"
        "                    Value::Set(s) => s.contains(vv),\n"
        "                    Value::Array(a) => a.contains(vv),\n"
        "                    Value::Object(o) => o.contains_key(vv) || o.values().any(|v| v == vv),\n"
        "                    _ => false,\n"
        "                };"
    )
    return c

def tr_fix_eq_refs(c):
    """Fix SmtExpr::eq(z, ...) where z is &SmtExpr from pattern match."""
    # Lines 2987, 2993: z is from match (ContainsZ3Value::Int(z), ...) - z is &SmtExpr
    # Lines 3100-3112: child_var is from registry.get_* which returns SmtExpr... 
    # Actually registry.get_string etc may return &SmtExpr or SmtExpr. Let me be careful.
    # The safe fix: add .clone() where needed. But I need to check if the pattern gives owned or ref.
    
    # For lines 2987/2993: z comes from (ContainsZ3Value::Int(z), Value::Number(n))
    # If ContainsZ3Value::Int wraps SmtExpr, then z is &SmtExpr (since we match on &).
    # Need z.clone()
    c = c.replace(
        '                            (ContainsZ3Value::Int(z), Value::Number(n)) => {\n'
        '                                if let Some(i) = n.as_i64() {\n'
        '                                    SmtExpr::eq(z, SmtExpr::IntLit(i))',
        '                            (ContainsZ3Value::Int(z), Value::Number(n)) => {\n'
        '                                if let Some(i) = n.as_i64() {\n'
        '                                    SmtExpr::eq(z.clone(), SmtExpr::IntLit(i))'
    )
    c = c.replace(
        '                            (ContainsZ3Value::Bool(z), Value::Bool(b)) => {\n'
        '                                SmtExpr::eq(z, SmtExpr::bool_lit(*b))',
        '                            (ContainsZ3Value::Bool(z), Value::Bool(b)) => {\n'
        '                                SmtExpr::eq(z.clone(), SmtExpr::bool_lit(*b))'
    )
    
    # Lines 3100-3112: get_string etc return owned SmtExpr, but val is a ref
    # ContainsZ3Value::Str(v) — v is &SmtExpr from match
    c = c.replace('Ok(SmtExpr::eq(child_var, v))', 'Ok(SmtExpr::eq(child_var, v.clone()))')
    
    return c

def tr_fix_min_max(c):
    """Fix min/max at lines 4699/4701 — references and moved values."""
    c = c.replace(
        '        let mut cur = values[0].clone();\n'
        '        for next in values.iter().skip(1) {\n'
        '            cur = if min_mode {\n'
        '                SmtExpr::ite(SmtExpr::le(cur, next), cur, next)\n'
        '            } else {\n'
        '                SmtExpr::ite(SmtExpr::ge(cur, next), cur, next)\n'
        '            };\n'
        '        }',
        '        let mut cur = values[0].clone();\n'
        '        for next in values.iter().skip(1) {\n'
        '            cur = if min_mode {\n'
        '                SmtExpr::ite(SmtExpr::le(cur.clone(), next.clone()), cur.clone(), next.clone())\n'
        '            } else {\n'
        '                SmtExpr::ite(SmtExpr::ge(cur.clone(), next.clone()), cur.clone(), next.clone())\n'
        '            };\n'
        '        }'
    )
    return c

def tr_fix_moved_prefix_suffix(c):
    """Fix moved values in prefix/suffix operations (lines 5158-5160, 5204-5206)."""
    # trim_prefix: s0 and prefix are moved into SeqPrefix Box::new(), then used again
    c = c.replace(
        '                let has_prefix = SmtExpr::SeqPrefix(Box::new(prefix), Box::new(s0));\n'
        '                let s_len = SmtExpr::SeqLength(Box::new(s0.clone()));\n'
        '                let p_len = SmtExpr::SeqLength(Box::new(prefix.clone()));',
        '                let has_prefix = SmtExpr::SeqPrefix(Box::new(prefix.clone()), Box::new(s0.clone()));\n'
        '                let s_len = SmtExpr::SeqLength(Box::new(s0.clone()));\n'
        '                let p_len = SmtExpr::SeqLength(Box::new(prefix.clone()));'
    )
    # trim_suffix
    c = c.replace(
        '                let has_suffix = SmtExpr::SeqSuffix(Box::new(suffix), Box::new(s0));\n'
        '                let s_len = SmtExpr::SeqLength(Box::new(s0.clone()));\n'
        '                let sfx_len = SmtExpr::SeqLength(Box::new(suffix.clone()));',
        '                let has_suffix = SmtExpr::SeqSuffix(Box::new(suffix.clone()), Box::new(s0.clone()));\n'
        '                let s_len = SmtExpr::SeqLength(Box::new(s0.clone()));\n'
        '                let sfx_len = SmtExpr::SeqLength(Box::new(suffix.clone()));'
    )
    return c

def tr_fix_abs_moved(c):
    """Fix abs: z moved into Neg, then used in ite. Line 5563-5564."""
    c = c.replace(
        '                let neg = SmtExpr::Neg(Box::new(z));\n'
        '                let result = SmtExpr::ite(SmtExpr::ge(z.clone(), zero.clone()), z, neg);',
        '                let neg = SmtExpr::Neg(Box::new(z.clone()));\n'
        '                let result = SmtExpr::ite(SmtExpr::ge(z.clone(), zero.clone()), z, neg);'
    )
    return c

def tr_fix_ite_elem_type(c):
    """Fix SmtExpr::ite(elem.clone(), ...) at 2748, 3689, 3823.
    elem is from 'for elem in &elements' where elements is Vec<SmtExpr>.
    elem is &SmtExpr. elem.clone() returns SmtExpr (Rust derefs).
    The actual error is likely from `condition` not being in scope.
    Let me check line 2748 more carefully."""
    # Actually looking at 2748: SmtExpr::ite(elem.clone(), one.clone(), zero.clone())
    # The original code had: elem.ite(&one, &zero) where elem was a Z3 Bool (the condition).
    # elem IS the condition, and the true/false branches are one/zero.
    # This looks correct. The error might be that elem is a different type at this point.
    # Let me check what sym_elements/elements contain...
    # The error at 2748 says "expected SmtExpr, found &SmtExpr" at col 48.
    # Column 48 of "let contrib = SmtExpr::ite(elem.clone()," is right at elem.clone().
    # But elem.clone() on &SmtExpr does call SmtExpr::clone and returns SmtExpr.
    # Unless SmtExpr doesn't derive Clone... which it does.
    # 
    # Wait — maybe the issue is that ite expects owned SmtExpr but elem.clone()
    # ... actually in Rust, Clone::clone on &T calls T::clone because of auto-deref.
    # OK let me check: for elem in &sym_elements iterating over &Vec<X> means elem: &X.
    # .clone() on &X → X (because Rust auto-derefs to call X::clone()).
    # But WAIT: Clone::clone(self: &Self) -> Self. For &SmtExpr, Self = &SmtExpr.
    # So (&SmtExpr).clone() → &SmtExpr! To get SmtExpr you need (*elem).clone() or
    # <SmtExpr as Clone>::clone(elem).
    # 
    # Actually no. In Rust, given `elem: &SmtExpr`:
    # - elem.clone() resolves to <SmtExpr as Clone>::clone(elem) which returns SmtExpr
    #   (because SmtExpr: Clone, and clone takes &self, so &SmtExpr matches &SmtExpr)
    # - The &T: Clone impl gives <&T as Clone>::clone(&&T) -> &T
    #   which would need elem to be of type &&SmtExpr for ambiguity.
    #
    # With elem: &SmtExpr, Rust prefers SmtExpr::clone over <&SmtExpr>::clone because
    # it requires fewer auto-refs. So elem.clone() → SmtExpr. Should be fine.
    #
    # Maybe the issue is that `elements` at this scope is not Vec<SmtExpr>?
    # It could be the result of into_iter or some transformation that changes the type.
    # For now, just assume the type is fine and see if the other fixes resolve this.
    return c

print("Fixing translator.rs...")
fix_file(base + 'translator.rs', [
    ('fix arithmetic ops', tr_fix_arithmetic_ops),
    ('fix broken ite 5114', tr_fix_ite_line5114),
    ('fix not(&eq)', tr_fix_not_ref),
    ('fix ite ref cond', tr_fix_ite_ref_cond),
    ('fix ite def_bool', tr_fix_ite_def_bool),
    ('fix Or(conds)', tr_fix_or_conds),
    ('fix concrete contains', tr_fix_concrete_contains),
    ('fix eq refs', tr_fix_eq_refs),
    ('fix min/max', tr_fix_min_max),
    ('fix moved prefix/suffix', tr_fix_moved_prefix_suffix),
    ('fix abs moved', tr_fix_abs_moved),
])

print("Done with phase 3 fixes.")
