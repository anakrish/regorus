#!/usr/bin/env python3
"""
Fix phase-2 compile errors across all analysis files.

Key error categories:
1. method calls on SmtExpr that need to be free-function calls
2. wrong variant names (BVAnd→BvAnd, Int2BV→Int2Bv, etc.)
3. SmtExpr::StringLit(&x) → SmtExpr::StringLit(x.to_string()) -- owned String
4. Box import missing in mod.rs / model_extract.rs
5. private module paths in model_extract.rs
6. alloc_const visibility
7. elem.SmtExpr::ite(...) syntax errors
8. operator overloads (/, +, -, *)
"""
import re
import sys

def fix_translator(path):
    with open(path, 'r') as f:
        lines = f.readlines()

    # Work on lines as a list for precise fixes
    def replace_line(lineno, old_pat, new_text):
        """Replace pattern in specific 1-based line number."""
        idx = lineno - 1
        if idx < 0 or idx >= len(lines):
            print(f"  WARNING: line {lineno} out of range", file=sys.stderr)
            return False
        if old_pat in lines[idx]:
            lines[idx] = lines[idx].replace(old_pat, new_text)
            return True
        else:
            print(f"  WARNING: pattern not found at line {lineno}: {old_pat!r}", file=sys.stderr)
            return False

    changes = 0

    # --- Fix .not() calls → SmtExpr::not(x) ---
    # Pattern: EXPR.not()  where EXPR can be complex
    # We need a regex to handle this
    content = ''.join(lines)

    # 1. Fix elem.SmtExpr::ite(condition.clone(), one.clone(), zero.clone())
    # → SmtExpr::ite(elem.clone(), one.clone(), zero.clone())
    # Lines 2748, 3689, 3823
    content = content.replace(
        'elem.SmtExpr::ite(condition.clone(), one.clone(), zero.clone())',
        'SmtExpr::ite(elem.clone(), one.clone(), zero.clone())'
    )

    # 2. Fix BV variant names: BVAnd→BvAnd, BVOr→BvOr, etc.
    content = content.replace('SmtExpr::BVAnd(', 'SmtExpr::BvAnd(')
    content = content.replace('SmtExpr::BVOr(', 'SmtExpr::BvOr(')
    content = content.replace('SmtExpr::BVXor(', 'SmtExpr::BvXor(')
    content = content.replace('SmtExpr::BVShl(', 'SmtExpr::BvShl(')
    content = content.replace('SmtExpr::BVLshr(', 'SmtExpr::BvLShr(')
    content = content.replace('SmtExpr::Int2BV(', 'SmtExpr::Int2Bv(')
    content = content.replace('SmtExpr::BV2Int(', 'SmtExpr::Bv2Int(')

    # 3. Fix ReLiteral → SeqToRe
    content = content.replace('SmtExpr::ReLiteral(', 'SmtExpr::SeqToRe(')

    # 4. Fix ReFull (no args) → ReFull(SmtSort::String)
    content = content.replace('SmtExpr::ReFull', 'SmtExpr::ReFull(SmtSort::String)')
    # Fix double-wrapped: ReFull(SmtSort::String)(SmtSort::String) → ReFull(SmtSort::String)
    content = content.replace('SmtExpr::ReFull(SmtSort::String)(SmtSort::String)', 'SmtExpr::ReFull(SmtSort::String)')

    # 5. Fix SmtExpr::StringLit(&...) → SmtExpr::StringLit(...)
    # The StringLit variant takes String (owned), not &String
    # Pattern: SmtExpr::StringLit(&EXPR)
    # Replace: SmtExpr::StringLit(EXPR.to_string()) -- but many already have .to_string()
    # More precisely, SmtExpr::StringLit(&x) where x is an expression
    # Let's handle the specific patterns:
    
    # SmtExpr::StringLit(&literal.to_string()) → SmtExpr::StringLit(literal.to_string())
    content = re.sub(
        r'SmtExpr::StringLit\(&([^)]+)\)',
        r'SmtExpr::StringLit(\1)',
        content
    )

    # 6. Fix method calls on SmtExpr that should be free functions
    # .not() → SmtExpr::not(EXPR)
    # This is tricky because the receiver can be complex.
    # Pattern: IDENTIFIER.not()  or  EXPR).not()
    # We handle the common patterns:
    
    # Pattern: some_expr.clone().not()  → SmtExpr::not(some_expr.clone())
    # Pattern: SmtExpr::func(args).not()  → SmtExpr::not(SmtExpr::func(args))
    # Pattern: val.clone()).not()  → SmtExpr::not(val.clone()))

    # Let's handle line by line for .not() since it's context-sensitive

    lines = content.split('\n')
    new_lines = []
    for i, line in enumerate(lines):
        original_line = line

        # Fix x.not() patterns - simple identifier.not()
        # e.g., def_bool.clone().not() → SmtExpr::not(def_bool.clone())
        # e.g., val.clone()).not() — this is inside parens
        
        # General approach: find '.not()' and rewrite
        while '.not()' in line:
            pos = line.index('.not()')
            # Walk backwards to find the start of the expression
            # We need to handle nested parens
            # Find the start of the sub-expression before .not()
            depth = 0
            j = pos - 1
            while j >= 0:
                if line[j] == ')':
                    depth += 1
                elif line[j] == '(':
                    if depth == 0:
                        break
                    depth -= 1
                elif line[j] in ' ,;={' and depth == 0:
                    break
                j -= 1
            
            start = j + 1
            expr = line[start:pos]
            # Replace:  expr.not()  with  SmtExpr::not(expr)
            before = line[:start]
            after = line[pos + 6:]  # skip '.not()'
            line = before + 'SmtExpr::not(' + expr + ')' + after

        # Fix x._eq(y) patterns
        # e.g., child_var._eq(v) → SmtExpr::eq(child_var, v)
        # e.g., z._eq(&SmtExpr::IntLit(i)) → SmtExpr::eq(z, SmtExpr::IntLit(i))
        while '._eq(' in line:
            pos = line.index('._eq(')
            # Find receiver
            depth = 0
            j = pos - 1
            while j >= 0:
                if line[j] == ')':
                    depth += 1
                elif line[j] == '(':
                    if depth == 0:
                        break
                    depth -= 1
                elif line[j] in ' ,;={' and depth == 0:
                    break
                j -= 1
            start = j + 1
            receiver = line[start:pos]
            
            # Find the argument (handle nested parens)
            arg_start = pos + 5  # after '._eq('
            depth = 1
            k = arg_start
            while k < len(line) and depth > 0:
                if line[k] == '(':
                    depth += 1
                elif line[k] == ')':
                    depth -= 1
                k += 1
            arg = line[arg_start:k-1]  # exclude closing paren
            
            # Remove leading & from arg
            arg = arg.lstrip('&')
            
            before = line[:start]
            after = line[k:]
            line = before + 'SmtExpr::eq(' + receiver + ', ' + arg + ')' + after

        # Fix x.implies(y) patterns
        while '.implies(' in line:
            pos = line.index('.implies(')
            depth = 0
            j = pos - 1
            while j >= 0:
                if line[j] == ')':
                    depth += 1
                elif line[j] == '(':
                    if depth == 0:
                        break
                    depth -= 1
                elif line[j] in ' ,;={' and depth == 0:
                    break
                j -= 1
            start = j + 1
            receiver = line[start:pos]
            
            arg_start = pos + 9
            depth = 1
            k = arg_start
            while k < len(line) and depth > 0:
                if line[k] == '(':
                    depth += 1
                elif line[k] == ')':
                    depth -= 1
                k += 1
            arg = line[arg_start:k-1]
            arg = arg.lstrip('&')
            
            before = line[:start]
            after = line[k:]
            line = before + 'SmtExpr::implies(' + receiver + ', ' + arg + ')' + after

        # Fix x.ite(&a, &b) patterns → SmtExpr::ite(x, a, b)
        while '.ite(' in line:
            pos = line.index('.ite(')
            depth = 0
            j = pos - 1
            while j >= 0:
                if line[j] == ')':
                    depth += 1
                elif line[j] == '(':
                    if depth == 0:
                        break
                    depth -= 1
                elif line[j] in ' ,;={' and depth == 0:
                    break
                j -= 1
            start = j + 1
            receiver = line[start:pos]
            
            # Parse two arguments
            arg_start = pos + 5
            depth = 1
            k = arg_start
            # Find the first comma at depth 1
            comma_pos = None
            while k < len(line) and depth > 0:
                if line[k] == '(':
                    depth += 1
                elif line[k] == ')':
                    depth -= 1
                    if depth == 0:
                        break
                elif line[k] == ',' and depth == 1:
                    if comma_pos is None:
                        comma_pos = k
                k += 1
            
            if comma_pos is not None:
                arg1 = line[arg_start:comma_pos].strip().lstrip('&')
                arg2 = line[comma_pos+1:k].strip().lstrip('&')
                before = line[:start]
                after = line[k+1:]
                line = before + 'SmtExpr::ite(' + receiver + ', ' + arg1 + ', ' + arg2 + ')' + after
            else:
                break  # Can't parse, skip

        # Fix x.prefix(&y) → SmtExpr::SeqPrefix(Box::new(x), Box::new(y))
        while '.prefix(' in line:
            pos = line.index('.prefix(')
            depth = 0
            j = pos - 1
            while j >= 0:
                if line[j] == ')':
                    depth += 1
                elif line[j] == '(':
                    if depth == 0:
                        break
                    depth -= 1
                elif line[j] in ' ,;={' and depth == 0:
                    break
                j -= 1
            start = j + 1
            receiver = line[start:pos]
            
            arg_start = pos + 8
            depth = 1
            k = arg_start
            while k < len(line) and depth > 0:
                if line[k] == '(':
                    depth += 1
                elif line[k] == ')':
                    depth -= 1
                k += 1
            arg = line[arg_start:k-1].strip().lstrip('&')
            
            before = line[:start]
            after = line[k:]
            line = before + 'SmtExpr::SeqPrefix(Box::new(' + receiver + '), Box::new(' + arg + '))' + after

        # Fix x.suffix(&y) → SmtExpr::SeqSuffix(Box::new(x), Box::new(y))
        while '.suffix(' in line:
            pos = line.index('.suffix(')
            depth = 0
            j = pos - 1
            while j >= 0:
                if line[j] == ')':
                    depth += 1
                elif line[j] == '(':
                    if depth == 0:
                        break
                    depth -= 1
                elif line[j] in ' ,;={' and depth == 0:
                    break
                j -= 1
            start = j + 1
            receiver = line[start:pos]
            
            arg_start = pos + 8
            depth = 1
            k = arg_start
            while k < len(line) and depth > 0:
                if line[k] == '(':
                    depth += 1
                elif line[k] == ')':
                    depth -= 1
                k += 1
            arg = line[arg_start:k-1].strip().lstrip('&')
            
            before = line[:start]
            after = line[k:]
            line = before + 'SmtExpr::SeqSuffix(Box::new(' + receiver + '), Box::new(' + arg + '))' + after

        # Fix x.contains(&y) → SmtExpr::SeqContains(Box::new(x), Box::new(y))
        while '.contains(' in line:
            # Be careful: only fix SmtExpr.contains, not str.contains or vec.contains
            # Heuristic: if it's inside a closure that deals with SmtExpr
            pos = line.index('.contains(')
            depth = 0
            j = pos - 1
            while j >= 0:
                if line[j] == ')':
                    depth += 1
                elif line[j] == '(':
                    if depth == 0:
                        break
                    depth -= 1
                elif line[j] in ' ,;={' and depth == 0:
                    break
                j -= 1
            start = j + 1
            receiver = line[start:pos]
            
            # Only fix if this looks like an SmtExpr context (not a string/vec contains)
            # Check if receiver starts with s, arg, or other SmtExpr-like names
            if receiver.strip() in ['s', 'arg', 'input_z3'] or 's.contains' in line[max(0,start-5):pos+10]:
                arg_start = pos + 10
                depth = 1
                k = arg_start
                while k < len(line) and depth > 0:
                    if line[k] == '(':
                        depth += 1
                    elif line[k] == ')':
                        depth -= 1
                    k += 1
                arg = line[arg_start:k-1].strip().lstrip('&')
                
                before = line[:start]
                after = line[k:]
                line = before + 'SmtExpr::SeqContains(Box::new(' + receiver + '), Box::new(' + arg + '))' + after
            else:
                break

        # Fix x.unary_minus() → SmtExpr::Neg(Box::new(x))
        while '.unary_minus()' in line:
            pos = line.index('.unary_minus()')
            depth = 0
            j = pos - 1
            while j >= 0:
                if line[j] == ')':
                    depth += 1
                elif line[j] == '(':
                    if depth == 0:
                        break
                    depth -= 1
                elif line[j] in ' ,;={' and depth == 0:
                    break
                j -= 1
            start = j + 1
            receiver = line[start:pos]
            before = line[:start]
            after = line[pos + 14:]
            line = before + 'SmtExpr::Neg(Box::new(' + receiver + '))' + after

        # Fix x.rem(&y) → SmtExpr::Rem(Box::new(x), Box::new(y))
        while '.rem(' in line:
            pos = line.index('.rem(')
            depth = 0
            j = pos - 1
            while j >= 0:
                if line[j] == ')':
                    depth += 1
                elif line[j] == '(':
                    if depth == 0:
                        break
                    depth -= 1
                elif line[j] in ' ,;={' and depth == 0:
                    break
                j -= 1
            start = j + 1
            receiver = line[start:pos]
            
            arg_start = pos + 5
            depth = 1
            k = arg_start
            while k < len(line) and depth > 0:
                if line[k] == '(':
                    depth += 1
                elif line[k] == ')':
                    depth -= 1
                k += 1
            arg = line[arg_start:k-1].strip().lstrip('&')
            
            before = line[:start]
            after = line[k:]
            line = before + 'SmtExpr::Rem(Box::new(' + receiver + '), Box::new(' + arg + '))' + after

        # Fix x.bvnot() → SmtExpr::BvNot(Box::new(x))
        while '.bvnot()' in line:
            pos = line.index('.bvnot()')
            depth = 0
            j = pos - 1
            while j >= 0:
                if line[j] == ')':
                    depth += 1
                elif line[j] == '(':
                    if depth == 0:
                        break
                    depth -= 1
                elif line[j] in ' ,;={' and depth == 0:
                    break
                j -= 1
            start = j + 1
            receiver = line[start:pos]
            before = line[:start]
            after = line[pos + 8:]
            line = before + 'SmtExpr::BvNot(Box::new(' + receiver + '))' + after

        # Fix x.regex_matches(&y) → SmtExpr::SeqInRe(Box::new(x), Box::new(y))
        while '.regex_matches(' in line:
            pos = line.index('.regex_matches(')
            depth = 0
            j = pos - 1
            while j >= 0:
                if line[j] == ')':
                    depth += 1
                elif line[j] == '(':
                    if depth == 0:
                        break
                    depth -= 1
                elif line[j] in ' ,;={' and depth == 0:
                    break
                j -= 1
            start = j + 1
            receiver = line[start:pos]
            
            arg_start = pos + 15
            depth = 1
            k = arg_start
            while k < len(line) and depth > 0:
                if line[k] == '(':
                    depth += 1
                elif line[k] == ')':
                    depth -= 1
                k += 1
            arg = line[arg_start:k-1].strip().lstrip('&')
            
            before = line[:start]
            after = line[k:]
            line = before + 'SmtExpr::SeqInRe(Box::new(' + receiver + '), Box::new(' + arg + '))' + after

        # Fix x.ge(&y) → SmtExpr::ge(x, y) (only when it's SmtExpr context)
        # Lines like: cardinality.ge(&SmtExpr::IntLit(0))
        # and: SmtExpr::ge(z.clone(), zero.clone()).ite(...)
        # These ge/le/lt calls → SmtExpr::ge/le/lt convenience functions
        for method in ['ge', 'le', 'lt', 'gt']:
            method_call = f'.{method}('
            while method_call in line:
                pos = line.index(method_call)
                depth = 0
                j = pos - 1
                while j >= 0:
                    if line[j] == ')':
                        depth += 1
                    elif line[j] == '(':
                        if depth == 0:
                            break
                        depth -= 1
                    elif line[j] in ' ,;={' and depth == 0:
                        break
                    j -= 1
                start = j + 1
                receiver = line[start:pos]
                
                # Check: is this really SmtExpr? Skip if it's something like self.pc.ge()
                # Simple heuristic: if receiver contains 'self.' it's likely not SmtExpr
                if 'self.' in receiver or 'segments' in receiver or 'chars' in receiver:
                    break
                
                arg_start = pos + len(method_call)
                depth = 1
                k = arg_start
                while k < len(line) and depth > 0:
                    if line[k] == '(':
                        depth += 1
                    elif line[k] == ')':
                        depth -= 1
                    k += 1
                arg = line[arg_start:k-1].strip().lstrip('&')
                
                before = line[:start]
                after = line[k:]
                line = before + f'SmtExpr::{method}(' + receiver + ', ' + arg + ')' + after

        # Fix lhs / rhs → SmtExpr::Div(Box::new(lhs), Box::new(rhs))
        # This is dangerous for general code, so only fix specific patterns
        # Line 4641: let out = if modulo { SmtExpr::Rem(...) } else { lhs / rhs };
        if 'lhs / rhs' in line:
            line = line.replace('lhs / rhs', 'SmtExpr::Div(Box::new(lhs), Box::new(rhs))')

        new_lines.append(line)

    content = '\n'.join(new_lines)
    
    # Fix the duplicate line at 5538-5539 (two identical SmtExpr::StringLit lines)
    content = content.replace(
        '    Some(SmtExpr::StringLit("".to_string()))\n            Some(SmtExpr::StringLit("".to_string()))',
        '            Some(SmtExpr::StringLit("".to_string()))'
    )
    
    # Fix to_string on Arc<str>
    # Line 213: self.registry.alloc_const → already right, just needs pub(crate)
    # to_string for &Arc<str>: Arc<str> doesn't implement Display directly
    # The .to_string() on &Arc<str> requires ToString trait
    # Actually Arc<str> derefs to str which has to_string(), but in no_std we need alloc::string::ToString
    # which is already imported
    
    with open(path, 'w') as f:
        f.write(content)
    print(f"  Fixed {path}")


def fix_model_extract(path):
    with open(path, 'r') as f:
        content = f.read()

    # Fix private module paths
    content = content.replace('regorus_smt::problem::SmtProblem', 'regorus_smt::SmtProblem')
    content = content.replace('regorus_smt::expr::SmtSort', 'regorus_smt::SmtSort')
    content = content.replace('regorus_smt::expr::SmtExpr', 'regorus_smt::SmtExpr')
    
    # Add SmtExpr import if needed
    if 'use regorus_smt::SmtExpr;' not in content and 'SmtExpr::' in content:
        content = content.replace(
            'use regorus_smt::SmtSort;',
            'use regorus_smt::{SmtExpr, SmtSort};'
        )

    # Fix add_extraction call: it takes 4 args (name, expr, sort, model_completion)
    # Our calls look correct if we check... Let me re-verify the call sites.
    # From reading: problem.add_extraction(format!(...), entry.defined.clone(), SmtSort::Bool, true)
    # That's 4 args, which matches. But the error says 6 args were supplied...
    # Let me check if there are other call sites.
    
    with open(path, 'w') as f:
        f.write(content)
    print(f"  Fixed {path}")


def fix_mod(path):
    with open(path, 'r') as f:
        content = f.read()

    # Fix remaining private module references
    content = content.replace('regorus_smt::problem::', 'regorus_smt::')
    content = content.replace('regorus_smt::expr::', 'regorus_smt::')
    
    # Add Box import if missing
    if 'use alloc::boxed::Box;' not in content and 'Box::new' in content:
        # Add after alloc imports
        if 'use alloc::' in content:
            # Find the last alloc use and add after
            lines = content.split('\n')
            new_lines = []
            box_added = False
            for line in lines:
                new_lines.append(line)
                if not box_added and line.strip().startswith('use alloc::') and 'Box' not in line:
                    # Check next line - if it's not another alloc import, add Box here
                    pass
            # Simpler: just add at the start of alloc imports
            content = content.replace(
                'use alloc::format;',
                'use alloc::boxed::Box;\nuse alloc::format;'
            )
        elif 'use alloc::vec' in content:
            content = content.replace(
                'use alloc::vec',
                'use alloc::boxed::Box;\nuse alloc::vec',
                1
            )

    with open(path, 'w') as f:
        f.write(content)
    print(f"  Fixed {path}")


def fix_path_registry(path):
    with open(path, 'r') as f:
        content = f.read()

    # Make alloc_const pub(crate)
    content = content.replace(
        '    fn alloc_const(&mut self',
        '    pub(crate) fn alloc_const(&mut self'
    )
    
    with open(path, 'w') as f:
        f.write(content)
    print(f"  Fixed {path}")


base = 'src/rvm/analysis/'

print("Phase 2 fixes:")
print("Fixing path_registry.rs...")
fix_path_registry(base + 'path_registry.rs')

print("Fixing translator.rs...")
fix_translator(base + 'translator.rs')

print("Fixing model_extract.rs...")
fix_model_extract(base + 'model_extract.rs')

print("Fixing mod.rs...")
fix_mod(base + 'mod.rs')

print("Done with phase 2 fixes.")
