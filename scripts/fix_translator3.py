#!/usr/bin/env python3
"""Third pass: fix FIXME markers in translator.rs."""
import re

path = 'src/rvm/analysis/translator.rs'
with open(path, 'r') as f:
    content = f.read()

# Fix 2-arg and_FIXME patterns (multiline)
# Pattern: SmtExpr::and_FIXME(\n    &[&A, &B],\n)
content = re.sub(
    r'SmtExpr::and_FIXME\(\n\s+&\[&self\.(\w+), &self\.(\w+)\],?\n\s*\)',
    r'SmtExpr::and2(self.\1.clone(), self.\2.clone())',
    content
)
content = re.sub(
    r'SmtExpr::and_FIXME\(\n\s+&\[&self\.(\w+), &(\w+)\],?\n\s*\)',
    r'SmtExpr::and2(self.\1.clone(), \2.clone())',
    content
)
content = re.sub(
    r'SmtExpr::and_FIXME\(\n\s+&\[&(\w+)\.(\w+)\.(\w+)\(\), &(\w+)\],?\n\s*\)',
    r'SmtExpr::and2(\1.\2.\3(), \4.clone())',
    content
)
content = re.sub(
    r'SmtExpr::and_FIXME\(\n\s+&\[&(\w+), &SmtExpr::not\((\w+)\.clone\(\)\)\],?\n\s*\)',
    r'SmtExpr::and2(\1.clone(), SmtExpr::not(\2.clone()))',
    content
)

# Single-line 2-arg patterns
content = re.sub(
    r'SmtExpr::and_FIXME\(\s*&\[&(\w+)\.(\w+), &(\w+)\]\)',
    r'SmtExpr::and2(\1.\2.clone(), \3.clone())',
    content
)
content = re.sub(
    r'SmtExpr::and_FIXME\(\s*&\[&(\w+), &(\w+)\.(\w+)\]\)',
    r'SmtExpr::and2(\1.clone(), \2.\3.clone())',
    content
)
content = re.sub(
    r'SmtExpr::and_FIXME\(\s*&\[&(\w+), &(\w+)\]\)',
    r'SmtExpr::and2(\1.clone(), \2.clone())',
    content
)

# N-arg and_FIXME with refs variable
content = re.sub(
    r'SmtExpr::and_FIXME\(\s*&(\w+)\)',
    r'SmtExpr::And(\1.into_iter().cloned().collect())',
    content
)

# Similarly for or_FIXME (if any)
content = re.sub(
    r'SmtExpr::or_FIXME\(\s*&(\w+)\)',
    r'SmtExpr::Or(\1.into_iter().cloned().collect())',
    content
)
content = re.sub(
    r'SmtExpr::or_FIXME\(\s*&\[&(\w+), &(\w+)\]\)',
    r'SmtExpr::or2(\1.clone(), \2.clone())',
    content
)

with open(path, 'w') as f:
    f.write(content)

# Verify
import subprocess
result = subprocess.run(['grep', '-c', 'FIXME', path], capture_output=True, text=True)
count = result.stdout.strip()
print(f"Remaining FIXME markers: {count}")
if count != "0":
    result = subprocess.run(['grep', '-n', 'FIXME', path], capture_output=True, text=True)
    for line in result.stdout.strip().split('\n')[:20]:
        print(f"  {line}")

result = subprocess.run(['grep', '-c', 'self.ctx', path], capture_output=True, text=True)
print(f"Remaining self.ctx: {result.stdout.strip()}")
