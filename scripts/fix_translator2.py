#!/usr/bin/env python3
"""Second pass: fix remaining self.ctx references in translator.rs."""
import re

path = 'src/rvm/analysis/translator.rs'
with open(path, 'r') as f:
    content = f.read()

# Fix SmtExpr::and(self.ctx, ...) multiline patterns
# Pattern: SmtExpr::and(self.ctx, &[&X, &Y])
content = re.sub(
    r'SmtExpr::and\(self\.ctx, &\[&self\.(\w+), &(\w+)\]\)',
    r'SmtExpr::and2(self.\1.clone(), \2.clone())',
    content
)
content = re.sub(
    r'SmtExpr::and\(self\.ctx, &\[&(\w+), &(\w+)\]\)',
    r'SmtExpr::and2(\1.clone(), \2.clone())',
    content
)
content = re.sub(
    r'SmtExpr::and\(self\.ctx, &\[(\w+), (\w+)\]\)',
    r'SmtExpr::and2(\1.clone(), \2.clone())',
    content
)
# 3-arg and with self.ctx
content = re.sub(
    r'SmtExpr::and\(self\.ctx, &\[&(\w+)\.(\w+), &(\w+), &(\w+)\]\)',
    r'SmtExpr::And(vec![\1.\2.clone(), \3.clone(), \4.clone()])',
    content
)
content = re.sub(
    r'SmtExpr::and\(self\.ctx, &\[&(\w+), &(\w+), &(\w+)\]\)',
    r'SmtExpr::And(vec![\1.clone(), \2.clone(), \3.clone()])',
    content
)

# Fix SmtExpr::or(self.ctx, ...) patterns
content = re.sub(
    r'SmtExpr::or\(self\.ctx, &\[&(\w+), &(\w+)\]\)',
    r'SmtExpr::or2(\1.clone(), \2.clone())',
    content
)
content = re.sub(
    r'SmtExpr::or\(self\.ctx, &\[&(\w+), &SmtExpr::not\((\w+)\.clone\(\)\)\]\)',
    r'SmtExpr::or2(\1.clone(), SmtExpr::not(\2.clone()))',
    content
)
content = re.sub(
    r'SmtExpr::or\(self\.ctx, (\w+)\)',
    r'SmtExpr::Or(\1)',
    content
)

# Fix multiline SmtExpr::and( \n  self.ctx, ... ) patterns
# These are inside blocks like:
#   let full_pc_cond = SmtExpr::and(
#       self.ctx,
#       &[&self.caller_path_condition, &pc_cond],
#   );
content = re.sub(
    r'SmtExpr::and\(\n\s+self\.ctx,\n\s+&\[&self\.(\w+), &(\w+)\],?\n\s*\)',
    r'SmtExpr::and2(self.\1.clone(), \2.clone())',
    content
)
content = re.sub(
    r'SmtExpr::and\(\n\s+self\.ctx,\n\s+&\[&(\w+), &(\w+)\],?\n\s*\)',
    r'SmtExpr::and2(\1.clone(), \2.clone())',
    content
)
content = re.sub(
    r'SmtExpr::and\(\n\s+self\.ctx, &\[&self\.(\w+), &(\w+)\]\)',
    r'SmtExpr::and2(self.\1.clone(), \2.clone())',
    content
)

# Handle remaining self.ctx by looking at surrounding context
# SmtExpr::and(\n    self.ctx, ... with 3 args
content = re.sub(
    r'SmtExpr::and\(\n\s+self\.ctx,\s*&\[&(\w+)\.(\w+),\s*&(\w+),\s*&(\w+)\]\)',
    r'SmtExpr::And(vec![\1.\2.clone(), \3.clone(), \4.clone()])',
    content
)

# Any remaining SmtExpr::and(self.ctx, ...) on a single line
content = re.sub(
    r'SmtExpr::and\(\s*self\.ctx\s*,',
    r'SmtExpr::and_FIXME(',
    content
)
# Any remaining SmtExpr::or(self.ctx, ...) on a single line  
content = re.sub(
    r'SmtExpr::or\(\s*self\.ctx\s*,',
    r'SmtExpr::or_FIXME(',
    content
)

with open(path, 'w') as f:
    f.write(content)

# Count remaining
import subprocess
result = subprocess.run(['grep', '-c', 'self.ctx', path], capture_output=True, text=True)
count = result.stdout.strip()
print(f"Remaining self.ctx references: {count}")

# Show them
result = subprocess.run(['grep', '-n', 'self.ctx', path], capture_output=True, text=True)
if result.stdout.strip():
    for line in result.stdout.strip().split('\n')[:20]:
        print(f"  {line.strip()}")
