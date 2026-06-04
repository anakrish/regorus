# Parser Robustness Issues

This document catalogs robustness issues identified in `src/parser.rs` that need to be fixed.

## Critical Issues (Potential Runtime Errors)

### 1. Span End Calculation Bug in `parse_empty_set`
**Location:** Line 560  
**Issue:** After consuming the `)` token with `expect()`, the code incorrectly uses `self.tok.1.end` (which points to the *next* token after `)`) instead of `self.end` (which still points to the consumed `)` token).

```rust
// Current (WRONG):
fn parse_empty_set(&mut self) -> Result<Expr> {
    let mut span = self.tok.1.clone();
    self.expect("set(", "while parsing empty set")?;
    self.expect(")", "while parsing empty set")?;
    span.end = self.tok.1.end;  // ❌ Points to next token after )
    Ok(Expr::Set { ... })
}

// Should be:
span.end = self.end;  // ✅ Points to the consumed ) token
```

**Impact:** The span will have an incorrect end position, affecting error reporting and source location tracking.

---

### 2. Column Arithmetic Underflow (`col - 1`)
**Locations:** Lines 195, 648, 1269, 1286, 1372, 1389  
**Issue:** Multiple locations perform `col - 1` arithmetic when calling `source.error()`. With the new guards in `Source::message` that reject `col == 0`, these operations produce column 0 when `col == 1`, triggering the guard and returning a generic "invalid source location" message instead of the specific error.

**Examples:**

**Line 195** - `handle_import_future_keywords`:
```rust
self.source.error(s.line, s.col - 1, "invalid future keyword")
```

**Line 648** - `parse_ref`:
```rust
self.source.error(
    field.line,
    field.col - 1,
    "invalid whitespace between . and identifier"
)
```

**Line 1269** - `parse_path_ref`:
```rust
self.source.error(
    self.tok.1.line,
    self.tok.1.col - 1,
    format!("invalid whitespace before {}", self.token_text()).as_str()
)
```

**Line 1286** - `parse_path_ref`:
```rust
self.source.error(
    field.line,
    field.col - 1,
    "invalid whitespace between . and identifier"
)
```

**Line 1372** - `parse_rule_ref`:
```rust
self.source.error(
    self.tok.1.line,
    self.tok.1.col - 1,
    format!("invalid whitespace before {}", self.token_text()).as_str()
)
```

**Line 1389** - `parse_rule_ref`:
```rust
self.source.error(
    field.line,
    field.col - 1,
    "invalid whitespace between . and identifier"
)
```

**Recommended Fix:** Use saturating arithmetic with a minimum of 1:
```rust
// Replace all instances of:
col - 1

// With:
col.saturating_sub(1).max(1)
```

---

### 3. Array Indexing Without Explicit Bounds Checks
**Locations:** Lines 184, 192, 1079, 1827  
**Issue:** Direct array indexing (`comps[2]`, `vars[2]`, etc.) without explicit bounds checks. While the logic may ensure arrays have sufficient elements, this is fragile and could panic if assumptions change.

**Line 184** - `handle_import_future_keywords`:
```rust
match comps.len() - 2 {
    1 => self.set_future_keyword(comps[2].text(), &Some(comps[2].clone()))?,
    //                            ^^^^^^^^ Assumes comps.len() >= 3
```

**Line 192** - `handle_import_future_keywords`:
```rust
_ => {
    let s = &comps[3];  // Assumes comps.len() >= 4
    return Err(self.source.error(s.line, s.col - 1, "invalid future keyword"));
}
```

**Line 1079** - `parse_some_stmt`:
```rust
let (key, value) = match refs.len() {
    2 => (Some(refs[0].clone()), refs[1].clone()),
    1 => (None, refs[0].clone()),
    _ => {
        let span = &vars[2];  // ❌ Could panic if vars.len() < 3
        return Err(anyhow!(...));
    }
};
```

**Line 1827** - `parse_imports`:
```rust
let comps = Self::get_path_ref_components(&refr)?;
// ...
if !matches!(comps[0].text(), "data" | "future" | "input" | "rego") {
    //       ^^^^^^^^ Assumes comps is non-empty
```

**Recommended Fix:** Use `.get()` with proper error handling:
```rust
// Instead of:
let item = comps[2];

// Use:
let item = comps.get(2)
    .ok_or_else(|| anyhow!("internal error: invalid component index"))?;
```

---

## Performance Issues

### 4. Heavy Parser State Cloning for Backtracking
**Locations:** Lines 366, 437, 937, 1143, 1506  
**Issue:** The parser clones its entire state (`let state = self.clone()`) for speculative parsing. This is expensive as it includes:
- Lexer state and token iterator
- BTreeMap for future keywords
- All parser counters and indices

**Examples:**

**Line 366** - `parse_compr`:
```rust
fn parse_compr(&mut self, delim: &str) -> Result<(Expr, Query)> {
    // Save the state.
    let state = self.clone();  // ❌ Clones entire parser
    // ...
    *self = state;  // Restore on failure
}
```

**Line 437** - `parse_compr_or_array`:
```rust
fn parse_compr_or_array(&mut self) -> Result<Expr> {
    // Save the state.
    let mut span = self.tok.1.clone();
    // ... (no explicit state clone here, but relies on parse_compr)
}
```

**Line 937** - `parse_compr_set_or_object`:
```rust
// Similar pattern
```

**Line 1143** - `parse_query`:
```rust
fn parse_query(&mut self, mut span: Span, end_delim: &str) -> Result<Query> {
    let state = self.clone();  // ❌ Clones entire parser
    // ...
}
```

**Line 1506** - `parse_assign_expr`:
```rust
pub fn parse_assign_expr(&mut self) -> Result<Expr> {
    let state = self.clone();  // ❌ Clones entire parser
    // ...
    *self = state;  // Restore if not assignment
}
```

**Impact:** Performance degradation when parsing:
- Complex expressions with comprehensions
- Assignment expressions in rule bodies
- Deeply nested queries

**Possible Optimization:** Consider a lighter-weight checkpoint mechanism:
```rust
struct ParserCheckpoint {
    tok: Token,
    line: u32,
    end: u32,
    eidx: u32,
    sidx: u32,
    qidx: u32,
}

impl Parser {
    fn checkpoint(&self) -> ParserCheckpoint { ... }
    fn restore(&mut self, cp: ParserCheckpoint) { ... }
}
```

---

## Theoretical Issues

### 5. Integer Overflow in Expression/Statement/Query Counters
**Locations:** Throughout parser (fields `eidx`, `sidx`, `qidx`)  
**Issue:** Counters are `u32` and increment without overflow checks. Parsing a policy with 4 billion+ expressions would wrap silently.

```rust
pub struct Parser<'source> {
    // ...
    eidx: u32,  // Could overflow
    sidx: u32,  // Could overflow
    qidx: u32,  // Could overflow
}

fn next_eidx(&mut self) -> u32 {
    let eidx = self.eidx;
    self.eidx += 1;  // No overflow check
    eidx
}
```

**Impact:** Extremely unlikely in practice (no Rego policy would be that large), but technically unsound.

**Possible Fix:** Use `checked_add` or `saturating_add`:
```rust
fn next_eidx(&mut self) -> Result<u32> {
    let eidx = self.eidx;
    self.eidx = self.eidx.checked_add(1)
        .ok_or_else(|| anyhow!("expression count overflow"))?;
    Ok(eidx)
}
```

---

## Summary

| Category | Count | Priority |
|----------|-------|----------|
| Critical (Runtime errors) | 3 issues (8+ locations) | High |
| Performance | 5 locations | Medium |
| Theoretical | 3 counters | Low |

**Priority Order:**
1. **High Priority:**
   - Fix `parse_empty_set` span calculation (line 560)
   - Replace all `col - 1` with saturating arithmetic (6 locations)
   - Add bounds checks for array indexing (4+ locations)

2. **Medium Priority:**
   - Consider optimizing parser cloning for backtracking (5 locations)

3. **Low Priority:**
   - Add overflow checks for counters (mostly theoretical)

---

## Recommendations

1. **Immediate fixes** (High Priority):
   - Replace `span.end = self.tok.1.end` with `span.end = self.end` at line 560
   - Search and replace all instances of `.col - 1` with `.col.saturating_sub(1).max(1)`
   - Add defensive `.get()` checks before array indexing

2. **Future improvements** (Medium Priority):
   - Implement lightweight checkpoint mechanism for backtracking
   - Profile parser performance on complex policies to validate optimization gains

3. **Optional enhancements** (Low Priority):
   - Add overflow checks if targeting extreme edge cases
