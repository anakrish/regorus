# Azure Policy Compiler — Test Coverage Audit

**Date:** 2026-02-17  
**Scope:** All YAML test files under `tests/azure_policy/cases/`, all compiler source files, builtins, parser, AST, and expression parser.

---

## 1. Test File Inventory

| File | # Cases | Focus |
|---|---|---|
| `operators.yaml` | 28 | All 20 operator kinds |
| `expressions.yaml` | 22 | ARM template expressions |
| `logical_combinators.yaml` | 15 | allOf, anyOf, not, nesting |
| `value_conditions.yaml` | 16 | `"value"` LHS conditions |
| `count.yaml` | 16 | Field count, value count, where |
| `fields.yaml` | 14 | FieldKind variants, tags |
| `type_coercion.yaml` | 15 | String↔Number, null, bool |
| `effects.yaml` | 15 | All 9 effect kinds + parameterized |
| `complex_policies.yaml` | 12 | Real-world multi-feature combos |
| `parse_errors.yaml` | 13 | Malformed input rejection |
| **Total** | **166** | |

---

## 2. Feature-by-Feature Coverage Matrix

### 2.1 Logical Combinators (`conditions.rs` → `compile_constraint`)

| Feature | Code Path | Test(s) | Coverage |
|---|---|---|---|
| `allOf` — 2 children | `Constraint::AllOf` | `allOf_two_conditions`, `allOf_partial_match` | ✅ Good |
| `allOf` — 3 children | same | `allOf_three_conditions` | ✅ Good |
| `allOf` — 1 child | same | `allOf_single_condition` | ✅ Good |
| `allOf` — empty array | same | `allOf_empty_array`, `trivial_allOf_empty` | ✅ Good |
| `anyOf` — first matches | `Constraint::AnyOf` | `anyOf_first_matches` | ✅ Good |
| `anyOf` — second matches | same | `anyOf_second_matches` | ✅ Good |
| `anyOf` — no match | same | `anyOf_no_match` | ✅ Good |
| `anyOf` — 3 options | same | `anyOf_three_options` | ✅ Good |
| `not` — true case | `Constraint::Not` | `not_condition` | ✅ Good |
| `not` — false case | same | `not_condition_no_match` | ✅ Good |
| `not(allOf)` | same nested | `not_allOf` | ✅ Good |
| `not(anyOf)` | same nested | `not_anyOf` | ✅ Good |
| `allOf > anyOf` (2 deep) | nested | `allOf_with_nested_anyOf` | ✅ Good |
| `anyOf > allOf` (2 deep) | nested | `anyOf_with_nested_allOf` | ✅ Good |
| `allOf > not` (2 deep) | nested | `allOf_with_not` | ✅ Good |
| `allOf > not > anyOf > allOf` (3+ deep) | nested | `deeply_nested_combinators` | ✅ Good |
| `not > not` (double negation) | nested | `double_negation` | ✅ Good |
| `anyOf` — empty array | `Constraint::AnyOf`, empty | ❌ **NONE** | ⚠️ Gap |
| `not > not > not` (triple negation) | deeply nested | ❌ **NONE** | ⚠️ Gap |
| `anyOf > not > allOf` (3+ deep, different shape) | deeply nested | ❌ **NONE** | ⚠️ Gap |
| 4+ levels deep nesting | deeply nested | ❌ **NONE** | ⚠️ Gap |

### 2.2 Operators (`conditions.rs` → `compile_condition`, `azure_policy.rs`)

| Operator | Positive Test | Negative Test | Null/Undefined Edge | Coverage |
|---|---|---|---|---|
| `equals` | `equals_string`, `equals_number`, `equals_boolean`, `equals_null` | `equals_string_no_match` | `equals_null` (partial) | ✅ Good |
| `notEquals` | `notEquals_string` | `notEquals_no_match` | ❌ No undefined-LHS test | ⚠️ Partial |
| `contains` | `contains_string` | `contains_no_match` | ❌ No null/undefined test | ⚠️ Partial |
| `notContains` | `notContains_string` | ❌ no false case | ❌ No null test | ⚠️ Partial |
| `containsKey` | `containsKey_field` | ❌ no false case | ❌ No null test | ⚠️ Partial |
| `notContainsKey` | `notContainsKey_field` | ❌ no false case | ❌ No null test | ⚠️ Partial |
| `greater` | `greater_number` | `greater_no_match` | ❌ No null/undefined test | ⚠️ Partial |
| `greaterOrEquals` | `greaterOrEquals_equal` | ❌ no false case | ❌ No null test | ⚠️ Partial |
| `less` | `less_number` | ❌ no false case | ❌ No null test | ⚠️ Partial |
| `lessOrEquals` | `lessOrEquals_number` | ❌ no false case | ❌ No null test | ⚠️ Partial |
| `in` | `in_string_array`, `in_number_array` | `in_no_match` | ❌ No null/undefined test | ⚠️ Partial |
| `notIn` | `notIn_string_array` | ❌ no false case | ❌ No null test | ⚠️ Partial |
| `like` | `like_wildcard`, `like_question_mark` | ❌ no false case | ❌ No null test | ⚠️ Partial |
| `notLike` | `notLike_wildcard` | ❌ no false case | ❌ No null test | ⚠️ Partial |
| `match` | `match_pattern` | ❌ no false case | ❌ No null test | ⚠️ Partial |
| `notMatch` | `notMatch_pattern` | ❌ no false case | ❌ No null test | ⚠️ Partial |
| `matchInsensitively` | `matchInsensitively_pattern` | ❌ no false case | ❌ No null test | ⚠️ Partial |
| `notMatchInsensitively` | `notMatchInsensitively_pattern` | ❌ no false case | ❌ No null test | ⚠️ Partial |
| `exists` | `exists_true`, `exists_false`, `exists_string_true` | — | Tested (null/missing → false) | ✅ Good |
| Case-insensitive string equality | Implicit in `equals` | — | — | ⚠️ Not explicitly tested |
| String comparison ordering | Not tested for `greater`/`less` | — | — | ❌ **NONE** |
| `contains` with array LHS | — | — | — | ❌ **NONE** |

### 2.3 ARM Template Expressions (`expressions.rs` → `compile_call_expr`)

| Function | Test(s) | Coverage |
|---|---|---|
| `parameters()` | `expr_parameters_in_value`, `expr_parameters_in_rhs`, `expr_parameters_in_effect` | ✅ Good |
| `field()` | `expr_field_function`, `expr_field_in_concat` | ✅ Good |
| `current()` | `expr_current_in_value_count`, `value_count_with_name_and_where` | ✅ Good |
| `resourceGroup()` | `expr_resourceGroup`, `expr_dot_access` | ✅ Good |
| `subscription()` | `expr_subscription` | ✅ Good |
| `concat()` | `expr_concat_strings`, `expr_concat_with_parameters`, `expr_concat_nested` | ✅ Good |
| `if()` | `expr_if_conditional`, `expr_complex_nested` | ✅ Good |
| `toLower()` | `expr_toLower` | ✅ Good |
| `toUpper()` | `expr_toUpper` | ✅ Good |
| `replace()` | `expr_replace` | ✅ Good |
| `substring()` | `expr_substring` | ✅ Good |
| `length()` | `expr_length` | ✅ Good |
| `add()` | `expr_add` | ✅ Good |
| `equals()` (in-expr) | `expr_if_conditional` (nested) | ✅ Shallow |
| `contains()` (in-expr) | `expr_complex_nested` (nested) | ✅ Shallow |
| `Expr::Dot` (property access) | `expr_dot_access`, `expr_resourceGroup` | ✅ Good |
| `Expr::Index` (bracket access) | `expr_index_access` | ✅ Good |
| Escaped bracket `[[...]` | `escaped_bracket_literal` | ✅ Good |
| `empty()` | ❌ **Not supported in compiler — not tested** | ❌ Gap |
| `bool()` | ❌ Not supported | ❌ N/A |
| `string()` | ❌ Not supported | ❌ N/A |
| `int()` | ❌ Not supported | ❌ N/A |
| `first()` / `last()` | ❌ Not supported | ❌ N/A |
| `not()` (expr-level) | ❌ Not supported | ❌ N/A |
| `and()` / `or()` (expr-level) | ❌ Not supported | ❌ N/A |
| `greater()` / `less()` (expr-level) | ❌ Not supported | ❌ N/A |
| `trim()` / `padLeft()` | ❌ Not supported | ❌ N/A |
| `split()` / `join()` | ❌ Not supported | ❌ N/A |
| `startsWith()` / `endsWith()` | ❌ Not supported | ❌ N/A |
| Unsupported function → **error message** | ❌ No test | ⚠️ Gap |

### 2.4 Nested ARM Expressions

| Pattern | Test | Coverage |
|---|---|---|
| `concat(concat(), ...)` | `expr_concat_nested` | ✅ |
| `if(contains(toLower(field()), ...), ...)` | `expr_complex_nested` | ✅ |
| `concat(field(), field())` | `expr_field_in_concat` | ✅ |
| `concat(parameters(), literal)` | `expr_concat_with_parameters` | ✅ |
| `concat(toLower(field()), parameters())` | ❌ **NONE** | ⚠️ Gap |
| `replace(toLower(field()), ...)` | ❌ **NONE** | ⚠️ Gap |
| `if(equals(...), concat(...), toLower(...))` — all 3 branches complex | ❌ **NONE** | ⚠️ Gap |
| `length(concat(...))` — numeric over string | ❌ **NONE** | ⚠️ Gap |
| `add(length(...), length(...))` — numeric over numeric | ❌ **NONE** | ⚠️ Gap |
| `substring(concat(...), ...)` | ❌ **NONE** | ⚠️ Gap |

### 2.5 FieldKind Variants (`fields.rs` → `compile_field_kind`)

| FieldKind | Test(s) | Coverage |
|---|---|---|
| `Type` | `field_type`, many operators/complex | ✅ Good |
| `Id` | `field_id` | ✅ Good |
| `Kind` | `field_kind` | ✅ Good |
| `Name` | `field_name`, many operators | ✅ Good |
| `Location` | `field_location`, many combinators | ✅ Good |
| `FullName` | `field_fullName` | ✅ Good |
| `Tags` | `field_tags_object` | ✅ Good |
| `IdentityType` | `field_identity_type` | ✅ Good |
| `Tag(name)` — dot notation | `field_tags_dot_notation`, `field_tags_dot_hyphen` | ✅ Good |
| `Tag(name)` — bracket notation | `field_tags_bracket_notation`, `field_tags_bracket_space` | ✅ Good |
| `Alias(path)` — shallow | `field_deep_property` | ✅ Good |
| `Alias(path)` — alias with `/` | Skipped at runtime (alias-resolution check) | ⚠️ Shallow |
| `Expr(expr)` — dynamic field path | `require_tag_environment` only (concat in field) | ⚠️ Shallow |
| `Expr(expr)` — dedicated test | ❌ **NONE** | ⚠️ Gap |
| `resolve_field` builtin — path tokenization, bracket access, array index | ❌ **No direct tests** | ⚠️ Gap |

### 2.6 Count (`count.rs`)

| Feature | Test(s) | Coverage |
|---|---|---|
| Field count — basic | `field_count_basic`, `field_count_direct_path_core` | ✅ Good |
| Field count — equals 0 (missing array) | `field_count_equals_zero` | ✅ Good |
| Field count — with `where` | `field_count_with_where`, `field_count_direct_path_where_core` | ✅ Good |
| Field count `where` + allOf | `field_count_where_allOf` | ✅ Good |
| Field count `where` + anyOf | `field_count_where_anyOf` | ✅ Good |
| Field count `where` + not | `field_count_where_not` | ✅ Good |
| Value count — basic (literal array) | `value_count_basic` | ✅ Good |
| Value count — with name | `value_count_with_name` | ✅ Good |
| Value count — name + where + current() | `value_count_with_name_and_where` | ✅ Good |
| Value count — expression source | `value_count_expression` | ✅ Good |
| Count inside allOf | `count_in_allOf` | ✅ Good |
| Count inside not | `count_in_not` | ✅ Good |
| Value count — nested where with concat+current+exists | `value_count_nested_where` | ✅ Good |
| Field count — empty array (present but []) | ❌ **NONE** | ⚠️ Gap |
| Field count — where matches nothing → count=0 | ❌ **NONE** | ⚠️ Gap |
| Field count — where matches all → count=len | ❌ **NONE** | ⚠️ Gap |
| Value count — empty array [] | ❌ **NONE** | ⚠️ Gap |
| Nested count (count inside count where) | ❌ **NONE** | ⚠️ Gap |
| Count inside anyOf | ❌ **NONE** | ⚠️ Gap |
| current() with property access (current('item').prop) | ❌ **NONE** | ⚠️ Gap |
| Field count where with `current()` via wildcard binding | ❌ explicit test **NONE** | ⚠️ Gap |

### 2.7 Effect Types (`mod.rs` → `compile_effect`)

| Effect | Test(s) | Coverage |
|---|---|---|
| `deny` | `effect_deny` | ✅ Good |
| `audit` | `effect_audit` | ✅ Good |
| `disabled` | `effect_disabled` | ✅ Good |
| `manual` | `effect_manual` | ✅ Good |
| `denyAction` | `effect_denyAction` | ✅ Good |
| `append` | `effect_append` | ✅ Good |
| `modify` | `effect_modify`, `effect_modify_multiple_operations` | ✅ Good |
| `auditIfNotExists` | `effect_auditIfNotExists` | ✅ Good |
| `deployIfNotExists` | `effect_deployIfNotExists` | ✅ Good |
| Parameterized `[parameters('effect')]` | `effect_parameterized` | ✅ Good |
| Parameterized with details | `effect_parameterized_with_details` | ✅ Good |
| Case-insensitive ("Deny", "AUDIT") | `effect_case_insensitive_Deny`, `effect_case_insensitive_AUDIT` | ✅ Good |
| `Other` — unknown literal effect | ❌ **NONE** | ⚠️ Gap |
| `Other` — complex expression effect (concat, if, etc.) | ❌ **NONE** | ⚠️ Gap |

### 2.8 Type Coercion (`azure_policy.rs`)

| Coercion Path | Test(s) | Coverage |
|---|---|---|
| String→Number: `equals` | `coercion_string_number_equals` | ✅ Good |
| Number→String: `equals` | `coercion_number_string_equals` | ✅ Good |
| String→Number: `greater` | `coercion_string_number_greater` | ✅ Good |
| String→Number: `less` | `coercion_string_number_less` | ✅ Good |
| Mixed types in `in` | `coercion_in_with_mixed_types` | ✅ Good |
| Non-numeric string → undefined | `coercion_non_numeric_string` | ✅ Good |
| Null field `exists false` | `null_field_exists_false` | ✅ Good |
| Null field `equals null` | `null_field_equals_null` | ✅ Good |
| Empty string `exists true` | `empty_string_not_undefined` | ✅ Good |
| Bool string ≠ bool value | `bool_string_not_equal` | ✅ Good |
| Bool direct comparison | `bool_equals_direct` | ✅ Good |
| Negative number | `negative_number_rhs` | ✅ Good |
| Fractional number | `fractional_number_rhs` | ✅ Good |
| String→Number: `greaterOrEquals` | ❌ **NONE** | ⚠️ Gap |
| String→Number: `lessOrEquals` | ❌ **NONE** | ⚠️ Gap |
| String→Number: `notEquals` | ❌ **NONE** | ⚠️ Gap |
| Mixed types in `notIn` | ❌ **NONE** | ⚠️ Gap |
| Undefined LHS + any op (undefined propagation) | ❌ except `coercion_non_numeric_string` | ⚠️ Shallow |
| Null LHS + `greater`/`less`/etc. | ❌ **NONE** | ⚠️ Gap |
| String case-insensitive `greater`/`less` | ❌ **NONE** | ⚠️ Gap |

### 2.9 Parse Error Cases (`parser/`)

| Error | Test | Coverage |
|---|---|---|
| Missing `if` key | `missing_if_key` | ✅ |
| Missing `then` key | `missing_then_key` | ✅ |
| Missing `effect` in `then` | `missing_effect_in_then` | ✅ |
| `field` without operator | `field_without_operator` | ✅ |
| `value` without operator | `value_without_operator` | ✅ |
| `allOf` not array | `allOf_not_array` | ✅ |
| `anyOf` not array | `anyOf_not_array` | ✅ |
| `not` not object | `not_not_object` | ✅ |
| Unknown key in condition | `unknown_key_in_condition` | ✅ |
| Count missing field+value | `count_missing_field_and_value` | ✅ |
| Count with both field+value | `count_with_both_field_and_value` | ✅ |
| Malformed expression | `malformed_expression_unclosed_paren` | ✅ |
| Both field and value LHS | `both_field_and_value_lhs` | ✅ |
| Empty object | `empty_object` | ✅ |
| Not an object (string) | `not_an_object` | ✅ |
| Extra keys with `allOf`/`anyOf`/`not` | ❌ **NONE** | ⚠️ Gap |
| Count `name` without `value` | ❌ **NONE** | ⚠️ Gap |
| Count `name` not a string | ❌ **NONE** | ⚠️ Gap |
| `field` value not a string | ❌ **NONE** | ⚠️ Gap |
| Duplicate operators | ❌ **NONE** | ⚠️ Gap |
| Deeply nested malformed JSON | ❌ **NONE** | ⚠️ Gap |

### 2.10 `resolve_field` Builtin

| Feature | Test | Coverage |
|---|---|---|
| Dot path resolution | Implicitly tested via `require_tag_environment` | ⚠️ Shallow |
| Bracket path resolution (tags['key']) | ❌ **NONE** | ⚠️ Gap |
| Array index resolution | ❌ **NONE** | ⚠️ Gap |
| Nested object traversal | ❌ **NONE** | ⚠️ Gap |
| Case-insensitive key lookup | ❌ **NONE** | ⚠️ Gap |
| Undefined when path doesn't exist | ❌ **NONE** | ⚠️ Gap |

---

## 3. Identified Gaps — Detailed

### Gap 1: Empty `anyOf` Array
**Risk:** High — `allOf` empty returns `deny` (all-true), what does `anyOf []` return?  
The code calls `logic_any` with 0 args → `any()` of empty = `false` → undefined. This should be tested.

### Gap 2: Operator Negative/Edge Cases
**Risk:** Medium — Most operators only have 1‒2 tests (positive match). Missing:
- False-case tests for `notContains`, `containsKey`, `notContainsKey`, `greaterOrEquals`, `less`, `lessOrEquals`, `like`, `match`, etc.
- Null/undefined LHS for every comparison operator
- String-comparison ordering for `greater`/`less`

### Gap 3: `contains` with Array LHS
**Risk:** Medium — The builtin supports `Array.contains(value)` and `String.contains(substring)`, but tests only cover string form.

### Gap 4: Nested ARM Expression Composition
**Risk:** Medium — Only 2 truly deeply nested expression tests exist. Missing combinations like `concat(toLower(), parameters())`.

### Gap 5: `FieldKind::Expr` Dedicated Testing
**Risk:** High — The `resolve_field` path (dynamic field paths from expressions) is only indirectly tested via one complex policy.

### Gap 6: Count Edge Cases
**Risk:** Medium — No tests for: where-matches-nothing, where-matches-all, empty-present-array, nested count, count inside anyOf, value count with empty array.

### Gap 7: Type Coercion Completeness
**Risk:** Medium — Coercion tested for `equals`/`in`/`greater`/`less` but not `greaterOrEquals`, `lessOrEquals`, `notEquals`, `notIn` with mixed types.

### Gap 8: Parse Error Completeness
**Risk:** Low — Several parser error variants (`ExtraKeysInLogical`, `MisplacedCountName`, `InvalidCountName`, field-value-not-string) are untested.

### Gap 9: `Other` Effect Kind
**Risk:** Low — An unrecognized literal effect string (not an expression) would produce `EffectKind::Other` → loads as literal. Never tested.

### Gap 10: Unsupported Function Error
**Risk:** Low — Calling an unknown function like `empty()` should produce a clear error. Never tested.

---

## 4. Suggested Test Cases

### 4.1 Empty `anyOf` Array

```yaml
  - note: anyOf_empty_array
    policy_rule: |
      {
        "if": {
          "anyOf": []
        },
        "then": { "effect": "deny" }
      }
    resource:
      type: "anything"
    want_undefined: true
```

### 4.2 Operator Negative/Edge Cases — Null and Undefined LHS

```yaml
  # In operators.yaml or type_coercion.yaml:

  - note: greater_undefined_lhs
    policy_rule: |
      {
        "if": {
          "field": "properties.nonexistent",
          "greater": 5
        },
        "then": { "effect": "deny" }
      }
    resource:
      properties: {}
    want_undefined: true

  - note: less_undefined_lhs
    policy_rule: |
      {
        "if": {
          "field": "properties.nonexistent",
          "less": 5
        },
        "then": { "effect": "deny" }
      }
    resource:
      properties: {}
    want_undefined: true

  - note: contains_undefined_lhs
    policy_rule: |
      {
        "if": {
          "field": "properties.nonexistent",
          "contains": "foo"
        },
        "then": { "effect": "deny" }
      }
    resource:
      properties: {}
    want_undefined: true

  - note: containsKey_undefined_lhs
    policy_rule: |
      {
        "if": {
          "field": "properties.nonexistent",
          "containsKey": "foo"
        },
        "then": { "effect": "deny" }
      }
    resource:
      properties: {}
    want_undefined: true

  - note: like_undefined_lhs
    policy_rule: |
      {
        "if": {
          "field": "properties.nonexistent",
          "like": "foo*"
        },
        "then": { "effect": "deny" }
      }
    resource:
      properties: {}
    want_undefined: true

  - note: match_undefined_lhs
    policy_rule: |
      {
        "if": {
          "field": "properties.nonexistent",
          "match": "foo##"
        },
        "then": { "effect": "deny" }
      }
    resource:
      properties: {}
    want_undefined: true

  - note: in_undefined_lhs
    policy_rule: |
      {
        "if": {
          "field": "properties.nonexistent",
          "in": ["a", "b"]
        },
        "then": { "effect": "deny" }
      }
    resource:
      properties: {}
    want_undefined: true

  - note: notEquals_undefined_lhs
    policy_rule: |
      {
        "if": {
          "field": "properties.nonexistent",
          "notEquals": "something"
        },
        "then": { "effect": "deny" }
      }
    resource:
      properties: {}
    want_effect: "deny"

  - note: notIn_undefined_lhs
    policy_rule: |
      {
        "if": {
          "field": "properties.nonexistent",
          "notIn": ["a", "b"]
        },
        "then": { "effect": "deny" }
      }
    resource:
      properties: {}
    want_effect: "deny"

  - note: notContains_undefined_lhs
    policy_rule: |
      {
        "if": {
          "field": "properties.nonexistent",
          "notContains": "foo"
        },
        "then": { "effect": "deny" }
      }
    resource:
      properties: {}
    want_effect: "deny"

  - note: notLike_undefined_lhs
    policy_rule: |
      {
        "if": {
          "field": "properties.nonexistent",
          "notLike": "foo*"
        },
        "then": { "effect": "deny" }
      }
    resource:
      properties: {}
    want_effect: "deny"
```

### 4.3 String Comparison with `greater`/`less`

```yaml
  - note: greater_string_comparison
    policy_rule: |
      {
        "if": {
          "field": "name",
          "greater": "alpha"
        },
        "then": { "effect": "audit" }
      }
    resource:
      name: "beta"
    want_effect: "audit"

  - note: less_string_comparison
    policy_rule: |
      {
        "if": {
          "field": "name",
          "less": "beta"
        },
        "then": { "effect": "audit" }
      }
    resource:
      name: "alpha"
    want_effect: "audit"
```

### 4.4 `contains` with Array LHS

```yaml
  - note: contains_array_lhs
    policy_rule: |
      {
        "if": {
          "field": "properties.allowedProtocols",
          "contains": "TCP"
        },
        "then": { "effect": "audit" }
      }
    resource:
      properties:
        allowedProtocols: ["TCP", "UDP", "ICMP"]
    want_effect: "audit"

  - note: contains_array_lhs_no_match
    policy_rule: |
      {
        "if": {
          "field": "properties.allowedProtocols",
          "contains": "SSH"
        },
        "then": { "effect": "audit" }
      }
    resource:
      properties:
        allowedProtocols: ["TCP", "UDP"]
    want_undefined: true
```

### 4.5 Nested ARM Expression Composition

```yaml
  - note: expr_concat_tolower_parameters
    policy_rule: |
      {
        "if": {
          "value": "[concat(toLower(field('name')), '-', parameters('suffix'))]",
          "equals": "my-vm-prod"
        },
        "then": { "effect": "audit" }
      }
    parameters:
      suffix: "prod"
    resource:
      name: "My-VM"
    want_effect: "audit"

  - note: expr_length_of_concat
    policy_rule: |
      {
        "if": {
          "value": "[length(concat(parameters('prefix'), parameters('suffix')))]",
          "greater": 5
        },
        "then": { "effect": "audit" }
      }
    parameters:
      prefix: "prod"
      suffix: "-server"
    resource:
      type: "any"
    want_effect: "audit"

  - note: expr_add_length_length
    policy_rule: |
      {
        "if": {
          "value": "[add(length(parameters('list1')), length(parameters('list2')))]",
          "greater": 3
        },
        "then": { "effect": "audit" }
      }
    parameters:
      list1: ["a", "b"]
      list2: ["c", "d"]
    resource:
      type: "any"
    want_effect: "audit"

  - note: expr_if_all_branches_complex
    policy_rule: |
      {
        "if": {
          "value": "[if(equals(parameters('env'), 'prod'), concat('deny-', parameters('env')), toLower(parameters('env')))]",
          "equals": "deny-prod"
        },
        "then": { "effect": "audit" }
      }
    parameters:
      env: "prod"
    resource:
      type: "any"
    want_effect: "audit"

  - note: expr_substring_concat
    policy_rule: |
      {
        "if": {
          "value": "[substring(concat('Hello', 'World'), 0, 5)]",
          "equals": "Hello"
        },
        "then": { "effect": "audit" }
      }
    resource:
      type: "any"
    want_effect: "audit"

  - note: expr_replace_tolower
    policy_rule: |
      {
        "if": {
          "value": "[replace(toLower(field('name')), '-', '_')]",
          "equals": "my_vm"
        },
        "then": { "effect": "audit" }
      }
    resource:
      name: "My-VM"
    want_effect: "audit"
```

### 4.6 Dedicated `FieldKind::Expr` Tests

```yaml
  - note: field_expr_concat_tags
    policy_rule: |
      {
        "if": {
          "field": "[concat('tags[', 'environment', ']')]",
          "equals": "production"
        },
        "then": { "effect": "audit" }
      }
    resource:
      tags:
        environment: "production"
    want_effect: "audit"

  - note: field_expr_concat_missing
    policy_rule: |
      {
        "if": {
          "field": "[concat('tags[', 'nonexistent', ']')]",
          "exists": false
        },
        "then": { "effect": "audit" }
      }
    resource:
      tags:
        environment: "production"
    want_effect: "audit"

  - note: field_expr_concat_parameters_tag
    policy_rule: |
      {
        "if": {
          "field": "[concat('tags[', parameters('tagName'), ']')]",
          "exists": true
        },
        "then": { "effect": "audit" }
      }
    parameters:
      tagName: "environment"
    resource:
      tags:
        environment: "production"
    want_effect: "audit"
```

### 4.7 Count Edge Cases

```yaml
  - note: field_count_present_empty_array
    policy_rule: |
      {
        "if": {
          "count": {
            "field": "securityRules[*]"
          },
          "equals": 0
        },
        "then": { "effect": "audit" }
      }
    resource:
      securityRules: []
    want_effect: "audit"

  - note: field_count_where_matches_nothing
    policy_rule: |
      {
        "if": {
          "count": {
            "field": "securityRules[*]",
            "where": {
              "field": "securityRules[*].access",
              "equals": "SuperAllow"
            }
          },
          "equals": 0
        },
        "then": { "effect": "audit" }
      }
    resource:
      securityRules:
        - { "access": "Allow" }
        - { "access": "Deny" }
    want_effect: "audit"

  - note: field_count_where_matches_all
    policy_rule: |
      {
        "if": {
          "count": {
            "field": "securityRules[*]",
            "where": {
              "field": "securityRules[*].access",
              "equals": "Allow"
            }
          },
          "equals": 3
        },
        "then": { "effect": "audit" }
      }
    resource:
      securityRules:
        - { "access": "Allow" }
        - { "access": "Allow" }
        - { "access": "Allow" }
    want_effect: "audit"

  - note: value_count_empty_literal_array
    policy_rule: |
      {
        "if": {
          "count": {
            "value": []
          },
          "equals": 0
        },
        "then": { "effect": "audit" }
      }
    resource:
      type: "any"
    want_effect: "audit"

  - note: count_inside_anyOf
    policy_rule: |
      {
        "if": {
          "anyOf": [
            {
              "count": {
                "field": "securityRules[*]"
              },
              "greater": 10
            },
            {
              "field": "type",
              "equals": "Microsoft.Network/networkSecurityGroups"
            }
          ]
        },
        "then": { "effect": "audit" }
      }
    resource:
      type: "Microsoft.Network/networkSecurityGroups"
      securityRules:
        - { "name": "r1" }
    want_effect: "audit"

  - note: value_count_current_property_access
    policy_rule: |
      {
        "if": {
          "count": {
            "value": "[parameters('items')]",
            "name": "item",
            "where": {
              "value": "[current('item')]",
              "notEquals": "skip"
            }
          },
          "greater": 0
        },
        "then": { "effect": "audit" }
      }
    parameters:
      items: ["keep", "skip", "also-keep"]
    resource:
      type: "any"
    want_effect: "audit"
```

### 4.8 Deeply Nested Structures (4+ levels)

```yaml
  - note: four_level_nesting
    policy_rule: |
      {
        "if": {
          "allOf": [
            {
              "field": "type",
              "equals": "Microsoft.Compute/virtualMachines"
            },
            {
              "anyOf": [
                {
                  "not": {
                    "allOf": [
                      { "field": "location", "equals": "eastus" },
                      { "field": "tags.env", "equals": "prod" }
                    ]
                  }
                },
                {
                  "not": {
                    "anyOf": [
                      { "field": "kind", "equals": "special" },
                      { "field": "name", "contains": "test" }
                    ]
                  }
                }
              ]
            }
          ]
        },
        "then": { "effect": "deny" }
      }
    resource:
      type: "Microsoft.Compute/virtualMachines"
      location: "westus"
      tags:
        env: "staging"
      kind: "regular"
      name: "prod-vm-01"
    want_effect: "deny"

  - note: triple_negation
    policy_rule: |
      {
        "if": {
          "not": {
            "not": {
              "not": {
                "field": "type",
                "equals": "Microsoft.Compute/virtualMachines"
              }
            }
          }
        },
        "then": { "effect": "deny" }
      }
    resource:
      type: "Microsoft.Storage/storageAccounts"
    want_effect: "deny"
```

### 4.9 Type Coercion Completeness

```yaml
  - note: coercion_string_number_greaterOrEquals
    policy_rule: |
      {
        "if": {
          "field": "properties.port",
          "greaterOrEquals": 443
        },
        "then": { "effect": "deny" }
      }
    resource:
      properties:
        port: "443"
    want_effect: "deny"

  - note: coercion_string_number_lessOrEquals
    policy_rule: |
      {
        "if": {
          "field": "properties.port",
          "lessOrEquals": 1024
        },
        "then": { "effect": "deny" }
      }
    resource:
      properties:
        port: "443"
    want_effect: "deny"

  - note: coercion_string_number_notEquals
    policy_rule: |
      {
        "if": {
          "field": "properties.port",
          "notEquals": 80
        },
        "then": { "effect": "deny" }
      }
    resource:
      properties:
        port: "443"
    want_effect: "deny"

  - note: coercion_mixed_types_notIn
    policy_rule: |
      {
        "if": {
          "field": "properties.port",
          "notIn": [22, 80]
        },
        "then": { "effect": "deny" }
      }
    resource:
      properties:
        port: "443"
    want_effect: "deny"

  - note: null_lhs_greater
    policy_rule: |
      {
        "if": {
          "field": "properties.optionalCount",
          "greater": 0
        },
        "then": { "effect": "deny" }
      }
    resource:
      properties: {}
    want_undefined: true
```

### 4.10 `Other` Effect Kind and Unsupported Function Error

```yaml
  - note: effect_unknown_literal
    policy_rule: |
      {
        "if": {
          "field": "type",
          "equals": "Microsoft.Compute/virtualMachines"
        },
        "then": { "effect": "customEffect" }
      }
    resource:
      type: "Microsoft.Compute/virtualMachines"
    want_effect: "customEffect"
```

### 4.11 Parse Error Completeness

```yaml
  - note: allOf_with_extra_keys
    policy_rule: |
      {
        "if": {
          "allOf": [
            { "field": "type", "equals": "any" }
          ],
          "field": "location",
          "equals": "eastus"
        },
        "then": { "effect": "deny" }
      }
    want_parse_error: true

  - note: count_name_without_value
    policy_rule: |
      {
        "if": {
          "count": {
            "field": "items[*]",
            "name": "item"
          },
          "equals": 0
        },
        "then": { "effect": "deny" }
      }
    want_parse_error: true

  - note: count_name_not_string
    policy_rule: |
      {
        "if": {
          "count": {
            "value": ["a", "b"],
            "name": 42
          },
          "equals": 0
        },
        "then": { "effect": "deny" }
      }
    want_parse_error: true

  - note: field_value_not_string
    policy_rule: |
      {
        "if": {
          "field": 42,
          "equals": "something"
        },
        "then": { "effect": "deny" }
      }
    want_parse_error: true
```

### 4.12 Case-Insensitive String `equals`

```yaml
  - note: equals_case_insensitive
    policy_rule: |
      {
        "if": {
          "field": "type",
          "equals": "microsoft.compute/virtualmachines"
        },
        "then": { "effect": "deny" }
      }
    resource:
      type: "Microsoft.Compute/virtualMachines"
    want_effect: "deny"
```

### 4.13 Count with `where` Nested Combinators

```yaml
  - note: field_count_where_not_allOf
    policy_rule: |
      {
        "if": {
          "count": {
            "field": "securityRules[*]",
            "where": {
              "not": {
                "allOf": [
                  {
                    "field": "securityRules[*].access",
                    "equals": "Deny"
                  },
                  {
                    "field": "securityRules[*].direction",
                    "equals": "Outbound"
                  }
                ]
              }
            }
          },
          "greater": 0
        },
        "then": { "effect": "deny" }
      }
    resource:
      securityRules:
        - { "access": "Allow", "direction": "Inbound" }
        - { "access": "Deny", "direction": "Outbound" }
    want_effect: "deny"
```

---

## 5. Summary

### Coverage Statistics

| Category | Features | Tested | Gaps |
|---|---|---|---|
| Logical Combinators | 21 | 17 | 4 |
| Operators | 22 | 15 (positive only) | 7+ (negative/edge) |
| Expressions (functions) | 15 supported | 15 | 0 (but 11+ unsupported funcs) |
| Nested Expressions | 10 patterns | 4 | 6 |
| Field Kinds | 11 | 9 well-tested | 2 (Expr, Alias w/ alias-resolution) |
| Count | 17 patterns | 10 | 7 |
| Effects | 14 | 12 | 2 |
| Type Coercion | 18 | 13 | 5 |
| Parse Errors | 19 variants | 15 | 4 |
| resolve_field | 6 paths | 1 (shallow) | 5 |

### Priority Recommendations

1. **HIGH** — Add null/undefined LHS tests for all operators (§4.2). This is the single biggest category of missing coverage and likely to surface real bugs.
2. **HIGH** — Add dedicated `FieldKind::Expr` tests (§4.6). The dynamic field path / `resolve_field` path is essentially untested in isolation.
3. **HIGH** — Add count edge cases (§4.7): empty arrays, where-matches-nothing, where-matches-all. These are common real-world scenarios.
4. **MEDIUM** — Add nested expression composition tests (§4.5). Ensures the compiler's recursive expression handling works for realistic patterns.
5. **MEDIUM** — Add type coercion completeness tests (§4.9). Ensures `greaterOrEquals`, `lessOrEquals`, `notEquals`, `notIn` all coerce correctly.
6. **MEDIUM** — Add parse error completeness (§4.11). Ensures parser rejects malformed inputs with the right error variant.
7. **LOW** — Add `anyOf []` empty (§4.1), `Other` effect (§4.10), triple negation (§4.8).
8. **LOW** — Add case-insensitive string `equals` explicit test (§4.12) — implicitly works but worth documenting.
