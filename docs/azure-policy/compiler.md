# Azure Policy JSON → RVM Compiler — Design and Plan

This document presents the analysis and implementation plan for compiling Azure
Policy JSON into RVM bytecode. For alias design decisions, see
[Alias Design Discussion](aliases.md). For normalization details, see
[Alias Normalization](alias-normalization.md).

---

## 1. Azure Policy JSON Language

### 1.1 Overview

Azure Policy uses a JSON-based domain-specific language to express resource
compliance rules. A policy rule has two parts:

```json
{
  "if": { <condition> },
  "then": { "effect": "<effect-name>", "details": { ... } }
}
```

The **`if`** clause is a boolean condition tree over resource fields. The
**`then`** clause specifies what happens when the condition matches (deny,
audit, modify, etc.).

### 1.2 Condition Language

Azure Policy conditions are a tree of logical connectives and field comparisons.

#### Logical operators

```json
{ "allOf": [ <condition>, <condition>, ... ] }    // AND
{ "anyOf": [ <condition>, <condition>, ... ] }    // OR
{ "not": <condition> }                             // NOT
```

#### Field conditions

A field condition compares a resource field against a value:

```json
{ "field": "<field-path>", "<operator>": <value> }
```

#### Comparison operators

| Operator | Semantics | RVM mapping |
|:---------|:----------|:-----------|
| `equals` | Exact equality (case-insensitive for strings) | `BuiltinCall` (`azure.policy.compare`) + `Eq` vs 0 |
| `notEquals` | Inequality (case-insensitive for strings) | `BuiltinCall` (`azure.policy.compare`) + `Ne` vs 0 |
| `greater` | Greater than (case-insensitive for strings) | `BuiltinCall` (`azure.policy.compare`) + `Gt` vs 0 |
| `greaterOrEquals` | Greater or equal (case-insensitive for strings) | `BuiltinCall` (`azure.policy.compare`) + `Ge` vs 0 |
| `less` | Less than (case-insensitive for strings) | `BuiltinCall` (`azure.policy.compare`) + `Lt` vs 0 |
| `lessOrEquals` | Less or equal (case-insensitive for strings) | `BuiltinCall` (`azure.policy.compare`) + `Le` vs 0 |
| `like` | Glob-style pattern match (case-insensitive) | `BuiltinCall` (`azure.policy.like`) |
| `notLike` | Negated glob match | `BuiltinCall` (`azure.policy.like`) + `Not` |
| `match` | Custom pattern match (`#`=digit, `?`=letter) | `BuiltinCall` (`azure.policy.match`) |
| `notMatch` | Negated pattern match | `BuiltinCall` + `Not` |
| `matchInsensitively` | Case-insensitive pattern match | `BuiltinCall` (`azure.policy.match_insensitively`) |
| `notMatchInsensitively` | Negated case-insensitive pattern match | `BuiltinCall` + `Not` |
| `in` | Value in set (case-insensitive for strings) | `BuiltinCall` (`azure.policy.in`) |
| `notIn` | Value not in set | `BuiltinCall` (`azure.policy.in`) + `Not` |
| `contains` | String/array contains (case-insensitive) | `BuiltinCall` (`azure.policy.contains`) |
| `notContains` | Negated contains | `BuiltinCall` (`azure.policy.contains`) + `Not` |
| `containsKey` | Object has key | `Contains` |
| `notContainsKey` | Object lacks key | `Contains` + `Not` |
| `exists` | Field is defined (true) / undefined (false) | `AssertNotUndefined` / `Not` |

#### Value conditions

Compare a computed value (from a `count` or `value`) against a literal:

```json
{ "value": "<template-expression>", "<operator>": <value> }
{ "count": { "field": "<array-field>[*]" }, "<operator>": <value> }
{ "count": { "field": "<array-field>[*]", "where": <condition> }, "<operator>": <value> }
{ "count": { "value": "<expression>", "name": "<binding>", "where": <condition> }, "<operator>": <value> }
```

**`[*]` quantification note**: When `[*]` appears in a **bare field condition**
(not inside count), it means ALL elements must match (universal ∀). When `[*]`
appears inside `count.where`, it refers to the **current** iteration element.
See §6.5 for full scoping rules.

#### Template expressions

String values in Azure Policy can contain ARM template expressions:

| Expression | Maps to | Normalized path |
|:-----------|:--------|:---------------|
| `[parameters('paramName')]` | Policy parameter | `input.parameters.paramName` |
| `[field('aliasName')]` | Resource field value | `input.resource.<shortName>` |
| `[resourceGroup().name]` | Resource group info | `input.context.resourceGroup.name` |
| `[subscription().subscriptionId]` | Subscription info | `input.context.subscription.subscriptionId` |
| `[concat(a, b)]` | String concatenation | `BuiltinCall` (concat) |
| `[if(cond, a, b)]` | Conditional value | Conditional logic |
| `[toLower(s)]` | Lowercase | `BuiltinCall` (lower) |
| `[toUpper(s)]` | Uppercase | `BuiltinCall` (upper) |

### 1.3 Effects

The `then` clause produces an effect value. For the full effects strategy
(precedence, cross-resource evaluation, parameterized effects, compilation
details), see [effects.md](effects.md).

| Effect | Semantics |
|:-------|:----------|
| `Deny` | Block resource creation/update |
| `Audit` | Log non-compliance |
| `AuditIfNotExists` | Audit if related resource missing |
| `DeployIfNotExists` | Deploy related resource if missing |
| `Modify` | Mutate resource fields |
| `Append` | Add fields to resource |
| `Disabled` | Policy inactive |
| `Manual` | Manual compliance tracking |
| `DenyAction` | Block specific actions |

### 1.4 Feature Complexity Tiers

| Tier | Features | Difficulty |
|:-----|:---------|:-----------|
| **T1 — Core** | `allOf`, `field`+scalar comparisons, simple effects (deny/audit/disabled) | Straightforward |
| **T2 — Standard** | `anyOf`, `not`, `in`/`notIn`, `like`/`match`, `exists`, `contains`/`containsKey`, `denyAction` | Moderate |
| **T3 — Iteration** | `[*]` bare field conditions (universal ∀), simple `count` (no where), nested `[*]` | Requires loop emission with correct quantifier |
| **T3b — Count** | `count` with `where`, `current()`, value count, nested counts, De Morgan with `not`+`[*]` | Count scope stack, per-element iteration |
| **T4 — Expressions** | `[parameters()]`, `[field()]`, `[concat()]`, `[if()]`, `[resourceGroup()]`, `[current()]` | Template parser needed |
| **T5 — Advanced effects** | `modify` (add/replace/remove/addOrReplace operations, including `[*]` targets), `append` | Object manipulation instructions |
| **T6 — Cross-resource** | `auditIfNotExists`, `deployIfNotExists` (related resource queries) | Requires `HostAwait` |

**Note**: Azure Policy *initiatives* (policy sets, parameter pass-through,
exemptions) are a host orchestration concern, not a compiler feature. Each
policy in an initiative compiles individually; the host dispatches the resource
to each compiled program and aggregates results.

**Other host-side concerns** (not part of the compiler) — see
[host-side-features.md](host-side-features.md) for detailed descriptions:
- **Policy exemptions** (waiver/mitigated) — host skips evaluation
- **Resource selectors** (`resourceSelectors`) — host filters which resources
  are evaluated against a policy by location, resource type, etc.
- **Policy mode** (`All`, `Indexed`, `Microsoft.Kubernetes.Data`) — affects
  which resources are in scope; host determines applicability
- **Assignment overrides** — host can override the effect at assignment level
- **Non-compliance messages** (`nonComplianceMessages`) — assignment-level
  display text, not part of the compiled rule
- **Compliance reason codes** — enriched compliance results added by the host

### 1.5 Case-insensitivity

Azure Policy is case-insensitive in several dimensions:

| What | Case-insensitive? | Handling |
|:-----|:-------------------|:---------|
| Operator names (`"equals"`, `"Equals"`, `"EQUALS"`) | Yes | Parser normalizes to lowercase during parsing |
| String comparisons (`equals`, `notEquals`, `in`, etc.) | Yes | Custom comparison builtins handle internally (§6.2.2) |
| `like`/`notLike` patterns | Yes | `azure.policy.like` builtin handles internally |
| `match`/`notMatch` patterns | No (by design) | Use `matchInsensitively` for case-insensitive |
| Field names in aliases | Yes | Handled by normalization (see [alias-normalization.md]) |

---

## 2. Compiler Architecture

### 2.1 Pipeline

```
Azure Policy JSON
       │
       ▼
   ┌───────┐
   │ Parse │  JSON string → typed AST
   └───┬───┘
       │ PolicyRule AST
       ▼
   ┌──────────┐
   │ Validate │  Structural validation, operator checks
   └────┬─────┘
        │ validated AST
        ▼
   ┌──────────┐
   │ Compile  │  AST → RVM instructions
   └────┬─────┘
        │ Program
        ▼
   ┌──────────┐
   │ Finalize │  Entry points, rule tree, metadata
   └────┬─────┘
        │ Arc<Program>
        ▼
    Serializable bytecode
```

### 2.2 Where it lives

```
src/languages/
├── azure_rbac/         # Existing: RBAC condition language
├── azure_policy/       # NEW: Azure Policy JSON language
│   ├── mod.rs          # Public API, feature gate
│   ├── ast/            # AST type definitions
│   │   ├── mod.rs
│   │   ├── condition.rs    # Condition tree types
│   │   ├── effect.rs       # Effect types
│   │   ├── expression.rs   # Template expression types
│   │   └── field.rs        # Field path types
│   ├── parser/         # JSON → AST
│   │   ├── mod.rs
│   │   ├── condition.rs    # Condition parsing
│   │   ├── expression.rs   # Template expression parsing
│   │   └── field.rs        # Field path parsing
│   └── compiler/       # AST → RVM Program
│       ├── mod.rs          # Compiler struct, public entry point
│       ├── conditions.rs   # Condition compilation
│       ├── fields.rs       # Field access compilation
│       ├── effects.rs      # Effect compilation
│       ├── expressions.rs  # Template expression compilation
│       ├── count.rs        # Count expression compilation
│       └── loops.rs        # [*] iteration compilation
├── mod.rs              # Module declarations
└── rego/               # Existing: Rego language
```

Feature gated under `#[cfg(feature = "azure_policy")]`.

---

## 3. AST Design

### 3.1 Policy Rule

```rust
/// A complete Azure Policy rule definition
pub struct PolicyRule {
    /// The condition that triggers the effect
    pub condition: Condition,
    /// The effect to apply when the condition matches
    pub effect: Effect,
}
```

### 3.2 Conditions

```rust
/// Boolean condition tree
pub enum Condition {
    /// Logical AND: all conditions must be true
    AllOf(Vec<Condition>),
    /// Logical OR: any condition must be true
    AnyOf(Vec<Condition>),
    /// Logical NOT: negate the inner condition
    Not(Box<Condition>),
    /// Field comparison: compare a resource field against a value
    Field(FieldCondition),
    /// Value comparison: compare a computed expression against a value
    Value(ValueCondition),
    /// Count expression: count array elements, optionally with a filter
    Count(CountCondition),
}

/// A comparison of a resource field against a value
pub struct FieldCondition {
    /// The field path (alias short name)
    pub field: FieldPath,
    /// The comparison operator and its operand
    pub comparison: Comparison,
}

/// A comparison of a computed value against a literal
pub struct ValueCondition {
    /// The template expression producing the value
    pub value: Expression,
    /// The comparison operator and its operand
    pub comparison: Comparison,
}

/// Count array elements matching a condition
pub struct CountCondition {
    /// What is being counted
    pub source: CountSource,
    /// Optional filter condition applied to each element
    pub where_condition: Option<Box<Condition>>,
    /// The comparison on the resulting count
    pub comparison: Comparison,
}

/// What a count expression iterates over
pub enum CountSource {
    /// Field count: iterate over an array in the resource
    /// The field path must end in [*]
    Field(FieldPath),
    /// Value count: iterate over an explicit array expression
    Value {
        /// Expression producing the array to iterate (often a parameter)
        value: Expression,
        /// Binding name for `current()` references
        name: String,
    },
}
```

### 3.3 Comparisons

```rust
/// A comparison operator with its target value
pub struct Comparison {
    pub operator: ComparisonOp,
    pub value: ComparisonValue,
}

/// Comparison operators
pub enum ComparisonOp {
    Equals,
    NotEquals,
    Greater,
    GreaterOrEquals,
    Less,
    LessOrEquals,
    Like,
    NotLike,
    Match,
    NotMatch,
    MatchInsensitively,
    NotMatchInsensitively,
    In,
    NotIn,
    Contains,
    NotContains,
    ContainsKey,
    NotContainsKey,
    Exists,
}

/// The right-hand side of a comparison
pub enum ComparisonValue {
    /// A literal JSON value (string, number, boolean, array, object)
    Literal(Value),
    /// A template expression
    Expression(Expression),
}
```

### 3.4 Field Paths

```rust
/// A parsed field path into the normalized resource
pub struct FieldPath {
    /// The raw field string from the policy JSON
    pub raw: String,
    /// Parsed path segments
    pub segments: Vec<FieldSegment>,
}

/// A segment of a field path
pub enum FieldSegment {
    /// Named field access (e.g., "securityRules", "protocol")
    Field(String),
    /// Array wildcard iteration (e.g., "[*]")
    Wildcard,
}
```

For example, `"securityRules[*].protocol"` parses to:

```
[Field("securityRules"), Wildcard, Field("protocol")]
```

And `"networkAcls.defaultAction"` parses to:

```
[Field("networkAcls"), Field("defaultAction")]
```

### 3.5 Template Expressions

```rust
/// ARM template expressions that can appear in string values
pub enum Expression {
    /// Literal string (no template expression)
    Literal(Value),
    /// Parameter reference: [parameters('name')]
    Parameter(String),
    /// Field reference: [field('path')]
    Field(FieldPath),
    /// Current iteration element: [current('name')] or [current('array[*].field')]
    /// Only valid inside count.where
    Current {
        /// The scope name — either a count's field array prefix
        /// (e.g., "securityRules[*]") or a value count's binding name
        name: String,
        /// Optional sub-path after the [*] (e.g., "protocol")
        sub_path: Vec<String>,
    },
    /// Resource group property: [resourceGroup().property]
    ResourceGroup(String),
    /// Subscription property: [subscription().property]
    Subscription(String),
    /// Concatenation: [concat(expr, expr, ...)]
    Concat(Vec<Expression>),
    /// Conditional: [if(condition, true_value, false_value)]
    If {
        condition: Box<Expression>,
        true_value: Box<Expression>,
        false_value: Box<Expression>,
    },
    /// String functions: [toLower(expr)], [toUpper(expr)]
    StringFunction {
        function: StringFunc,
        argument: Box<Expression>,
    },
}

pub enum StringFunc {
    ToLower,
    ToUpper,
    // Note: trim() and replace() are valid ARM template functions but are
    // rarely used in Azure Policy. They can be added when needed.
}
```

### 3.6 Effects

```rust
/// The effect to apply when a policy condition matches
pub struct Effect {
    /// Effect name (deny, audit, modify, etc.)
    pub name: EffectName,
    /// Effect details (specific to each effect type)
    pub details: Option<EffectDetails>,
}

pub enum EffectName {
    Deny,
    Audit,
    AuditIfNotExists,
    DeployIfNotExists,
    Modify,
    Append,
    Disabled,
    Manual,
    DenyAction,
    /// Parameterized: the effect name comes from a parameter
    Parameterized(Expression),
}

/// Effect-specific details
///
/// When the effect is parameterized, the parser picks the EffectDetails
/// variant based on the presence of details fields (operations → Modify,
/// details.type → ExistenceCheck, actionNames → DenyAction, etc.).
/// The host ignores irrelevant details for the resolved effect.
pub enum EffectDetails {
    /// Deny details: optional message
    Deny {
        message: Option<Expression>,
    },

    /// Modify details: mutation operations
    Modify {
        role_definition_ids: Vec<String>,
        conflict_effect: Option<String>,
        operations: Vec<ModifyOperation>,
    },

    /// Append details: array of field-value pairs (legacy)
    Append {
        fields: Vec<AppendField>,
    },

    /// AuditIfNotExists / DeployIfNotExists details
    ExistenceCheck {
        /// Related resource type to query
        resource_type: String,
        /// Specific resource name (optional)
        name: Option<Expression>,
        /// Condition the related resource must satisfy
        existence_condition: Option<Box<Condition>>,
        /// Query scope
        existence_scope: Option<String>,
        /// Resource group to search
        resource_group_name: Option<Expression>,
        /// Evaluation delay
        evaluation_delay: Option<String>,
        /// RBAC roles (required for DINE)
        role_definition_ids: Vec<String>,
        /// ARM deployment spec (DINE only, opaque JSON)
        deployment: Option<Value>,
    },

    /// DenyAction details
    DenyAction {
        action_names: Vec<String>,
        cascade_behaviors: Option<Value>,
    },
}

/// A field-value pair for append effect
pub struct AppendField {
    pub field: FieldPath,
    pub value: Expression,
}

pub struct ModifyOperation {
    pub operation: ModifyOp,
    pub field: FieldPath,
    pub value: Option<Expression>,
}

pub enum ModifyOp {
    Add,
    AddOrReplace,
    Remove,
    // Note: there is no standalone "replace" — addOrReplace covers that case.
}
```

---

## 4. Parser Design

### 4.1 Entry point

```rust
/// Parse an Azure Policy rule JSON string into a typed AST.
pub fn parse_policy_rule(json: &str) -> Result<PolicyRule> {
    let value: serde_json::Value = serde_json::from_str(json)?;
    let obj = value.as_object().ok_or(ParseError::ExpectedObject)?;

    let if_clause = obj.get("if").ok_or(ParseError::MissingIf)?;
    let then_clause = obj.get("then").ok_or(ParseError::MissingThen)?;

    let condition = parse_condition(if_clause)?;
    let effect = parse_effect(then_clause)?;

    Ok(PolicyRule { condition, effect })
}
```

### 4.2 Condition parsing

The condition parser is recursive. The JSON structure is self-describing — the
presence of `allOf`, `anyOf`, `not`, `field`, `value`, or `count` as a key
determines the condition type:

```rust
fn parse_condition(value: &serde_json::Value) -> Result<Condition> {
    let obj = value.as_object().ok_or(ParseError::ExpectedObject)?;

    if let Some(conditions) = obj.get("allOf") {
        let items = conditions.as_array().ok_or(ParseError::ExpectedArray)?;
        let parsed: Vec<Condition> = items.iter()
            .map(parse_condition)
            .collect::<Result<_>>()?;
        return Ok(Condition::AllOf(parsed));
    }

    if let Some(conditions) = obj.get("anyOf") {
        let items = conditions.as_array().ok_or(ParseError::ExpectedArray)?;
        let parsed: Vec<Condition> = items.iter()
            .map(parse_condition)
            .collect::<Result<_>>()?;
        return Ok(Condition::AnyOf(parsed));
    }

    if let Some(inner) = obj.get("not") {
        let parsed = parse_condition(inner)?;
        return Ok(Condition::Not(Box::new(parsed)));
    }

    if let Some(count_obj) = obj.get("count") {
        return parse_count_condition(count_obj, obj);
        // parse_count_condition inspects count_obj for "field" vs "value" key:
        //   "field" → CountSource::Field(parse_field_path(...))
        //   "value" → CountSource::Value { value: parse_expression(...), name: ... }
    }

    if let Some(field_value) = obj.get("field") {
        let field = parse_field_path(field_value)?;
        let comparison = parse_comparison(obj)?;
        return Ok(Condition::Field(FieldCondition { field, comparison }));
    }

    if let Some(value_expr) = obj.get("value") {
        let expr = parse_expression(value_expr)?;
        let comparison = parse_comparison(obj)?;
        return Ok(Condition::Value(ValueCondition {
            value: expr,
            comparison,
        }));
    }

    Err(ParseError::UnrecognizedCondition)
}
```

### 4.3 Field path parsing

Field paths are strings with `.`-delimited segments, `[*]` array wildcards,
and `['key']` bracket notation (used for tag names containing dots):

```rust
fn parse_field_path(value: &serde_json::Value) -> Result<FieldPath> {
    let raw = value.as_str().ok_or(ParseError::ExpectedString)?;

    // Strip resource type prefix if present
    let short_name = strip_resource_type_prefix(raw);

    let mut segments = Vec::new();
    let mut remaining = short_name;

    while !remaining.is_empty() {
        // Handle [*] as a wildcard segment
        if remaining.starts_with("[*]") {
            segments.push(FieldSegment::Wildcard);
            remaining = &remaining[3..];
            if remaining.starts_with('.') {
                remaining = &remaining[1..];
            }
            continue;
        }

        // Handle ['key'] bracket notation (e.g., tags['Acct.CostCenter'])
        if remaining.starts_with("['") {
            let end = remaining.find("']")
                .ok_or(ParseError::UnterminatedBracket)?;
            let key = &remaining[2..end];
            segments.push(FieldSegment::Field(key.to_string()));
            remaining = &remaining[end + 2..];
            if remaining.starts_with('.') {
                remaining = &remaining[1..];
            }
            continue;
        }

        // Find next delimiter (. or [)
        let end = remaining.find(|c: char| c == '.' || c == '[')
            .unwrap_or(remaining.len());
        let name = &remaining[..end];
        if !name.is_empty() {
            segments.push(FieldSegment::Field(name.to_string()));
        }
        remaining = &remaining[end..];
        if remaining.starts_with('.') {
            remaining = &remaining[1..];
        }
    }

    Ok(FieldPath { raw: raw.to_string(), segments })
}
```

### 4.4 Template expression parsing

Template expressions appear as string values wrapped in `[...]`:

```rust
fn parse_expression(value: &serde_json::Value) -> Result<Expression> {
    match value {
        serde_json::Value::String(s) if s.starts_with('[') && s.ends_with(']') => {
            parse_template_expression(&s[1..s.len()-1])
        }
        _ => Ok(Expression::Literal(value_to_regorus(value)?)),
    }
}

fn parse_template_expression(expr: &str) -> Result<Expression> {
    let expr = expr.trim();
    if expr.starts_with("parameters(") {
        let param_name = extract_quoted_arg(expr, "parameters(")?;
        Ok(Expression::Parameter(param_name))
    } else if expr.starts_with("field(") {
        let field_str = extract_quoted_arg(expr, "field(")?;
        let field_path = parse_field_path_from_str(&field_str)?;
        Ok(Expression::Field(field_path))
    } else if expr.starts_with("current(") {
        let name_str = extract_quoted_arg(expr, "current(")?;
        // Parse "securityRules[*]" or "securityRules[*].protocol" or just "myName"
        let (name, sub_path) = parse_current_reference(&name_str)?;
        Ok(Expression::Current { name, sub_path })
    } else if expr.starts_with("resourceGroup()") {
        let prop = extract_property_chain(expr, "resourceGroup()")?;
        Ok(Expression::ResourceGroup(prop))
    } else if expr.starts_with("subscription()") {
        let prop = extract_property_chain(expr, "subscription()")?;
        Ok(Expression::Subscription(prop))
    } else if expr.starts_with("concat(") {
        let args = parse_function_args(expr, "concat(")?;
        let parsed: Vec<Expression> = args.iter()
            .map(|a| parse_expression_from_str(a))
            .collect::<Result<_>>()?;
        Ok(Expression::Concat(parsed))
    } else if expr.starts_with("if(") {
        let args = parse_function_args(expr, "if(")?;
        // if(condition, trueValue, falseValue)
        Ok(Expression::If {
            condition: Box::new(parse_expression_from_str(&args[0])?),
            true_value: Box::new(parse_expression_from_str(&args[1])?),
            false_value: Box::new(parse_expression_from_str(&args[2])?),
        })
    } else if expr.starts_with("toLower(") {
        let arg = extract_single_arg(expr, "toLower(")?;
        Ok(Expression::StringFunction {
            function: StringFunc::ToLower,
            argument: Box::new(parse_expression_from_str(&arg)?),
        })
    } else if expr.starts_with("toUpper(") {
        let arg = extract_single_arg(expr, "toUpper(")?;
        Ok(Expression::StringFunction {
            function: StringFunc::ToUpper,
            argument: Box::new(parse_expression_from_str(&arg)?),
        })
    } else {
        Err(ParseError::UnsupportedTemplateExpression(expr.to_string()))
    }
}
```

### 4.5 Comparison parsing

The comparison operator is the "unknown" key in the condition object — it's
whichever key is NOT `field`, `value`, or `count`:

```rust
fn parse_comparison(obj: &serde_json::Map<String, serde_json::Value>) -> Result<Comparison> {
    // Known non-comparison keys
    let reserved = ["field", "value", "count", "allOf", "anyOf", "not", "where"];

    for (key, val) in obj {
        if reserved.contains(&key.as_str()) {
            continue;
        }
        // Azure Policy operator names are case-insensitive
        let operator = match key.to_lowercase().as_str() {
            "equals" => ComparisonOp::Equals,
            "notequals" => ComparisonOp::NotEquals,
            "greater" => ComparisonOp::Greater,
            "greaterorequals" => ComparisonOp::GreaterOrEquals,
            "less" => ComparisonOp::Less,
            "lessorequals" => ComparisonOp::LessOrEquals,
            "like" => ComparisonOp::Like,
            "notlike" => ComparisonOp::NotLike,
            "match" => ComparisonOp::Match,
            "notmatch" => ComparisonOp::NotMatch,
            "matchinsensitively" => ComparisonOp::MatchInsensitively,
            "notmatchinsensitively" => ComparisonOp::NotMatchInsensitively,
            "in" => ComparisonOp::In,
            "notin" => ComparisonOp::NotIn,
            "contains" => ComparisonOp::Contains,
            "notcontains" => ComparisonOp::NotContains,
            "containskey" => ComparisonOp::ContainsKey,
            "notcontainskey" => ComparisonOp::NotContainsKey,
            "exists" => ComparisonOp::Exists,
            other => return Err(ParseError::UnknownOperator(other.to_string())),
        };
        let value = parse_comparison_value(val)?;
        return Ok(Comparison { operator, value });
    }

    Err(ParseError::MissingComparison)
}
```

---

## 5. Compiler Design

### 5.1 Compiler struct

```rust
pub struct AzurePolicyCompiler {
    /// The output program being built
    program: Program,
    /// Current register counter
    register_counter: u8,
    /// Span information for debugging
    spans: Vec<SpanInfo>,
    /// Literal value deduplication cache
    literal_cache: BTreeMap<Value, u16>,
    /// Builtin function index cache
    builtin_cache: BTreeMap<String, u16>,
    /// The policy rule being compiled
    policy: PolicyRule,
    /// Resource type (for alias resolution context)
    resource_type: Option<String>,
    /// Stack of active count iteration scopes (see §6.5.3)
    /// Used to resolve `current()` references and implicit [*] scoping
    /// inside count.where clauses
    count_scope_stack: Vec<CountScope>,
    /// Next helper rule index (for anyOf multi-definition rules)
    next_rule_index: u16,
}

/// Represents an active count iteration scope
struct CountScope {
    /// The scope identifier:
    /// - For field counts: the array prefix (e.g., "securityRules")
    /// - For value counts: the binding name (e.g., "protocol")
    name: String,
    /// Register holding the current iteration element
    element_reg: u8,
}
```

### 5.2 Entry point

```rust
impl AzurePolicyCompiler {
    /// Compile an Azure Policy JSON rule into an RVM Program.
    pub fn compile(
        policy_json: &str,
        resource_type: Option<&str>,
    ) -> Result<Arc<Program>> {
        let policy_rule = parse_policy_rule(policy_json)?;

        let mut compiler = AzurePolicyCompiler {
            program: Program::new(),
            register_counter: 1,
            spans: Vec::new(),
            literal_cache: BTreeMap::new(),
            builtin_cache: BTreeMap::new(),
            policy: policy_rule,
            resource_type: resource_type.map(|s| s.to_string()),
            count_scope_stack: Vec::new(),
            next_rule_index: 1, // 0 is reserved for the main policy rule
        };

        compiler.compile_policy()?;
        Ok(Arc::new(compiler.finish()?))
    }
}
```

### 5.3 Overall compilation strategy

The compiler produces a **single rule** in the RVM program. The rule:
1. Evaluates the `if` condition.
2. If the condition is true, produces the `then` effect value.
3. If the condition is false, produces `undefined` (the rule doesn't match).

```rust
fn compile_policy(&mut self) -> Result<()> {
    // Register rule
    let rule_index = 0u16;
    let result_reg = self.alloc_register();

    // Entry point: call rule and return
    let entry_offset = self.program.instructions.len();
    self.entry_points.insert("data.policy.eval".to_string(), entry_offset);
    self.emit(Instruction::CallRule { dest: result_reg, rule_index });
    self.emit(Instruction::Return { value: result_reg });

    // Rule body
    let rule_start = self.program.instructions.len();
    self.emit(Instruction::RuleInit { result_reg, rule_index });

    // Evaluate condition
    let condition_reg = self.compile_condition(&self.policy.condition)?;
    self.emit(Instruction::AssertCondition { condition: condition_reg });

    // If condition passed, produce effect value
    let effect_reg = self.compile_effect(&self.policy.effect)?;
    self.emit(Instruction::Move { dest: result_reg, src: effect_reg });

    self.emit(Instruction::RuleReturn {});

    // Record rule info
    self.record_rule(rule_index, rule_start, result_reg)?;

    Ok(())
}
```

### 5.4 Note on parameterized effects

Many Azure policies have the effect name come from a parameter:

```json
{
  "if": { ... },
  "then": { "effect": "[parameters('effect')]" }
}
```

This means the *same* compiled policy can produce `deny`, `audit`, or
`disabled` depending on the parameter value at evaluation time. The compiler
handles this by:

1. Compiling two things: the condition and the effect **object**.
2. The effect object includes the effect name as a field — at runtime, the
   host inspects the returned object to determine which effect was produced.

The compiled rule returns an object like:

```json
{ "effect": "deny", "details": { "message": "..." } }
```

The host inspects this object to determine which effect applies and takes
the appropriate action. Effect validation is the host's responsibility.

---

## 6. Condition Compilation — Instruction Mappings

### 6.1 Logical operators

**`allOf`** — AND chain. Each sub-condition must succeed. Uses
`AssertCondition` to short-circuit:

```
compile(allOf[c₁, c₂, c₃]):
    r₁ = compile(c₁)
    AssertCondition { condition: r₁ }    // fail early if false
    r₂ = compile(c₂)
    AssertCondition { condition: r₂ }
    r₃ = compile(c₃)
    // r₃ is the result
```

**`anyOf`** — OR chain. Any sub-condition succeeding makes the whole thing
succeed. Compiled as **multi-definition rules** — see §6.7 for full details.

Each `anyOf` branch becomes a separate definition of a helper rule. The parent
condition calls the helper via `CallRule`; the VM tries each definition and
succeeds on the first match.

```
compile(anyOf[c₁, c₂, c₃]):
    // Create helper rule "anyof_N" with one definition per branch
    // Each definition compiles one branch in asserting mode
    // Parent: CallRule { dest: r_anyof, rule_index: <helper> }
    //         AssertNotUndefined { register: r_anyof }
    // See §6.7 for full pseudocode
```

**`not`** — Negate the inner condition. Uses the same helper-rule pattern:
the inner condition is compiled into a helper rule, called via `CallRule`, and
the result is negated. If the inner rule **succeeds** (returns a value), `not`
**fails**. If the inner rule **fails** (returns undefined), `not` **succeeds**.

```
compile(not(c)):
    // Compile c into a helper rule "not_N"
    // The helper rule compiles c in asserting mode:
    RuleInit { result_reg, rule_index: <helper> }
      <compile c — asserting mode>
      LoadTrue { dest: result_reg }
    RuleReturn

    // In the parent condition:
    CallRule { dest: r_inner, rule_index: <helper> }
    // r_inner = true if c succeeded, undefined if c failed
    // We need the opposite:
    Not { dest: r_neg, operand: r_inner }  // undefined→true, true→false
    AssertCondition { condition: r_neg }    // succeeds when c failed
```

This avoids the need for a separate `compile_soft()` function — the helper-rule
pattern provides boolean inversion naturally through the defined/undefined
distinction.

### 6.2 Field conditions

A field condition accesses a field on `input.resource` and compares it.

**Important: `[*]` in bare field conditions is UNIVERSAL (all must match).**
In Azure Policy, when `[*]` appears in a bare field condition (outside of a
`count`), it means **every** element of the array must satisfy the comparison.
This is ∀-quantification, compiled with `LoopStart(Every)`. The loop exits
early on the **first failure** — if any element doesn't match, the condition
is false.

#### 6.2.1 Undefined field semantics

Azure Policy has specific behavior when a field is **absent/undefined**.
For comprehensive coverage of type coercion, null/undefined/empty-string
distinctions, string ordering, date/time comparison, and other edge cases,
see [semantic-behaviors.md](semantic-behaviors.md).

| Operator | Field undefined → result |
|:---------|:------------------------|
| `equals` | **false** |
| `notEquals` | **true** |
| `greater`/`greaterOrEquals`/`less`/`lessOrEquals` | **false** |
| `in` | **false** |
| `notIn` | **true** |
| `contains`/`containsKey` | **false** |
| `notContains`/`notContainsKey` | **true** |
| `like`/`match`/`matchInsensitively` | **false** |
| `notLike`/`notMatch`/`notMatchInsensitively` | **true** |
| `exists` (true) | **false** |
| `exists` (false) | **true** |

**Pattern**: "positive" operators treat undefined as false; "negative" (not*)
operators treat undefined as true.

The compiler must NOT use a blanket `AssertNotUndefined` before all comparisons.
Instead, for negative operators it uses `IsDefined` + `IfThenElse` to branch
on whether the field is defined (see
[control-flow.md](control-flow.md) for the full rationale):

```
compile("field": "location", "notEquals": "eastus"):
    LoadInput { dest: r_input }
    ChainedIndex { root: r_input, path: ["resource", "location"], dest: r_field }

    // Check if field is defined
    IsDefined { dest: r_def, operand: r_field }

    IfThenElse { condition: r_def, else_start: ELSE, end: END }
      // Then: field is defined — compare and negate
      Load { dest: r_expected, literal_idx: <"eastus"> }
      BuiltinCall("azure.policy.compare") { dest: r_cmp, args: [r_field, r_expected] }
      Load { dest: r_zero, literal_idx: <0> }
      Eq { dest: r_eq, left: r_cmp, right: r_zero }
      Not { dest: r_result, operand: r_eq }
    ELSE:
      // Else: field is undefined → notEquals succeeds
      LoadTrue { dest: r_result }
    END:

    AssertCondition { condition: r_result }
```

For "positive" operators where undefined → false:

```
compile("field": "location", "equals": "eastus"):
    LoadInput { dest: r_input }
    ChainedIndex { root: r_input, path: ["resource", "location"], dest: r_field }

    // For "positive" operators, undefined = condition fails
    AssertNotUndefined { register: r_field }

    // Field exists — compare (case-insensitive via builtin)
    Load { dest: r_expected, literal_idx: <"eastus"> }
    BuiltinCall("azure.policy.compare") { dest: r_cmp, args: [r_field, r_expected] }
    Load { dest: r_zero, literal_idx: <0> }
    Eq { dest: r_result, left: r_cmp, right: r_zero }
    AssertCondition { condition: r_result }
```

#### 6.2.2 Case-insensitive string comparisons

Azure Policy string comparisons are **case-insensitive** for:
`equals`, `notEquals`, `in`, `notIn`, `contains`, `notContains`, `like`,
`notLike`.

The compiler handles this by emitting **custom Azure Policy comparison
builtins** that perform case-insensitive comparison internally:

| Builtin | Semantics | Covers |
|:--------|:----------|:-------|
| `azure.policy.compare(a, b)` | Returns -1/0/1; case-insensitive for strings, preserves type-appropriate ordering for numbers/bools | `equals`, `notEquals`, `greater`, `less`, `greaterOrEquals`, `lessOrEquals` |
| `azure.policy.contains(haystack, needle)` | Case-insensitive substring check (string) OR case-insensitive membership (array) | `contains`, `notContains` |
| `azure.policy.in(element, array)` | Case-insensitive element membership | `in`, `notIn` |
| `azure.policy.like(input, pattern)` | Case-insensitive glob-style pattern match | `like`, `notLike` |
| `azure.policy.match(input, pattern)` | Case-sensitive `#`/`?` pattern match | `match`, `notMatch` |
| `azure.policy.match_insensitively(input, pattern)` | Case-insensitive `#`/`?` pattern match | `matchInsensitively`, `notMatchInsensitively` |

**Why builtins instead of `lower()` + standard Rego ops?**

1. **Type safety**: `lower()` on a number or boolean would fail in Rego's type
   system. Comparison builtins handle mixed types correctly (case-insensitive
   for strings, standard comparison for non-strings).
2. **Fewer instructions**: One `BuiltinCall` instead of two `lower()` calls +
   one comparison instruction.
3. **Rego semantics preserved**: When policies are written directly in Rego
   (not compiled from Azure Policy JSON), the Rego compiler emits standard
   `Eq`/`Lt`/`Gt`/etc. instructions which are **case-sensitive**. The custom
   builtins are only emitted by the Azure Policy JSON compiler.
4. **Extensibility**: If Azure Policy adds new comparison semantics (e.g.,
   locale-aware ordering), only the builtin implementation changes — no
   compiler changes needed.

All builtins are registered under the `#[cfg(feature = "azure_policy")]`
feature gate.

#### 6.2.3 Array field conditions with `[*]`

```
compile("field": "securityRules[*].protocol", "equals": "Tcp"):

    // Step 1: Load input
    LoadInput { dest: r_input }

    // Step 2: Navigate to field — split on '.' and handle [*]
    // "securityRules[*].protocol" has a wildcard → requires loop

    // Access input.resource.securityRules
    ChainedIndex { root: r_input, path: ["resource", "securityRules"], dest: r_arr }
    AssertNotUndefined { register: r_arr }

    // Load comparison value
    Load { dest: r_expected, literal_idx: <"Tcp"> }

    // Loop over ALL array elements — EVERY element must match (universal)
    LoopStart(Every) { collection: r_arr, value_reg: r_elem }
      // Access element.protocol
      ChainedIndex { root: r_elem, path: ["protocol"], dest: r_field }
      // Compare (case-insensitive for strings)
      BuiltinCall("azure.policy.compare") { dest: r_cmp, args: [r_field, r_expected] }
      Load { dest: r_zero, literal_idx: <0> }
      Eq { dest: r_eq, left: r_cmp, right: r_zero }
      AssertCondition { condition: r_eq }    // fails loop on first mismatch
    LoopNext
```

**Empty arrays**: When the array is empty, `LoopStart(Every)` succeeds
vacuously (∀x∈∅. P(x) = true). This matches Azure Policy semantics.

For a simple (non-array) field:

```
compile("field": "supportsHttpsTrafficOnly", "equals": true):

    LoadInput { dest: r_input }
    ChainedIndex { root: r_input, path: ["resource", "supportsHttpsTrafficOnly"], dest: r_field }
    AssertNotUndefined { register: r_field }
    LoadTrue { dest: r_expected }
    BuiltinCall("azure.policy.compare") { dest: r_cmp, args: [r_field, r_expected] }
    Load { dest: r_zero, literal_idx: <0> }
    Eq { dest: r_eq, left: r_cmp, right: r_zero }
    AssertCondition { condition: r_eq }
```

### 6.3 Comparison operator mappings

All string comparisons use **custom Azure Policy builtins** that handle
case-insensitivity internally (see §6.2.2). This leaves standard Rego
comparison instructions (`Eq`, `Lt`, etc.) with their original case-sensitive
semantics, preserving correctness for Rego-authored policies.

For undefined-field handling, see §6.2.1. "Positive" operators use
`AssertNotUndefined`; "negative" operators use `IsDefined` + `IfThenElse`.

| Operator | Instructions | Notes |
|:---------|:------------|:------|
| `equals` | `BuiltinCall("azure.policy.compare", r_field, r_value)` → r_cmp, `Load 0` → r_zero, `Eq(r_cmp, r_zero)` → r_result | Case-insensitive for strings |
| `notEquals` | Same as equals → `Not` | Undefined → true |
| `greater` | `BuiltinCall("azure.policy.compare", ...)` → r_cmp, `Gt(r_cmp, r_zero)` | |
| `greaterOrEquals` | `azure.policy.compare` → `Ge(r_cmp, r_zero)` | |
| `less` | `azure.policy.compare` → `Lt(r_cmp, r_zero)` | |
| `lessOrEquals` | `azure.policy.compare` → `Le(r_cmp, r_zero)` | |
| `in` | `BuiltinCall("azure.policy.in", r_field, r_set)` → r_result | Case-insensitive for string elements |
| `notIn` | `azure.policy.in` → `Not` | Undefined → true |
| `contains` | `BuiltinCall("azure.policy.contains", r_field, r_value)` → r_result | Dual-mode: §6.3.1 |
| `notContains` | `azure.policy.contains` → `Not` | Undefined → true |
| `containsKey` | `Contains { collection: r_field, value: r_key }` | Case-insensitive (keys are normalized) |
| `notContainsKey` | `Contains` → `Not` | Undefined → true |
| `like` | `BuiltinCall("azure.policy.like", r_field, r_pattern)` → r_result | Case-insensitive |
| `notLike` | `azure.policy.like` → `Not` | Undefined → true |
| `match` | `BuiltinCall("azure.policy.match", r_field, r_pattern)` → r_result | See §6.3.2 |
| `notMatch` | `azure.policy.match` → `Not` | Undefined → true |
| `matchInsensitively` | `BuiltinCall("azure.policy.match_insensitively", r_field, r_pattern)` → r_result | See §6.3.2 |
| `notMatchInsensitively` | Same → `Not` | |
| `exists` (true) | `AssertNotUndefined { register: r_field }` | |
| `exists` (false) | `IsDefined` + `IfThenElse` or `Not` pattern | See §6.3.3 |

#### 6.3.1 `contains` — dual-mode (string vs array)

Azure Policy `contains` checks:
- **String** operand: substring check (`"foobar" contains "bar"` → true)
- **Array** operand: element membership (`["a","b"] contains "a"` → true)

Both modes are **case-insensitive** for strings.

The `azure.policy.contains` builtin handles both modes internally with a
runtime type check:

```rust
/// azure.policy.contains(haystack, needle) -> bool
/// If haystack is a string: case-insensitive substring check
/// If haystack is an array: case-insensitive element membership
fn azure_policy_contains(haystack: &Value, needle: &Value) -> bool {
    match haystack {
        Value::String(s) => {
            if let Value::String(n) = needle {
                s.to_lowercase().contains(&n.to_lowercase())
            } else {
                false
            }
        }
        Value::Array(arr) => {
            arr.iter().any(|elem| azure_policy_equal(elem, needle))
        }
        _ => false,
    }
}
```

**Compilation**:

```
compile("field": "someField", "contains": "value"):
    <load r_field, check undefined per §6.2.1>
    Load { dest: r_value, literal_idx: <"value"> }
    BuiltinCall("azure.policy.contains") { dest: r_result, args: [r_field, r_value] }
    AssertCondition { condition: r_result }
```

The dual-mode dispatch, case-insensitivity, and type handling are all
encapsulated inside the builtin — the compiler emits a single call.

#### 6.3.2 `match`/`notMatch` — custom pattern builtin

Azure Policy `match` uses a **custom pattern language**, NOT regex:
- `#` matches any single digit (`[0-9]`)
- `?` matches any single letter (`[a-zA-Z]`)
- All other characters are literal

The pattern **cannot** be translated to regex at compile time because the
pattern value may come from a runtime parameter (e.g.,
`"match": "[parameters('namePattern')]"`).

Instead, the compiler emits a call to a **custom builtin** that performs the
pattern matching at runtime:

```rust
/// Custom builtin: azure.policy.match(input, pattern) -> bool
/// Matches `input` against an Azure Policy pattern where:
///   '#' matches any single digit [0-9]
///   '?' matches any single letter [a-zA-Z]
///   all other characters are literal (case-sensitive)
fn azure_policy_match(input: &str, pattern: &str) -> bool {
    let input_chars: Vec<char> = input.chars().collect();
    let pattern_chars: Vec<char> = pattern.chars().collect();
    if input_chars.len() != pattern_chars.len() {
        return false;
    }
    input_chars.iter().zip(pattern_chars.iter()).all(|(i, p)| match p {
        '#' => i.is_ascii_digit(),
        '?' => i.is_ascii_alphabetic(),
        _ => i == p,
    })
}

/// azure.policy.match_insensitively: same but case-insensitive for literals
fn azure_policy_match_insensitively(input: &str, pattern: &str) -> bool {
    let input_chars: Vec<char> = input.chars().collect();
    let pattern_chars: Vec<char> = pattern.chars().collect();
    if input_chars.len() != pattern_chars.len() {
        return false;
    }
    input_chars.iter().zip(pattern_chars.iter()).all(|(i, p)| match p {
        '#' => i.is_ascii_digit(),
        '?' => i.is_ascii_alphabetic(),
        _ => i.to_ascii_lowercase() == p.to_ascii_lowercase(),
    })
}
```

These builtins are registered under the `azure_policy` feature gate, alongside
the existing Rego builtins.

**Compilation**:

```
compile("field": "name", "match": "contoso-vm-##"):
    <load r_field>
    Load { dest: r_pattern, literal_idx: <"contoso-vm-##"> }
    BuiltinCall("azure.policy.match") { dest: r_result, args: [r_field, r_pattern] }
    AssertCondition { condition: r_result }

compile("field": "name", "match": "[parameters('namePattern')]"):
    <load r_field>
    <compile parameters('namePattern') → r_pattern>
    BuiltinCall("azure.policy.match") { dest: r_result, args: [r_field, r_pattern] }
    AssertCondition { condition: r_result }
```

**`matchInsensitively`**: Uses `azure.policy.match_insensitively` which
compares literal characters case-insensitively. The `#` and `?` wildcards
are inherently case-insensitive (digit/letter classes).

**Why not translate at runtime to regex?** A dedicated builtin is simpler,
faster (no regex compilation overhead), and avoids edge cases with regex
escaping. The pattern language is trivial — character-by-character comparison
with two wildcard types.

#### 6.3.3 `exists` (false) — instruction sequence

```
compile("field": "optionalField", "exists": false):
    LoadInput { dest: r_input }
    ChainedIndex { root: r_input, path: ["resource", "optionalField"], dest: r_field }
    IsDefined { dest: r_def, operand: r_field }
    Not { dest: r_not_def, operand: r_def }
    AssertCondition { condition: r_not_def }  // succeeds only if field is absent
```

### 6.4 Count compilation

**Simple count** (no where clause):

```json
{ "count": { "field": "securityRules[*]" }, "greater": 0 }
```

```
LoadInput { dest: r_input }
ChainedIndex { root: r_input, path: ["resource", "securityRules"], dest: r_arr }
Count { dest: r_count, collection: r_arr }
Load { dest: r_zero, literal_idx: <0> }
Gt { dest: r_result, left: r_count, right: r_zero }
AssertCondition { condition: r_result }
```

**Filtered count** (with where clause):

```json
{
  "count": {
    "field": "securityRules[*]",
    "where": {
      "field": "securityRules[*].protocol",
      "equals": "Tcp"
    }
  },
  "equals": 0
}
```

Strategy: use an **array comprehension** to collect elements that satisfy the
`where` clause, then `Count` the result. This maps directly to Rego's
`count([x | some x in arr; <condition>])` pattern and reuses existing RVM
comprehension instructions without needing a conditional-increment primitive.

```
LoadInput { dest: r_input }
ChainedIndex { root: r_input, path: ["resource", "securityRules"], dest: r_arr }

// Collect elements that satisfy the where clause
ComprehensionBegin(Array) { collection: r_arr, value_reg: r_elem, result_reg: r_filtered }
  // — where condition body —
  ChainedIndex { root: r_elem, path: ["protocol"], dest: r_field }
  Load { dest: r_expected, literal_idx: <"Tcp"> }
  BuiltinCall("azure.policy.compare") { dest: r_cmp, args: [r_field, r_expected] }
  Load { dest: r_zero_cmp, literal_idx: <0> }
  Eq { dest: r_match, left: r_cmp, right: r_zero_cmp }
  AssertCondition { condition: r_match }
  ComprehensionYield { value_reg: r_elem }
ComprehensionEnd

// Count matching elements, compare against threshold
Count { dest: r_count, collection: r_filtered }
Load { dest: r_zero, literal_idx: <0> }
BuiltinCall("azure.policy.compare") { dest: r_cmp2, args: [r_count, r_zero] }
Load { dest: r_zero2, literal_idx: <0> }
Eq { dest: r_result, left: r_cmp2, right: r_zero2 }
AssertCondition { condition: r_result }
```

The comprehension body acts as a filter: only elements where `AssertCondition`
succeeds reach `ComprehensionYield`; failing elements skip to the next
iteration (the RVM handles this via the comprehension's built-in backtracking).
This is clean, requires no new instructions, and nests naturally (see §6.5.6).

### 6.5 Loop semantics — `[*]` scoping rules

This is a critical section. Azure Policy's `[*]` wildcard has **different
quantification semantics** depending on where it appears. Getting this wrong
produces incorrect compliance results.

#### 6.5.1 The two contexts for `[*]`

| Context | Quantifier | Meaning | Loop mode |
|:--------|:-----------|:--------|:----------|
| **Bare field condition** | Universal (∀) | ALL elements must match | `Every` |
| **Inside `count.where`** | Per-element | Each element tested individually, matches counted | `ForEach` |

**Bare field condition** (universal — the default):

```json
{
  "field": "securityRules[*].protocol",
  "equals": "Tcp"
}
```

This means: "**Every** security rule's protocol must equal Tcp." If any rule
has a different protocol, the condition is **false**. If the array is empty,
the condition is **true** (vacuous truth).

**Inside `count.where`** (per-element):

```json
{
  "count": {
    "field": "securityRules[*]",
    "where": {
      "field": "securityRules[*].protocol",
      "equals": "Tcp"
    }
  },
  "greater": 0
}
```

Inside `count.where`, the `[*]` in `securityRules[*].protocol` refers to the
**current element** being iterated — i.e., the current security rule. The where
clause tests each element individually, and the count tallies how many passed.

#### 6.5.2 `[*]` scoping in `count.where`

When a field reference inside `count.where` shares the same array prefix as the
count's `field`, that `[*]` is **bound** to the current iteration element:

```json
{
  "count": {
    "field": "securityRules[*]",        // ← iterates this array
    "where": {
      "allOf": [
        {
          "field": "securityRules[*].protocol",     // ← bound to current element
          "equals": "Tcp"
        },
        {
          "field": "securityRules[*].direction",    // ← bound to current element
          "equals": "Inbound"
        }
      ]
    }
  },
  "greater": 0
}
```

The compiler must recognize that `securityRules[*].protocol` inside the where
clause of `count { field: "securityRules[*]" }` means `current_element.protocol`,
not "iterate all security rules again."

**Compilation**: The compiler passes the current element register into the where
condition compilation. When compiling a field reference inside `count.where`:

1. Check if the field path's array prefix matches the count's array field.
2. If yes: access the sub-path from the **current element register** (no new loop).
3. If no: access via the normal `input.resource` path (may start a new loop
   if the field has its own `[*]`).

```
// Compiling count.where { field: "securityRules[*].protocol", equals: "Tcp" }
// when current_element_reg = r_elem (from the count's ForEach loop):

ChainedIndex { root: r_elem, path: ["protocol"], dest: r_field }    // NOT from input.resource
Load { dest: r_expected, literal_idx: <"Tcp"> }
BuiltinCall("azure.policy.compare") { dest: r_cmp, args: [r_field, r_expected] }
Load { dest: r_zero, literal_idx: <0> }
Eq { dest: r_eq, left: r_cmp, right: r_zero }
AssertCondition { condition: r_eq }
```

#### 6.5.3 The `current()` function

Azure Policy provides `current()` as an explicit way to reference the current
iteration element. It can appear in template expressions:

```json
{
  "count": {
    "field": "securityRules[*]",
    "where": {
      "field": "securityRules[*].protocol",
      "equals": "[current('securityRules[*]')]"
    }
  }
}
```

`current('securityRules[*]')` returns the entire current element.
`current('securityRules[*].protocol')` returns the `protocol` field of the
current element (equivalent to the implicit scoping above).

**Compilation**: `current()` resolves to the current element register. The
compiler maintains a stack of active count scopes:

```rust
struct CountScope {
    /// The array prefix being iterated (e.g., "securityRules")
    array_prefix: String,
    /// Register holding the current element
    element_reg: u8,
}

/// Stack of active count scopes (innermost last)
count_scope_stack: Vec<CountScope>,
```

When compiling `current('securityRules[*]')`:
1. Find the innermost `CountScope` whose array prefix matches.
2. Return that scope's `element_reg`.
3. If the `current()` argument includes sub-fields after `[*]`, emit a
   `ChainedIndex` from the element register.

#### 6.5.4 Value count

Azure Policy also supports counting over an **explicit array of values** rather
than a resource field:

```json
{
  "count": {
    "value": "[parameters('allowedProtocols')]",
    "name": "protocol",
    "where": {
      "field": "securityRules[*].protocol",
      "contains": "[current('protocol')]"
    }
  },
  "equals": 0
}
```

This iterates over the parameter array, binding each element to the name
`"protocol"`. Inside the `where` clause, `current('protocol')` returns the
current value from the parameter array.

**Limits**: Azure Policy limits value count to **100 iterations** maximum.

**Compilation**:

```
// Step 1: Load the value array
LoadInput { dest: r_input }
ChainedIndex { root: r_input, path: ["parameters", "allowedProtocols"], dest: r_values }

// Step 2: Iterate and count matches via comprehension
ComprehensionBegin(Array) { collection: r_values, value_reg: r_val, result_reg: r_filtered }
  // Push named count scope: name="protocol", element_reg=r_val
  // Compile where condition with scope active
  // ... where body accesses current('protocol') → r_val
  AssertCondition { condition: r_where_result }
  ComprehensionYield { value_reg: r_val }
ComprehensionEnd

Count { dest: r_count, collection: r_filtered }
// Compare count
```

#### 6.5.5 Nested counts

Counts can be nested — a `count.where` can itself contain another `count`:

```json
{
  "count": {
    "field": "securityRules[*]",
    "where": {
      "count": {
        "field": "securityRules[*].destinationPortRanges[*]",
        "where": {
          "field": "securityRules[*].destinationPortRanges[*]",
          "equals": "*"
        }
      },
      "greater": 0
    }
  },
  "greater": 0
}
```

The inner count's `securityRules[*]` is bound to the outer count's current
element. The inner `[*]` (on `destinationPortRanges`) starts a **new** iteration
scope. The scoping follows lexical nesting:

- Outer scope: `securityRules[*]` → iterates security rules.
- Inner scope: `securityRules[*].destinationPortRanges[*]` → for each security
  rule, iterates its destination port ranges.

**Compilation**: The `count_scope_stack` naturally handles this — each nested
count pushes a new scope, and `current()` resolution walks the stack from
innermost to outermost.

#### 6.5.6 `not` with `[*]` — De Morgan inversion

When `not` wraps a bare field condition with `[*]`, it inverts the quantifier
via De Morgan's law:

| Expression | Meaning |
|:-----------|:--------|
| `{ "field": "x[*].y", "equals": "v" }` | ∀ x: x.y = v |
| `{ "not": { "field": "x[*].y", "equals": "v" } }` | ¬(∀ x: x.y = v) = ∃ x: x.y ≠ v |
| `{ "not": { "field": "x[*].y", "notEquals": "v" } }` | ¬(∀ x: x.y ≠ v) = ∃ x: x.y = v |

The compiler does NOT need to transform quantifiers — compiling the inner
condition into a helper rule and negating the result (the §6.1 `not` pattern)
produces the correct behavior naturally:

```
compile(not({ field: "securityRules[*].protocol", "equals": "Tcp" })):

    // Helper rule compiles the inner [*] condition with LoopStart(Every)
    // If ALL elements match → helper returns true
    // If ANY element fails → helper returns undefined (assertion fails inside loop)
    CallRule { dest: r_inner, rule_index: <helper> }

    // Negate: succeed if helper failed (some element didn't match)
    Not { dest: r_neg, operand: r_inner }  // undefined→true, true→false
    AssertCondition { condition: r_neg }
```

#### 6.5.7 `field()` inside `count.where`

When `[field('aliasPath')]` is used inside a `count.where`, it returns the field
value for the **current** element (not an array of all values). Under the hood,
Azure Policy binds `field()` to the count's current element when the alias path
shares the count's array prefix.

**Compilation**: Same as §6.5.2 — the compiler checks if the field reference's
array prefix matches an active count scope.

#### 6.5.8 Modify with `[*]`

When a `modify` effect targets a field with `[*]`, each existing array element
is operated on individually:

```json
{
  "then": {
    "effect": "modify",
    "details": {
      "operations": [
        {
          "operation": "addOrReplace",
          "field": "securityRules[*].protocol",
          "value": "Https"
        }
      ]
    }
  }
}
```

This is a per-element operation, but the **compiler does not expand** `[*]` in
modify field targets. The field path `"securityRules[*].protocol"` is passed
through as a literal string in the effect result object. The host is responsible
for per-element expansion when applying the modification.

This aligns with the pass-through strategy in [effects.md](effects.md) §3.4 —
the compiler treats modify field paths opaquely, and the host handles array
element iteration at mutation time.

#### 6.5.9 Empty arrays

| Context | Empty array behavior |
|:--------|:--------------------|
| Bare `[*]` field condition | **true** (vacuous truth — ∀x∈∅ is true) |
| `count` (no where) | **0** |
| `count` (with where) | **0** |
| `modify` with `[*]` | No-op (nothing to modify) |

The compiler must ensure that `LoopStart(Every)` on an empty collection produces
`true` (the loop body never executes, so no assertion fails) and `Count` /
`ComprehensionBegin` on an empty collection produces `0` / empty array.

#### 6.5.10 Iteration limits

Azure Policy imposes limits on iteration:

| Limit | Value |
|:------|:------|
| Field counts per array (`[*]`) | 5 per policy rule |
| Value counts per policy rule | 10 |
| Value count iterations (array length) | 100 |

These limits affect **validation** — the compiler can check them at parse/compile
time and reject policies that exceed them. For field counts, the compiler counts
how many distinct `count { field: "...[*]" }` expressions target the same array.
For value counts, it counts total `count { value: ... }` nodes.

### 6.6 Template expression compilation

Template expressions are compiled to instructions that load values from the
normalized `input` envelope:

```
compile([parameters('effect')]):
    LoadInput { dest: r_input }
    ChainedIndex { root: r_input, path: ["parameters", "effect"], dest: r_result }

compile([resourceGroup().location]):
    LoadInput { dest: r_input }
    ChainedIndex { root: r_input, path: ["context", "resourceGroup", "location"], dest: r_result }

compile([field('securityRules[*].protocol')]):
    // Same as a field access
    LoadInput { dest: r_input }
    ChainedIndex { root: r_input, path: ["resource", "securityRules"], dest: r_arr }
    // ... (with loop if [*] present — mode depends on context)

compile([current('securityRules[*]')]):
    // Only valid inside count.where — resolves to current element register
    // Look up "securityRules" in count_scope_stack → element_reg
    Move { dest: r_result, src: r_elem }    // r_elem from active CountScope

compile([current('securityRules[*].protocol')]):
    // Current element + sub-path
    // Look up "securityRules" in count_scope_stack → element_reg
    ChainedIndex { root: r_elem, path: ["protocol"], dest: r_result }

compile([current('protocol')]):
    // Value count binding name — look up "protocol" in count_scope_stack
    Move { dest: r_result, src: r_val }    // r_val from value count's ForEach

compile([concat(field('name'), '-suffix')]):
    // Compile each argument
    <compile field('name') → r_name>
    Load { dest: r_suffix, literal_idx: <"-suffix"> }
    // Create array of args and call concat
    ArrayCreate { dest: r_args, elements: [r_name, r_suffix] }
    BuiltinCall("concat") { dest: r_result, args: [r_args] }

compile([toLower(field('location'))]):
    <compile field('location') → r_loc>
    BuiltinCall("lower") { dest: r_result, args: [r_loc] }

compile([if(equals(field('kind'), 'BlobStorage'), field('accessTier'), 'N/A')]):
    // The if() condition is a simple comparison expression, not a full
    // policy condition — it supports: equals, contains, less, greater, etc.
    // Compile condition expression:
    <compile field('kind') → r_kind>
    Load { dest: r_test, literal_idx: <"BlobStorage"> }
    BuiltinCall("azure.policy.compare") { dest: r_cmp, args: [r_kind, r_test] }
    Load { dest: r_zero, literal_idx: <0> }
    Eq { dest: r_cond, left: r_cmp, right: r_zero }

    // Compile true/false branches using structured IfThenElse:
    IfThenElse { condition: r_cond, else_start: ELSE, end: END }
      <compile field('accessTier') → r_true>
      Move { dest: r_result, src: r_true }
    ELSE:
      Load { dest: r_false, literal_idx: <"N/A"> }
      Move { dest: r_result, src: r_false }
    END:
```

**Note on `if()` conditions**: ARM template `if()` supports a simpler set of
comparisons than the full policy condition grammar. The condition argument is
typically `equals(expr, expr)`, `contains(expr, expr)`, `greater(expr, expr)`,
`less(expr, expr)`, or `empty(expr)`. These are compiled inline as expression
comparisons, not as full condition trees.

### 6.7 `anyOf` using multi-definition rules

The most natural RVM pattern for `anyOf` is multiple definitions of the same
rule. In the Rego compiler, a rule like:

```rego
allow if condition_a
allow if condition_b
```

compiles to two definitions for rule `allow`. When `CallRule` executes for
`allow`, each definition is tried; the first that succeeds produces the result.

For `anyOf`, the Azure Policy compiler can:
1. Create a helper rule (e.g., `anyof_0`).
2. Each `anyOf` branch becomes a separate definition of that helper rule.
3. The parent condition calls the helper rule via `CallRule`.

```
// For: anyOf: [cond_a, cond_b, cond_c]

// Helper rule "anyof_0" — definition 0
RuleInit { result_reg, rule_index: 1 }
  <compile cond_a, asserting on success>
  LoadTrue { dest: result_reg }
RuleReturn

// Helper rule "anyof_0" — definition 1
RuleInit { result_reg, rule_index: 1 }
  <compile cond_b, asserting on success>
  LoadTrue { dest: result_reg }
RuleReturn

// Helper rule "anyof_0" — definition 2
RuleInit { result_reg, rule_index: 1 }
  <compile cond_c, asserting on success>
  LoadTrue { dest: result_reg }
RuleReturn

// In the parent condition:
CallRule { dest: r_anyof, rule_index: 1 }
AssertNotUndefined { register: r_anyof }
```

This is the cleanest approach because it reuses the VM's existing
multi-definition rule evaluation with early exit on first match.

---

## 7. Effect Compilation

For the comprehensive effects reference (all 9 effects, cross-resource
patterns, parameterized effects, and precedence), see [effects.md](effects.md).

### 7.1 Simple effects (deny, audit)

The compiler produces an object containing the effect name and any details:

```
compile(then: { effect: "deny" }):
    // Build the effect result object
    Load { dest: r_effect_name, literal_idx: <"deny"> }
    ObjectCreate { dest: r_result, fields: [("effect", r_effect_name)] }
```

For `deny` with a message:

```
compile(then: { effect: "deny", details: { message: "HTTPS required" } }):
    Load { dest: r_effect, literal_idx: <"deny"> }
    Load { dest: r_msg, literal_idx: <"HTTPS required"> }
    ObjectCreate { dest: r_details, fields: [("message", r_msg)] }
    ObjectCreate { dest: r_result, fields: [("effect", r_effect), ("details", r_details)] }
```

### 7.2 Parameterized effects

```
compile(then: { effect: "[parameters('effect')]" }):
    LoadInput { dest: r_input }
    ChainedIndex { root: r_input, path: ["parameters", "effect"], dest: r_effect_name }
    ObjectCreate { dest: r_result, fields: [("effect", r_effect_name)] }
```

### 7.3 Modify effects

```json
{
  "then": {
    "effect": "modify",
    "details": {
      "operations": [
        { "operation": "addOrReplace", "field": "tags['environment']", "value": "production" }
      ]
    }
  }
}
```

```
Load { dest: r_effect, literal_idx: <"modify"> }
Load { dest: r_op_type, literal_idx: <"addOrReplace"> }
Load { dest: r_field, literal_idx: <"tags.environment"> }
Load { dest: r_value, literal_idx: <"production"> }
ObjectCreate { dest: r_op, fields: [("operation", r_op_type), ("field", r_field), ("value", r_value)] }
ArrayCreate { dest: r_operations, elements: [r_op] }

// roleDefinitionIds — RBAC roles the host needs for making the modification
Load { dest: r_role, literal_idx: <"&lt;role-guid&gt;"> }
ArrayCreate { dest: r_roles, elements: [r_role] }

ObjectCreate { dest: r_details, fields: [("roleDefinitionIds", r_roles), ("operations", r_operations)] }
ObjectCreate { dest: r_result, fields: [("effect", r_effect), ("details", r_details)] }
```

---

## 8. Field Access Compilation — Detailed

### 8.1 Simple field (no wildcards)

Field: `supportsHttpsTrafficOnly`

```
LoadInput { dest: r0 }
ChainedIndex { root: r0, path: ["resource", "supportsHttpsTrafficOnly"], dest: r1 }
```

### 8.2 Nested field (no wildcards)

Field: `networkAcls.defaultAction`

```
LoadInput { dest: r0 }
ChainedIndex { root: r0, path: ["resource", "networkAcls", "defaultAction"], dest: r1 }
```

### 8.3 Single wildcard

Field: `securityRules[*].protocol`

The wildcard means "for each element." The loop mode depends on context:

| Context | Quantifier | Loop mode | Early exit |
|:--------|:-----------|:----------|:-----------|
| Bare field condition (`"field": "...[*]...", "equals": ...`) | Universal (∀) — **all** must match | `LoopStart(Every)` | First failure |
| Inside `count.where` | Per-element — test **each**, count matches | `LoopStart(ForEach)` | Never (visit all) |
| Simple count (no where) | N/A — just count array length | `Count` instruction | N/A |
| Inside `not { field condition }` | Existential (∃) — via De Morgan ¬∀=∃¬ | `LoopStart(Every)` inside negation | First failure |

For a **universal** bare field condition (the default):

```
LoadInput { dest: r0 }
ChainedIndex { root: r0, path: ["resource", "securityRules"], dest: r_arr }

LoopStart(Every) { collection: r_arr, value_reg: r_elem }
  ChainedIndex { root: r_elem, path: ["protocol"], dest: r_field }
  <comparison instructions>
  AssertCondition { condition: r_cmp }    // fail → loop exits false
LoopNext
```

**Empty arrays**: `LoopStart(Every)` with an empty collection succeeds
vacuously — this matches Azure Policy behavior where an empty array satisfies
all bare `[*]` conditions.

### 8.4 Nested wildcards

Field: `requestRoutingRules[*].backendAddressPool.backendAddresses[*].fqdn`

Both loops use `Every` because this is a bare field condition — **all** outer
elements must satisfy the condition, and for each outer element, **all** inner
elements must also satisfy it. This is nested universal quantification: ∀x∈outer. ∀y∈x.inner. P(y).

```
LoadInput { dest: r0 }
ChainedIndex { root: r0, path: ["resource", "requestRoutingRules"], dest: r_outer }

LoopStart(Every) { collection: r_outer, value_reg: r_outer_elem }
  ChainedIndex { root: r_outer_elem, path: ["backendAddressPool", "backendAddresses"], dest: r_inner }

  LoopStart(Every) { collection: r_inner, value_reg: r_inner_elem }
    ChainedIndex { root: r_inner_elem, path: ["fqdn"], dest: r_field }
    <comparison instructions>
    AssertCondition { condition: r_cmp }
  LoopNext
LoopNext
```

**Context-dependent nesting**: When nested wildcards appear inside `count.where`,
both loops use `ForEach` instead. The context (bare condition vs. count body)
determines the loop mode for **all** wildcard levels in that field path.

### 8.5 Tags with bracket notation

Field: `tags['Acct.CostCenter']`

```
LoadInput { dest: r0 }
ChainedIndex { root: r0, path: ["resource", "tags", "Acct.CostCenter"], dest: r1 }
```

The tag key is treated as a single literal string in the path, not split on `.`.

### 8.6 Built-in fields

Field: `type`

```
LoadInput { dest: r0 }
ChainedIndex { root: r0, path: ["resource", "type"], dest: r1 }
```

Built-in fields live at the root of `input.resource`, same as aliased fields.

---

## 9. Register Allocation

The compiler uses a simple linear register allocation:

```rust
fn alloc_register(&mut self) -> u8 {
    let reg = self.register_counter;
    self.register_counter = self.register_counter.checked_add(1)
        .expect("register overflow");
    reg
}
```

Register 0 is reserved for the rule result. Registers are allocated
monotonically. The RVM uses register windowing — each rule gets its own register
window, so there is no inter-rule register conflict.

For Azure Policy rules, register pressure is low compared to Rego. A typical
policy rule uses:
- 1 register for `input`
- 1 register per field access
- 1 register per comparison result
- 1 register per literal
- A few registers for loop variables
- 1 register for the effect result

A complex policy with nested conditions might use 20–30 registers. The u8 limit
(255) is more than sufficient.

---

## 10. Literal Management

The compiler maintains a deduplication cache for literal values:

```rust
fn get_or_add_literal(&mut self, value: Value) -> u16 {
    if let Some(&idx) = self.literal_cache.get(&value) {
        return idx;
    }
    let idx = self.program.literals.len() as u16;
    self.literal_cache.insert(value.clone(), idx);
    self.program.literals.push(value);
    idx
}
```

Common literals like `"resource"`, `"parameters"`, `"context"`, field names,
and comparison values are deduplicated. This is important because many
conditions in a policy reference the same field path prefixes.

---

## 11. Builtin Function Mapping

The Azure Policy compiler maps some operators to Rego builtins already available
in the RVM:

| Azure Policy operation | Rego builtin | Signature |
|:----------------------|:-------------|:----------|
| `like` / `notLike` | `glob.match` | `glob.match(pattern, ["."], value)` |
| `match` / `notMatch` | `regex.match` | `regex.match(pattern, value)` |
| `matchInsensitively` | `lower` + `regex.match` | lowercase both, then match |
| `contains` (string) | `contains` | `contains(haystack, needle)` |
| `toLower` | `lower` | `lower(str)` |
| `toUpper` | `upper` | `upper(str)` |
| `concat` | `concat` | `concat("", [a, b, ...])` |

The compiler registers these in the `builtin_info_table` and emits
`BuiltinCall` instructions referencing them by index.

---

## 12. Error Handling

### 12.1 Parse errors

```rust
pub enum ParseError {
    InvalidJson(serde_json::Error),
    ExpectedObject,
    ExpectedArray,
    ExpectedString,
    MissingIf,
    MissingThen,
    MissingComparison,
    UnrecognizedCondition,
    UnknownOperator(String),
    InvalidFieldPath(String),
    UnsupportedTemplateExpression(String),
    InvalidTemplateExpressionSyntax(String),
}
```

### 12.2 Compile errors

```rust
pub enum CompileError {
    RegisterOverflow,
    LiteralTableOverflow,
    InstructionLimitExceeded,
    UnsupportedFeature(String),
    InvalidFieldReference(String),
    UnknownBuiltin(String),
}
```

### 12.3 Error recovery

The parser validates the entire policy JSON before compilation begins. The
compiler does not attempt partial compilation — a single error fails the whole
policy. This is appropriate because Azure Policy JSON is machine-generated and
must be structurally correct.

---

## 13. Testing Strategy

### 13.1 Unit tests

**Parser tests**: Verify that each JSON condition structure parses to the
correct AST. Cover all operators, all field path shapes, nested conditions,
template expressions.

**Compiler tests**: Verify that each AST node compiles to the expected
instruction sequence. Test in isolation: single field condition, allOf, anyOf,
not, count, template expressions.

### 13.2 Integration tests

**End-to-end tests**: Provide Azure Policy JSON + normalized input → evaluate
→ check effect output. Structured as YAML test cases following the existing
pattern in `tests/`:

```yaml
- note: "deny HTTPS not enabled"
  policy_json: |
    {
      "if": {
        "allOf": [
          { "field": "type", "equals": "Microsoft.Storage/storageAccounts" },
          { "field": "supportsHttpsTrafficOnly", "notEquals": true }
        ]
      },
      "then": { "effect": "deny" }
    }
  input:
    resource:
      type: "Microsoft.Storage/storageAccounts"
      name: "mystorage"
      supportsHttpsTrafficOnly: false
    parameters: {}
    context: {}
  result:
    effect: "deny"
```

### 13.3 Equivalence tests

For policies that can be expressed in both Azure Policy JSON and Rego, verify
that both compilers produce semantically equivalent results on the same inputs.
This validates the normalization contract.

### 13.4 Test matrix

| Category | Count | Description |
|:---------|:------|:-----------|
| Field conditions | ~20 | One test per operator |
| Logical operators | ~10 | allOf, anyOf, not, nesting |
| Bare `[*]` (universal) | ~12 | Single `[*]` all-match, some-fail, empty array (vacuous truth), nested `[*]`, `not` + `[*]` (De Morgan) |
| Count (field) | ~12 | Simple count, filtered count with where, nested count, empty array → 0, multi-[*] in count |
| Count (value) | ~8 | Value count with name binding, `current()` in where, iteration limit check, empty value array |
| `current()` function | ~6 | `current('array[*]')`, `current('array[*].field')`, `current('name')`, invalid scope |
| Template expressions | ~15 | parameters, field, resourceGroup, concat, if, toLower, current |
| Effects | ~12 | deny, audit, modify, modify with `[*]` targets, parameterized, append |
| Tags | ~5 | Simple tag, special characters, missing tag |
| Built-in fields | ~5 | name, type, location, kind, id |
| Edge cases | ~10 | Empty conditions, missing fields, deeply nested, iteration limits |
| **Total** | **~115** | |

---

## 14. Public API

### 14.1 Compilation function

```rust
/// Compile an Azure Policy JSON rule to RVM bytecode.
///
/// # Arguments
/// * `policy_json` - The Azure Policy rule JSON string
/// * `resource_type` - Optional resource type for alias context
///
/// # Returns
/// An `Arc<Program>` containing the compiled bytecode.
#[cfg(feature = "azure_policy")]
pub fn compile_azure_policy(
    policy_json: &str,
    resource_type: Option<&str>,
) -> Result<Arc<Program>>;
```

### 14.2 Evaluation flow

```rust
// Compile
let program = compile_azure_policy(policy_json, Some("Microsoft.Storage/storageAccounts"))?;

// Prepare input (host responsibility)
let input = json!({
    "resource": normalized_resource,
    "context": { "resourceGroup": { "name": "rg1", "location": "eastus" } },
    "parameters": { "effect": "deny" }
});

// Evaluate via RVM
let result = vm.eval(program, input)?;
// result: { "effect": "deny" } or undefined if condition didn't match
```

---

## 15. Implementation Phases

### Phase 1: AST and Parser

**Goal**: Parse Azure Policy JSON into a typed AST.

**Files**:
- `src/languages/azure_policy/mod.rs`
- `src/languages/azure_policy/ast/mod.rs`
- `src/languages/azure_policy/ast/condition.rs`
- `src/languages/azure_policy/ast/effect.rs`
- `src/languages/azure_policy/ast/expression.rs`
- `src/languages/azure_policy/ast/field.rs`
- `src/languages/azure_policy/parser/mod.rs`
- `src/languages/azure_policy/parser/condition.rs`
- `src/languages/azure_policy/parser/field.rs`

**Tests**: Parser unit tests for all condition types, field path shapes, and
comparison operators.

**Deliverable**: `parse_policy_rule(json) → PolicyRule` works for T1–T3 features.

### Phase 2: Core Compiler

**Goal**: Compile simple field conditions and effects to RVM bytecode.

**Files**:
- `src/languages/azure_policy/compiler/mod.rs`
- `src/languages/azure_policy/compiler/conditions.rs`
- `src/languages/azure_policy/compiler/fields.rs`
- `src/languages/azure_policy/compiler/effects.rs`

**Scope**: `allOf`, simple `field` conditions (no `[*]`), all comparison
operators, simple effects (deny, audit).

**Tests**: End-to-end tests: JSON policy + input → RVM evaluation → effect
value.

**Deliverable**: Can compile and evaluate policies like "deny if
supportsHttpsTrafficOnly != true".

### Phase 3: Full Conditions

**Goal**: Add `anyOf`, `not`, `in`/`notIn`, `like`/`match`, `exists`,
`contains`/`containsKey`.

**Files**: Extend `conditions.rs` with `anyOf` (multi-definition rules), `not`
(inversion), and all remaining operators.

**Tests**: One test per operator, nested logical combinations.

**Deliverable**: All T1–T2 features work.

### Phase 4: Wildcard and Iteration

**Goal**: Compile `[*]` field paths with correct universal quantification.

**Files**:
- `src/languages/azure_policy/compiler/loops.rs`

**Scope**: Single `[*]` (bare field condition → `LoopStart(Every)`), nested
`[*]`, empty array handling (vacuous truth), simple `count` (no where) via
`Count` instruction.

**Critical correctness**: Bare `[*]` is **universal** (∀ — all must match),
NOT existential. The loop must use `LoopStart(Every)` which exits on first
failure. See §6.2 and §6.5.1.

**Tests**: Array field conditions (all match, some fail, empty array), nested
array iteration, `not` wrapping `[*]` (De Morgan inversion).

**Deliverable**: All T3 features work.

### Phase 4b: Count and Scoping

**Goal**: Compile `count` with `where`, value count, `current()`, nested counts.

**Files**:
- `src/languages/azure_policy/compiler/count.rs`
- `src/languages/azure_policy/compiler/loops.rs` (extend with `ForEach` in
  count context, `count_scope_stack` management)

**Scope**: `count` with `where` (comprehension + Count), value count
(`CountSource::Value`), `current()` resolution from scope stack, nested counts,
`field()` inside `count.where`, iteration limits validation.

**Key design**: The `count_scope_stack` (§6.5.3) tracks active iteration scopes.
When compiling a field reference inside `count.where`, the compiler checks if the
field's array prefix matches an active scope — if so, it accesses via the current
element register instead of starting a new loop.

**Tests**: Filtered count, value count, nested count, `current()` in various
positions, empty arrays in count (= 0), iteration limit enforcement.

**Deliverable**: All T3b features work.

### Phase 5: Template Expressions

**Goal**: Compile ARM template expressions (`[parameters()]`, `[field()]`,
`[concat()]`, `[current()]`, etc.).

**Files**:
- `src/languages/azure_policy/parser/expression.rs`
- `src/languages/azure_policy/compiler/expressions.rs`

**Scope**: `[parameters()]`, `[field()]`, `[resourceGroup()]`,
`[subscription()]`, `[concat()]`, `[if()]`, `[toLower()]`, `[toUpper()]`,
`[current()]` (scope stack resolution).

**Tests**: Template expression parsing and compilation tests. `current()` tested
in combination with count (Phase 4b).

**Deliverable**: All T4 features work.

### Phase 6: Advanced Effects

**Goal**: Compile `modify` operations (add, replace, remove, addOrReplace),
including `[*]` targets for per-element modification.

**Files**: Extend `effects.rs`, use `loops.rs` for `[*]` in modify targets.

**Scope**: All modify operation types, `[*]` in field targets (§6.5.8 — emits
`ForEach` loop), `append` effect.

**Tests**: Modify effect compilation and evaluation. Per-element modify with
`[*]` targets.

**Deliverable**: T5 features work.

### Phase 7: Integration and Public API

**Goal**: Wire into `Engine`, expose public API, serialization.

**Files**:
- `src/compile.rs` — add `compile_azure_policy` function
- `src/engine.rs` — add `Engine::compile_azure_policy` method
- `src/languages/mod.rs` — add module declaration

**Tests**: Full integration tests, serialization round-trip.

**Deliverable**: Public API works end-to-end.

### Phase 8: Cross-Resource Effects (Future)

**Goal**: `auditIfNotExists` and `deployIfNotExists` requiring related resource
queries.

**Approach**: Use `HostAwait` instruction to suspend execution and request the
host to query for the related resource. On resume, check whether it exists and
evaluate the existence condition.

**Deliverable**: T6 features work.

### Phase 9: Input Normalizer

**Goal**: Build the runtime normalizer that transforms raw Azure resource JSON
into the `input.resource` envelope expected by compiled programs.

**Files**:
- `src/languages/azure_policy/normalizer/mod.rs`
- `src/languages/azure_policy/normalizer/alias_table.rs`

**Scope**: Alias short name resolution, sub-resource array detection,
case-insensitive field name normalization, input envelope construction
(`input.resource`, `input.parameters`, `input.context`).

**Spec**: See [alias-normalization.md](alias-normalization.md) §11.

**Deliverable**: Raw ARM resource JSON → normalized `input` envelope.

---

## 16. Relationship to Rego Compiler

The Azure Policy compiler is **independent** of the Rego compiler. It does not
parse Rego, does not use the Rego AST, and does not go through `CompiledPolicy`
or the Target/effect-resolution pipeline. It directly produces an RVM `Program`.

It reuses:
- The RVM `Program` struct and all instruction types
- The `InstructionData` parameter tables
- The `Value` type for literals
- The builtin function resolution infrastructure

It does **not** use:
- The `Target` struct or effect schema validation
- The `CompiledPolicy` / `TargetInfo` / `resolve_effect` pipeline
- Per-effect rule resolution (which requires knowing the effect at compile time)

The reason: Azure Policy's parameterized effects (`[parameters('effect')]`) mean
the effect name is often unknown at compile time. The compiled rule returns an
opaque `{ "effect": "<name>", "details": {...} }` object, and the host
determines which effect applies at evaluation time.

The two compilers share the same RVM output format, so their compiled programs
can be loaded, cached, and evaluated identically by the VM.

---

## 17. Serialization

Azure Policy compiled programs use the same serialization format as Rego
programs (version 3 with `REGO` magic bytes). The only difference is in the
`ProgramMetadata.source_info` field which indicates `"azure_policy"` instead
of a Rego source file.

This means:
- Existing deserialization code works unchanged.
- Rego and Azure Policy programs can be mixed in the same evaluation session.
- The VM cannot tell (and doesn't need to tell) whether a program came from
  Rego or Azure Policy JSON.

---

## 18. Design Decisions Summary

| Decision | Rationale |
|:---------|:---------|
| Independent compiler (not transpile to Rego) | Direct control over instruction selection. No Rego parse/compile overhead. Simpler error messages. |
| Single rule per policy | Azure Policy rules are single condition→effect pairs. No multi-rule dispatch needed within one policy. |
| `anyOf` via multi-definition rules | Reuses VM's existing multi-definition semantics. Clean, no new instructions. |
| `not` via helper rule + `Not` | Compile inner condition in helper rule; `Not` flips undefined→true / true→false. No `compile_soft` needed. |
| Bare `[*]` = universal (∀, `Every`) | Azure Policy specifies that ALL elements must match a bare field condition. This is the opposite of existential. Vacuous truth on empty arrays. |
| Count scope stack for `current()` | Clean compile-time resolution of `current()` references. The stack handles nested counts naturally — innermost scope wins. |
| Value count as separate `CountSource` variant | Cleanly separates field count (iterate resource array) from value count (iterate parameter/literal array). Same comprehension compilation. |
| Opaque effect result (no Target pipeline) | Parameterized effects mean the effect name is unknown at compile time. Returning `{ "effect": "<name>", ... }` and letting the host interpret it avoids the per-effect rule resolution that the Target system requires. |
| Normalized `input.resource` | See [aliases.md](aliases.md). Enables "compile once" — bytecode references alias short names which are stable. |
| Template expressions → `input` paths | `[parameters('x')]` → `input.parameters.x`. No runtime template parsing. |
| `count` via comprehension + Count | Comprehension collects matching elements; Count measures the result. Clean separation. |
| Builtin reuse | `regex.match`, `lower`, `upper`, `concat` are already in the Rego builtin table. |
| Case-insensitive string comparisons | Custom `azure.policy.*` comparison builtins handle case-insensitivity internally. Preserves Rego's case-sensitive semantics for Rego-authored policies. Type-safe for mixed types. See §6.2.2 and [comparison-strategy.md](comparison-strategy.md). |
| Per-operator undefined field handling | `notEquals`/`notIn`/`notContains` treat undefined as true; `equals`/`in`/`contains` treat undefined as false. Uses `IsDefined` + `IfThenElse` instead of blanket `AssertNotUndefined`. See §6.2.1 and [control-flow.md](control-flow.md). |
| `match` pattern → custom builtin | Azure Policy `match` uses `#`/`?` patterns, not regex. Pattern may come from a runtime parameter, so translation can't happen at compile time. A dedicated `azure.policy.match` builtin is simpler and faster than runtime regex compilation. See §6.3.2. |
| `contains` → `azure.policy.contains` builtin | Dual-mode (string substring vs array membership) and case-insensitivity are encapsulated in a single builtin call. No emitted `IsArray` + branch needed. See §6.3.1. |
| Modify `[*]` pass-through | Compiler passes `[*]` field paths through as literals; host handles per-element expansion. See [effects.md](effects.md) §3.4. |
| `HostAwait` for cross-resource | `auditIfNotExists`/`deployIfNotExists` need external resource queries. Three approaches documented in [effects.md](effects.md) §3.2 (HostAwait, two-rule result-driven, two-rule probing). `has_host_await` program metadata enables auto-selecting RunToCompletion vs Suspendable. |
