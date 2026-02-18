# Rego Builtins — Verus Verification Priority

Complete catalog of 124 registered builtins (plus 3 direct-call helpers), ranked by
verification priority for Verus.

---

## Tier 1 — Critical Path (verify first)

Always-on, pure, used in nearly every policy, tight specs. These form the semantic
core of policy evaluation.

| Builtin | Module | Notes |
|---------|--------|-------|
| `==`, `!=`, `<`, `<=`, `>`, `>=` (via `compare`) | comparison | Foundation of every rule condition; called directly by interpreter |
| `+`, `-`, `*`, `/`, `%` (via `arithmetic_operation`) | numbers | Every numeric expression; called directly by interpreter |
| `count` | aggregates | Most-used aggregate; basis of "is empty" checks |
| `object.get` | objects | Core data access pattern |
| `object.keys` | objects | Key enumeration |
| `contains` | strings | String matching — bread and butter of policy |
| `startswith` | strings | Prefix matching |
| `endswith` | strings | Suffix matching |
| `intersection` (set) | sets | Set operator; underpins rule composition |
| `union` (set) | sets | Set operator |
| `difference` (set) | sets | Set operator; called directly by interpreter |
| `__builtin_sets.union` | sets | Binary set union (internal) |
| `__builtin_sets.intersection` | sets | Binary set intersection (internal) |
| `is_array` | types | Type dispatch; trivial |
| `is_boolean` | types | Type dispatch; trivial |
| `is_null` | types | Type dispatch; trivial |
| `is_number` | types | Type dispatch; trivial |
| `is_object` | types | Type dispatch; trivial |
| `is_set` | types | Type dispatch; trivial |
| `is_string` | types | Type dispatch; trivial |
| `type_name` | types | Returns type name string; trivial |
| `to_number` | conversions | Single pure function |

**~25 functions. Pure, no feature gates, no external deps. Ideal Verus targets.**

---

## Tier 2 — High Value (verify next)

Used frequently, still pure and self-contained, moderate complexity.

| Builtin | Module | Notes |
|---------|--------|-------|
| `abs` | numbers | Absolute value |
| `ceil` | numbers | Ceiling |
| `floor` | numbers | Floor |
| `round` | numbers | Rounding |
| `numbers.range` | numbers | Generates integer array; bounds correctness matters |
| `numbers.range_step` | numbers | Generates integer array with step |
| `sum` | aggregates | Algebraic: associative, commutative |
| `product` | aggregates | Algebraic: associative, commutative |
| `min` | aggregates | Idempotent, commutative |
| `max` | aggregates | Idempotent, commutative |
| `sort` | aggregates | Permutation + ordering |
| `array.concat` | arrays | Concatenation |
| `array.reverse` | arrays | Reverse; involution property |
| `array.slice` | arrays | Bounds checking |
| `object.filter` | objects | Filter keys by set/array/object |
| `object.remove` | objects | Remove keys by set/array/object |
| `object.subset` | objects | Recursive subset check |
| `object.union` | objects | Deep merge |
| `object.union_n` | objects | Deep merge of array of objects |
| `concat` | strings | Join with delimiter |
| `split` | strings | Split by delimiter |
| `replace` | strings | Replace all occurrences |
| `lower` | strings | To lowercase |
| `upper` | strings | To uppercase |
| `trim` | strings | Trim characters both ends |
| `trim_left` | strings | Trim characters left |
| `trim_right` | strings | Trim characters right |
| `trim_prefix` | strings | Remove prefix |
| `trim_suffix` | strings | Remove suffix |
| `trim_space` | strings | Trim whitespace |
| `indexof` | strings | First occurrence index |
| `indexof_n` | strings | All occurrence indices |
| `strings.count` | strings | Non-overlapping occurrence count |
| `substring` | strings | Extract by offset and length |
| `strings.reverse` | strings | Reverse; involution property |
| `format_int` | strings | Base conversion (2, 8, 10, 16) |
| `bits.and` | bitwise | Bitwise AND |
| `bits.or` | bitwise | Bitwise OR |
| `bits.xor` | bitwise | Bitwise XOR |
| `bits.negate` | bitwise | Bitwise NOT |
| `bits.lsh` | bitwise | Left shift |
| `bits.rsh` | bitwise | Right shift |
| `json.filter` | objects | Recursive path-based filter |
| `json.remove` | objects | Recursive path-based remove |

**~45 functions. No external deps. Good Verus targets with clear algebraic specs.**

---

## Tier 3 — Important but harder

Feature-gated or depending on external crates. Verification requires modeling
external behavior or treating it as trusted.

| Builtin | Module | External Dep | Notes |
|---------|--------|-------------|-------|
| `sprintf` | strings | — | Complex Go-style format string parsing |
| `strings.replace_n` | strings | — | Multiple pattern replacement; ordering matters |
| `strings.any_prefix_match` | strings | — | Cross-product prefix matching |
| `strings.any_suffix_match` | strings | — | Cross-product suffix matching |
| `json.marshal` | encoding | serde_json | Serialization |
| `json.unmarshal` | encoding | serde_json | Deserialization |
| `json.is_valid` | encoding | serde_json | Validation |
| `json.marshal_with_options` | encoding | serde_json | Serialization with options |
| `base64.encode` | encoding | base64 crate | Encoding roundtrip |
| `base64.decode` | encoding | base64 crate | Encoding roundtrip |
| `base64.is_valid` | encoding | base64 crate | Validation |
| `base64url.encode` | encoding | base64 crate | URL-safe variant |
| `base64url.decode` | encoding | base64 crate | URL-safe variant |
| `base64url.encode_no_pad` | encoding | base64 crate | No-padding variant |
| `hex.encode` | encoding | hex crate | Hex encoding |
| `hex.decode` | encoding | hex crate | Hex decoding |
| `graph.reachable` | graph | — | BFS correctness |
| `graph.reachable_paths` | graph | — | DFS with path tracking |
| `walk` | graph | — | Recursive value traversal |
| `units.parse` | units | — | SI/IEC unit string parsing |
| `units.parse_bytes` | units | — | Byte unit string parsing |
| `regex.match` | regex | regex crate | External engine |
| `regex.is_valid` | regex | regex crate | Validation |
| `regex.find_n` | regex | regex crate | Find N matches |
| `regex.find_all_string_submatch_n` | regex | regex crate | Capture groups |
| `regex.replace` | regex | regex crate | Replacement |
| `regex.split` | regex | regex crate | Split by regex |
| `regex.template_match` | regex | regex crate | Template matching |
| `glob.match` | glob | globset crate | Glob pattern matching |
| `glob.quote_meta` | glob | — | Escape metacharacters |
| `net.cidr_is_valid` | net | ipnet crate | CIDR validation |
| `net.cidr_contains` | net | ipnet crate | CIDR containment |
| `net.cidr_expand` | net | ipnet crate | CIDR expansion |

**~33 functions. Verification possible but requires abstraction over external deps.**

---

## Tier 4 — Low priority / trust boundary

Side-effectful, nondeterministic, or stub implementations. Verify the interface
contract, not internals.

| Builtin | Module | Notes |
|---------|--------|-------|
| `rand.intn` | numbers | Nondeterministic; verify caching contract only |
| `time.now_ns` | time | Current time; nondeterministic |
| `time.clock` | time | External chrono dep |
| `time.date` | time | External chrono dep |
| `time.add_date` | time | External chrono dep |
| `time.diff` | time | Complex calendar math |
| `time.format` | time | Go-style layout strings |
| `time.parse_ns` | time | Go-style layout parsing |
| `time.parse_rfc3339_ns` | time | RFC 3339 parsing |
| `time.parse_duration_ns` | time | Duration string parsing |
| `time.weekday` | time | Weekday name |
| `semver.compare` | semver | External semver crate |
| `semver.is_valid` | semver | External semver crate |
| `uuid.rfc4122` | uuid | Nondeterministic |
| `uuid.parse` | uuid | External uuid crate |
| `http.send` | http | Stub (always undefined) |
| `opa.runtime` | opa | Runtime metadata |
| `trace` | tracing | Side-effect only |
| `test.sleep` | test | Test utility |
| `json.match_schema` | objects | External jsonschema crate |
| `json.verify_schema` | objects | External jsonschema crate |
| `urlquery.encode` | encoding | URL encoding |
| `urlquery.decode` | encoding | URL decoding |
| `urlquery.encode_object` | encoding | URL encoding |
| `urlquery.decode_object` | encoding | URL decoding |
| `yaml.marshal` | encoding | External serde_yaml |
| `yaml.unmarshal` | encoding | External serde_yaml |
| `yaml.is_valid` | encoding | External serde_yaml |

**~28 functions. Model as trusted axioms or verify only interface contracts.**

---

## Recommended Verification Order

1. **Tier 1 first** — semantic core. Proving comparison, arithmetic, type checks,
   `count`, `object.get`, and set operations correct gives a verified foundation
   for nearly all real policies.

2. **Tier 2 next** — extends coverage to the full always-on builtin surface. After
   Tier 1 + Tier 2, ~70 functions are verified covering the vast majority of
   policy evaluation paths.

3. **Tier 3 selectively** — pick based on what target policies actually use.
   `graph.reachable` and `json.marshal`/`unmarshal` are high-value. Regex/glob
   are best modeled as axioms.

4. **Tier 4 as axioms** — define spec-level contracts and assume them. Verify only
   caching/memoization contracts where relevant.

## Key Properties Worth Proving

| Category | Properties |
|----------|-----------|
| Comparison | Reflexivity, antisymmetry, transitivity, totality |
| Arithmetic | Commutativity, associativity, identity, division-by-zero error |
| Aggregates | `sort` is a permutation and ordered; `min`/`max` are idempotent |
| Sets | `union`/`intersection` commutative, associative, idempotent; de Morgan |
| Objects | `union` is idempotent on identical objects; `filter`/`remove` complementary |
| Strings | `split`/`concat` roundtrip; `reverse` is an involution; `trim_prefix`/`startswith` relationship |
| Types | `is_*` predicates are mutually exclusive and exhaustive |
| Encoding | `encode`/`decode` roundtrip for base64, hex, JSON |
| Arrays | `reverse` is an involution; `concat` is associative; `slice` bounds |
