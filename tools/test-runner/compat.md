# External Test Suite Compatibility

**Date:** 2026-03-03
**Test suite:** `/Users/anakrish/OnCall/azure-policy-tests` (139 files, 785 cases)
**Alias catalog:** Full `ResourceTypesAndAliases.json` (5547 resource types)
**Data manifests:** `dataPolicyManifests/Prod/` (13 files, 15 data-plane resource types)

## Results Summary

| Metric | Count |
|--------|-------|
| Files  | 139   |
| Cases  | 785   |
| **Pass**   | **777 (98.9%)** |
| Fail   | 5     |
| Skip   | 3 (DenyAction) |
| File-errors | 9 (YAML multi-doc / missing policy) |

### Progress History

| Date | Pass | Rate | Delta | Notes |
|------|------|------|-------|-------|
| Initial | 597 | 77.1% | -- | Baseline (774 cases) |
| 2026-02-27 | 607 | 77.3% | +10 | Non-array Every, nested count |
| 2026-02-28 | 622 | 79.2% | +15 | fullName computation + parentResource injection |
| 2026-02-28b | 634 | 80.8% | +12 | Runtime effect param resolution |
| 2026-03-01 | 677 | 86.2% | +43 | Null host_await fallback for AINE/DINE |
| 2026-03-01b | 675 | 86.0% | -2 | Undefined/Null field distinction (+6, -2 alias regressions) |
| 2026-03-01c | 699 | 89.0% | +24 | Virtual element for [*] on non-collection |
| 2026-03-01d | 710 | 90.4% | +11 | Alias path prefix stripping |
| 2026-03-02 | 742 | 94.5% | +32 | Data-plane normalizer, PolicyIn/NotIn scalar, normalizer key casing |
| 2026-03-02b | 757 | 96.4% | +15 | String coercion for numeric counts, null LHS in PolicyIn/NotIn |
| 2026-03-02c | 763 | 97.2% | +6 | Split array delimiter, tag bracket notation |
| 2026-03-03 | 765 | 97.5% | +2 | Tags[tagName] with dots in tag names |
| 2026-03-03b | 773 | 98.5% | +8 | JSON unescape, objects as non-collections, inner wildcards, param coercion |
| 2026-03-03c | 777 | 98.9% | +4* | Data policy manifests, utcNow context, case-insensitive type, array rename |

*Note: Baseline for 2026-03-03c is 771 (2 pre-existing GuestConfiguration failures
were obscured in previous counts). True delta is +6 from 771.

---

## Current Failures (5 case failures + 9 file-level errors)

### Case-Level Failures (5)

#### SharedDashboard extension metadata paths (2)

| # | Test | Error |
|---|------|-------|
| 1 | SharedDashboard_NoInlineContent x 2 | expected Compliant, got Audit |

**Root cause:** Policy uses alias paths containing Azure Portal extension metadata
segments like `metadata.Extension-HubsExtension-PartType-MarkdownPart.settings.content.settings`.
This hyphenated notation encodes the extension type (`Extension/HubsExtension/PartType/MarkdownPart`)
into the alias path. Without `Microsoft.Portal/dashboards` aliases in the catalog,
the fallback path resolution includes this segment literally, failing to navigate the
actual resource structure.

#### GuestConfiguration NotApplicable scope (2)

| # | Test | Error |
|---|------|-------|
| 1 | GuestConfiguration_SecureShell_Audit (VM 2019) | expected NotApplicable, got AuditIfNotExists |
| 2 | GuestConfiguration_SetSecureShell_Deploy (VM 2019) | expected NotApplicable, got AuditIfNotExists |

**Root cause:** The tests expect "NotApplicable" for a VM with an older image
(Windows Server 2019). The policy's `if` clause matches the resource type and
the resource satisfies the `AuditIfNotExists` conditions, so the engine
correctly evaluates the effect. The "NotApplicable" expectation may depend on
runtime Guest Configuration agent scoping logic not modeled in the compiler.

#### Non-standard field paths (1)

| # | Test | Error |
|---|------|-------|
| 1 | VmsizeExistsTest step2 | expected NonCompliant, got Undefined |

**Root cause:** Test uses non-standard field path `Properties.VMSize` (with
capital `P`) on a resource where `properties` contents are flattened to root
by the normalizer. Compiler resolves to `properties.vmsize` but normalizer
flattens it to `vmsize` at root.

### File-Level Errors (9)

| Sub | Description | Count | Files |
|-----|-------------|-------|-------|
| YAML multi-doc | `---` separators not supported | 7 | Append, AuditDeny, AuditIfNotExists, DeployIfNotExists, EnvironmentResourceGroup, Modify, ModifyBoolean |
| Missing policy | Referenced .json not on disk | 2 | ValidateAzureKeyVaultDelete, ValidateTrafficManagerProfileDelete |

---

## Fixes Applied (597 -> 777, +180 tests over baseline)

### Session 2026-03-03c (771 -> 777, +6)

| Fix | Description | Tests Fixed |
|-----|-------------|-------------|
| #13 | Data policy manifest loading: `DataPolicyManifest` types, `load_data_policy_manifest_json()`, auto-discovery from `dataPolicyManifests/Prod/` | +4 (Factory_OutboundTraffic x2, AML x1, BannedTags x1) |
| #14 | `utcNow` context injection: populate `context.utcNow` with current timestamp for `utcNow()` template function | +2 (KeyVault_Certificates_Expiry x2) |
| #15 | `normalize_short_name`: strip `properties.` prefix from data-plane alias short names (normalizer flattens properties to root) | (infrastructure for #13) |
| #16 | Case-insensitive `type` field extraction: `extract_type_field()` in normalizer for resources with `"Type"` (capital T) | (infrastructure for #13) |
| #17 | Array-base rename in `apply_alias_entries`: when alias short name `X[*]` maps to ARM path `Y[*]` (different base), copy Y→X in normalized output | (infrastructure for BannedTags) |

### Session 2026-03-03b (765 -> 773, +8)

| Fix | Description | Tests Fixed |
|-----|-------------|-------------|
| #8 | JSON string unescaping: `json_unescape()` in parser for `\"`, `\\`, `\uXXXX` etc. | +1 (ContainsKeyTest step6) |
| #9 | Objects as non-collections: `[*]` on Object now treats as non-collection (virtual element for Every, false for Any) | +2 (ArrayInTest step6, ArrayNotInTest step14) |
| #10 | Case-insensitive normalizer: ROOT_FIELDS and properties flattening use case-insensitive key lookup | (infrastructure) |
| #11 | Inner unbound wildcards in count where: nested `[*]` inside count binding gets implicit allOf treatment | +3 (CountExpressionTest step2 + 2 others) |
| #12 | Test runner parameter coercion: YAML `true`/`false` → policy String `"Yes"`/`"No"` etc. | +2 (KeyVault FirewallEnabled) |

### Session 2026-03-02 / 2026-03-03 (710 -> 765, +55)

| Fix | Description | Tests Fixed |
|-----|-------------|-------------|
| #1 | Data-plane normalizer: `.Data` resources use `normalize_value()` + flatten properties | +32 (batch) |
| #2 | PolicyIn/PolicyNotIn scalar RHS: dispatch fallback `case_insensitive_equals(r, l)` | (included in batch) |
| #3 | Normalizer key casing: `normalize_value()` before `set_nested_value()` in `apply_alias_entries` | +10 |
| #4 | String operators on numeric counts: `coerce_to_string()` / `coerce_to_string_ci()` | +5 |
| #5 | PolicyIn/NotIn null LHS: coerce to `""` for comparison | +4 |
| #6 | Split function array delimiter: handle `Value::Array` as delimiter | +2 |
| #7 | Tags[tagName] bracket notation: parser + single-key emit for dot-containing names | +2 |

### Earlier Sessions (597 -> 710, +113)

| Fix | Description | Tests Fixed |
|-----|-------------|-------------|
| fullName computation | Compute fullName from resource id in test runner | +15 |
| Runtime effect params | `compile_effect_name_expression()` defers to runtime | +12 |
| Null host_await fallback | Inject `null` for AINE/DINE existence check | +43 |
| Undefined/Null distinction | Remove coalesce-to-null, add Undefined guards | +6 (-2 regressed) |
| Virtual element [*] | `IterationState::Single` for non-collection allOf | +24 |
| Alias prefix stripping | `strip_fq_prefix()` for unknown aliases | +11 |
| Non-array Every + nested count | Initial VM fixes | +10 |

---

## Remaining Work -- Priority Order

### Tier 1: Extension metadata alias paths (2 cases)

| Fix | Tests | Effort |
|-----|-------|--------|
| Portal extension metadata segment handling | SharedDashboard x 2 | Hard (no Portal aliases in any catalog) |

### Tier 2: GuestConfiguration NotApplicable scoping (2 cases)

| Fix | Tests | Effort |
|-----|-------|--------|
| Guest Configuration agent scope logic | GuestConfiguration x 2 | Hard (runtime scoping not in compiler) |

### Tier 3: Known limitations (1 case)

| Fix | Tests | Effort |
|-----|-------|--------|
| Non-standard `Properties.VMSize` field path | VmsizeExistsTest x 1 | Hard (properties prefix conflict) |

### Tier 4: Infrastructure (9 file-errors)

| Fix | Tests | Effort |
|-----|-------|--------|
| YAML multi-doc support | 7 files | Easy |
| Missing policy files | 2 files | External (not our bug) |
