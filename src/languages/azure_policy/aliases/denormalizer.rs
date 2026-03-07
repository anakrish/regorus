// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Normalized `input.resource` → ARM JSON reverse transformation.
//!
//! The denormalizer reconstructs the original ARM resource JSON from the
//! normalized `input.resource` structure produced by [`super::normalizer`].
//!
//! ## Transformations reversed
//!
//! | Normalizer step | Denormalizer reversal |
//! |:----------------|:----------------------|
//! | Root `properties` flattened into root | Non-root fields moved back under `properties` |
//! | Sub-resource element `properties` flattened | Element fields re-wrapped under `properties` |
//! | All keys lowercased | Key casing restored from alias metadata |
//! | Per-alias versioned paths resolved | Values written to versioned ARM paths |
//! | Collision-safe keys (`_p_X`) | Restored to `properties.X` |
//! | Array base renames | Reversed using alias path info |
//!
//! ## Limitations
//!
//! - **Tag/identity key casing**: The normalizer shallow-lowercases `tags` and
//!   `identity` keys. Original casing cannot be recovered since it's not stored
//!   in the alias catalog. These fields are returned with lowercase keys.
//!
//! - **Non-aliased field casing**: Fields that have no matching alias entry
//!   cannot have their key casing restored. They remain lowercase.
//!
//! - **Element field remaps**: When a versioned ARM path renames a field within
//!   sub-resource array elements (e.g., `prio` → `priority`), the denormalizer
//!   does not currently reverse this. This affects <0.1% of aliases in practice.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use serde_json::{Map, Value};

use super::types::{ResolvedAliases, ResolvedEntry};
use super::AliasRegistry;

use super::normalizer::{is_root_field_collision, ROOT_FIELDS};

/// Sub-resource array element envelope fields that remain at the element root
/// (not under `properties`) during re-wrapping.
///
/// These are the standard ARM envelope fields found in sub-resource entities.
/// The [`classify_envelope_fields`] function augments this list with
/// alias-derived information for each specific sub-resource array.
const ELEMENT_ENVELOPE_FIELDS: &[&str] = &["name", "type", "id", "etag"];

/// Denormalize a normalized resource back to ARM JSON structure.
///
/// The resource type is extracted from the `type` field of `normalized` and
/// used to look up alias entries in the registry.
///
/// # Arguments
///
/// * `normalized` — The normalized JSON object (as produced by
///   [`super::normalizer::normalize`]).
/// * `registry` — Optional alias registry for casing restoration and path
///   mapping.  When `None`, only structural reconstruction is performed
///   (properties wrapping, sub-resource re-wrapping) without casing
///   restoration.
/// * `api_version` — Optional API version for versioned path selection.
///   When provided, alias paths are resolved via
///   [`ResolvedEntry::select_path`] to reconstruct the correct ARM structure
///   for that version.
///
/// # Returns
///
/// A JSON object with the ARM resource structure restored:
/// - Root-level ARM fields (`name`, `type`, `location`, etc.) at the top level
/// - All other fields wrapped under `properties`
/// - Sub-resource array elements re-wrapped with `properties`
/// - Key casing restored from alias metadata where available
pub fn denormalize(
    normalized: &Value,
    registry: Option<&AliasRegistry>,
    api_version: Option<&str>,
) -> Value {
    let aliases = registry.and_then(|r| extract_type_field(normalized).and_then(|rt| r.get(rt)));
    denormalize_with_aliases(normalized, aliases, api_version)
}

/// Extract the `type` field value from a resource JSON object.
///
/// Performs a case-insensitive key lookup so both `"type"` and `"Type"` work.
fn extract_type_field(resource: &Value) -> Option<&str> {
    resource.as_object().and_then(|obj| {
        obj.iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("type"))
            .and_then(|(_, v)| v.as_str())
    })
}

/// Internal denormalization with pre-resolved alias data.
///
/// This is the core implementation used by [`denormalize`] after looking up
/// the alias entries from the registry.  Also used directly in unit tests
/// that construct `ResolvedAliases` by hand.
pub(crate) fn denormalize_with_aliases(
    normalized: &Value,
    aliases: Option<&ResolvedAliases>,
    api_version: Option<&str>,
) -> Value {
    let obj = match normalized.as_object() {
        Some(o) => o,
        None => return normalized.clone(),
    };

    let entries = aliases.map(|a| &a.entries);
    let casing_map = entries.map(build_casing_map).unwrap_or_default();

    let is_data_plane =
        extract_type_field(normalized).is_some_and(|t| t.to_ascii_lowercase().contains(".data/"));

    let mut result = Map::new();
    let mut properties = Map::new();

    // ── Phase 1: Root fields → ARM root with original casing ────────────
    //
    // ROOT_FIELDS are always at the ARM resource root.  Copy them from the
    // normalized object using the original ROOT_FIELD casing.
    //
    // `tags` and `identity` had their keys shallow-lowercased by the
    // normalizer. We cannot undo that, so they're copied as-is.
    for &field in ROOT_FIELDS {
        let lc = field.to_ascii_lowercase();
        if let Some(val) = obj.get(&lc) {
            let restored =
                if field.eq_ignore_ascii_case("tags") || field.eq_ignore_ascii_case("identity") {
                    val.clone()
                } else {
                    denormalize_value(val, &casing_map)
                };
            result.insert(field.to_string(), restored);
        }
    }

    // ── Phase 2a: Non-aliased, non-root fields ─────────────────────────
    //
    // Fields that don't match any alias entry are placed under `properties`
    // (control-plane) or kept at root (data-plane) with best-effort casing.
    // These are processed first so that aliased fields (Phase 2b) can
    // overwrite if the ARM path overlaps.
    for (key, val) in obj {
        if ROOT_FIELDS.iter().any(|f| f.eq_ignore_ascii_case(key)) {
            continue;
        }

        let lookup_key = key.strip_prefix("_p_").unwrap_or(key);
        let has_alias = entries.is_some_and(|e| e.contains_key(lookup_key));
        if has_alias {
            continue; // Handled in Phase 2b
        }

        let denorm_val = denormalize_value(val, &casing_map);

        if key.starts_with("_p_") {
            // Collision-safe key without matching alias → properties.{original}
            let restored = restore_casing(lookup_key, &casing_map);
            properties.insert(restored, denorm_val);
        } else if is_data_plane {
            // Data-plane: unknown fields stay at root (they were root-level
            // in the original ARM data-plane resource).
            let restored = restore_casing(key, &casing_map);
            result.insert(restored, denorm_val);
        } else {
            // Control-plane: unknown fields go under properties.
            let restored = restore_casing(key, &casing_map);
            properties.insert(restored, denorm_val);
        }
    }

    // ── Phase 2b: Aliased scalar fields → versioned ARM paths ───────────
    //
    // For each scalar alias (no `[*]`), read from the normalized output at
    // the alias short name and write to the ARM path selected by
    // `api_version`.  This handles versioned paths where the ARM field name
    // differs from the alias short name.
    if let Some(entries) = entries {
        for (lc_key, entry) in entries {
            if entry.short_name.contains("[*]") {
                continue; // Array aliases handled in Phase 2c
            }

            // Skip sub-resource array root entries — their structure is
            // handled by Phase 2a (the array itself) and Phase 3 (re-wrap).
            if aliases.is_some_and(|a| {
                a.sub_resource_arrays
                    .iter()
                    .any(|s| s.eq_ignore_ascii_case(&entry.short_name))
            }) {
                continue;
            }

            // Determine the key in the normalized output.
            let normalized_key = if is_root_field_collision(&entry.short_name, &entry.default_path)
            {
                alloc::format!("_p_{}", entry.short_name.to_ascii_lowercase())
            } else {
                lc_key.clone()
            };

            let val = match obj.get(&normalized_key) {
                Some(v) => v,
                None => continue,
            };

            let arm_path = entry.select_path(api_version);
            let denorm_val = denormalize_value(val, &casing_map);

            if let Some(props_path) = arm_path.strip_prefix("properties.") {
                set_nested_value(&mut properties, props_path, denorm_val);
            } else {
                set_nested_value(&mut result, arm_path, denorm_val);
            }
        }

        // ── Phase 2c: Array base renames ────────────────────────────────
        //
        // When an alias like `tags[*]` maps to ARM path `kvtags[*]`, the
        // normalizer copies the array under the alias base name.  Reverse
        // this by moving from the alias base to the ARM base.
        let mut array_renames: Vec<(String, String)> = Vec::new(); // (alias_base_lc, arm_base)

        for (_lc_key, entry) in entries {
            if !entry.short_name.contains("[*]") {
                continue;
            }

            let arm_path = entry.select_path(api_version);
            if let (Some(short_base), Some(arm_base_raw)) = (
                entry.short_name.split("[*]").next(),
                arm_path.split("[*]").next(),
            ) {
                let arm_base = arm_base_raw
                    .strip_prefix("properties.")
                    .unwrap_or(arm_base_raw);
                if !short_base.eq_ignore_ascii_case(arm_base) {
                    let pair = (short_base.to_ascii_lowercase(), arm_base.to_string());
                    if !array_renames.contains(&pair) {
                        array_renames.push(pair);
                    }
                }
            }
        }

        for (alias_base_lc, arm_base) in &array_renames {
            // Move from alias base name to ARM base name in properties.
            let alias_key = find_key_ci(&properties, alias_base_lc);
            if let Some(key) = alias_key {
                if let Some(val) = properties.remove(&key) {
                    properties.insert(arm_base.clone(), val);
                }
            }
        }
    }

    // ── Phase 3: Re-wrap sub-resource array elements ────────────────────
    //
    // Sub-resource arrays had their element `properties` flattened by the
    // normalizer.  Re-wrap by moving non-envelope fields back under each
    // element's `properties` object.
    if let Some(aliases) = aliases {
        if !aliases.sub_resource_arrays.is_empty() {
            rewrap_sub_resource_arrays(
                &mut properties,
                &aliases.sub_resource_arrays,
                &aliases.entries,
            );
        }
    }

    // ── Phase 4: Attach properties to result ────────────────────────────
    if !properties.is_empty() {
        if let Some(Value::Object(existing)) = result.get_mut("properties") {
            for (k, v) in properties {
                existing.entry(k).or_insert(v);
            }
        } else {
            result.insert("properties".to_string(), Value::Object(properties));
        }
    }

    Value::Object(result)
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper functions
// ─────────────────────────────────────────────────────────────────────────────

/// Build a mapping from lowercase key → original-cased key from alias entries.
///
/// Sources of original casing:
/// - [`ROOT_FIELDS`] constant (e.g., `managedBy`, `apiVersion`)
/// - `ResolvedEntry::short_name` segments (e.g., `supportsHttpsTrafficOnly`)
/// - `ResolvedEntry::default_path` segments (e.g., `properties.accessTier`)
fn build_casing_map(entries: &BTreeMap<String, ResolvedEntry>) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();

    // ROOT_FIELDS provide canonical casing for root-level fields.
    for &field in ROOT_FIELDS {
        map.insert(field.to_ascii_lowercase(), field.to_string());
    }

    for entry in entries.values() {
        // Extract casing from each segment of the alias short name.
        for segment in entry.short_name.split('.') {
            let clean = segment.replace("[*]", "");
            if !clean.is_empty() {
                map.entry(clean.to_ascii_lowercase())
                    .or_insert_with(|| clean.to_string());
            }
        }

        // Extract casing from each segment of the default ARM path.
        for segment in entry.default_path.split('.') {
            let clean = segment.replace("[*]", "");
            // Skip "properties" — it's a structural wrapper, not a field name.
            if !clean.is_empty() && !clean.eq_ignore_ascii_case("properties") {
                map.entry(clean.to_ascii_lowercase())
                    .or_insert_with(|| clean.to_string());
            }
        }
    }

    map
}

/// Restore the original casing of a key using the casing map.
///
/// Returns the original-cased key if found, otherwise returns `key` unchanged.
fn restore_casing(key: &str, casing_map: &BTreeMap<String, String>) -> String {
    casing_map
        .get(&key.to_ascii_lowercase())
        .cloned()
        .unwrap_or_else(|| key.to_string())
}

/// Recursively restore key casing in a JSON value.
///
/// - **Objects**: keys are restored via the casing map; child values are
///   recursed.
/// - **Arrays**: each element is recursed.
/// - **Scalars**: returned as-is.
fn denormalize_value(value: &Value, casing_map: &BTreeMap<String, String>) -> Value {
    match value {
        Value::Object(obj) => {
            let mut result = Map::new();
            for (k, v) in obj {
                let restored_key = restore_casing(k, casing_map);
                result.insert(restored_key, denormalize_value(v, casing_map));
            }
            Value::Object(result)
        }
        Value::Array(arr) => {
            let items: Vec<Value> = arr
                .iter()
                .map(|v| denormalize_value(v, casing_map))
                .collect();
            Value::Array(items)
        }
        _ => value.clone(),
    }
}

/// Write a value at a dot-separated path in a JSON object, creating
/// intermediate objects as needed.
///
/// Unlike the normalizer's `set_nested_value`, this preserves the original
/// casing of path segments (the caller is responsible for providing
/// correctly-cased paths).
fn set_nested_value(target: &mut Map<String, Value>, path: &str, value: Value) {
    let segments: Vec<&str> = path.split('.').collect();
    if segments.is_empty() {
        return;
    }
    if segments.len() == 1 {
        target.insert(segments[0].to_string(), value);
        return;
    }
    let mut current = target;
    for &segment in &segments[..segments.len() - 1] {
        let entry = current
            .entry(segment.to_string())
            .or_insert_with(|| Value::Object(Map::new()));
        current = match entry.as_object_mut() {
            Some(m) => m,
            None => return, // Can't navigate into a non-object
        };
    }
    if let Some(&last) = segments.last() {
        current.insert(last.to_string(), value);
    }
}

/// Find a key in a JSON object map using case-insensitive comparison.
fn find_key_ci(obj: &Map<String, Value>, key: &str) -> Option<String> {
    obj.keys().find(|k| k.eq_ignore_ascii_case(key)).cloned()
}

// ─────────────────────────────────────────────────────────────────────────────
// Sub-resource array re-wrapping
// ─────────────────────────────────────────────────────────────────────────────

/// Re-wrap sub-resource array elements by moving non-envelope fields back
/// under each element's `properties` object.
///
/// Sub-resource arrays are processed from deepest nesting level first so
/// that inner arrays (e.g., `subnets.ipConfigurations`) are re-wrapped
/// before their parent arrays (e.g., `subnets`).
fn rewrap_sub_resource_arrays(
    properties: &mut Map<String, Value>,
    sub_arrays: &[String],
    entries: &BTreeMap<String, ResolvedEntry>,
) {
    // Sort by nesting depth (deepest first).
    let mut sorted: Vec<&String> = sub_arrays.iter().collect();
    sorted.sort_by(|a, b| {
        let depth_a = a.chars().filter(|&c| c == '.').count();
        let depth_b = b.chars().filter(|&c| c == '.').count();
        depth_b.cmp(&depth_a) // descending
    });

    for sub_array_path in sorted {
        let envelope_fields = classify_envelope_fields(sub_array_path, entries);
        let parts: Vec<&str> = sub_array_path.split('.').collect();

        if parts.len() == 1 {
            // Top-level sub-resource array directly in properties.
            let key = find_key_ci(properties, parts[0]);
            if let Some(key) = key {
                if let Some(Value::Array(arr)) = properties.get_mut(&key) {
                    for elem in arr.iter_mut() {
                        *elem = rewrap_element(elem, &envelope_fields);
                    }
                }
            }
        } else {
            // Nested sub-resource array: navigate to parent elements,
            // then re-wrap inner array elements.
            let parent_parts = &parts[..parts.len() - 1];
            let array_name = parts[parts.len() - 1];
            rewrap_nested_array(properties, parent_parts, array_name, &envelope_fields);
        }
    }
}

/// Determine which element-level fields are envelope fields (stay at the
/// element root, not under `properties`) for a given sub-resource array.
///
/// Starts with the default [`ELEMENT_ENVELOPE_FIELDS`] and augments with
/// alias-derived information: if an alias's ARM path has `[*].field`
/// (without a `properties.` prefix after the wildcard), `field` is an
/// envelope field.
fn classify_envelope_fields(
    sub_array_path: &str,
    entries: &BTreeMap<String, ResolvedEntry>,
) -> BTreeSet<String> {
    let mut envelope = BTreeSet::new();
    for &f in ELEMENT_ENVELOPE_FIELDS {
        envelope.insert(f.to_ascii_lowercase());
    }

    // Build the wildcard prefix for this sub-resource level.
    // "securityRules"            → "securityrules[*]."
    // "subnets.ipConfigurations" → "subnets[*].ipconfigurations[*]."
    let wildcard_prefix: String = {
        let parts: Vec<&str> = sub_array_path.split('.').collect();
        let mut prefix = String::new();
        for (i, part) in parts.iter().enumerate() {
            if i > 0 {
                prefix.push_str("[*].");
            }
            prefix.push_str(&part.to_ascii_lowercase());
        }
        prefix.push_str("[*].");
        prefix
    };

    for (lc_key, entry) in entries {
        if !lc_key.starts_with(&wildcard_prefix) {
            continue;
        }
        let field = &lc_key[wildcard_prefix.len()..];
        let first_segment = field.split('.').next().unwrap_or(field);

        // Check the ARM path after the last `[*].`.
        let arm_after_last_wildcard = entry.default_path.rsplit("[*].").next().unwrap_or("");

        if !arm_after_last_wildcard.starts_with("properties.") {
            // No `properties.` wrapper → this is an envelope field.
            envelope.insert(first_segment.to_ascii_lowercase());
        }
    }

    envelope
}

/// Recursively navigate nested arrays and re-wrap elements of the innermost
/// sub-resource array.
fn rewrap_nested_array(
    obj: &mut Map<String, Value>,
    parent_parts: &[&str],
    array_name: &str,
    envelope_fields: &BTreeSet<String>,
) {
    if parent_parts.is_empty() {
        return;
    }

    let parent_key = match find_key_ci(obj, parent_parts[0]) {
        Some(k) => k,
        None => return,
    };

    let parent_arr = match obj.get_mut(&parent_key) {
        Some(Value::Array(arr)) => arr,
        _ => return,
    };

    for element in parent_arr.iter_mut() {
        let elem_obj = match element.as_object_mut() {
            Some(o) => o,
            None => continue,
        };

        if parent_parts.len() > 1 {
            // More nesting levels to navigate.
            rewrap_nested_array(elem_obj, &parent_parts[1..], array_name, envelope_fields);
        } else {
            // At the parent element level — find the target array and re-wrap.
            let arr_key = match find_key_ci(elem_obj, array_name) {
                Some(k) => k,
                None => continue,
            };
            if let Some(Value::Array(arr)) = elem_obj.get_mut(&arr_key) {
                for inner_elem in arr.iter_mut() {
                    *inner_elem = rewrap_element(inner_elem, envelope_fields);
                }
            }
        }
    }
}

/// Re-wrap a single sub-resource array element by moving non-envelope
/// fields back under a `properties` object.
fn rewrap_element(element: &Value, envelope_fields: &BTreeSet<String>) -> Value {
    let obj = match element.as_object() {
        Some(o) => o,
        None => return element.clone(),
    };

    let mut envelope = Map::new();
    let mut props = Map::new();

    for (key, val) in obj {
        if envelope_fields.contains(&key.to_ascii_lowercase()) {
            envelope.insert(key.clone(), val.clone());
        } else {
            props.insert(key.clone(), val.clone());
        }
    }

    if !props.is_empty() {
        envelope.insert("properties".to_string(), Value::Object(props));
    }

    Value::Object(envelope)
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::unwrap_used)]
mod tests {
    use alloc::string::ToString as _;
    use alloc::vec;

    use super::*;
    use serde_json::json;

    fn make_entry(short: &str, default: &str, versioned: Vec<(&str, &str)>) -> ResolvedEntry {
        ResolvedEntry {
            short_name: short.to_string(),
            default_path: default.to_string(),
            versioned_paths: versioned
                .into_iter()
                .map(|(v, p)| (v.to_string(), p.to_string()))
                .collect(),
            metadata: None,
        }
    }

    fn make_aliases(
        resource_type: &str,
        entries: Vec<(&str, ResolvedEntry)>,
        sub_resource_arrays: Vec<&str>,
    ) -> ResolvedAliases {
        let mut map = BTreeMap::new();
        for (key, entry) in entries {
            map.insert(key.to_string(), entry);
        }
        ResolvedAliases {
            resource_type: resource_type.to_string(),
            entries: map,
            sub_resource_arrays: sub_resource_arrays.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn denormalize_wraps_properties() {
        let normalized = json!({
            "name": "myStorage",
            "type": "Microsoft.Storage/storageAccounts",
            "location": "westus2",
            "supportshttpstrafficonly": true,
            "ishnsenabled": false
        });

        let result = denormalize(&normalized, None, None);
        assert_eq!(result["name"], "myStorage");
        assert_eq!(result["type"], "Microsoft.Storage/storageAccounts");
        assert_eq!(result["location"], "westus2");
        assert_eq!(result["properties"]["supportshttpstrafficonly"], true);
        assert_eq!(result["properties"]["ishnsenabled"], false);
        assert!(result.get("supportshttpstrafficonly").is_none());
    }

    #[test]
    fn denormalize_restores_casing_from_aliases() {
        let aliases = make_aliases(
            "Microsoft.Storage/storageAccounts",
            vec![
                (
                    "supportshttpstrafficonly",
                    make_entry(
                        "supportsHttpsTrafficOnly",
                        "properties.supportsHttpsTrafficOnly",
                        vec![],
                    ),
                ),
                (
                    "accesstier",
                    make_entry("accessTier", "properties.accessTier", vec![]),
                ),
            ],
            vec![],
        );

        let normalized = json!({
            "name": "myStorage",
            "type": "Microsoft.Storage/storageAccounts",
            "supportshttpstrafficonly": true,
            "accesstier": "Hot"
        });

        let result = denormalize_with_aliases(&normalized, Some(&aliases), None);
        assert_eq!(result["name"], "myStorage");
        assert_eq!(result["properties"]["supportsHttpsTrafficOnly"], true);
        assert_eq!(result["properties"]["accessTier"], "Hot");
    }

    #[test]
    fn denormalize_versioned_path() {
        let aliases = make_aliases(
            "test",
            vec![(
                "isenabled",
                make_entry(
                    "isEnabled",
                    "properties.isEnabled",
                    vec![("2020-01-01", "properties.enabled")],
                ),
            )],
            vec![],
        );

        let normalized = json!({
            "type": "test",
            "isenabled": true
        });

        // Without API version → uses default path
        let result = denormalize_with_aliases(&normalized, Some(&aliases), None);
        assert_eq!(result["properties"]["isEnabled"], true);

        // With matching API version → uses versioned path
        let result = denormalize_with_aliases(&normalized, Some(&aliases), Some("2020-01-01"));
        assert_eq!(result["properties"]["enabled"], true);
        assert!(result["properties"].get("isEnabled").is_none());
    }

    #[test]
    fn denormalize_collision_safe_key() {
        let aliases = make_aliases(
            "test",
            vec![("type", make_entry("type", "properties.type", vec![]))],
            vec![],
        );

        let normalized = json!({
            "type": "test/resource",
            "_p_type": "SubType"
        });

        let result = denormalize_with_aliases(&normalized, Some(&aliases), None);
        assert_eq!(result["type"], "test/resource");
        assert_eq!(result["properties"]["type"], "SubType");
    }

    #[test]
    fn denormalize_sub_resource_array() {
        let aliases = make_aliases(
            "Microsoft.Network/networkSecurityGroups",
            vec![
                (
                    "securityrules[*].protocol",
                    make_entry(
                        "securityRules[*].protocol",
                        "properties.securityRules[*].properties.protocol",
                        vec![],
                    ),
                ),
                (
                    "securityrules[*].access",
                    make_entry(
                        "securityRules[*].access",
                        "properties.securityRules[*].properties.access",
                        vec![],
                    ),
                ),
                (
                    "securityrules[*].name",
                    make_entry(
                        "securityRules[*].name",
                        "properties.securityRules[*].name",
                        vec![],
                    ),
                ),
            ],
            vec!["securityRules"],
        );

        let normalized = json!({
            "name": "myNsg",
            "type": "Microsoft.Network/networkSecurityGroups",
            "securityrules": [
                {
                    "name": "rule1",
                    "protocol": "Tcp",
                    "access": "Allow"
                },
                {
                    "name": "rule2",
                    "protocol": "*",
                    "access": "Deny"
                }
            ]
        });

        let result = denormalize_with_aliases(&normalized, Some(&aliases), None);
        let rules = result["properties"]["securityRules"].as_array().unwrap();
        assert_eq!(rules.len(), 2);

        // Envelope fields stay at element root
        assert_eq!(rules[0]["name"], "rule1");
        // Properties fields go under `properties`
        assert_eq!(rules[0]["properties"]["protocol"], "Tcp");
        assert_eq!(rules[0]["properties"]["access"], "Allow");
        assert!(rules[0].get("protocol").is_none());

        assert_eq!(rules[1]["name"], "rule2");
        assert_eq!(rules[1]["properties"]["protocol"], "*");
        assert_eq!(rules[1]["properties"]["access"], "Deny");
    }

    #[test]
    fn denormalize_nested_sub_resource_arrays() {
        let aliases = make_aliases(
            "Microsoft.Network/virtualNetworks",
            vec![
                (
                    "subnets[*].addressprefix",
                    make_entry(
                        "subnets[*].addressPrefix",
                        "properties.subnets[*].properties.addressPrefix",
                        vec![],
                    ),
                ),
                (
                    "subnets[*].name",
                    make_entry(
                        "subnets[*].name",
                        "properties.subnets[*].name",
                        vec![],
                    ),
                ),
                (
                    "subnets[*].ipconfigurations[*].privateipaddress",
                    make_entry(
                        "subnets[*].ipConfigurations[*].privateIPAddress",
                        "properties.subnets[*].properties.ipConfigurations[*].properties.privateIPAddress",
                        vec![],
                    ),
                ),
                (
                    "subnets[*].ipconfigurations[*].name",
                    make_entry(
                        "subnets[*].ipConfigurations[*].name",
                        "properties.subnets[*].properties.ipConfigurations[*].name",
                        vec![],
                    ),
                ),
            ],
            vec!["subnets", "subnets.ipConfigurations"],
        );

        let normalized = json!({
            "name": "myVnet",
            "type": "Microsoft.Network/virtualNetworks",
            "subnets": [
                {
                    "name": "subnet1",
                    "addressprefix": "10.0.0.0/24",
                    "ipconfigurations": [
                        {
                            "name": "ipconfig1",
                            "privateipaddress": "10.0.0.4"
                        }
                    ]
                }
            ]
        });

        let result = denormalize_with_aliases(&normalized, Some(&aliases), None);
        let subnets = result["properties"]["subnets"].as_array().unwrap();

        // First level: subnet envelope + properties
        assert_eq!(subnets[0]["name"], "subnet1");
        assert_eq!(subnets[0]["properties"]["addressPrefix"], "10.0.0.0/24");
        assert!(subnets[0].get("addressprefix").is_none());

        // Second level: ipConfig envelope + properties
        let ip_configs = subnets[0]["properties"]["ipConfigurations"]
            .as_array()
            .unwrap();
        assert_eq!(ip_configs[0]["name"], "ipconfig1");
        assert_eq!(ip_configs[0]["properties"]["privateIPAddress"], "10.0.0.4");
        assert!(ip_configs[0].get("privateipaddress").is_none());
    }

    #[test]
    fn denormalize_preserves_root_fields() {
        let normalized = json!({
            "name": "r",
            "type": "t",
            "location": "l",
            "kind": "k",
            "id": "/sub/rg/r",
            "tags": {"env": "prod"},
            "identity": {"type": "SystemAssigned"},
            "sku": {"name": "Basic"},
            "plan": {"name": "p1"},
            "zones": ["1", "2"],
            "managedby": "/sub/other",
            "etag": "W/\"abc\"",
            "apiversion": "2023-01-01",
            "fullname": "parent/child"
        });

        let result = denormalize(&normalized, None, None);
        assert_eq!(result["name"], "r");
        assert_eq!(result["type"], "t");
        assert_eq!(result["location"], "l");
        assert_eq!(result["kind"], "k");
        assert_eq!(result["id"], "/sub/rg/r");
        assert_eq!(result["tags"]["env"], "prod");
        assert_eq!(result["identity"]["type"], "SystemAssigned");
        assert_eq!(result["sku"]["name"], "Basic");
        assert_eq!(result["plan"]["name"], "p1");
        assert_eq!(result["zones"][0], "1");
        assert_eq!(result["managedBy"], "/sub/other");
        assert_eq!(result["etag"], "W/\"abc\"");
        assert_eq!(result["apiVersion"], "2023-01-01");
        assert_eq!(result["fullName"], "parent/child");
    }

    #[test]
    fn denormalize_non_object_returns_clone() {
        let val = json!("just a string");
        let result = denormalize(&val, None, None);
        assert_eq!(result, json!("just a string"));
    }

    #[test]
    fn denormalize_empty_normalized() {
        let normalized = json!({});
        let result = denormalize(&normalized, None, None);
        assert_eq!(result, json!({}));
    }

    #[test]
    fn denormalize_root_level_alias() {
        // Aliases like sku.name have ARM path "sku.name" (no properties prefix).
        let aliases = make_aliases(
            "test",
            vec![("sku.name", make_entry("sku.name", "sku.name", vec![]))],
            vec![],
        );

        let normalized = json!({
            "type": "test",
            "sku": { "name": "Standard_LRS" }
        });

        let result = denormalize_with_aliases(&normalized, Some(&aliases), None);
        // sku is a ROOT_FIELD, should stay at root
        assert_eq!(result["sku"]["name"], "Standard_LRS");
    }

    #[test]
    fn round_trip_simple_resource() {
        use super::super::normalizer;

        let arm = json!({
            "name": "myStorage",
            "type": "Microsoft.Storage/storageAccounts",
            "location": "westus2",
            "sku": { "name": "Standard_LRS" },
            "properties": {
                "supportsHttpsTrafficOnly": true,
                "isHnsEnabled": false
            }
        });

        let aliases = make_aliases(
            "Microsoft.Storage/storageAccounts",
            vec![
                (
                    "supportshttpstrafficonly",
                    make_entry(
                        "supportsHttpsTrafficOnly",
                        "properties.supportsHttpsTrafficOnly",
                        vec![],
                    ),
                ),
                (
                    "ishnsenabled",
                    make_entry("isHnsEnabled", "properties.isHnsEnabled", vec![]),
                ),
            ],
            vec![],
        );

        let normalized = normalizer::normalize_with_aliases(&arm, Some(&aliases), None);
        let denormalized = denormalize_with_aliases(&normalized, Some(&aliases), None);

        assert_eq!(denormalized["name"], "myStorage");
        assert_eq!(denormalized["type"], "Microsoft.Storage/storageAccounts");
        assert_eq!(denormalized["location"], "westus2");
        assert_eq!(denormalized["sku"]["name"], "Standard_LRS");
        assert_eq!(denormalized["properties"]["supportsHttpsTrafficOnly"], true);
        assert_eq!(denormalized["properties"]["isHnsEnabled"], false);
    }

    #[test]
    fn round_trip_sub_resource() {
        use super::super::normalizer;

        let aliases = make_aliases(
            "Microsoft.Network/networkSecurityGroups",
            vec![
                (
                    "securityrules[*].protocol",
                    make_entry(
                        "securityRules[*].protocol",
                        "properties.securityRules[*].properties.protocol",
                        vec![],
                    ),
                ),
                (
                    "securityrules[*].access",
                    make_entry(
                        "securityRules[*].access",
                        "properties.securityRules[*].properties.access",
                        vec![],
                    ),
                ),
                (
                    "securityrules[*].name",
                    make_entry(
                        "securityRules[*].name",
                        "properties.securityRules[*].name",
                        vec![],
                    ),
                ),
            ],
            vec!["securityRules"],
        );

        let arm = json!({
            "name": "myNsg",
            "type": "Microsoft.Network/networkSecurityGroups",
            "properties": {
                "securityRules": [
                    {
                        "name": "rule1",
                        "properties": {
                            "protocol": "Tcp",
                            "access": "Allow"
                        }
                    }
                ]
            }
        });

        let normalized = normalizer::normalize_with_aliases(&arm, Some(&aliases), None);
        let denormalized = denormalize_with_aliases(&normalized, Some(&aliases), None);

        assert_eq!(denormalized["name"], "myNsg");
        let rules = denormalized["properties"]["securityRules"]
            .as_array()
            .unwrap();
        assert_eq!(rules[0]["name"], "rule1");
        assert_eq!(rules[0]["properties"]["protocol"], "Tcp");
        assert_eq!(rules[0]["properties"]["access"], "Allow");
    }

    #[test]
    fn build_casing_map_extracts_from_aliases() {
        let mut entries = BTreeMap::new();
        entries.insert(
            "supportshttpstrafficonly".to_string(),
            make_entry(
                "supportsHttpsTrafficOnly",
                "properties.supportsHttpsTrafficOnly",
                vec![],
            ),
        );
        entries.insert(
            "networkacls.defaultaction".to_string(),
            make_entry(
                "networkAcls.defaultAction",
                "properties.networkAcls.defaultAction",
                vec![],
            ),
        );

        let map = build_casing_map(&entries);
        assert_eq!(
            map.get("supportshttpstrafficonly").unwrap(),
            "supportsHttpsTrafficOnly"
        );
        assert_eq!(map.get("networkacls").unwrap(), "networkAcls");
        assert_eq!(map.get("defaultaction").unwrap(), "defaultAction");
        // ROOT_FIELDS included
        assert_eq!(map.get("managedby").unwrap(), "managedBy");
        assert_eq!(map.get("apiversion").unwrap(), "apiVersion");
    }

    #[test]
    fn classify_envelope_fields_detects_from_aliases() {
        let mut entries = BTreeMap::new();
        entries.insert(
            "securityrules[*].protocol".to_string(),
            make_entry(
                "securityRules[*].protocol",
                "properties.securityRules[*].properties.protocol",
                vec![],
            ),
        );
        entries.insert(
            "securityrules[*].name".to_string(),
            make_entry(
                "securityRules[*].name",
                "properties.securityRules[*].name",
                vec![],
            ),
        );
        entries.insert(
            "securityrules[*].etag".to_string(),
            make_entry(
                "securityRules[*].etag",
                "properties.securityRules[*].etag",
                vec![],
            ),
        );

        let envelope = classify_envelope_fields("securityRules", &entries);
        // Default envelope fields
        assert!(envelope.contains("name"));
        assert!(envelope.contains("type"));
        assert!(envelope.contains("id"));
        assert!(envelope.contains("etag"));
        // Derived from alias: name and etag have no properties. prefix
        assert!(envelope.contains("name"));
        assert!(envelope.contains("etag"));
        // protocol has properties. prefix → NOT envelope
        assert!(!envelope.contains("protocol"));
    }
}
