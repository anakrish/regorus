// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! ARM JSON → normalized `input.resource` transformation.
//!
//! The normalizer flattens `properties` wrappers from raw ARM resource JSON so
//! that alias short names become direct paths into the normalized structure.
//!
//! See `docs/azure-policy/alias-normalization.md` for the full specification.

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use serde_json::{Map, Value};

use super::types::{ResolvedAliases, ResolvedEntry};

/// Fields that exist at the ARM resource root (not under `properties`).
const ROOT_FIELDS: &[&str] = &[
    "name",
    "type",
    "location",
    "kind",
    "id",
    "tags",
    "identity",
    "sku",
    "plan",
    "zones",
    "managedBy",
    "etag",
    "apiVersion",
    "fullName",
];

/// Check whether an alias short name collides with a reserved ARM root field
/// and needs a collision-safe key.
///
/// Returns `true` when `short_name` exactly matches (case-insensitive) one of
/// the [`ROOT_FIELDS`] AND `default_path` starts with `"properties."`, meaning
/// the alias points to a properties-level field that shadows the root field.
///
/// When `true`, both the normalizer and the compiler must use
/// [`collision_safe_key`] to avoid overwriting the ARM envelope value.
pub(crate) fn is_root_field_collision(short_name: &str, default_path: &str) -> bool {
    ROOT_FIELDS
        .iter()
        .any(|f| f.eq_ignore_ascii_case(short_name))
        && default_path.to_ascii_lowercase().starts_with("properties.")
}

/// Return a collision-safe key for an alias whose short name collides with a
/// root ARM field.  The key is `_p_` + the lowercased short name (e.g.,
/// `_p_type` for alias short name `type` when the default path is
/// `properties.type`).
pub(crate) fn collision_safe_key(short_name: &str) -> String {
    alloc::format!("_p_{}", short_name.to_ascii_lowercase())
}

/// Normalize a raw ARM resource JSON value into the `input.resource` structure.
///
/// # Arguments
///
/// * `arm_resource` — The raw ARM JSON object for the resource.
/// * `aliases` — Resolved alias data for the resource type. Used to determine
///   which array fields contain sub-resources and to perform per-alias
///   path resolution. If `None`, only root `properties` flattening is performed.
/// * `api_version` — Optional API version string. When provided, versioned
///   alias paths are selected via [`ResolvedEntry::select_path`]. This enables
///   correct normalization for resources whose ARM JSON structure varies across
///   API versions.
///
/// # Returns
///
/// A JSON object where:
/// - Root-level ARM fields (`name`, `type`, `location`, etc.) are preserved.
/// - `properties` contents are merged into the root.
/// - Sub-resource array element `properties` are flattened recursively.
/// - Per-alias path resolution places values at alias short name paths,
///   handling versioned ARM paths when `api_version` is supplied.
pub fn normalize(
    arm_resource: &Value,
    aliases: Option<&ResolvedAliases>,
    api_version: Option<&str>,
) -> Value {
    let obj = match arm_resource.as_object() {
        Some(o) => o,
        None => return arm_resource.clone(),
    };

    let sub_arrays = aliases.map(|a| &a.sub_resource_arrays);
    let mut result = Map::new();

    // Rule 2: Copy root-level fields as-is (keys lowercased).
    for &field in ROOT_FIELDS {
        if let Some(val) = obj.get(field) {
            result.insert(field.to_ascii_lowercase(), val.clone());
        }
    }

    // Rule 1: Flatten root `properties` into the root (keys lowercased).
    if let Some(Value::Object(props)) = obj.get("properties") {
        for (key, val) in props {
            let lc_key = key.to_lowercase();
            // Root-level fields take precedence (shouldn't happen in practice).
            if result.contains_key(&lc_key) {
                continue;
            }
            let normalized = normalize_value(val, key, sub_arrays);
            result.insert(lc_key, normalized);
        }
    }

    // Per-alias path resolution: for each scalar alias, read the value from
    // the ARM path selected by `api_version` and place it at the alias short
    // name path in the output.  This handles versioned ARM paths (e.g.,
    // `sku.name` vs `properties.accountType` depending on API version) and
    // ensures every known alias is populated even when the ARM field name
    // differs from the alias short name.
    if let Some(aliases) = aliases {
        apply_alias_entries(
            &mut result,
            arm_resource,
            &aliases.entries,
            api_version,
            &aliases.sub_resource_arrays,
        );
    }

    Value::Object(result)
}

/// Recursively normalize a value, flattening sub-resource array elements.
fn normalize_value(value: &Value, field_path: &str, sub_arrays: Option<&Vec<String>>) -> Value {
    match value {
        Value::Array(arr) => {
            if is_sub_resource_array(field_path, sub_arrays) {
                // Rule 3: Flatten sub-resource array elements.
                let items: Vec<Value> = arr
                    .iter()
                    .map(|elem| flatten_element(elem, field_path, sub_arrays))
                    .collect();
                Value::Array(items)
            } else {
                // Rule 4 & 6: Recurse into elements to lowercase any nested
                // object keys (primitives pass through unchanged).
                let items: Vec<Value> = arr
                    .iter()
                    .map(|elem| normalize_value(elem, field_path, sub_arrays))
                    .collect();
                Value::Array(items)
            }
        }
        Value::Object(obj) => {
            // Recurse into nested objects to find sub-resource arrays (keys lowercased).
            let mut result = Map::new();
            for (k, v) in obj {
                let child_path = alloc::format!("{}.{}", field_path, k);
                result.insert(
                    k.to_lowercase(),
                    normalize_value(v, &child_path, sub_arrays),
                );
            }
            Value::Object(result)
        }
        _ => value.clone(),
    }
}

/// Flatten a sub-resource array element by merging its `properties` into
/// the element root.
fn flatten_element(element: &Value, array_path: &str, sub_arrays: Option<&Vec<String>>) -> Value {
    let obj = match element.as_object() {
        Some(o) => o,
        None => return element.clone(),
    };

    let mut result = Map::new();

    // Copy non-`properties` fields from the element envelope (keys lowercased).
    for (key, val) in obj {
        if key == "properties" {
            continue;
        }
        let child_path = alloc::format!("{}.{}", array_path, key);
        result.insert(
            key.to_lowercase(),
            normalize_value(val, &child_path, sub_arrays),
        );
    }

    // Merge `properties` into the element (keys lowercased).
    if let Some(Value::Object(props)) = obj.get("properties") {
        for (key, val) in props {
            let lc_key = key.to_lowercase();
            if result.contains_key(&lc_key) {
                continue;
            }
            let child_path = alloc::format!("{}.{}", array_path, key);
            result.insert(lc_key, normalize_value(val, &child_path, sub_arrays));
        }
    }

    Value::Object(result)
}

/// Check if a field path corresponds to a sub-resource array.
fn is_sub_resource_array(field_path: &str, sub_arrays: Option<&Vec<String>>) -> bool {
    match sub_arrays {
        Some(arrays) => arrays.iter().any(|a| a.eq_ignore_ascii_case(field_path)),
        None => false,
    }
}

/// Apply per-alias path resolution to the normalized result.
///
/// **Scalar aliases** (no `[*]`): reads the value from the ARM path selected
/// by `api_version` and writes it at the alias short name path in `result`.
///
/// **Array-element aliases** (one `[*]`): when the selected API-versioned path
/// has a different leaf field name than the short name, remaps the field in
/// each already-flattened element.  For example, alias `rules[*].priority`
/// with new-API path `properties.rules[*].properties.prio` remaps each
/// element's `prio` → `priority`.
fn apply_alias_entries(
    result: &mut Map<String, Value>,
    raw: &Value,
    entries: &BTreeMap<String, ResolvedEntry>,
    api_version: Option<&str>,
    sub_resource_arrays: &[String],
) {
    // Collect element-level remappings first, then apply them.  This avoids
    // borrow-conflict issues with iterating entries while mutating result.
    let mut element_remaps: Vec<ElementRemap> = Vec::new();

    for (_lowercase_key, entry) in entries {
        if entry.short_name.contains("[*]") {
            // Array-element alias: check if versioned path changes the leaf
            // field name relative to the default path.
            if let Some(remap) = compute_element_remap(entry, api_version) {
                element_remaps.push(remap);
            }
            continue;
        }

        // Skip sub-resource array root entries (e.g., "securityRules").
        // Structural flattening already flattens each sub-resource element's
        // `properties` wrapper; per-alias resolution would overwrite with
        // the raw unflattened array.
        if sub_resource_arrays
            .iter()
            .any(|s| s.eq_ignore_ascii_case(&entry.short_name))
        {
            continue;
        }

        let arm_path = entry.select_path(api_version);
        if let Some(value) = navigate_arm_path(raw, arm_path) {
            // When the alias short name collides with a reserved ARM root
            // field (e.g., alias short name "type" vs root "type"), store
            // the alias value under a collision-safe key so it doesn't
            // overwrite the ARM envelope field.
            let target = if is_root_field_collision(&entry.short_name, &entry.default_path) {
                collision_safe_key(&entry.short_name)
            } else {
                entry.short_name.clone()
            };
            set_nested_value(result, &target, value);
        }
    }

    // Apply element-level remappings.
    for remap in &element_remaps {
        apply_element_remap(result, remap);
    }
}

/// Describes a field remapping inside each element of a sub-resource array.
struct ElementRemap {
    /// Dot-separated path to the array in the normalized result
    /// (e.g., `"rules"` for `rules[*].priority`).
    array_path: Vec<String>,
    /// The field name to read from each element (from the versioned ARM path).
    source_field: String,
    /// The field name to write in each element (from the alias short name).
    target_field: String,
}

/// Determine if an array-element alias needs a per-element field remap for the
/// given API version.
///
/// Returns `Some(ElementRemap)` when the leaf field name in the selected ARM
/// path differs from the leaf field name in the alias short name.
fn compute_element_remap(entry: &ResolvedEntry, api_version: Option<&str>) -> Option<ElementRemap> {
    let selected_path = entry.select_path(api_version);

    // Extract the last field name from the selected ARM path and the short name.
    // For `rules[*].priority` (short name) and `properties.rules[*].properties.prio`
    // (ARM path), the target leaf is "priority" and source leaf is "prio".

    // Find the leaf after the last `[*].` in the short name.
    let short_leaf = entry.short_name.rsplit("[*].").next()?;
    // Find the leaf after the last `[*].` in the ARM path, then strip any
    // leading `properties.` wrapper (structural flattening already removed it).
    let arm_after_wildcard = selected_path.rsplit("[*].").next()?;
    let arm_leaf = arm_after_wildcard
        .strip_prefix("properties.")
        .unwrap_or(arm_after_wildcard);

    // If the leaf field names are the same, no remap needed.
    if short_leaf == arm_leaf {
        return None;
    }

    // Extract the array path from the short name (everything before `[*]`).
    let wildcard_pos = entry.short_name.find("[*]")?;
    let array_name = &entry.short_name[..wildcard_pos];

    Some(ElementRemap {
        array_path: array_name
            .split('.')
            .map(|s| s.to_ascii_lowercase())
            .collect(),
        source_field: arm_leaf.to_ascii_lowercase(),
        target_field: short_leaf.to_ascii_lowercase(),
    })
}

/// Apply an element-level field remap to each element in a sub-resource array.
fn apply_element_remap(result: &mut Map<String, Value>, remap: &ElementRemap) {
    // Navigate to the array value at remap.array_path in result.
    let arr = {
        let mut cur: &mut Value = match remap.array_path.first() {
            Some(first) => match result.get_mut(first) {
                Some(v) => v,
                None => return,
            },
            None => return,
        };
        for segment in remap.array_path.iter().skip(1) {
            cur = match cur.get_mut(segment) {
                Some(v) => v,
                None => return,
            };
        }
        cur
    };

    if let Value::Array(elements) = arr {
        for elem in elements.iter_mut() {
            if let Value::Object(obj) = elem {
                // Remap: take the value from the versioned source field and
                // place it at the alias target field, overwriting any existing
                // value.  This handles cases where both field names are present
                // in the ARM template (e.g., `priority: 50` and `prio: 200`):
                // the selected API version determines which value wins.
                if obj.contains_key(&remap.source_field) {
                    if let Some(val) = obj.remove(&remap.source_field) {
                        obj.insert(remap.target_field.clone(), val);
                    }
                }
            }
        }
    }
}

/// Navigate a dot-separated ARM path in a JSON value.
///
/// Returns `None` if any segment is missing.
fn navigate_arm_path(value: &Value, path: &str) -> Option<Value> {
    let mut current = value;
    for segment in path.split('.') {
        current = current.get(segment)?;
    }
    Some(current.clone())
}

/// Set a value at a dot-separated path in a JSON object, creating
/// intermediate objects as needed.
fn set_nested_value(result: &mut Map<String, Value>, path: &str, value: Value) {
    let segments: Vec<&str> = path.split('.').collect();
    if segments.is_empty() {
        return;
    }
    if segments.len() == 1 {
        result.insert(segments[0].to_ascii_lowercase(), value);
        return;
    }
    // Navigate/create intermediate objects (keys lowercased).
    let mut current = result;
    for &segment in &segments[..segments.len() - 1] {
        let lc = segment.to_ascii_lowercase();
        let entry = current
            .entry(lc)
            .or_insert_with(|| Value::Object(Map::new()));
        current = match entry.as_object_mut() {
            Some(map) => map,
            None => return, // Can't navigate into a non-object
        };
    }
    if let Some(last_segment) = segments.last() {
        current.insert(last_segment.to_ascii_lowercase(), value);
    }
}

/// Wrap a normalized resource into the full `input` envelope.
///
/// Produces: `{ "resource": <normalized>, "context": <context>, "parameters": <params> }`
///
/// Any of the optional fields can be `None`, in which case they default to `{}`.
pub fn build_input_envelope(
    normalized_resource: Value,
    context: Option<Value>,
    parameters: Option<Value>,
) -> Value {
    let mut envelope = Map::new();
    envelope.insert("resource".to_string(), normalized_resource);
    envelope.insert(
        "context".to_string(),
        context.unwrap_or_else(|| Value::Object(Map::new())),
    );
    envelope.insert(
        "parameters".to_string(),
        parameters.unwrap_or_else(|| Value::Object(Map::new())),
    );
    Value::Object(envelope)
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::unwrap_used)]
mod tests {
    use alloc::vec;

    use super::*;
    use serde_json::json;

    #[test]
    fn normalize_flattens_root_properties() {
        let arm = json!({
            "name": "myStorage",
            "type": "Microsoft.Storage/storageAccounts",
            "location": "westus2",
            "properties": {
                "supportsHttpsTrafficOnly": true,
                "isHnsEnabled": false
            }
        });

        let result = normalize(&arm, None, None);
        assert_eq!(result["name"], "myStorage");
        assert_eq!(result["type"], "Microsoft.Storage/storageAccounts");
        assert_eq!(result["location"], "westus2");
        assert_eq!(result["supportshttpstrafficonly"], true);
        assert_eq!(result["ishnsenabled"], false);
        // `properties` wrapper itself should not be in the result
        assert!(result.get("properties").is_none());
    }

    #[test]
    fn normalize_preserves_root_level_precedence() {
        let arm = json!({
            "name": "root-name",
            "properties": {
                "name": "props-name"
            }
        });

        let result = normalize(&arm, None, None);
        assert_eq!(result["name"], "root-name");
    }

    #[test]
    fn normalize_flattens_sub_resource_arrays() {
        let aliases = ResolvedAliases {
            resource_type: "Microsoft.Network/networkSecurityGroups".to_string(),
            entries: Default::default(),
            sub_resource_arrays: vec!["securityRules".to_string()],
        };

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
                    },
                    {
                        "name": "rule2",
                        "properties": {
                            "protocol": "*",
                            "access": "Deny"
                        }
                    }
                ]
            }
        });

        let result = normalize(&arm, Some(&aliases), None);
        let rules = result["securityrules"].as_array().unwrap();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0]["name"], "rule1");
        assert_eq!(rules[0]["protocol"], "Tcp");
        assert_eq!(rules[0]["access"], "Allow");
        assert!(rules[0].get("properties").is_none());
        assert_eq!(rules[1]["protocol"], "*");
        assert_eq!(rules[1]["access"], "Deny");
    }

    #[test]
    fn normalize_leaves_plain_arrays_alone() {
        let arm = json!({
            "name": "test",
            "properties": {
                "networkAcls": {
                    "ipRules": [
                        { "value": "10.0.0.1", "action": "Allow" },
                        { "value": "10.0.0.2", "action": "Deny" }
                    ]
                }
            }
        });

        let result = normalize(&arm, None, None);
        let rules = result["networkacls"]["iprules"].as_array().unwrap();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0]["value"], "10.0.0.1");
    }

    #[test]
    fn normalize_handles_sku_at_root() {
        let arm = json!({
            "name": "test",
            "sku": { "name": "Standard_LRS", "tier": "Standard" },
            "properties": {
                "supportsHttpsTrafficOnly": true
            }
        });

        let result = normalize(&arm, None, None);
        assert_eq!(result["sku"]["name"], "Standard_LRS");
        assert_eq!(result["supportshttpstrafficonly"], true);
    }

    #[test]
    fn build_envelope_defaults() {
        let resource = json!({"name": "x"});
        let envelope = build_input_envelope(resource, None, None);
        assert_eq!(envelope["resource"]["name"], "x");
        assert!(envelope["context"].is_object());
        assert!(envelope["parameters"].is_object());
    }

    #[test]
    fn build_envelope_with_context_and_parameters() {
        let resource = json!({"name": "x"});
        let context = json!({"resourceGroup": {"name": "rg1"}});
        let parameters = json!({"env": "prod"});
        let envelope = build_input_envelope(resource, Some(context), Some(parameters));
        assert_eq!(envelope["context"]["resourceGroup"]["name"], "rg1");
        assert_eq!(envelope["parameters"]["env"], "prod");
    }

    #[test]
    fn normalize_non_object_returns_clone() {
        let arm = json!("just a string");
        let result = normalize(&arm, None, None);
        assert_eq!(result, json!("just a string"));
    }

    #[test]
    fn normalize_empty_properties() {
        let arm = json!({
            "name": "test",
            "properties": {}
        });
        let result = normalize(&arm, None, None);
        assert_eq!(result["name"], "test");
        assert!(result.get("properties").is_none());
    }

    #[test]
    fn normalize_missing_properties() {
        let arm = json!({
            "name": "test",
            "location": "eastus"
        });
        let result = normalize(&arm, None, None);
        assert_eq!(result["name"], "test");
        assert_eq!(result["location"], "eastus");
    }

    #[test]
    fn normalize_preserves_all_root_fields() {
        let arm = json!({
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
            "managedBy": "/sub/other",
            "etag": "W/\"abc\"",
            "apiVersion": "2023-01-01",
            "fullName": "parent/child",
            "properties": {
                "someProp": true
            }
        });
        let result = normalize(&arm, None, None);
        assert_eq!(result["name"], "r");
        assert_eq!(result["type"], "t");
        assert_eq!(result["kind"], "k");
        assert_eq!(result["id"], "/sub/rg/r");
        assert_eq!(result["tags"]["env"], "prod");
        assert_eq!(result["identity"]["type"], "SystemAssigned");
        assert_eq!(result["sku"]["name"], "Basic");
        assert_eq!(result["plan"]["name"], "p1");
        assert_eq!(result["zones"][0], "1");
        assert_eq!(result["managedby"], "/sub/other");
        assert_eq!(result["etag"], "W/\"abc\"");
        assert_eq!(result["apiversion"], "2023-01-01");
        assert_eq!(result["fullname"], "parent/child");
        assert_eq!(result["someprop"], true);
    }

    #[test]
    fn normalize_nested_sub_resource_arrays() {
        // Two levels of sub-resource nesting:
        // subnets[*] → flatten properties
        // subnets.ipConfigurations[*] → flatten properties (nested)
        let aliases = ResolvedAliases {
            resource_type: "Microsoft.Network/virtualNetworks".to_string(),
            entries: Default::default(),
            sub_resource_arrays: vec![
                "subnets".to_string(),
                "subnets.ipConfigurations".to_string(),
            ],
        };

        let arm = json!({
            "name": "myVnet",
            "properties": {
                "subnets": [
                    {
                        "name": "subnet1",
                        "properties": {
                            "addressPrefix": "10.0.0.0/24",
                            "ipConfigurations": [
                                {
                                    "name": "ipconfig1",
                                    "properties": {
                                        "privateIPAddress": "10.0.0.4"
                                    }
                                }
                            ]
                        }
                    }
                ]
            }
        });

        let result = normalize(&arm, Some(&aliases), None);
        let subnets = result["subnets"].as_array().unwrap();
        assert_eq!(subnets.len(), 1);
        // First level flatten: subnet element has name + addressPrefix merged
        assert_eq!(subnets[0]["name"], "subnet1");
        assert_eq!(subnets[0]["addressprefix"], "10.0.0.0/24");
        assert!(subnets[0].get("properties").is_none());
        // Second level flatten: ipConfig element has name + privateIPAddress
        let ip_configs = subnets[0]["ipconfigurations"].as_array().unwrap();
        assert_eq!(ip_configs[0]["name"], "ipconfig1");
        assert_eq!(ip_configs[0]["privateipaddress"], "10.0.0.4");
        assert!(ip_configs[0].get("properties").is_none());
    }

    #[test]
    fn normalize_sub_resource_element_without_properties() {
        // Sub-resource array marked but element has no `properties` key
        let aliases = ResolvedAliases {
            resource_type: "test".to_string(),
            entries: Default::default(),
            sub_resource_arrays: vec!["items".to_string()],
        };

        let arm = json!({
            "name": "test",
            "properties": {
                "items": [
                    { "name": "plain-object", "enabled": true }
                ]
            }
        });

        let result = normalize(&arm, Some(&aliases), None);
        let items = result["items"].as_array().unwrap();
        assert_eq!(items[0]["name"], "plain-object");
        assert_eq!(items[0]["enabled"], true);
    }

    #[test]
    fn normalize_primitive_array_pass_through() {
        let arm = json!({
            "name": "test",
            "properties": {
                "allowedIPs": ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
            }
        });

        let result = normalize(&arm, None, None);
        let ips = result["allowedips"].as_array().unwrap();
        assert_eq!(ips.len(), 3);
        assert_eq!(ips[0], "10.0.0.1");
    }

    #[test]
    fn normalize_deeply_nested_object_no_sub_resource() {
        // Nested objects are recursed but no flattening happens without sub-resource marker
        let arm = json!({
            "name": "test",
            "properties": {
                "networkAcls": {
                    "defaultAction": "Deny",
                    "virtualNetworkRules": [
                        { "id": "/vnet/subnet1", "action": "Allow" }
                    ]
                }
            }
        });

        let result = normalize(&arm, None, None);
        assert_eq!(result["networkacls"]["defaultaction"], "Deny");
        let rules = result["networkacls"]["virtualnetworkrules"]
            .as_array()
            .unwrap();
        assert_eq!(rules[0]["id"], "/vnet/subnet1");
    }

    #[test]
    fn normalize_case_insensitive_sub_resource_match() {
        let aliases = ResolvedAliases {
            resource_type: "test".to_string(),
            entries: Default::default(),
            sub_resource_arrays: vec!["SecurityRules".to_string()],
        };

        let arm = json!({
            "name": "test",
            "properties": {
                "securityRules": [
                    {
                        "name": "r1",
                        "properties": { "protocol": "Tcp" }
                    }
                ]
            }
        });

        // The sub_resource_arrays entry is "SecurityRules" but the ARM JSON
        // field is "securityRules" — should still match case-insensitively.
        let result = normalize(&arm, Some(&aliases), None);
        let rules = result["securityrules"].as_array().unwrap();
        assert_eq!(rules[0]["protocol"], "Tcp");
        assert!(rules[0].get("properties").is_none());
    }
}
