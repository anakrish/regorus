// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Azure Policy alias resolution and ARM resource normalization.
//!
//! This module provides:
//! - [`types`]: Data types for deserializing production alias catalogs
//! - [`normalizer`]: ARM JSON → normalized `input.resource` transformation
//!
//! # Overview
//!
//! Azure Policy aliases are short names for ARM JSON paths. For example,
//! `Microsoft.Storage/storageAccounts/supportsHttpsTrafficOnly` maps to the
//! ARM path `properties.supportsHttpsTrafficOnly`.
//!
//! The normalizer transforms raw ARM resource JSON into a flat structure where
//! alias short names are direct paths. This means the compiler and VM never
//! need to know about aliases — the normalizer handles the translation once
//! before evaluation.

pub mod normalizer;
pub mod types;

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use anyhow::Result;

use types::{ProviderAliases, ResolvedAliases, ResolvedEntry};

use normalizer::{collision_safe_key, is_root_field_collision};

/// Registry of resolved alias data, keyed by fully-qualified resource type
/// (case-insensitive, stored lowercase).
#[derive(Debug, Clone, Default)]
pub struct AliasRegistry {
    /// Map from lowercase resource type → resolved alias data.
    types: BTreeMap<String, ResolvedAliases>,
    /// Global reverse lookup: lowercase fully-qualified alias name → short name.
    ///
    /// Built during [`load_provider`] so the compiler can resolve any alias
    /// to its short name without knowing the resource type.
    alias_to_short: BTreeMap<String, String>,
    /// Global lookup: lowercase fully-qualified alias name → modifiable flag.
    ///
    /// `true` when `defaultMetadata.attributes == "Modifiable"`, `false` otherwise.
    alias_modifiable: BTreeMap<String, bool>,
}

impl AliasRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self {
            types: BTreeMap::new(),
            alias_to_short: BTreeMap::new(),
            alias_modifiable: BTreeMap::new(),
        }
    }

    /// Load alias data from a JSON string in the production catalog format.
    ///
    /// The JSON should be an array of `ProviderAliases` objects, as produced
    /// by `Get-AzPolicyAlias` or extracted from ARM provider metadata.
    ///
    /// Multiple calls accumulate data; duplicates overwrite earlier entries.
    pub fn load_from_json(&mut self, json: &str) -> Result<()> {
        let providers: Vec<ProviderAliases> = serde_json::from_str(json)?;
        for provider in providers {
            self.load_provider(provider);
        }
        Ok(())
    }

    /// Load a single provider's alias data.
    pub fn load_provider(&mut self, provider: ProviderAliases) {
        let namespace = &provider.namespace;
        for rt in provider.resource_types {
            let fq_type = alloc::format!("{}/{}", namespace, rt.resource_type);
            // Build the global FQ alias → short name lookup and modifiable map.
            let prefix = alloc::format!("{}/", fq_type);
            for alias in &rt.aliases {
                // Derive the short name by stripping the resource type prefix.
                // For cross-type aliases (e.g., Microsoft.Compute/imagePublisher
                // under the virtualMachines resource type), the name does not
                // start with the resource type prefix.  In that case, take the
                // part after the last '/'.
                let raw_short = if alias.name.len() > prefix.len()
                    && alias.name[..prefix.len()].eq_ignore_ascii_case(&prefix)
                {
                    alias.name[prefix.len()..].to_string()
                } else if let Some(idx) = alias.name.rfind('/') {
                    alias.name[idx + 1..].to_string()
                } else {
                    continue;
                };

                let default_path = alias.default_path.as_deref().unwrap_or("");
                // When an alias short name collides with a reserved ARM
                // root field (name, type, id, etc.), use a collision-safe
                // key so the compiler and normalizer agree on where the
                // alias value lives in the normalized resource.
                let short = if is_root_field_collision(&raw_short, default_path) {
                    collision_safe_key(&raw_short)
                } else {
                    raw_short
                };
                let lc_name = alias.name.to_lowercase();
                self.alias_to_short.insert(lc_name.clone(), short);
                let is_modifiable = alias
                    .default_metadata
                    .as_ref()
                    .and_then(|m| m.attributes.as_deref())
                    .is_some_and(|a| a.eq_ignore_ascii_case("Modifiable"));
                self.alias_modifiable.insert(lc_name, is_modifiable);
            }
            let resolved = resolve_resource_type(&fq_type, &rt.aliases);
            self.types.insert(fq_type.to_lowercase(), resolved);
        }
    }

    /// Look up resolved aliases for a resource type.
    ///
    /// The lookup is case-insensitive.
    pub fn get(&self, resource_type: &str) -> Option<&ResolvedAliases> {
        self.types.get(&resource_type.to_lowercase())
    }

    /// Number of registered resource types.
    pub fn len(&self) -> usize {
        self.types.len()
    }

    /// Whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.types.is_empty()
    }

    /// Resolve a fully-qualified alias name to its short name.
    ///
    /// The lookup is case-insensitive. Returns `None` if the alias is not
    /// found in the registry (meaning it's either already a short name or
    /// not a known alias).
    pub fn resolve_alias(&self, fq_name: &str) -> Option<&str> {
        self.alias_to_short
            .get(&fq_name.to_lowercase())
            .map(String::as_str)
    }

    /// Return a clone of the alias-to-short-name map for use by the compiler.
    ///
    /// The compiler stores this map internally so it can resolve fully-qualified
    /// alias names without holding a reference to the registry.
    pub fn alias_map(&self) -> BTreeMap<String, String> {
        self.alias_to_short.clone()
    }

    /// Return a clone of the alias-to-modifiable map for use by the compiler.
    ///
    /// Maps lowercase fully-qualified alias names to `true` when the alias
    /// has `defaultMetadata.attributes = "Modifiable"`.
    pub fn alias_modifiable_map(&self) -> BTreeMap<String, bool> {
        self.alias_modifiable.clone()
    }

    /// Normalize a raw ARM resource and wrap it in the input envelope.
    ///
    /// Convenience method that combines alias lookup, normalization, and
    /// envelope construction.  The resource type is extracted from the
    /// `type` field of `arm_resource` automatically.
    ///
    /// # Arguments
    ///
    /// * `arm_resource` — The raw ARM JSON for the resource.
    /// * `api_version` — Optional API version to select versioned alias paths.
    /// * `context` — Optional context object for the input envelope.
    /// * `parameters` — Optional parameters object for the input envelope.
    pub fn normalize_and_wrap(
        &self,
        arm_resource: &serde_json::Value,
        api_version: Option<&str>,
        context: Option<serde_json::Value>,
        parameters: Option<serde_json::Value>,
    ) -> serde_json::Value {
        let normalized = normalizer::normalize(arm_resource, Some(self), api_version);
        normalizer::build_input_envelope(normalized, context, parameters)
    }
}

/// Resolve a resource type's alias entries into `ResolvedAliases`.
///
/// This:
/// 1. Strips the resource type prefix from alias names to produce short names.
/// 2. Extracts `defaultPath` and versioned paths.
/// 3. Detects sub-resource arrays from alias path patterns.
fn resolve_resource_type(fq_type: &str, aliases: &[types::AliasEntry]) -> ResolvedAliases {
    let prefix = alloc::format!("{}/", fq_type);
    let mut entries = BTreeMap::new();
    let mut sub_resource_arrays: Vec<String> = Vec::new();

    for alias in aliases {
        // Derive short name by stripping the resource type prefix.
        // For cross-type aliases (e.g., Microsoft.Compute/imagePublisher
        // under the virtualMachines resource type), the name does not
        // start with the resource type prefix.  In that case, take the
        // part after the last '/'.
        let short_name = if alias.name.len() > prefix.len()
            && alias.name[..prefix.len()].eq_ignore_ascii_case(&prefix)
        {
            &alias.name[prefix.len()..]
        } else if let Some(idx) = alias.name.rfind('/') {
            &alias.name[idx + 1..]
        } else {
            &alias.name
        };

        let default_path = match &alias.default_path {
            Some(p) => p.clone(),
            None => continue, // Skip aliases without a default path (shouldn't happen in production)
        };

        // Detect sub-resource arrays from the alias pattern.
        // If short name contains `[*]` and default_path has
        // `properties.X[*].properties.Y`, then X is a sub-resource array.
        detect_sub_resource_array(short_name, &default_path, &mut sub_resource_arrays);

        let versioned_paths: Vec<(String, String)> = alias
            .paths
            .iter()
            .flat_map(|p| {
                p.api_versions
                    .iter()
                    .map(move |v| (v.clone(), p.path.clone()))
            })
            .collect();

        entries.insert(
            short_name.to_lowercase(),
            ResolvedEntry {
                short_name: short_name.to_string(),
                default_path,
                versioned_paths,
                metadata: alias.default_metadata.clone(),
            },
        );
    }

    // Deduplicate sub_resource_arrays
    sub_resource_arrays.sort();
    sub_resource_arrays.dedup();

    ResolvedAliases {
        resource_type: fq_type.to_string(),
        entries,
        sub_resource_arrays,
    }
}

/// Detect sub-resource arrays from alias naming patterns.
///
/// If the alias short name has `X[*].Y` and the default path has
/// `properties.X[*].properties.Y`, then `X` is a sub-resource array whose
/// elements need `properties` flattening during normalization.
///
/// For nested sub-resource arrays like `X[*].Y[*].Z` mapping to
/// `properties.X[*].properties.Y[*].properties.Z`, both `X` and `X.Y`
/// (dotted path within the normalized structure) are sub-resource arrays.
fn detect_sub_resource_array(
    short_name: &str,
    default_path: &str,
    sub_resource_arrays: &mut Vec<String>,
) {
    // Split short name and default path by `[*].`
    let short_parts: Vec<&str> = short_name.split("[*].").collect();
    let path_parts: Vec<&str> = default_path.split("[*].").collect();

    if short_parts.len() < 2 || path_parts.len() < 2 {
        return; // No wildcard — not a sub-resource array alias
    }

    // For each `[*]` level, check if the pattern matches sub-resource wrapping.
    // short_name: securityRules[*].protocol
    // default_path: properties.securityRules[*].properties.protocol
    //
    // The first segment of the default_path after splitting should start with
    // "properties." and the part after the first [*]. should start with
    // "properties." to indicate sub-resource wrapping.

    // Build up the chain of sub-resource array names.
    let mut accumulated_name = String::new();

    for i in 0..short_parts.len() - 1 {
        // The array field name from the short name
        let array_field = short_parts[i];

        // For the first level, check that default_path starts with `properties.X[*].properties.`
        // For nested levels, the segment after [*]. should also start with `properties.`
        if i + 1 < path_parts.len() {
            let next_path_segment = path_parts[i + 1];
            if next_path_segment.starts_with("properties.")
                || next_path_segment.starts_with("properties/")
            {
                // This is a sub-resource array!
                let name = if accumulated_name.is_empty() {
                    array_field.to_string()
                } else {
                    alloc::format!("{}.{}", accumulated_name, array_field)
                };

                sub_resource_arrays.push(name.clone());
                accumulated_name = name;
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use alloc::string::ToString as _;
    use alloc::vec;

    use super::*;

    #[test]
    fn test_detect_sub_resource_nsg() {
        let mut subs = Vec::new();
        detect_sub_resource_array(
            "securityRules[*].protocol",
            "properties.securityRules[*].properties.protocol",
            &mut subs,
        );
        assert_eq!(subs, vec!["securityRules"]);
    }

    #[test]
    fn test_detect_no_sub_resource() {
        let mut subs = Vec::new();
        // ipRules[*].value -> properties.networkAcls.ipRules[*].value
        // No `properties.` after the `[*].` means NOT a sub-resource
        detect_sub_resource_array(
            "networkAcls.ipRules[*].value",
            "properties.networkAcls.ipRules[*].value",
            &mut subs,
        );
        assert!(subs.is_empty());
    }

    #[test]
    fn test_detect_nested_sub_resource() {
        let mut subs = Vec::new();
        detect_sub_resource_array(
            "subnets[*].ipConfigurations[*].name",
            "properties.subnets[*].properties.ipConfigurations[*].properties.name",
            &mut subs,
        );
        assert_eq!(subs, vec!["subnets", "subnets.ipConfigurations"]);
    }

    #[test]
    fn test_resolve_resource_type_basic() {
        let aliases = vec![
            types::AliasEntry {
                name: "Microsoft.Storage/storageAccounts/supportsHttpsTrafficOnly".to_string(),
                default_path: Some("properties.supportsHttpsTrafficOnly".to_string()),
                default_metadata: None,
                paths: vec![],
            },
            types::AliasEntry {
                name: "Microsoft.Storage/storageAccounts/sku.name".to_string(),
                default_path: Some("sku.name".to_string()),
                default_metadata: None,
                paths: vec![],
            },
        ];

        let resolved = resolve_resource_type("Microsoft.Storage/storageAccounts", &aliases);
        assert_eq!(resolved.entries.len(), 2);

        let https_entry = resolved.entries.get("supportshttpstrafficonly").unwrap();
        assert_eq!(
            https_entry.default_path,
            "properties.supportsHttpsTrafficOnly"
        );

        let sku_entry = resolved.entries.get("sku.name").unwrap();
        assert_eq!(sku_entry.default_path, "sku.name");

        assert!(resolved.sub_resource_arrays.is_empty());
    }

    #[test]
    fn test_resolve_nsg_has_sub_resource_arrays() {
        let aliases = vec![
            types::AliasEntry {
                name: "Microsoft.Network/networkSecurityGroups/securityRules[*].protocol"
                    .to_string(),
                default_path: Some("properties.securityRules[*].properties.protocol".to_string()),
                default_metadata: None,
                paths: vec![],
            },
            types::AliasEntry {
                name: "Microsoft.Network/networkSecurityGroups/securityRules[*].access".to_string(),
                default_path: Some("properties.securityRules[*].properties.access".to_string()),
                default_metadata: None,
                paths: vec![],
            },
        ];

        let resolved = resolve_resource_type("Microsoft.Network/networkSecurityGroups", &aliases);
        assert_eq!(resolved.sub_resource_arrays, vec!["securityRules"]);
    }

    #[test]
    fn test_load_from_json() {
        let json = r#"[
            {
                "namespace": "Microsoft.Storage",
                "resourceTypes": [
                    {
                        "resourceType": "storageAccounts",
                        "aliases": [
                            {
                                "name": "Microsoft.Storage/storageAccounts/supportsHttpsTrafficOnly",
                                "defaultPath": "properties.supportsHttpsTrafficOnly",
                                "paths": []
                            }
                        ]
                    }
                ]
            }
        ]"#;

        let mut registry = AliasRegistry::new();
        registry.load_from_json(json).unwrap();
        assert_eq!(registry.len(), 1);

        let resolved = registry.get("Microsoft.Storage/storageAccounts").unwrap();
        assert_eq!(resolved.entries.len(), 1);
        assert!(resolved.entries.contains_key("supportshttpstrafficonly"));
    }

    #[test]
    fn test_registry_case_insensitive_get() {
        let json = r#"[
            {
                "namespace": "Microsoft.Storage",
                "resourceTypes": [
                    {
                        "resourceType": "storageAccounts",
                        "aliases": [
                            {
                                "name": "Microsoft.Storage/storageAccounts/supportsHttpsTrafficOnly",
                                "defaultPath": "properties.supportsHttpsTrafficOnly",
                                "paths": []
                            }
                        ]
                    }
                ]
            }
        ]"#;

        let mut registry = AliasRegistry::new();
        registry.load_from_json(json).unwrap();

        // Mixed-case lookup should work
        assert!(registry.get("microsoft.storage/STORAGEACCOUNTS").is_some());
        assert!(registry.get("MICROSOFT.STORAGE/storageAccounts").is_some());
    }

    #[test]
    fn test_resolve_with_versioned_paths() {
        let aliases = vec![types::AliasEntry {
            name: "Microsoft.Web/sites/siteConfig.numberOfWorkers".to_string(),
            default_path: Some("properties.siteConfig.numberOfWorkers".to_string()),
            default_metadata: None,
            paths: vec![
                types::AliasPath {
                    path: "properties.siteConfig.properties.numberOfWorkers".to_string(),
                    api_versions: vec!["2014-04-01".to_string(), "2014-06-01".to_string()],
                    metadata: None,
                },
                types::AliasPath {
                    path: "properties.siteConfig.numberOfWorkers".to_string(),
                    api_versions: vec!["2021-01-01".to_string()],
                    metadata: None,
                },
            ],
        }];

        let resolved = resolve_resource_type("Microsoft.Web/sites", &aliases);
        let entry = resolved.entries.get("siteconfig.numberofworkers").unwrap();

        assert_eq!(entry.default_path, "properties.siteConfig.numberOfWorkers");
        // Has versioned paths
        assert_eq!(entry.versioned_paths.len(), 3); // 2 + 1
        assert_eq!(
            entry.select_path(Some("2014-04-01")),
            "properties.siteConfig.properties.numberOfWorkers"
        );
        assert_eq!(
            entry.select_path(Some("2021-01-01")),
            "properties.siteConfig.numberOfWorkers"
        );
        // Unknown version falls back to default
        assert_eq!(
            entry.select_path(Some("9999-01-01")),
            "properties.siteConfig.numberOfWorkers"
        );
    }

    #[test]
    fn test_resolve_alias_without_default_path_skipped() {
        let aliases = vec![
            types::AliasEntry {
                name: "Microsoft.Storage/storageAccounts/good".to_string(),
                default_path: Some("properties.good".to_string()),
                default_metadata: None,
                paths: vec![],
            },
            types::AliasEntry {
                name: "Microsoft.Storage/storageAccounts/bad".to_string(),
                default_path: None,
                default_metadata: None,
                paths: vec![],
            },
        ];

        let resolved = resolve_resource_type("Microsoft.Storage/storageAccounts", &aliases);
        assert_eq!(resolved.entries.len(), 1);
        assert!(resolved.entries.contains_key("good"));
        assert!(!resolved.entries.contains_key("bad"));
    }

    #[test]
    fn test_empty_registry() {
        let registry = AliasRegistry::new();
        assert!(registry.is_empty());
        assert_eq!(registry.len(), 0);
        assert!(registry.get("Microsoft.Storage/storageAccounts").is_none());
    }

    #[test]
    fn test_resolve_empty_aliases() {
        let resolved = resolve_resource_type("Microsoft.Test/empty", &[]);
        assert!(resolved.entries.is_empty());
        assert!(resolved.sub_resource_arrays.is_empty());
    }

    #[test]
    fn test_sub_resource_dedup() {
        // Multiple aliases for the same sub-resource array should deduplicate
        let aliases = vec![
            types::AliasEntry {
                name: "T/R/rules[*].a".to_string(),
                default_path: Some("properties.rules[*].properties.a".to_string()),
                default_metadata: None,
                paths: vec![],
            },
            types::AliasEntry {
                name: "T/R/rules[*].b".to_string(),
                default_path: Some("properties.rules[*].properties.b".to_string()),
                default_metadata: None,
                paths: vec![],
            },
            types::AliasEntry {
                name: "T/R/rules[*].c".to_string(),
                default_path: Some("properties.rules[*].properties.c".to_string()),
                default_metadata: None,
                paths: vec![],
            },
        ];

        let resolved = resolve_resource_type("T/R", &aliases);
        // "rules" should appear only once despite 3 aliases detecting it
        assert_eq!(resolved.sub_resource_arrays, vec!["rules"]);
    }

    #[test]
    fn test_normalize_and_wrap_full_pipeline() {
        let json = r#"[
            {
                "namespace": "Microsoft.Network",
                "resourceTypes": [
                    {
                        "resourceType": "networkSecurityGroups",
                        "aliases": [
                            {
                                "name": "Microsoft.Network/networkSecurityGroups/securityRules[*].protocol",
                                "defaultPath": "properties.securityRules[*].properties.protocol",
                                "paths": []
                            }
                        ]
                    }
                ]
            }
        ]"#;

        let mut registry = AliasRegistry::new();
        registry.load_from_json(json).unwrap();

        let arm_resource = serde_json::json!({
            "name": "myNsg",
            "type": "Microsoft.Network/networkSecurityGroups",
            "properties": {
                "securityRules": [
                    {
                        "name": "rule1",
                        "properties": {
                            "protocol": "Tcp"
                        }
                    }
                ]
            }
        });

        let envelope = registry.normalize_and_wrap(
            &arm_resource,
            None,
            Some(serde_json::json!({"resourceGroup": {"name": "rg1"}})),
            Some(serde_json::json!({"env": "prod"})),
        );

        // Resource is normalized (all keys lowercased)
        assert_eq!(envelope["resource"]["name"], "myNsg");
        let rules = envelope["resource"]["securityrules"].as_array().unwrap();
        assert_eq!(rules[0]["protocol"], "Tcp");
        assert!(rules[0].get("properties").is_none());
        // Context and parameters are passed through
        assert_eq!(envelope["context"]["resourceGroup"]["name"], "rg1");
        assert_eq!(envelope["parameters"]["env"], "prod");
    }

    #[test]
    fn test_load_test_aliases_json() {
        // Integration test: load the actual test_aliases.json file
        let json = std::fs::read_to_string("tests/azure_policy/aliases/test_aliases.json")
            .expect("test_aliases.json should exist");

        let mut registry = AliasRegistry::new();
        registry
            .load_from_json(&json)
            .expect("test_aliases.json should parse");

        // Expect 32 resource types (23 original + 9 added for lockdown tests)
        assert_eq!(registry.len(), 32);

        // Storage
        let storage = registry
            .get("Microsoft.Storage/storageAccounts")
            .expect("Storage aliases should exist");
        assert!(!storage.entries.is_empty());
        assert!(storage.sub_resource_arrays.is_empty());

        // NSG — should have sub-resource arrays
        let nsg = registry
            .get("Microsoft.Network/networkSecurityGroups")
            .expect("NSG aliases should exist");
        assert!(!nsg.entries.is_empty());
        assert!(
            nsg.sub_resource_arrays
                .contains(&"securityRules".to_string()),
            "NSG should detect securityRules as sub-resource array"
        );

        // KeyVault
        assert!(registry.get("Microsoft.KeyVault/vaults").is_some());

        // SQL
        assert!(registry.get("Microsoft.Sql/servers").is_some());

        // VM
        assert!(registry.get("Microsoft.Compute/virtualMachines").is_some());

        // Web
        assert!(registry.get("Microsoft.Web/sites").is_some());

        // AKS
        assert!(registry
            .get("Microsoft.ContainerService/managedClusters")
            .is_some());

        // Disks
        assert!(registry.get("Microsoft.Compute/disks").is_some());

        // NIC — should have sub-resource arrays
        let nic = registry
            .get("Microsoft.Network/networkInterfaces")
            .expect("NIC aliases should exist");
        assert!(
            nic.sub_resource_arrays
                .contains(&"ipConfigurations".to_string()),
            "NIC should detect ipConfigurations as sub-resource array"
        );
    }

    #[test]
    fn test_resolve_alias_basic() {
        let json = r#"[
            {
                "namespace": "Microsoft.Storage",
                "resourceTypes": [
                    {
                        "resourceType": "storageAccounts",
                        "aliases": [
                            {
                                "name": "Microsoft.Storage/storageAccounts/supportsHttpsTrafficOnly",
                                "defaultPath": "properties.supportsHttpsTrafficOnly",
                                "paths": []
                            },
                            {
                                "name": "Microsoft.Storage/storageAccounts/sku.name",
                                "defaultPath": "sku.name",
                                "paths": []
                            }
                        ]
                    }
                ]
            }
        ]"#;

        let mut registry = AliasRegistry::new();
        registry.load_from_json(json).unwrap();

        assert_eq!(
            registry.resolve_alias("Microsoft.Storage/storageAccounts/supportsHttpsTrafficOnly"),
            Some("supportsHttpsTrafficOnly")
        );
        assert_eq!(
            registry.resolve_alias("Microsoft.Storage/storageAccounts/sku.name"),
            Some("sku.name")
        );
        // Case-insensitive
        assert_eq!(
            registry.resolve_alias("microsoft.storage/STORAGEACCOUNTS/supportsHttpsTrafficOnly"),
            Some("supportsHttpsTrafficOnly")
        );
        // Unknown alias
        assert_eq!(
            registry.resolve_alias("Microsoft.Storage/storageAccounts/unknown"),
            None
        );
        // Already a short name
        assert_eq!(registry.resolve_alias("supportsHttpsTrafficOnly"), None);
    }

    #[test]
    fn test_alias_map_for_compiler() {
        let json = r#"[
            {
                "namespace": "Microsoft.Network",
                "resourceTypes": [
                    {
                        "resourceType": "networkSecurityGroups",
                        "aliases": [
                            {
                                "name": "Microsoft.Network/networkSecurityGroups/securityRules[*].protocol",
                                "defaultPath": "properties.securityRules[*].properties.protocol",
                                "paths": []
                            }
                        ]
                    }
                ]
            }
        ]"#;

        let mut registry = AliasRegistry::new();
        registry.load_from_json(json).unwrap();

        let map = registry.alias_map();
        assert_eq!(
            map.get("microsoft.network/networksecuritygroups/securityrules[*].protocol"),
            Some(&"securityRules[*].protocol".to_string())
        );
    }
}
