// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Data types for Azure Policy alias definitions.
//!
//! These types deserialize the production alias catalog format used by
//! `Get-AzPolicyAlias` and the ARM provider metadata API.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use serde::Deserialize;

/// Metadata associated with an alias or a versioned path.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct AliasMetadata {
    /// The data type of the alias value (e.g., "String", "Integer", "Boolean",
    /// "Array", "Object").
    #[serde(rename = "type")]
    pub kind: Option<String>,

    /// Modifiability attributes (e.g., "Modifiable", "None").
    pub attributes: Option<String>,
}

/// A versioned path mapping for an alias.
///
/// When an alias maps to different ARM JSON paths across API versions, each
/// distinct path is recorded as an `AliasPath` entry.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct AliasPath {
    /// The ARM JSON path (e.g., `"properties.encryption.services.blob.enabled"`).
    pub path: String,

    /// API versions for which this path is valid. Empty means all versions.
    #[serde(default, rename = "apiVersions")]
    pub api_versions: Vec<String>,

    /// Optional per-version metadata.
    #[serde(default)]
    pub metadata: Option<AliasMetadata>,
}

/// A single alias entry within a resource type.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct AliasEntry {
    /// Fully qualified alias name
    /// (e.g., `"Microsoft.Storage/storageAccounts/supportsHttpsTrafficOnly"`).
    pub name: String,

    /// The default ARM JSON path used when no versioned path matches.
    /// Every alias in production has a `defaultPath`.
    #[serde(default, rename = "defaultPath")]
    pub default_path: Option<String>,

    /// Optional default metadata (type, modifiability).
    #[serde(default, rename = "defaultMetadata")]
    pub default_metadata: Option<AliasMetadata>,

    /// Versioned path entries. Empty for the 97.6% of aliases that have only
    /// a `defaultPath`.
    #[serde(default)]
    pub paths: Vec<AliasPath>,
}

/// Aliases for a single resource type within a provider.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct ResourceTypeAliases {
    /// The resource type name (e.g., `"storageAccounts"`).
    #[serde(rename = "resourceType")]
    pub resource_type: String,

    /// Resource capabilities (e.g., `"SupportsTags, SupportsLocation"`).
    #[serde(default)]
    pub capabilities: Option<String>,

    /// Default API version for the resource type.
    #[serde(default, rename = "defaultApiVersion")]
    pub default_api_version: Option<String>,

    /// All alias entries for this resource type.
    #[serde(default)]
    pub aliases: Vec<AliasEntry>,
}

/// A resource provider's alias definitions.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct ProviderAliases {
    /// The provider namespace (e.g., `"Microsoft.Storage"`).
    pub namespace: String,

    /// Resource types with their alias entries.
    #[serde(default, rename = "resourceTypes")]
    pub resource_types: Vec<ResourceTypeAliases>,
}

/// Parsed alias data for a single resource type, keyed by short name.
///
/// The short name is derived by stripping the resource type prefix from the
/// fully qualified alias name:
/// `Microsoft.Storage/storageAccounts/sku.name` → `sku.name`
#[derive(Debug, Clone)]
pub struct ResolvedAliases {
    /// Fully qualified resource type (e.g., `"Microsoft.Storage/storageAccounts"`).
    pub resource_type: String,
    /// Map from alias short name (case-insensitive key, stored lowercase) to
    /// the resolved ARM path.
    pub entries: BTreeMap<String, ResolvedEntry>,
    /// Array field names whose elements are sub-resources (have their own
    /// `properties` wrapper to flatten).
    pub sub_resource_arrays: Vec<String>,
}

/// A resolved alias entry with its default path and optional versioned paths.
#[derive(Debug, Clone)]
pub struct ResolvedEntry {
    /// The original-cased alias short name (e.g., `"accountType"`, not
    /// `"accounttype"`).  The entries map uses lowercase keys for
    /// case-insensitive lookup, but the normalizer needs the original casing
    /// to write values at correctly-cased paths in the output.
    pub short_name: String,
    /// The default ARM JSON path.
    pub default_path: String,
    /// Versioned path overrides: `(api_version, arm_path)` pairs.
    pub versioned_paths: Vec<(String, String)>,
    /// Optional metadata from the alias catalog (type, modifiability).
    pub metadata: Option<AliasMetadata>,
}

impl ResolvedEntry {
    /// Select the ARM path for a given API version.
    ///
    /// If `api_version` is `Some` and matches a versioned path, returns that
    /// path. Otherwise returns the `default_path`.
    pub fn select_path(&self, api_version: Option<&str>) -> &str {
        if let Some(ver) = api_version {
            for (v, path) in &self.versioned_paths {
                if v.eq_ignore_ascii_case(ver) {
                    return path;
                }
            }
        }
        &self.default_path
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::unwrap_used)]
mod tests {
    use alloc::string::ToString as _;
    use alloc::vec;

    use super::*;

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

    #[test]
    fn select_path_no_version_returns_default() {
        let entry = make_entry(
            "enabled",
            "properties.enabled",
            vec![("2020-01-01", "properties.isEnabled")],
        );
        assert_eq!(entry.select_path(None), "properties.enabled");
    }

    #[test]
    fn select_path_matching_version() {
        let entry = make_entry(
            "enabled",
            "properties.enabled",
            vec![
                ("2020-01-01", "properties.isEnabled"),
                ("2021-06-01", "properties.enabled"),
            ],
        );
        assert_eq!(
            entry.select_path(Some("2020-01-01")),
            "properties.isEnabled"
        );
    }

    #[test]
    fn select_path_no_matching_version_returns_default() {
        let entry = make_entry(
            "enabled",
            "properties.enabled",
            vec![("2020-01-01", "properties.isEnabled")],
        );
        assert_eq!(entry.select_path(Some("9999-01-01")), "properties.enabled");
    }

    #[test]
    fn select_path_case_insensitive_version() {
        let entry = make_entry(
            "enabled",
            "properties.enabled",
            vec![("2020-01-01-Preview", "properties.isEnabled")],
        );
        assert_eq!(
            entry.select_path(Some("2020-01-01-preview")),
            "properties.isEnabled"
        );
    }

    #[test]
    fn select_path_empty_versioned_paths() {
        let entry = make_entry("enabled", "properties.enabled", vec![]);
        assert_eq!(entry.select_path(Some("2020-01-01")), "properties.enabled");
    }

    #[test]
    fn deserialize_provider_aliases() {
        let json = r#"{
            "namespace": "Microsoft.Storage",
            "resourceTypes": [
                {
                    "resourceType": "storageAccounts",
                    "aliases": [
                        {
                            "name": "Microsoft.Storage/storageAccounts/sku.name",
                            "defaultPath": "sku.name",
                            "defaultMetadata": { "type": "String", "attributes": "Modifiable" },
                            "paths": []
                        },
                        {
                            "name": "Microsoft.Storage/storageAccounts/accessTier",
                            "defaultPath": "properties.accessTier",
                            "paths": [
                                {
                                    "path": "properties.accessTier",
                                    "apiVersions": ["2021-01-01", "2020-08-01-preview"],
                                    "metadata": { "type": "String" }
                                }
                            ]
                        }
                    ]
                }
            ]
        }"#;

        let provider: ProviderAliases = serde_json::from_str(json).unwrap();
        assert_eq!(provider.namespace, "Microsoft.Storage");
        assert_eq!(provider.resource_types.len(), 1);

        let rt = &provider.resource_types[0];
        assert_eq!(rt.resource_type, "storageAccounts");
        assert_eq!(rt.aliases.len(), 2);

        let sku_alias = &rt.aliases[0];
        assert_eq!(sku_alias.default_path.as_deref(), Some("sku.name"));
        assert!(sku_alias.paths.is_empty());

        let access_alias = &rt.aliases[1];
        assert_eq!(access_alias.paths.len(), 1);
        assert_eq!(access_alias.paths[0].api_versions.len(), 2);
    }

    #[test]
    fn deserialize_alias_metadata() {
        let json = r#"{
            "name": "test/alias",
            "defaultPath": "properties.value",
            "defaultMetadata": { "type": "Integer", "attributes": "None" },
            "paths": []
        }"#;
        let entry: AliasEntry = serde_json::from_str(json).unwrap();
        let meta = entry.default_metadata.unwrap();
        assert_eq!(meta.kind.as_deref(), Some("Integer"));
        assert_eq!(meta.attributes.as_deref(), Some("None"));
    }
}
