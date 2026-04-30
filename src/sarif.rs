// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! SARIF (Static Analysis Results Interchange Format) output for policy evaluation.
//!
//! This module converts policy evaluation results into SARIF v2.1.0 format,
//! enabling integration with GitHub Advanced Security, Azure DevOps, and other
//! SARIF-consuming tools.
//!
//! # Usage
//! ```no_run
//! use regorus::sarif::{SarifReport, SarifConfig};
//! use regorus::Engine;
//!
//! let mut engine = Engine::new();
//! // ... load policies and data ...
//! let results = engine.eval_query("data.policy.violations".to_string(), false)?;
//! let report = SarifReport::from_query_results(&results, &SarifConfig::default())?;
//! println!("{}", report.to_json()?);
//! ```

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use serde::Serialize;

use crate::QueryResults;
use crate::Value;

/// Configuration for SARIF report generation.
#[derive(Clone, Debug)]
pub struct SarifConfig {
    /// Tool name reported in the SARIF output.
    pub tool_name: String,
    /// Tool version.
    pub tool_version: String,
    /// Base URI for artifact locations (e.g., file:///workspace/).
    pub base_uri: String,
    /// Severity mapping: field name in violation objects that maps to SARIF level.
    pub severity_field: String,
    /// Message field name in violation objects.
    pub message_field: String,
    /// File/location field name in violation objects.
    pub location_field: String,
    /// Rule ID field name in violation objects.
    pub rule_id_field: String,
    /// Maximum number of results to include (0 = unlimited).
    pub max_results: usize,
}

impl Default for SarifConfig {
    fn default() -> Self {
        Self {
            tool_name: "regorus".to_string(),
            tool_version: env!("CARGO_PKG_VERSION").to_string(),
            base_uri: String::new(),
            severity_field: "severity".to_string(),
            message_field: "msg".to_string(),
            location_field: "file".to_string(),
            rule_id_field: "rule_id".to_string(),
            max_results: 0,
        }
    }
}

/// A complete SARIF v2.1.0 report.
#[derive(Debug, Serialize)]
pub struct SarifReport {
    #[serde(rename = "$schema")]
    schema: String,
    version: String,
    runs: Vec<SarifRun>,
}

#[derive(Debug, Serialize)]
struct SarifRun {
    tool: SarifTool,
    results: Vec<SarifResult>,
    #[serde(rename = "originalUriBaseIds")]
    #[serde(skip_serializing_if = "Option::is_none")]
    original_uri_base_ids: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
struct SarifTool {
    driver: SarifToolComponent,
}

#[derive(Debug, Serialize)]
struct SarifToolComponent {
    name: String,
    version: String,
    #[serde(rename = "informationUri")]
    information_uri: String,
    rules: Vec<SarifReportingDescriptor>,
}

#[derive(Debug, Serialize)]
struct SarifReportingDescriptor {
    id: String,
    #[serde(rename = "shortDescription")]
    short_description: SarifMessage,
}

#[derive(Debug, Serialize)]
struct SarifResult {
    #[serde(rename = "ruleId")]
    rule_id: String,
    level: String,
    message: SarifMessage,
    locations: Vec<SarifLocation>,
}

#[derive(Debug, Serialize)]
struct SarifLocation {
    #[serde(rename = "physicalLocation")]
    physical_location: SarifPhysicalLocation,
}

#[derive(Debug, Serialize)]
struct SarifPhysicalLocation {
    #[serde(rename = "artifactLocation")]
    artifact_location: SarifArtifactLocation,
}

#[derive(Debug, Serialize)]
struct SarifArtifactLocation {
    uri: String,
    #[serde(rename = "uriBaseId")]
    #[serde(skip_serializing_if = "Option::is_none")]
    uri_base_id: Option<String>,
}

#[derive(Debug, Serialize, Clone)]
struct SarifMessage {
    text: String,
}

/// Maps OPA-style severity strings to SARIF levels.
fn map_severity(severity: &str) -> &'static str {
    match severity.to_lowercase().as_str() {
        "error" | "critical" | "high" => "error",
        "warning" | "medium" => "warning",
        "info" | "note" | "low" => "note",
        _ => "warning",
    }
}

/// Sanitize a string for use as a SARIF rule ID.
/// Rule IDs must be stable identifiers — only alphanumeric, dash, dot, slash allowed.
fn sanitize_rule_id(raw: &str) -> String {
    raw.chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '.' || c == '/' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// Construct an artifact URI from the location field value.
/// If base_uri is configured, the location is treated as relative.
fn build_artifact_uri(location: &str, base_uri: &str) -> (String, Option<String>) {
    if base_uri.is_empty() {
        // Use location as-is; if it looks like an absolute path, convert to file URI
        if location.starts_with('/') {
            (format!("file://{location}"), None)
        } else {
            (location.to_string(), None)
        }
    } else {
        // Strip leading slash/dot from relative path
        let relative = location.trim_start_matches('/').trim_start_matches("./");
        (relative.to_string(), Some("SRCROOT".to_string()))
    }
}

impl SarifReport {
    /// Create a SARIF report from query results.
    ///
    /// Expects query results where each result expression value is either:
    /// - A set/array of violation objects, or
    /// - A single violation object
    ///
    /// Violation objects should have fields matching the config (msg, severity, file, rule_id).
    pub fn from_query_results(
        query_results: &QueryResults,
        config: &SarifConfig,
    ) -> Result<Self, String> {
        let mut results = Vec::new();
        let mut rules_seen = Vec::new();

        for query_result in query_results.result.iter() {
            for expression in query_result.expressions.iter() {
                let violations = extract_violations(&expression.value);
                for violation in violations {
                    if config.max_results > 0 && results.len() >= config.max_results {
                        break;
                    }

                    let rule_id = extract_string_field(&violation, &config.rule_id_field)
                        .unwrap_or_else(|| "policy-violation".to_string());
                    let rule_id = sanitize_rule_id(&rule_id);

                    let message = extract_string_field(&violation, &config.message_field)
                        .unwrap_or_else(|| "Policy violation detected".to_string());

                    let severity = extract_string_field(&violation, &config.severity_field)
                        .unwrap_or_else(|| "warning".to_string());

                    let location = extract_string_field(&violation, &config.location_field)
                        .unwrap_or_else(|| "unknown".to_string());

                    let level = map_severity(&severity).to_string();
                    let (uri, uri_base_id) = build_artifact_uri(&location, &config.base_uri);

                    // Track unique rules
                    if !rules_seen.iter().any(|r: &String| *r == rule_id) {
                        rules_seen.push(rule_id.clone());
                    }

                    results.push(SarifResult {
                        rule_id: rule_id.clone(),
                        level,
                        message: SarifMessage { text: message },
                        locations: vec![SarifLocation {
                            physical_location: SarifPhysicalLocation {
                                artifact_location: SarifArtifactLocation { uri, uri_base_id },
                            },
                        }],
                    });
                }
            }
        }

        let rules: Vec<SarifReportingDescriptor> = rules_seen
            .iter()
            .map(|id| SarifReportingDescriptor {
                id: id.clone(),
                short_description: SarifMessage {
                    text: format!("Policy rule: {id}"),
                },
            })
            .collect();

        let original_uri_base_ids = if !config.base_uri.is_empty() {
            Some(serde_json::json!({
                "SRCROOT": {
                    "uri": config.base_uri
                }
            }))
        } else {
            None
        };

        Ok(SarifReport {
            schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json".to_string(),
            version: "2.1.0".to_string(),
            runs: vec![SarifRun {
                tool: SarifTool {
                    driver: SarifToolComponent {
                        name: config.tool_name.clone(),
                        version: config.tool_version.clone(),
                        information_uri: "https://github.com/microsoft/regorus".to_string(),
                        rules,
                    },
                },
                results,
                original_uri_base_ids,
            }],
        })
    }

    /// Serialize the SARIF report to a JSON string.
    pub fn to_json(&self) -> Result<String, String> {
        serde_json::to_string_pretty(self).map_err(|e| format!("JSON serialization failed: {e}"))
    }

    /// Returns the total number of results in the report.
    pub fn result_count(&self) -> usize {
        self.runs.iter().map(|r| r.results.len()).sum()
    }
}

/// Extract violation objects from a Value.
/// Handles sets, arrays, and single objects.
fn extract_violations(value: &Value) -> Vec<&Value> {
    match value {
        Value::Array(arr) => arr.iter().collect(),
        Value::Set(set) => set.iter().collect(),
        Value::Object(_) => vec![value],
        _ => vec![],
    }
}

/// Extract a string field from a Value object.
fn extract_string_field(value: &Value, field: &str) -> Option<String> {
    if let Value::Object(obj) = value {
        for (k, v) in obj.iter() {
            if let Value::String(key_str) = k {
                if key_str.as_ref() == field {
                    return match v {
                        Value::String(s) => Some(s.as_ref().to_string()),
                        other => Some(format!("{other}")),
                    };
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Engine, Value};

    #[test]
    fn test_empty_results() {
        let engine = Engine::new();
        let results = crate::QueryResults {
            result: vec![],
        };
        let report = SarifReport::from_query_results(&results, &SarifConfig::default()).unwrap();
        assert_eq!(report.result_count(), 0);
        let json = report.to_json().unwrap();
        assert!(json.contains("\"version\": \"2.1.0\""));
    }

    #[test]
    fn test_severity_mapping() {
        assert_eq!(map_severity("error"), "error");
        assert_eq!(map_severity("critical"), "error");
        assert_eq!(map_severity("HIGH"), "error");
        assert_eq!(map_severity("warning"), "warning");
        assert_eq!(map_severity("medium"), "warning");
        assert_eq!(map_severity("info"), "note");
        assert_eq!(map_severity("low"), "note");
        assert_eq!(map_severity("unknown"), "warning");
    }

    #[test]
    fn test_sanitize_rule_id() {
        assert_eq!(sanitize_rule_id("my-rule.v1"), "my-rule.v1");
        assert_eq!(sanitize_rule_id("rule with spaces"), "rule_with_spaces");
        assert_eq!(sanitize_rule_id("data.policy/deny"), "data.policy/deny");
    }

    #[test]
    fn test_build_artifact_uri_absolute() {
        let (uri, base) = build_artifact_uri("/home/user/file.rego", "");
        assert_eq!(uri, "file:///home/user/file.rego");
        assert!(base.is_none());
    }

    #[test]
    fn test_build_artifact_uri_relative() {
        let (uri, base) = build_artifact_uri("./src/policy.rego", "file:///workspace/");
        assert_eq!(uri, "src/policy.rego");
        assert_eq!(base.unwrap(), "SRCROOT");
    }

    #[test]
    fn test_max_results_limit() {
        let mut engine = Engine::new();
        engine
            .add_policy(
                "test.rego".to_string(),
                r#"
                package test
                violations contains v if {
                    some i in [1, 2, 3, 4, 5]
                    v := {"msg": sprintf("violation %d", [i]), "severity": "error", "file": "test.rego", "rule_id": "test-rule"}
                }
                "#
                .to_string(),
            )
            .unwrap();

        let results = engine
            .eval_query("data.test.violations".to_string(), false)
            .unwrap();

        let mut config = SarifConfig::default();
        config.max_results = 3;

        let report = SarifReport::from_query_results(&results, &config).unwrap();
        assert_eq!(report.result_count(), 3);
    }

    #[test]
    fn test_full_sarif_structure() {
        let mut engine = Engine::new();
        engine
            .add_policy(
                "policy.rego".to_string(),
                r#"
                package security
                deny contains msg if {
                    msg := {
                        "msg": "Container running as root",
                        "severity": "critical",
                        "file": "deployment.yaml",
                        "rule_id": "container-security/no-root"
                    }
                }
                "#
                .to_string(),
            )
            .unwrap();

        let results = engine
            .eval_query("data.security.deny".to_string(), false)
            .unwrap();

        let config = SarifConfig {
            base_uri: "file:///workspace/".to_string(),
            ..Default::default()
        };

        let report = SarifReport::from_query_results(&results, &config).unwrap();
        assert_eq!(report.result_count(), 1);

        let json = report.to_json().unwrap();
        assert!(json.contains("container-security/no-root"));
        assert!(json.contains("Container running as root"));
        assert!(json.contains("\"level\": \"error\""));
        assert!(json.contains("deployment.yaml"));
        assert!(json.contains("SRCROOT"));
    }
}
