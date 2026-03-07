// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! YAML format definitions for external Azure Policy test suites.
//!
//! Supports the formats used by:
//! - `csharp-converted/` — inline `policyRule` per test case
//! - `builtin/` — file-level `policy:` path to a JSON definition
//! - `samples/` — same as builtin
//! - `managed-policies/` — DenyAction tests with `requests` (skipped)
//! - `dataplane/` — data-plane policies with `parentResource`

use serde::Deserialize;

/// Top-level structure of a `*.Test.yaml` file.
#[derive(Deserialize, Debug)]
pub struct TestFile {
    #[serde(default)]
    pub title: Option<String>,

    /// Path to a policy definition JSON file (relative to the YAML file).
    /// May use Windows-style backslashes.
    #[serde(default)]
    pub policy: Option<String>,

    #[serde(default)]
    pub tests: Vec<TestCase>,
}

/// A single test case.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct TestCase {
    pub name: String,

    /// Parameters passed to the policy.
    #[serde(default)]
    pub parameters: Option<serde_json::Value>,

    /// Inline policy rule JSON (used in `csharp-converted` tests).
    /// When present, takes precedence over the file-level `policy` path.
    #[serde(default)]
    pub policy_rule: Option<serde_json::Value>,

    /// Expected outcome.
    pub expected: Expected,

    /// Resource JSON strings to evaluate. Each string is a JSON object.
    #[serde(default)]
    pub resources: Vec<String>,

    /// Optional environment context (related resources, resource group, etc.).
    #[serde(default)]
    pub environment: Option<Environment>,

    /// DenyAction-style tests use `requests` instead of `resources`.
    #[serde(default)]
    pub requests: Vec<Request>,
}

/// A single DenyAction request.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Request {
    /// HTTP method (e.g., `Delete`).
    pub http_method: String,

    /// Identity claims JSON string (contains `idtyp`, etc.).
    #[serde(default)]
    pub request_identity_claims: Option<String>,

    /// Policy token claims JSON string (contains `outcome`, `validationOutput`, etc.).
    #[serde(default)]
    pub policy_token_claims: Option<String>,

    /// The existing resource JSON string.
    #[serde(default)]
    pub existing_resource: Option<String>,
}

/// Expected evaluation outcome.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Expected {
    /// `Compliant`, `NonCompliant`, `Protected`, `NotApplicable`, etc.
    #[serde(default)]
    pub compliance_state: Option<String>,

    /// Legacy alias for `complianceState`.
    #[serde(default)]
    pub outcome: Option<String>,

    /// Expected policy effect name (e.g., `Deny`, `Audit`, `Modify`).
    #[serde(default)]
    pub effect: Option<String>,

    /// Expected field modifications (for Modify/Append effects).
    #[serde(default)]
    pub fields: Vec<FieldExpectation>,

    /// Expected deployment template assertions (for DINE effects).
    #[serde(default)]
    pub deployment: Vec<serde_json::Value>,

    /// Expected missing token action (for DenyAction).
    #[serde(default)]
    pub missing_token_action: Option<String>,
}

/// A single field value expectation (Modify/Append).
#[derive(Deserialize, Debug)]
pub struct FieldExpectation {
    pub path: String,
    pub value: serde_json::Value,
}

/// Test environment context.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Environment {
    /// Related resource JSON string (for AINE/DINE existence checks).
    #[serde(default)]
    pub related_resource: Option<String>,

    /// Resource group override.
    #[serde(default)]
    pub resource_group: Option<String>,

    /// Parent resource (for data-plane tests).
    #[serde(default)]
    pub parent_resource: Option<String>,
}

impl Expected {
    /// Return the normalised compliance state string.
    pub fn state(&self) -> Option<&str> {
        self.compliance_state.as_deref().or(self.outcome.as_deref())
    }
}
