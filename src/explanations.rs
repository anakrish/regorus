// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::{Rc, Value};
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use alloc::string::ToString as _;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

const REDACTED_VALUE: &str = "<redacted>";
const SECRET_HINTS: &[&str] = &[
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "credential",
    "auth",
    "jwt",
    "bearer",
    "cookie",
    "session",
    "private",
    "client_secret",
    "refresh_token",
    "access_token",
    "certificate",
    "cert",
];

/// Source location for an explanation record.
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct SourceLocation {
    /// Path of the policy file.
    pub file: Rc<str>,
    /// 1-based line number.
    pub row: u32,
    /// 1-based column number.
    pub col: u32,
}

/// Controls whether explanation bindings keep or redact secret-looking values.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Eq, PartialEq, Default)]
pub enum ExplanationValueMode {
    /// Replace secret-looking values with a redaction marker.
    #[default]
    Redacted,
    /// Preserve values exactly as evaluated.
    Full,
}

/// Controls whether reasons include only the primary condition or all contributing conditions.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Eq, PartialEq, Default)]
#[serde(rename_all = "snake_case")]
pub enum ExplanationConditionMode {
    /// Capture one primary condition per block.
    #[default]
    PrimaryOnly,
    /// Capture all contributing conditions for each block in evaluation order.
    AllContributing,
}

/// Runtime settings for explanation capture.
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, Default)]
pub struct ExplanationSettings {
    /// Enables explanation capture for subsequent evaluations.
    pub enabled: bool,
    /// Controls whether captured bindings should be redacted.
    pub value_mode: ExplanationValueMode,
    /// Controls whether one primary or all contributing conditions are captured.
    #[serde(default)]
    pub condition_mode: ExplanationConditionMode,
}

/// One captured binding in an explanation record.
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct ExplanationBinding {
    /// Variable name visible at the success point.
    pub name: Rc<str>,
    /// Captured value, possibly redacted.
    pub value: Value,
    /// True when the value was redacted.
    pub redacted: bool,
}

/// Outcome recorded for a block summary.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ExplanationOutcome {
    /// The block succeeded and the terminal condition completed the proof.
    Success,
    /// The block failed and the terminal condition blocked the proof.
    Failure,
}

/// Normalized condition category for structured reason payloads.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ConditionEvaluationKind {
    Comparison,
    Membership,
    Existence,
    Truthiness,
    Quantifier,
    Comprehension,
    Builtin,
    Call,
    Unknown,
}

/// Normalized operator for structured reason payloads.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ConditionOperator {
    Any,
    Equals,
    NotEquals,
    LessThan,
    LessThanOrEquals,
    GreaterThan,
    GreaterThanOrEquals,
    ForEach,
    In,
    Contains,
    StartsWith,
    EndsWith,
    RegexMatch,
    GlobMatch,
    Exists,
    NotExists,
    Truthy,
    Falsy,
    Every,
    IsArray,
    IsBoolean,
    IsNull,
    IsNumber,
    IsObject,
    IsSet,
    IsString,
}

/// Bounded witness data for quantified or collection-producing conditions.
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct ConditionIterationWitness {
    /// Sample key for the iteration, when available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sample_key: Option<Value>,
    /// Sample value for the iteration, when available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sample_value: Option<Value>,
    /// Bindings visible in the sampled iteration.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bindings: Vec<ExplanationBinding>,
    /// True when `sample_key` was redacted.
    #[serde(default, skip_serializing_if = "is_false")]
    pub sample_key_redacted: bool,
    /// True when `sample_value` was redacted.
    #[serde(default, skip_serializing_if = "is_false")]
    pub sample_value_redacted: bool,
}

/// Bounded witness data for quantified or collection-producing conditions.
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct ConditionEvaluationWitness {
    /// Number of iterations considered by the condition.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iteration_count: Option<u32>,
    /// Number of successful iterations.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub success_count: Option<u32>,
    /// Number of yielded entries for comprehensions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub yield_count: Option<u32>,
    /// Distinct condition texts checked within the loop or quantifier body.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub condition_texts: Vec<Rc<str>>,
    /// Sample key associated with a decisive iteration or yielded entry.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sample_key: Option<Value>,
    /// Sample value associated with a decisive iteration or yielded entry.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sample_value: Option<Value>,
    /// True when `sample_key` was redacted.
    #[serde(default, skip_serializing_if = "is_false")]
    pub sample_key_redacted: bool,
    /// True when `sample_value` was redacted.
    #[serde(default, skip_serializing_if = "is_false")]
    pub sample_value_redacted: bool,
    /// One passing iteration, when captured.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub passing_iteration: Option<ConditionIterationWitness>,
    /// One failing iteration, when captured.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failing_iteration: Option<ConditionIterationWitness>,
}

/// Structured evaluation details for a condition.
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct ConditionEvaluation {
    /// Broad category of the condition.
    pub kind: ConditionEvaluationKind,
    /// Optional normalized operator for the condition.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operator: Option<ConditionOperator>,
    /// Observed value at evaluation time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actual_value: Option<Value>,
    /// Comparison target or expected value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_value: Option<Value>,
    /// True when `actual_value` was redacted.
    #[serde(default, skip_serializing_if = "is_false")]
    pub actual_value_redacted: bool,
    /// True when `expected_value` was redacted.
    #[serde(default, skip_serializing_if = "is_false")]
    pub expected_value_redacted: bool,
    /// Optional bounded witness details for loops, quantifiers, or comprehensions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub witness: Option<ConditionEvaluationWitness>,
}

/// One explanation record for a produced rule result.
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct ExplanationRecord {
    /// Whether the block succeeded or failed.
    pub outcome: ExplanationOutcome,
    /// Source location associated with the successful emission.
    pub location: SourceLocation,
    /// Source text for the successful contributing condition.
    pub text: Rc<str>,
    /// Optional structured evaluation details for the condition.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evaluation: Option<ConditionEvaluation>,
    /// Visible named bindings captured at the success point.
    pub bindings: Vec<ExplanationBinding>,
}

/// Result of evaluating a rule with explanation records.
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct RuleWithExplanations {
    /// The evaluated rule value.
    pub value: Value,
    /// Explanation records grouped by emitted set element, object key, or final value.
    pub explanations: BTreeMap<Value, Vec<ExplanationRecord>>,
}

pub fn sanitize_explanation_binding(
    name: &str,
    value: &Value,
    settings: &ExplanationSettings,
) -> ExplanationBinding {
    let (sanitized_value, redacted) =
        sanitize_explanation_value(value, settings.value_mode, Some(name));
    ExplanationBinding {
        name: name.to_string().into(),
        value: sanitized_value,
        redacted,
    }
}

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
struct ConditionDisplayKey {
    file: Rc<str>,
    row: u32,
    col: u32,
    text: Rc<str>,
}

fn quantifier_condition_texts(record: &ExplanationRecord) -> Option<BTreeSet<Rc<str>>> {
    let evaluation = record.evaluation.as_ref()?;
    if evaluation.kind != ConditionEvaluationKind::Quantifier {
        return None;
    }

    let witness = evaluation.witness.as_ref()?;
    if witness.condition_texts.is_empty() {
        return None;
    }

    Some(witness.condition_texts.iter().cloned().collect())
}

fn is_earlier_record(lhs: &ExplanationRecord, rhs: &ExplanationRecord) -> bool {
    (lhs.location.row, lhs.location.col, lhs.text.as_ref())
        < (rhs.location.row, rhs.location.col, rhs.text.as_ref())
}

fn project_explanation_records(records: Vec<ExplanationRecord>) -> Vec<ExplanationRecord> {
    let quantifier_text_sets = records
        .iter()
        .enumerate()
        .filter_map(|(idx, record)| quantifier_condition_texts(record).map(|texts| (idx, texts)))
        .collect::<Vec<_>>();

    records
        .iter()
        .enumerate()
        .filter_map(|(idx, record)| {
            let keep_record = quantifier_condition_texts(record).map_or_else(
                || {
                    !quantifier_text_sets.iter().any(|entry| {
                        record.outcome == ExplanationOutcome::Success
                            && entry.1.contains(&record.text)
                    })
                },
                |current_texts| {
                    !quantifier_text_sets.iter().any(|entry| {
                        let other_idx = entry.0;
                        let other_texts = &entry.1;
                        let Some(other) = records.get(other_idx) else {
                            return false;
                        };

                        if idx == other_idx || other.outcome != record.outcome {
                            return false;
                        }

                        let is_strict_superset = other_texts.is_superset(&current_texts)
                            && other_texts.len() > current_texts.len();
                        let is_same_set_but_earlier =
                            other_texts == &current_texts && is_earlier_record(other, record);

                        is_strict_superset || is_same_set_but_earlier
                    })
                },
            );

            keep_record.then_some(record.clone())
        })
        .collect()
}

pub fn normalize_explanation_records(records: Vec<ExplanationRecord>) -> Vec<ExplanationRecord> {
    let successful_keys = records
        .iter()
        .filter(|record| record.outcome == ExplanationOutcome::Success)
        .map(|record| ConditionDisplayKey {
            file: record.location.file.clone(),
            row: record.location.row,
            col: record.location.col,
            text: record.text.clone(),
        })
        .collect::<BTreeSet<_>>();

    let records = records
        .into_iter()
        .filter(|record| {
            record.outcome == ExplanationOutcome::Success
                || !successful_keys.contains(&ConditionDisplayKey {
                    file: record.location.file.clone(),
                    row: record.location.row,
                    col: record.location.col,
                    text: record.text.clone(),
                })
        })
        .collect();

    project_explanation_records(records)
}

pub fn normalize_explanations(
    explanations: BTreeMap<Value, Vec<ExplanationRecord>>,
) -> BTreeMap<Value, Vec<ExplanationRecord>> {
    explanations
        .into_iter()
        .map(|(value, records)| {
            let records = normalize_explanation_records(records);
            let has_success = records
                .iter()
                .any(|record| record.outcome == ExplanationOutcome::Success);
            let records = if has_success && value != Value::Bool(false) {
                records
                    .into_iter()
                    .filter(|record| record.outcome == ExplanationOutcome::Success)
                    .collect()
            } else {
                records
            };
            (value, records)
        })
        .collect()
}

pub fn filter_explanations_for_complete_rule(
    mut explanations: BTreeMap<Value, Vec<ExplanationRecord>>,
    result: &Value,
) -> BTreeMap<Value, Vec<ExplanationRecord>> {
    let mut merged_records = explanations.remove(result).unwrap_or_default();

    merged_records.extend(
        explanations
            .into_iter()
            .filter(|entry| entry.0 != *result)
            .flat_map(|(_, records)| records),
    );

    if merged_records.is_empty() {
        return BTreeMap::new();
    }

    let mut filtered = BTreeMap::new();
    filtered.insert(
        result.clone(),
        normalize_explanation_records(merged_records),
    );
    filtered
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RawConditionEvaluation {
    pub kind: ConditionEvaluationKind,
    pub operator: Option<ConditionOperator>,
    pub actual_value: Option<Value>,
    pub actual_hint: Option<String>,
    pub expected_value: Option<Value>,
    pub expected_hint: Option<String>,
    pub witness: Option<RawConditionEvaluationWitness>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RawConditionEvaluationWitness {
    pub iteration_count: Option<u32>,
    pub success_count: Option<u32>,
    pub yield_count: Option<u32>,
    pub condition_texts: Vec<String>,
    pub sample_key: Option<Value>,
    pub sample_key_hint: Option<String>,
    pub sample_value: Option<Value>,
    pub sample_value_hint: Option<String>,
    pub passing_iteration: Option<RawConditionIterationWitness>,
    pub failing_iteration: Option<RawConditionIterationWitness>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RawConditionIterationWitness {
    pub sample_key: Option<Value>,
    pub sample_key_hint: Option<String>,
    pub sample_value: Option<Value>,
    pub sample_value_hint: Option<String>,
    pub bindings: Vec<ExplanationBinding>,
}

impl RawConditionEvaluation {
    pub(crate) fn sanitize(self, settings: &ExplanationSettings) -> ConditionEvaluation {
        let (actual_value, actual_value_redacted) = self
            .actual_value
            .as_ref()
            .map(|value| sanitize_condition_value(value, settings, self.actual_hint.as_deref()))
            .map_or((None, false), |(value, redacted)| (Some(value), redacted));
        let (expected_value, expected_value_redacted) = self
            .expected_value
            .as_ref()
            .map(|value| sanitize_condition_value(value, settings, self.expected_hint.as_deref()))
            .map_or((None, false), |(value, redacted)| (Some(value), redacted));
        let witness = self.witness.map(|witness| witness.sanitize(settings));

        ConditionEvaluation {
            kind: self.kind,
            operator: self.operator,
            actual_value,
            expected_value,
            actual_value_redacted,
            expected_value_redacted,
            witness,
        }
    }
}

impl RawConditionEvaluationWitness {
    pub(crate) fn sanitize(self, settings: &ExplanationSettings) -> ConditionEvaluationWitness {
        let (sample_key, sample_key_redacted) = self
            .sample_key
            .as_ref()
            .map(|value| sanitize_condition_value(value, settings, self.sample_key_hint.as_deref()))
            .map_or((None, false), |(value, redacted)| (Some(value), redacted));
        let (sample_value, sample_value_redacted) = self
            .sample_value
            .as_ref()
            .map(|value| {
                sanitize_condition_value(value, settings, self.sample_value_hint.as_deref())
            })
            .map_or((None, false), |(value, redacted)| (Some(value), redacted));

        let passing_iteration = self
            .passing_iteration
            .map(|witness| witness.sanitize(settings));
        let failing_iteration = self
            .failing_iteration
            .map(|witness| witness.sanitize(settings));

        ConditionEvaluationWitness {
            iteration_count: self.iteration_count,
            success_count: self.success_count,
            yield_count: self.yield_count,
            condition_texts: self
                .condition_texts
                .into_iter()
                .map(|text| text.into())
                .collect(),
            sample_key,
            sample_value,
            sample_key_redacted,
            sample_value_redacted,
            passing_iteration,
            failing_iteration,
        }
    }
}

impl RawConditionIterationWitness {
    pub(crate) fn sanitize(self, settings: &ExplanationSettings) -> ConditionIterationWitness {
        let (sample_key, sample_key_redacted) = self
            .sample_key
            .as_ref()
            .map(|value| sanitize_condition_value(value, settings, self.sample_key_hint.as_deref()))
            .map_or((None, false), |(value, redacted)| (Some(value), redacted));
        let (sample_value, sample_value_redacted) = self
            .sample_value
            .as_ref()
            .map(|value| {
                sanitize_condition_value(value, settings, self.sample_value_hint.as_deref())
            })
            .map_or((None, false), |(value, redacted)| (Some(value), redacted));

        ConditionIterationWitness {
            sample_key,
            sample_value,
            bindings: self.bindings,
            sample_key_redacted,
            sample_value_redacted,
        }
    }
}

pub fn sanitize_condition_value(
    value: &Value,
    settings: &ExplanationSettings,
    hint: Option<&str>,
) -> (Value, bool) {
    sanitize_explanation_value(value, settings.value_mode, hint)
}

fn sanitize_explanation_value(
    value: &Value,
    value_mode: ExplanationValueMode,
    field_name: Option<&str>,
) -> (Value, bool) {
    if value_mode == ExplanationValueMode::Full {
        return (value.clone(), false);
    }

    if field_name.is_some_and(looks_secret_like_name) {
        return (redacted_placeholder(), true);
    }

    match *value {
        Value::Array(ref items) => {
            let mut redacted = false;
            let sanitized_items = items
                .iter()
                .map(|item| {
                    let (sanitized, item_redacted) =
                        sanitize_explanation_value(item, value_mode, None);
                    redacted |= item_redacted;
                    sanitized
                })
                .collect::<Vec<_>>();
            (Value::from_array(sanitized_items), redacted)
        }
        Value::Set(ref items) => {
            let mut redacted = false;
            let sanitized_items = items
                .iter()
                .map(|item| {
                    let (sanitized, item_redacted) =
                        sanitize_explanation_value(item, value_mode, None);
                    redacted |= item_redacted;
                    sanitized
                })
                .collect::<BTreeSet<_>>();
            (Value::from_set(sanitized_items), redacted)
        }
        Value::Object(ref fields) => {
            let mut redacted = false;
            let sanitized_fields = fields
                .iter()
                .map(|(key, item_value)| {
                    let key_name = match *key {
                        Value::String(ref name) => Some(name.as_ref()),
                        _ => None,
                    };
                    let (sanitized, item_redacted) =
                        sanitize_explanation_value(item_value, value_mode, key_name);
                    redacted |= item_redacted;
                    (key.clone(), sanitized)
                })
                .collect::<BTreeMap<_, _>>();
            (Value::from_map(sanitized_fields), redacted)
        }
        _ => (value.clone(), false),
    }
}

fn redacted_placeholder() -> Value {
    Value::from(REDACTED_VALUE)
}

fn looks_secret_like_name(name: &str) -> bool {
    let lower_name = name.to_ascii_lowercase();
    SECRET_HINTS.iter().any(|hint| lower_name.contains(hint))
}

const fn is_false(value: &bool) -> bool {
    !*value
}
