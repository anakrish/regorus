// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Legacy explanation types — public types are re-exported from `crate::causality`.
//! This module retains internal (`Raw*`) types used by the AST interpreter and
//! the old RVM recording path until they are fully migrated.

// Re-export all public types from causality so that existing `crate::explanations::X`
// references resolve to the canonical definitions.
#[allow(unused_imports)]
pub use crate::causality::{
    filter_explanations_for_complete_rule, normalize_explanations, sanitize_condition_value,
    sanitize_explanation_binding, AnnotatedValue, BindingExplanation, CausalityReport,
    ConditionEvaluation, ConditionEvaluationKind, ConditionEvaluationWitness,
    ConditionIterationWitness, ConditionOperator, EmissionExplanation, ExplanationBinding,
    ExplanationConditionMode, ExplanationOutcome, ExplanationRecord, ExplanationSettings,
    ExplanationValueMode, RuleWithExplanations, SourceLocation,
};

use crate::Value;
use alloc::string::String;
use alloc::vec::Vec;

// ── Internal types (still used by interpreter and old RVM code) ──────

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
            actual_path: None,
            expected_path: None,
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
            collection_path: None,
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
