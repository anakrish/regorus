// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Causality tracking for Rego evaluation.
//!
//! This module provides production-grade causal explanation capture.
//! During evaluation, thin events are recorded with minimal allocation
//! (Value clones are Rc-bumps, no string construction or sanitization).
//! Materialization into the public output model happens once when
//! `take_explanations()` is called.

// Some event variants and helper methods are defined for future two-pass evaluation
// but not yet wired into the current single-pass recording path.
#![allow(dead_code)]

use crate::value::Value;
use crate::Rc;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

// ── Public output types (serializable) ────────────────────────────────

/// Source location for an explanation record.
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct SourceLocation {
    pub file: Rc<str>,
    pub row: u32,
    pub col: u32,
}

/// Controls whether explanation bindings keep or redact secret-looking values.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Eq, PartialEq, Default)]
pub enum ExplanationValueMode {
    #[default]
    Redacted,
    Full,
}

/// Controls whether reasons include only the primary condition or all contributing conditions.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Eq, PartialEq, Default)]
#[serde(rename_all = "snake_case")]
pub enum ExplanationConditionMode {
    #[default]
    PrimaryOnly,
    AllContributing,
}

/// Runtime settings for explanation capture.
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, Default)]
pub struct ExplanationSettings {
    pub enabled: bool,
    pub value_mode: ExplanationValueMode,
    #[serde(default)]
    pub condition_mode: ExplanationConditionMode,
}

/// One captured binding in an explanation record.
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct ExplanationBinding {
    pub name: Rc<str>,
    pub value: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_path: Option<Rc<str>>,
    pub redacted: bool,
}

/// Outcome recorded for a block summary.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ExplanationOutcome {
    Success,
    Failure,
}

/// Normalized condition category.
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

/// Normalized operator.
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

/// Bounded witness for a single iteration.
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct ConditionIterationWitness {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sample_key: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sample_value: Option<Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bindings: Vec<ExplanationBinding>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub sample_key_redacted: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub sample_value_redacted: bool,
}

/// Witness data for quantified or collection-producing conditions.
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct ConditionEvaluationWitness {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub collection_path: Option<Rc<str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iteration_count: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub success_count: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub yield_count: Option<u32>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub condition_texts: Vec<Rc<str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sample_key: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sample_value: Option<Value>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub sample_key_redacted: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub sample_value_redacted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub passing_iteration: Option<ConditionIterationWitness>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failing_iteration: Option<ConditionIterationWitness>,
}

/// Structured evaluation details for a condition.
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct ConditionEvaluation {
    pub kind: ConditionEvaluationKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operator: Option<ConditionOperator>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actual_value: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_value: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actual_path: Option<Rc<str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_path: Option<Rc<str>>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub actual_value_redacted: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub expected_value_redacted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub witness: Option<ConditionEvaluationWitness>,
}

/// One explanation record for a produced rule result.
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct ExplanationRecord {
    pub outcome: ExplanationOutcome,
    pub location: SourceLocation,
    pub text: Rc<str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evaluation: Option<ConditionEvaluation>,
    pub bindings: Vec<ExplanationBinding>,
}

/// Result of evaluating a rule with explanation records.
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct RuleWithExplanations {
    pub value: Value,
    pub explanations: BTreeMap<Value, Vec<ExplanationRecord>>,
}

// ── P1: Rich output types ─────────────────────────────────────────────

/// A value annotated with its data-path provenance and redaction status.
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct AnnotatedValue {
    pub value: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<Rc<str>>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub redacted: bool,
}

/// Explanation for a variable binding, with a link to the condition that
/// first established it.
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct BindingExplanation {
    pub name: Rc<str>,
    pub value: AnnotatedValue,
    /// Index into the parent emission's `conditions` list identifying the
    /// condition that first established this binding. `None` if the origin
    /// is unknown.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evaluation_index: Option<usize>,
}

/// Explanation for a single emitted (output) value and the conditions that
/// produced it.
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct EmissionExplanation {
    pub result: Value,
    pub conditions: Vec<ExplanationRecord>,
    pub bindings: Vec<BindingExplanation>,
}

/// Top-level causality report containing explanations for all emitted values.
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct CausalityReport {
    pub emissions: Vec<EmissionExplanation>,
}

impl From<BTreeMap<Value, Vec<ExplanationRecord>>> for CausalityReport {
    fn from(explanations: BTreeMap<Value, Vec<ExplanationRecord>>) -> Self {
        let emissions = explanations
            .into_iter()
            .map(|(result, conditions)| {
                let mut first_seen: BTreeMap<Rc<str>, usize> = BTreeMap::new();
                for (ci, cond) in conditions.iter().enumerate() {
                    for b in &cond.bindings {
                        first_seen.entry(b.name.clone()).or_insert(ci);
                    }
                }

                let mut latest: BTreeMap<Rc<str>, &ExplanationBinding> = BTreeMap::new();
                for cond in &conditions {
                    for b in &cond.bindings {
                        latest.insert(b.name.clone(), b);
                    }
                }

                let bindings = latest
                    .into_iter()
                    .map(|(name, b)| BindingExplanation {
                        name: name.clone(),
                        value: AnnotatedValue {
                            value: b.value.clone(),
                            path: b.source_path.clone(),
                            redacted: b.redacted,
                        },
                        evaluation_index: first_seen.get(&name).copied(),
                    })
                    .collect();

                EmissionExplanation {
                    result,
                    conditions,
                    bindings,
                }
            })
            .collect();

        CausalityReport { emissions }
    }
}

// ── Internal event types (not serialized, used during evaluation) ─────

/// Index into `CausalityCapture::values`.
type ValueIdx = u32;

/// Index into `CausalityCapture::binding_entries`.
type BindingIdx = u32;

/// A thin event recorded during evaluation.
///
/// Values are captured by Rc-bump clone (no deep copy, no sanitization).
/// Source location and rich metadata are resolved at materialization time
/// using the program's instruction spans and explanation info tables.
#[derive(Debug, Clone)]
pub struct CausalEvent {
    /// Program counter at the time of the event.
    pub pc: u32,
    /// Event payload.
    pub kind: CausalEventKind,
}

#[derive(Debug, Clone)]
pub enum CausalEventKind {
    /// A condition was evaluated (AssertCondition / AssertNotUndefined).
    Condition {
        passed: bool,
        /// Index range into `CausalityCapture::binding_entries`.
        bindings_start: BindingIdx,
        bindings_end: BindingIdx,
        /// Snapshot of actual value (Rc-bump clone).
        actual: Option<ValueIdx>,
        /// Snapshot of expected value (Rc-bump clone).
        expected: Option<ValueIdx>,
    },
    /// All conditions for the current block have been finalized.
    BlockFinalized { outcome: ExplanationOutcome },
    /// A value was emitted (set element, object key, or return for complete rule).
    Emission { key: ValueIdx },
    /// Nested rule call records should be inlined for this condition.
    NestedRuleCondition {
        passed: bool,
        /// Range of events from the nested call that should be inlined.
        nested_events_start: u32,
        nested_events_end: u32,
    },
    /// Loop iteration boundary.
    LoopIterationStart {
        result_reg: u8,
        key: Option<ValueIdx>,
        value: ValueIdx,
    },
    /// Loop finished.
    LoopEnd {
        result_reg: u8,
        total_iterations: u32,
        success_count: u32,
    },
}

/// A captured binding entry: (register_index, name, snapshotted_value_index).
#[derive(Debug, Clone)]
pub struct BindingEntry {
    pub name: Rc<str>,
    pub value_idx: ValueIdx,
    pub source_path: Option<Rc<str>>,
}

/// Raw (unsanitized) condition evaluation captured during evaluation.
///
/// This replaces the old `RawConditionEvaluation`. The key difference is that
/// values are stored as indices into the capture's value table and hints are
/// not resolved until materialization.
#[derive(Debug, Clone)]
pub struct RawConditionSnapshot {
    pub kind: ConditionEvaluationKind,
    pub operator: Option<ConditionOperator>,
    pub actual: Option<ValueIdx>,
    pub actual_hint: Option<String>,
    pub actual_path: Option<Rc<str>>,
    pub expected: Option<ValueIdx>,
    pub expected_hint: Option<String>,
    pub expected_path: Option<Rc<str>>,
    pub witness: Option<RawWitnessSnapshot>,
}

/// Raw witness snapshot (indices into capture's value table).
#[derive(Debug, Clone)]
pub struct RawWitnessSnapshot {
    pub collection_path: Option<Rc<str>>,
    pub iteration_count: Option<u32>,
    pub success_count: Option<u32>,
    pub yield_count: Option<u32>,
    pub condition_texts: Vec<String>,
    pub sample_key: Option<ValueIdx>,
    pub sample_key_hint: Option<String>,
    pub sample_value: Option<ValueIdx>,
    pub sample_value_hint: Option<String>,
    pub passing_iteration: Option<RawIterationSnapshot>,
    pub failing_iteration: Option<RawIterationSnapshot>,
}

/// Raw iteration witness snapshot.
#[derive(Debug, Clone)]
pub struct RawIterationSnapshot {
    pub sample_key: Option<ValueIdx>,
    pub sample_key_hint: Option<String>,
    pub sample_value: Option<ValueIdx>,
    pub sample_value_hint: Option<String>,
    pub bindings_start: BindingIdx,
    pub bindings_end: BindingIdx,
}

// ── Loop witness tracking (parallel to loop stack) ───────────────────

/// Lightweight loop witness state tracked during iteration.
/// Replaces the old `WitnessState` with indexed value references.
#[derive(Debug, Clone, Default)]
pub struct LoopWitnessState {
    pub sample_key: Option<ValueIdx>,
    pub sample_value: Option<ValueIdx>,
    pub yield_count: u32,
    pub passing_iteration: Option<RawIterationSnapshot>,
    pub failing_iteration: Option<RawIterationSnapshot>,
    /// Start of block records at loop entry (for slicing iteration records).
    pub block_event_start: u32,
    /// Events from a passing iteration.
    pub passing_events_start: Option<u32>,
    pub passing_events_end: Option<u32>,
    /// Events from a failing iteration.
    pub failing_events_start: Option<u32>,
    pub failing_events_end: Option<u32>,
}

/// Replacement for `LoopExplanationRecordSet`.
/// Stores event ranges for passing/failing iterations rather than cloned records.
#[derive(Debug, Clone, Default)]
pub struct LoopEventRanges {
    pub passing_start: Option<u32>,
    pub passing_end: Option<u32>,
    pub failing_start: Option<u32>,
    pub failing_end: Option<u32>,
}

// ── ProvenanceTracker: parallel to register file ─────────────────────

/// Tracks data-path provenance for each register in the RVM.
///
/// Parallel to `RegoVM::registers`. Each entry records the data-path origin
/// of the register value, e.g. `"input.containers[_].securityContext.privileged"`.
/// `None` means the value is a literal or computed (no data-path origin).
#[derive(Debug, Clone)]
pub struct ProvenanceTracker {
    paths: Vec<Option<Rc<str>>>,
}

impl ProvenanceTracker {
    pub const fn new() -> Self {
        Self { paths: Vec::new() }
    }

    /// Resize to match the register file length. New slots are `None`.
    pub fn resize(&mut self, len: usize) {
        self.paths.resize(len, None);
    }

    /// Clear all entries (retain capacity).
    pub fn clear(&mut self) {
        for slot in &mut self.paths {
            *slot = None;
        }
    }

    /// Get the provenance path for a register.
    #[inline]
    pub fn get(&self, reg: u8) -> Option<&Rc<str>> {
        self.paths.get(usize::from(reg)).and_then(|p| p.as_ref())
    }

    /// Set a root provenance (e.g. `"input"` or `"data"`).
    #[inline]
    pub fn set_root(&mut self, reg: u8, root: &str) {
        if let Some(slot) = self.paths.get_mut(usize::from(reg)) {
            *slot = Some(Rc::from(root));
        }
    }

    /// Clear provenance for a register (computed/literal value).
    #[inline]
    pub fn clear_reg(&mut self, reg: u8) {
        if let Some(slot) = self.paths.get_mut(usize::from(reg)) {
            *slot = None;
        }
    }

    /// Directly set the provenance path for a register.
    #[inline]
    pub fn set_path(&mut self, reg: u8, path: Option<Rc<str>>) {
        if let Some(slot) = self.paths.get_mut(usize::from(reg)) {
            *slot = path;
        }
    }

    /// Copy provenance from `src` to `dest`.
    #[inline]
    pub fn copy(&mut self, dest: u8, src: u8) {
        let src_path = self.paths.get(usize::from(src)).cloned().flatten();
        if let Some(slot) = self.paths.get_mut(usize::from(dest)) {
            *slot = src_path;
        }
    }

    /// Append a dot-separated field to the source register's provenance.
    /// If source has no provenance, dest gets `None`.
    pub fn append_field(&mut self, dest: u8, src: u8, field: &str) {
        let new_path = self
            .paths
            .get(usize::from(src))
            .and_then(|p| p.as_ref())
            .map(|base| {
                let mut s = alloc::string::String::with_capacity(
                    base.len().saturating_add(1).saturating_add(field.len()),
                );
                s.push_str(base);
                s.push('.');
                s.push_str(field);
                Rc::from(s.as_str())
            });
        if let Some(slot) = self.paths.get_mut(usize::from(dest)) {
            *slot = new_path;
        }
    }

    /// Append a bracketed index `[_]` (wildcard) to the source register's provenance.
    pub fn append_wildcard(&mut self, dest: u8, src: u8) {
        let new_path = self
            .paths
            .get(usize::from(src))
            .and_then(|p| p.as_ref())
            .map(|base| {
                let mut s = alloc::string::String::with_capacity(base.len().saturating_add(3));
                s.push_str(base);
                s.push_str("[_]");
                Rc::from(s.as_str())
            });
        if let Some(slot) = self.paths.get_mut(usize::from(dest)) {
            *slot = new_path;
        }
    }

    /// Append a specific key in brackets to the source register's provenance.
    /// For string keys, uses dot notation: `base.key`.
    /// For non-string keys, uses bracket notation: `base[key]`.
    pub fn append_index(&mut self, dest: u8, src: u8, key: &Value) {
        let new_path = self
            .paths
            .get(usize::from(src))
            .and_then(|p| p.as_ref())
            .map(|base| {
                let mut s = alloc::string::String::with_capacity(base.len().saturating_add(16));
                s.push_str(base);
                match *key {
                    Value::String(ref k) => {
                        s.push('.');
                        s.push_str(k);
                    }
                    _ => {
                        use core::fmt::Write as _;
                        let _ = write!(s, "[{}]", key);
                    }
                }
                Rc::from(s.as_str())
            });
        if let Some(slot) = self.paths.get_mut(usize::from(dest)) {
            *slot = new_path;
        }
    }

    /// Append a specific key in brackets to a stored base path string, then set on dest register.
    /// Used by loop-next where the collection register's provenance has been saved as a string.
    pub fn append_index_to_stored_path(&mut self, dest: u8, base: &str, key: &Value) {
        let mut s = alloc::string::String::with_capacity(base.len().saturating_add(16));
        s.push_str(base);
        match *key {
            Value::String(ref k) => {
                s.push('.');
                s.push_str(k);
            }
            _ => {
                use core::fmt::Write as _;
                let _ = write!(s, "[{}]", key);
            }
        }
        if let Some(slot) = self.paths.get_mut(usize::from(dest)) {
            *slot = Some(Rc::from(s.as_str()));
        }
    }

    /// Take ownership of the paths vec (used during register save/restore).
    pub fn take_paths(&mut self) -> Vec<Option<Rc<str>>> {
        core::mem::take(&mut self.paths)
    }

    /// Restore paths (used during register save/restore).
    pub fn restore_paths(&mut self, paths: Vec<Option<Rc<str>>>) {
        self.paths = paths;
    }
}

// ── CausalityCapture: the main recording structure ───────────────────

/// Append-only event log for causality recording during evaluation.
///
/// All values are stored as Rc-bump clones (no deep copy, no sanitization).
/// Materialization is deferred to `materialize()`.
#[derive(Debug, Clone)]
pub struct CausalityCapture {
    /// Whether capture is active.
    enabled: bool,
    /// Flat event log.
    events: Vec<CausalEvent>,
    /// Flat value table (Rc-bump clones).
    values: Vec<Value>,
    /// Flat binding entry table.
    binding_entries: Vec<BindingEntry>,
    /// Per-condition snapshots (indexed by condition event index).
    condition_snapshots: Vec<Option<RawConditionSnapshot>>,
    /// Loop witness state keyed by result register.
    loop_witnesses: BTreeMap<u8, RawWitnessSnapshot>,
    /// Loop event ranges keyed by result register.
    loop_event_ranges: BTreeMap<u8, LoopEventRanges>,
    /// Comprehension witness state keyed by result register.
    comprehension_witnesses: BTreeMap<u8, RawWitnessSnapshot>,

    // ── Block management (replaces block_records / current_block_records) ──
    /// Indices of condition events that form the current block.
    current_block_condition_indices: Vec<u32>,
    /// Finalized block condition event indices accumulated for the current rule.
    finalized_block_indices: Vec<u32>,
    /// Block condition event indices produced by the most recent nested rule call.
    last_rule_block_indices: Vec<u32>,

    // ── Emission tracking ──
    /// Accumulated explanations: emission_key → list of block event index ranges.
    emissions: BTreeMap<Value, Vec<BlockRange>>,
    /// Stack of loop emission scopes. Each scope tracks emission keys produced
    /// during a loop's iterations so the loop's quantifier condition can be
    /// retroactively attached to those emissions.
    loop_emission_scopes: Vec<Vec<Value>>,

    // ── Call depth tracking ──
    /// How many nested rule/function calls deep we are. When > 0, emission
    /// creation is suppressed (conditions still accumulate so they can be
    /// inlined into the caller's block via `last_rule_block_indices`).
    call_depth: u32,

    // ── Rule tracking ──
    last_entrypoint_rule_type: Option<crate::rvm::program::RuleType>,
    last_explanation_result: Option<Value>,
}

/// A range of condition event indices representing one finalized block.
#[derive(Debug, Clone)]
struct BlockRange {
    start: u32,
    end: u32,
}

impl CausalityCapture {
    pub const fn new() -> Self {
        Self {
            enabled: false,
            events: Vec::new(),
            values: Vec::new(),
            binding_entries: Vec::new(),
            condition_snapshots: Vec::new(),
            loop_witnesses: BTreeMap::new(),
            loop_event_ranges: BTreeMap::new(),
            comprehension_witnesses: BTreeMap::new(),
            current_block_condition_indices: Vec::new(),
            finalized_block_indices: Vec::new(),
            last_rule_block_indices: Vec::new(),
            emissions: BTreeMap::new(),
            loop_emission_scopes: Vec::new(),
            call_depth: 0,
            last_entrypoint_rule_type: None,
            last_explanation_result: None,
        }
    }

    #[inline]
    pub const fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
        if enabled {
            self.clear();
        }
    }

    pub fn clear(&mut self) {
        self.events.clear();
        self.values.clear();
        self.binding_entries.clear();
        self.condition_snapshots.clear();
        self.loop_witnesses.clear();
        self.loop_event_ranges.clear();
        self.comprehension_witnesses.clear();
        self.current_block_condition_indices.clear();
        self.finalized_block_indices.clear();
        self.last_rule_block_indices.clear();
        self.emissions.clear();
        self.loop_emission_scopes.clear();
        self.call_depth = 0;
        self.last_entrypoint_rule_type = None;
        self.last_explanation_result = None;
    }

    // ── Value capture (Rc-bump) ──

    #[inline]
    pub fn snapshot_value(&mut self, value: &Value) -> ValueIdx {
        let idx = self.values.len();
        self.values.push(value.clone()); // Rc-bump, not deep copy
        u32::try_from(idx).unwrap_or(u32::MAX)
    }

    #[inline]
    pub fn snapshot_optional_value(&mut self, value: Option<&Value>) -> Option<ValueIdx> {
        value.map(|v| self.snapshot_value(v))
    }

    // ── Binding capture ──

    /// Capture a set of bindings. Returns (start, end) indices.
    pub fn snapshot_bindings(
        &mut self,
        binding_infos: &[crate::rvm::program::ExplanationBindingInfo],
        registers: &[Value],
        provenance: &ProvenanceTracker,
    ) -> (BindingIdx, BindingIdx) {
        let start = u32::try_from(self.binding_entries.len()).unwrap_or(u32::MAX);
        for info in binding_infos {
            let value = registers
                .get(usize::from(info.register))
                .cloned()
                .unwrap_or(Value::Undefined);
            if value != Value::Undefined {
                let value_idx = self.snapshot_value(&value);
                let source_path = provenance.get(info.register).cloned();
                self.binding_entries.push(BindingEntry {
                    name: Rc::from(info.name.as_str()),
                    value_idx,
                    source_path,
                });
            }
        }
        let end = u32::try_from(self.binding_entries.len()).unwrap_or(u32::MAX);
        (start, end)
    }

    // ── Event recording ──

    /// Record a condition evaluation event.
    /// Returns the event index.
    #[allow(clippy::too_many_arguments)]
    pub fn record_condition(
        &mut self,
        pc: u32,
        passed: bool,
        actual: Option<ValueIdx>,
        expected: Option<ValueIdx>,
        bindings_start: BindingIdx,
        bindings_end: BindingIdx,
        snapshot: Option<RawConditionSnapshot>,
    ) -> u32 {
        let event_idx = u32::try_from(self.events.len()).unwrap_or(u32::MAX);
        self.events.push(CausalEvent {
            pc,
            kind: CausalEventKind::Condition {
                passed,
                bindings_start,
                bindings_end,
                actual,
                expected,
            },
        });
        self.condition_snapshots.push(snapshot);
        event_idx
    }

    /// Push a condition event index into the current block.
    pub fn push_current_block_condition(&mut self, event_idx: u32) {
        self.current_block_condition_indices.push(event_idx);
    }

    /// Replace the current block's conditions (for primary-only mode).
    pub fn replace_current_block_conditions(&mut self, event_indices: Vec<u32>) {
        self.current_block_condition_indices = event_indices;
    }

    /// Finalize the current block: move current conditions into finalized set.
    /// Returns the condition event indices that were finalized.
    pub fn finalize_current_block(&mut self) -> Vec<u32> {
        if self.current_block_condition_indices.is_empty() {
            return Vec::new();
        }
        let indices = core::mem::take(&mut self.current_block_condition_indices);
        self.finalized_block_indices.extend_from_slice(&indices);
        indices
    }

    /// Snapshot the latest (current) block's conditions to an emission key.
    ///
    /// Finalize the current condition block and create an emission entry for
    /// the given key. Unlike `snapshot_all_blocks`, this does NOT suppress
    /// emissions at `call_depth > 0` because intermediate results (Move,
    /// SetAdd, ObjectSet) inside nested rules form the supporting explanation
    /// chain that callers need.
    pub fn snapshot_latest_block(&mut self, key: Value) {
        let indices = self.finalize_current_block();
        if let (Some(&start), Some(&last)) = (indices.first(), indices.last()) {
            let end = last.saturating_add(1);
            // Track this emission key in the innermost active loop scope.
            if let Some(scope) = self.loop_emission_scopes.last_mut() {
                scope.push(key.clone());
            }
            self.emissions
                .entry(key)
                .or_default()
                .push(BlockRange { start, end });
        }
    }

    /// Begin a new loop emission scope.
    pub fn push_loop_emission_scope(&mut self) {
        self.loop_emission_scopes.push(Vec::new());
    }

    /// End the current loop emission scope, returning the emission keys
    /// produced during the loop's iterations.
    pub fn pop_loop_emission_scope(&mut self) -> Vec<Value> {
        self.loop_emission_scopes.pop().unwrap_or_default()
    }

    /// Append a condition event (e.g. a loop quantifier) to every emission
    /// identified by `keys`.
    pub fn append_condition_to_emissions(&mut self, event_idx: u32, keys: &[Value]) {
        let range = BlockRange {
            start: event_idx,
            end: event_idx.saturating_add(1),
        };
        for key in keys {
            if let Some(ranges) = self.emissions.get_mut(key) {
                ranges.push(range.clone());
            }
        }
    }

    /// Increment call depth (entering a nested rule/function call).
    pub const fn increment_call_depth(&mut self) {
        self.call_depth = self.call_depth.saturating_add(1);
    }

    /// Decrement call depth (leaving a nested rule/function call).
    pub const fn decrement_call_depth(&mut self) {
        self.call_depth = self.call_depth.saturating_sub(1);
    }

    /// Check if currently inside a nested rule/function call.
    pub const fn is_in_nested_call(&self) -> bool {
        self.call_depth > 0
    }

    /// Snapshot all finalized blocks to an emission key.
    ///
    /// Like `snapshot_latest_block`, emission creation is suppressed when
    /// inside a nested call.
    pub fn snapshot_all_blocks(&mut self, key: Value) {
        let _ = self.finalize_current_block();
        if !self.finalized_block_indices.is_empty() && self.call_depth == 0 {
            let indices = &self.finalized_block_indices;
            let start = *indices.first().unwrap_or(&0);
            let end = indices.last().unwrap_or(&0).saturating_add(1);
            self.emissions
                .entry(key)
                .or_default()
                .push(BlockRange { start, end });
        }
    }

    pub fn set_last_rule_block_indices(&mut self, indices: Vec<u32>) {
        self.last_rule_block_indices = indices;
    }

    pub fn take_last_rule_block_indices(&mut self) -> Vec<u32> {
        core::mem::take(&mut self.last_rule_block_indices)
    }

    pub fn last_rule_block_indices(&self) -> &[u32] {
        &self.last_rule_block_indices
    }

    /// Insert loop summary witness state.
    pub fn insert_loop_witness(
        &mut self,
        result_reg: u8,
        witness: RawWitnessSnapshot,
        event_ranges: LoopEventRanges,
    ) {
        self.loop_witnesses.insert(result_reg, witness);
        self.loop_event_ranges.insert(result_reg, event_ranges);
    }

    /// Get a reference to a loop witness.
    pub fn loop_witness(&self, result_reg: u8) -> Option<&RawWitnessSnapshot> {
        self.loop_witnesses.get(&result_reg)
    }

    /// Get any loop witness (last inserted, i.e. highest register key).
    /// Used by comprehension end to adopt the inner loop's iteration data.
    pub fn last_loop_witness(&self) -> Option<&RawWitnessSnapshot> {
        self.loop_witnesses.values().next_back()
    }

    /// Insert a comprehension witness.
    pub fn insert_comprehension_witness(&mut self, result_reg: u8, witness: RawWitnessSnapshot) {
        self.comprehension_witnesses.insert(result_reg, witness);
    }

    /// Get a reference to a comprehension witness.
    pub fn comprehension_witness(&self, result_reg: u8) -> Option<&RawWitnessSnapshot> {
        self.comprehension_witnesses.get(&result_reg)
    }

    pub const fn set_last_entrypoint_rule_type(
        &mut self,
        rule_type: Option<crate::rvm::program::RuleType>,
    ) {
        self.last_entrypoint_rule_type = rule_type;
    }

    pub fn set_last_explanation_result(&mut self, result: Option<Value>) {
        self.last_explanation_result = result;
    }

    /// Number of events currently recorded.
    #[allow(clippy::as_conversions)]
    pub const fn event_count(&self) -> u32 {
        self.events.len() as u32
    }

    /// Get the value at the given index.
    pub fn get_value(&self, idx: ValueIdx) -> &Value {
        self.values
            .get(usize::try_from(idx).unwrap_or(usize::MAX))
            .unwrap_or(&Value::Undefined)
    }

    /// Get the finalized block indices.
    pub fn finalized_block_indices(&self) -> &[u32] {
        &self.finalized_block_indices
    }

    pub fn clear_finalized_blocks(&mut self) {
        self.finalized_block_indices.clear();
    }

    pub fn clear_current_block(&mut self) {
        self.current_block_condition_indices.clear();
    }

    /// Truncate finalized block indices to the given length.
    pub fn truncate_finalized_blocks(&mut self, len: usize) {
        self.finalized_block_indices.truncate(len);
    }

    pub const fn finalized_block_len(&self) -> usize {
        self.finalized_block_indices.len()
    }

    pub fn current_block_condition_indices(&self) -> &[u32] {
        &self.current_block_condition_indices
    }

    /// Get a reference to the event log.
    pub fn events_ref(&self) -> &[CausalEvent] {
        &self.events
    }

    /// Get loop event range indices for the given register, selecting passing or failing.
    /// Returns the condition event indices from the appropriate iteration range.
    pub fn loop_event_range_indices(&self, result_reg: u8, passed: bool) -> Vec<u32> {
        let Some(ranges) = self.loop_event_ranges.get(&result_reg) else {
            return Vec::new();
        };
        let (start, end) = if passed {
            (ranges.passing_start, ranges.passing_end)
        } else {
            // Failing fallback to passing if no failing range exists
            let (s, e) = (ranges.failing_start, ranges.failing_end);
            if s.is_some() && e.is_some() {
                (s, e)
            } else {
                (ranges.passing_start, ranges.passing_end)
            }
        };
        match (start, end) {
            (Some(s), Some(e)) => {
                // Return all finalized_block_indices that fall within this range
                self.finalized_block_indices
                    .iter()
                    .copied()
                    .filter(|&idx| idx >= s && idx < e)
                    .collect()
            }
            _ => Vec::new(),
        }
    }
}

// ── Materialization ──────────────────────────────────────────────────

impl CausalityCapture {
    /// Materialize the captured event log into the public explanation output.
    ///
    /// This is the only place where:
    /// - Source locations are resolved from instruction spans
    /// - Values are sanitized (redaction)
    /// - Rich `ExplanationRecord` structs are constructed
    pub fn materialize(
        &self,
        settings: &ExplanationSettings,
        program: &crate::rvm::program::Program,
    ) -> BTreeMap<Value, Vec<ExplanationRecord>> {
        let mut result: BTreeMap<Value, Vec<ExplanationRecord>> = BTreeMap::new();

        for (key, block_ranges) in &self.emissions {
            let records: Vec<ExplanationRecord> = block_ranges
                .iter()
                .flat_map(|range| self.materialize_block_range(range, settings, program))
                .collect();
            if !records.is_empty() {
                result.entry(key.clone()).or_default().extend(records);
            }
        }

        let result = normalize_explanations(result);

        match self.last_entrypoint_rule_type {
            Some(crate::rvm::program::RuleType::Complete) => {
                if let Some(ref last_result) = self.last_explanation_result {
                    return filter_explanations_for_complete_rule(result, last_result);
                }
            }
            Some(crate::rvm::program::RuleType::PartialSet) => {
                if let Some(Value::Set(ref members)) = self.last_explanation_result {
                    return filter_explanations_for_partial_set_rule(result, members);
                }
            }
            Some(crate::rvm::program::RuleType::PartialObject) => {
                if let Some(Value::Object(ref obj)) = self.last_explanation_result {
                    return filter_explanations_for_partial_object_rule(result, obj);
                }
            }
            None => {}
        }

        result
    }

    /// Materialize a `CausalityReport` with rich output types.
    ///
    /// Each emission includes the emitted value, its conditions, and
    /// per-binding `evaluation_index` linking each binding to the condition
    /// that first introduced it.
    pub fn materialize_report(
        &self,
        settings: &ExplanationSettings,
        program: &crate::rvm::program::Program,
    ) -> CausalityReport {
        self.materialize(settings, program).into()
    }

    fn materialize_block_range(
        &self,
        range: &BlockRange,
        settings: &ExplanationSettings,
        program: &crate::rvm::program::Program,
    ) -> Vec<ExplanationRecord> {
        let mut records = Vec::new();
        for idx in range.start..range.end {
            if let Some(record) = self.materialize_condition_event(idx, settings, program) {
                records.push(record);
            }
        }
        records
    }

    fn materialize_condition_event(
        &self,
        event_idx: u32,
        settings: &ExplanationSettings,
        program: &crate::rvm::program::Program,
    ) -> Option<ExplanationRecord> {
        // Find the corresponding condition in finalized_block_indices
        // that maps to this event index.
        let condition_event_idx = self
            .finalized_block_indices
            .iter()
            .position(|&i| i == event_idx)
            .map(|_| event_idx)
            .or(Some(event_idx))?;

        let event = self
            .events
            .get(usize::try_from(condition_event_idx).ok()?)?;
        let (passed, bindings_start, bindings_end) = match event.kind {
            CausalEventKind::Condition {
                passed,
                bindings_start,
                bindings_end,
                ..
            } => (passed, bindings_start, bindings_end),
            _ => return None,
        };

        let outcome = if passed {
            ExplanationOutcome::Success
        } else {
            ExplanationOutcome::Failure
        };

        // Resolve source location from program
        let location = program
            .instruction_spans
            .get(usize::try_from(event.pc).unwrap_or(usize::MAX))
            .and_then(|span| span.as_ref())
            .map(|span| SourceLocation {
                file: span
                    .get_source_name(&program.sources)
                    .unwrap_or_default()
                    .into(),
                row: u32::try_from(span.line).unwrap_or(u32::MAX),
                col: u32::try_from(span.column).unwrap_or(u32::MAX),
            })
            .unwrap_or(SourceLocation {
                file: "".into(),
                row: 0,
                col: 0,
            });

        // Resolve text and evaluation from instruction explanation metadata
        let metadata = program
            .instruction_explanations
            .get(usize::try_from(event.pc).unwrap_or(usize::MAX))
            .and_then(|m| m.as_ref());

        let text: Rc<str> = metadata
            .map(|m| Rc::from(m.text.as_str()))
            .unwrap_or_else(|| "".into());

        // Materialize condition snapshot into ConditionEvaluation
        let condition_snapshot_idx = self
            .events
            .iter()
            .take(
                usize::try_from(condition_event_idx)
                    .unwrap_or(usize::MAX)
                    .saturating_add(1),
            )
            .filter(|e| matches!(e.kind, CausalEventKind::Condition { .. }))
            .count()
            .checked_sub(1);

        let evaluation = condition_snapshot_idx
            .and_then(|idx| self.condition_snapshots.get(idx))
            .and_then(|s| s.as_ref())
            .map(|snapshot| self.materialize_condition_snapshot(snapshot, settings));

        // Materialize bindings with sanitization
        let bindings = self.materialize_bindings(bindings_start, bindings_end, settings);

        Some(ExplanationRecord {
            outcome,
            location,
            text,
            evaluation,
            bindings,
        })
    }

    fn materialize_condition_snapshot(
        &self,
        snapshot: &RawConditionSnapshot,
        settings: &ExplanationSettings,
    ) -> ConditionEvaluation {
        let (actual_value, actual_value_redacted) = snapshot
            .actual
            .map(|idx| {
                sanitize_condition_value(
                    self.get_value(idx),
                    settings,
                    snapshot.actual_hint.as_deref(),
                )
            })
            .map_or((None, false), |(v, r)| (Some(v), r));

        let (expected_value, expected_value_redacted) = snapshot
            .expected
            .map(|idx| {
                sanitize_condition_value(
                    self.get_value(idx),
                    settings,
                    snapshot.expected_hint.as_deref(),
                )
            })
            .map_or((None, false), |(v, r)| (Some(v), r));

        let witness = snapshot
            .witness
            .as_ref()
            .map(|w| self.materialize_witness_snapshot(w, settings));

        ConditionEvaluation {
            kind: snapshot.kind,
            operator: snapshot.operator,
            actual_value,
            expected_value,
            actual_path: snapshot.actual_path.clone(),
            expected_path: snapshot.expected_path.clone(),
            actual_value_redacted,
            expected_value_redacted,
            witness,
        }
    }

    fn materialize_witness_snapshot(
        &self,
        witness: &RawWitnessSnapshot,
        settings: &ExplanationSettings,
    ) -> ConditionEvaluationWitness {
        let (sample_key, sample_key_redacted) = witness
            .sample_key
            .map(|idx| {
                sanitize_condition_value(
                    self.get_value(idx),
                    settings,
                    witness.sample_key_hint.as_deref(),
                )
            })
            .map_or((None, false), |(v, r)| (Some(v), r));

        let (sample_value, sample_value_redacted) = witness
            .sample_value
            .map(|idx| {
                sanitize_condition_value(
                    self.get_value(idx),
                    settings,
                    witness.sample_value_hint.as_deref(),
                )
            })
            .map_or((None, false), |(v, r)| (Some(v), r));

        let passing_iteration = witness
            .passing_iteration
            .as_ref()
            .map(|iter| self.materialize_iteration_snapshot(iter, settings));
        let failing_iteration = witness
            .failing_iteration
            .as_ref()
            .map(|iter| self.materialize_iteration_snapshot(iter, settings));

        ConditionEvaluationWitness {
            collection_path: witness.collection_path.clone(),
            iteration_count: witness.iteration_count,
            success_count: witness.success_count,
            yield_count: witness.yield_count,
            condition_texts: witness
                .condition_texts
                .iter()
                .map(|t| Rc::from(t.as_str()))
                .collect(),
            sample_key,
            sample_value,
            sample_key_redacted,
            sample_value_redacted,
            passing_iteration,
            failing_iteration,
        }
    }

    fn materialize_iteration_snapshot(
        &self,
        iter: &RawIterationSnapshot,
        settings: &ExplanationSettings,
    ) -> ConditionIterationWitness {
        let (sample_key, sample_key_redacted) = iter
            .sample_key
            .map(|idx| {
                sanitize_condition_value(
                    self.get_value(idx),
                    settings,
                    iter.sample_key_hint.as_deref(),
                )
            })
            .map_or((None, false), |(v, r)| (Some(v), r));

        let (sample_value, sample_value_redacted) = iter
            .sample_value
            .map(|idx| {
                sanitize_condition_value(
                    self.get_value(idx),
                    settings,
                    iter.sample_value_hint.as_deref(),
                )
            })
            .map_or((None, false), |(v, r)| (Some(v), r));

        let bindings = self.materialize_bindings(iter.bindings_start, iter.bindings_end, settings);

        ConditionIterationWitness {
            sample_key,
            sample_value,
            bindings,
            sample_key_redacted,
            sample_value_redacted,
        }
    }

    fn materialize_bindings(
        &self,
        start: BindingIdx,
        end: BindingIdx,
        settings: &ExplanationSettings,
    ) -> Vec<ExplanationBinding> {
        let start_idx = usize::try_from(start).unwrap_or(usize::MAX);
        let end_idx = usize::try_from(end).unwrap_or(usize::MAX);
        self.binding_entries
            .get(start_idx..end_idx)
            .unwrap_or(&[])
            .iter()
            .map(|entry| {
                let value = self.get_value(entry.value_idx);
                let mut binding = sanitize_explanation_binding(&entry.name, value, settings);
                binding.source_path = entry.source_path.clone();
                binding
            })
            .collect()
    }
}

// ── Sanitization (deferred to materialization) ───────────────────────

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

pub fn sanitize_explanation_binding(
    name: &str,
    value: &Value,
    settings: &ExplanationSettings,
) -> ExplanationBinding {
    let (sanitized_value, redacted) =
        sanitize_explanation_value(value, settings.value_mode, Some(name));
    ExplanationBinding {
        name: Rc::from(name),
        value: sanitized_value,
        source_path: None,
        redacted,
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
            let sanitized_items: Vec<_> = items
                .iter()
                .map(|item| {
                    let (sanitized, item_redacted) =
                        sanitize_explanation_value(item, value_mode, None);
                    redacted |= item_redacted;
                    sanitized
                })
                .collect();
            (Value::from_array(sanitized_items), redacted)
        }
        Value::Set(ref items) => {
            let mut redacted = false;
            let sanitized_items: alloc::collections::BTreeSet<_> = items
                .iter()
                .map(|item| {
                    let (sanitized, item_redacted) =
                        sanitize_explanation_value(item, value_mode, None);
                    redacted |= item_redacted;
                    sanitized
                })
                .collect();
            (Value::from_set(sanitized_items), redacted)
        }
        Value::Object(ref fields) => {
            let mut redacted = false;
            let sanitized_fields: BTreeMap<_, _> = fields
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
                .collect();
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

// ── Normalization ────────────────────────────────────────────────────

use alloc::collections::BTreeSet;

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
    let quantifier_text_sets: Vec<(usize, BTreeSet<Rc<str>>)> = records
        .iter()
        .enumerate()
        .filter_map(|(idx, record)| quantifier_condition_texts(record).map(|texts| (idx, texts)))
        .collect();

    records
        .iter()
        .enumerate()
        .filter_map(|(idx, record)| {
            let keep_record = quantifier_condition_texts(record).map_or_else(
                || {
                    // Keep records that carry concrete evaluation data (e.g. comparison
                    // with actual_value/expected_value) even when a co-located quantifier
                    // lists the same text in its condition_texts. The quantifier provides
                    // iteration context; the inner record provides discriminating detail.
                    let has_evaluation_detail = record
                        .evaluation
                        .as_ref()
                        .is_some_and(|e| e.actual_value.is_some());
                    has_evaluation_detail
                        || !quantifier_text_sets.iter().any(|entry| {
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
    let successful_keys: BTreeSet<ConditionDisplayKey> = records
        .iter()
        .filter(|record| record.outcome == ExplanationOutcome::Success)
        .map(|record| ConditionDisplayKey {
            file: record.location.file.clone(),
            row: record.location.row,
            col: record.location.col,
            text: record.text.clone(),
        })
        .collect();

    let records: Vec<_> = records
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

/// Filter explanations for a partial set rule.
///
/// Only keep emissions whose key is a member of the result set.
/// Emissions from helper functions (whose keys are intermediate values
/// not in the final set) are discarded.
#[allow(clippy::pattern_type_mismatch)]
pub fn filter_explanations_for_partial_set_rule(
    explanations: BTreeMap<Value, Vec<ExplanationRecord>>,
    members: &BTreeSet<Value>,
) -> BTreeMap<Value, Vec<ExplanationRecord>> {
    explanations
        .into_iter()
        .filter(|(key, _)| members.contains(key))
        .collect()
}

/// Filter explanations for a partial object rule.
///
/// Only keep emissions whose key is a value in the result object.
/// Partial object emissions use the assigned value (not the object key)
/// as their emission key.
#[allow(clippy::pattern_type_mismatch)]
pub fn filter_explanations_for_partial_object_rule(
    explanations: BTreeMap<Value, Vec<ExplanationRecord>>,
    obj: &BTreeMap<Value, Value>,
) -> BTreeMap<Value, Vec<ExplanationRecord>> {
    explanations
        .into_iter()
        .filter(|(key, _)| obj.values().any(|v| v == key))
        .collect()
}
