//! `regorus-lift`: lift the kernel-enforceable subset of a Regorus policy into a
//! fixed enforcement config.
//!
//! This crate consumes the **hardened partial-evaluation output** of a Rego
//! policy ([`regorus::causality_report::PartialEvalResult`]) and *lifts* only the
//! sound, kernel-enforceable subset of its constraints into a compact
//! [`EnforcerConfig`]. Everything that is not provably safe to enforce is
//! rejected (with a reason) and must remain a user-space RVM decision.
//!
//! # Status
//! Phase 0 — pure user-space, no kernel. Supports the MVP subset:
//! conjunctions of `==` atoms over kernel-observable scalar input fields. The
//! [`sim`] module provides a faithful user-space simulator so the lift can be
//! conformance-tested against full RVM evaluation with **no over-permission**.
//!
//! The design contract this relies on (provided by the hardened PE):
//! a residual is only safe to lift when, locally, its disjunct outcome is
//! [`Soundness::Sound`] and implies *allow*, and every condition is an
//! [`Lowerability::Atom`] whose `input_path` binds to an observable field.

use std::collections::BTreeMap;

use regorus::causality_report::{
    Lowerability, PartialEvalResult, ResidualCondition, Soundness,
};
use regorus::evaluation_trace::PeUnsoundReason;
use regorus::Value;

pub mod ir;
pub mod schema;
pub mod sim;

pub use ir::{Clause, EnforcerConfig, EqAtom, LiftScalar, Verdict};
pub use schema::{ContextSchema, FieldType};

/// Why a policy/disjunct/condition could not be lifted into the enforcer config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RejectReason {
    /// The PE result is structurally unsound to enforce: a result-level unsound
    /// reason that is *not* attributable to a droppable disjunct condition
    /// (e.g. a deny rule or unknown-fold that may corrupt the residual DNF).
    /// All lifting is blocked.
    ResultUnsound(PeUnsoundReason),
    /// A disjunct's outcome is not [`Soundness::Sound`].
    DisjunctUnsound,
    /// A disjunct does not imply `allow` (its outcome value is not `true`).
    DisjunctNotAllow,
    /// A condition is not an [`Lowerability::Atom`].
    ConditionNotAtom,
    /// A condition is not sound.
    ConditionUnsound,
    /// The operator is outside the Phase-0 supported set (`==`).
    UnsupportedOperator(String),
    /// A condition is missing its `input_path`.
    MissingInputPath,
    /// The `input_path` is not bound to an observable kernel field.
    UnboundField(String),
    /// The condition value could not be represented as a lowerable scalar.
    UnencodableValue,
    /// The PE result carried unknown-input dependencies that were not lifted,
    /// so the enforced subset would be an unsound under-approximation of the
    /// schema. Reported so callers can decide to keep the policy in user space.
    UnliftedDependency(String),
}

/// A single rejected element with context for diagnostics/audit.
#[derive(Debug, Clone)]
pub struct Rejection {
    pub reason: RejectReason,
    /// Originating rule, if known (`ResidualCondition::source_rule`).
    pub source_rule: Option<String>,
}

/// Output of [`lift`].
#[derive(Debug, Clone)]
pub struct LiftResult {
    /// The enforcer config covering the lifted (allow) subset. `None` when
    /// nothing could be safely lifted.
    pub config: Option<EnforcerConfig>,
    /// Everything that was rejected and why.
    pub rejections: Vec<Rejection>,
}

impl LiftResult {
    /// True when nothing was rejected — the enforcer config fully covers the
    /// policy's allow surface (modulo deny/undecided handling).
    pub fn is_complete(&self) -> bool {
        self.rejections.is_empty()
    }
}

fn value_is_true(v: &Value) -> bool {
    matches!(serde_json::to_value(v), Ok(serde_json::Value::Bool(true)))
}

fn is_sound(s: &Soundness) -> bool {
    matches!(s, Soundness::Sound)
}

fn soundness_reason(s: &Soundness) -> Option<PeUnsoundReason> {
    match s {
        Soundness::Sound => None,
        Soundness::Unsound { reason } => Some(*reason),
    }
}

/// Gather the unsound reasons attached to residual conditions (recursing into
/// negated sub-conditions). These are the *local* lowering failures that the
/// per-disjunct/per-condition gates will drop, so they don't make the whole
/// result structurally unsound.
fn collect_condition_reasons(conds: &[ResidualCondition], out: &mut Vec<PeUnsoundReason>) {
    for c in conds {
        if let Some(r) = soundness_reason(&c.soundness) {
            if !out.contains(&r) {
                out.push(r);
            }
        }
        collect_condition_reasons(&c.negated_conditions, out);
    }
}

/// The result-level unsound reasons that are *not* explained by a droppable
/// disjunct condition. Their presence means the residual DNF itself may not
/// faithfully represent the allow surface (e.g. an unsoundly folded deny rule),
/// so lifting any subset could over-permit.
fn structural_reasons(pe: &PartialEvalResult) -> Vec<PeUnsoundReason> {
    let mut local = Vec::new();
    for disjunct in &pe.residual_queries {
        collect_condition_reasons(disjunct, &mut local);
    }

    let mut result_reasons = pe.unsound_reasons.clone();
    if let Some(r) = soundness_reason(&pe.soundness) {
        if !result_reasons.contains(&r) {
            result_reasons.push(r);
        }
    }

    result_reasons
        .into_iter()
        .filter(|r| !local.contains(r))
        .collect()
}

/// Lift the sound, kernel-enforceable subset of `pe` into an [`EnforcerConfig`],
/// binding input paths against `schema`.
///
/// The function never produces an over-permissive config: any disjunct or
/// condition that cannot be *proved* safe (via the hardened PE soundness tags
/// and the schema binding) is rejected, not guessed.
pub fn lift(pe: &PartialEvalResult, schema: &ContextSchema) -> LiftResult {
    let mut rejections = Vec::new();

    // Structural soundness gate. A result-level unsound reason is tolerated only
    // when it is also attached to a residual condition (a disjunct we will drop)
    // — that is a *local* lowering failure. Any other result-level unsound
    // reason, or an unlifted unknown-input dependency, may corrupt the residual
    // DNF, so we refuse to lift anything (fail closed).
    let structural = structural_reasons(pe);
    let blocked = !structural.is_empty() || !pe.depends_on_unknown.is_empty();

    for reason in &structural {
        rejections.push(Rejection {
            reason: RejectReason::ResultUnsound(*reason),
            source_rule: None,
        });
    }
    // Surface unlifted unknown-input dependencies: enforcing a subset while the
    // decision also depended on an unobservable/unlifted input is unsound for
    // the schema gate, so the caller is told (and lifting is blocked).
    for dep in &pe.depends_on_unknown {
        rejections.push(Rejection {
            reason: RejectReason::UnliftedDependency(dep.clone()),
            source_rule: None,
        });
    }
    if blocked {
        return LiftResult {
            config: None,
            rejections,
        };
    }

    // Fully-determined result with no residual: static verdict.
    if pe.residual_queries.is_empty() {
        let verdict = if value_is_true(&pe.result) {
            Verdict::Allow
        } else {
            Verdict::Deny
        };
        return LiftResult {
            config: Some(EnforcerConfig::with_static(verdict)),
            rejections,
        };
    }

    let mut fields: BTreeMap<String, FieldType> = BTreeMap::new();
    let mut clauses: Vec<Clause> = Vec::new();

    for (i, disjunct) in pe.residual_queries.iter().enumerate() {
        // Per-disjunct outcome gate (aligned by index with residual_queries).
        let outcome = pe.residual_outcomes.get(i);
        match outcome {
            Some(o) if !is_sound(&o.soundness) => {
                rejections.push(Rejection {
                    reason: RejectReason::DisjunctUnsound,
                    source_rule: disjunct_source_rule(disjunct),
                });
                continue;
            }
            Some(o) if !value_is_true(&o.result) => {
                rejections.push(Rejection {
                    reason: RejectReason::DisjunctNotAllow,
                    source_rule: disjunct_source_rule(disjunct),
                });
                continue;
            }
            None => {
                // No outcome metadata — cannot prove this disjunct implies allow.
                rejections.push(Rejection {
                    reason: RejectReason::DisjunctNotAllow,
                    source_rule: disjunct_source_rule(disjunct),
                });
                continue;
            }
            _ => {}
        }

        match lift_disjunct(disjunct, schema, &mut fields) {
            Ok(clause) => clauses.push(clause),
            Err(rej) => rejections.push(rej),
        }
    }

    let config = if clauses.is_empty() {
        None
    } else {
        Some(EnforcerConfig::new(fields, clauses))
    };

    LiftResult { config, rejections }
}

fn lift_disjunct(
    disjunct: &[ResidualCondition],
    schema: &ContextSchema,
    fields: &mut BTreeMap<String, FieldType>,
) -> Result<Clause, Rejection> {
    let mut atoms = Vec::new();
    for cond in disjunct {
        let atom = lift_condition(cond, schema)?;
        fields.insert(atom.input_path.clone(), atom.scalar.field_type());
        atoms.push(atom);
    }
    Ok(Clause { atoms })
}

fn lift_condition(
    cond: &ResidualCondition,
    schema: &ContextSchema,
) -> Result<EqAtom, Rejection> {
    let src = cond.source_rule.clone();
    let reject = |reason| Rejection {
        reason,
        source_rule: src.clone(),
    };

    if !matches!(cond.lowerable, Lowerability::Atom) {
        return Err(reject(RejectReason::ConditionNotAtom));
    }
    if !is_sound(&cond.soundness) {
        return Err(reject(RejectReason::ConditionUnsound));
    }

    // Phase 0 supports equality only.
    match cond.operator.as_deref() {
        Some("==") => {}
        Some(op) => return Err(reject(RejectReason::UnsupportedOperator(op.to_string()))),
        None => return Err(reject(RejectReason::UnsupportedOperator("<none>".to_string()))),
    }

    let input_path = cond
        .input_path
        .clone()
        .ok_or_else(|| reject(RejectReason::MissingInputPath))?;

    let field_type = schema
        .field_type(&input_path)
        .ok_or_else(|| reject(RejectReason::UnboundField(input_path.clone())))?;

    let value = cond
        .value
        .as_ref()
        .ok_or_else(|| reject(RejectReason::UnencodableValue))?;
    let scalar =
        LiftScalar::from_value(value).ok_or_else(|| reject(RejectReason::UnencodableValue))?;

    if scalar.field_type() != field_type {
        return Err(reject(RejectReason::UnboundField(input_path)));
    }

    Ok(EqAtom { input_path, scalar })
}

fn disjunct_source_rule(disjunct: &[ResidualCondition]) -> Option<String> {
    disjunct.iter().find_map(|c| c.source_rule.clone())
}
