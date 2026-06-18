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

use regorus::causality_report::{Lowerability, PartialEvalResult, ResidualCondition, Soundness};
use regorus::evaluation_trace::PeUnsoundReason;
use regorus::Value;

pub mod ir;
pub mod schema;
pub mod sim;

pub use ir::{Atom, Clause, EnforcerConfig, EqAtom, LiftScalar, Verdict};
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
    /// The operator is outside the supported lift set.
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
        insert_atom_fields(&atom, schema, fields);
        atoms.push(atom);
    }
    Ok(Clause { atoms })
}

fn insert_atom_fields(
    atom: &Atom,
    schema: &ContextSchema,
    fields: &mut BTreeMap<String, FieldType>,
) {
    match atom {
        Atom::FieldCmp(atom) => {
            if let Some(field_type) = schema.field_type(&atom.left_path) {
                fields.insert(atom.left_path.clone(), field_type);
            }
            if let Some(field_type) = schema.field_type(&atom.right_path) {
                fields.insert(atom.right_path.clone(), field_type);
            }
        }
        _ => {
            if let Some(field_type) = schema.field_type(atom.input_path()) {
                fields.insert(atom.input_path().to_string(), field_type);
            }
        }
    }
}

fn lift_condition(cond: &ResidualCondition, schema: &ContextSchema) -> Result<Atom, Rejection> {
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

    let input_path = cond
        .input_path
        .clone()
        .ok_or_else(|| reject(RejectReason::MissingInputPath))?;

    let field_type = schema
        .field_type(&input_path)
        .ok_or_else(|| reject(RejectReason::UnboundField(input_path.clone())))?;

    if let Some(right_path) = cond.right_input_path.clone() {
        let right_type = schema
            .field_type(&right_path)
            .ok_or_else(|| reject(RejectReason::UnboundField(right_path.clone())))?;
        let op = field_cmp_op(cond.operator.as_deref())
            .ok_or_else(|| reject(RejectReason::UnsupportedOperator("<none>".to_string())))?;
        if !field_types_compatible(field_type, right_type, op) {
            return Err(reject(RejectReason::UnboundField(input_path)));
        }
        return Ok(Atom::FieldCmp(ir::FieldCmpAtom {
            left_path: input_path,
            op,
            right_path,
        }));
    }

    match cond.operator.as_deref() {
        None if cond.kind == "exists" => Ok(Atom::Exists(ir::ExistsAtom { input_path })),
        Some("==") => {
            let scalar = scalar_value(cond, &reject)?;
            if scalar.field_type() != field_type
                && !(field_type == FieldType::Ip && scalar.field_type() == FieldType::Str)
            {
                return Err(reject(RejectReason::UnboundField(input_path)));
            }
            Ok(Atom::Eq(EqAtom { input_path, scalar }))
        }
        Some("!=") => {
            let scalar = scalar_value(cond, &reject)?;
            if scalar.field_type() != field_type {
                return Err(reject(RejectReason::UnboundField(input_path)));
            }
            Ok(Atom::Cmp(ir::CmpAtom {
                input_path,
                op: ir::CmpOp::Ne,
                scalar,
                missing_matches: cond.kind == "negation_complement",
            }))
        }
        Some("<" | "<=" | ">" | ">=") => {
            if !matches!(field_type, FieldType::Int | FieldType::Uint) {
                return Err(reject(RejectReason::UnboundField(input_path)));
            }
            let scalar = scalar_value(cond, &reject)?;
            if !matches!(scalar, LiftScalar::Int(_) | LiftScalar::Uint(_)) {
                return Err(reject(RejectReason::UnencodableValue));
            }
            let op = match cond.operator.as_deref() {
                Some("<") => ir::CmpOp::Lt,
                Some("<=") => ir::CmpOp::Le,
                Some(">") => ir::CmpOp::Gt,
                Some(">=") => ir::CmpOp::Ge,
                _ => {
                    return Err(reject(RejectReason::UnsupportedOperator(
                        "<none>".to_string(),
                    )))
                }
            };
            Ok(Atom::Cmp(ir::CmpAtom {
                input_path,
                op,
                scalar,
                missing_matches: cond.kind == "negation_complement",
            }))
        }
        Some("in") => {
            let values = membership_values(cond, &reject)?;
            Ok(Atom::Membership(ir::MembershipAtom { input_path, values }))
        }
        Some("bitmask_any_set" | "bitmask_any_clear" | "bitmask_all_set" | "bitmask_all_clear") => {
            if !matches!(field_type, FieldType::Int | FieldType::Uint) {
                return Err(reject(RejectReason::UnboundField(input_path)));
            }
            let mask = u64_value(cond, &reject)?;
            let test = match cond.operator.as_deref() {
                Some("bitmask_any_set") => ir::BitmaskTest::AnySet,
                Some("bitmask_any_clear") => ir::BitmaskTest::AnyClear,
                Some("bitmask_all_set") => ir::BitmaskTest::AllSet,
                Some("bitmask_all_clear") => ir::BitmaskTest::AllClear,
                _ => {
                    return Err(reject(RejectReason::UnsupportedOperator(
                        "<none>".to_string(),
                    )))
                }
            };
            Ok(Atom::Bitmask(ir::BitmaskAtom {
                input_path,
                mask,
                test,
            }))
        }
        Some("exists_in") => {
            if field_type != FieldType::Array {
                return Err(reject(RejectReason::UnboundField(input_path)));
            }
            let scalar = scalar_value(cond, &reject)?;
            let element_op = field_cmp_op(cond.element_operator.as_deref()).ok_or_else(|| {
                reject(RejectReason::UnsupportedOperator("exists_in".to_string()))
            })?;
            let schema_cap = schema
                .array_cap(&input_path)
                .ok_or_else(|| reject(RejectReason::UnboundField(input_path.clone())))?;
            let pe_cap = cond.collection_cap.unwrap_or(schema_cap);
            let cap = core::cmp::min(schema_cap, pe_cap);
            Ok(Atom::ExistsIn(ir::ExistsInAtom {
                input_path,
                element_op,
                scalar,
                cap,
            }))
        }
        Some("cidr_contains" | "not_cidr_contains") => {
            if !matches!(field_type, FieldType::Str | FieldType::Ip) {
                return Err(reject(RejectReason::UnboundField(input_path)));
            }
            let network = string_value(cond, &reject)?;
            let (family, prefix_len) = parse_cidr_metadata(&network)
                .ok_or_else(|| reject(RejectReason::UnencodableValue))?;
            Ok(Atom::Cidr(ir::CidrAtom {
                input_path,
                network,
                prefix_len,
                family,
                negated: cond.operator.as_deref() == Some("not_cidr_contains"),
            }))
        }
        Some("startswith" | "endswith" | "not_startswith" | "not_endswith") => {
            if field_type != FieldType::Str {
                return Err(reject(RejectReason::UnboundField(input_path)));
            }
            let pattern = string_value(cond, &reject)?;
            let op = cond.operator.as_deref();
            Ok(Atom::Prefix(ir::PrefixAtom {
                input_path,
                pattern,
                kind: if matches!(op, Some("endswith" | "not_endswith")) {
                    ir::PrefixKind::EndsWith
                } else {
                    ir::PrefixKind::StartsWith
                },
                negated: matches!(op, Some("not_startswith" | "not_endswith")),
            }))
        }
        Some("contains" | "not_contains") => {
            if field_type != FieldType::Str {
                return Err(reject(RejectReason::UnboundField(input_path)));
            }
            let pattern = string_value(cond, &reject)?;
            Ok(Atom::Prefix(ir::PrefixAtom {
                input_path,
                pattern,
                kind: ir::PrefixKind::Contains,
                negated: cond.operator.as_deref() == Some("not_contains"),
            }))
        }
        Some("non_empty") => {
            if field_type != FieldType::Array {
                return Err(reject(RejectReason::UnboundField(input_path)));
            }
            Ok(Atom::NonEmpty(ir::NonEmptyAtom { input_path }))
        }
        Some(op) => Err(reject(RejectReason::UnsupportedOperator(op.to_string()))),
        None => Err(reject(RejectReason::UnsupportedOperator(
            "<none>".to_string(),
        ))),
    }
}

fn scalar_value(
    cond: &ResidualCondition,
    reject: &impl Fn(RejectReason) -> Rejection,
) -> Result<LiftScalar, Rejection> {
    let value = cond
        .value
        .as_ref()
        .ok_or_else(|| reject(RejectReason::UnencodableValue))?;
    LiftScalar::from_value(value).ok_or_else(|| reject(RejectReason::UnencodableValue))
}

fn u64_value(
    cond: &ResidualCondition,
    reject: &impl Fn(RejectReason) -> Rejection,
) -> Result<u64, Rejection> {
    let value = cond
        .value
        .as_ref()
        .ok_or_else(|| reject(RejectReason::UnencodableValue))?;
    match serde_json::to_value(value).ok() {
        Some(serde_json::Value::Number(n)) => n
            .as_u64()
            .ok_or_else(|| reject(RejectReason::UnencodableValue)),
        _ => Err(reject(RejectReason::UnencodableValue)),
    }
}

fn field_cmp_op(op: Option<&str>) -> Option<ir::FieldCmpOp> {
    match op {
        Some("==") => Some(ir::FieldCmpOp::Eq),
        Some("!=") => Some(ir::FieldCmpOp::Ne),
        Some("<") => Some(ir::FieldCmpOp::Lt),
        Some("<=") => Some(ir::FieldCmpOp::Le),
        Some(">") => Some(ir::FieldCmpOp::Gt),
        Some(">=") => Some(ir::FieldCmpOp::Ge),
        _ => None,
    }
}

fn field_types_compatible(left: FieldType, right: FieldType, op: ir::FieldCmpOp) -> bool {
    if matches!(
        (left, right),
        (
            FieldType::Int | FieldType::Uint,
            FieldType::Int | FieldType::Uint
        )
    ) {
        return true;
    }
    if left != right {
        return false;
    }
    matches!(op, ir::FieldCmpOp::Eq | ir::FieldCmpOp::Ne) || matches!(left, FieldType::Str)
}

fn string_value(
    cond: &ResidualCondition,
    reject: &impl Fn(RejectReason) -> Rejection,
) -> Result<String, Rejection> {
    match scalar_value(cond, reject)? {
        LiftScalar::Str(s) => Ok(s),
        _ => Err(reject(RejectReason::UnencodableValue)),
    }
}

fn membership_values(
    cond: &ResidualCondition,
    reject: &impl Fn(RejectReason) -> Rejection,
) -> Result<Vec<LiftScalar>, Rejection> {
    let value = cond
        .value
        .as_ref()
        .ok_or_else(|| reject(RejectReason::UnencodableValue))?;
    match value {
        Value::Array(items) => items
            .iter()
            .map(|item| {
                LiftScalar::from_value(item).ok_or_else(|| reject(RejectReason::UnencodableValue))
            })
            .collect(),
        Value::Set(items) => items
            .iter()
            .map(|item| {
                LiftScalar::from_value(item).ok_or_else(|| reject(RejectReason::UnencodableValue))
            })
            .collect(),
        _ => scalar_value(cond, reject).map(|scalar| vec![scalar]),
    }
}

fn parse_cidr_metadata(cidr: &str) -> Option<(ir::IpFamily, u8)> {
    let (addr, prefix) = cidr.split_once('/')?;
    let prefix_len = prefix.parse::<u8>().ok()?;
    match addr.parse::<std::net::IpAddr>().ok()? {
        std::net::IpAddr::V4(_) if prefix_len <= 32 => Some((ir::IpFamily::V4, prefix_len)),
        std::net::IpAddr::V6(_) if prefix_len <= 128 => Some((ir::IpFamily::V6, prefix_len)),
        _ => None,
    }
}

fn disjunct_source_rule(disjunct: &[ResidualCondition]) -> Option<String> {
    disjunct.iter().find_map(|c| c.source_rule.clone())
}
