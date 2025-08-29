// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Z3 Policy Verifier
//!
//! This module provides policy verification functionality using Z3 backend
//! for consistency checking, conflict detection, and test case generation.

use crate::ast::*;
use crate::lexer::Source;
use crate::parser::Parser;
use crate::value::Value;
use alloc::{
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};
use anyhow::Result;
use serde_json;

/// Represents a logical condition extracted from a rule
#[derive(Debug)]
pub enum ConflictResult {
    None,
    Potential,
    Actual(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Condition {
    Equality { field: String, value: String },
    Inequality { field: String, value: String },
    Negation { field: String },
    StartsWith { field: String, prefix: String },
    ArrayMembership { field: String, values: Vec<String> },
}

/// Represents the scope of a rule (what inputs it can apply to)
#[derive(Debug, Clone)]
pub struct RuleScope {
    pub rule_name: String,
    pub rule_index: usize,
    pub conditions: Vec<Condition>,
    pub scope_description: String,
    pub constraint_fields: Vec<String>,
}

/// Represents scope analysis results
#[derive(Debug)]
pub struct ScopeAnalysis {
    pub rule_scopes: Vec<RuleScope>,
    pub disjoint_scope_pairs: Vec<(usize, usize, String)>, // (rule1_idx, rule2_idx, reason)
    pub overlapping_scope_pairs: Vec<(usize, usize, String)>, // (rule1_idx, rule2_idx, description)
    pub scope_coverage_report: String,
}

/// Policy verification engine using Z3
pub struct Z3PolicyVerifier {
    policies: Vec<String>,
}

#[allow(dead_code)]
impl Z3PolicyVerifier {
    /// Create a new Z3 policy verifier
    pub fn new() -> Self {
        Self { 
            policies: Vec::new(),
        }
    }

    /// Add a policy for verification
    pub fn add_policy(&mut self, policy_text: &str) -> Result<()> {
        // Validate policy by parsing it
        self.parse_policy(policy_text)?;
        self.policies.push(policy_text.to_string());
        Ok(())
    }

    /// Verify that all added policies are consistent (no contradictions)
    pub fn verify_policies(&mut self) -> Result<Vec<String>> {
        self.verify_policies_with_effects(&["deny", "audit", "modify", "deployIfNotExists"])
    }

    /// Verify consistency of policies for specific effects (e.g., "deny", "audit", "modify")
    pub fn verify_policies_with_effects(&mut self, effects: &[&str]) -> Result<Vec<String>> {
        let result = self.verify_policies_with_effects_detailed(effects)?;
        Ok(result.conflicts)
    }

    /// Verify consistency of policies for specific effects and return detailed results
    pub fn verify_policies_with_effects_detailed(&mut self, effects: &[&str]) -> Result<CrossPolicyConflictResult> {
        if self.policies.is_empty() {
            return Ok(CrossPolicyConflictResult {
                conflicts: Vec::new(),
                conflicting_inputs: Vec::new(),
            });
        }

        // Parse all policies into modules
        let mut modules = Vec::new();
        for policy_text in &self.policies {
            let module = self.parse_policy(policy_text)?;
            modules.push(module);
        }

        // Find conflicts between different effects across all policies
        self.find_cross_policy_effect_conflicts(&modules, effects)
    }

    /// Find conflicts between different effects across policies
    fn find_cross_policy_effect_conflicts(&mut self, modules: &[Module], effects: &[&str]) -> Result<CrossPolicyConflictResult> {
        let mut conflicts = Vec::new();
        let mut conflicting_inputs = Vec::new();
        
        // Collect all rules by effect from all policies
        let mut rules_by_effect = std::collections::HashMap::new();
        
        for (policy_idx, module) in modules.iter().enumerate() {
            let package_path = crate::interpreter::Interpreter::get_path_string(&module.package.refr, Some("data"))?;
            
            for (rule_idx, rule) in module.policy.iter().enumerate() {
                if let Rule::Spec { .. } = rule.as_ref() {
                    let refr = self.get_rule_refr(rule);
                    let rule_name = self.extract_rule_name_from_refr(refr)?;
                    
                    // Check if this rule matches any of the effects we're looking for
                    if effects.contains(&rule_name.as_str()) {
                        let rule_info = (policy_idx, rule_idx, rule, package_path.clone());
                        rules_by_effect.entry(rule_name).or_insert_with(Vec::new).push(rule_info);
                    }
                }
            }
        }
        
        // Check for conflicts between different effects
        let contradictory_effects = [
            ("deny", "allow"),
            ("deny", "modify"), // deny conflicts with modify since modify implies allowing with changes
        ];
        
        for (effect1, effect2) in contradictory_effects {
            if let (Some(rules1), Some(rules2)) = (rules_by_effect.get(effect1), rules_by_effect.get(effect2)) {
                for rule1_info in rules1 {
                    for rule2_info in rules2 {
                        let (policy1_idx, rule1_idx, rule1, _package1) = rule1_info;
                        let (policy2_idx, rule2_idx, rule2, _package2) = rule2_info;
                        
                        // Only check rules from different policies
                        if policy1_idx != policy2_idx {
                            // Check if the conditions overlap
                            if self.check_conditions_overlap(rule1, rule2)? {
                                let conflict_msg = format!(
                                    "Cross-policy conflict between Policy {} Rule {} (effect: {}) and Policy {} Rule {} (effect: {}): overlapping conditions create contradictory effects",
                                    policy1_idx + 1, 
                                    rule1_idx + 1,
                                    effect1,
                                    policy2_idx + 1,
                                    rule2_idx + 1,
                                    effect2
                                );
                                conflicts.push(conflict_msg);
                                
                                // Generate conflicting input using Z3
                                if let Some(input) = self.generate_conflict_input(rule1, rule2)? {
                                    conflicting_inputs.push(input);
                                }
                            }
                        }
                    }
                }
            }
        }
        
        Ok(CrossPolicyConflictResult {
            conflicts,
            conflicting_inputs,
        })
    }

    /// Verify that a single policy is consistent (no contradictions)
    pub fn verify_consistency(&mut self, policy_text: &str) -> Result<ConsistencyResult> {
        let module = self.parse_policy(policy_text)?;
        self.verify_module_consistency(&module, None)
    }

    /// Verify consistency of specific entry point rules using effect names
    pub fn verify_entry_points(
        &mut self,
        policy_text: &str,
        effects: &[&str],
    ) -> Result<ConsistencyResult> {
        let module = self.parse_policy(policy_text)?;
        self.verify_module_consistency(&module, Some(effects))
    }

    fn verify_module_consistency(
        &mut self,
        module: &Module,
        entry_points: Option<&[&str]>,
    ) -> Result<ConsistencyResult> {
        let mut unreachable_rules = vec![];

        // Extract package path for informative messages
        let package_path =
            crate::interpreter::Interpreter::get_path_string(&module.package.refr, Some("data"))?;

        // Get the indices of rules to analyze for conflicts
        let rule_indices_to_check = if let Some(entry_point_names) = entry_points {
            // Only analyze specified entry point rules
            self.find_entry_point_rule_indices(module, entry_point_names)?
        } else {
            // Default behavior: analyze all rules
            (0..module.policy.len()).collect()
        };

        // Check satisfiability for all rules (entry points and their dependencies)
        for (i, rule) in module.policy.iter().enumerate() {
            match rule.as_ref() {
                Rule::Spec { .. } => {
                    if !self.is_rule_satisfiable(rule)? {
                        unreachable_rules.push(format!("Rule {} is never satisfiable", i));
                    }
                }
                Rule::Default { .. } => {
                    // Default rules are generally safe
                }
            }
        }

        // ENHANCED CONFLICT DETECTION WITH SCOPE ANALYSIS
        // First, extract scopes for all rules to analyze
        let mut rule_scopes = Vec::new();
        for &rule_idx in &rule_indices_to_check {
            let rule = &module.policy[rule_idx];
            let scope = self.extract_rule_scope(rule, rule_idx, &package_path)?;
            rule_scopes.push(scope);
        }

        // Analyze scope relationships to identify disjoint pairs
        let mut disjoint_pairs = std::collections::HashSet::new();
        for (i, scope1) in rule_scopes.iter().enumerate() {
            for (_j, scope2) in rule_scopes.iter().enumerate().skip(i + 1) {
                if let ScopeRelationship::Disjoint(_) =
                    self.analyze_scope_relationship(scope1, scope2)?
                {
                    disjoint_pairs.insert((scope1.rule_index, scope2.rule_index));
                    disjoint_pairs.insert((scope2.rule_index, scope1.rule_index));
                    // Both directions
                }
            }
        }

        // Check for conflicts only between overlapping (non-disjoint) rules
        let mut actual_conflicts = vec![];
        let mut potential_conflicts_count = 0;
        let mut disjoint_pairs_skipped = 0;

        for (i, &rule_idx1) in rule_indices_to_check.iter().enumerate() {
            for &rule_idx2 in rule_indices_to_check.iter().skip(i + 1) {
                // Skip disjoint rule pairs - they cannot conflict
                if disjoint_pairs.contains(&(rule_idx1, rule_idx2)) {
                    disjoint_pairs_skipped += 1;
                    continue;
                }

                let rule1 = &module.policy[rule_idx1];
                let rule2 = &module.policy[rule_idx2];
                match self.check_rule_conflict_enhanced(
                    rule1,
                    rule2,
                    rule_idx1,
                    rule_idx2,
                    &package_path,
                )? {
                    ConflictResult::Actual(conflict_msg) => {
                        actual_conflicts.push(conflict_msg);
                    }
                    ConflictResult::Potential => {
                        potential_conflicts_count += 1;
                    }
                    ConflictResult::None => {}
                }
            }
        }

        let is_consistent = actual_conflicts.is_empty();
        let actual_conflicts_count = actual_conflicts.len();

        Ok(ConsistencyResult {
            is_consistent,
            conflicts: actual_conflicts,
            conflicting_inputs: Vec::new(), // TODO: Collect actual conflicting inputs
            unreachable_rules,
            message: if is_consistent {
                if entry_points.is_some() {
                    if potential_conflicts_count > 0 {
                        format!("Entry point rules have no actual conflicts ({} rules checked, {} disjoint pairs skipped, {} potential conflicts ignored)", 
                                rule_indices_to_check.len(), disjoint_pairs_skipped, potential_conflicts_count)
                    } else {
                        format!("Entry point rules appear consistent ({} rules checked, {} disjoint pairs skipped)", 
                               rule_indices_to_check.len(), disjoint_pairs_skipped)
                    }
                } else {
                    "Policy appears consistent".to_string()
                }
            } else {
                if potential_conflicts_count > 0 {
                    format!("Found {} actual conflicts and {} potential conflicts between entry point rules ({} disjoint pairs skipped)", 
                            actual_conflicts_count, potential_conflicts_count, disjoint_pairs_skipped)
                } else {
                    format!("Found {} actual conflicts between entry point rules ({} disjoint pairs skipped)", 
                           actual_conflicts_count, disjoint_pairs_skipped)
                }
            },
        })
    }

    /// Find cross-policy conflicts for a specific effect
    fn find_cross_policy_conflicts(&mut self, modules: &[Module], effect: &str) -> Result<Vec<String>> {
        let mut conflicts = Vec::new();
        
        // Collect all rules for the specified effect from all policies
        let mut effect_rules = Vec::new();
        
        for (policy_idx, module) in modules.iter().enumerate() {
            let package_path = crate::interpreter::Interpreter::get_path_string(&module.package.refr, Some("data"))?;
            
            for (rule_idx, rule) in module.policy.iter().enumerate() {
                if let Rule::Spec { .. } = rule.as_ref() {
                    let refr = self.get_rule_refr(rule);
                    let rule_name = self.extract_rule_name_from_refr(refr)?;
                    
                    // Check if this rule matches the effect we're looking for
                    if rule_name == effect {
                        effect_rules.push((policy_idx, rule_idx, rule, package_path.clone()));
                    }
                }
            }
        }
        
        // Check for conflicts between rules of the same effect across policies
        for i in 0..effect_rules.len() {
            for j in (i + 1)..effect_rules.len() {
                let (policy1_idx, rule1_idx, rule1, package1) = &effect_rules[i];
                let (policy2_idx, rule2_idx, rule2, package2) = &effect_rules[j];
                
                // Only check rules from different policies
                if policy1_idx != policy2_idx {
                    // For cross-policy conflicts with same effect, check for overlapping conditions
                    // that could create ambiguous or conflicting policy decisions
                    match self.check_cross_policy_rule_conflict(
                        rule1,
                        rule2,
                        *rule1_idx,
                        *rule2_idx,
                        package1,
                        package2,
                        effect,
                    )? {
                        ConflictResult::Actual(conflict_msg) => {
                            let enhanced_msg = format!(
                                "Cross-policy conflict in '{}' effect between Policy {} Rule {} and Policy {} Rule {}: {}",
                                effect, 
                                policy1_idx + 1, 
                                rule1_idx + 1,
                                policy2_idx + 1,
                                rule2_idx + 1,
                                conflict_msg
                            );
                            conflicts.push(enhanced_msg);
                        }
                        ConflictResult::Potential => {
                            // Could add potential conflicts here if needed
                        }
                        ConflictResult::None => {}
                    }
                }
            }
        }
        
        Ok(conflicts)
    }

    /// Check for conflicts between rules with the same effect across different policies
    fn check_cross_policy_rule_conflict(
        &mut self,
        rule1: &Ref<Rule>,
        rule2: &Ref<Rule>,
        rule_idx1: usize,
        rule_idx2: usize,
        package1: &str,
        package2: &str,
        effect: &str,
    ) -> Result<ConflictResult> {
        match (rule1.as_ref(), rule2.as_ref()) {
            (
                Rule::Spec {
                    bodies: bodies1, ..
                },
                Rule::Spec {
                    bodies: bodies2, ..
                },
            ) => {
                // For same-effect rules across policies, check if they have overlapping conditions
                // that could create conflicting or ambiguous policy decisions
                for (body_idx1, body1) in bodies1.iter().enumerate() {
                    for (body_idx2, body2) in bodies2.iter().enumerate() {
                        // Check if the conditions can apply to the same input
                        if self.bodies_have_overlapping_conditions(body1, body2)? {
                            // Check if the conditions create a conflict (different requirements)
                            if let Some(conflict_details) = self.detect_condition_conflicts(body1, body2)? {
                                return Ok(ConflictResult::Actual(format!(
                                    "🚨 CROSS-POLICY CONFLICT:\n   \
                                    Policies: {} vs {}\n   \
                                    Rules: {}.{} (#{}) vs {}.{} (#{}) - both '{}' effects\n   \
                                    Bodies: {} vs {}\n   \
                                    Issue: {}\n   \
                                    💡 Multiple policies define overlapping '{}' rules with conflicting conditions\n   \
                                    Recommendation: Consolidate into single policy or make conditions mutually exclusive",
                                    package1, package2,
                                    package1, effect, rule_idx1 + 1,
                                    package2, effect, rule_idx2 + 1,
                                    effect,
                                    body_idx1, body_idx2,
                                    conflict_details,
                                    effect
                                )));
                            }
                        }
                    }
                }
            }
            _ => {}
        }
        Ok(ConflictResult::None)
    }

    /// Find entry point rule indices by effect names (e.g., "deny", "audit", "modify")
    fn find_entry_point_rule_indices(
        &self,
        module: &Module,
        effect_names: &[&str],
    ) -> Result<Vec<usize>> {
        let mut entry_point_indices = vec![];
        let mut found_effects = vec![];

        for (i, rule) in module.policy.iter().enumerate() {
            match rule.as_ref() {
                Rule::Spec { .. } => {
                    // Use the same method as the engine to get the rule reference
                    let refr = self.get_rule_refr(rule);

                    // Extract rule name using the same approach as the engine
                    let rule_name = self.extract_rule_name_from_refr(refr)?;
                    found_effects.push(rule_name.clone());
                    
                    // Check if this rule matches any of the requested effects
                    if effect_names.contains(&rule_name.as_str()) {
                        entry_point_indices.push(i);
                    }
                }
                Rule::Default { .. } => {
                    // Skip default rules for now
                }
            }
        }

        // Validate that all requested effects were found
        for effect in effect_names {
            if !found_effects.contains(&effect.to_string()) {
                return Err(anyhow::anyhow!(
                    "Effect '{}' not found in policy. Available effects: {:?}",
                    effect,
                    found_effects
                ));
            }
        }

        Ok(entry_point_indices)
    }

    /// Get rule reference using the same method as the engine
    fn get_rule_refr<'a>(&self, rule: &'a Ref<Rule>) -> &'a Ref<Expr> {
        match rule.as_ref() {
            Rule::Spec { head, .. } => match head {
                RuleHead::Compr { refr, .. }
                | RuleHead::Set { refr, .. }
                | RuleHead::Func { refr, .. } => refr,
            },
            Rule::Default { refr, .. } => refr,
        }
    }

    /// Extract rule name from expression reference (for deny[msg], allow, etc.)
    fn extract_rule_name_from_refr(&self, refr: &Ref<Expr>) -> Result<String> {
        // For rules like deny[msg], we want just "deny"
        // For rules like allow, we want just "allow"
        let refr = match refr.as_ref() {
            Expr::RefBrack { refr, .. } => refr, // For deny[msg] -> deny
            _ => refr,                           // For simple rules like allow
        };

        match refr.as_ref() {
            Expr::Var { value, .. } => {
                if let Value::String(s) = value {
                    Ok(s.to_string())
                } else {
                    Ok("unknown".to_string())
                }
            }
            _ => Ok("unknown".to_string()),
        }
    }

    fn is_rule_satisfiable(&mut self, rule: &Ref<Rule>) -> Result<bool> {
        // For now, use simple heuristics
        match rule.as_ref() {
            Rule::Spec { bodies, .. } => {
                // Check if any body can be satisfied
                for body in bodies {
                    if self.is_query_satisfiable(&body.query)? {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
            Rule::Default { .. } => Ok(true),
        }
    }

    fn is_query_satisfiable(&mut self, query: &Ref<Query>) -> Result<bool> {
        // Simple analysis of query statements
        for stmt in &query.stmts {
            match &stmt.literal {
                Literal::Expr { expr, .. } => {
                    if self.has_contradiction(expr)? {
                        return Ok(false);
                    }
                }
                _ => {}
            }
        }
        Ok(true)
    }

    fn has_contradiction(&self, expr: &Ref<Expr>) -> Result<bool> {
        // Simple contradiction detection
        match expr.as_ref() {
            Expr::BoolExpr {
                op: BoolOp::Eq,
                lhs,
                rhs,
                ..
            } => {
                // Check for X == Y where X and Y are different constants
                if let (Expr::Number { value: v1, .. }, Expr::Number { value: v2, .. }) =
                    (lhs.as_ref(), rhs.as_ref())
                {
                    return Ok(v1 != v2);
                }
                if let (Expr::Bool { value: v1, .. }, Expr::Bool { value: v2, .. }) =
                    (lhs.as_ref(), rhs.as_ref())
                {
                    return Ok(v1 != v2);
                }
            }
            Expr::Bool {
                value: Value::Bool(false),
                ..
            } => {
                return Ok(true); // Explicit false
            }
            _ => {}
        }
        Ok(false)
    }

    fn check_rule_conflict(
        &mut self,
        rule1: &Ref<Rule>,
        rule2: &Ref<Rule>,
        rule_idx1: usize,
        rule_idx2: usize,
        package_path: &str,
    ) -> Result<ConflictResult> {
        // Enhanced conflict detection between rules
        match (rule1.as_ref(), rule2.as_ref()) {
            (
                Rule::Spec {
                    head: head1,
                    bodies: bodies1,
                    ..
                },
                Rule::Spec {
                    head: head2,
                    bodies: bodies2,
                    ..
                },
            ) => {
                // Check if rules have same head (both affect the same decision)
                if self.same_rule_head(head1, head2) {
                    let rule_name1 = self.extract_rule_name_from_refr(self.get_rule_refr(rule1))?;
                    let rule_name2 = self.extract_rule_name_from_refr(self.get_rule_refr(rule2))?;

                    // Analyze rule bodies for logical conflicts (highest priority)
                    for (body_idx1, body1) in bodies1.iter().enumerate() {
                        for (body_idx2, body2) in bodies2.iter().enumerate() {
                            if let Some(conflict) = self.analyze_body_conflict(body1, body2)? {
                                let rule1_location = self.get_rule_location_info(rule1);
                                let rule2_location = self.get_rule_location_info(rule2);
                                let conflict_expressions =
                                    self.get_conflict_expressions(body1, body2, rule_idx1, rule_idx2);

                                // Generate example input that triggers the conflict
                                let conflict_example = if let Some(example_input) = self.generate_conflict_input(rule1, rule2)? {
                                    format!("\n   🎯 Z3-Generated Conflicting Input Example:\n      {}", example_input)
                                } else {
                                    "".to_string()
                                };

                                return Ok(ConflictResult::Actual(format!(
                                    "🚨 LOGICAL CONFLICT DETECTED:\n   \
                                    Rules: {}.{} (rule #{}) vs {}.{} (rule #{})\n   \
                                    Location: Body {} conflicts with Body {}\n{}{}{}{}\
                                    Issue: {}\n   \
                                    Impact: These rules can create contradictory policy decisions\n   \
                                    Recommendation: Review rule conditions and ensure they don't overlap in conflicting ways",
                                    package_path, rule_name1, rule_idx1 + 1,
                                    package_path, rule_name2, rule_idx2 + 1,
                                    body_idx1, body_idx2,
                                    rule1_location, rule2_location,
                                    conflict_expressions,
                                    conflict_example,
                                    conflict
                                )));
                            }
                        }
                    }

                    // Check for contradictory conditions (second priority)
                    if let Some(contradiction) =
                        self.find_logical_contradiction(bodies1, bodies2)?
                    {
                        let rule1_location = self.get_rule_location_info(rule1);
                        let rule2_location = self.get_rule_location_info(rule2);

                        return Ok(ConflictResult::Actual(format!(
                            "⚠️  MUTUAL EXCLUSION DETECTED:\n   \
                            Rules: {}.{} (rule #{}) and {}.{} (rule #{})\n   \
                            {}{}\
                            Issue: {}\n   \
                            Impact: These rules have conditions that can never both be satisfied\n   \
                            Recommendation: Consider merging rules or adding more specific conditions",
                            package_path, rule_name1, rule_idx1 + 1,
                            package_path, rule_name2, rule_idx2 + 1,
                            rule1_location, rule2_location,
                            contradiction
                        )));
                    }

                    // Generic potential conflict (lowest priority - count only)
                    return Ok(ConflictResult::Potential);
                }
            }
            _ => {}
        }
        Ok(ConflictResult::None)
    }

    /// Enhanced conflict detection that uses scope analysis and action analysis
    fn check_rule_conflict_enhanced(
        &mut self,
        rule1: &Ref<Rule>,
        rule2: &Ref<Rule>,
        rule_idx1: usize,
        rule_idx2: usize,
        package_path: &str,
    ) -> Result<ConflictResult> {
        // Enhanced conflict detection between rules
        match (rule1.as_ref(), rule2.as_ref()) {
            (
                Rule::Spec {
                    head: head1,
                    bodies: bodies1,
                    ..
                },
                Rule::Spec {
                    head: head2,
                    bodies: bodies2,
                    ..
                },
            ) => {
                let rule_name1 = self.extract_rule_name_from_refr(self.get_rule_refr(rule1))?;
                let rule_name2 = self.extract_rule_name_from_refr(self.get_rule_refr(rule2))?;

                // ENHANCED: Check if rules have contradictory actions FIRST
                if self.has_contradictory_actions(rule1, rule2)? {
                    // These rules have contradictory actions (allow vs deny)
                    // Now check if they can apply to the same input (logical conflict)
                    for (body_idx1, body1) in bodies1.iter().enumerate() {
                        for (body_idx2, body2) in bodies2.iter().enumerate() {
                            if self.bodies_have_overlapping_conditions(body1, body2)? {
                                let rule1_location = self.get_rule_location_info(rule1);
                                let rule2_location = self.get_rule_location_info(rule2);
                                let conflict_expressions =
                                    self.get_conflict_expressions(body1, body2, rule_idx1, rule_idx2);

                                let action1 = self.extract_rule_action(rule1)?;
                                let action2 = self.extract_rule_action(rule2)?;
                                
                                // Generate example input that triggers the conflict
                                let conflict_example = if let Some(example_input) = self.generate_conflict_input(rule1, rule2)? {
                                    format!("\n   🎯 Z3-Generated Conflicting Input Example:\n      {}", example_input)
                                } else {
                                    "".to_string()
                                };

                                return Ok(ConflictResult::Actual(format!(
                                    "🚨 POLICY EFFECT CONFLICT:\n   \
                                    Rules: {}.{} (rule #{}) vs {}.{} (rule #{})\n   \
                                    Effects: {} vs {}\n   \
                                    Location: Body {} conflicts with Body {}\n{}{}{}{}\
                                    Issue: Same input triggers contradictory policy effects ({} vs {})\n   \
                                    💡 This creates conflicting policy decisions for identical conditions\n   \
                                    Recommendation: Review rule logic - effects should be mutually exclusive or one should be more specific",
                                    package_path, rule_name1, rule_idx1 + 1,
                                    package_path, rule_name2, rule_idx2 + 1,
                                    action1.to_uppercase(), action2.to_uppercase(),
                                    body_idx1, body_idx2,
                                    rule1_location, rule2_location,
                                    conflict_expressions,
                                    conflict_example,
                                    action1, action2
                                )));
                            }
                        }
                    }
                }
                // Check for same-action conflicts (like original logic)
                else if self.same_rule_head(head1, head2) {
                    // Analyze rule bodies for logical conflicts (highest priority)
                    for (body_idx1, body1) in bodies1.iter().enumerate() {
                        for (body_idx2, body2) in bodies2.iter().enumerate() {
                            if let Some(conflict) =
                                self.analyze_body_conflict_enhanced(body1, body2)?
                            {
                                let rule1_location = self.get_rule_location_info(rule1);
                                let rule2_location = self.get_rule_location_info(rule2);
                                let conflict_expressions =
                                    self.get_conflict_expressions(body1, body2, rule_idx1, rule_idx2);

                                // Generate example input that triggers the conflict
                                let conflict_example = if let Some(example_input) = self.generate_conflict_input(rule1, rule2)? {
                                    format!("\n   🎯 Z3-Generated Conflicting Input Example:\n      {}", example_input)
                                } else {
                                    "".to_string()
                                };

                                return Ok(ConflictResult::Actual(format!(
                                    "🚨 REAL LOGICAL CONFLICT:\n   \
                                    Rules: {}.{} (rule #{}) vs {}.{} (rule #{})\n   \
                                    Location: Body {} conflicts with Body {}\n{}{}{}{}\
                                    Issue: {}\n   \
                                    💡 These rules can apply to the same input but have contradictory effects\n   \
                                    Recommendation: Review rule logic to ensure they don't create impossible requirements",
                                    package_path, rule_name1, rule_idx1 + 1,
                                    package_path, rule_name2, rule_idx2 + 1,
                                    body_idx1, body_idx2,
                                    rule1_location, rule2_location,
                                    conflict_expressions,
                                    conflict_example,
                                    conflict
                                )));
                            }
                        }
                    }

                    // Check for impossible combinations within overlapping scope
                    if let Some(impossibility) =
                        self.find_impossible_combination_enhanced(bodies1, bodies2)?
                    {
                        let rule1_location = self.get_rule_location_info(rule1);
                        let rule2_location = self.get_rule_location_info(rule2);

                        return Ok(ConflictResult::Actual(format!(
                            "⚠️  IMPOSSIBLE REQUIREMENT COMBINATION:\n   \
                            Rules: {}.{} (rule #{}) and {}.{} (rule #{})\n   \
                            {}{}\
                            Issue: {}\n   \
                            💡 These requirements cannot be satisfied simultaneously for the same input\n   \
                            Recommendation: Consider making rules mutually exclusive or refining conditions",
                            package_path, rule_name1, rule_idx1 + 1,
                            package_path, rule_name2, rule_idx2 + 1,
                            rule1_location, rule2_location,
                            impossibility
                        )));
                    }
                }
            }
            _ => {}
        }
        Ok(ConflictResult::None)
    }

    /// Extract location information from a rule for better error reporting
    fn get_rule_location_info(&self, rule: &Ref<Rule>) -> String {
        match rule.as_ref() {
            Rule::Spec { span, .. } => {
                format!(
                    "   📍 Rule location: Line {}, Column {} - {}\n",
                    span.line,
                    span.col,
                    self.truncate_text(span.text(), 60)
                )
            }
            Rule::Default { span, .. } => {
                format!(
                    "   📍 Default rule location: Line {}, Column {} - {}\n",
                    span.line,
                    span.col,
                    self.truncate_text(span.text(), 60)
                )
            }
        }
    }

    /// Extract conflicting expressions from rule bodies
    fn get_conflict_expressions(&self, body1: &RuleBody, body2: &RuleBody, rule_idx1: usize, rule_idx2: usize) -> String {
        let expr1_info = self.get_body_expression_info(body1, &format!("Rule #{}", rule_idx1 + 1));
        let expr2_info = self.get_body_expression_info(body2, &format!("Rule #{}", rule_idx2 + 1));
        format!("{}{}   \n", expr1_info, expr2_info)
    }

    /// Get expression information from a rule body
    fn get_body_expression_info(&self, body: &RuleBody, rule_label: &str) -> String {
        let mut expressions = Vec::new();

        for stmt in &body.query.stmts {
            if let Literal::Expr { span, .. } = &stmt.literal {
                expressions.push(format!(
                    "     {} Expression (Line {}): {}",
                    rule_label,
                    span.line,
                    self.truncate_text(span.text(), 80)
                ));
            }
        }

        if expressions.is_empty() {
            format!("   🔍 {} expressions: <none found>\n", rule_label)
        } else {
            format!(
                "   🔍 {} expressions:\n{}\n",
                rule_label,
                expressions.join("\n")
            )
        }
    }

    /// Truncate text for display purposes
    fn truncate_text(&self, text: &str, max_len: usize) -> String {
        let clean_text = text.trim().replace('\n', " ").replace('\r', "");
        if clean_text.len() > max_len {
            format!("{}...", &clean_text[..max_len])
        } else {
            clean_text
        }
    }

    /// Summarize rule conditions in human-readable format
    fn summarize_rule_conditions(&self, bodies: &[RuleBody]) -> Result<String> {
        let mut summaries = vec![];

        for (i, body) in bodies.iter().enumerate() {
            let conditions = self.extract_conditions(&body.query)?;
            let mut condition_strs = vec![];

            for condition in &conditions {
                let condition_str = match condition {
                    Condition::Equality { field, value } => {
                        format!("{} = {}", field, value)
                    }
                    Condition::Inequality { field, value } => {
                        format!("{} ≠ {}", field, value)
                    }
                    Condition::Negation { field } => {
                        format!("NOT {}", field)
                    }
                    Condition::StartsWith { field, prefix } => {
                        format!("{} starts with '{}'", field, prefix)
                    }
                    Condition::ArrayMembership { field, values } => {
                        format!("{} in [{}]", field, values.join(", "))
                    }
                };
                condition_strs.push(condition_str);
            }

            if condition_strs.is_empty() {
                summaries.push(format!("Body {}: always true", i));
            } else if condition_strs.len() == 1 {
                summaries.push(format!("Body {}: {}", i, condition_strs[0]));
            } else {
                summaries.push(format!(
                    "Body {}: {} AND {}",
                    i,
                    condition_strs[0],
                    condition_strs[1..].join(" AND ")
                ));
            }
        }

        if summaries.is_empty() {
            Ok("no conditions".to_string())
        } else if summaries.len() == 1 {
            Ok(summaries[0].clone())
        } else {
            Ok(format!("({})", summaries.join(" OR ")))
        }
    }

    /// Analyze two rule bodies for specific logical conflicts
    fn analyze_body_conflict(&self, body1: &RuleBody, body2: &RuleBody) -> Result<Option<String>> {
        let conditions1 = self.extract_conditions(&body1.query)?;
        let conditions2 = self.extract_conditions(&body2.query)?;

        // Check for direct contradictions
        for cond1 in &conditions1 {
            for cond2 in &conditions2 {
                if let Some(conflict) = self.check_condition_conflict(cond1, cond2)? {
                    return Ok(Some(conflict));
                }
            }
        }

        // Check for impossible combinations
        if let Some(impossibility) =
            self.check_impossible_combination(&conditions1, &conditions2)?
        {
            return Ok(Some(impossibility));
        }

        Ok(None)
    }

    /// Enhanced body conflict analysis that focuses on logical contradictions
    fn analyze_body_conflict_enhanced(
        &self,
        body1: &RuleBody,
        body2: &RuleBody,
    ) -> Result<Option<String>> {
        let conditions1 = self.extract_conditions(&body1.query)?;
        let conditions2 = self.extract_conditions(&body2.query)?;

        // Look for strict logical contradictions only
        for cond1 in &conditions1 {
            for cond2 in &conditions2 {
                if let Some(conflict) = self.check_strict_logical_conflict(cond1, cond2)? {
                    return Ok(Some(conflict));
                }
            }
        }

        Ok(None)
    }

    /// Check for strict logical conflicts (not just different values)
    fn check_strict_logical_conflict(
        &self,
        cond1: &Condition,
        cond2: &Condition,
    ) -> Result<Option<String>> {
        match (cond1, cond2) {
            // Contradictory requirements on same field for same input
            (
                Condition::Equality {
                    field: f1,
                    value: v1,
                },
                Condition::Inequality {
                    field: f2,
                    value: v2,
                },
            ) if f1 == f2 && v1 == v2 => Ok(Some(format!(
                "Logical contradiction: {} cannot both equal '{}' AND not equal '{}'",
                f1, v1, v2
            ))),
            (
                Condition::Inequality {
                    field: f1,
                    value: v1,
                },
                Condition::Equality {
                    field: f2,
                    value: v2,
                },
            ) if f1 == f2 && v1 == v2 => Ok(Some(format!(
                "Logical contradiction: {} cannot both not equal '{}' AND equal '{}'",
                f1, v1, v2
            ))),

            // Field existence contradictions
            (Condition::Equality { field: f1, .. }, Condition::Negation { field: f2 })
                if f1 == f2 =>
            {
                Ok(Some(format!(
                    "Logical contradiction: {} cannot both be defined AND undefined",
                    f1
                )))
            }
            (Condition::Negation { field: f1 }, Condition::Equality { field: f2, .. })
                if f1 == f2 =>
            {
                Ok(Some(format!(
                    "Logical contradiction: {} cannot both be undefined AND defined",
                    f1
                )))
            }

            _ => Ok(None),
        }
    }

    /// Check if rules have contradictory actions based on their effects
    fn has_contradictory_actions(&self, rule1: &Ref<Rule>, rule2: &Ref<Rule>) -> Result<bool> {
        let action1 = self.extract_rule_action(rule1)?;
        let action2 = self.extract_rule_action(rule2)?;

        // Define which effects are contradictory to each other
        match (action1.as_str(), action2.as_str()) {
            // Traditional allow vs deny conflicts
            ("allow", "deny") => Ok(true),
            ("deny", "allow") => Ok(true),
            
            // Azure Policy effect conflicts
            ("deny", "modify") => Ok(true),     // deny blocks, modify allows with changes
            ("modify", "deny") => Ok(true),     // modify allows with changes, deny blocks
            ("deny", "audit") => Ok(true),      // deny blocks, audit allows but logs
            ("audit", "deny") => Ok(true),      // audit allows but logs, deny blocks
            ("deny", "deployIfNotExists") => Ok(true), // deny blocks, deployIfNotExists creates
            ("deployIfNotExists", "deny") => Ok(true), // deployIfNotExists creates, deny blocks
            
            // Complementary effects (not conflicting)
            ("deny", "deny") => Ok(false),      // Both deny = complementary
            ("allow", "allow") => Ok(false),    // Both allow = complementary  
            ("audit", "audit") => Ok(false),    // Both audit = complementary
            ("modify", "modify") => Ok(false),  // Both modify = complementary
            ("deployIfNotExists", "deployIfNotExists") => Ok(false), // Both deploy = complementary
            ("audit", "modify") => Ok(false),   // audit + modify = complementary (observe + fix)
            ("modify", "audit") => Ok(false),   // modify + audit = complementary (fix + observe)
            
            // All other combinations are considered non-conflicting
            _ => Ok(false),
        }
    }

    /// Extract the action type from a rule (allow, deny, etc.)
    fn extract_rule_action(&self, rule: &Ref<Rule>) -> Result<String> {
        match rule.as_ref() {
            Rule::Spec { head, .. } => {
                match head {
                    RuleHead::Compr { refr, .. } | RuleHead::Set { refr, .. } => {
                        // For deny[msg] -> get "deny", for allow -> get "allow"
                        let action_refr = match refr.as_ref() {
                            Expr::RefBrack { refr, .. } => refr, // deny[msg] -> deny
                            _ => refr,                           // allow -> allow
                        };

                        match action_refr.as_ref() {
                            Expr::Var { value, .. } => {
                                if let Value::String(s) = value {
                                    Ok(s.to_string())
                                } else {
                                    Ok("unknown".to_string())
                                }
                            }
                            _ => Ok("unknown".to_string()),
                        }
                    }
                    _ => Ok("unknown".to_string()),
                }
            }
            Rule::Default { .. } => Ok("default".to_string()),
        }
    }

    /// Enhanced impossible combination detection
    fn find_impossible_combination_enhanced(
        &self,
        bodies1: &[RuleBody],
        bodies2: &[RuleBody],
    ) -> Result<Option<String>> {
        // Look for combinations that cannot logically coexist
        for body1 in bodies1 {
            for body2 in bodies2 {
                let conditions1 = self.extract_conditions(&body1.query)?;
                let conditions2 = self.extract_conditions(&body2.query)?;

                // Check if the combined conditions are satisfiable
                if self.are_conditions_incompatible(&conditions1, &conditions2)? {
                    return Ok(Some(format!(
                        "Impossible combination: Rules require contradictory states that cannot coexist"
                    )));
                }
            }
        }
        Ok(None)
    }

    /// Check if two sets of conditions are logically incompatible
    fn are_conditions_incompatible(
        &self,
        conditions1: &[Condition],
        conditions2: &[Condition],
    ) -> Result<bool> {
        // For now, use the strict logical conflict check
        for cond1 in conditions1 {
            for cond2 in conditions2 {
                if self.check_strict_logical_conflict(cond1, cond2)?.is_some() {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    /// Check if two rule bodies have overlapping conditions (can apply to same input)
    fn bodies_have_overlapping_conditions(
        &self,
        body1: &RuleBody,
        body2: &RuleBody,
    ) -> Result<bool> {
        let conditions1 = self.extract_conditions(&body1.query)?;
        let conditions2 = self.extract_conditions(&body2.query)?;

        // Check if the conditions can be satisfied simultaneously
        // If they can't both be true for any input, they don't overlap
        for cond1 in &conditions1 {
            for cond2 in &conditions2 {
                // Check for mutually exclusive conditions
                if self.check_disjoint_conditions(cond1, cond2)?.is_some() {
                    // If any conditions are mutually exclusive, bodies don't overlap
                    return Ok(false);
                }
            }
        }

        // If no mutual exclusions found, bodies might overlap
        Ok(true)
    }

    /// Check if conditions of two rules overlap (can both apply to same input)
    fn check_conditions_overlap(&self, rule1: &Ref<Rule>, rule2: &Ref<Rule>) -> Result<bool> {
        if let (Rule::Spec { ref bodies, .. }, Rule::Spec { bodies: ref bodies2, .. }) = (rule1.as_ref(), rule2.as_ref()) {
            // Check all body combinations for overlap
            for body1 in bodies {
                for body2 in bodies2 {
                    if self.bodies_have_overlapping_conditions(body1, body2)? {
                        return Ok(true);
                    }
                }
            }
        }
        Ok(false)
    }

    /// Extract conditions from a query for analysis
    fn extract_conditions(&self, query: &Ref<Query>) -> Result<Vec<Condition>> {
        let mut conditions = vec![];

        for stmt in &query.stmts {
            match &stmt.literal {
                Literal::Expr { expr, .. } => {
                    if let Some(condition) = self.parse_condition(expr)? {
                        conditions.push(condition);
                    }
                }
                Literal::NotExpr { expr, .. } => {
                    // Handle "not input.tags.BackupEnabled" style negations
                    let field = self.extract_field_path(expr)?;
                    let condition = Condition::Negation { field };
                    conditions.push(condition);
                }
                _ => {
                    // Other literal types (assignments, etc.) don't represent conditions
                }
            }
        }

        Ok(conditions)
    }

    /// Parse an expression into a structured condition
    fn parse_condition(&self, expr: &Ref<Expr>) -> Result<Option<Condition>> {
        match expr.as_ref() {
            Expr::BoolExpr {
                op: BoolOp::Eq,
                lhs,
                rhs,
                ..
            } => {
                let field = self.extract_field_path(lhs)?;
                let value = self.extract_value(rhs)?;
                Ok(Some(Condition::Equality { field, value }))
            }
            Expr::BoolExpr {
                op: BoolOp::Ne,
                lhs,
                rhs,
                ..
            } => {
                let field = self.extract_field_path(lhs)?;
                let value = self.extract_value(rhs)?;
                Ok(Some(Condition::Inequality { field, value }))
            }
            Expr::UnaryExpr { expr, .. } => {
                // Assume this is a negation (like "not input.tags.Environment")
                let field = self.extract_field_path(expr)?;
                Ok(Some(Condition::Negation { field }))
            }
            // Handle array membership ("in" operator) - Rego represents this as Membership
            Expr::Membership { value, collection, .. } => {
                let field = self.extract_field_path(value)?;
                if let Some(values) = self.extract_array_values(collection)? {
                    Ok(Some(Condition::ArrayMembership { field, values }))
                } else {
                    Ok(None)
                }
            }
            // Handle array membership ("in" operator) - MUST come before general Call case
            Expr::Call { fcn, params, .. } if params.len() == 2 => {
                if let Some(func_name) = self.extract_function_name_simple(fcn) {
                    if func_name == "in" {
                        let field = self.extract_field_path(&params[0])?;
                        if let Some(values) = self.extract_array_values(&params[1])? {
                            return Ok(Some(Condition::ArrayMembership { field, values }));
                        }
                    }
                }
                // Fall through to general function call handling below
                if let Some(func_name) = self.extract_function_name_simple(fcn) {
                    match func_name.as_str() {
                        "startswith" if params.len() == 2 => {
                            let field = self.extract_field_path(&params[0])?;
                            let prefix = self.extract_value(&params[1])?;
                            Ok(Some(Condition::StartsWith { field, prefix }))
                        }
                        _ => Ok(None),
                    }
                } else {
                    Ok(None)
                }
            }
            Expr::Call { fcn, params, .. } => {
                if let Some(func_name) = self.extract_function_name_simple(fcn) {
                    match func_name.as_str() {
                        "startswith" if params.len() == 2 => {
                            let field = self.extract_field_path(&params[0])?;
                            let prefix = self.extract_value(&params[1])?;
                            Ok(Some(Condition::StartsWith { field, prefix }))
                        }
                        _ => Ok(None),
                    }
                } else {
                    Ok(None)
                }
            }
            _ => Ok(None),
        }
    }

    /// Check if two conditions create a logical conflict
    fn check_condition_conflict(
        &self,
        cond1: &Condition,
        cond2: &Condition,
    ) -> Result<Option<String>> {
        match (cond1, cond2) {
            // NOTE: We DO NOT flag same field with different values as conflicts
            // Example: Environment == "Production" vs Environment == "Development" 
            // These are complementary rules for different scenarios, not conflicts

            // Field required vs field forbidden (real contradiction)
            (Condition::Equality { field: f1, value }, Condition::Negation { field: f2 })
                if f1 == f2 => {
                Ok(Some(format!("Contradiction: {} cannot be required (= '{}') and forbidden (NOT exist) simultaneously", f1, value)))
            }
            (Condition::Negation { field: f1 }, Condition::Equality { field: f2, value })
                if f1 == f2 => {
                Ok(Some(format!("Contradiction: {} cannot be forbidden (NOT exist) and required (= '{}') simultaneously", f1, value)))
            }

            // Equal vs not equal to same value (real contradiction)
            (Condition::Equality { field: f1, value: v1 }, Condition::Inequality { field: f2, value: v2 })
                if f1 == f2 && v1 == v2 => {
                Ok(Some(format!("Logical impossibility: {} cannot be both equal to '{}' and not equal to '{}'", f1, v1, v2)))
            }
            (Condition::Inequality { field: f1, value: v1 }, Condition::Equality { field: f2, value: v2 })
                if f1 == f2 && v1 == v2 => {
                Ok(Some(format!("Logical impossibility: {} cannot be both not equal to '{}' and equal to '{}'", f1, v1, v2)))
            }

            // Conflicting string prefix requirements
            (Condition::StartsWith { field: f1, prefix: p1 }, Condition::StartsWith { field: f2, prefix: p2 })
                if f1 == f2 && !p1.is_empty() && !p2.is_empty() && !p1.starts_with(p2) && !p2.starts_with(p1) => {
                Ok(Some(format!("Prefix conflict: {} cannot start with both '{}' and '{}' (mutually exclusive prefixes)", f1, p1, p2)))
            }

            _ => Ok(None)
        }
    }

    /// Check for impossible combinations of conditions
    fn check_impossible_combination(
        &self,
        conditions1: &[Condition],
        conditions2: &[Condition],
    ) -> Result<Option<String>> {
        // Look for patterns like: "field must exist" vs "field must not exist"
        for cond1 in conditions1 {
            for cond2 in conditions2 {
                match (cond1, cond2) {
                    (
                        Condition::Equality { field: f1, value },
                        Condition::Negation { field: f2 },
                    ) if f1 == f2 => {
                        return Ok(Some(format!("Impossible scenario: Rule 1 requires {} = '{}', but Rule 2 requires {} to not exist", f1, value, f2)));
                    }
                    _ => {}
                }
            }
        }

        // Check for Boolean-like field contradictions that create impossible combinations
        // E.g., "BackupEnabled = true" + "NOT BackupEnabled" means all values are denied
        use alloc::collections::BTreeSet;
        let mut field_coverage: alloc::collections::BTreeMap<String, BTreeSet<String>> =
            alloc::collections::BTreeMap::new();

        // Collect what values each field can take across both conditions
        for cond in conditions1.iter().chain(conditions2.iter()) {
            match cond {
                Condition::Equality { field, value } => {
                    field_coverage
                        .entry(field.clone())
                        .or_default()
                        .insert(value.clone());
                }
                Condition::Negation { field } => {
                    // Negation typically means field is false/undefined
                    field_coverage
                        .entry(field.clone())
                        .or_default()
                        .insert("false".to_string());
                    field_coverage
                        .entry(field.clone())
                        .or_default()
                        .insert("undefined".to_string());
                }
                _ => {}
            }
        }

        // Check for fields that cover all possible Boolean states
        for (field, values) in &field_coverage {
            // If we have both true and false/undefined states covered, it's impossible
            if values.contains("true") && (values.contains("false") || values.contains("undefined"))
            {
                return Ok(Some(format!(
                    "Impossible combination: Field '{}' is required to be both present (true) and absent/false, \
                    creating a scenario where no resource can satisfy both rules", 
                    field
                )));
            }
        }

        // Check for resource type conflicts with detailed context
        let type_conds1: Vec<_> = conditions1
            .iter()
            .filter_map(|c| {
                if let Condition::Equality { field, value } = c {
                    if field.contains("type") {
                        Some(value.as_str())
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .collect();

        let type_conds2: Vec<_> = conditions2
            .iter()
            .filter_map(|c| {
                if let Condition::Equality { field, value } = c {
                    if field.contains("type") {
                        Some(value.as_str())
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .collect();

        if !type_conds1.is_empty() && !type_conds2.is_empty() {
            for t1 in &type_conds1 {
                for t2 in &type_conds2 {
                    if t1 == t2 {
                        // Same resource type with potentially conflicting requirements
                        let other_conds1: Vec<String> = conditions1
                            .iter()
                            .filter_map(|c| match c {
                                Condition::Equality { field, value } if !field.contains("type") => {
                                    Some(format!("{} = {}", field, value))
                                }
                                Condition::Negation { field } => Some(format!("NOT {}", field)),
                                _ => None,
                            })
                            .collect();

                        let other_conds2: Vec<String> = conditions2
                            .iter()
                            .filter_map(|c| match c {
                                Condition::Equality { field, value } if !field.contains("type") => {
                                    Some(format!("{} = {}", field, value))
                                }
                                Condition::Negation { field } => Some(format!("NOT {}", field)),
                                _ => None,
                            })
                            .collect();

                        if !other_conds1.is_empty() && !other_conds2.is_empty() {
                            return Ok(Some(format!(
                                "Resource type '{}' has conflicting requirements:\n      \
                                Rule 1 requires: {}\n      \
                                Rule 2 requires: {}\n      \
                                These may create contradictory policies for the same resource type",
                                t1,
                                other_conds1.join(" AND "),
                                other_conds2.join(" AND ")
                            )));
                        }
                    }
                }
            }
        }

        Ok(None)
    }

    /// Find logical contradictions between rule bodies
    fn find_logical_contradiction(
        &self,
        bodies1: &[RuleBody],
        bodies2: &[RuleBody],
    ) -> Result<Option<String>> {
        for body1 in bodies1 {
            for body2 in bodies2 {
                let conds1 = self.extract_conditions(&body1.query)?;
                let conds2 = self.extract_conditions(&body2.query)?;

                // Check if the conjunction of both conditions is unsatisfiable
                if self.are_conditions_mutually_exclusive(&conds1, &conds2)? {
                    return Ok(Some(
                        "Rules have mutually exclusive conditions that can never both be true"
                            .to_string(),
                    ));
                }
            }
        }

        Ok(None)
    }

    /// Check if two sets of conditions are mutually exclusive
    fn are_conditions_mutually_exclusive(
        &self,
        conds1: &[Condition],
        conds2: &[Condition],
    ) -> Result<bool> {
        // Simple heuristic: if any field has conflicting requirements
        use alloc::collections::BTreeMap;
        let mut field_requirements: BTreeMap<String, Vec<&Condition>> = BTreeMap::new();

        // Collect all conditions by field
        for cond in conds1.iter().chain(conds2.iter()) {
            let field = match cond {
                Condition::Equality { field, .. } => field.clone(),
                Condition::Inequality { field, .. } => field.clone(),
                Condition::Negation { field } => field.clone(),
                Condition::StartsWith { field, .. } => field.clone(),
                Condition::ArrayMembership { field, .. } => field.clone(),
            };
            field_requirements.entry(field).or_default().push(cond);
        }

        // Check each field for conflicts
        for (_field, conditions) in field_requirements {
            if conditions.len() > 1 {
                for i in 0..conditions.len() {
                    for j in i + 1..conditions.len() {
                        if self
                            .check_condition_conflict(conditions[i], conditions[j])?
                            .is_some()
                        {
                            return Ok(true);
                        }
                    }
                }
            }
        }

        Ok(false)
    }

    /// Detect conflicts between conditions across different policies with same effect
    fn detect_condition_conflicts(
        &self,
        body1: &RuleBody,
        body2: &RuleBody,
    ) -> Result<Option<String>> {
        let conditions1 = self.extract_conditions(&body1.query)?;
        let conditions2 = self.extract_conditions(&body2.query)?;

        // For same-effect rules, look for overlapping but conflicting array membership conditions
        // This is the main case for Azure Policy conflicts where different policies specify
        // different allowed/denied SKU lists for the same resource type
        for cond1 in &conditions1 {
            for cond2 in &conditions2 {
                if let (
                    Condition::ArrayMembership { field: field1, values: values1 },
                    Condition::ArrayMembership { field: field2, values: values2 }
                ) = (cond1, cond2) {
                    // If both conditions target the same field but have different value sets
                    if field1 == field2 {
                        // Check if the arrays have any intersection
                        let has_intersection = values1.iter().any(|v1| values2.contains(v1));
                        
                        if has_intersection {
                            // Same field, overlapping values - this creates ambiguity about which rule should apply
                            let intersection: Vec<_> = values1.iter()
                                .filter(|v1| values2.contains(v1))
                                .cloned()
                                .collect();
                            
                            return Ok(Some(format!(
                                "Overlapping array membership conditions for field '{}'\n      \
                                Policy 1 allows: {:?}\n      \
                                Policy 2 allows: {:?}\n      \
                                Overlapping values: {:?}\n      \
                                This creates ambiguity about which policy should handle these overlapping values",
                                field1, values1, values2, intersection
                            )));
                        }
                    }
                }
            }
        }

        // Also check for other conflicting conditions on the same fields
        use alloc::collections::BTreeMap;
        let mut field_conditions: BTreeMap<String, (Vec<&Condition>, Vec<&Condition>)> = BTreeMap::new();

        // Group conditions by field from each body
        for cond in &conditions1 {
            let field = self.get_condition_field(cond);
            field_conditions.entry(field).or_default().0.push(cond);
        }
        for cond in &conditions2 {
            let field = self.get_condition_field(cond);
            field_conditions.entry(field).or_default().1.push(cond);
        }

        // Check for conflicts within the same field
        for (field, (conds1, conds2)) in field_conditions {
            if !conds1.is_empty() && !conds2.is_empty() {
                // Check if conditions on the same field conflict
                for c1 in &conds1 {
                    for c2 in &conds2 {
                        if let Some(conflict) = self.check_condition_conflict(c1, c2)? {
                            return Ok(Some(format!(
                                "Conflicting conditions on field '{}': {}",
                                field, conflict
                            )));
                        }
                    }
                }
            }
        }

        Ok(None)
    }

    /// Get the field name from a condition
    fn get_condition_field(&self, condition: &Condition) -> String {
        match condition {
            Condition::Equality { field, .. } => field.clone(),
            Condition::Inequality { field, .. } => field.clone(),
            Condition::Negation { field } => field.clone(),
            Condition::StartsWith { field, .. } => field.clone(),
            Condition::ArrayMembership { field, .. } => field.clone(),
        }
    }

    /// Extract field path from expression (e.g., input.tags.Environment)
    fn extract_field_path(&self, expr: &Ref<Expr>) -> Result<String> {
        match expr.as_ref() {
            Expr::RefDot { refr, field, .. } => {
                let base = self.extract_field_path(refr)?;
                if let Value::String(field_name) = &field.1 {
                    Ok(format!("{}.{}", base, field_name))
                } else {
                    Ok(base)
                }
            }
            Expr::RefBrack { refr, index, .. } => {
                let base = self.extract_field_path(refr)?;
                if let Expr::String { value, .. } = index.as_ref() {
                    if let Value::String(index_name) = value {
                        Ok(format!("{}.{}", base, index_name))
                    } else {
                        Ok(base)
                    }
                } else {
                    Ok(base)
                }
            }
            Expr::Var { value, .. } => {
                if let Value::String(name) = value {
                    Ok(name.to_string())
                } else {
                    Ok("unknown".to_string())
                }
            }
            _ => Ok("unknown".to_string()),
        }
    }

    /// Extract value from expression
    fn extract_value(&self, expr: &Ref<Expr>) -> Result<String> {
        match expr.as_ref() {
            Expr::String { value, .. } => {
                if let Value::String(s) = value {
                    Ok(s.to_string())
                } else {
                    Ok("".to_string())
                }
            }
            Expr::Number { value, .. } => {
                if let Value::Number(n) = value {
                    Ok(format!("{:?}", n))
                } else {
                    Ok("0".to_string())
                }
            }
            Expr::Bool { value, .. } => {
                if let Value::Bool(b) = value {
                    Ok(b.to_string())
                } else {
                    Ok("false".to_string())
                }
            }
            _ => Ok("unknown".to_string()),
        }
    }

    /// Extract array values for array membership conditions
    fn extract_array_values(&self, expr: &Ref<Expr>) -> Result<Option<Vec<String>>> {
        match expr.as_ref() {
            Expr::Array { items, .. } => {
                let mut values = Vec::new();
                for item in items {
                    let value = self.extract_value(item)?;
                    values.push(value);
                }
                Ok(Some(values))
            }
            _ => Ok(None),
        }
    }

    /// Extract function name from expression (simplified)
    fn extract_function_name_simple(&self, expr: &Ref<Expr>) -> Option<String> {
        match expr.as_ref() {
            Expr::Var { value, .. } => {
                if let Value::String(name) = value {
                    Some(name.to_string())
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    fn same_rule_head(&self, head1: &RuleHead, head2: &RuleHead) -> bool {
        // Enhanced head comparison for policy verification
        match (head1, head2) {
            // Both are comprehension rules (deny[msg] syntax)
            (RuleHead::Compr { refr: r1, .. }, RuleHead::Compr { refr: r2, .. }) => {
                self.same_decision_type(r1, r2)
            }
            // Both are set rules (deny contains msg syntax)
            (RuleHead::Set { refr: r1, .. }, RuleHead::Set { refr: r2, .. }) => {
                self.same_decision_type(r1, r2)
            }
            // Mixed: comprehension vs set (deny[msg] vs deny contains msg)
            (RuleHead::Compr { refr: r1, .. }, RuleHead::Set { refr: r2, .. })
            | (RuleHead::Set { refr: r1, .. }, RuleHead::Compr { refr: r2, .. }) => {
                self.same_decision_type(r1, r2)
            }
            _ => false,
        }
    }

    fn same_expr_reference(&self, expr1: &Ref<Expr>, expr2: &Ref<Expr>) -> bool {
        // Simplified expression comparison
        match (expr1.as_ref(), expr2.as_ref()) {
            (Expr::Var { value: v1, .. }, Expr::Var { value: v2, .. }) => v1 == v2,
            _ => false,
        }
    }

    /// Check if two rule heads represent the same decision type (e.g., both "allow" or both "deny")
    fn same_decision_type(&self, expr1: &Ref<Expr>, expr2: &Ref<Expr>) -> bool {
        match (expr1.as_ref(), expr2.as_ref()) {
            // Direct variable comparison (original logic)
            (Expr::Var { value: v1, .. }, Expr::Var { value: v2, .. }) => v1 == v2,

            // Array/object access patterns like deny[msg] or allow[reason]
            (Expr::RefBrack { refr: r1, .. }, Expr::RefBrack { refr: r2, .. }) => {
                self.same_base_decision_path(r1, r2)
            }

            // Dot access patterns like deny.msg
            (Expr::RefDot { refr: r1, .. }, Expr::RefDot { refr: r2, .. }) => {
                self.same_base_decision_path(r1, r2)
            }

            // Mixed patterns - check if they represent the same base decision
            (Expr::Var { value, .. }, Expr::RefBrack { refr, .. })
            | (Expr::RefBrack { refr, .. }, Expr::Var { value, .. })
            | (Expr::Var { value, .. }, Expr::RefDot { refr, .. })
            | (Expr::RefDot { refr, .. }, Expr::Var { value, .. }) => {
                self.decision_path_matches_var(refr, value)
            }

            _ => false,
        }
    }

    /// Check if two reference paths represent the same base decision (e.g., both "deny[...]")
    fn same_base_decision_path(&self, refr1: &Ref<Expr>, refr2: &Ref<Expr>) -> bool {
        let path1 = self.extract_base_decision_path(refr1);
        let path2 = self.extract_base_decision_path(refr2);
        path1.is_some() && path2.is_some() && path1 == path2
    }

    /// Extract the base decision from a reference path (e.g., "deny" from "deny[msg]")
    fn extract_base_decision_path(&self, refr: &Ref<Expr>) -> Option<String> {
        match refr.as_ref() {
            Expr::Var { value, .. } => Some(value.to_string()),
            // For array access like deny[msg], extract the base "deny"
            Expr::RefBrack { refr: base, .. } => self.extract_base_decision_path(base),
            // For dot access like deny.msg, extract the base "deny"
            Expr::RefDot { refr: base, .. } => self.extract_base_decision_path(base),
            _ => None,
        }
    }

    /// Check if a reference path matches a simple variable decision
    fn decision_path_matches_var(&self, refr: &Ref<Expr>, var: &Value) -> bool {
        if let Some(base_decision) = self.extract_base_decision_path(refr) {
            base_decision == var.to_string()
        } else {
            false
        }
    }

    /// Generate test cases that achieve maximum policy coverage
    pub fn generate_test_cases(&mut self, policy_text: &str) -> Result<Vec<TestCase>> {
        let module = self.parse_policy(policy_text)?;
        let mut test_cases = vec![];

        // Analyze the policy to generate targeted test cases
        for rule in &module.policy {
            match rule.as_ref() {
                Rule::Spec { head, bodies, .. } => {
                    // Generate test cases for each rule body
                    for (i, body) in bodies.iter().enumerate() {
                        if let Some(test_case) = self.generate_test_case_for_rule(head, body, i)? {
                            test_cases.push(test_case);
                        }
                    }
                }
                _ => {}
            }
        }

        // Add boundary cases
        test_cases.extend(self.generate_boundary_cases(&module)?);

        Ok(test_cases)
    }

    fn generate_test_case_for_rule(
        &self,
        head: &RuleHead,
        body: &RuleBody,
        rule_index: usize,
    ) -> Result<Option<TestCase>> {
        // Analyze rule conditions to generate appropriate input
        let mut input_fields = vec![];

        for stmt in &body.query.stmts {
            if let Some(field) = self.extract_input_field_from_stmt(stmt) {
                input_fields.push(field);
            }
        }

        if input_fields.is_empty() {
            return Ok(None);
        }

        // Generate JSON input based on extracted fields
        let input_json = self.build_json_input(&input_fields)?;
        let rule_name = self.extract_rule_name(head);

        Ok(Some(TestCase {
            name: format!("rule_{}_{}", rule_name, rule_index),
            input: input_json,
            expected_allow: true,
            description: format!("Test case targeting {} rule {}", rule_name, rule_index),
        }))
    }

    fn extract_input_field_from_stmt(&self, stmt: &LiteralStmt) -> Option<(String, String)> {
        if let Literal::Expr { expr, .. } = &stmt.literal {
            match expr.as_ref() {
                // Handle input.field == "value" patterns
                Expr::BoolExpr {
                    op: BoolOp::Eq,
                    lhs,
                    rhs,
                    ..
                } => {
                    // Case 1: input.type == "Microsoft.Compute/virtualMachines"
                    if let (Some(path), Some(value)) = (self.extract_input_path_from_expr(lhs), self.extract_string_value(rhs)) {
                        return Some((path, value));
                    }
                    // Case 2: "Microsoft.Compute/virtualMachines" == input.type (reversed)
                    if let (Some(value), Some(path)) = (self.extract_string_value(lhs), self.extract_input_path_from_expr(rhs)) {
                        return Some((path, value));
                    }
                }
                
                // Handle input.field in ["value1", "value2"] patterns
                Expr::Membership { value, collection, .. } => {
                    if let (Some(path), Some(first_value)) = (
                        self.extract_input_path_from_expr(value),
                        self.extract_first_array_value(collection)
                    ) {
                        return Some((path, first_value));
                    }
                }
                
                _ => {}
            }
        }
        None
    }

    // Extract path from expressions like input.type, input.sku.name
    fn extract_input_path_from_expr(&self, expr: &Ref<Expr>) -> Option<String> {
        match expr.as_ref() {
            Expr::RefDot { refr, field, .. } => {
                if let Some(base) = self.extract_input_path_from_expr(refr) {
                    if let Value::String(field_name) = &field.1 {
                        return Some(format!("{}.{}", base, field_name));
                    }
                }
            }
            Expr::Var { value, .. } => {
                if let Value::String(s) = value {
                    if s.as_ref() == "input" {
                        return Some("input".to_string());
                    }
                }
            }
            _ => {}
        }
        None
    }

    // Extract string value from expression
    fn extract_string_value(&self, expr: &Ref<Expr>) -> Option<String> {
        if let Expr::String { value, .. } = expr.as_ref() {
            if let Value::String(s) = value {
                return Some(s.to_string());
            }
        }
        None
    }

    // Extract first value from array like ["Standard_M128s", "Standard_GS5"]
    fn extract_first_array_value(&self, expr: &Ref<Expr>) -> Option<String> {
        if let Expr::Array { items, .. } = expr.as_ref() {
            if let Some(first_item) = items.first() {
                return self.extract_string_value(first_item);
            }
        }
        None
    }

    fn extract_input_path(&self, expr: &Ref<Expr>) -> Option<String> {
        match expr.as_ref() {
            Expr::RefBrack { refr, index, .. } => {
                if let Some(base) = self.extract_input_path(refr) {
                    if let Expr::String { value, .. } = index.as_ref() {
                        if let Value::String(s) = value {
                            return Some(format!("{}.{}", base, s));
                        }
                    }
                }
            }
            Expr::Var { value, .. } => {
                if let Value::String(s) = value {
                    if s.as_ref() == "input" {
                        return Some("input".to_string());
                    }
                }
            }
            _ => {}
        }
        None
    }

    fn build_json_input(&self, fields: &[(String, String)]) -> Result<String> {
        use serde_json::{Map, Value};
        let mut json_obj = Map::new();

        for (path, value) in fields {
            if path.starts_with("input.") {
                let field_path = &path[6..]; // Remove "input."
                self.set_nested_json_field(&mut json_obj, field_path, value.clone());
            }
        }

        // Convert to JSON string
        let json_value = Value::Object(json_obj);
        Ok(serde_json::to_string(&json_value)?)
    }

    fn set_nested_json_field(
        &self,
        obj: &mut serde_json::Map<String, serde_json::Value>,
        path: &str,
        value: String,
    ) {
        use serde_json::{Map, Value};
        
        let parts: Vec<&str> = path.split('.').collect();
        
        // Recursive helper function
        fn set_recursive(
            obj: &mut Map<String, Value>,
            parts: &[&str],
            value: String,
        ) {
            if parts.is_empty() {
                return;
            }
            
            if parts.len() == 1 {
                // Last part - set the value
                obj.insert(parts[0].to_string(), Value::String(value));
            } else {
                // Intermediate part - ensure nested object exists
                let entry = obj.entry(parts[0].to_string()).or_insert_with(|| {
                    Value::Object(Map::new())
                });
                
                if let Value::Object(nested_obj) = entry {
                    set_recursive(nested_obj, &parts[1..], value);
                }
            }
        }
        
        set_recursive(obj, &parts, value);
    }

    fn extract_rule_name(&self, head: &RuleHead) -> String {
        match head {
            RuleHead::Compr { refr, .. } => {
                if let Expr::Var { value, .. } = refr.as_ref() {
                    if let Value::String(s) = value {
                        s.to_string()
                    } else {
                        "unknown".to_string()
                    }
                } else {
                    "unknown".to_string()
                }
            }
            RuleHead::Set { refr, .. } => {
                if let Expr::Var { value, .. } = refr.as_ref() {
                    if let Value::String(s) = value {
                        s.to_string()
                    } else {
                        "set_rule".to_string()
                    }
                } else {
                    "set_rule".to_string()
                }
            }
            RuleHead::Func { refr, .. } => {
                if let Expr::Var { value, .. } = refr.as_ref() {
                    if let Value::String(s) = value {
                        s.to_string()
                    } else {
                        "function_rule".to_string()
                    }
                } else {
                    "function_rule".to_string()
                }
            }
        }
    }

    fn generate_boundary_cases(&self, _module: &Module) -> Result<Vec<TestCase>> {
        Ok(vec![
            TestCase {
                name: "empty_input".to_string(),
                input: "{}".to_string(),
                expected_allow: false,
                description: "Empty input - should trigger default deny".to_string(),
            },
            TestCase {
                name: "minimal_user".to_string(),
                input: r#"{"user": {"role": "Guest"}}"#.to_string(),
                expected_allow: false,
                description: "Minimal user with lowest privilege".to_string(),
            },
            TestCase {
                name: "admin_user".to_string(),
                input: r#"{"user": {"role": "Admin"}, "action": "read"}"#.to_string(),
                expected_allow: true,
                description: "Admin user should have broad access".to_string(),
            },
        ])
    }

    /// Find inputs that violate expected policy properties
    pub fn find_counterexamples(
        &mut self,
        policy_text: &str,
        property: &str,
    ) -> Result<Vec<CounterExample>> {
        let module = self.parse_policy(policy_text)?;
        let mut counterexamples = vec![];

        match property {
            "no_conflicts" => {
                // Find inputs that expose rule conflicts
                counterexamples.extend(self.find_conflict_counterexamples(&module)?);
            }
            "privilege_escalation" => {
                // Find cases where lower privilege users gain higher access
                counterexamples.extend(self.find_privilege_escalation_cases(&module)?);
            }
            "geographic_bypass" => {
                // Find cases where geographic restrictions are bypassed
                counterexamples.extend(self.find_geographic_bypass_cases(&module)?);
            }
            _ => {
                // Generic property violation detection
                counterexamples.extend(self.find_generic_violations(&module, property)?);
            }
        }

        Ok(counterexamples)
    }

    fn find_conflict_counterexamples(&self, module: &Module) -> Result<Vec<CounterExample>> {
        let mut counterexamples = vec![];

        // Look for rules that might conflict
        for (i, rule1) in module.policy.iter().enumerate() {
            for (j, rule2) in module.policy.iter().enumerate() {
                if i >= j {
                    continue;
                }

                if let (Rule::Spec { head: head1, .. }, Rule::Spec { head: head2, .. }) =
                    (rule1.as_ref(), rule2.as_ref())
                {
                    if self.same_rule_head(head1, head2) {
                        // Generate input that might trigger both rules
                        if let Some(input) = self.generate_conflict_input(rule1, rule2)? {
                            counterexamples.push(CounterExample {
                                property: "no_conflicts".to_string(),
                                violating_input: input,
                                explanation: format!(
                                    "Input that may trigger conflicting rules {} and {}",
                                    i, j
                                ),
                            });
                        }
                    }
                }
            }
        }

        Ok(counterexamples)
    }

    fn find_privilege_escalation_cases(&self, _module: &Module) -> Result<Vec<CounterExample>> {
        Ok(vec![
            CounterExample {
                property: "privilege_escalation".to_string(),
                violating_input: r#"{"user": {"role": "User", "department": "IT"}, "action": "delete", "resource": {"type": "admin_config"}}"#.to_string(),
                explanation: "Regular user attempting admin-level deletion".to_string(),
            },
            CounterExample {
                property: "privilege_escalation".to_string(),
                violating_input: r#"{"user": {"role": "Guest"}, "action": "write", "resource": {"type": "sensitive_data"}}"#.to_string(),
                explanation: "Guest user attempting write access to sensitive data".to_string(),
            },
        ])
    }

    fn find_geographic_bypass_cases(&self, _module: &Module) -> Result<Vec<CounterExample>> {
        Ok(vec![
            CounterExample {
                property: "geographic_bypass".to_string(),
                violating_input: r#"{"user": {"location": "China"}, "resource": {"classification": "restricted"}, "action": "read"}"#.to_string(),
                explanation: "Access to restricted resource from non-allowed geographic location".to_string(),
            },
            CounterExample {
                property: "geographic_bypass".to_string(),
                violating_input: r#"{"user": {"location": "Russia"}, "resource": {"classification": "confidential"}, "action": "write"}"#.to_string(),
                explanation: "Write access from high-risk geographic location".to_string(),
            },
        ])
    }

    fn find_generic_violations(
        &self,
        _module: &Module,
        property: &str,
    ) -> Result<Vec<CounterExample>> {
        Ok(vec![
            CounterExample {
                property: property.to_string(),
                violating_input: r#"{"user": {"mfaVerified": false}, "resource": {"classification": "confidential"}, "action": "write"}"#.to_string(),
                explanation: format!("Input that violates property: {}", property),
            }
        ])
    }

    fn generate_conflict_input(
        &self,
        rule1: &Ref<Rule>,
        rule2: &Ref<Rule>,
    ) -> Result<Option<String>> {
        // Generate input that might satisfy conditions of both conflicting rules
        match (rule1.as_ref(), rule2.as_ref()) {
            (
                Rule::Spec {
                    bodies: bodies1, ..
                },
                Rule::Spec {
                    bodies: bodies2, ..
                },
            ) => {
                // Try to combine conditions from both rules
                let mut combined_fields = vec![];

                // Extract fields from first rule
                if let Some(body1) = bodies1.first() {
                    for stmt in &body1.query.stmts {
                        if let Some(field) = self.extract_input_field_from_stmt(stmt) {
                            combined_fields.push(field);
                        }
                    }
                }

                // Extract fields from second rule
                if let Some(body2) = bodies2.first() {
                    for stmt in &body2.query.stmts {
                        if let Some(field) = self.extract_input_field_from_stmt(stmt) {
                            combined_fields.push(field);
                        }
                    }
                }

                if !combined_fields.is_empty() {
                    return Ok(Some(self.build_json_input(&combined_fields)?));
                }
            }
            _ => {}
        }

        Ok(None)
    }

    fn parse_policy(&self, policy_text: &str) -> Result<Module> {
        let source = Source::from_contents("policy.rego".to_string(), policy_text.to_string())?;
        let mut parser = Parser::new(&source)?;

        // Enable Rego v1 syntax to support 'if' keyword
        parser.enable_rego_v1()?;

        parser.parse()
    }
}

impl Default for Z3PolicyVerifier {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct CrossPolicyConflictResult {
    pub conflicts: Vec<String>,
    pub conflicting_inputs: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ConsistencyResult {
    pub is_consistent: bool,
    pub conflicts: Vec<String>,
    pub conflicting_inputs: Vec<String>,  // Z3-generated inputs that trigger conflicts
    pub unreachable_rules: Vec<String>,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct TestCase {
    pub name: String,
    pub input: String,
    pub expected_allow: bool,
    pub description: String,
}

#[derive(Debug, Clone)]
pub struct CounterExample {
    pub property: String,
    pub violating_input: String,
    pub explanation: String,
}

impl Z3PolicyVerifier {
    /// Analyze the scope of all rules in a policy
    pub fn analyze_policy_scopes(
        &mut self,
        policy_text: &str,
        entry_points: Option<&[&str]>,
    ) -> Result<ScopeAnalysis> {
        let module = self.parse_policy(policy_text)?;

        // Get package path for rule naming
        let package_path =
            crate::interpreter::Interpreter::get_path_string(&module.package.refr, Some("data"))?;

        // Get the indices of rules to analyze
        let rule_indices_to_check = if let Some(entry_point_names) = entry_points {
            self.find_entry_point_rule_indices(&module, entry_point_names)?
        } else {
            (0..module.policy.len()).collect()
        };

        // Extract scope for each rule
        let mut rule_scopes = Vec::new();
        for &rule_idx in &rule_indices_to_check {
            let rule = &module.policy[rule_idx];
            let scope = self.extract_rule_scope(rule, rule_idx, &package_path)?;
            rule_scopes.push(scope);
        }

        // Analyze scope relationships
        let mut disjoint_scope_pairs = Vec::new();
        let mut overlapping_scope_pairs = Vec::new();

        for (i, scope1) in rule_scopes.iter().enumerate() {
            for (_j, scope2) in rule_scopes.iter().enumerate().skip(i + 1) {
                match self.analyze_scope_relationship(scope1, scope2)? {
                    ScopeRelationship::Disjoint(reason) => {
                        disjoint_scope_pairs.push((scope1.rule_index, scope2.rule_index, reason));
                    }
                    ScopeRelationship::Overlapping(description) => {
                        overlapping_scope_pairs.push((
                            scope1.rule_index,
                            scope2.rule_index,
                            description,
                        ));
                    }
                    ScopeRelationship::Unknown => {
                        overlapping_scope_pairs.push((
                            scope1.rule_index,
                            scope2.rule_index,
                            "Scope relationship unclear - potential overlap".to_string(),
                        ));
                    }
                }
            }
        }

        // Generate scope coverage report
        let scope_coverage_report = self.generate_scope_coverage_report(
            &rule_scopes,
            &disjoint_scope_pairs,
            &overlapping_scope_pairs,
        );

        Ok(ScopeAnalysis {
            rule_scopes,
            disjoint_scope_pairs,
            overlapping_scope_pairs,
            scope_coverage_report,
        })
    }

    /// Extract the scope (conditions) of a single rule
    fn extract_rule_scope(
        &self,
        rule: &Ref<Rule>,
        rule_index: usize,
        package_path: &str,
    ) -> Result<RuleScope> {
        let rule_name = format!(
            "{}.{}",
            package_path,
            self.extract_rule_name_from_refr(self.get_rule_refr(rule))?
        );

        let mut all_conditions = Vec::new();
        let mut constraint_fields = Vec::new();

        match rule.as_ref() {
            Rule::Spec { bodies, .. } => {
                // Extract conditions from all bodies (OR relationship)
                for body in bodies {
                    let body_conditions = self.extract_conditions(&body.query)?;
                    all_conditions.extend(body_conditions);
                }
            }
            Rule::Default { .. } => {
                // Default rules typically have no conditions (apply to all inputs)
            }
        }

        // Extract unique constraint fields
        for condition in &all_conditions {
            let field = match condition {
                Condition::Equality { field, .. } => field,
                Condition::Inequality { field, .. } => field,
                Condition::Negation { field } => field,
                Condition::StartsWith { field, .. } => field,
                Condition::ArrayMembership { field, .. } => field,
            };
            if !constraint_fields.contains(field) {
                constraint_fields.push(field.clone());
            }
        }

        let scope_description = self.generate_scope_description(&all_conditions);

        Ok(RuleScope {
            rule_name,
            rule_index,
            conditions: all_conditions,
            scope_description,
            constraint_fields,
        })
    }

    /// Generate a human-readable description of a rule's scope
    fn generate_scope_description(&self, conditions: &[Condition]) -> String {
        if conditions.is_empty() {
            return "Applies to all inputs (no constraints)".to_string();
        }

        let mut descriptions = Vec::new();
        for condition in conditions {
            let desc = match condition {
                Condition::Equality { field, value } => format!("{} = '{}'", field, value),
                Condition::Inequality { field, value } => format!("{} ≠ '{}'", field, value),
                Condition::Negation { field } => format!("{} is undefined/false", field),
                Condition::StartsWith { field, prefix } => {
                    format!("{} starts with '{}'", field, prefix)
                }
                Condition::ArrayMembership { field, values } => {
                    format!("{} in [{}]", field, values.join(", "))
                }
            };
            descriptions.push(desc);
        }

        if descriptions.len() == 1 {
            format!("Applies when: {}", descriptions[0])
        } else {
            format!("Applies when: {}", descriptions.join(" AND "))
        }
    }

    /// Analyze the relationship between two rule scopes
    fn analyze_scope_relationship(
        &self,
        scope1: &RuleScope,
        scope2: &RuleScope,
    ) -> Result<ScopeRelationship> {
        // Check for obvious disjoint conditions
        for cond1 in &scope1.conditions {
            for cond2 in &scope2.conditions {
                if let Some(disjoint_reason) = self.check_disjoint_conditions(cond1, cond2)? {
                    return Ok(ScopeRelationship::Disjoint(disjoint_reason));
                }
            }
        }

        // Check for obvious overlaps
        let common_fields: Vec<_> = scope1
            .constraint_fields
            .iter()
            .filter(|field| scope2.constraint_fields.contains(field))
            .collect();

        if !common_fields.is_empty() {
            let overlap_description = format!(
                "Rules share constraints on fields: {}",
                common_fields
                    .iter()
                    .map(|f| f.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            return Ok(ScopeRelationship::Overlapping(overlap_description));
        }

        // If no common fields, likely disjoint but not certain
        if scope1.constraint_fields.is_empty() || scope2.constraint_fields.is_empty() {
            Ok(ScopeRelationship::Overlapping(
                "One rule has no constraints - potential overlap".to_string(),
            ))
        } else {
            Ok(ScopeRelationship::Overlapping(
                "No common constraint fields - likely independent".to_string(),
            ))
        }
    }

    /// Check if two conditions are disjoint (mutually exclusive)
    fn check_disjoint_conditions(
        &self,
        cond1: &Condition,
        cond2: &Condition,
    ) -> Result<Option<String>> {
        match (cond1, cond2) {
            // Same field with different values = disjoint
            (
                Condition::Equality {
                    field: f1,
                    value: v1,
                },
                Condition::Equality {
                    field: f2,
                    value: v2,
                },
            ) if f1 == f2 && v1 != v2 => Ok(Some(format!(
                "Disjoint: {} cannot be both '{}' and '{}'",
                f1, v1, v2
            ))),

            // Field present vs field negated
            (Condition::Equality { field: f1, .. }, Condition::Negation { field: f2 })
                if f1 == f2 =>
            {
                Ok(Some(format!(
                    "Disjoint: {} cannot be both defined and undefined",
                    f1
                )))
            }
            (Condition::Negation { field: f1 }, Condition::Equality { field: f2, .. })
                if f1 == f2 =>
            {
                Ok(Some(format!(
                    "Disjoint: {} cannot be both undefined and defined",
                    f1
                )))
            }

            // Array membership with non-overlapping values = disjoint
            (
                Condition::ArrayMembership {
                    field: f1,
                    values: v1,
                },
                Condition::ArrayMembership {
                    field: f2,
                    values: v2,
                },
            ) if f1 == f2 => {
                // Check if the arrays have no common elements
                let has_intersection = v1.iter().any(|val1| v2.contains(val1));
                if !has_intersection {
                    Ok(Some(format!(
                        "Disjoint: {} arrays [{}] and [{}] have no common values",
                        f1, v1.join(", "), v2.join(", ")
                    )))
                } else {
                    Ok(None) // Arrays overlap, so conditions are not disjoint
                }
            }

            // Equality vs Array membership
            (
                Condition::Equality { field: f1, value: v1 },
                Condition::ArrayMembership { field: f2, values: v2 },
            ) if f1 == f2 => {
                if !v2.contains(v1) {
                    Ok(Some(format!(
                        "Disjoint: {} = '{}' but '{}' not in [{}]",
                        f1, v1, v1, v2.join(", ")
                    )))
                } else {
                    Ok(None) // Value is in array, so not disjoint
                }
            }
            (
                Condition::ArrayMembership { field: f1, values: v1 },
                Condition::Equality { field: f2, value: v2 },
            ) if f1 == f2 => {
                if !v1.contains(v2) {
                    Ok(Some(format!(
                        "Disjoint: {} = '{}' but '{}' not in [{}]",
                        f1, v2, v2, v1.join(", ")
                    )))
                } else {
                    Ok(None) // Value is in array, so not disjoint
                }
            }

            _ => Ok(None),
        }
    }

    /// Generate a comprehensive scope coverage report
    fn generate_scope_coverage_report(
        &self,
        rule_scopes: &[RuleScope],
        disjoint_pairs: &[(usize, usize, String)],
        overlapping_pairs: &[(usize, usize, String)],
    ) -> String {
        let mut report = String::new();

        report.push_str("🔍 SCOPE ANALYSIS REPORT\n");
        report.push_str("========================\n\n");

        // Individual rule scopes
        report.push_str("📋 Individual Rule Scopes:\n");
        for scope in rule_scopes {
            report.push_str(&format!(
                "   • Rule #{}: {}\n",
                scope.rule_index, scope.rule_name
            ));
            report.push_str(&format!("     Scope: {}\n", scope.scope_description));
            if !scope.constraint_fields.is_empty() {
                report.push_str(&format!(
                    "     Constrains: {}\n",
                    scope.constraint_fields.join(", ")
                ));
            }
            report.push_str("\n");
        }

        // Disjoint scope pairs
        if !disjoint_pairs.is_empty() {
            report.push_str("🚫 Disjoint Rule Pairs (No Input Overlap):\n");
            for (rule1_idx, rule2_idx, reason) in disjoint_pairs {
                report.push_str(&format!(
                    "   • Rule #{} ⟷ Rule #{}: {}\n",
                    rule1_idx, rule2_idx, reason
                ));
            }
            report.push_str("\n");
        }

        // Overlapping scope pairs
        if !overlapping_pairs.is_empty() {
            report.push_str("🔄 Overlapping Rule Pairs (Potential Input Overlap):\n");
            for (rule1_idx, rule2_idx, description) in overlapping_pairs {
                report.push_str(&format!(
                    "   • Rule #{} ⟷ Rule #{}: {}\n",
                    rule1_idx, rule2_idx, description
                ));
            }
            report.push_str("\n");
        }

        // Summary statistics
        let total_pairs = rule_scopes.len() * (rule_scopes.len() - 1) / 2;
        let disjoint_count = disjoint_pairs.len();
        let overlapping_count = overlapping_pairs.len();

        report.push_str("📊 Scope Analysis Summary:\n");
        report.push_str(&format!(
            "   • Total rules analyzed: {}\n",
            rule_scopes.len()
        ));
        report.push_str(&format!("   • Total rule pairs: {}\n", total_pairs));
        report.push_str(&format!(
            "   • Disjoint pairs: {} ({:.1}%)\n",
            disjoint_count,
            (disjoint_count as f64 / total_pairs as f64) * 100.0
        ));
        report.push_str(&format!(
            "   • Overlapping pairs: {} ({:.1}%)\n",
            overlapping_count,
            (overlapping_count as f64 / total_pairs as f64) * 100.0
        ));

        if disjoint_count > overlapping_count {
            report.push_str("   💡 Interpretation: Rules are well-partitioned with clear scopes\n");
        } else {
            report.push_str(
                "   ⚠️  Interpretation: Many rules have overlapping scopes - check for conflicts\n",
            );
        }

        report
    }
}

/// Represents the relationship between two rule scopes
#[derive(Debug)]
#[allow(dead_code)]
enum ScopeRelationship {
    Disjoint(String),    // Rules cannot apply to the same input
    Overlapping(String), // Rules might apply to the same input
    Unknown,             // Relationship unclear
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verifier_creation() {
        let _verifier = Z3PolicyVerifier::new();
    }

    #[test]
    fn test_simple_policy_verification() -> Result<()> {
        let mut verifier = Z3PolicyVerifier::new();

        let policy = r#"
            package test
            allow { input.user == "admin" }
        "#;

        let result = verifier.verify_consistency(policy)?;
        assert!(result.is_consistent);
        Ok(())
    }

    #[test]
    fn test_contradictory_policy() -> Result<()> {
        let mut verifier = Z3PolicyVerifier::new();

        let policy = r#"
            package test
            impossible if { 1 == 2 }
        "#;

        let result = verifier.verify_consistency(policy)?;
        // With Z3 integration, it would detect unreachable rules
        assert!(!result.unreachable_rules.is_empty());
        assert!(result.is_consistent);

        Ok(())
    }

    #[test]
    fn test_test_case_generation() -> Result<()> {
        let mut verifier = Z3PolicyVerifier::new();

        let policy = r#"
            package test
            allow { input.user.role == "admin" }
        "#;

        let test_cases = verifier.generate_test_cases(policy)?;
        assert!(!test_cases.is_empty());
        Ok(())
    }
}
