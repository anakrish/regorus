// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#![allow(dead_code, clippy::missing_const_for_fn)]
#![allow(clippy::unused_self)]

//! Annotation accumulation and metadata population.
//!
//! Stub — real implementation added in a later commit.

use crate::languages::azure_policy::ast::{EffectNode, OperatorKind, PolicyDefinition, PolicyRule};

use super::core::Compiler;

impl Compiler {
    pub(super) fn record_field_kind(&mut self, _name: &str) {}
    pub(super) fn record_alias(&mut self, _path: &str) {}
    pub(super) fn record_tag_name(&mut self, _tag: &str) {}
    pub(super) fn record_operator(&mut self, _kind: &OperatorKind) {}
    pub(super) fn record_resource_type_from_condition(
        &mut self,
        _condition: &crate::languages::azure_policy::ast::Condition,
    ) {
    }

    pub(super) fn resolve_effect_annotation(&self, rule: &PolicyRule) -> alloc::string::String {
        rule.then_block.effect.raw.clone()
    }

    pub(super) fn resolve_effect_kind(
        &self,
        effect: &EffectNode,
    ) -> crate::languages::azure_policy::ast::EffectKind {
        effect.kind.clone()
    }

    pub(super) fn populate_compiled_annotations(&mut self) {}
    pub(super) fn populate_definition_metadata(&mut self, _defn: &PolicyDefinition) {}
}
