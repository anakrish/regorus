// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Azure Policy builtins: operators, logic functions, and ARM template functions.

#![allow(
    clippy::as_conversions,
    clippy::indexing_slicing,
    clippy::missing_const_for_fn,
    clippy::pattern_type_mismatch,
    clippy::unused_trait_names
)]

mod helpers;
mod operators;
mod template_functions;

use crate::builtins;

pub fn register(m: &mut builtins::BuiltinsMap<&'static str, builtins::BuiltinFcn>) {
    // Logic functions
    m.insert("azure.policy.logic_all", (operators::logic_all, 0));
    m.insert("azure.policy.logic_any", (operators::logic_any, 0));
    m.insert("azure.policy.logic_not", (operators::logic_not, 1));
    m.insert("azure.policy.if", (operators::if_fn, 3));

    // Comparison operators
    m.insert("azure.policy.op.equals", (operators::op_equals, 2));
    m.insert("azure.policy.op.not_equals", (operators::op_not_equals, 2));
    m.insert("azure.policy.op.greater", (operators::op_greater, 2));
    m.insert(
        "azure.policy.op.greater_or_equals",
        (operators::op_greater_or_equals, 2),
    );
    m.insert("azure.policy.op.less", (operators::op_less, 2));
    m.insert(
        "azure.policy.op.less_or_equals",
        (operators::op_less_or_equals, 2),
    );

    // Set membership
    m.insert("azure.policy.op.in", (operators::op_in, 2));
    m.insert("azure.policy.op.not_in", (operators::op_not_in, 2));

    // String/collection contains
    m.insert("azure.policy.op.contains", (operators::op_contains, 2));
    m.insert(
        "azure.policy.op.not_contains",
        (operators::op_not_contains, 2),
    );
    m.insert(
        "azure.policy.op.contains_key",
        (operators::op_contains_key, 2),
    );
    m.insert(
        "azure.policy.op.not_contains_key",
        (operators::op_not_contains_key, 2),
    );

    // Pattern matching
    m.insert("azure.policy.op.like", (operators::op_like, 2));
    m.insert("azure.policy.op.not_like", (operators::op_not_like, 2));
    m.insert("azure.policy.op.match", (operators::op_match, 2));
    m.insert("azure.policy.op.not_match", (operators::op_not_match, 2));
    m.insert(
        "azure.policy.op.match_insensitively",
        (operators::op_match_insensitively, 2),
    );
    m.insert(
        "azure.policy.op.not_match_insensitively",
        (operators::op_not_match_insensitively, 2),
    );

    // Exists
    m.insert("azure.policy.op.exists", (operators::op_exists, 2));

    // Field resolution
    m.insert("azure.policy.resolve_field", (operators::resolve_field, 2));

    // Parameter resolution with default-value fallback
    m.insert("azure.policy.get_parameter", (operators::get_parameter, 3));

    // ARM template functions
    template_functions::register(m);
}
