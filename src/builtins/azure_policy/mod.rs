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

pub mod helpers;
mod operators;
mod template_functions;
mod template_functions_collection;
mod template_functions_datetime;
mod template_functions_encoding;
mod template_functions_numeric;
mod template_functions_string;

use crate::builtins;

pub fn register(m: &mut builtins::BuiltinsMap<&'static str, builtins::BuiltinFcn>) {
    // Logic functions
    m.insert("azure.policy.logic_all", (operators::logic_all, 0));
    m.insert("azure.policy.if", (operators::if_fn, 3));

    // Field resolution
    m.insert("azure.policy.resolve_field", (operators::resolve_field, 2));

    // Parameter resolution with default-value fallback
    m.insert("azure.policy.get_parameter", (operators::get_parameter, 3));

    // ARM template functions
    template_functions::register(m);
    template_functions_string::register(m);
    template_functions_encoding::register(m);
    template_functions_collection::register(m);
    template_functions_numeric::register(m);
    template_functions_datetime::register(m);
}
