pub(crate) mod traversal;

pub(super) use traversal::{
	gather_assigned_vars, gather_input_vars, gather_loop_vars, gather_vars, traverse, Scope,
};
