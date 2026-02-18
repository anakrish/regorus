// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::error::{CompilerError, Result, SpannedCompilerError};
use crate::Value;
use alloc::string::{String, ToString as _};
use alloc::vec::Vec;

pub fn path_to_string(path: &[Value]) -> Result<Value> {
    let mut parts: Vec<String> = Vec::new();
    for part in path {
        let part_str = part
            .as_string()
            .map_err(|_| SpannedCompilerError::from(CompilerError::InvalidPath))?;
        parts.push(part_str.as_ref().to_string());
    }
    Ok(Value::String(parts.join("::").into()))
}

pub fn path_to_name(path: &[Value]) -> Result<String> {
    let mut parts: Vec<String> = Vec::new();
    for part in path {
        let part_str = part
            .as_string()
            .map_err(|_| SpannedCompilerError::from(CompilerError::InvalidPath))?;
        parts.push(part_str.as_ref().to_string());
    }
    Ok(parts.join("::"))
}
