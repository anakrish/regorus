use crate::rvm::instructions::{Instruction, LoopMode};
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use anyhow::{anyhow, bail, Result};

/// Parse a textual instruction like "Load { dest: 0, literal_idx: 1 }"
pub fn parse_instruction(text: &str) -> Result<Instruction> {
    let text = text.trim();

    // Find the instruction name and parameters
    if let Some(brace_start) = text.find('{') {
        let name = text[..brace_start].trim();
        let params_text = &text[brace_start..];

        match name {
            "Load" => parse_load(params_text),
            "LoadTrue" => parse_load_true(params_text),
            "LoadFalse" => parse_load_false(params_text),
            "LoadNull" => parse_load_null(params_text),
            "LoadBool" => parse_load_bool(params_text),
            "LoadData" => parse_load_data(params_text),
            "LoadInput" => parse_load_input(params_text),
            "Move" => parse_move(params_text),
            "Add" => parse_add(params_text),
            "Sub" => parse_sub(params_text),
            "Mul" => parse_mul(params_text),
            "Div" => parse_div(params_text),
            "Mod" => parse_mod(params_text),
            "Eq" => parse_eq(params_text),
            "Ne" => parse_ne_instruction(params_text),
            "Lt" => parse_lt(params_text),
            "Le" => parse_le_instruction(params_text),
            "Gt" => parse_gt(params_text),
            "Ge" => parse_ge_instruction(params_text),
            "And" => parse_and(params_text),
            "Or" => parse_or(params_text),
            "Not" => parse_not(params_text),
            "Concat" => parse_concat(params_text),
            "Return" => parse_return(params_text),
            "ObjectNew" => parse_object_new(params_text),
            "ObjectSet" => parse_object_set(params_text),
            "Index" => parse_index(params_text),
            "ArrayNew" => parse_array_new(params_text),
            "ArrayPush" => parse_array_push(params_text),
            "SetNew" => parse_set_new(params_text),
            "SetAdd" => parse_set_add(params_text),
            "Contains" => parse_contains(params_text),
            "AssertCondition" => parse_assert_condition(params_text),
            "LoopStart" => parse_loop_start(params_text),
            "LoopNext" => parse_loop_next(params_text),
            "Halt" => Ok(Instruction::Halt),
            _ => bail!("Unknown instruction: {}", name),
        }
    } else {
        bail!("Invalid instruction format: {}", text);
    }
}

// Parameter parsing helpers
fn parse_params(text: &str) -> Result<Vec<(String, String)>> {
    if !text.starts_with('{') || !text.ends_with('}') {
        bail!("Parameters must be enclosed in braces");
    }

    let inner = &text[1..text.len() - 1];
    let mut params = Vec::new();
    let mut current = String::new();
    let in_value = false;
    let mut colon_pos = None;

    for ch in inner.chars() {
        match ch {
            ':' if !in_value => {
                colon_pos = Some(current.len());
                current.push(ch);
            }
            ',' if !in_value => {
                if let Some(pos) = colon_pos {
                    let key = current[..pos].trim().to_string();
                    let value = current[pos + 1..].trim().to_string();
                    params.push((key, value));
                    current.clear();
                    colon_pos = None;
                } else {
                    bail!("Invalid parameter format");
                }
            }
            _ => current.push(ch),
        }
    }

    // Handle the last parameter
    if !current.trim().is_empty() {
        if let Some(pos) = colon_pos {
            let key = current[..pos].trim().to_string();
            let value = current[pos + 1..].trim().to_string();
            params.push((key, value));
        } else {
            bail!("Invalid parameter format");
        }
    }

    Ok(params)
}

fn get_param_u16(params: &[(String, String)], name: &str) -> Result<u16> {
    for (key, value) in params {
        if key == name {
            return value
                .parse::<u16>()
                .map_err(|_| anyhow!("Invalid u16 value for {}: {}", name, value));
        }
    }
    bail!("Missing parameter: {}", name);
}

fn get_param_bool(params: &[(String, String)], name: &str) -> Result<bool> {
    for (key, value) in params {
        if key == name {
            return value
                .parse::<bool>()
                .map_err(|_| anyhow!("Invalid bool value for {}: {}", name, value));
        }
    }
    bail!("Missing parameter: {}", name);
}

pub fn parse_loop_mode(text: &str) -> Result<LoopMode> {
    match text {
        "Any" => Ok(LoopMode::Any),
        "Every" => Ok(LoopMode::Every),
        "ForEach" => Ok(LoopMode::ForEach),
        "ArrayComprehension" => Ok(LoopMode::ArrayComprehension),
        "SetComprehension" => Ok(LoopMode::SetComprehension),
        "ObjectComprehension" => Ok(LoopMode::ObjectComprehension),
        // Keep backwards compatibility for now
        "Existential" => Ok(LoopMode::Any),
        "Universal" => Ok(LoopMode::Every),
        "Collect" => Ok(LoopMode::ForEach),
        _ => bail!("Invalid loop mode: {}", text),
    }
}

// Individual instruction parsers
fn parse_load(params_text: &str) -> Result<Instruction> {
    let params = parse_params(params_text)?;
    let dest = get_param_u16(&params, "dest")?;
    let literal_idx = get_param_u16(&params, "literal_idx")?;
    Ok(Instruction::Load { dest, literal_idx })
}

fn parse_move(params_text: &str) -> Result<Instruction> {
    let params = parse_params(params_text)?;
    let dest = get_param_u16(&params, "dest")?;
    let src = get_param_u16(&params, "src")?;
    Ok(Instruction::Move { dest, src })
}

fn parse_add(params_text: &str) -> Result<Instruction> {
    let params = parse_params(params_text)?;
    let dest = get_param_u16(&params, "dest")?;
    let left = get_param_u16(&params, "left")?;
    let right = get_param_u16(&params, "right")?;
    Ok(Instruction::Add { dest, left, right })
}

fn parse_sub(params_text: &str) -> Result<Instruction> {
    let params = parse_params(params_text)?;
    let dest = get_param_u16(&params, "dest")?;
    let left = get_param_u16(&params, "left")?;
    let right = get_param_u16(&params, "right")?;
    Ok(Instruction::Sub { dest, left, right })
}

fn parse_mul(params_text: &str) -> Result<Instruction> {
    let params = parse_params(params_text)?;
    let dest = get_param_u16(&params, "dest")?;
    let left = get_param_u16(&params, "left")?;
    let right = get_param_u16(&params, "right")?;
    Ok(Instruction::Mul { dest, left, right })
}

fn parse_div(params_text: &str) -> Result<Instruction> {
    let params = parse_params(params_text)?;
    let dest = get_param_u16(&params, "dest")?;
    let left = get_param_u16(&params, "left")?;
    let right = get_param_u16(&params, "right")?;
    Ok(Instruction::Div { dest, left, right })
}

fn parse_eq(params_text: &str) -> Result<Instruction> {
    let params = parse_params(params_text)?;
    let dest = get_param_u16(&params, "dest")?;
    let left = get_param_u16(&params, "left")?;
    let right = get_param_u16(&params, "right")?;
    Ok(Instruction::Eq { dest, left, right })
}

fn parse_ne_instruction(content: &str) -> Result<Instruction> {
    let params = parse_params(content)?;
    let dest = get_param_u16(&params, "dest")?;
    let left = get_param_u16(&params, "left")?;
    let right = get_param_u16(&params, "right")?;
    Ok(Instruction::Ne { dest, left, right })
}

fn parse_lt(params_text: &str) -> Result<Instruction> {
    let params = parse_params(params_text)?;
    let dest = get_param_u16(&params, "dest")?;
    let left = get_param_u16(&params, "left")?;
    let right = get_param_u16(&params, "right")?;
    Ok(Instruction::Lt { dest, left, right })
}

fn parse_le_instruction(content: &str) -> Result<Instruction> {
    let params = parse_params(content)?;
    let dest = get_param_u16(&params, "dest")?;
    let left = get_param_u16(&params, "left")?;
    let right = get_param_u16(&params, "right")?;
    Ok(Instruction::Le { dest, left, right })
}

fn parse_gt(params_text: &str) -> Result<Instruction> {
    let params = parse_params(params_text)?;
    let dest = get_param_u16(&params, "dest")?;
    let left = get_param_u16(&params, "left")?;
    let right = get_param_u16(&params, "right")?;
    Ok(Instruction::Gt { dest, left, right })
}

fn parse_ge_instruction(content: &str) -> Result<Instruction> {
    let params = parse_params(content)?;
    let dest = get_param_u16(&params, "dest")?;
    let left = get_param_u16(&params, "left")?;
    let right = get_param_u16(&params, "right")?;
    Ok(Instruction::Ge { dest, left, right })
}

fn parse_return(params_text: &str) -> Result<Instruction> {
    let params = parse_params(params_text)?;
    let value = get_param_u16(&params, "value")?;
    Ok(Instruction::Return { value })
}

fn parse_object_new(params_text: &str) -> Result<Instruction> {
    let params = parse_params(params_text)?;
    let dest = get_param_u16(&params, "dest")?;
    Ok(Instruction::ObjectNew { dest })
}

fn parse_object_set(params_text: &str) -> Result<Instruction> {
    let params = parse_params(params_text)?;
    let obj = get_param_u16(&params, "obj")?;
    let key = get_param_u16(&params, "key")?;
    let value = get_param_u16(&params, "value")?;
    Ok(Instruction::ObjectSet { obj, key, value })
}

fn parse_index(params_text: &str) -> Result<Instruction> {
    let params = parse_params(params_text)?;
    let dest = get_param_u16(&params, "dest")?;
    let container = get_param_u16(&params, "container")?;
    let key = get_param_u16(&params, "key")?;
    Ok(Instruction::Index {
        dest,
        container,
        key,
    })
}

fn parse_array_new(params_text: &str) -> Result<Instruction> {
    let params = parse_params(params_text)?;
    let dest = get_param_u16(&params, "dest")?;
    Ok(Instruction::ArrayNew { dest })
}

fn parse_array_push(params_text: &str) -> Result<Instruction> {
    let params = parse_params(params_text)?;
    let arr = get_param_u16(&params, "arr")?;
    let value = get_param_u16(&params, "value")?;
    Ok(Instruction::ArrayPush { arr, value })
}

fn parse_set_new(params_text: &str) -> Result<Instruction> {
    let params = parse_params(params_text)?;
    let dest = get_param_u16(&params, "dest")?;
    Ok(Instruction::SetNew { dest })
}

fn parse_set_add(params_text: &str) -> Result<Instruction> {
    let params = parse_params(params_text)?;
    let set = get_param_u16(&params, "set")?;
    let value = get_param_u16(&params, "value")?;
    Ok(Instruction::SetAdd { set, value })
}

fn parse_contains(params_text: &str) -> Result<Instruction> {
    let params = parse_params(params_text)?;
    let dest = get_param_u16(&params, "dest")?;
    let collection = get_param_u16(&params, "collection")?;
    let value = get_param_u16(&params, "value")?;
    Ok(Instruction::Contains {
        dest,
        collection,
        value,
    })
}

fn parse_assert_condition(params_text: &str) -> Result<Instruction> {
    let params = parse_params(params_text)?;
    let condition = get_param_u16(&params, "condition")?;
    Ok(Instruction::AssertCondition { condition })
}

fn parse_loop_start(params_text: &str) -> Result<Instruction> {
    let params = parse_params(params_text)?;

    // Get params_index parameter - this should be specified in the test
    let params_index = get_param_u16(&params, "params_index")?;

    Ok(Instruction::LoopStart { params_index })
}

fn parse_loop_next(params_text: &str) -> Result<Instruction> {
    let params = parse_params(params_text)?;
    let body_start = get_param_u16(&params, "body_start")?;
    let loop_end = get_param_u16(&params, "loop_end")?;
    Ok(Instruction::LoopNext {
        body_start,
        loop_end,
    })
}

fn parse_load_true(params_text: &str) -> Result<Instruction> {
    let params = parse_params(params_text)?;
    let dest = get_param_u16(&params, "dest")?;
    Ok(Instruction::LoadTrue { dest })
}

fn parse_load_false(params_text: &str) -> Result<Instruction> {
    let params = parse_params(params_text)?;
    let dest = get_param_u16(&params, "dest")?;
    Ok(Instruction::LoadFalse { dest })
}

fn parse_load_null(params_text: &str) -> Result<Instruction> {
    let params = parse_params(params_text)?;
    let dest = get_param_u16(&params, "dest")?;
    Ok(Instruction::LoadNull { dest })
}

fn parse_load_bool(params_text: &str) -> Result<Instruction> {
    let params = parse_params(params_text)?;
    let dest = get_param_u16(&params, "dest")?;
    let value = get_param_bool(&params, "value")?;
    Ok(Instruction::LoadBool { dest, value })
}

fn parse_load_data(params_text: &str) -> Result<Instruction> {
    let params = parse_params(params_text)?;
    let dest = get_param_u16(&params, "dest")?;
    Ok(Instruction::LoadData { dest })
}

fn parse_load_input(params_text: &str) -> Result<Instruction> {
    let params = parse_params(params_text)?;
    let dest = get_param_u16(&params, "dest")?;
    Ok(Instruction::LoadInput { dest })
}

fn parse_mod(params_text: &str) -> Result<Instruction> {
    let params = parse_params(params_text)?;
    let dest = get_param_u16(&params, "dest")?;
    let left = get_param_u16(&params, "left")?;
    let right = get_param_u16(&params, "right")?;
    Ok(Instruction::Mod { dest, left, right })
}

fn parse_and(params_text: &str) -> Result<Instruction> {
    let params = parse_params(params_text)?;
    let dest = get_param_u16(&params, "dest")?;
    let left = get_param_u16(&params, "left")?;
    let right = get_param_u16(&params, "right")?;
    Ok(Instruction::And { dest, left, right })
}

fn parse_or(params_text: &str) -> Result<Instruction> {
    let params = parse_params(params_text)?;
    let dest = get_param_u16(&params, "dest")?;
    let left = get_param_u16(&params, "left")?;
    let right = get_param_u16(&params, "right")?;
    Ok(Instruction::Or { dest, left, right })
}

fn parse_not(params_text: &str) -> Result<Instruction> {
    let params = parse_params(params_text)?;
    let dest = get_param_u16(&params, "dest")?;
    let operand = get_param_u16(&params, "operand")?;
    Ok(Instruction::Not { dest, operand })
}

fn parse_concat(params_text: &str) -> Result<Instruction> {
    let params = parse_params(params_text)?;
    let dest = get_param_u16(&params, "dest")?;
    let left = get_param_u16(&params, "left")?;
    let right = get_param_u16(&params, "right")?;
    Ok(Instruction::Concat { dest, left, right })
}
