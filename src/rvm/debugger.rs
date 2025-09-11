use super::assembly_listing::{
    generate_assembly_listing, generate_tabular_assembly_listing, AssemblyListingConfig,
};
use super::instructions::Instruction;
use super::program::Program;
use super::vm::{CallRuleContext, LoopContext};
use crate::value::Value;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use std::collections::HashSet;
use std::io::Write;
use std::{print, println};

/// Debug context containing all VM state information
pub struct DebugContext<'a> {
    pub pc: usize,
    pub instruction: &'a Instruction,
    pub registers: &'a [Value],
    pub call_rule_stack: &'a [CallRuleContext],
    pub loop_stack: &'a [LoopContext],
    pub executed_instructions: usize,
    pub program: &'a Program,
}

/// Interactive debugger for RVM execution
/// Enhanced version with comprehensive debugging features
#[derive(Debug)]
pub struct InteractiveDebugger {
    pub enabled: bool,
    pub step_mode: bool,
    pub breakpoints: HashSet<usize>,
    pub auto_break_on_loops: bool,
    pub auto_break_on_rules: bool,
    pub last_valid_source_index: usize,
    pub last_valid_line: usize,
    pub recently_changed_registers: Vec<usize>, // Track recently changed registers
    pub previous_registers: Vec<Value>,         // Previous register values for comparison
}

impl Default for InteractiveDebugger {
    fn default() -> Self {
        Self::new()
    }
}

impl InteractiveDebugger {
    pub fn new() -> Self {
        Self {
            enabled: std::env::var("RVM_INTERACTIVE_DEBUG")
                .map(|v| v == "1" || v.to_lowercase() == "true")
                .unwrap_or(false),
            step_mode: std::env::var("RVM_STEP_MODE")
                .map(|v| v == "1" || v.to_lowercase() == "true")
                .unwrap_or(false),
            breakpoints: {
                let mut set = HashSet::new();
                if let Ok(bp_str) = std::env::var("RVM_BREAKPOINT") {
                    for bp in bp_str.split(',') {
                        if let Ok(pc) = bp.trim().parse::<usize>() {
                            set.insert(pc);
                        }
                    }
                }
                set
            },
            auto_break_on_loops: std::env::var("RVM_BREAK_ON_LOOPS")
                .map(|v| v == "1" || v.to_lowercase() == "true")
                .unwrap_or(false),
            auto_break_on_rules: std::env::var("RVM_BREAK_ON_RULES")
                .map(|v| v == "1" || v.to_lowercase() == "true")
                .unwrap_or(false),
            last_valid_source_index: 0,
            last_valid_line: 1,
            recently_changed_registers: Vec::new(),
            previous_registers: Vec::new(),
        }
    }

    pub fn should_break(&self, pc: usize, instruction: &Instruction) -> bool {
        if !self.enabled {
            return false;
        }

        // Always break in step mode
        if self.step_mode {
            return true;
        }

        // Break on specific breakpoints
        if self.breakpoints.contains(&pc) {
            return true;
        }

        // Auto-break on certain instruction types
        match instruction {
            Instruction::LoopStart { .. } if self.auto_break_on_loops => true,
            Instruction::CallRule { .. } if self.auto_break_on_rules => true,
            Instruction::AssertCondition { .. } => true, // Always break on assertions for debugging
            _ => false,
        }
    }

    /// Update register tracking to identify recently changed registers
    pub fn update_register_tracking(&mut self, current_registers: &[Value]) {
        // Find registers that have changed
        let mut changed = Vec::new();

        for (i, register) in current_registers.iter().enumerate() {
            // Check if this register has changed since last update
            if i >= self.previous_registers.len() || self.previous_registers[i] != *register {
                changed.push(i);
            }
        }

        // Update recently changed list (keep only last 8 changes)
        for reg_idx in changed {
            if !self.recently_changed_registers.contains(&reg_idx) {
                self.recently_changed_registers.insert(0, reg_idx);
            }
        }

        // Keep only the 8 most recent changes
        self.recently_changed_registers.truncate(8);

        // Update previous registers
        self.previous_registers = current_registers.to_vec();
    }

    pub fn debug_prompt(&mut self, ctx: &DebugContext) {
        // Update register tracking
        self.update_register_tracking(ctx.registers);

        // Clear screen and reset cursor to top
        print!("\x1B[2J\x1B[H");
        std::io::stdout().flush().unwrap();

        // Get terminal size (default to 160x40 if detection fails)
        let (term_width, term_height) = self.get_terminal_size().unwrap_or((160, 40));
        let half_width = (term_width - 3) / 2; // Account for border

        // Header
        self.draw_header(ctx.executed_instructions, ctx.pc, term_width);

        // Main content area with side-by-side layout
        self.draw_side_by_side_content(
            ctx.pc,
            ctx.instruction,
            ctx.program,
            term_width,
            half_width,
            term_height,
        );

        // Bottom section: registers and stacks
        self.draw_bottom_section(
            ctx.registers,
            ctx.call_rule_stack,
            ctx.loop_stack,
            ctx.pc,
            ctx.program,
            term_width,
        );

        // Command prompt
        self.draw_command_prompt(term_width);

        // Ensure all output is flushed before entering command loop
        std::io::stdout().flush().unwrap();

        // Main command loop - pass all context for enhanced commands
        self.handle_debug_commands(ctx);
    }

    fn get_terminal_size(&self) -> Option<(usize, usize)> {
        // Try to get terminal size from environment
        if let (Ok(cols), Ok(rows)) = (std::env::var("COLUMNS"), std::env::var("LINES")) {
            if let (Ok(w), Ok(h)) = (cols.parse::<usize>(), rows.parse::<usize>()) {
                return Some((w, h));
            }
        }
        None
    }

    fn draw_header(&self, executed_instructions: usize, pc: usize, width: usize) {
        let title = format!(
            " RVM Interactive Debugger - Step {} at PC {} ",
            executed_instructions, pc
        );
        let padding = if title.len() < width {
            (width - title.len()) / 2
        } else {
            0
        };

        println!("┌{}┐", "─".repeat(width - 2));
        println!(
            "│{}{}{}│",
            " ".repeat(padding),
            title,
            " ".repeat(width - 2 - padding - title.len())
        );
        println!("├{}┤", "─".repeat(width - 2));
    }

    fn draw_side_by_side_content(
        &mut self,
        pc: usize,
        _instruction: &Instruction,
        program: &Program,
        _width: usize,
        half_width: usize,
        height: usize,
    ) {
        let content_height = height - 10; // Reserve space for header, registers, commands
        let rego_lines = self.get_rego_display_lines(pc, program, content_height);
        let instruction_lines = self.get_instruction_display_lines(pc, program, content_height);

        // Header row for the two panels - Instructions first, then Source
        println!(
            "│ {:<width$} │ {:<width$} │",
            "� Instructions",
            "� Rego Source",
            width = half_width - 2
        );
        println!("├{}┼{}┤", "─".repeat(half_width), "─".repeat(half_width));

        // Content rows - Instructions first, then Source
        for i in 0..content_height {
            let rego_line = if i < rego_lines.len() {
                &rego_lines[i]
            } else {
                ""
            };
            let inst_line = if i < instruction_lines.len() {
                &instruction_lines[i]
            } else {
                ""
            };

            println!(
                "│ {:<width$} │ {:<width$} │",
                self.truncate_or_pad(inst_line, half_width - 2),
                self.truncate_or_pad(rego_line, half_width - 2),
                width = half_width - 2
            );
        }
    }

    fn get_rego_display_lines(
        &mut self,
        pc: usize,
        program: &Program,
        max_lines: usize,
    ) -> Vec<String> {
        let mut lines = Vec::new();

        if program.sources.is_empty() {
            lines.push(String::from("No source available"));
            return lines;
        }

        let current_span = program.get_instruction_span(pc);

        // Validate span to check if it's reasonable for highlighting
        let is_valid_span = |span: &super::program::SpanInfo| {
            // Check basic validity
            span.source_index < program.sources.len() &&
            span.line > 0 &&
            span.column > 0 &&
            span.length > 0 &&
            // Ensure span is not excessively long (likely a temporary/invalid span)
            span.length < 200 && // Reasonable max expression length
            {
                // Check that the span doesn't extend beyond reasonable bounds
                let source_content = &program.sources[span.source_index].content;
                let source_lines: Vec<&str> = source_content.lines().collect();
                if span.line <= source_lines.len() {
                    let line_content = source_lines[span.line - 1];
                    span.column <= line_content.len() + 1 &&
                    span.length <= line_content.len() &&
                    (span.column - 1 + span.length) <= line_content.len() &&
                    // Critical fix: Highlight should not extend beyond a single line
                    // Check that the span doesn't contain newlines or extend to next line
                    {
                        let start_pos = span.column.saturating_sub(1);
                        let end_pos = start_pos + span.length;
                        // Ensure we don't go beyond the current line
                        end_pos <= line_content.len() &&
                        // Also check that the span content doesn't contain newlines
                        !line_content[start_pos..end_pos.min(line_content.len())].contains('\n')
                    }
                } else {
                    false
                }
            }
        };

        // Find the correct source file and line info, with fallback to last valid info
        let (source_lines, current_line, validated_span) = if let Some(span) = current_span {
            if is_valid_span(&span) && span.source_index < program.sources.len() {
                // Update last valid source info only for valid spans
                self.last_valid_source_index = span.source_index;
                self.last_valid_line = span.line;

                let source_content = &program.sources[span.source_index].content;
                let source_lines: Vec<&str> = source_content.lines().collect();
                (source_lines, span.line, Some(span))
            } else {
                // Invalid span - don't update highlight position, use last valid source info
                if self.last_valid_source_index < program.sources.len() {
                    let source_content = &program.sources[self.last_valid_source_index].content;
                    let source_lines: Vec<&str> = source_content.lines().collect();
                    (source_lines, self.last_valid_line, None)
                } else {
                    let source_lines: Vec<&str> = program.sources[0].content.lines().collect();
                    (source_lines, 1, None)
                }
            }
        } else {
            // No span info, use last valid source info if available
            if self.last_valid_source_index < program.sources.len() {
                let source_content = &program.sources[self.last_valid_source_index].content;
                let source_lines: Vec<&str> = source_content.lines().collect();
                (source_lines, self.last_valid_line, None)
            } else {
                let source_lines: Vec<&str> = program.sources[0].content.lines().collect();
                (source_lines, 1, None)
            }
        };

        // Show a window around the current line
        let start_line = if current_line > max_lines / 2 {
            current_line - max_lines / 2
        } else {
            1
        };
        let end_line = std::cmp::min(source_lines.len(), start_line + max_lines - 1);

        for line_num in start_line..=end_line {
            if line_num <= source_lines.len() {
                let line_content = source_lines[line_num - 1];
                let is_current = if let Some(span) = validated_span {
                    span.line == line_num
                } else {
                    false
                };

                if is_current {
                    // Highlight the current line and expression with color
                    if let Some(span) = validated_span {
                        let col = if span.column > 0 { span.column - 1 } else { 0 };
                        if col < line_content.len() {
                            let end_col = (col + span.length).min(line_content.len());

                            // Only highlight if the span length is reasonable and not too large
                            // Be more restrictive: max 25 chars and max 1/4 of line length
                            if span.length > 0
                                && span.length <= 25
                                && span.length <= line_content.len() / 4
                            {
                                // Split the line into: before expression | expression | after expression
                                let before = &line_content[..col];
                                let expression = &line_content[col..end_col];
                                let after = &line_content[end_col..];

                                // Use ANSI colors: \x1b[43m\x1b[30m for yellow background with black text
                                let highlighted_line = format!(
                                    "*** {:3}: {}\x1b[43m\x1b[30m{}\x1b[0m{}",
                                    line_num, before, expression, after
                                );
                                lines.push(highlighted_line);
                            } else {
                                // Fallback if span is too large - just mark the line
                                lines.push(format!("*** {:3}: {}", line_num, line_content));
                            }
                        } else {
                            // Fallback if column is out of bounds
                            lines.push(format!("*** {:3}: {}", line_num, line_content));
                        }
                    } else {
                        lines.push(format!("*** {:3}: {}", line_num, line_content));
                    }

                    // Add cursor line if we have span info and it's reasonable
                    if let Some(span) = validated_span {
                        if span.column > 0
                            && span.column <= line_content.len() + 1
                            && span.length > 0
                            && span.length <= 25
                            && span.length <= line_content.len() / 4
                        {
                            let prefix_len = 8; // Length of "*** 123: "
                            let col_offset = span.column.saturating_sub(1);
                            let cursor_length = std::cmp::min(
                                std::cmp::max(1, span.length),
                                line_content.len().saturating_sub(col_offset),
                            );

                            let cursor_indicator = format!(
                                "{}{}{}",
                                " ".repeat(prefix_len + col_offset),
                                "^".repeat(cursor_length),
                                if span.length > 1 {
                                    format!(" ({})", span.length)
                                } else {
                                    String::new()
                                }
                            );
                            lines.push(cursor_indicator);
                        }
                    }
                } else {
                    lines.push(format!("    {:3}: {}", line_num, line_content));
                }
            }
        }

        lines
    }

    fn get_instruction_display_lines(
        &self,
        pc: usize,
        program: &Program,
        max_lines: usize,
    ) -> Vec<String> {
        let mut lines = Vec::new();

        // Use enhanced assembly listing for better formatting
        let config = AssemblyListingConfig {
            show_addresses: true,
            show_bytes: false,
            indent_size: 2, // Smaller indent for side panel
            instruction_width: 30,
            show_literal_values: false, // Too verbose for side panel
            comment_column: 40,
        };

        let listing = generate_assembly_listing(program, &config);
        let assembly_lines: Vec<&str> = listing.lines().collect();

        // Find the line containing current PC
        let mut current_line_idx = None;
        for (idx, line) in assembly_lines.iter().enumerate() {
            if line.contains(&format!("{:03}:", pc)) {
                current_line_idx = Some(idx);
                break;
            }
        }

        // Show context around current PC
        let context_size = max_lines / 2;
        let start_idx = if let Some(curr_idx) = current_line_idx {
            curr_idx.saturating_sub(context_size)
        } else {
            0
        };
        let end_idx = (start_idx + max_lines).min(assembly_lines.len());

        for (idx, line) in assembly_lines[start_idx..end_idx].iter().enumerate() {
            let actual_idx = start_idx + idx;
            let is_current = current_line_idx == Some(actual_idx);

            // Skip comment lines (starting with ;) to save space
            if line.trim_start().starts_with(';') {
                continue;
            }

            let display_line = if is_current {
                format!(">>> {}", line.trim())
            } else {
                format!("    {}", line.trim())
            };

            lines.push(display_line);

            if lines.len() >= max_lines {
                break;
            }
        }

        // If we still have space and didn't find the current PC, fall back to old method
        if lines.is_empty() {
            let start_pc = pc.saturating_sub(max_lines / 2);
            let end_pc = (start_pc + max_lines).min(program.instructions.len());

            for i in start_pc..end_pc {
                if i < program.instructions.len() {
                    let marker = if i == pc { ">>>" } else { "   " };
                    let inst = &program.instructions[i];
                    lines.push(format!("{} {:3}: {:?}", marker, i, inst));
                }
            }
        }

        lines
    }

    fn draw_bottom_section(
        &self,
        registers: &[Value],
        call_rule_stack: &[CallRuleContext],
        loop_stack: &[LoopContext],
        _pc: usize,
        _program: &Program,
        width: usize,
    ) {
        println!("├{}┤", "─".repeat(width - 2));

        // Recently changed registers in a compact format
        println!(
            "│ {:<width$} │",
            "📊 Recently Changed Registers",
            width = width - 4
        );

        let mut reg_lines = Vec::new();
        let mut displayed_count = 0;

        // Show recently changed registers first
        for &reg_idx in &self.recently_changed_registers {
            if displayed_count >= 8 {
                break;
            } // Limit to 8 registers
            if reg_idx < registers.len() {
                let register = &registers[reg_idx];
                if *register != Value::Null && *register != Value::Undefined {
                    let type_indicator = match register {
                        Value::Set(_) => "Set",
                        Value::Array(_) => "Array",
                        Value::Object(_) => "Object",
                        Value::String(_) => "String",
                        Value::Number(_) => "Number",
                        Value::Bool(_) => "Bool",
                        _ => "Other",
                    };

                    let val_json = self.value_to_compact_json(register);
                    let truncated = if val_json.len() > 40 {
                        format!("{}...", &val_json[..37])
                    } else {
                        val_json
                    };

                    reg_lines.push(format!(
                        "r{:2} ({:6}): {}",
                        reg_idx, type_indicator, truncated
                    ));
                    displayed_count += 1;
                }
            }
        }

        // If we have fewer than 8 recently changed, fill with other active registers
        if displayed_count < 8 {
            for (i, register) in registers.iter().enumerate().take(16) {
                if displayed_count >= 8 {
                    break;
                }
                if !self.recently_changed_registers.contains(&i)
                    && *register != Value::Null
                    && *register != Value::Undefined
                {
                    let type_indicator = match register {
                        Value::Set(_) => "Set",
                        Value::Array(_) => "Array",
                        Value::Object(_) => "Object",
                        Value::String(_) => "String",
                        Value::Number(_) => "Number",
                        Value::Bool(_) => "Bool",
                        _ => "Other",
                    };

                    let val_json = self.value_to_compact_json(register);
                    let truncated = if val_json.len() > 40 {
                        format!("{}...", &val_json[..37])
                    } else {
                        val_json
                    };

                    reg_lines.push(format!("r{:2} ({:6}): {}", i, type_indicator, truncated));
                    displayed_count += 1;
                }
            }
        }

        if reg_lines.is_empty() {
            println!(
                "│ {:<width$} │",
                "  (No active registers)",
                width = width - 4
            );
        } else {
            for reg_line in reg_lines {
                println!(
                    "│ {:<width$} │",
                    format!("  {}", reg_line),
                    width = width - 4
                );
            }
        }

        // Show stacks if present
        if !call_rule_stack.is_empty() || !loop_stack.is_empty() {
            let mut stack_info = Vec::new();
            if !call_rule_stack.is_empty() {
                stack_info.push(format!("📞 Call:{}", call_rule_stack.len()));
            }
            if !loop_stack.is_empty() {
                stack_info.push(format!("🔄 Loop:{}", loop_stack.len()));
            }
            println!(
                "│ {:<width$} │",
                format!("  {}", stack_info.join(" ")),
                width = width - 4
            );
        }
    }

    fn draw_command_prompt(&self, width: usize) {
        println!("├{}┤", "─".repeat(width - 2));
        println!(
            "│ {:<width$} │",
            "💻 Commands: (c)ontinue (s)tep (l)ist (asm)embly (r)egisters (cs)call-stack (ls)loop-stack (h)elp (q)uit",
            width = width - 4
        );
        println!("└{}┘", "─".repeat(width - 2));
        print!("debug> ");
        std::io::stdout().flush().unwrap();
    }

    fn truncate_or_pad(&self, text: &str, width: usize) -> String {
        if text.len() > width {
            format!("{}...", &text[..width.saturating_sub(3)])
        } else {
            format!("{:<width$}", text, width = width)
        }
    }

    /// Convert a value to compact JSON string (no pretty formatting)
    fn value_to_compact_json(&self, value: &Value) -> String {
        serde_json::to_string(value)
            .unwrap_or_else(|_| format!("{:?}", value))
            .replace(['\n', '\r'], " ")
    }

    fn handle_debug_commands(&mut self, ctx: &DebugContext) {
        loop {
            let mut input = String::new();
            if std::io::stdin().read_line(&mut input).is_ok() {
                let command = input.trim().to_lowercase();

                match command.as_str() {
                    "c" | "continue" => {
                        self.step_mode = false;
                        break;
                    }
                    "s" | "step" => {
                        self.step_mode = true;
                        break;
                    }
                    "n" | "next" => {
                        self.step_mode = true;
                        break;
                    }
                    "l" | "list" => {
                        self.show_enhanced_assembly_listing(ctx);
                        return;
                    }
                    "lt" | "list-tabular" => {
                        self.show_tabular_assembly_listing(ctx);
                        return;
                    }
                    "asm" | "assembly" => {
                        self.show_full_assembly_listing(ctx);
                        return;
                    }
                    "r" | "registers" => {
                        self.show_detailed_registers(ctx);
                        return;
                    }
                    "cs" | "call-stack" => {
                        self.show_call_stack_details(ctx.call_rule_stack, ctx.program);
                        return;
                    }
                    "ls" | "loop-stack" => {
                        self.show_loop_stack_details(ctx.loop_stack);
                        return;
                    }
                    "ctx" | "context" => {
                        self.show_vm_context(ctx);
                        return;
                    }
                    "src" | "source" => {
                        self.show_extended_source(ctx.pc, ctx.program);
                        return;
                    }
                    "q" | "quit" => {
                        self.enabled = false;
                        std::process::exit(0); // Exit the entire program
                    }
                    _ if command.starts_with("b ") => {
                        if let Ok(break_pc) = command[2..].trim().parse::<usize>() {
                            self.breakpoints.insert(break_pc);
                            print!("\x1B[2J\x1B[H");
                            println!("✅ Breakpoint set at PC {}", break_pc);
                            println!("Press Enter to continue...");
                            let mut _dummy = String::new();
                            std::io::stdin().read_line(&mut _dummy).ok();
                            continue;
                        } else {
                            print!("\x1B[2J\x1B[H");
                            println!("❌ Invalid PC number");
                            println!("Press Enter to continue...");
                            let mut _dummy = String::new();
                            std::io::stdin().read_line(&mut _dummy).ok();
                            continue;
                        }
                    }
                    "help" | "h" => {
                        self.show_help();
                        continue;
                    }
                    "" => {
                        // Empty command, just step
                        self.step_mode = true;
                        break;
                    }
                    _ => {
                        print!("\x1B[2J\x1B[H");
                        println!(
                            "❌ Unknown command '{}'. Type 'help' for available commands.",
                            command
                        );
                        println!("Press Enter to continue...");
                        let mut _dummy = String::new();
                        std::io::stdin().read_line(&mut _dummy).ok();
                        continue;
                    }
                }
            } else {
                break;
            }
        }
    }

    /// Helper method to get the source expression that produced a register value
    fn get_register_source_expression(
        &self,
        reg: usize,
        current_pc: usize,
        program: &Program,
    ) -> Option<String> {
        // Look backwards through instructions to find where this register was last assigned
        for pc in (0..=current_pc).rev() {
            if pc >= program.instructions.len() {
                continue;
            }

            let instruction = &program.instructions[pc];

            // Check if this instruction writes to our register
            let writes_to_reg = match instruction {
                Instruction::Load { dest, .. } => *dest as usize == reg,
                Instruction::Move { dest, .. } => *dest as usize == reg,
                Instruction::LoadInput { dest } => *dest as usize == reg,
                Instruction::Index { dest, .. } => *dest as usize == reg,
                Instruction::IndexLiteral { dest, .. } => *dest as usize == reg,
                Instruction::Eq { dest, .. } => *dest as usize == reg,
                Instruction::Add { dest, .. } => *dest as usize == reg,
                Instruction::Sub { dest, .. } => *dest as usize == reg,
                Instruction::Mul { dest, .. } => *dest as usize == reg,
                Instruction::Div { dest, .. } => *dest as usize == reg,
                _ => false,
            };

            if writes_to_reg {
                // Get span information for this instruction
                if let Some(span) = program.get_instruction_span(pc) {
                    if span.source_index < program.sources.len() {
                        let source = &program.sources[span.source_index];
                        let lines: Vec<&str> = source.content.lines().collect();

                        if span.line > 0 && span.line <= lines.len() {
                            let line = lines[span.line - 1];
                            let start_col = if span.column > 0 { span.column - 1 } else { 0 };
                            let end_col = std::cmp::min(start_col + span.length, line.len());

                            if start_col < line.len() {
                                let expr = &line[start_col..end_col];
                                return Some(format!("{}:{}", span.line, expr.trim()));
                            }
                        }
                    }
                }

                // Fallback: describe the instruction type
                return Some(match instruction {
                    Instruction::Load { literal_idx, .. } => {
                        if let Some(literal) = program.literals.get(*literal_idx as usize) {
                            format!("literal {:?}", literal)
                        } else {
                            format!("literal[{}]", literal_idx)
                        }
                    }
                    Instruction::Move { src, .. } => format!("R{}", src),
                    Instruction::LoadInput { .. } => String::from("input"),
                    Instruction::Index { container, key, .. } => {
                        format!("R{}[R{}]", container, key)
                    }
                    Instruction::IndexLiteral {
                        container,
                        literal_idx,
                        ..
                    } => {
                        if let Some(literal) = program.literals.get(*literal_idx as usize) {
                            format!("R{}[{:?}]", container, literal)
                        } else {
                            format!("R{}[L({})]", container, literal_idx)
                        }
                    }
                    Instruction::Eq { left, right, .. } => format!("R{} == R{}", left, right),
                    Instruction::Add { left, right, .. } => format!("R{} + R{}", left, right),
                    Instruction::Sub { left, right, .. } => format!("R{} - R{}", left, right),
                    Instruction::Mul { left, right, .. } => format!("R{} * R{}", left, right),
                    Instruction::Div { left, right, .. } => format!("R{} / R{}", left, right),
                    _ => String::from("unknown"),
                });
            }
        }

        None
    }

    /// Show detailed register information
    fn show_detailed_registers(&self, ctx: &DebugContext) {
        print!("\x1B[2J\x1B[H");
        println!("┌{}┐", "─".repeat(140));
        println!("│ {:<138} │", "📊 All Registers - Detailed View");
        println!("├{}┤", "─".repeat(140));

        for (i, register) in ctx
            .registers
            .iter()
            .enumerate()
            .take(std::cmp::min(ctx.registers.len(), 32))
        {
            if *register != Value::Null || i < 16 {
                let type_indicator = match register {
                    Value::Set(_) => "Set",
                    Value::Array(_) => "Array",
                    Value::Object(_) => "Object",
                    Value::String(_) => "String",
                    Value::Number(_) => "Number",
                    Value::Bool(_) => "Bool",
                    Value::Null => "Null",
                    Value::Undefined => "Undefined",
                };

                let val_json = self.value_to_compact_json(register);
                let truncated = if val_json.len() > 100 {
                    format!("{}...", &val_json[..97])
                } else {
                    val_json
                };

                let source_expr = self.get_register_source_expression(i, ctx.pc, ctx.program);
                let line = if let Some(expr) = source_expr {
                    format!("R{:2}: {} {} ← {}", i, type_indicator, truncated, expr)
                } else {
                    format!("R{:2}: {} {}", i, type_indicator, truncated)
                };
                println!("│ {:<138} │", self.truncate_or_pad(&line, 138));
            }
        }

        println!("└{}┘", "─".repeat(140));
        println!("Press Enter to return to debugger...");
        let mut _dummy = String::new();
        std::io::stdin().read_line(&mut _dummy).ok();
    }

    /// Show detailed call stack information
    fn show_call_stack_details(&self, call_rule_stack: &[CallRuleContext], program: &Program) {
        print!("\x1B[2J\x1B[H");
        println!("┌{}┐", "─".repeat(100));
        println!("│ {:<98} │", "📞 Call Stack - Detailed View");
        println!("├{}┤", "─".repeat(100));

        if call_rule_stack.is_empty() {
            println!("│ {:<98} │", "  No active calls");
        } else {
            for (i, call_ctx) in call_rule_stack.iter().enumerate() {
                println!(
                    "│ {:<98} │",
                    format!(
                        "  [{:2}] Rule {} → PC {}",
                        i, call_ctx.rule_index, call_ctx.return_pc
                    )
                );
                println!(
                    "│ {:<98} │",
                    format!(
                        "       Dest reg: {}, Result reg: {}",
                        call_ctx.dest_reg, call_ctx.result_reg
                    )
                );
                println!(
                    "│ {:<98} │",
                    format!("       Type: {:?}", call_ctx.rule_type)
                );
                println!(
                    "│ {:<98} │",
                    format!(
                        "       Definition: {}, Body: {}",
                        call_ctx.current_definition_index, call_ctx.current_body_index
                    )
                );

                // Show rule name if available
                if let Some(rule_info) = program.rule_infos.get(call_ctx.rule_index as usize) {
                    println!(
                        "│ {:<98} │",
                        format!("       Name: {}", self.truncate_or_pad(&rule_info.name, 85))
                    );
                }
                println!("│ {:<98} │", "");
            }
        }
        println!("└{}┘", "─".repeat(100));
        println!("Press Enter to return to debugger...");
        let mut _dummy = String::new();
        std::io::stdin().read_line(&mut _dummy).ok();
    }

    /// Show detailed loop stack information
    fn show_loop_stack_details(&self, loop_stack: &[LoopContext]) {
        print!("\x1B[2J\x1B[H");
        println!("┌{}┐", "─".repeat(100));
        println!("│ {:<98} │", "🔄 Loop Stack - Detailed View");
        println!("├{}┤", "─".repeat(100));

        if loop_stack.is_empty() {
            println!("│ {:<98} │", "  No active loops");
        } else {
            for (i, loop_ctx) in loop_stack.iter().enumerate() {
                println!(
                    "│ {:<98} │",
                    format!("  [{:2}] Mode: {:?}", i, loop_ctx.mode)
                );
                println!(
                    "│ {:<98} │",
                    format!(
                        "       Registers - Key: {}, Value: {}, Result: {}",
                        loop_ctx.key_reg, loop_ctx.value_reg, loop_ctx.result_reg
                    )
                );
                println!(
                    "│ {:<98} │",
                    format!(
                        "       Body: {} → {}, Loop end: {}",
                        loop_ctx.body_start, loop_ctx.loop_next_pc, loop_ctx.loop_end
                    )
                );
                println!(
                    "│ {:<98} │",
                    format!(
                        "       Iterations: {} total, {} successful",
                        loop_ctx.total_iterations, loop_ctx.success_count
                    )
                );
                println!(
                    "│ {:<98} │",
                    format!(
                        "       Current iteration failed: {}",
                        loop_ctx.current_iteration_failed
                    )
                );

                // Show iteration state details
                match &loop_ctx.iteration_state {
                    super::vm::IterationState::Array { items, index } => {
                        println!(
                            "│ {:<98} │",
                            format!("       Array iteration: {}/{} items", index, items.len())
                        );
                    }
                    super::vm::IterationState::Object {
                        obj,
                        current_key,
                        first_iteration,
                    } => {
                        println!(
                            "│ {:<98} │",
                            format!(
                                "       Object iteration: {} keys, first: {}",
                                obj.len(),
                                first_iteration
                            )
                        );
                        if let Some(key) = current_key {
                            let key_str = self.value_to_compact_json(key);
                            println!(
                                "│ {:<98} │",
                                format!(
                                    "         Current key: {}",
                                    self.truncate_or_pad(&key_str, 82)
                                )
                            );
                        }
                    }
                    super::vm::IterationState::Set {
                        items,
                        current_item,
                        first_iteration,
                    } => {
                        println!(
                            "│ {:<98} │",
                            format!(
                                "       Set iteration: {} items, first: {}",
                                items.len(),
                                first_iteration
                            )
                        );
                        if let Some(item) = current_item {
                            let item_str = self.value_to_compact_json(item);
                            println!(
                                "│ {:<98} │",
                                format!(
                                    "         Current item: {}",
                                    self.truncate_or_pad(&item_str, 82)
                                )
                            );
                        }
                    }
                }
                println!("│ {:<98} │", "");
            }
        }
        println!("└{}┘", "─".repeat(100));
        println!("Press Enter to return to debugger...");
        let mut _dummy = String::new();
        std::io::stdin().read_line(&mut _dummy).ok();
    }

    /// Show complete VM context
    fn show_vm_context(&self, ctx: &DebugContext) {
        print!("\x1B[2J\x1B[H");
        println!("┌{}┐", "─".repeat(120));
        println!("│ {:<118} │", "🔍 Complete VM Context");
        println!("├{}┤", "─".repeat(120));

        // Execution state
        println!("│ {:<118} │", format!("🚀 Execution State:"));
        println!(
            "│ {:<118} │",
            format!("   PC: {} / {}", ctx.pc, ctx.program.instructions.len())
        );
        println!(
            "│ {:<118} │",
            format!("   Instructions executed: {}", ctx.executed_instructions)
        );
        println!(
            "│ {:<118} │",
            format!("   Current instruction: {:?}", ctx.instruction)
        );
        println!("│ {:<118} │", "");

        // Active stacks
        println!("│ {:<118} │", format!("📚 Stack Status:"));
        println!(
            "│ {:<118} │",
            format!("   Call stack depth: {}", ctx.call_rule_stack.len())
        );
        println!(
            "│ {:<118} │",
            format!("   Loop stack depth: {}", ctx.loop_stack.len())
        );
        println!("│ {:<118} │", "");

        // Register summary
        let active_regs = ctx
            .registers
            .iter()
            .enumerate()
            .filter(|(_, r)| **r != Value::Null && **r != Value::Undefined)
            .count();
        println!("│ {:<118} │", format!("📊 Registers:"));
        println!(
            "│ {:<118} │",
            format!(
                "   Active registers: {} / {}",
                active_regs,
                ctx.registers.len()
            )
        );
        println!("│ {:<118} │", "");

        // Program info
        println!("│ {:<118} │", format!("📄 Program Info:"));
        println!(
            "│ {:<118} │",
            format!("   Instructions: {}", ctx.program.instructions.len())
        );
        println!(
            "│ {:<118} │",
            format!("   Literals: {}", ctx.program.literals.len())
        );
        println!(
            "│ {:<118} │",
            format!("   Rules: {}", ctx.program.rule_infos.len())
        );
        println!(
            "│ {:<118} │",
            format!("   Sources: {}", ctx.program.sources.len())
        );

        println!("└{}┘", "─".repeat(120));
        println!("Press Enter to return to debugger...");
        let mut _dummy = String::new();
        std::io::stdin().read_line(&mut _dummy).ok();
    }

    /// Show extended source view with better synchronization
    fn show_extended_source(&self, pc: usize, program: &Program) {
        print!("\x1B[2J\x1B[H");
        println!("┌{}┐", "─".repeat(120));
        println!(
            "│ {:<118} │",
            "📜 Extended Source View with Enhanced Cursor Positioning"
        );
        println!("├{}┤", "─".repeat(120));

        if program.sources.is_empty() {
            println!("│ {:<118} │", "No source files available");
            println!("└{}┘", "─".repeat(120));
            println!("Press Enter to return to debugger...");
            let mut _dummy = String::new();
            std::io::stdin().read_line(&mut _dummy).ok();
            return;
        }

        // Get the span information for the current PC
        let current_span = program.get_instruction_span(pc);

        // Display all source files with current position highlighted
        for (source_idx, source) in program.sources.iter().enumerate() {
            println!(
                "│ {:<118} │",
                format!(
                    "📄 Source {}: {}",
                    source_idx,
                    self.truncate_or_pad(
                        &if source.name.is_empty() {
                            format!("source_{}", source_idx)
                        } else {
                            source.name.clone()
                        },
                        110
                    )
                )
            );
            println!("│ {:<118} │", "");

            let lines: Vec<&str> = source.content.lines().collect();
            let current_line = if let Some(span) = current_span {
                if span.source_index == source_idx {
                    Some(span.line)
                } else {
                    None
                }
            } else {
                None
            };

            for (line_num, line_content) in lines.iter().enumerate() {
                let actual_line_num = line_num + 1;
                let is_current = current_line == Some(actual_line_num);

                let marker = if is_current { ">>>" } else { "   " };
                let line_display = format!("{} {:3}: {}", marker, actual_line_num, line_content);
                println!("│ {:<118} │", self.truncate_or_pad(&line_display, 118));

                // Show cursor position if this is the current line
                if is_current {
                    if let Some(span) = current_span {
                        if span.column > 0
                            && span.column <= line_content.len() + 1
                            && span.length > 0
                        {
                            let prefix_len = 8; // ">>> 123: ".len()
                            let col_offset = span.column.saturating_sub(1);

                            // Sanity check: don't highlight if span is too large (likely corrupted data)
                            let max_reasonable_length =
                                line_content.len().saturating_sub(col_offset);
                            let safe_cursor_length = if span.length > max_reasonable_length
                                || span.length > line_content.len() / 2
                            {
                                // If span is unreasonably large, just show a single character cursor
                                1
                            } else {
                                std::cmp::min(span.length, max_reasonable_length)
                            };

                            let cursor_indicator = format!(
                                "{}{}{}",
                                " ".repeat(prefix_len + col_offset),
                                "^".repeat(safe_cursor_length),
                                if span.length > safe_cursor_length {
                                    format!(" (span_len:{} capped)", span.length)
                                } else if span.length > 1 {
                                    format!(" (len:{})", span.length)
                                } else {
                                    String::new()
                                }
                            );
                            println!("│ {:<118} │", self.truncate_or_pad(&cursor_indicator, 118));
                        } else {
                            // Show cursor info even if position is out of bounds
                            let cursor_indicator = format!(
                                "{}^ (col:{}, len:{}) [out_of_bounds]",
                                " ".repeat(8 + line_content.len().min(40)), // Don't go too far right
                                span.column,
                                span.length
                            );
                            println!("│ {:<118} │", self.truncate_or_pad(&cursor_indicator, 118));
                        }
                    }
                }
            }
            println!("│ {:<118} │", "");
        }

        if let Some(span) = current_span {
            println!(
                "│ {:<118} │",
                format!(
                    "📍 Current position: Source {}, Line {}, Column {}, Length {}",
                    span.source_index, span.line, span.column, span.length
                )
            );
        } else {
            println!(
                "│ {:<118} │",
                "📍 No source position information for current instruction"
            );
        }

        println!("└{}┘", "─".repeat(120));
        println!("Press Enter to return to debugger...");
        let mut _dummy = String::new();
        std::io::stdin().read_line(&mut _dummy).ok();
    }

    /// Show help information
    fn show_help(&self) {
        print!("\x1B[2J\x1B[H");
        println!("┌{}┐", "─".repeat(80));
        println!("│ {:<78} │", "📖 RVM Interactive Debugger - Enhanced Help");
        println!("├{}┤", "─".repeat(80));
        println!("│ {:<78} │", "🚀 Basic Commands:");
        println!(
            "│ {:<78} │",
            "  c, continue - Continue execution until next breakpoint"
        );
        println!("│ {:<78} │", "  s, step     - Step one instruction");
        println!(
            "│ {:<78} │",
            "  n, next     - Step one instruction (alias for step)"
        );
        println!(
            "│ {:<78} │",
            "  q, quit     - Exit debugger and continue execution"
        );
        println!("│ {:<78} │", "");
        println!("│ {:<78} │", "🔍 Inspection Commands:");
        println!(
            "│ {:<78} │",
            "  l, list     - Show enhanced assembly listing (context)"
        );
        println!(
            "│ {:<78} │",
            "  lt, list-tabular - Show tabular assembly format"
        );
        println!(
            "│ {:<78} │",
            "  asm, assembly    - Show full enhanced assembly listing"
        );
        println!(
            "│ {:<78} │",
            "  r, registers- Show all registers and their values"
        );
        println!("│ {:<78} │", "  cs, call-stack - Show detailed call stack");
        println!("│ {:<78} │", "  ls, loop-stack - Show detailed loop stack");
        println!("│ {:<78} │", "  ctx, context   - Show complete VM context");
        println!(
            "│ {:<78} │",
            "  src, source    - Show extended source view with cursor"
        );
        println!("│ {:<78} │", "");
        println!("│ {:<78} │", "🔴 Breakpoint Commands:");
        println!(
            "│ {:<78} │",
            "  b [pc]      - Set breakpoint at specific PC"
        );
        println!("│ {:<78} │", "");
        println!("│ {:<78} │", "⚙️  Environment Variables:");
        println!(
            "│ {:<78} │",
            "  RVM_INTERACTIVE_DEBUG=1  - Enable interactive debugging"
        );
        println!(
            "│ {:<78} │",
            "  RVM_STEP_MODE=1         - Break on every instruction"
        );
        println!(
            "│ {:<78} │",
            "  RVM_BREAK_ON_LOOPS=1    - Auto-break on loop starts"
        );
        println!(
            "│ {:<78} │",
            "  RVM_BREAK_ON_RULES=1    - Auto-break on rule calls"
        );
        println!(
            "│ {:<78} │",
            "  RVM_BREAKPOINT=pc1,pc2  - Set initial breakpoints"
        );
        println!("└{}┘", "─".repeat(80));
        println!("Press Enter to return to debugger...");
        let mut _dummy = String::new();
        std::io::stdin().read_line(&mut _dummy).ok();
    }

    /// Show enhanced assembly listing with new format
    fn show_enhanced_assembly_listing(&self, ctx: &DebugContext) {
        print!("\x1B[2J\x1B[H");
        println!("┌{}┐", "─".repeat(140));
        println!(
            "│ {:<138} │",
            "📋 Enhanced Assembly Listing with Current PC Highlighted"
        );
        println!("├{}┤", "─".repeat(140));

        let config = AssemblyListingConfig {
            show_addresses: true,
            show_bytes: false,
            indent_size: 4,
            instruction_width: 40,
            show_literal_values: true,
            comment_column: 60,
        };

        let listing = generate_assembly_listing(ctx.program, &config);
        let lines: Vec<&str> = listing.lines().collect();

        // Find current instruction line in the listing
        let mut current_line_idx = None;
        for (idx, line) in lines.iter().enumerate() {
            if line.contains(&format!("{:03}:", ctx.pc)) {
                current_line_idx = Some(idx);
                break;
            }
        }

        // Show context around current instruction
        let context_size = 15;
        let start_idx = if let Some(curr_idx) = current_line_idx {
            curr_idx.saturating_sub(context_size)
        } else {
            0
        };
        let end_idx = (start_idx + context_size * 2).min(lines.len());

        for (idx, line) in lines[start_idx..end_idx].iter().enumerate() {
            let actual_idx = start_idx + idx;
            let is_current = current_line_idx == Some(actual_idx);

            let display_line = if is_current {
                format!(">>> {}", line)
            } else {
                format!("    {}", line)
            };

            println!("│ {:<138} │", self.truncate_or_pad(&display_line, 138));
        }

        println!("└{}┘", "─".repeat(140));
        println!("Commands: (f)ull listing, (t)abular format, (Enter) return to debugger");

        let mut input = String::new();
        std::io::stdin().read_line(&mut input).ok();
        match input.trim() {
            "f" | "full" => self.show_full_assembly_listing(ctx),
            "t" | "tabular" => self.show_tabular_assembly_listing(ctx),
            _ => {} // Return to main debugger
        }
    }

    /// Show full assembly listing with enhanced format
    fn show_full_assembly_listing(&self, ctx: &DebugContext) {
        print!("\x1B[2J\x1B[H");
        println!("┌{}┐", "─".repeat(160));
        println!(
            "│ {:<158} │",
            "📋 Full Enhanced Assembly Listing - All Instructions with Builtins & Rules"
        );
        println!("├{}┤", "─".repeat(160));

        let config = AssemblyListingConfig {
            show_addresses: true,
            show_bytes: false,
            indent_size: 4,
            instruction_width: 50,
            show_literal_values: true,
            comment_column: 70,
        };

        let listing = generate_assembly_listing(ctx.program, &config);
        let lines: Vec<&str> = listing.lines().collect();

        for line in &lines {
            // Highlight current PC line
            let is_current_pc = line.contains(&format!("{:03}:", ctx.pc));
            let display_line = if is_current_pc {
                format!(">>> {}", line)
            } else {
                format!("    {}", line)
            };

            println!("│ {:<158} │", self.truncate_or_pad(&display_line, 158));
        }

        println!("└{}┘", "─".repeat(160));
        println!("Press Enter to return to debugger...");
        let mut _dummy = String::new();
        std::io::stdin().read_line(&mut _dummy).ok();
    }

    /// Show tabular assembly listing
    fn show_tabular_assembly_listing(&self, ctx: &DebugContext) {
        print!("\x1B[2J\x1B[H");
        println!("┌{}┐", "─".repeat(120));
        println!(
            "│ {:<118} │",
            "📋 Tabular Assembly Listing - Compact Format"
        );
        println!("├{}┤", "─".repeat(120));

        let config = AssemblyListingConfig::default();
        let listing = generate_tabular_assembly_listing(ctx.program, &config);
        let lines: Vec<&str> = listing.lines().collect();

        for line in &lines {
            // Highlight current PC line if it contains the PC
            let contains_current_pc = line.contains(&format!("{:>4}", ctx.pc))
                || line.contains(&format!("{:03}", ctx.pc));
            let display_line = if contains_current_pc && !line.starts_with(';') {
                format!(">>> {}", line)
            } else {
                format!("    {}", line)
            };

            println!("│ {:<118} │", self.truncate_or_pad(&display_line, 118));
        }

        println!("└{}┘", "─".repeat(120));
        println!("Press Enter to return to debugger...");
        let mut _dummy = String::new();
        std::io::stdin().read_line(&mut _dummy).ok();
    }
}
