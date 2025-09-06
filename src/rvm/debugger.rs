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
}

impl Default for InteractiveDebugger {
    fn default() -> Self {
        Self::new()
    }
}

impl InteractiveDebugger {
    pub fn new() -> Self {
        Self {
            enabled: std::env::var("RVM_INTERACTIVE_DEBUG").is_ok(),
            step_mode: std::env::var("RVM_STEP_MODE").is_ok(),
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
            auto_break_on_loops: std::env::var("RVM_BREAK_ON_LOOPS").is_ok(),
            auto_break_on_rules: std::env::var("RVM_BREAK_ON_RULES").is_ok(),
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

    pub fn debug_prompt(&mut self, ctx: &DebugContext) {
        // Clear screen and reset cursor to top
        print!("\x1B[2J\x1B[H");

        // Get terminal size (default to 120x30 if detection fails)
        let (term_width, term_height) = self.get_terminal_size().unwrap_or((120, 30));
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

        // Main command loop
        self.handle_debug_commands(ctx.pc, ctx.registers, ctx.program);
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
        &self,
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

        // Header row for the two panels
        println!(
            "│ {:<width$} │ {:<width$} │",
            "📜 Rego Source",
            "📋 Instructions",
            width = half_width - 2
        );
        println!("├{}┼{}┤", "─".repeat(half_width), "─".repeat(half_width));

        // Content rows
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
                self.truncate_or_pad(rego_line, half_width - 2),
                self.truncate_or_pad(inst_line, half_width - 2),
                width = half_width - 2
            );
        }
    }

    fn get_rego_display_lines(
        &self,
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

        // Find the correct source file and line info
        let (source_lines, current_line) = if let Some(span) = current_span {
            if span.source_index < program.sources.len() {
                let source_content = &program.sources[span.source_index].content;
                let source_lines: Vec<&str> = source_content.lines().collect();
                (source_lines, span.line)
            } else {
                // Fallback to first source if index is invalid
                let source_lines: Vec<&str> = program.sources[0].content.lines().collect();
                (source_lines, 1)
            }
        } else {
            // No span info, use first source and line 1
            let source_lines: Vec<&str> = program.sources[0].content.lines().collect();
            (source_lines, 1)
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
                let is_current = if let Some(span) = current_span {
                    span.line == line_num
                } else {
                    false
                };

                if is_current {
                    lines.push(format!(">>> {:3}: {}", line_num, line_content));

                    // Add cursor line if we have span info
                    if let Some(span) = current_span {
                        let col = if span.column > 0 { span.column - 1 } else { 0 };
                        if col < line_content.len() {
                            let cursor_line = format!(
                                "    {}{}",
                                " ".repeat(7 + col), // 7 for ">>> 123: "
                                "^".repeat(std::cmp::min(span.length, line_content.len() - col))
                            );
                            lines.push(cursor_line);
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

        // Show instructions around current PC
        let start_pc = pc.saturating_sub(max_lines / 2);
        let end_pc = std::cmp::min(program.instructions.len(), start_pc + max_lines);

        for i in start_pc..end_pc {
            if i < program.instructions.len() {
                let marker = if i == pc { ">>>" } else { "   " };
                let inst = &program.instructions[i];
                lines.push(format!("{} {:3}: {:?}", marker, i, inst));
            }
        }

        lines
    }

    fn draw_bottom_section(
        &self,
        registers: &[Value],
        call_rule_stack: &[CallRuleContext],
        loop_stack: &[LoopContext],
        pc: usize,
        program: &Program,
        width: usize,
    ) {
        println!("├{}┤", "─".repeat(width - 2));

        // Active registers in a compact format
        println!("│ {:<width$} │", "📊 Active Registers", width = width - 4);

        let mut reg_lines = Vec::new();
        let mut active_count = 0;
        for (i, register) in registers.iter().enumerate().take(16) {
            if *register != Value::Null && *register != Value::Undefined && active_count < 4 {
                let type_indicator = match register {
                    Value::Set(_) => "Set",
                    Value::Array(_) => "Array",
                    Value::Object(_) => "Object",
                    Value::String(_) => "String",
                    Value::Number(_) => "Number",
                    Value::Bool(_) => "Bool",
                    _ => "Other",
                };

                let val_json = register
                    .to_json_str()
                    .unwrap_or_else(|_| format!("{:?}", register));
                let truncated = if val_json.len() > 25 {
                    format!("{}...", &val_json[..22])
                } else {
                    val_json
                };

                let source_expr = self.get_register_source_expression(i, pc, program);
                if let Some(expr) = source_expr {
                    reg_lines.push(format!(
                        "R{:2}: {} {} ← {}",
                        i, type_indicator, truncated, expr
                    ));
                } else {
                    reg_lines.push(format!("R{:2}: {} {}", i, type_indicator, truncated));
                }
                active_count += 1;
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
            "💻 Commands: (c)ontinue (s)tep (l)ist (r)egisters (h)elp (q)uit",
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

    fn handle_debug_commands(&mut self, pc: usize, registers: &[Value], program: &Program) {
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
                        // Clear screen and show full instruction listing
                        print!("\x1B[2J\x1B[H");
                        println!("┌{}┐", "─".repeat(80));
                        println!("│ {:<78} │", "📋 Full Instruction Listing");
                        println!("├{}┤", "─".repeat(80));

                        for (i, inst) in program.instructions.iter().enumerate() {
                            let marker = if i == pc { ">>>" } else { "   " };
                            let line = format!("{} {:3}: {:?}", marker, i, inst);
                            println!("│ {:<78} │", self.truncate_or_pad(&line, 78));
                        }

                        println!("└{}┘", "─".repeat(80));
                        println!("Press Enter to return to debugger...");
                        let mut _dummy = String::new();
                        std::io::stdin().read_line(&mut _dummy).ok();
                        return; // This will redraw the main screen
                    }
                    "r" | "registers" => {
                        // Clear screen and show full register listing
                        print!("\x1B[2J\x1B[H");
                        println!("┌{}┐", "─".repeat(100));
                        println!("│ {:<98} │", "📊 All Registers");
                        println!("├{}┤", "─".repeat(100));

                        for (i, register) in registers
                            .iter()
                            .enumerate()
                            .take(std::cmp::min(registers.len(), 32))
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

                                let val_json = register
                                    .to_json_str()
                                    .unwrap_or_else(|_| format!("{:?}", register));
                                let truncated = if val_json.len() > 70 {
                                    format!("{}...", &val_json[..67])
                                } else {
                                    val_json
                                };

                                let source_expr =
                                    self.get_register_source_expression(i, pc, program);
                                let line = if let Some(expr) = source_expr {
                                    format!("R{:2}: {} {} ← {}", i, type_indicator, truncated, expr)
                                } else {
                                    format!("R{:2}: {} {}", i, type_indicator, truncated)
                                };
                                println!("│ {:<98} │", self.truncate_or_pad(&line, 98));
                            }
                        }

                        println!("└{}┘", "─".repeat(100));
                        println!("Press Enter to return to debugger...");
                        let mut _dummy = String::new();
                        std::io::stdin().read_line(&mut _dummy).ok();
                        return; // This will redraw the main screen
                    }
                    "q" | "quit" => {
                        self.enabled = false;
                        break;
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
                        print!("\x1B[2J\x1B[H");
                        println!("┌{}┐", "─".repeat(60));
                        println!("│ {:<58} │", "📖 RVM Debugger Help");
                        println!("├{}┤", "─".repeat(60));
                        println!(
                            "│ {:<58} │",
                            "c, continue - Continue execution until next breakpoint"
                        );
                        println!("│ {:<58} │", "s, step     - Step one instruction");
                        println!(
                            "│ {:<58} │",
                            "n, next     - Step one instruction (alias for step)"
                        );
                        println!(
                            "│ {:<58} │",
                            "l, list     - Show all instructions with current PC"
                        );
                        println!("│ {:<58} │", "b [pc]      - Set breakpoint at specific PC");
                        println!(
                            "│ {:<58} │",
                            "r, registers- Show all registers and their values"
                        );
                        println!("│ {:<58} │", "h, help     - Show this help message");
                        println!(
                            "│ {:<58} │",
                            "q, quit     - Exit debugger and continue execution"
                        );
                        println!("│ {:<58} │", "");
                        println!("│ {:<58} │", "Environment Variables:");
                        println!(
                            "│ {:<58} │",
                            "RVM_INTERACTIVE_DEBUG=1  - Enable interactive debugging"
                        );
                        println!(
                            "│ {:<58} │",
                            "RVM_STEP_MODE=1         - Break on every instruction"
                        );
                        println!(
                            "│ {:<58} │",
                            "RVM_BREAK_ON_LOOPS=1    - Auto-break on loop starts"
                        );
                        println!(
                            "│ {:<58} │",
                            "RVM_BREAK_ON_RULES=1    - Auto-break on rule calls"
                        );
                        println!("└{}┘", "─".repeat(60));
                        println!("Press Enter to return to debugger...");
                        let mut _dummy = String::new();
                        std::io::stdin().read_line(&mut _dummy).ok();
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
}
