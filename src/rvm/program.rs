use crate::rvm::instructions::InstructionData;
use crate::rvm::Instruction;
use crate::value::Value;
use crate::builtins::BuiltinFcn;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

extern crate alloc;

/// Builtin function information stored in program's builtin info table
#[repr(C)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuiltinInfo {
    /// Builtin function name
    pub name: String,
    /// Exact number of arguments required
    pub num_args: u16,
}

/// Span information for debugging and error reporting
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpanInfo {
    /// Index into the source table
    pub source_index: usize,
    /// Line number (1-based)
    pub line: usize,
    /// Column number (1-based)
    pub column: usize,
    /// Length of the span
    pub length: usize,
}

/// Rule type enumeration for different kinds of rules (complete, partial set, partial object)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, PartialOrd, Eq, Ord)]
pub enum RuleType {
    Complete,
    PartialSet,
    PartialObject,
}

impl SpanInfo {
    pub fn new(source_index: usize, line: usize, column: usize, length: usize) -> Self {
        Self {
            source_index,
            line,
            column,
            length,
        }
    }

    /// Create SpanInfo from lexer Span with source table lookup
    pub fn from_lexer_span(span: &crate::lexer::Span, source_index: usize) -> Self {
        Self {
            source_index,
            line: span.line as usize,
            column: span.col as usize,
            length: span.text().len(),
        }
    }

    /// Get source information using the program's source table
    pub fn get_source<'a>(&self, source_table: &'a [SourceFile]) -> Option<&'a str> {
        source_table
            .get(self.source_index)
            .map(|s| s.content.as_str())
    }

    /// Get source name using the program's source table
    pub fn get_source_name<'a>(&self, source_table: &'a [SourceFile]) -> Option<&'a str> {
        source_table.get(self.source_index).map(|s| s.name.as_str())
    }
}

/// Rule metadata for debugging and introspection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleInfo {
    /// Rule name (e.g., "data.package.rule_name")
    pub name: String,
    /// Rule type
    pub rule_type: RuleType,
    /// Definitions
    pub definitions: crate::Rc<Vec<Vec<usize>>>,
}

impl RuleInfo {
    pub fn new(name: String, rule_type: RuleType, definitions: crate::Rc<Vec<Vec<usize>>>) -> Self {
        Self {
            name,
            rule_type,
            definitions,
        }
    }
}

/// Source file information containing filename and contents
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceFile {
    /// Source file identifier/path
    pub name: String,
    /// The actual source code content
    pub content: String,
}

impl SourceFile {}

impl SourceFile {
    pub fn new(name: String, content: String) -> Self {
        Self { name, content }
    }
}

/// Versioned program wrapper for serialization compatibility
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionedProgram {
    /// Format version for compatibility checking
    pub version: u32,
    /// The actual program data
    pub program: Program,
}

/// Complete compiled program containing all execution artifacts
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Program {
    /// Compiled bytecode instructions
    pub instructions: Vec<Instruction>,

    /// Literal value table
    pub literals: Vec<Value>,

    /// Complex instruction parameter data (for LoopStart, Call, etc.)
    pub instruction_data: InstructionData,

    /// Builtin function information table
    pub builtin_info_table: Vec<BuiltinInfo>,

    /// Source files table with content
    pub sources: Vec<SourceFile>,

    /// Rule metadata: rule_index -> rule information
    pub rule_infos: Vec<RuleInfo>,

    /// Span information for each instruction (for debugging)
    pub instruction_spans: Vec<Option<SpanInfo>>,

    /// Main program entry point
    pub main_entry_point: usize,

    /// Number of registers required by this program
    pub num_registers: usize,

    /// Program metadata
    pub metadata: ProgramMetadata,

    /// Resolved builtins - actual builtin function values fetched from interpreter's builtin map
    /// This field is skipped during serialization and reinitialized after deserialization
    #[serde(skip)]
    pub resolved_builtins: Vec<BuiltinFcn>,
}

/// Program compilation metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramMetadata {
    /// Compiler version that generated this program
    pub compiler_version: String,
    /// Compilation timestamp
    pub compiled_at: String,
    /// Source policy information
    pub source_info: String,
    /// Optimization level used
    pub optimization_level: u8,
}

impl Program {
    /// Current serialization format version
    pub const SERIALIZATION_VERSION: u32 = 1;
    /// Magic bytes to identify Regorus program files
    pub const MAGIC: [u8; 4] = *b"REGO";

    /// Serialize program to binary format with version header
    ///
    /// Binary format:
    /// - 4 bytes: Magic number "REGO"
    /// - 4 bytes: Version (little-endian u32)
    /// - 4 bytes: Data length (little-endian u32)
    /// - N bytes: Serialized program data
    pub fn serialize_binary(&self) -> Result<Vec<u8>, String> {
        let mut buffer = Vec::new();

        // Write magic number and version header
        buffer.extend_from_slice(&Self::MAGIC);
        buffer.extend_from_slice(&Self::SERIALIZATION_VERSION.to_le_bytes());

        // Serialize the program directly (no wrapper needed)
        let json_data =
            serde_json::to_vec(self).map_err(|e| format!("JSON serialization failed: {}", e))?;

        // Write length of data
        buffer.extend_from_slice(&(json_data.len() as u32).to_le_bytes());

        // Write the actual program data
        buffer.extend_from_slice(&json_data);

        Ok(buffer)
    }

    /// Deserialize program from binary format with version checking
    pub fn deserialize_binary(data: &[u8]) -> Result<Self, String> {
        if data.len() < 12 {
            return Err("Data too short for header".to_string());
        }

        // Check magic number
        if data[0..4] != Self::MAGIC {
            return Err("Invalid file format - magic number mismatch".to_string());
        }

        // Check version
        let version = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        if version > Self::SERIALIZATION_VERSION {
            return Err(format!(
                "Unsupported version {}. Maximum supported version is {}",
                version,
                Self::SERIALIZATION_VERSION
            ));
        }

        // Read data length
        let data_len = u32::from_le_bytes([data[8], data[9], data[10], data[11]]) as usize;
        if data.len() < 12 + data_len {
            return Err("Data truncated".to_string());
        }

        // Deserialize the program based on version
        match version {
            1 => {
                // Current version - deserialize directly as Program
                serde_json::from_slice(&data[12..12 + data_len])
                    .map_err(|e| format!("JSON deserialization failed: {}", e))
            }
            v => Err(format!("Unsupported version {}", v)),
        }
    }

    /// Check if data can be deserialized without actually deserializing
    pub fn can_deserialize(data: &[u8]) -> Result<bool, String> {
        if data.len() < 8 {
            return Ok(false);
        }

        // Check magic number
        if data[0..4] != Self::MAGIC {
            return Ok(false);
        }

        // Check version
        let version = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);

        match version {
            1 => Ok(true),  // Supported version
            _ => Ok(false), // Unsupported version
        }
    }

    /// Get file format information without deserializing
    pub fn get_file_info(data: &[u8]) -> Result<(u32, usize), String> {
        if data.len() < 12 {
            return Err("Data too short for header".to_string());
        }

        if data[0..4] != Self::MAGIC {
            return Err("Invalid file format".to_string());
        }

        let version = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let data_len = u32::from_le_bytes([data[8], data[9], data[10], data[11]]) as usize;

        Ok((version, data_len))
    }

    /// Create a new empty program
    pub fn new() -> Self {
        Self {
            instructions: Vec::new(),
            literals: Vec::new(),
            instruction_data: InstructionData::new(),
            builtin_info_table: Vec::new(),
            sources: Vec::new(),
            rule_infos: Vec::new(),
            instruction_spans: Vec::new(),
            main_entry_point: 0,
            num_registers: 0,
            metadata: ProgramMetadata {
                compiler_version: env!("CARGO_PKG_VERSION").to_string(),
                compiled_at: "unknown".to_string(),
                source_info: "unknown".to_string(),
                optimization_level: 0,
            },
            resolved_builtins: Vec::new(),
        }
    }

    /// Add a source file and return its index
    pub fn add_source(&mut self, name: String, content: String) -> usize {
        let source_file = SourceFile::new(name.clone(), content);
        let index = self.sources.len();
        self.sources.push(source_file);
        index
    }

    /// Add loop parameters and return the index
    pub fn add_loop_params(&mut self, params: crate::rvm::instructions::LoopStartParams) -> u16 {
        self.instruction_data.add_loop_params(params)
    }

    /// Add builtin call parameters and return the index
    pub fn add_builtin_call_params(
        &mut self,
        params: crate::rvm::instructions::BuiltinCallParams,
    ) -> u16 {
        self.instruction_data.add_builtin_call_params(params)
    }

    /// Add function call parameters and return the index
    pub fn add_function_call_params(
        &mut self,
        params: crate::rvm::instructions::FunctionCallParams,
    ) -> u16 {
        self.instruction_data.add_function_call_params(params)
    }

    /// Add builtin info and return the index
    pub fn add_builtin_info(&mut self, builtin_info: BuiltinInfo) -> u16 {
        let index = self.builtin_info_table.len();
        self.builtin_info_table.push(builtin_info);
        index as u16
    }

    /// Get builtin info by index
    pub fn get_builtin_info(&self, index: u16) -> Option<&BuiltinInfo> {
        self.builtin_info_table.get(index as usize)
    }

    /// Update loop parameters by index
    pub fn update_loop_params<F>(&mut self, params_index: u16, updater: F)
    where
        F: FnOnce(&mut crate::rvm::instructions::LoopStartParams),
    {
        if let Some(params) = self.instruction_data.get_loop_params_mut(params_index) {
            updater(params);
        }
    }

    /// Get detailed instruction display with parameter resolution
    pub fn display_instruction_with_params(&self, instruction: &Instruction) -> String {
        instruction.display_with_params(&self.instruction_data)
    }

    /// Add a source file directly and return its index
    pub fn add_source_file(&mut self, source_file: SourceFile) -> usize {
        // Check if source already exists to avoid duplicates (by name)
        for (i, existing) in self.sources.iter().enumerate() {
            if existing.name == source_file.name {
                return i;
            }
        }

        let index = self.sources.len();
        self.sources.push(source_file);
        index
    }

    /// Get source file by index
    pub fn get_source_file(&self, index: usize) -> Option<&SourceFile> {
        self.sources.get(index)
    }

    /// Get source content by index
    pub fn get_source(&self, index: usize) -> Option<&str> {
        self.sources.get(index).map(|s| s.content.as_str())
    }

    /// Get source name by index
    pub fn get_source_name(&self, index: usize) -> Option<&str> {
        self.sources.get(index).map(|s| s.name.as_str())
    }

    /// Get rule info by index
    pub fn get_rule_info(&self, rule_index: usize) -> Option<&RuleInfo> {
        self.rule_infos.get(rule_index)
    }

    /// Get span information for instruction
    pub fn get_instruction_span(&self, instruction_index: usize) -> Option<&SpanInfo> {
        self.instruction_spans
            .get(instruction_index)
            .and_then(|span| span.as_ref())
    }

    /// Add instruction with optional span
    pub fn add_instruction(&mut self, instruction: Instruction, span: Option<SpanInfo>) {
        self.instructions.push(instruction);
        self.instruction_spans.push(span);
    }

    /// Add literal value and return its index
    pub fn add_literal(&mut self, value: Value) -> usize {
        // Check if literal already exists to avoid duplicates
        for (i, existing) in self.literals.iter().enumerate() {
            if existing == &value {
                return i;
            }
        }

        let index = self.literals.len();
        self.literals.push(value);
        index
    }

    /// Initialize resolved builtins from interpreter's builtin map
    /// This should be called after deserialization to populate the skipped field
    pub fn initialize_resolved_builtins(&mut self, builtin_map: &std::collections::BTreeMap<&'static str, BuiltinFcn>) {
        self.resolved_builtins.clear();
        self.resolved_builtins.reserve(self.builtin_info_table.len());

        // Helper function for missing builtins
        fn missing_builtin_error(_span: &crate::lexer::Span, _exprs: &[crate::ast::Ref<crate::ast::Expr>], _args: &[Value], _strict: bool) -> anyhow::Result<Value> {
            Err(anyhow::anyhow!("Builtin function not found"))
        }

        for builtin_info in &self.builtin_info_table {
            if let Some(&builtin_fcn) = builtin_map.get(builtin_info.name.as_str()) {
                self.resolved_builtins.push(builtin_fcn);
            } else {
                // Use a placeholder for missing builtins - this shouldn't happen in normal operation
                self.resolved_builtins.push((missing_builtin_error, 0));
            }
        }
    }

    /// Get resolved builtin function by index
    pub fn get_resolved_builtin(&self, index: u16) -> Option<&BuiltinFcn> {
        self.resolved_builtins.get(index as usize)
    }

    /// Check if resolved builtins are initialized
    pub fn has_resolved_builtins(&self) -> bool {
        !self.resolved_builtins.is_empty()
    }
}

impl Default for Program {
    fn default() -> Self {
        Self::new()
    }
}
