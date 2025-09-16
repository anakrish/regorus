use crate::builtins::BuiltinFcn;
use crate::rvm::instructions::InstructionData;
use crate::rvm::Instruction;
use crate::value::Value;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use anyhow::Result;
use serde::{Deserialize, Serialize};

extern crate alloc;

// Use HashMap when std is available for better performance, BTreeMap otherwise
#[cfg(not(feature = "std"))]
use alloc::collections::BTreeMap as Map;
#[cfg(feature = "std")]
use std::collections::HashMap as Map;

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
    /// Function-specific information (only present for function rules)
    pub function_info: Option<FunctionInfo>,
    /// Index into the program's literal table for default value (only for Complete rules)
    pub default_literal_index: Option<u16>,
    /// Register allocated for this rule's result accumulation
    pub result_reg: u8,
    /// Number of registers used by this rule (for register windowing)
    pub num_registers: u8,
}

/// Information about function rules
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionInfo {
    /// Parameter names in order
    pub param_names: Vec<String>,
    /// Number of parameters
    pub num_params: usize,
}

impl RuleInfo {
    pub fn new(
        name: String,
        rule_type: RuleType,
        definitions: crate::Rc<Vec<Vec<usize>>>,
        result_reg: u8,
        num_registers: u8,
    ) -> Self {
        Self {
            name,
            rule_type,
            definitions,
            function_info: None,
            default_literal_index: None,
            result_reg,
            num_registers,
        }
    }

    /// Create a new function rule with parameter information
    pub fn new_function(
        name: String,
        rule_type: RuleType,
        definitions: crate::Rc<Vec<Vec<usize>>>,
        param_names: Vec<String>,
        result_reg: u8,
        num_registers: u8,
    ) -> Self {
        let num_params = param_names.len();
        Self {
            name,
            rule_type,
            definitions,
            function_info: Some(FunctionInfo {
                param_names,
                num_params,
            }),
            default_literal_index: None,
            result_reg,
            num_registers,
        }
    }

    /// Set the default literal index for this rule
    pub fn set_default_literal_index(&mut self, default_literal_index: u16) {
        self.default_literal_index = Some(default_literal_index);
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

    /// Literal value table (skipped in serde, serialized separately as JSON)
    #[serde(skip, default = "Vec::new")]
    pub literals: Vec<Value>,

    /// Complex instruction parameter data (for LoopStart, Call, etc.)
    pub instruction_data: InstructionData,

    /// Builtin function information table
    pub builtin_info_table: Vec<BuiltinInfo>,

    /// Entry points mapping from entry point path to rule index (skipped in serde, serialized separately as JSON)
    #[serde(skip, default = "Map::new")]
    pub entry_points: Map<String, usize>,

    /// Source files table with content (skipped in serde, serialized separately as JSON)
    #[serde(skip, default = "Vec::new")]
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

    /// Rule tree for efficient rule lookup (skipped in serde, serialized separately as JSON)
    /// Maps rule paths (e.g., "data.p1.r1") to rule indices
    /// Structure: {"p1": {"r1": rule_index}, "p2": {"p3": {"r2": rule_index}}}
    #[serde(skip, default = "Value::new_object")]
    pub rule_tree: Value,

    /// Resolved builtins - actual builtin function values fetched from interpreter's builtin map
    /// This field is skipped during serialization and reinitialized after deserialization
    #[serde(skip)]
    pub resolved_builtins: Vec<BuiltinFcn>,

    /// Flag indicating that VirtualDataDocumentLookup instruction was used and runtime recursion checking is needed
    pub needs_runtime_recursion_check: bool,

    /// Flag indicating that recompilation is needed due to partial deserialization failure
    /// This is set to true when the artifact section was successfully read but the extensible
    /// section failed to deserialize (e.g., due to version incompatibility)
    #[serde(default)]
    pub needs_recompilation: bool,
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

/// Result of program deserialization that explicitly indicates completeness
#[derive(Debug, Clone)]
pub enum DeserializationResult {
    /// Full deserialization was successful - program is fully functional
    Complete(Program),
    /// Only artifact section was deserialized - extensible sections failed
    /// The program contains entry_points and sources but requires recompilation
    Partial(Program),
}

impl Program {
    /// Current serialization format version
    pub const SERIALIZATION_VERSION: u32 = 1;
    /// Magic bytes to identify Regorus program files
    pub const MAGIC: [u8; 4] = *b"REGO";

    /// Serialize program to binary format with hybrid approach:
    /// - Binary serialization for most data (fast)
    /// - JSON serialization for Value fields (compatible)
    ///
    /// SERIALIZATION CONTRACT:
    /// The artifact section (entry_points, sources) represents the original compilation
    /// artifacts and MUST always be deserializable. These sections will never change
    /// location or order, ensuring forward compatibility.
    ///
    /// The extensible section (binary data, literals, rule_tree) may evolve and can
    /// fail to deserialize in newer format versions. When this happens, the deserializer
    /// will set needs_recompilation=true to signal that regeneration is required.
    ///
    /// Binary format:
    /// - 4 bytes: Magic number "REGO"
    /// - 4 bytes: Version (little-endian u32)
    ///
    /// ARTIFACT SECTION (always deserializable):
    /// - 4 bytes: JSON entry_points length (little-endian u32)
    /// - 4 bytes: JSON sources length (little-endian u32)
    /// - N bytes: JSON serialized entry_points
    /// - M bytes: JSON serialized sources
    ///
    /// EXTENSIBLE SECTION (may fail in newer versions):
    /// - 4 bytes: Binary data length (little-endian u32)
    /// - 4 bytes: JSON literals length (little-endian u32)
    /// - 4 bytes: JSON rule_tree length (little-endian u32)
    /// - P bytes: Binary serialized program data (without Value, entry_points, and sources fields)
    /// - Q bytes: JSON serialized literals
    /// - R bytes: JSON serialized rule_tree
    pub fn serialize_binary(&self) -> Result<Vec<u8>, String> {
        let mut buffer = Vec::new();

        // Write magic number and version header
        buffer.extend_from_slice(&Self::MAGIC);
        buffer.extend_from_slice(&Self::SERIALIZATION_VERSION.to_le_bytes());

        // Serialize entry_points and sources to JSON first
        let entry_points_json = serde_json::to_vec(&self.entry_points)
            .map_err(|e| format!("Entry points JSON serialization failed: {}", e))?;

        let sources_json = serde_json::to_vec(&self.sources)
            .map_err(|e| format!("Sources JSON serialization failed: {}", e))?;

        // Serialize the main program structure (without Value, entry_points, and sources fields) to binary using bincode
        // Note: The Value, entry_points, and sources fields are skipped via #[serde(skip)] so this won't include them
        let binary_data = bincode::serialize(self)
            .map_err(|e| format!("Program structure binary serialization failed: {}", e))?;

        // Serialize Value fields to JSON
        let literals_json = serde_json::to_vec(&self.literals)
            .map_err(|e| format!("Literals JSON serialization failed: {}", e))?;

        let rule_tree_json = serde_json::to_vec(&self.rule_tree)
            .map_err(|e| format!("Rule tree JSON serialization failed: {}", e))?;

        // Write lengths for entry_points and sources first
        buffer.extend_from_slice(&(entry_points_json.len() as u32).to_le_bytes());
        buffer.extend_from_slice(&(sources_json.len() as u32).to_le_bytes());

        // Write the JSON data first (entry_points and sources)
        buffer.extend_from_slice(&entry_points_json);
        buffer.extend_from_slice(&sources_json);

        // Write lengths for remaining data
        buffer.extend_from_slice(&(binary_data.len() as u32).to_le_bytes());
        buffer.extend_from_slice(&(literals_json.len() as u32).to_le_bytes());
        buffer.extend_from_slice(&(rule_tree_json.len() as u32).to_le_bytes());

        // Write the remaining data
        buffer.extend_from_slice(&binary_data);
        buffer.extend_from_slice(&literals_json);
        buffer.extend_from_slice(&rule_tree_json);

        Ok(buffer)
    }

    /// Deserialize only the artifact section (entry_points and sources) from binary format
    /// This method is guaranteed to work across all format versions and provides access
    /// to the original compilation artifacts even if the extensible section cannot be parsed.
    pub fn deserialize_artifacts_only(
        data: &[u8],
    ) -> Result<(Map<String, usize>, Vec<SourceFile>), String> {
        if data.len() < 16 {
            return Err("Data too short for artifact header".to_string());
        }

        // Check magic number
        if data[0..4] != Self::MAGIC {
            return Err("Invalid file format - magic number mismatch".to_string());
        }

        // Check version (we support all versions for artifact section)
        let _version = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);

        // Read lengths for entry_points and sources
        let entry_points_len = u32::from_le_bytes([data[8], data[9], data[10], data[11]]) as usize;
        let sources_len = u32::from_le_bytes([data[12], data[13], data[14], data[15]]) as usize;

        // Calculate positions
        let entry_points_start = 16;
        let sources_start = entry_points_start + entry_points_len;
        let sources_end = sources_start + sources_len;

        if data.len() < sources_end {
            return Err("Data truncated in artifact section".to_string());
        }

        // Deserialize artifacts
        let entry_points: Map<String, usize> =
            serde_json::from_slice(&data[entry_points_start..sources_start])
                .map_err(|e| format!("Entry points deserialization failed: {}", e))?;

        let sources: Vec<SourceFile> = serde_json::from_slice(&data[sources_start..sources_end])
            .map_err(|e| format!("Sources deserialization failed: {}", e))?;

        Ok((entry_points, sources))
    }

    /// Deserialize program from binary format with version checking
    pub fn deserialize_binary(data: &[u8]) -> Result<DeserializationResult, String> {
        if data.len() < 28 {
            // Updated minimum size for new format (8 + 4*5 = 28 bytes for header)
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

        // Read lengths for entry_points and sources (first two sections)
        let entry_points_len = u32::from_le_bytes([data[8], data[9], data[10], data[11]]) as usize;
        let sources_len = u32::from_le_bytes([data[12], data[13], data[14], data[15]]) as usize;

        // Calculate positions for entry_points and sources data
        let entry_points_start = 16;
        let sources_start = entry_points_start + entry_points_len;
        let lengths_start = sources_start + sources_len;

        // Ensure we have enough data for the lengths section
        if data.len() < lengths_start + 12 {
            return Err("Data too short for lengths section".to_string());
        }

        // Read lengths for the remaining three data sections
        let binary_len = u32::from_le_bytes([
            data[lengths_start],
            data[lengths_start + 1],
            data[lengths_start + 2],
            data[lengths_start + 3],
        ]) as usize;
        let literals_len = u32::from_le_bytes([
            data[lengths_start + 4],
            data[lengths_start + 5],
            data[lengths_start + 6],
            data[lengths_start + 7],
        ]) as usize;
        let rule_tree_len = u32::from_le_bytes([
            data[lengths_start + 8],
            data[lengths_start + 9],
            data[lengths_start + 10],
            data[lengths_start + 11],
        ]) as usize;

        let total_expected = lengths_start + 12 + binary_len + literals_len + rule_tree_len;
        if data.len() < total_expected {
            return Err("Data truncated".to_string());
        }

        // Deserialize the program based on version
        match version {
            1 => {
                // Extract data sections (entry_points first, then sources, then binary, then literals, then rule_tree)
                let binary_start = lengths_start + 12;
                let literals_start = binary_start + binary_len;
                let rule_tree_start = literals_start + literals_len;

                // ARTIFACT SECTION - Always deserialize these first (guaranteed to work)
                let entry_points: Map<String, usize> =
                    serde_json::from_slice(&data[entry_points_start..sources_start])
                        .map_err(|e| format!("Entry points deserialization failed: {}", e))?;

                let sources: Vec<SourceFile> =
                    serde_json::from_slice(&data[sources_start..lengths_start])
                        .map_err(|e| format!("Sources deserialization failed: {}", e))?;

                // EXTENSIBLE SECTION - Try to deserialize, but allow graceful fallback
                let mut needs_recompilation = false;

                // Try to deserialize binary program structure
                let mut program =
                    match bincode::deserialize::<Program>(&data[binary_start..literals_start]) {
                        Ok(prog) => prog,
                        Err(_e) => {
                            // Binary section failed - create minimal program with artifacts only
                            needs_recompilation = true;
                            Program::new()
                        }
                    };

                // Try to deserialize literals
                let literals = match serde_json::from_slice::<Vec<Value>>(
                    &data[literals_start..rule_tree_start],
                ) {
                    Ok(lit) => lit,
                    Err(_e) => {
                        // Literals deserialization failed - use empty literals
                        needs_recompilation = true;
                        Vec::new()
                    }
                };

                // Try to deserialize rule tree
                let rule_tree = match serde_json::from_slice::<Value>(
                    &data[rule_tree_start..rule_tree_start + rule_tree_len],
                ) {
                    Ok(tree) => tree,
                    Err(_e) => {
                        // Rule tree deserialization failed - use empty rule tree
                        needs_recompilation = true;
                        Value::new_object()
                    }
                };

                // Set all fields (artifacts always succeed, extensible may have fallback values)
                program.entry_points = entry_points;
                program.sources = sources;
                program.literals = literals;
                program.rule_tree = rule_tree;
                program.needs_recompilation = needs_recompilation;

                // Try to initialize resolved builtins if we have builtin info
                if !program.builtin_info_table.is_empty() {
                    if let Err(_e) = program.initialize_resolved_builtins() {
                        // Failed to initialize resolved builtins - recompilation needed
                        program.needs_recompilation = true;
                    }
                }

                // Return appropriate enum variant based on whether recompilation is needed
                if program.needs_recompilation {
                    Ok(DeserializationResult::Partial(program))
                } else {
                    Ok(DeserializationResult::Complete(program))
                }
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
            entry_points: Map::new(),
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
            rule_tree: Value::new_object(),
            resolved_builtins: Vec::new(),
            needs_runtime_recursion_check: false,
            needs_recompilation: false,
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

    /// Initialize resolved builtins directly from the BUILTINS HashMap
    /// This should be called after deserialization to populate the skipped field
    /// Returns an error if any required builtin is missing
    pub fn initialize_resolved_builtins(&mut self) -> anyhow::Result<()> {
        self.resolved_builtins.clear();
        self.resolved_builtins
            .reserve(self.builtin_info_table.len());

        for builtin_info in &self.builtin_info_table {
            if let Some(&builtin_fcn) = crate::builtins::BUILTINS.get(builtin_info.name.as_str()) {
                self.resolved_builtins.push(builtin_fcn);
            } else {
                // Raise an error immediately when a builtin is missing
                return Err(anyhow::anyhow!(
                    "Missing builtin function: {}",
                    builtin_info.name
                ));
            }
        }

        Ok(())
    }

    /// Get resolved builtin function by index
    pub fn get_resolved_builtin(&self, index: u16) -> Option<&BuiltinFcn> {
        self.resolved_builtins.get(index as usize)
    }

    /// Check if resolved builtins are initialized
    pub fn has_resolved_builtins(&self) -> bool {
        !self.resolved_builtins.is_empty()
    }

    /// Add an entry point mapping from path to rule index
    pub fn add_entry_point(&mut self, path: String, rule_index: usize) {
        self.entry_points.insert(path, rule_index);
    }

    /// Get rule index for an entry point path
    pub fn get_entry_point(&self, path: &str) -> Option<usize> {
        self.entry_points.get(path).copied()
    }

    /// Get all entry points
    pub fn get_entry_points(&self) -> &Map<String, usize> {
        &self.entry_points
    }

    /// Check if recompilation is needed due to partial deserialization failure
    pub fn needs_recompilation(&self) -> bool {
        self.needs_recompilation
    }

    /// Mark that recompilation is needed
    pub fn set_needs_recompilation(&mut self, needs_recompilation: bool) {
        self.needs_recompilation = needs_recompilation;
    }

    /// Check if the program is fully functional (not needing recompilation)
    pub fn is_fully_functional(&self) -> bool {
        !self.needs_recompilation
    }

    /// Add a rule to the rule tree
    /// path: Package path components (e.g., ["p1", "p2"] for data.p1.p2.rule)
    /// rule_name: Rule name (e.g., "rule")
    /// rule_index: Index of the rule in rule_infos
    pub fn add_rule_to_tree(
        &mut self,
        path: &[String],
        rule_name: &str,
        rule_index: usize,
    ) -> Result<()> {
        // Create the full path including the rule name
        let mut full_path = Vec::with_capacity(path.len() + 1);
        full_path.extend(path.iter().map(|s| s.as_str()));
        full_path.push(rule_name);

        // Use make_or_get_value_mut to navigate/create the nested structure
        let target = self.rule_tree.make_or_get_value_mut(&full_path)?;

        // Set the rule index at the target location
        *target = Value::Number(rule_index.into());

        Ok(())
    }

    /// Check for conflicts between rule tree and data
    /// Returns an error if any rule path conflicts with data paths
    pub fn check_rule_data_conflicts(&self, data: &Value) -> Result<(), crate::rvm::vm::VmError> {
        // Ignore "data" prefix in rule tree.
        let actual_rule_tree = &self.rule_tree["data"];

        // If rule tree is empty or undefined (no rules compiled), there can be no conflicts
        match actual_rule_tree {
            Value::Undefined => return Ok(()),
            Value::Object(rule_obj) if rule_obj.is_empty() => return Ok(()),
            _ => {}
        }

        self.check_conflicts_recursive(actual_rule_tree, data, &mut Vec::new())
    }

    /// Recursively check for conflicts between rule tree and data
    fn check_conflicts_recursive(
        &self,
        rule_tree: &Value,
        data: &Value,
        current_path: &mut Vec<String>,
    ) -> Result<(), crate::rvm::vm::VmError> {
        match rule_tree {
            Value::Object(rule_obj) => {
                for (key, rule_value) in rule_obj.iter() {
                    if let Value::String(key_str) = key {
                        current_path.push(key_str.to_string());

                        // Check if data has the same path
                        let data_value = &data[key];

                        match rule_value {
                            Value::Number(_) => {
                                // This is a leaf rule - check for conflict
                                if data_value != &Value::Undefined {
                                    return Err(crate::rvm::vm::VmError::RuleDataConflict(format!(
                                        "Conflict: rule defines path '{}' but data also provides this path",
                                        current_path.join(".")
                                    )));
                                }
                            }
                            Value::Object(_) => {
                                // This is an intermediate node - recurse if data also has an object
                                if let Value::Object(_) = data_value {
                                    self.check_conflicts_recursive(
                                        rule_value,
                                        data_value,
                                        current_path,
                                    )?;
                                } else if data_value != &Value::Undefined {
                                    return Err(crate::rvm::vm::VmError::RuleDataConflict(format!(
                                        "Conflict: rule defines subpaths under '{}' but data provides a non-object value at this path",
                                        current_path.join(".")
                                    )));
                                }
                            }
                            _ => {
                                // Unexpected rule tree structure
                                return Err(crate::rvm::vm::VmError::RuleDataConflict(format!(
                                    "Invalid rule tree structure at path '{}'",
                                    current_path.join(".")
                                )));
                            }
                        }

                        current_path.pop();
                    }
                }
            }
            _ => {
                return Err(crate::rvm::vm::VmError::RuleDataConflict(
                    "Rule tree root must be an object".to_string(),
                ));
            }
        }

        Ok(())
    }
}

impl Default for Program {
    fn default() -> Self {
        Self::new()
    }
}
