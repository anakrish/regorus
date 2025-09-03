use crate::rvm::instructions::Instruction;
use crate::value::Value;
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

extern crate alloc;

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
        source_table.get(self.source_index).map(|s| s.content.as_str())
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
    /// Span information for the rule definition
    pub span: SpanInfo,
    /// Rule type (e.g., "basic", "set", "function")
    pub rule_type: String,
    /// Entry point instruction index
    pub entry_point: usize,
    /// End instruction index (exclusive)
    pub end_point: usize,
}

impl RuleInfo {
    pub fn new(
        name: String,
        span: SpanInfo,
        rule_type: String,
        entry_point: usize,
        end_point: usize,
    ) -> Self {
        Self {
            name,
            span,
            rule_type,
            entry_point,
            end_point,
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

impl SourceFile {
}

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
    
    /// Source files table with content
    pub sources: Vec<SourceFile>,
    
    /// Rule entry points: rule_index -> instruction_address
    pub rule_entry_points: Vec<usize>,
    
    /// Rule metadata: rule_index -> rule information
    pub rule_info: Vec<RuleInfo>,
    
    /// Span information for each instruction (for debugging)
    pub instruction_spans: Vec<Option<SpanInfo>>,
    
    /// Main program entry point
    pub main_entry_point: usize,
    
    /// Rule name to index mapping for lookup
    pub rule_name_to_index: BTreeMap<String, usize>,
    
    /// Program metadata
    pub metadata: ProgramMetadata,
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
        let json_data = serde_json::to_vec(self)
            .map_err(|e| format!("JSON serialization failed: {}", e))?;
        
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
        if &data[0..4] != &Self::MAGIC {
            return Err("Invalid file format - magic number mismatch".to_string());
        }
        
        // Check version
        let version = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        if version > Self::SERIALIZATION_VERSION {
            return Err(format!(
                "Unsupported version {}. Maximum supported version is {}",
                version, Self::SERIALIZATION_VERSION
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
        if &data[0..4] != &Self::MAGIC {
            return Ok(false);
        }
        
        // Check version
        let version = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        
        match version {
            1 => Ok(true), // Supported version
            _ => Ok(false), // Unsupported version
        }
    }
    
    /// Get file format information without deserializing
    pub fn get_file_info(data: &[u8]) -> Result<(u32, usize), String> {
        if data.len() < 12 {
            return Err("Data too short for header".to_string());
        }
        
        if &data[0..4] != &Self::MAGIC {
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
            sources: Vec::new(),
            rule_entry_points: Vec::new(),
            rule_info: Vec::new(),
            instruction_spans: Vec::new(),
            main_entry_point: 0,
            rule_name_to_index: BTreeMap::new(),
            metadata: ProgramMetadata {
                compiler_version: env!("CARGO_PKG_VERSION").to_string(),
                compiled_at: "unknown".to_string(),
                source_info: "unknown".to_string(),
                optimization_level: 0,
            },
        }
    }
    
    /// Add a source file and return its index
    pub fn add_source(&mut self, name: String, content: String) -> usize {
        let source_file = SourceFile::new(name.clone(), content);
        
        // Check if source already exists to avoid duplicates (by name)
        for (i, existing) in self.sources.iter().enumerate() {
            if existing.name == name {
                return i;
            }
        }
        
        let index = self.sources.len();
        self.sources.push(source_file);
        index
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
    
    /// Get rule index by name
    pub fn get_rule_index(&self, rule_name: &str) -> Option<usize> {
        self.rule_name_to_index.get(rule_name).copied()
    }
    
    /// Get rule info by index
    pub fn get_rule_info(&self, rule_index: usize) -> Option<&RuleInfo> {
        self.rule_info.get(rule_index)
    }
    
    /// Get rule info by name
    pub fn get_rule_info_by_name(&self, rule_name: &str) -> Option<&RuleInfo> {
        self.get_rule_index(rule_name)
            .and_then(|idx| self.get_rule_info(idx))
    }
    
    /// Get entry point for rule
    pub fn get_rule_entry_point(&self, rule_index: usize) -> Option<usize> {
        self.rule_entry_points.get(rule_index).copied()
    }
    
    /// Get span information for instruction
    pub fn get_instruction_span(&self, instruction_index: usize) -> Option<&SpanInfo> {
        self.instruction_spans
            .get(instruction_index)
            .and_then(|span| span.as_ref())
    }
    
    /// Add a new rule to the program
    pub fn add_rule(
        &mut self,
        name: String,
        span: SpanInfo,
        rule_type: String,
        entry_point: usize,
        end_point: usize,
    ) -> usize {
        let rule_index = self.rule_info.len();
        
        // Add rule info
        self.rule_info.push(RuleInfo::new(
            name.clone(),
            span,
            rule_type,
            entry_point,
            end_point,
        ));
        
        // Add entry point
        self.rule_entry_points.push(entry_point);
        
        // Add name mapping
        self.rule_name_to_index.insert(name, rule_index);
        
        rule_index
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
    
    /// Validate program integrity
    pub fn validate(&self) -> Result<(), String> {
        // Check that rule entry points are valid
        for (i, &entry_point) in self.rule_entry_points.iter().enumerate() {
            if entry_point >= self.instructions.len() {
                return Err(format!(
                    "Rule {} has invalid entry point {}, program has {} instructions",
                    i, entry_point, self.instructions.len()
                ));
            }
        }
        
        // Check that main entry point is valid
        if self.main_entry_point >= self.instructions.len() && !self.instructions.is_empty() {
            return Err(format!(
                "Main entry point {} is invalid, program has {} instructions",
                self.main_entry_point, self.instructions.len()
            ));
        }
        
        // Check that instruction spans match instructions
        if self.instruction_spans.len() != self.instructions.len() {
            return Err(format!(
                "Instruction spans length {} doesn't match instructions length {}",
                self.instruction_spans.len(), self.instructions.len()
            ));
        }
        
        // Check rule info consistency
        if self.rule_info.len() != self.rule_entry_points.len() {
            return Err(format!(
                "Rule info length {} doesn't match entry points length {}",
                self.rule_info.len(), self.rule_entry_points.len()
            ));
        }
        
        Ok(())
    }
    
    /// Get statistics about the program
    pub fn get_stats(&self) -> ProgramStats {
        ProgramStats {
            instruction_count: self.instructions.len(),
            literal_count: self.literals.len(),
            rule_count: self.rule_info.len(),
            memory_usage: self.estimate_memory_usage(),
        }
    }
    
    /// Estimate memory usage in bytes
    fn estimate_memory_usage(&self) -> usize {
        use core::mem::size_of;
        
        let instructions_size = self.instructions.len() * size_of::<Instruction>();
        let literals_size = self.literals.iter()
            .map(|v| v.estimate_size())
            .sum::<usize>();
        let metadata_size = size_of::<ProgramMetadata>() + 
            self.rule_info.len() * size_of::<RuleInfo>() +
            self.rule_entry_points.len() * size_of::<usize>();
        
        instructions_size + literals_size + metadata_size
    }
}

/// Program statistics for monitoring and debugging
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramStats {
    pub instruction_count: usize,
    pub literal_count: usize,
    pub rule_count: usize,
    pub memory_usage: usize,
}

impl Default for Program {
    fn default() -> Self {
        Self::new()
    }
}

// Extension trait for Value to estimate memory usage
trait ValueSize {
    fn estimate_size(&self) -> usize;
}

impl ValueSize for Value {
    fn estimate_size(&self) -> usize {
        use core::mem::size_of;
        
        match self {
            Value::Null | Value::Undefined => size_of::<Value>(),
            Value::Bool(_) => size_of::<Value>(),
            Value::Number(_) => size_of::<Value>() + size_of::<f64>(),
            Value::String(s) => size_of::<Value>() + s.len(),
            Value::Array(arr) => {
                size_of::<Value>() + arr.iter().map(|v| v.estimate_size()).sum::<usize>()
            }
            Value::Object(obj) => {
                size_of::<Value>() + obj.iter()
                    .map(|(k, v)| k.estimate_size() + v.estimate_size())
                    .sum::<usize>()
            }
            Value::Set(set) => {
                size_of::<Value>() + set.iter().map(|v| v.estimate_size()).sum::<usize>()
            }
        }
    }
}
