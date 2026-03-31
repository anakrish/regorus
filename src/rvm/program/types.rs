// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
use crate::Rc;
use alloc::collections::BTreeMap;
use alloc::collections::BTreeSet;
use alloc::string::String;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

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

impl SpanInfo {
    pub const fn new(source_index: usize, line: usize, column: usize, length: usize) -> Self {
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
            line: span.line.try_into().unwrap_or(usize::MAX),
            column: span.col.try_into().unwrap_or(usize::MAX),
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

/// Rule type enumeration for different kinds of rules (complete, partial set, partial object)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, PartialOrd, Eq, Ord)]
pub enum RuleType {
    Complete,
    PartialSet,
    PartialObject,
}

/// Information about function rules
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionInfo {
    /// Parameter names in order
    pub param_names: Vec<String>,
    /// Number of parameters
    pub num_params: u32,
}

/// Rule metadata for debugging and introspection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleInfo {
    /// Rule name (e.g., "data.package.rule_name")
    pub name: String,
    /// Rule type
    pub rule_type: RuleType,
    /// Definitions
    pub definitions: crate::Rc<Vec<Vec<u32>>>,
    /// Function-specific information (only present for function rules)
    pub function_info: Option<FunctionInfo>,
    /// Index into the program's literal table for default value (only for Complete rules)
    pub default_literal_index: Option<u16>,
    /// Register allocated for this rule's result accumulation
    pub result_reg: u8,
    /// Number of registers used by this rule (for register windowing)
    pub num_registers: u8,
    /// Optional destructuring block entry point per definition
    /// Index: definition_index → Some(entry_point) | None
    pub destructuring_blocks: Vec<Option<u32>>,
}

impl RuleInfo {
    pub fn new(
        name: String,
        rule_type: RuleType,
        definitions: crate::Rc<Vec<Vec<u32>>>,
        result_reg: u8,
        num_registers: u8,
    ) -> Self {
        let num_definitions = definitions.len();
        Self {
            name,
            rule_type,
            definitions,
            function_info: None,
            default_literal_index: None,
            result_reg,
            num_registers,
            destructuring_blocks: alloc::vec![None; num_definitions],
        }
    }

    /// Create a new function rule with parameter information
    pub fn new_function(
        name: String,
        rule_type: RuleType,
        definitions: crate::Rc<Vec<Vec<u32>>>,
        param_names: Vec<String>,
        result_reg: u8,
        num_registers: u8,
    ) -> Self {
        let num_params = u32::try_from(param_names.len()).unwrap_or(u32::MAX);
        let num_definitions = definitions.len();
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
            destructuring_blocks: alloc::vec![None; num_definitions],
        }
    }

    /// Set the default literal index for this rule
    pub const fn set_default_literal_index(&mut self, default_literal_index: u16) {
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

impl SourceFile {
    pub const fn new(name: String, content: String) -> Self {
        Self { name, content }
    }
}

/// Program compilation metadata
///
/// Annotations are stored as `Value` at runtime for zero-cost access via `LoadMetadata`.
/// Serialization converts through `MetadataValue` — a postcard/bincode-safe enum that
/// avoids `deserialize_any`.
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
    /// Source language that was compiled (e.g. "rego", "azure_policy", "cedar")
    #[serde(default)]
    pub language: String,
    /// Language-specific and user-defined annotations for indexing and introspection.
    /// Stored as `Value` for direct runtime use; serialized via `MetadataValue`.
    #[serde(
        default,
        serialize_with = "metadata_serde::serialize_annotations",
        deserialize_with = "metadata_serde::deserialize_annotations"
    )]
    pub annotations: BTreeMap<String, crate::value::Value>,
}

impl ProgramMetadata {
    /// Convert the full metadata struct into a regorus `Value` for runtime access.
    pub fn to_value(&self) -> crate::value::Value {
        use crate::value::Value;

        let mut obj = BTreeMap::new();
        obj.insert(
            Value::String("compiler_version".into()),
            Value::String(self.compiler_version.as_str().into()),
        );
        obj.insert(
            Value::String("compiled_at".into()),
            Value::String(self.compiled_at.as_str().into()),
        );
        obj.insert(
            Value::String("source_info".into()),
            Value::String(self.source_info.as_str().into()),
        );
        obj.insert(
            Value::String("optimization_level".into()),
            Value::from(f64::from(self.optimization_level)),
        );
        obj.insert(
            Value::String("language".into()),
            Value::String(self.language.as_str().into()),
        );

        if !self.annotations.is_empty() {
            let mut annotations_obj = BTreeMap::new();
            for (k, v) in &self.annotations {
                annotations_obj.insert(Value::String(k.as_str().into()), v.clone());
            }
            obj.insert(
                Value::String("annotations".into()),
                Value::Object(Rc::new(annotations_obj)),
            );
        }

        Value::Object(Rc::new(obj))
    }
}

// ── MetadataValue: postcard-safe serialization bridge ────────────────────────

/// A postcard-compatible, recursive value type used exclusively for serializing
/// program metadata annotations.
///
/// Unlike `serde_json::Value` or regorus `Value`, this enum uses explicit variant
/// tags and does not rely on `deserialize_any`, making it safe for use with
/// non-self-describing formats such as postcard and bincode.
///
/// At runtime, annotations are stored as `Value` for zero-cost access.
/// This type is only used during `Serialize` / `Deserialize` of `ProgramMetadata`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum MetadataValue {
    /// A string value
    String(String),
    /// A set of unique strings (sorted)
    StringSet(BTreeSet<String>),
    /// A boolean value
    Bool(bool),
    /// A 64-bit signed integer
    Integer(i64),
    /// An ordered list of metadata values (recursive)
    List(Vec<MetadataValue>),
    /// A string-keyed map of metadata values (recursive)
    Map(BTreeMap<String, MetadataValue>),
}

impl MetadataValue {
    /// Convert a regorus `Value` into a `MetadataValue` for serialization.
    ///
    /// Values that cannot be represented (Undefined, Number with fractional part,
    /// non-string object keys) are mapped on a best-effort basis.
    pub fn from_value(value: &crate::value::Value) -> Self {
        use crate::value::Value;
        match *value {
            Value::String(ref s) => MetadataValue::String(String::from(s.as_ref())),
            Value::Bool(b) => MetadataValue::Bool(b),
            Value::Number(ref n) => {
                // Try integer first, fall back to f64 truncation
                n.as_i64().map_or_else(
                    || {
                        n.as_f64().map_or(MetadataValue::Integer(0), |f| {
                            // Deliberate truncation of f64 to i64 for metadata storage
                            #[expect(clippy::as_conversions)]
                            let i = f as i64;
                            MetadataValue::Integer(i)
                        })
                    },
                    MetadataValue::Integer,
                )
            }
            Value::Array(ref arr) => {
                MetadataValue::List(arr.iter().map(MetadataValue::from_value).collect())
            }
            Value::Set(ref set) => {
                // If all elements are strings, use StringSet; otherwise List
                let all_strings = set.iter().all(|v| matches!(*v, Value::String(_)));
                if all_strings {
                    MetadataValue::StringSet(
                        set.iter()
                            .filter_map(|v| match *v {
                                Value::String(ref s) => Some(String::from(s.as_ref())),
                                _ => None,
                            })
                            .collect(),
                    )
                } else {
                    MetadataValue::List(set.iter().map(MetadataValue::from_value).collect())
                }
            }
            Value::Object(ref obj) => {
                let mut map = BTreeMap::new();
                for (k, v) in obj.iter() {
                    let key = match *k {
                        Value::String(ref s) => String::from(s.as_ref()),
                        ref other => alloc::format!("{}", other),
                    };
                    map.insert(key, MetadataValue::from_value(v));
                }
                MetadataValue::Map(map)
            }
            Value::Null | Value::Undefined => MetadataValue::String(String::new()),
        }
    }

    /// Convert this `MetadataValue` into a regorus `Value`.
    pub fn to_value(&self) -> crate::value::Value {
        use crate::value::Value;
        match *self {
            MetadataValue::String(ref s) => Value::String(s.as_str().into()),
            MetadataValue::StringSet(ref set) => {
                let mut bset = alloc::collections::BTreeSet::new();
                for s in set {
                    bset.insert(Value::String(s.as_str().into()));
                }
                Value::Set(Rc::new(bset))
            }
            MetadataValue::Bool(b) => Value::Bool(b),
            MetadataValue::Integer(n) => Value::from(n),
            MetadataValue::List(ref list) => {
                let values: Vec<Value> = list.iter().map(MetadataValue::to_value).collect();
                Value::Array(Rc::new(values))
            }
            MetadataValue::Map(ref map) => {
                let mut obj = BTreeMap::new();
                for (k, v) in map {
                    obj.insert(Value::String(k.as_str().into()), v.to_value());
                }
                Value::Object(Rc::new(obj))
            }
        }
    }
}

/// Serde helpers for `annotations: BTreeMap<String, Value>`.
/// Serializes via `BTreeMap<String, MetadataValue>` to stay postcard-compatible.
mod metadata_serde {
    use super::*;

    pub fn serialize_annotations<S>(
        annotations: &BTreeMap<String, crate::value::Value>,
        serializer: S,
    ) -> core::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::Serialize as _;
        let bridge: BTreeMap<String, MetadataValue> = annotations
            .iter()
            .map(|(k, v)| (k.clone(), MetadataValue::from_value(v)))
            .collect();
        bridge.serialize(serializer)
    }

    pub fn deserialize_annotations<'de, D>(
        deserializer: D,
    ) -> core::result::Result<BTreeMap<String, crate::value::Value>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bridge: BTreeMap<String, MetadataValue> = BTreeMap::deserialize(deserializer)?;
        Ok(bridge
            .iter()
            .map(|(k, v)| (k.clone(), v.to_value()))
            .collect())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::value::Value;
    use alloc::collections::BTreeSet;

    /// Round-trip: Value → MetadataValue → Value must be equivalent for
    /// all lossless variants.
    fn assert_round_trip(original: &Value, expected: &Value) {
        let mv = MetadataValue::from_value(original);
        let recovered = mv.to_value();
        assert_eq!(
            &recovered, expected,
            "round-trip failed for {original:?} → {mv:?} → {recovered:?}"
        );
    }

    #[test]
    fn round_trip_string() {
        let v = Value::String("hello".into());
        assert_round_trip(&v, &v);
    }

    #[test]
    fn round_trip_bool() {
        assert_round_trip(&Value::Bool(true), &Value::Bool(true));
        assert_round_trip(&Value::Bool(false), &Value::Bool(false));
    }

    #[test]
    fn round_trip_integer() {
        let v = Value::from(42_i64);
        assert_round_trip(&v, &v);
    }

    #[test]
    fn round_trip_array() {
        let v = Value::from_json_str(r#"[1, "two", true]"#).unwrap();
        assert_round_trip(&v, &v);
    }

    #[test]
    fn round_trip_string_set() {
        let mut set = BTreeSet::new();
        set.insert(Value::String("a".into()));
        set.insert(Value::String("b".into()));
        let v = Value::Set(Rc::new(set));
        assert_round_trip(&v, &v);
    }

    #[test]
    fn round_trip_object() {
        let v = Value::from_json_str(r#"{"key": "value", "n": 7}"#).unwrap();
        assert_round_trip(&v, &v);
    }

    #[test]
    fn null_maps_to_empty_string() {
        let mv = MetadataValue::from_value(&Value::Null);
        assert_eq!(mv, MetadataValue::String(String::new()));
    }

    #[test]
    fn undefined_maps_to_empty_string() {
        let mv = MetadataValue::from_value(&Value::Undefined);
        assert_eq!(mv, MetadataValue::String(String::new()));
    }

    #[test]
    fn mixed_set_uses_list() {
        let mut set = BTreeSet::new();
        set.insert(Value::String("a".into()));
        set.insert(Value::from(1_i64));
        let v = Value::Set(Rc::new(set));
        let mv = MetadataValue::from_value(&v);
        assert!(
            matches!(mv, MetadataValue::List(_)),
            "mixed-type set should produce List, got {mv:?}"
        );
    }
}
