// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Lazy evaluation and deferred value resolution
//!
//! This module provides lazy loading and deferred evaluation capabilities for Values.
//!
//! # Key Concepts
//!
//! - **LazyObject**: An object whose fields are loaded on-demand from external sources
//! - **DeferredValue**: A value that tracks a path but delays materialization until needed
//! - **LazyRegistry**: Global registry of schemas that define how to fetch fields
//! - **Field Strategies**: Per-field control over immediate vs deferred fetching
//!
//! # Use Cases
//!
//! - Database records with lazy joins
//! - Cloud resources with expensive API calls
//! - CBOR documents with lazy field decoding
//! - Azure Policy aliases with path tracking
//!
//! # Example
//!
//! ```rust,ignore
//! use regorus::lazy::*;
//!
//! // Register a schema
//! SchemaBuilder::new("User")
//!     .field_immediate("id", |ctx| Ok(ctx.get("user_id")?.clone()))
//!     .field_deferred("profile", |ctx| {
//!         // Expensive DB query - deferred until accessed
//!         let user_id = ctx.get("user_id")?.as_u64()?;
//!         fetch_user_profile(user_id)
//!     })
//!     .register();
//!
//! // Create lazy user
//! let user = create_lazy_user(123);
//!
//! // Access immediate field - no fetch
//! let id = user.get("id");  // Returns concrete value
//!
//! // Access deferred field - returns Deferred value
//! let profile = user.get("profile");  // Returns Deferred
//!
//! // Comparison triggers materialization
//! if profile.get("name") == "Alice" {  // NOW fetches from DB
//!     println!("Found Alice!");
//! }
//! ```

use alloc::{
    collections::BTreeMap,
    string::{String, ToString},
    sync::Arc,
    vec,
    vec::Vec,
};
use anyhow::{anyhow, bail, Result};
use core::any::Any;
use dashmap::DashMap;
use once_cell::sync::{Lazy, OnceCell};

// Import Value from parent crate
use crate::value::Value;

// Re-export for use by other modules
pub use dashmap;
pub use once_cell;

// ============================================================================
// Type Identifiers
// ============================================================================

/// Identifies a lazy object type (e.g., "User", "AzureVM", "CborObject")
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TypeId(Arc<str>);

impl TypeId {
    /// Create a new type identifier
    pub fn new(name: &str) -> Self {
        TypeId(name.into())
    }

    /// Get the type name
    pub fn as_str(&self) -> &str {
        self.0.as_ref()
    }
}

impl From<&str> for TypeId {
    fn from(s: &str) -> Self {
        TypeId::new(s)
    }
}

impl From<String> for TypeId {
    fn from(s: String) -> Self {
        TypeId::new(&s)
    }
}

// ============================================================================
// Path Segments for Tracking Field Access
// ============================================================================

/// A segment in a field access path
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PathSegment {
    /// Field access by name (e.g., `.properties`)
    Field(Arc<str>),
    /// Array index access (e.g., `[0]`)
    Index(usize),
}

impl PathSegment {
    /// Create a field segment
    pub fn field(name: impl Into<Arc<str>>) -> Self {
        PathSegment::Field(name.into())
    }

    /// Create an index segment
    pub fn index(idx: usize) -> Self {
        PathSegment::Index(idx)
    }

    /// Get as field name if this is a field segment
    pub fn as_field(&self) -> Option<&str> {
        match self {
            PathSegment::Field(name) => Some(name.as_ref()),
            _ => None,
        }
    }

    /// Get as index if this is an index segment
    pub fn as_index(&self) -> Option<usize> {
        match self {
            PathSegment::Index(idx) => Some(*idx),
            _ => None,
        }
    }
}

impl core::fmt::Display for PathSegment {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            PathSegment::Field(name) => write!(f, ".{}", name),
            PathSegment::Index(idx) => write!(f, "[{}]", idx),
        }
    }
}

// ============================================================================
// Lazy Context - Instance-Specific Data
// ============================================================================

/// Context data for a lazy object instance
///
/// Contains instance-specific information like IDs, raw bytes, etc.
/// that getters can use to fetch field values.
#[derive(Debug, Clone)]
pub struct LazyContext {
    /// Context data keyed by string names
    data: BTreeMap<Arc<str>, ContextValue>,
}

/// Values that can be stored in context
#[derive(Debug, Clone)]
pub enum ContextValue {
    U64(u64),
    I64(i64),
    String(Arc<str>),
    Bytes(Arc<Vec<u8>>),
    Bool(bool),
}

impl LazyContext {
    /// Create a new empty context
    pub fn new() -> Self {
        Self {
            data: BTreeMap::new(),
        }
    }

    /// Create context with initial data
    pub fn with_data(data: BTreeMap<Arc<str>, ContextValue>) -> Self {
        Self { data }
    }

    /// Insert a value into the context
    pub fn insert(&mut self, key: impl Into<Arc<str>>, value: impl Into<ContextValue>) {
        self.data.insert(key.into(), value.into());
    }

    /// Get a value from the context
    pub fn get(&self, key: &str) -> Option<&ContextValue> {
        self.data.get(key)
    }

    /// Get a u64 value
    pub fn get_u64(&self, key: &str) -> Result<u64> {
        match self.get(key) {
            Some(ContextValue::U64(v)) => Ok(*v),
            Some(ContextValue::I64(v)) if *v >= 0 => Ok(*v as u64),
            _ => bail!("missing or invalid u64 context value: {}", key),
        }
    }

    /// Get an i64 value
    pub fn get_i64(&self, key: &str) -> Result<i64> {
        match self.get(key) {
            Some(ContextValue::I64(v)) => Ok(*v),
            Some(ContextValue::U64(v)) if *v <= i64::MAX as u64 => Ok(*v as i64),
            _ => bail!("missing or invalid i64 context value: {}", key),
        }
    }

    /// Get a string value
    pub fn get_string(&self, key: &str) -> Result<&str> {
        match self.get(key) {
            Some(ContextValue::String(s)) => Ok(s.as_ref()),
            _ => bail!("missing or invalid string context value: {}", key),
        }
    }

    /// Get bytes value
    pub fn get_bytes(&self, key: &str) -> Result<&[u8]> {
        match self.get(key) {
            Some(ContextValue::Bytes(b)) => Ok(b.as_ref()),
            _ => bail!("missing or invalid bytes context value: {}", key),
        }
    }

    /// Get bool value
    pub fn get_bool(&self, key: &str) -> Result<bool> {
        match self.get(key) {
            Some(ContextValue::Bool(b)) => Ok(*b),
            _ => bail!("missing or invalid bool context value: {}", key),
        }
    }
}

impl Default for LazyContext {
    fn default() -> Self {
        Self::new()
    }
}

// Conversions for ContextValue
impl From<u64> for ContextValue {
    fn from(v: u64) -> Self {
        ContextValue::U64(v)
    }
}

impl From<i64> for ContextValue {
    fn from(v: i64) -> Self {
        ContextValue::I64(v)
    }
}

impl From<&str> for ContextValue {
    fn from(s: &str) -> Self {
        ContextValue::String(s.into())
    }
}

impl From<String> for ContextValue {
    fn from(s: String) -> Self {
        ContextValue::String(s.into())
    }
}

impl From<Arc<str>> for ContextValue {
    fn from(s: Arc<str>) -> Self {
        ContextValue::String(s)
    }
}

impl From<Vec<u8>> for ContextValue {
    fn from(b: Vec<u8>) -> Self {
        ContextValue::Bytes(Arc::new(b))
    }
}

impl From<&[u8]> for ContextValue {
    fn from(b: &[u8]) -> Self {
        ContextValue::Bytes(Arc::new(b.to_vec()))
    }
}

impl From<bool> for ContextValue {
    fn from(b: bool) -> Self {
        ContextValue::Bool(b)
    }
}

// ============================================================================
// Field Getters and Strategies
// ============================================================================

/// Trait for getting a field value
pub trait FieldGetter: Send + Sync {
    /// Get the field value from context
    fn get(&self, ctx: &LazyContext) -> Result<Value>;
}

/// Trait for getting all available keys
pub trait KeysGetter: Send + Sync {
    /// Get all keys that are available
    fn keys(&self, ctx: &LazyContext) -> Result<Vec<String>>;
}

/// Strategy for when to fetch a field
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldStrategy {
    /// Fetch immediately when field is accessed
    Immediate,

    /// Return a deferred value that fetches on materialization
    Deferred,

    /// Decide at runtime based on context
    Dynamic,
}

/// Trait for getters that can decide at runtime whether to defer
pub trait DynamicDeferrable: FieldGetter {
    /// Should this field be deferred for the given context?
    fn should_defer(&self, ctx: &LazyContext, field_name: &str) -> bool;

    /// Downcast to Any for type checking
    fn as_any(&self) -> &dyn Any;
}

/// Descriptor for a field - combines getter with strategy
#[derive(Clone)]
pub struct FieldDescriptor {
    /// The getter function
    getter: Arc<dyn FieldGetter>,

    /// Strategy for this field
    strategy: FieldStrategy,
}

impl FieldDescriptor {
    /// Create a new field descriptor
    pub fn new(getter: impl FieldGetter + 'static) -> Self {
        Self {
            getter: Arc::new(getter),
            strategy: FieldStrategy::Immediate,
        }
    }

    /// Set the strategy
    pub fn with_strategy(mut self, strategy: FieldStrategy) -> Self {
        self.strategy = strategy;
        self
    }

    /// Create an immediate field
    pub fn immediate(getter: impl FieldGetter + 'static) -> Self {
        Self::new(getter).with_strategy(FieldStrategy::Immediate)
    }

    /// Create a deferred field
    pub fn deferred(getter: impl FieldGetter + 'static) -> Self {
        Self::new(getter).with_strategy(FieldStrategy::Deferred)
    }

    /// Create a dynamic field
    pub fn dynamic(getter: impl FieldGetter + 'static) -> Self {
        Self::new(getter).with_strategy(FieldStrategy::Dynamic)
    }

    /// Get the strategy
    pub fn strategy(&self) -> FieldStrategy {
        self.strategy
    }

    /// Get the getter
    pub fn getter(&self) -> &Arc<dyn FieldGetter> {
        &self.getter
    }
}

// ============================================================================
// Lazy Schema
// ============================================================================

/// Schema defining how to fetch fields for a type
pub struct LazySchema {
    /// Type identifier
    type_id: TypeId,

    /// Field getters
    field_getters: DashMap<Arc<str>, Arc<FieldDescriptor>>,

    /// Keys getter (optional - if None, uses field names)
    key_getter: Option<Arc<dyn KeysGetter>>,
}

impl LazySchema {
    /// Create a new schema
    pub fn new(type_id: TypeId) -> Self {
        Self {
            type_id,
            field_getters: DashMap::new(),
            key_getter: None,
        }
    }

    /// Get the type ID
    pub fn type_id(&self) -> &TypeId {
        &self.type_id
    }

    /// Add a field descriptor
    pub fn add_field(&self, name: impl Into<Arc<str>>, descriptor: FieldDescriptor) {
        self.field_getters.insert(name.into(), Arc::new(descriptor));
    }

    /// Get a field descriptor
    pub fn get_field(&self, name: &str) -> Option<Arc<FieldDescriptor>> {
        self.field_getters.get(name).map(|r| r.value().clone())
    }

    /// Set the keys getter
    pub fn set_key_getter(&mut self, getter: impl KeysGetter + 'static) {
        self.key_getter = Some(Arc::new(getter));
    }

    /// Get all field names
    pub fn field_names(&self) -> Vec<String> {
        self.field_getters
            .iter()
            .map(|entry| entry.key().to_string())
            .collect()
    }

    /// Get keys using the key getter or field names
    pub fn get_keys(&self, ctx: &LazyContext) -> Result<Vec<String>> {
        if let Some(getter) = &self.key_getter {
            getter.keys(ctx)
        } else {
            Ok(self.field_names())
        }
    }
}

// ============================================================================
// Global Lazy Registry
// ============================================================================

/// Global registry of lazy schemas
pub struct LazyRegistry {
    schemas: DashMap<TypeId, Arc<LazySchema>>,
}

impl LazyRegistry {
    /// Create a new registry
    pub fn new() -> Self {
        Self {
            schemas: DashMap::new(),
        }
    }

    /// Get the global registry instance
    pub fn global() -> &'static LazyRegistry {
        static INSTANCE: Lazy<LazyRegistry> = Lazy::new(LazyRegistry::new);
        &INSTANCE
    }

    /// Register a schema
    pub fn register_schema(&self, schema: LazySchema) {
        let type_id = schema.type_id.clone();
        self.schemas.insert(type_id, Arc::new(schema));
    }

    /// Get a schema by type ID
    pub fn get_schema(&self, type_id: &TypeId) -> Option<Arc<LazySchema>> {
        self.schemas.get(type_id).map(|r| r.value().clone())
    }

    /// Check if a type is registered
    pub fn has_schema(&self, type_id: &TypeId) -> bool {
        self.schemas.contains_key(type_id)
    }
}

impl Default for LazyRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Schema Builder - Ergonomic API
// ============================================================================

/// Builder for creating lazy schemas
pub struct SchemaBuilder {
    type_id: TypeId,
    field_getters: DashMap<Arc<str>, Arc<FieldDescriptor>>,
    key_getter: Option<Arc<dyn KeysGetter>>,
}

impl SchemaBuilder {
    /// Create a new schema builder
    pub fn new(type_name: impl Into<TypeId>) -> Self {
        Self {
            type_id: type_name.into(),
            field_getters: DashMap::new(),
            key_getter: None,
        }
    }

    /// Add an immediate field with a custom getter
    pub fn field_immediate<G: FieldGetter + 'static>(self, name: &str, getter: G) -> Self {
        self.field_getters
            .insert(name.into(), Arc::new(FieldDescriptor::immediate(getter)));
        self
    }

    /// Add a deferred field with a custom getter
    pub fn field_deferred<G: FieldGetter + 'static>(self, name: &str, getter: G) -> Self {
        self.field_getters
            .insert(name.into(), Arc::new(FieldDescriptor::deferred(getter)));
        self
    }

    /// Add a dynamic field with a custom getter
    pub fn field_dynamic<G: FieldGetter + DynamicDeferrable + 'static>(
        self,
        name: &str,
        getter: G,
    ) -> Self {
        self.field_getters
            .insert(name.into(), Arc::new(FieldDescriptor::dynamic(getter)));
        self
    }

    /// Add a field with explicit strategy
    pub fn field_with_strategy<G: FieldGetter + 'static>(
        self,
        name: &str,
        getter: G,
        strategy: FieldStrategy,
    ) -> Self {
        self.field_getters.insert(
            name.into(),
            Arc::new(FieldDescriptor::new(getter).with_strategy(strategy)),
        );
        self
    }

    /// Set a custom keys getter
    pub fn keys<K: KeysGetter + 'static>(mut self, getter: K) -> Self {
        self.key_getter = Some(Arc::new(getter));
        self
    }

    /// Set keys from a static list
    pub fn keys_static(mut self, keys: &'static [&'static str]) -> Self {
        struct StaticKeysGetter(&'static [&'static str]);
        impl KeysGetter for StaticKeysGetter {
            fn keys(&self, _ctx: &LazyContext) -> Result<Vec<String>> {
                Ok(self.0.iter().map(|&k| k.to_string()).collect())
            }
        }

        self.key_getter = Some(Arc::new(StaticKeysGetter(keys)));
        self
    }

    /// Build and register the schema
    pub fn register(self) {
        let mut schema = LazySchema::new(self.type_id);

        for entry in self.field_getters.iter() {
            schema.add_field(entry.key().clone(), (**entry.value()).clone());
        }

        if let Some(getter) = self.key_getter {
            // We can't move out of Arc, so we need to clone the inner value
            // For now, we'll skip setting it - this would need refactoring
            // to make KeysGetter cloneable or use a different approach
            schema.key_getter = Some(getter);
        }

        LazyRegistry::global().register_schema(schema);
    }
}

// ============================================================================
// Closure-based Getters
// ============================================================================

/// Field getter implemented via closure
pub struct ClosureFieldGetter<F>
where
    F: Fn(&LazyContext) -> Result<Value> + Send + Sync,
{
    func: F,
}

impl<F> ClosureFieldGetter<F>
where
    F: Fn(&LazyContext) -> Result<Value> + Send + Sync,
{
    pub fn new(func: F) -> Self {
        Self { func }
    }
}

impl<F> FieldGetter for ClosureFieldGetter<F>
where
    F: Fn(&LazyContext) -> Result<Value> + Send + Sync,
{
    fn get(&self, ctx: &LazyContext) -> Result<Value> {
        (self.func)(ctx)
    }
}

// Extension methods for SchemaBuilder to support closures
impl SchemaBuilder {
    /// Add an immediate field with a closure
    pub fn field_immediate_fn<F>(self, name: &str, f: F) -> Self
    where
        F: Fn(&LazyContext) -> Result<Value> + Send + Sync + 'static,
    {
        self.field_immediate(name, ClosureFieldGetter::new(f))
    }

    /// Add a deferred field with a closure
    pub fn field_deferred_fn<F>(self, name: &str, f: F) -> Self
    where
        F: Fn(&LazyContext) -> Result<Value> + Send + Sync + 'static,
    {
        self.field_deferred(name, ClosureFieldGetter::new(f))
    }
}

// ============================================================================
// Deferred Value
// ============================================================================

/// A value whose materialization is deferred until needed
///
/// Tracks the path from root but doesn't fetch until compared or explicitly materialized.
pub struct DeferredValue {
    /// Path from root to this field
    path: Vec<PathSegment>,

    /// Root context for fetching
    root_context: Arc<LazyContext>,

    /// Root type ID
    root_type_id: TypeId,

    /// Cached materialized value
    materialized: OnceCell<Value>,
}

impl DeferredValue {
    /// Create a new deferred value
    pub fn new(
        path: Vec<PathSegment>,
        root_context: Arc<LazyContext>,
        root_type_id: TypeId,
    ) -> Self {
        Self {
            path,
            root_context,
            root_type_id,
            materialized: OnceCell::new(),
        }
    }

    /// Get the path
    pub fn path(&self) -> &[PathSegment] {
        &self.path
    }

    /// Get the root type ID
    pub fn root_type_id(&self) -> &TypeId {
        &self.root_type_id
    }

    /// Check if already materialized
    pub fn is_materialized(&self) -> bool {
        self.materialized.get().is_some()
    }

    /// Materialize the value by resolving the path
    pub fn materialize(&self) -> Result<&Value> {
        self.materialized
            .get_or_try_init(|| self.resolve_path())
            .map(|v| v as &Value)
    }

    /// Resolve the path to get the actual value
    fn resolve_path(&self) -> Result<Value> {
        let registry = LazyRegistry::global();

        // This is a placeholder - in real integration, this would walk the path
        // through Value types to fetch the actual field
        // For now, we just demonstrate the structure

        if self.path.is_empty() {
            return Ok(Value::Undefined);
        }

        // Get the schema for the root type
        let schema = registry
            .get_schema(&self.root_type_id)
            .ok_or_else(|| anyhow!("schema not found for type: {}", self.root_type_id.as_str()))?;

        // Get the first field
        if let Some(PathSegment::Field(field_name)) = self.path.first() {
            if let Some(descriptor) = schema.get_field(field_name.as_ref()) {
                return descriptor.getter().get(&self.root_context);
            }
        }

        bail!("cannot resolve path")
    }

    /// Extend the path with an additional segment
    pub fn extend(&self, segment: PathSegment) -> Self {
        let mut new_path = self.path.clone();
        new_path.push(segment);

        Self {
            path: new_path,
            root_context: self.root_context.clone(),
            root_type_id: self.root_type_id.clone(),
            materialized: OnceCell::new(),
        }
    }
}

impl core::fmt::Debug for DeferredValue {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DeferredValue")
            .field("type", &self.root_type_id.as_str())
            .field("path", &self.path)
            .field("materialized", &self.is_materialized())
            .finish()
    }
}

// Implement PartialEq for DeferredValue
impl PartialEq for DeferredValue {
    fn eq(&self, other: &Self) -> bool {
        // Two deferred values are equal if they point to the same path
        self.path == other.path && self.root_type_id == other.root_type_id
    }
}

impl Eq for DeferredValue {}

// Implement PartialOrd for DeferredValue
impl PartialOrd for DeferredValue {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

// Implement Ord for DeferredValue
impl Ord for DeferredValue {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        // Order by type ID first, then by path
        match self.root_type_id.cmp(&other.root_type_id) {
            core::cmp::Ordering::Equal => self.path.cmp(&other.path),
            other => other,
        }
    }
}

// ============================================================================
// Lazy Object
// ============================================================================

/// An object with lazy-loaded fields
pub struct LazyObject {
    /// Type identifier
    type_id: TypeId,

    /// Instance context
    context: Arc<LazyContext>,

    /// Cache for fetched fields
    cache: Arc<DashMap<String, Value>>,

    /// Eager fields (always available without fetching)
    eager_fields: Option<Arc<BTreeMap<String, Value>>>,

    /// Path from root (for nested lazy objects)
    path_from_root: Vec<PathSegment>,

    /// Root context (for creating deferred values)
    root_context: Option<Arc<LazyContext>>,

    /// Root type ID (for creating deferred values)
    root_type_id: Option<TypeId>,
}

impl LazyObject {
    /// Create a new lazy object (root)
    pub fn new(type_id: TypeId, context: LazyContext) -> Self {
        let context_arc = Arc::new(context);
        Self {
            type_id: type_id.clone(),
            context: context_arc.clone(),
            cache: Arc::new(DashMap::new()),
            eager_fields: None,
            path_from_root: vec![],
            root_context: Some(context_arc),
            root_type_id: Some(type_id),
        }
    }

    /// Create a nested lazy object that knows its path from root
    pub fn new_nested(
        type_id: TypeId,
        context: LazyContext,
        path_from_root: Vec<PathSegment>,
        root_context: Arc<LazyContext>,
        root_type_id: TypeId,
    ) -> Self {
        Self {
            type_id,
            context: Arc::new(context),
            cache: Arc::new(DashMap::new()),
            eager_fields: None,
            path_from_root,
            root_context: Some(root_context),
            root_type_id: Some(root_type_id),
        }
    }

    /// Set eager fields
    pub fn with_eager_fields(mut self, fields: BTreeMap<String, Value>) -> Self {
        self.eager_fields = Some(Arc::new(fields));
        self
    }

    /// Get the type ID
    pub fn type_id(&self) -> &TypeId {
        &self.type_id
    }

    /// Get the context
    pub fn context(&self) -> &LazyContext {
        &self.context
    }

    /// Get a field value
    ///
    /// Returns None if field doesn't exist.
    /// Depending on the field's strategy, may return a deferred value or fetch immediately.
    pub fn get_field(&self, field_name: &str) -> Result<Option<Value>> {
        // 1. Check eager fields first
        if let Some(eager) = &self.eager_fields {
            if let Some(value) = eager.get(field_name) {
                return Ok(Some(value.clone()));
            }
        }

        // 2. Check cache
        if let Some(cached) = self.cache.get(field_name) {
            return Ok(Some(cached.value().clone()));
        }

        // 3. Get from schema
        let registry = LazyRegistry::global();
        let schema = registry
            .get_schema(&self.type_id)
            .ok_or_else(|| anyhow!("schema not found for type: {}", self.type_id.as_str()))?;

        let descriptor = match schema.get_field(field_name) {
            Some(d) => d,
            None => return Ok(None),
        };

        // 4. Decide based on strategy
        let should_defer = match descriptor.strategy() {
            FieldStrategy::Immediate => false,
            FieldStrategy::Deferred => true,
            FieldStrategy::Dynamic => self.should_defer_field(field_name, descriptor.getter()),
        };

        if should_defer {
            // Return deferred value
            Ok(Some(self.create_deferred_for_field(field_name)))
        } else {
            // Fetch immediately
            let value = descriptor.getter().get(&self.context)?;
            self.cache.insert(field_name.to_string(), value.clone());
            Ok(Some(value))
        }
    }

    /// Check if a field should be deferred (for Dynamic strategy)
    fn should_defer_field(&self, _field_name: &str, _getter: &Arc<dyn FieldGetter>) -> bool {
        // Try to downcast to DynamicDeferrable
        // This is tricky with Arc<dyn FieldGetter> - would need better type structure

        // Check context for hints
        if let Ok(true) = self.context.get_bool("__defer_all") {
            return true;
        }

        // Default: don't defer
        false
    }

    /// Create a deferred value for a field
    fn create_deferred_for_field(&self, field_name: &str) -> Value {
        use crate::Rc;
        let root_context = self.root_context.as_ref().unwrap_or(&self.context).clone();
        let root_type_id = self.root_type_id.as_ref().unwrap_or(&self.type_id).clone();

        let mut full_path = self.path_from_root.clone();
        full_path.push(PathSegment::field(field_name));

        Value::Deferred(Rc::new(DeferredValue::new(
            full_path,
            root_context,
            root_type_id,
        )))
    }

    /// Get all keys
    pub fn keys(&self) -> Result<Vec<String>> {
        let mut keys = Vec::new();

        // Add eager keys
        if let Some(eager) = &self.eager_fields {
            keys.extend(eager.keys().cloned());
        }

        // Add lazy keys from schema
        let registry = LazyRegistry::global();
        if let Some(schema) = registry.get_schema(&self.type_id) {
            let lazy_keys = schema.get_keys(&self.context)?;
            for key in lazy_keys {
                if !keys.contains(&key) {
                    keys.push(key);
                }
            }
        }

        Ok(keys)
    }
}

impl core::fmt::Debug for LazyObject {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LazyObject")
            .field("type_id", &self.type_id.as_str())
            .field("cached_fields", &self.cache.len())
            .finish()
    }
}

// Implement PartialEq for LazyObject
impl PartialEq for LazyObject {
    fn eq(&self, other: &Self) -> bool {
        // Two lazy objects are equal if they have the same type and context
        // This is a shallow comparison - doesn't materialize fields
        self.type_id == other.type_id && Arc::ptr_eq(&self.context, &other.context)
    }
}

impl Eq for LazyObject {}

// Implement PartialOrd for LazyObject
impl PartialOrd for LazyObject {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

// Implement Ord for LazyObject
impl Ord for LazyObject {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        // Order by type ID first, then by context pointer
        match self.type_id.cmp(&other.type_id) {
            core::cmp::Ordering::Equal => {
                // Compare by pointer address as a stable ordering
                let self_ptr = Arc::as_ptr(&self.context) as usize;
                let other_ptr = Arc::as_ptr(&other.context) as usize;
                self_ptr.cmp(&other_ptr)
            }
            other => other,
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_type_id() {
        let id1 = TypeId::new("User");
        let id2 = TypeId::new("User");
        let id3 = TypeId::new("Post");

        assert_eq!(id1, id2);
        assert_ne!(id1, id3);
        assert_eq!(id1.as_str(), "User");
    }

    #[test]
    fn test_path_segment() {
        use alloc::format;

        let field = PathSegment::field("name");
        let index = PathSegment::index(42);

        assert_eq!(field.as_field(), Some("name"));
        assert_eq!(index.as_index(), Some(42));

        assert_eq!(format!("{}", field), ".name");
        assert_eq!(format!("{}", index), "[42]");
    }

    #[test]
    fn test_lazy_context() {
        let mut ctx = LazyContext::new();
        ctx.insert("user_id", 123u64);
        ctx.insert("name", "Alice");
        ctx.insert("active", true);

        assert_eq!(ctx.get_u64("user_id").unwrap(), 123);
        assert_eq!(ctx.get_string("name").unwrap(), "Alice");
        assert_eq!(ctx.get_bool("active").unwrap(), true);
    }

    #[test]
    fn test_deferred_value() {
        let mut ctx = LazyContext::new();
        ctx.insert("user_id", 123u64);

        let deferred = DeferredValue::new(
            vec![PathSegment::field("profile"), PathSegment::field("name")],
            Arc::new(ctx),
            TypeId::new("User"),
        );

        assert_eq!(deferred.path().len(), 2);
        assert_eq!(deferred.root_type_id().as_str(), "User");
        assert!(!deferred.is_materialized());
    }

    #[test]
    fn test_lazy_registry() {
        let registry = LazyRegistry::new();
        let schema = LazySchema::new(TypeId::new("TestType"));

        registry.register_schema(schema);
        assert!(registry.has_schema(&TypeId::new("TestType")));
        assert!(!registry.has_schema(&TypeId::new("OtherType")));
    }
}

/// Trait for getting the length of a lazy collection
pub trait LengthGetter: Send + Sync {
    /// Get the total number of elements in the collection
    fn len(&self, ctx: &LazyContext) -> Result<usize>;
}

/// Trait for getting an element at a specific index
pub trait IndexGetter: Send + Sync {
    /// Get the value at the specified index
    /// Returns None if index is out of bounds
    fn get_at(&self, ctx: &LazyContext, index: usize) -> Result<Option<Value>>;
}

/// A lazy array that fetches elements on-demand
#[derive(Clone)]
pub struct LazyArray {
    /// Context for this array
    context: Arc<LazyContext>,

    /// Length getter
    length_getter: Arc<dyn LengthGetter>,

    /// Index getter for fetching elements
    index_getter: Arc<dyn IndexGetter>,

    /// Cache for fetched elements
    cache: Arc<DashMap<usize, Value>>,

    /// Type identifier
    type_id: TypeId,
}

impl LazyArray {
    /// Create a new lazy array
    pub fn new(
        type_id: TypeId,
        context: LazyContext,
        length_getter: impl LengthGetter + 'static,
        index_getter: impl IndexGetter + 'static,
    ) -> Self {
        Self {
            context: Arc::new(context),
            length_getter: Arc::new(length_getter),
            index_getter: Arc::new(index_getter),
            cache: Arc::new(DashMap::new()),
            type_id,
        }
    }

    /// Get the type ID
    pub fn type_id(&self) -> &TypeId {
        &self.type_id
    }

    /// Get the length of the array
    pub fn len(&self) -> Result<usize> {
        self.length_getter.len(&self.context)
    }

    /// Check if array is empty
    pub fn is_empty(&self) -> Result<bool> {
        Ok(self.len()? == 0)
    }

    /// Get element at index (0-based)
    pub fn get(&self, index: usize) -> Result<Option<Value>> {
        // Check cache first
        if let Some(cached) = self.cache.get(&index) {
            return Ok(Some(cached.value().clone()));
        }

        // Fetch from getter
        let value = self.index_getter.get_at(&self.context, index)?;

        // Cache if found
        if let Some(ref v) = value {
            self.cache.insert(index, v.clone());
        }

        Ok(value)
    }

    /// Iterate over elements lazily
    /// This returns an iterator that fetches elements on-demand
    pub fn iter_lazy(&self) -> Result<LazyArrayIter> {
        let len = self.len()?;
        Ok(LazyArrayIter {
            array: self.clone(),
            current: 0,
            len,
        })
    }
}

/// Iterator for lazy arrays
pub struct LazyArrayIter {
    array: LazyArray,
    current: usize,
    len: usize,
}

impl Iterator for LazyArrayIter {
    type Item = Result<Value>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current >= self.len {
            return None;
        }

        let idx = self.current;
        self.current += 1;

        match self.array.get(idx) {
            Ok(Some(v)) => Some(Ok(v)),
            Ok(None) => None, // Index out of bounds
            Err(e) => Some(Err(e)),
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.len.saturating_sub(self.current);
        (remaining, Some(remaining))
    }
}

impl core::fmt::Debug for LazyArray {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LazyArray")
            .field("type_id", &self.type_id.as_str())
            .field("cached_elements", &self.cache.len())
            .finish()
    }
}

impl PartialEq for LazyArray {
    fn eq(&self, other: &Self) -> bool {
        // LazyArrays are equal if they have the same type_id and context
        self.type_id == other.type_id && Arc::ptr_eq(&self.context, &other.context)
    }
}

impl Eq for LazyArray {}

impl PartialOrd for LazyArray {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for LazyArray {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.type_id.cmp(&other.type_id)
    }
}

/// A lazy set that fetches elements on-demand
#[derive(Clone)]
pub struct LazySet {
    /// Context for this set
    context: Arc<LazyContext>,

    /// Length getter
    length_getter: Arc<dyn LengthGetter>,

    /// Index getter (sets are iterated by index internally)
    index_getter: Arc<dyn IndexGetter>,

    /// Cache for fetched elements
    cache: Arc<DashMap<usize, Value>>,

    /// Type identifier
    type_id: TypeId,
}

impl LazySet {
    /// Create a new lazy set
    pub fn new(
        type_id: TypeId,
        context: LazyContext,
        length_getter: impl LengthGetter + 'static,
        index_getter: impl IndexGetter + 'static,
    ) -> Self {
        Self {
            context: Arc::new(context),
            length_getter: Arc::new(length_getter),
            index_getter: Arc::new(index_getter),
            cache: Arc::new(DashMap::new()),
            type_id,
        }
    }

    /// Get the type ID
    pub fn type_id(&self) -> &TypeId {
        &self.type_id
    }

    /// Get the length of the set
    pub fn len(&self) -> Result<usize> {
        self.length_getter.len(&self.context)
    }

    /// Check if set is empty
    pub fn is_empty(&self) -> Result<bool> {
        Ok(self.len()? == 0)
    }

    /// Get element at index (for iteration)
    pub fn get(&self, index: usize) -> Result<Option<Value>> {
        // Check cache first
        if let Some(cached) = self.cache.get(&index) {
            return Ok(Some(cached.value().clone()));
        }

        // Fetch from getter
        let value = self.index_getter.get_at(&self.context, index)?;

        // Cache if found
        if let Some(ref v) = value {
            self.cache.insert(index, v.clone());
        }

        Ok(value)
    }

    /// Iterate over elements lazily
    pub fn iter_lazy(&self) -> Result<LazySetIter> {
        let len = self.len()?;
        Ok(LazySetIter {
            set: self.clone(),
            current: 0,
            len,
        })
    }
}

/// Iterator for lazy sets
pub struct LazySetIter {
    set: LazySet,
    current: usize,
    len: usize,
}

impl Iterator for LazySetIter {
    type Item = Result<Value>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current >= self.len {
            return None;
        }

        let idx = self.current;
        self.current += 1;

        match self.set.get(idx) {
            Ok(Some(v)) => Some(Ok(v)),
            Ok(None) => None,
            Err(e) => Some(Err(e)),
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.len.saturating_sub(self.current);
        (remaining, Some(remaining))
    }
}

impl core::fmt::Debug for LazySet {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LazySet")
            .field("type_id", &self.type_id.as_str())
            .field("cached_elements", &self.cache.len())
            .finish()
    }
}

impl PartialEq for LazySet {
    fn eq(&self, other: &Self) -> bool {
        // LazySets are equal if they have the same type_id and context
        self.type_id == other.type_id && Arc::ptr_eq(&self.context, &other.context)
    }
}

impl Eq for LazySet {}

impl PartialOrd for LazySet {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for LazySet {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.type_id.cmp(&other.type_id)
    }
}

// Integration tests in separate files
#[cfg(test)]
mod integration_tests;
