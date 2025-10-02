// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <memory>
#include <string>
#include <stdexcept>
#include <cstdint>
#include <vector>

// Forward declarations for C FFI
extern "C" {
    struct RegorusResult;
    
    // TypeId functions
    RegorusResult regorus_typeid_create(const char* name);
    void regorus_typeid_drop(void* type_id);
    
    // LazyContext functions
    RegorusResult regorus_lazy_context_create();
    RegorusResult regorus_lazy_context_insert_u64(void* context, const char* key, uint64_t value);
    RegorusResult regorus_lazy_context_insert_i64(void* context, const char* key, int64_t value);
    RegorusResult regorus_lazy_context_insert_string(void* context, const char* key, const char* value);
    RegorusResult regorus_lazy_context_insert_bool(void* context, const char* key, uint8_t value);
    RegorusResult regorus_lazy_context_insert_bytes(void* context, const char* key, const uint8_t* bytes, size_t len);
    RegorusResult regorus_lazy_context_get_u64(void* context, const char* key);
    void regorus_lazy_context_drop(void* context);
    
    // LazyObject functions
    RegorusResult regorus_lazy_object_create(void* type_id, void* context);
    RegorusResult regorus_value_from_lazy_object(void* lazy_object);
    void regorus_lazy_object_drop(void* lazy_object);
}

namespace regorus {

// Forward declarations
class Value;

/// RAII wrapper for Regorus TypeId
class TypeId {
private:
    void* ptr_;
    
    // Move-only type
    TypeId(const TypeId&) = delete;
    TypeId& operator=(const TypeId&) = delete;

public:
    /// Create a TypeId from a type name
    explicit TypeId(const std::string& name) {
        auto result = regorus_typeid_create(name.c_str());
        if (result.status != RegorusStatus::Ok) {
            throw std::runtime_error("Failed to create TypeId");
        }
        ptr_ = result.pointer_value;
        result.pointer_value = nullptr;  // Transfer ownership
        regorus_result_drop(result);
    }
    
    /// Move constructor
    TypeId(TypeId&& other) noexcept : ptr_(other.ptr_) {
        other.ptr_ = nullptr;
    }
    
    /// Move assignment
    TypeId& operator=(TypeId&& other) noexcept {
        if (this != &other) {
            if (ptr_) regorus_typeid_drop(ptr_);
            ptr_ = other.ptr_;
            other.ptr_ = nullptr;
        }
        return *this;
    }
    
    /// Destructor
    ~TypeId() noexcept {
        if (ptr_) regorus_typeid_drop(ptr_);
    }
    
    /// Release ownership of the underlying pointer
    void* release() noexcept {
        void* p = ptr_;
        ptr_ = nullptr;
        return p;
    }
    
    /// Check if valid
    bool is_valid() const noexcept {
        return ptr_ != nullptr;
    }
};

/// RAII wrapper for Regorus LazyContext
class LazyContext {
private:
    void* ptr_;
    
    // Move-only type
    LazyContext(const LazyContext&) = delete;
    LazyContext& operator=(const LazyContext&) = delete;

public:
    /// Create an empty LazyContext
    LazyContext() {
        auto result = regorus_lazy_context_create();
        if (result.status != RegorusStatus::Ok) {
            throw std::runtime_error("Failed to create LazyContext");
        }
        ptr_ = result.pointer_value;
        result.pointer_value = nullptr;  // Transfer ownership
        regorus_result_drop(result);
    }
    
    /// Move constructor
    LazyContext(LazyContext&& other) noexcept : ptr_(other.ptr_) {
        other.ptr_ = nullptr;
    }
    
    /// Move assignment
    LazyContext& operator=(LazyContext&& other) noexcept {
        if (this != &other) {
            if (ptr_) regorus_lazy_context_drop(ptr_);
            ptr_ = other.ptr_;
            other.ptr_ = nullptr;
        }
        return *this;
    }
    
    /// Destructor
    ~LazyContext() noexcept {
        if (ptr_) regorus_lazy_context_drop(ptr_);
    }
    
    /// Insert a u64 value
    LazyContext& insert_u64(const std::string& key, uint64_t value) {
        if (!ptr_) throw std::runtime_error("Invalid LazyContext");
        auto result = regorus_lazy_context_insert_u64(ptr_, key.c_str(), value);
        if (result.status != RegorusStatus::Ok) {
            throw std::runtime_error("Failed to insert u64");
        }
        return *this;
    }
    
    /// Insert an i64 value
    LazyContext& insert_i64(const std::string& key, int64_t value) {
        if (!ptr_) throw std::runtime_error("Invalid LazyContext");
        auto result = regorus_lazy_context_insert_i64(ptr_, key.c_str(), value);
        if (result.status != RegorusStatus::Ok) {
            throw std::runtime_error("Failed to insert i64");
        }
        return *this;
    }
    
    /// Insert a string value
    LazyContext& insert_string(const std::string& key, const std::string& value) {
        if (!ptr_) throw std::runtime_error("Invalid LazyContext");
        auto result = regorus_lazy_context_insert_string(ptr_, key.c_str(), value.c_str());
        if (result.status != RegorusStatus::Ok) {
            throw std::runtime_error("Failed to insert string");
        }
        return *this;
    }
    
    /// Insert a boolean value
    LazyContext& insert_bool(const std::string& key, bool value) {
        if (!ptr_) throw std::runtime_error("Invalid LazyContext");
        auto result = regorus_lazy_context_insert_bool(ptr_, key.c_str(), value ? 1 : 0);
        if (result.status != RegorusStatus::Ok) {
            throw std::runtime_error("Failed to insert bool");
        }
        return *this;
    }
    
    /// Insert a byte array
    LazyContext& insert_bytes(const std::string& key, const std::vector<uint8_t>& bytes) {
        if (!ptr_) throw std::runtime_error("Invalid LazyContext");
        auto result = regorus_lazy_context_insert_bytes(
            ptr_, key.c_str(), bytes.data(), bytes.size()
        );
        if (result.status != RegorusStatus::Ok) {
            throw std::runtime_error("Failed to insert bytes");
        }
        return *this;
    }
    
    /// Release ownership of the underlying pointer
    void* release() noexcept {
        void* p = ptr_;
        ptr_ = nullptr;
        return p;
    }
    
    /// Check if valid
    bool is_valid() const noexcept {
        return ptr_ != nullptr;
    }
};

/// RAII wrapper for Regorus LazyObject
class LazyObject {
private:
    void* ptr_;
    
    // Move-only type
    LazyObject(const LazyObject&) = delete;
    LazyObject& operator=(const LazyObject&) = delete;
    
    // Private constructor from raw pointer
    explicit LazyObject(void* ptr) : ptr_(ptr) {}

public:
    /// Create a LazyObject from TypeId and LazyContext
    /// Note: This takes ownership of type_id and context
    static LazyObject create(TypeId&& type_id, LazyContext&& context) {
        void* type_id_ptr = type_id.release();
        void* context_ptr = context.release();
        
        auto result = regorus_lazy_object_create(type_id_ptr, context_ptr);
        if (result.status != RegorusStatus::Ok) {
            throw std::runtime_error("Failed to create LazyObject");
        }
        
        void* ptr = result.pointer_value;
        result.pointer_value = nullptr;  // Transfer ownership
        regorus_result_drop(result);
        return LazyObject(ptr);
    }
    
    /// Move constructor
    LazyObject(LazyObject&& other) noexcept : ptr_(other.ptr_) {
        other.ptr_ = nullptr;
    }
    
    /// Move assignment
    LazyObject& operator=(LazyObject&& other) noexcept {
        if (this != &other) {
            if (ptr_) regorus_lazy_object_drop(ptr_);
            ptr_ = other.ptr_;
            other.ptr_ = nullptr;
        }
        return *this;
    }
    
    /// Destructor
    ~LazyObject() noexcept {
        if (ptr_) regorus_lazy_object_drop(ptr_);
    }
    
    /// Convert to a Value
    Value to_value() &&;  // Implemented in regorus_value.hpp
    
    /// Release ownership of the underlying pointer
    void* release() noexcept {
        void* p = ptr_;
        ptr_ = nullptr;
        return p;
    }
    
    /// Check if valid
    bool is_valid() const noexcept {
        return ptr_ != nullptr;
    }
};

// Forward declare Value class for to_value() implementation
class Value;

// Implementation of LazyObject::to_value() that needs Value definition
inline Value LazyObject::to_value() && {
    if (!ptr_) {
        throw std::runtime_error("Invalid LazyObject");
    }
    void* lazy_ptr = release();
    
    // Forward declaration - actual implementation requires regorus_value.hpp
    extern Value value_from_lazy_object_impl(void* lazy_object_ptr);
    return value_from_lazy_object_impl(lazy_ptr);
}

/// Helper to register a schema that extracts fields from LazyContext
inline void register_context_schema(
    const std::string& type_name,
    const std::vector<std::string>& string_fields = {},
    const std::vector<std::string>& i64_fields = {},
    const std::vector<std::string>& u64_fields = {},
    const std::vector<std::string>& bool_fields = {}
) {
    // Convert to C string arrays
    std::vector<const char*> str_ptrs;
    for (const auto& s : string_fields) {
        str_ptrs.push_back(s.c_str());
    }
    
    std::vector<const char*> i64_ptrs;
    for (const auto& s : i64_fields) {
        i64_ptrs.push_back(s.c_str());
    }
    
    std::vector<const char*> u64_ptrs;
    for (const auto& s : u64_fields) {
        u64_ptrs.push_back(s.c_str());
    }
    
    std::vector<const char*> bool_ptrs;
    for (const auto& s : bool_fields) {
        bool_ptrs.push_back(s.c_str());
    }
    
    auto result = regorus_register_context_schema(
        type_name.c_str(),
        str_ptrs.empty() ? nullptr : str_ptrs.data(), str_ptrs.size(),
        i64_ptrs.empty() ? nullptr : i64_ptrs.data(), i64_ptrs.size(),
        u64_ptrs.empty() ? nullptr : u64_ptrs.data(), u64_ptrs.size(),
        bool_ptrs.empty() ? nullptr : bool_ptrs.data(), bool_ptrs.size()
    );
    
    if (result.status != RegorusStatus::Ok) {
        std::string error = result.error_message ? result.error_message : "Failed to register schema";
        throw std::runtime_error(error);
    }
}

/// Type alias for field getter callbacks
/// Returns a Value pointer (which will be cloned and freed by Rust)
using FieldGetterCallback = void* (*)(const void* ctx, const char* field_name, void* user_data);

/// Helper class for callback-based schema registration
class CallbackSchemaBuilder {
private:
    std::string type_name_;
    std::vector<std::string> field_names_;
    std::vector<FieldGetterCallback> callbacks_;
    std::vector<void*> user_data_;

public:
    explicit CallbackSchemaBuilder(const std::string& type_name)
        : type_name_(type_name) {}
    
    /// Add a field with a custom getter callback
    CallbackSchemaBuilder& add_field(
        const std::string& field_name,
        FieldGetterCallback callback,
        void* user_data = nullptr
    ) {
        field_names_.push_back(field_name);
        callbacks_.push_back(callback);
        user_data_.push_back(user_data);
        return *this;
    }
    
    /// Register the schema
    void build() {
        if (field_names_.empty()) {
            throw std::runtime_error("No fields defined for schema");
        }
        
        // Convert field names to C strings
        std::vector<const char*> name_ptrs;
        for (const auto& name : field_names_) {
            name_ptrs.push_back(name.c_str());
        }
        
        auto result = regorus_register_callback_schema(
            type_name_.c_str(),
            name_ptrs.data(),
            callbacks_.data(),
            user_data_.data(),
            field_names_.size()
        );
        
        if (result.status != RegorusStatus::Ok) {
            std::string error = result.error_message ? result.error_message : "Failed to register callback schema";
            throw std::runtime_error(error);
        }
    }
};

} // namespace regorus
