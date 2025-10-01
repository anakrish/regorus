// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <string>
#include <memory>
#include <stdexcept>
#include <cstdint>

// Include the C FFI header
#include "regorus.ffi.hpp"

namespace regorus {

class RegorusException : public std::runtime_error {
public:
    explicit RegorusException(const std::string& message)
        : std::runtime_error(message) {}
};

// RAII wrapper for regorus::Value
class Value {
private:
    void* ptr_;

    // Private constructor from raw pointer (used internally)
    explicit Value(void* ptr) : ptr_(ptr) {
        if (!ptr) {
            throw RegorusException("Null value pointer");
        }
    }

    // Helper to check result and extract pointer
    static void* extract_pointer(RegorusResult result) {
        if (result.status != RegorusStatus::Ok) { // 0 = Ok
            std::string error = result.error_message ? result.error_message : "Unknown error";
            regorus_result_drop(result);
            throw RegorusException(error);
        }
        void* ptr = result.pointer_value;
        regorus_result_drop(result);
        return ptr;
    }

    // Helper to check result and extract string
    static std::string extract_string(RegorusResult result) {
        if (result.status != RegorusStatus::Ok) {
            std::string error = result.error_message ? result.error_message : "Unknown error";
            regorus_result_drop(result);
            throw RegorusException(error);
        }
        // Copy the string before dropping the result (which frees the C string)
        std::string str = result.output ? result.output : "";
        regorus_result_drop(result);  // This frees result.output
        return str;
    }

    // Helper to check result and extract bool
    static bool extract_bool(RegorusResult result) {
        if (result.status != RegorusStatus::Ok) {
            std::string error = result.error_message ? result.error_message : "Unknown error";
            regorus_result_drop(result);
            throw RegorusException(error);
        }
        bool value = result.bool_value;
        regorus_result_drop(result);
        return value;
    }

    // Helper to check void result
    static void check_result(RegorusResult result) {
        if (result.status != RegorusStatus::Ok) {
            std::string error = result.error_message ? result.error_message : "Unknown error";
            regorus_result_drop(result);
            throw RegorusException(error);
        }
        regorus_result_drop(result);
    }

public:
    // Factory methods for creating values
    static Value Null() {
        return Value(extract_pointer(regorus_value_create_null()));
    }

    static Value Bool(bool value) {
        return Value(extract_pointer(regorus_value_create_bool(value)));
    }

    static Value Int(int64_t value) {
        return Value(extract_pointer(regorus_value_create_int(value)));
    }

    static Value Float(double value) {
        return Value(extract_pointer(regorus_value_create_float(value)));
    }

    static Value String(const std::string& value) {
        return Value(extract_pointer(regorus_value_create_string(value.c_str())));
    }

    static Value Array() {
        return Value(extract_pointer(regorus_value_create_array()));
    }

    static Value Object() {
        return Value(extract_pointer(regorus_value_create_object()));
    }

    static Value Set() {
        return Value(extract_pointer(regorus_value_create_set()));
    }

    static Value FromJson(const std::string& json) {
        return Value(extract_pointer(regorus_value_from_json(json.c_str())));
    }

    // Move constructor
    Value(Value&& other) noexcept : ptr_(other.ptr_) {
        other.ptr_ = nullptr;
    }

    // Move assignment
    Value& operator=(Value&& other) noexcept {
        if (this != &other) {
            if (ptr_) {
                regorus_value_drop(ptr_);
            }
            ptr_ = other.ptr_;
            other.ptr_ = nullptr;
        }
        return *this;
    }

    // Disable copy (use Clone() explicitly)
    Value(const Value&) = delete;
    Value& operator=(const Value&) = delete;

    // Destructor - noexcept to prevent termination during stack unwinding
    ~Value() noexcept {
        if (ptr_) {
            regorus_value_drop(ptr_);
        }
    }

    // Get raw pointer (for internal use)
    void* get() const { return ptr_; }

    // Release ownership (returns raw pointer, caller must manage memory)
    void* release() {
        void* p = ptr_;
        ptr_ = nullptr;
        return p;
    }

    // Type checking - noexcept because const query methods should not throw
    // Returns false on error rather than throwing
    bool is_null() const noexcept {
        RegorusResult result = regorus_value_is_null(ptr_);
        bool value = (result.status == RegorusStatus::Ok) ? result.bool_value : false;
        regorus_result_drop(result);
        return value;
    }

    bool is_object() const noexcept {
        RegorusResult result = regorus_value_is_object(ptr_);
        bool value = (result.status == RegorusStatus::Ok) ? result.bool_value : false;
        regorus_result_drop(result);
        return value;
    }

    bool is_lazy_object() const noexcept {
        RegorusResult result = regorus_value_is_lazy_object(ptr_);
        bool value = (result.status == RegorusStatus::Ok) ? result.bool_value : false;
        regorus_result_drop(result);
        return value;
    }

    // Clone - creates a deep copy
    Value clone() const {
        return Value(extract_pointer(regorus_value_clone(ptr_)));
    }

    // JSON serialization
    std::string to_json() const {
        return extract_string(regorus_value_to_json(ptr_));
    }

    // Object operations
    void object_insert(const std::string& key, Value value) {
        check_result(regorus_value_object_insert(ptr_, key.c_str(), value.release()));
    }

    Value object_get(const std::string& key) const {
        return Value(extract_pointer(regorus_value_object_get(ptr_, key.c_str())));
    }

    // Array operations
    int64_t array_len() const {
        RegorusResult result = regorus_value_array_len(ptr_);
        if (result.status != RegorusStatus::Ok) {
            std::string error = result.error_message ? result.error_message : "Unknown error";
            regorus_result_drop(result);
            throw RegorusException(error);
        }
        int64_t len = result.int_value;
        regorus_result_drop(result);
        return len;
    }

    Value array_get(int64_t index) const {
        return Value(extract_pointer(regorus_value_array_get(ptr_, index)));
    }

    // Typed accessors
    bool as_bool() const {
        return extract_bool(regorus_value_as_bool(ptr_));
    }

    int64_t as_i64() const {
        RegorusResult result = regorus_value_as_i64(ptr_);
        if (result.status != RegorusStatus::Ok) {
            std::string error = result.error_message ? result.error_message : "Unknown error";
            regorus_result_drop(result);
            throw RegorusException(error);
        }
        int64_t val = result.int_value;
        regorus_result_drop(result);
        return val;
    }

    std::string as_string() const {
        return extract_string(regorus_value_as_string(ptr_));
    }
};

} // namespace regorus
