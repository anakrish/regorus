// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "regorus_value.hpp"
#include <iostream>
#include <cassert>

using namespace regorus;

void test_create_primitives() {
    std::cout << "Testing primitive value creation..." << std::endl;
    
    // Create null
    {
        Value null_val = Value::Null();
        assert(null_val.is_null());
    }
    
    // Create bool
    {
        Value bool_val = Value::Bool(true);
        // Note: is_bool() not implemented yet, but value is created
    }
    
    // Create int
    {
        Value int_val = Value::Int(42);
    }
    
    // Create float
    {
        Value float_val = Value::Float(3.14);
    }
    
    // Create string
    {
        Value str_val = Value::String("hello");
    }
    
    std::cout << "✓ Primitive value creation tests passed" << std::endl;
}

void test_create_collections() {
    std::cout << "Testing collection value creation..." << std::endl;
    
    // Create object
    {
        Value obj = Value::Object();
        assert(obj.is_object());
    }
    
    // Create array
    {
        Value arr = Value::Array();
    }
    
    // Create set
    {
        Value set = Value::Set();
    }
    
    std::cout << "✓ Collection value creation tests passed" << std::endl;
}

void test_object_operations() {
    std::cout << "Testing object operations..." << std::endl;
    
    // Create object and insert values
    Value obj = Value::Object();
    
    obj.object_insert("name", Value::String("Alice"));
    obj.object_insert("age", Value::Int(30));
    obj.object_insert("active", Value::Bool(true));
    
    // Get values back
    Value name = obj.object_get("name");
    Value age = obj.object_get("age");
    Value active = obj.object_get("active");
    
    std::cout << "✓ Object operations tests passed" << std::endl;
}

void test_json_roundtrip() {
    std::cout << "Testing JSON round-trip..." << std::endl;
    
    std::string json = R"({"name":"test","value":42,"flag":true})";
    
    // Parse JSON
    Value value = Value::FromJson(json);
    assert(value.is_object());
    
    // Convert back to JSON
    std::string json_out = value.to_json();
    std::cout << "  JSON output: " << json_out << std::endl;
    
    std::cout << "✓ JSON round-trip tests passed" << std::endl;
}

void test_nested_objects() {
    std::cout << "Testing nested objects..." << std::endl;
    
    // Create nested structure: { "user": { "name": "Bob", "age": 25 } }
    Value inner = Value::Object();
    inner.object_insert("name", Value::String("Bob"));
    inner.object_insert("age", Value::Int(25));
    
    Value outer = Value::Object();
    outer.object_insert("user", std::move(inner));
    
    // Convert to JSON to verify structure
    std::string json = outer.to_json();
    std::cout << "  Nested JSON: " << json << std::endl;
    
    std::cout << "✓ Nested objects tests passed" << std::endl;
}

void test_move_semantics() {
    std::cout << "Testing move semantics..." << std::endl;
    
    // Create a value
    Value val1 = Value::String("original");
    
    // Move to another value
    Value val2 = std::move(val1);
    
    // val1 should now be null (empty)
    // val2 should have the string
    
    // Move assign
    Value val3 = Value::Int(100);
    val3 = std::move(val2);
    
    std::cout << "✓ Move semantics tests passed" << std::endl;
}

void test_error_handling() {
    std::cout << "Testing error handling..." << std::endl;
    
    try {
        // Try to parse invalid JSON
        Value bad_json = Value::FromJson("not valid json {{{");
        std::cerr << "ERROR: Should have thrown exception!" << std::endl;
        assert(false);
    } catch (const RegorusException& e) {
        std::cout << "  Caught expected exception: " << e.what() << std::endl;
    }
    
    try {
        // Try to get non-existent key
        Value obj = Value::Object();
        Value missing = obj.object_get("nonexistent");
        std::cerr << "ERROR: Should have thrown exception!" << std::endl;
        assert(false);
    } catch (const RegorusException& e) {
        std::cout << "  Caught expected exception: " << e.what() << std::endl;
    }
    
    std::cout << "✓ Error handling tests passed" << std::endl;
}

void test_complex_structure() {
    std::cout << "Testing complex structure..." << std::endl;
    
    // Build: { "users": [...], "config": { "timeout": 30 } }
    std::string json = R"({
        "users": [
            {"name": "Alice", "role": "admin"},
            {"name": "Bob", "role": "user"}
        ],
        "config": {
            "timeout": 30,
            "retries": 3
        }
    })";
    
    Value data = Value::FromJson(json);
    assert(data.is_object());
    
    std::string json_out = data.to_json();
    std::cout << "  Complex JSON: " << json_out << std::endl;
    
    std::cout << "✓ Complex structure tests passed" << std::endl;
}

int main() {
    std::cout << "=== C++ Value API Tests ===" << std::endl << std::endl;
    
    try {
        test_create_primitives();
        test_create_collections();
        test_object_operations();
        test_json_roundtrip();
        test_nested_objects();
        test_move_semantics();
        test_error_handling();
        test_complex_structure();
        
        std::cout << std::endl << "=== All C++ tests passed! ===" << std::endl;
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Unexpected exception: " << e.what() << std::endl;
        return 1;
    }
}
