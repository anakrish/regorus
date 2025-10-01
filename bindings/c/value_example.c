// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>

// Forward declarations from FFI
typedef struct {
    int status;
    int data_type;
    char* output;
    bool bool_value;
    int64_t int_value;
    void* pointer_value;
    char* error_message;
} RegorusResult;

typedef struct RegorusEngine RegorusEngine;

// Engine functions
extern RegorusEngine* regorus_engine_new(void);
extern void regorus_engine_drop(RegorusEngine* engine);
extern RegorusResult regorus_engine_add_policy(RegorusEngine* engine, const char* path, const char* rego);
extern RegorusResult regorus_engine_eval_query(RegorusEngine* engine, const char* query);
extern RegorusResult regorus_engine_eval_rule(RegorusEngine* engine, const char* rule);
extern RegorusResult regorus_engine_set_input_value(RegorusEngine* engine, void* value);
extern RegorusResult regorus_engine_eval_query_as_value(RegorusEngine* engine, const char* query);
extern RegorusResult regorus_engine_eval_rule_as_value(RegorusEngine* engine, const char* rule);

// Value creation
extern RegorusResult regorus_value_create_null(void);
extern RegorusResult regorus_value_create_bool(bool value);
extern RegorusResult regorus_value_create_int(int64_t value);
extern RegorusResult regorus_value_create_string(const char* s);
extern RegorusResult regorus_value_create_array(void);
extern RegorusResult regorus_value_create_object(void);
extern RegorusResult regorus_value_from_json(const char* json);
extern RegorusResult regorus_value_to_json(void* value);

// Value type checking
extern RegorusResult regorus_value_is_object(void* value);
extern RegorusResult regorus_value_is_lazy_object(void* value);

// Object operations
extern RegorusResult regorus_value_object_insert(void* object, const char* key, void* value);
extern RegorusResult regorus_value_object_get(void* object, const char* key);

// Array operations
extern RegorusResult regorus_value_array_push(void* array, void* value);
extern RegorusResult regorus_value_array_len(void* array);

// Memory management
extern void regorus_value_drop(void* value);
extern void regorus_result_drop(RegorusResult result);

void check_result(RegorusResult r, const char* context) {
    if (r.status != 0) {
        fprintf(stderr, "Error in %s: %s\n", context, 
                r.error_message ? r.error_message : "Unknown error");
        regorus_result_drop(r);
        exit(1);
    }
}

void print_separator() {
    printf("\n========================================\n\n");
}

// Example 1: Traditional JSON workflow
void example_json_workflow() {
    printf("Example 1: Traditional JSON Workflow\n");
    print_separator();
    
    RegorusEngine* engine = regorus_engine_new();
    
    RegorusResult r = regorus_engine_add_policy(
        engine,
        "example.rego",
        "package example\n"
        "allow = true\n"
        "message = \"Hello from Rego\"\n"
        "count = 42\n"
    );
    check_result(r, "add_policy");
    regorus_result_drop(r);
    
    // Eval using JSON (traditional approach)
    r = regorus_engine_eval_query(engine, "data.example");
    if (r.status == 0) {
        printf("Query result (JSON):\n%s\n", r.output);
    }
    regorus_result_drop(r);
    
    regorus_engine_drop(engine);
}

// Example 2: Value API workflow (no JSON serialization)
void example_value_workflow() {
    printf("Example 2: Value API Workflow (Zero-Copy)\n");
    print_separator();
    
    RegorusEngine* engine = regorus_engine_new();
    
    RegorusResult r = regorus_engine_add_policy(
        engine,
        "value_example.rego",
        "package value_example\n"
        "result = {\"status\": \"success\", \"count\": 42, \"valid\": true}\n"
    );
    check_result(r, "add_policy");
    regorus_result_drop(r);
    
    // Eval and get Value instead of JSON
    r = regorus_engine_eval_rule_as_value(engine, "data.value_example.result");
    check_result(r, "eval_rule_as_value");
    
    void* value = r.pointer_value;
    regorus_result_drop(r);
    
    printf("Got Value pointer: %p\n", value);
    
    // Check if it's an object
    r = regorus_value_is_object(value);
    if (r.bool_value) {
        printf("✓ Value is an object\n");
    }
    regorus_result_drop(r);
    
    // Get a field from the object
    r = regorus_value_object_get(value, "status");
    check_result(r, "object_get");
    void* status_value = r.pointer_value;
    regorus_result_drop(r);
    
    // Convert field to JSON to print
    r = regorus_value_to_json(status_value);
    printf("Field 'status': %s\n", r.output);
    regorus_result_drop(r);
    regorus_value_drop(status_value);
    
    // Convert whole value to JSON
    r = regorus_value_to_json(value);
    printf("Full value as JSON:\n%s\n", r.output);
    regorus_result_drop(r);
    
    regorus_value_drop(value);
    regorus_engine_drop(engine);
}

// Example 3: Building input with Value API
void example_build_input() {
    printf("Example 3: Building Input with Value API\n");
    print_separator();
    
    RegorusEngine* engine = regorus_engine_new();
    
    RegorusResult r = regorus_engine_add_policy(
        engine,
        "auth.rego",
        "package auth\n"
        "allow { input.user == \"admin\" }\n"
        "allow { input.role == \"superuser\" }\n"
        "deny { input.blocked == true }\n"
    );
    check_result(r, "add_policy");
    regorus_result_drop(r);
    
    // Build input using Value API (no JSON parsing!)
    r = regorus_value_create_object();
    void* input = r.pointer_value;
    regorus_result_drop(r);
    
    // Add string field
    r = regorus_value_create_string("admin");
    void* user_value = r.pointer_value;
    regorus_result_drop(r);
    
    r = regorus_value_object_insert(input, "user", user_value);
    check_result(r, "object_insert");
    regorus_result_drop(r);
    
    // Add boolean field
    r = regorus_value_create_bool(false);
    void* blocked_value = r.pointer_value;
    regorus_result_drop(r);
    
    r = regorus_value_object_insert(input, "blocked", blocked_value);
    check_result(r, "object_insert");
    regorus_result_drop(r);
    
    // Set input using Value (not JSON!)
    r = regorus_engine_set_input_value(engine, input);
    check_result(r, "set_input_value");
    regorus_result_drop(r);
    
    // Evaluate
    r = regorus_engine_eval_query(engine, "data.auth.allow");
    printf("Auth result: %s\n", r.output);
    regorus_result_drop(r);
    
    regorus_engine_drop(engine);
}

// Example 4: Complex nested structures
void example_nested_structures() {
    printf("Example 4: Complex Nested Structures\n");
    print_separator();
    
    // Build: { "users": ["Alice", "Bob"], "config": { "timeout": 30 } }
    RegorusResult r = regorus_value_create_object();
    void* root = r.pointer_value;
    regorus_result_drop(r);
    
    // Create users array
    r = regorus_value_create_array();
    void* users = r.pointer_value;
    regorus_result_drop(r);
    
    r = regorus_value_create_string("Alice");
    void* alice = r.pointer_value;
    regorus_result_drop(r);
    
    r = regorus_value_array_push(users, alice);
    check_result(r, "array_push");
    regorus_result_drop(r);
    
    r = regorus_value_create_string("Bob");
    void* bob = r.pointer_value;
    regorus_result_drop(r);
    
    r = regorus_value_array_push(users, bob);
    check_result(r, "array_push");
    regorus_result_drop(r);
    
    // Add array to root
    r = regorus_value_object_insert(root, "users", users);
    check_result(r, "object_insert");
    regorus_result_drop(r);
    
    // Create config object
    r = regorus_value_create_object();
    void* config = r.pointer_value;
    regorus_result_drop(r);
    
    r = regorus_value_create_int(30);
    void* timeout = r.pointer_value;
    regorus_result_drop(r);
    
    r = regorus_value_object_insert(config, "timeout", timeout);
    check_result(r, "object_insert");
    regorus_result_drop(r);
    
    // Add config to root
    r = regorus_value_object_insert(root, "config", config);
    check_result(r, "object_insert");
    regorus_result_drop(r);
    
    // Print the structure
    r = regorus_value_to_json(root);
    printf("Nested structure:\n%s\n", r.output);
    regorus_result_drop(r);
    
    regorus_value_drop(root);
}

int main() {
    printf("=== Regorus C Value API Examples ===\n");
    
    example_json_workflow();
    example_value_workflow();
    example_build_input();
    example_nested_structures();
    
    printf("\n✓ All examples completed successfully!\n");
    return 0;
}
