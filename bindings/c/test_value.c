// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>

// Forward declare C API
typedef struct {
    int status;
    int data_type;
    char* output;
    bool bool_value;
    int64_t int_value;
    void* pointer_value;
    char* error_message;
} RegorusResult;

// Value creation
extern RegorusResult regorus_value_create_null(void);
extern RegorusResult regorus_value_create_bool(bool value);
extern RegorusResult regorus_value_create_int(int64_t value);
extern RegorusResult regorus_value_create_float(double value);
extern RegorusResult regorus_value_create_string(const char* s);
extern RegorusResult regorus_value_create_array(void);
extern RegorusResult regorus_value_create_object(void);
extern RegorusResult regorus_value_create_set(void);

// JSON
extern RegorusResult regorus_value_from_json(const char* json);
extern RegorusResult regorus_value_to_json(void* value);

// Type checking
extern RegorusResult regorus_value_is_null(void* value);
extern RegorusResult regorus_value_is_object(void* value);
extern RegorusResult regorus_value_is_lazy_object(void* value);

// Object operations
extern RegorusResult regorus_value_object_insert(void* object, const char* key, void* value);
extern RegorusResult regorus_value_object_get(void* object, const char* key);

// Memory management
extern void regorus_value_drop(void* value);
extern void regorus_result_drop(RegorusResult result);

// Helper to check result
void check_result(RegorusResult result, const char* context) {
    if (result.status != 0) {
        fprintf(stderr, "Error in %s: %s\n", context, 
                result.error_message ? result.error_message : "Unknown error");
        regorus_result_drop(result);
        exit(1);
    }
}

void test_create_primitives() {
    printf("Testing primitive value creation...\n");
    
    // Create null
    RegorusResult null_result = regorus_value_create_null();
    check_result(null_result, "create null");
    void* null_value = null_result.pointer_value;
    regorus_result_drop(null_result);
    
    // Check it's null
    RegorusResult is_null_result = regorus_value_is_null(null_value);
    check_result(is_null_result, "is_null");
    assert(is_null_result.bool_value == true);
    regorus_result_drop(is_null_result);
    
    regorus_value_drop(null_value);
    
    // Create bool
    RegorusResult bool_result = regorus_value_create_bool(true);
    check_result(bool_result, "create bool");
    void* bool_value = bool_result.pointer_value;
    regorus_result_drop(bool_result);
    regorus_value_drop(bool_value);
    
    // Create int
    RegorusResult int_result = regorus_value_create_int(42);
    check_result(int_result, "create int");
    void* int_value = int_result.pointer_value;
    regorus_result_drop(int_result);
    regorus_value_drop(int_value);
    
    // Create string
    RegorusResult str_result = regorus_value_create_string("hello");
    check_result(str_result, "create string");
    void* str_value = str_result.pointer_value;
    regorus_result_drop(str_result);
    regorus_value_drop(str_value);
    
    printf("✓ Primitive value creation tests passed\n");
}

void test_create_collections() {
    printf("Testing collection value creation...\n");
    
    // Create object
    RegorusResult obj_result = regorus_value_create_object();
    check_result(obj_result, "create object");
    void* obj_value = obj_result.pointer_value;
    regorus_result_drop(obj_result);
    
    // Check it's an object
    RegorusResult is_obj_result = regorus_value_is_object(obj_value);
    check_result(is_obj_result, "is_object");
    assert(is_obj_result.bool_value == true);
    regorus_result_drop(is_obj_result);
    
    regorus_value_drop(obj_value);
    
    // Create array
    RegorusResult arr_result = regorus_value_create_array();
    check_result(arr_result, "create array");
    void* arr_value = arr_result.pointer_value;
    regorus_result_drop(arr_result);
    regorus_value_drop(arr_value);
    
    // Create set
    RegorusResult set_result = regorus_value_create_set();
    check_result(set_result, "create set");
    void* set_value = set_result.pointer_value;
    regorus_result_drop(set_result);
    regorus_value_drop(set_value);
    
    printf("✓ Collection value creation tests passed\n");
}

void test_object_operations() {
    printf("Testing object operations...\n");
    
    // Create object
    RegorusResult obj_result = regorus_value_create_object();
    check_result(obj_result, "create object");
    void* obj = obj_result.pointer_value;
    regorus_result_drop(obj_result);
    
    // Create a string value to insert
    RegorusResult str_result = regorus_value_create_string("world");
    check_result(str_result, "create string");
    void* str_value = str_result.pointer_value;
    regorus_result_drop(str_result);
    
    // Insert into object
    RegorusResult insert_result = regorus_value_object_insert(obj, "hello", str_value);
    check_result(insert_result, "object insert");
    regorus_result_drop(insert_result);
    
    // Get from object
    RegorusResult get_result = regorus_value_object_get(obj, "hello");
    check_result(get_result, "object get");
    void* retrieved = get_result.pointer_value;
    regorus_result_drop(get_result);
    
    regorus_value_drop(retrieved);
    regorus_value_drop(obj);
    
    printf("✓ Object operations tests passed\n");
}

void test_json_roundtrip() {
    printf("Testing JSON round-trip...\n");
    
    const char* json = "{\"name\":\"test\",\"value\":42,\"flag\":true}";
    
    // Parse JSON
    RegorusResult parse_result = regorus_value_from_json(json);
    check_result(parse_result, "from_json");
    void* value = parse_result.pointer_value;
    regorus_result_drop(parse_result);
    
    // Check it's an object
    RegorusResult is_obj_result = regorus_value_is_object(value);
    check_result(is_obj_result, "is_object");
    assert(is_obj_result.bool_value == true);
    regorus_result_drop(is_obj_result);
    
    // Convert back to JSON
    RegorusResult json_result = regorus_value_to_json(value);
    check_result(json_result, "to_json");
    printf("  JSON output: %s\n", json_result.output);
    regorus_result_drop(json_result);
    
    regorus_value_drop(value);
    
    printf("✓ JSON round-trip tests passed\n");
}

int main() {
    printf("=== C Value API Tests ===\n\n");
    
    test_create_primitives();
    test_create_collections();
    test_object_operations();
    test_json_roundtrip();
    
    printf("\n=== All C tests passed! ===\n");
    return 0;
}
