#include <stdio.h>
#include "regorus.h"

int main() {
    // Create engine.
    RegorusEngine* engine = regorus_engine_new();
    RegorusResult r;

    // Turn on rego v0 since policy uses v0.
    r = regorus_engine_set_rego_v0(engine, true);
    if (r.status != Ok)
	goto error;

    // Load policies.
    r = regorus_engine_add_policy_from_file(engine, "../../../tests/aci/framework.rego");
    if (r.status != Ok)
	goto error;
    printf("Loaded package %s\n", r.output);
    regorus_result_drop(r);

    r = regorus_engine_add_policy_from_file(engine, "../../../tests/aci/api.rego");
    if (r.status != Ok)
	goto error;
    printf("Loaded package %s\n", r.output);
    regorus_result_drop(r);
    
    r = regorus_engine_add_policy_from_file(engine, "../../../tests/aci/policy.rego");
    if (r.status != Ok)
	goto error;
    printf("Loaded package %s\n", r.output);
    regorus_result_drop(r);

    // Add data
    r = regorus_engine_add_data_from_json_file(engine, "../../../tests/aci/data.json");
    if (r.status != Ok)
	goto error;
    regorus_result_drop(r);

    // Set input
    r = regorus_engine_set_input_from_json_file(engine, "../../../tests/aci/input.json");
    if (r.status != Ok)
	goto error;
    regorus_result_drop(r);

    // Eval rule.
    r = regorus_engine_eval_query(engine, "data.framework.mount_overlay");
    if (r.status != Ok)
	goto error;

    // Print output
    printf("%s\n", r.output);
    regorus_result_drop(r);
    
    // Free the engine.
    regorus_engine_drop(engine);

    // Create another engine.
    engine = regorus_engine_new();

    r = regorus_engine_add_policy(
	engine,
	"test.rego",
	"package test\n"
	"x = 1\n"
	"message = `Hello`"
	);

    // Evaluate rule.
    if (r.status != Ok)
	goto error;

    r = regorus_engine_set_enable_coverage(engine, true);
    regorus_result_drop(r);
    
    r = regorus_engine_eval_query(engine, "data.test.message");
    if (r.status != Ok)
	goto error;

    // Print output
    printf("%s\n", r.output);
    regorus_result_drop(r);
	
    // Print pretty coverage report.
    r = regorus_engine_get_coverage_report_pretty(engine);
    if (r.status != Ok)
	goto error;

    printf("%s\n", r.output);
    regorus_result_drop(r);
    
    // Free the engine.
    regorus_engine_drop(engine);
    
    printf("\n=== Value API Demo ===\n");
    
    // Re-create the first engine to reuse it for Value API demo
    engine = regorus_engine_new();
    r = regorus_engine_set_rego_v0(engine, true);
    if (r.status != Ok) goto error;
    regorus_result_drop(r);
    
    // Reload the same policies
    r = regorus_engine_add_policy_from_file(engine, "../../../tests/aci/framework.rego");
    if (r.status != Ok) goto error;
    regorus_result_drop(r);
    
    r = regorus_engine_add_policy_from_file(engine, "../../../tests/aci/api.rego");
    if (r.status != Ok) goto error;
    regorus_result_drop(r);
    
    r = regorus_engine_add_policy_from_file(engine, "../../../tests/aci/policy.rego");
    if (r.status != Ok) goto error;
    regorus_result_drop(r);
    
    r = regorus_engine_add_data_from_json_file(engine, "../../../tests/aci/data.json");
    if (r.status != Ok) goto error;
    regorus_result_drop(r);
    
    r = regorus_engine_set_input_from_json_file(engine, "../../../tests/aci/input.json");
    if (r.status != Ok) goto error;
    regorus_result_drop(r);
    
    // Evaluate and get result as Value (not JSON)
    printf("Evaluating data.framework.mount_overlay using eval_rule_as_value:\n");
    r = regorus_engine_eval_rule_as_value(engine, "data.framework.mount_overlay");
    if (r.status != Ok) goto error;
    
    void* policy_value = r.pointer_value;
    regorus_result_drop(r);
    
    printf("\n=== Navigating Value in a Typed Manner (No JSON Conversion) ===\n");
    
    // Check if it's an object
    r = regorus_value_is_object(policy_value);
    if (r.status == Ok && r.bool_value) {
        printf("✓ Policy result is an object\n");
        regorus_result_drop(r);
        
        // Get the "allowed" field and extract as bool
        printf("\n1. Navigate to 'allowed' field (using typed API):\n");
        r = regorus_value_object_get(policy_value, "allowed");
        if (r.status != Ok) goto error;
        void* allowed_value = r.pointer_value;
        regorus_result_drop(r);
        
        printf("   Type: bool\n");
        r = regorus_value_as_bool(allowed_value);
        if (r.status != Ok) goto error;
        printf("   Value: %s\n", r.bool_value ? "true" : "false");
        regorus_result_drop(r);
        regorus_value_drop(allowed_value);
        
        // Get the "metadata" array
        printf("\n2. Navigate to 'metadata' array:\n");
        r = regorus_value_object_get(policy_value, "metadata");
        if (r.status != Ok) goto error;
        void* metadata_value = r.pointer_value;
        regorus_result_drop(r);
        
        r = regorus_value_array_len(metadata_value);
        if (r.status != Ok) goto error;
        int64_t metadata_len = r.int_value;
        printf("   Array length: %lld\n", metadata_len);
        regorus_result_drop(r);
        
        // Navigate through array elements using typed API
        for (int64_t i = 0; i < metadata_len && i < 2; i++) {
            printf("\n   Metadata[%lld] (navigated with typed API):\n", i);
            
            r = regorus_value_array_get(metadata_value, i);
            if (r.status != Ok) goto error;
            void* item = r.pointer_value;
            regorus_result_drop(r);
            
            r = regorus_value_is_object(item);
            if (r.status == Ok && r.bool_value) {
                printf("     Type: object\n");
                regorus_result_drop(r);
                
                // Get "action" field as string
                r = regorus_value_object_get(item, "action");
                if (r.status != Ok) goto error;
                void* action_val = r.pointer_value;
                regorus_result_drop(r);
                
                r = regorus_value_as_string(action_val);
                if (r.status == Ok) {
                    printf("     action (string): \"%s\"\n", r.output);
                    regorus_result_drop(r);
                }
                regorus_value_drop(action_val);
                
                // Get "key" field as string
                r = regorus_value_object_get(item, "key");
                if (r.status != Ok) goto error;
                void* key_val = r.pointer_value;
                regorus_result_drop(r);
                
                r = regorus_value_as_string(key_val);
                if (r.status == Ok) {
                    printf("     key (string): \"%s\"\n", r.output);
                    regorus_result_drop(r);
                }
                regorus_value_drop(key_val);
                
                // Get "name" field as string
                r = regorus_value_object_get(item, "name");
                if (r.status != Ok) goto error;
                void* name_val = r.pointer_value;
                regorus_result_drop(r);
                
                r = regorus_value_as_string(name_val);
                if (r.status == Ok) {
                    printf("     name (string): \"%s\"\n", r.output);
                    regorus_result_drop(r);
                }
                regorus_value_drop(name_val);
                
                // Get "value" field
                r = regorus_value_object_get(item, "value");
                if (r.status != Ok) goto error;
                void* value_field = r.pointer_value;
                regorus_result_drop(r);
                
                // Check the type and extract accordingly
                if (i == 1) {  // Second item has a boolean value
                    r = regorus_value_as_bool(value_field);
                    if (r.status == Ok) {
                        printf("     value (bool): %s\n", r.bool_value ? "true" : "false");
                        regorus_result_drop(r);
                    }
                } else {
                    // First item has an array
                    r = regorus_value_array_len(value_field);
                    if (r.status == Ok) {
                        printf("     value: <array with %lld elements>\n", r.int_value);
                        regorus_result_drop(r);
                    }
                }
                
                regorus_value_drop(value_field);
            }
            
            regorus_value_drop(item);
        }
        
        regorus_value_drop(metadata_value);
        printf("\n✓ Successfully navigated nested array/object structure using Value API\n");
    }
    
    regorus_value_drop(policy_value);
    printf("\n✓ Value API demo completed successfully!\n");
    
    // Free the engine
    regorus_engine_drop(engine);
    
    return 0;
    
error:
    printf("%s", r.error_message);
    regorus_result_drop(r);
    regorus_engine_drop(engine);
	
    return 1;
}
