// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <iostream>
#include <string>
#include "regorus.hpp"

using namespace regorus;

int main() {
    std::cout << "=== Regorus C++ Lazy Evaluation Example ===" << std::endl;

    try {
        // Create a policy that uses lazy object fields
        const std::string policy = R"(
            package example

            # Check if resource is allowed based on type and cost
            allow if {
                input.type == "compute"
                input.cost < 1000
            }

            # Get resource info
            info := {
                "type": input.type,
                "cost": input.cost,
                "region": input.region,
                "allowed": allow
            }
            
            # Check for premium tier
            is_premium if {
                input.cost >= 500
            }
        )";

        // Register schema FIRST - before creating lazy object
        std::cout << "--- Registering Schema ---" << std::endl;
        register_context_schema(
            "ComputeResource",
            {"type", "region"},  // string fields
            {"cost"},            // i64 fields
            {},                  // u64 fields
            {}                   // bool fields
        );
        std::cout << "✓ Schema registered for ComputeResource with fields: type, region, cost" << std::endl;

        // Create engine
        Engine engine;
        std::cout << "✓ Engine created" << std::endl;

        // Add policy
        auto add_result = engine.add_policy("example.rego", policy.c_str());
        if (!add_result) {
            std::cerr << "Failed to add policy: " << add_result.error() << std::endl;
            return 1;
        }
        std::cout << "✓ Policy added" << std::endl;

        // Create a lazy object with context
        std::cout << "\n--- Creating Lazy Object ---" << std::endl;
        
        // Create TypeId
        TypeId type_id("ComputeResource");
        std::cout << "✓ TypeId created: ComputeResource" << std::endl;

        // Create LazyContext and populate it with data
        LazyContext context;
        context.insert_string("type", "compute")
               .insert_i64("cost", 500)
               .insert_string("region", "us-west-2");
        std::cout << "✓ LazyContext populated with:" << std::endl;
        std::cout << "  - type: compute (string)" << std::endl;
        std::cout << "  - cost: 500 (i64)" << std::endl;
        std::cout << "  - region: us-west-2 (string)" << std::endl;

        // Create LazyObject
        auto lazy_obj = LazyObject::create(std::move(type_id), std::move(context));
        std::cout << "✓ LazyObject created" << std::endl;

        // Convert to Value and set as input
        auto input_value = std::move(lazy_obj).to_value();
        std::cout << "✓ Converted to Value" << std::endl;

        // Check if it's a lazy object
        if (input_value.is_lazy_object()) {
            std::cout << "✓ Value confirmed as LazyObject" << std::endl;
        }

        // Set as engine input
        engine.set_input_value(input_value);
        std::cout << "✓ Set as engine input" << std::endl;

        // Evaluate policy - check if allowed
        std::cout << "\n--- Evaluating Policy ---" << std::endl;
        auto allow_result = engine.eval_query("data.example.allow");
        if (allow_result) {
            std::cout << "✓ Allow query result: " << allow_result.output() << std::endl;
        } else {
            std::cerr << "✗ Failed to evaluate allow: " << allow_result.error() << std::endl;
            return 1;
        }

        // Get info object
        auto info_json_result = engine.eval_query("data.example.info");
        if (info_json_result) {
            std::cout << "✓ Info query result: " << info_json_result.output() << std::endl;
        } else {
            std::cerr << "✗ Failed to evaluate info: " << info_json_result.error() << std::endl;
            return 1;
        }

        // Check premium status
        auto premium_result = engine.eval_query("data.example.is_premium");
        if (premium_result) {
            std::cout << "✓ Is Premium query result: " << premium_result.output() << std::endl;
        } else {
            std::cerr << "✗ Failed to evaluate is_premium: " << premium_result.error() << std::endl;
            return 1;
        }

        // Now try eval_rule_as_value to get typed access to info
        std::cout << "\n--- Using Typed Value Access ---" << std::endl;
        auto info_rule = engine.eval_rule_as_value("data.example.info");
        if (!info_rule) {
            std::cerr << "✗ Failed to evaluate info: " << info_rule.error() << std::endl;
            return 1;
        }
        
        auto info_value = info_rule.value();
        if (info_value.is_object()) {
            std::cout << "✓ Got info object via typed API" << std::endl;
            
            // Access individual fields
            auto type_val = info_value.object_get("type");
            if (type_val.is_string()) {
                std::cout << "  - type: " << type_val.as_string() << std::endl;
            }
            
            auto cost_val = info_value.object_get("cost");
            if (!cost_val.is_null()) {
                std::cout << "  - cost: " << cost_val.as_i64() << std::endl;
            }
            
            auto region_val = info_value.object_get("region");
            if (region_val.is_string()) {
                std::cout << "  - region: " << region_val.as_string() << std::endl;
            }
            
            auto allowed_val = info_value.object_get("allowed");
            if (!allowed_val.is_null()) {
                std::cout << "  - allowed: " << (allowed_val.as_bool() ? "true" : "false") << std::endl;
            }
        }
        
        std::cout << "\n📝 Lazy Evaluation Success!" << std::endl;
        std::cout << "   ✓ Schema registered with field getters" << std::endl;
        std::cout << "   ✓ LazyObject created with context data" << std::endl;
        std::cout << "   ✓ Fields accessed from policy (type, cost, region)" << std::endl;
        std::cout << "   ✓ Policy evaluation used lazy object fields" << std::endl;

        std::cout << "\n✅ All tests passed!" << std::endl;
        return 0;

    } catch (const std::exception& e) {
        std::cerr << "❌ Exception: " << e.what() << std::endl;
        return 1;
    }
}
