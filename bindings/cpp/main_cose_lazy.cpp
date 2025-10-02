// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <iostream>
#include <string>
#include <vector>
#include <cstring>
#include "regorus.hpp"

using namespace regorus;

// Simulated COSE object structure
struct CoseObject {
    std::vector<uint8_t> payload;
    std::vector<uint8_t> signature;
    std::string algorithm;
    std::string issuer;
    bool verified;
    
    CoseObject(const std::string& payload_str, const std::string& issuer_name)
        : algorithm("ES256"), issuer(issuer_name), verified(false) {
        // In real implementation, this would be actual COSE encoding
        payload = std::vector<uint8_t>(payload_str.begin(), payload_str.end());
        signature = {0xDE, 0xAD, 0xBE, 0xEF}; // Dummy signature
    }
    
    // Simulated expensive signature verification
    bool verify_signature() {
        std::cout << "  🔐 [EXPENSIVE] Verifying COSE signature..." << std::endl;
        // Simulate crypto operation delay
        for (volatile int i = 0; i < 10000000; i++);
        verified = true;
        return true;
    }
    
    std::string get_payload_string() const {
        return std::string(payload.begin(), payload.end());
    }
};

// Global COSE object (in real code, this would be passed via user_data)
static CoseObject* g_cose_object = nullptr;

// Field getter callback for "payload" - returns payload without verification
extern "C" void* get_cose_payload(const void* ctx, const char* field_name, void* user_data) {
    std::cout << "  📋 [GETTER CALLED] get_cose_payload" << std::endl;
    
    // Extract CoseObject pointer from context (stored as "_cose_ptr")
    auto result = regorus_lazy_context_get_u64(const_cast<void*>(ctx), "_cose_ptr");
    if (result.status != RegorusStatus::Ok) {
        std::cout << "     - ERROR: failed to get _cose_ptr from context" << std::endl;
        regorus_result_drop(result);
        return nullptr;
    }
    CoseObject* cose = reinterpret_cast<CoseObject*>(static_cast<uintptr_t>(result.u64_value));
    regorus_result_drop(result);
    
    if (!cose) {
        std::cout << "     - ERROR: null cose object" << std::endl;
        return nullptr;
    }
    
    std::cout << "     - Accessing payload (no verification needed)" << std::endl;
    std::string payload_str = cose->get_payload_string();
    std::cout << "     - Payload: " << payload_str << std::endl;
    
    // Create Value on stack, then clone the underlying Rust pointer
    Value temp_value = Value::FromJson(payload_str);
    RegorusResult clone_result = regorus_value_clone(temp_value.get_ptr());
    if (clone_result.status != RegorusStatus::Ok) {
        std::cout << "     - ERROR: Failed to clone value" << std::endl;
        regorus_result_drop(clone_result);
        return nullptr;
    }
    void* cloned_ptr = clone_result.pointer_value;
    clone_result.pointer_value = nullptr;  // Transfer ownership
    regorus_result_drop(clone_result);
    std::cout << "     - Value cloned successfully, returning: " << cloned_ptr << std::endl;
    return cloned_ptr;
}

// Field getter callback for "verified" - triggers signature verification
extern "C" void* get_cose_verified(const void* ctx, const char* field_name, void* user_data) {
    std::cout << "  🔐 [GETTER CALLED] get_cose_verified" << std::endl;
    
    // Extract CoseObject pointer from context
    auto result = regorus_lazy_context_get_u64(const_cast<void*>(ctx), "_cose_ptr");
    if (result.status != RegorusStatus::Ok) {
        std::cout << "     - ERROR: failed to get _cose_ptr from context" << std::endl;
        regorus_result_drop(result);
        return nullptr;
    }
    CoseObject* cose = reinterpret_cast<CoseObject*>(static_cast<uintptr_t>(result.u64_value));
    regorus_result_drop(result);
    
    if (!cose) {
        std::cout << "     - ERROR: null cose object" << std::endl;
        return nullptr;
    }
    
    std::cout << "     - Current verified status: " << cose->verified << std::endl;
    
    // This triggers expensive signature verification!
    if (!cose->verified) {
        std::cout << "     - Triggering signature verification..." << std::endl;
        cose->verify_signature();
        std::cout << "     - Verification complete: " << cose->verified << std::endl;
    }
    
    // Create Value on stack, then clone the underlying Rust pointer
    Value temp_value = Value::Bool(cose->verified);
    RegorusResult clone_result = regorus_value_clone(temp_value.get_ptr());
    if (clone_result.status != RegorusStatus::Ok) {
        std::cout << "     - ERROR: Failed to clone value" << std::endl;
        regorus_result_drop(clone_result);
        return nullptr;
    }
    void* cloned_ptr = clone_result.pointer_value;
    clone_result.pointer_value = nullptr;  // Transfer ownership
    regorus_result_drop(clone_result);
    std::cout << "     - Value cloned successfully, returning: " << cloned_ptr << std::endl;
    return cloned_ptr;
}

// Field getter callback for "issuer" - cheap metadata access
extern "C" void* get_cose_issuer(const void* ctx, const char* field_name, void* user_data) {
    std::cout << "  📝 [GETTER CALLED] get_cose_issuer" << std::endl;
    
    // Extract CoseObject pointer from context
    auto result = regorus_lazy_context_get_u64(const_cast<void*>(ctx), "_cose_ptr");
    if (result.status != RegorusStatus::Ok) {
        std::cout << "     - ERROR: failed to get _cose_ptr from context" << std::endl;
        regorus_result_drop(result);
        return nullptr;
    }
    CoseObject* cose = reinterpret_cast<CoseObject*>(static_cast<uintptr_t>(result.u64_value));
    regorus_result_drop(result);
    
    if (!cose) {
        std::cout << "     - ERROR: null cose object" << std::endl;
        return nullptr;
    }
    
    std::cout << "     - Issuer: " << cose->issuer << std::endl;
    // Create Value on stack, then clone the underlying Rust pointer
    Value temp_value = Value::String(cose->issuer);
    RegorusResult clone_result = regorus_value_clone(temp_value.get_ptr());
    if (clone_result.status != RegorusStatus::Ok) {
        std::cout << "     - ERROR: Failed to clone value" << std::endl;
        regorus_result_drop(clone_result);
        return nullptr;
    }
    void* cloned_ptr = clone_result.pointer_value;
    clone_result.pointer_value = nullptr;  // Transfer ownership
    regorus_result_drop(clone_result);
    std::cout << "     - Value cloned successfully, returning: " << cloned_ptr << std::endl;
    return cloned_ptr;
}

// Field getter callback for "algorithm" - cheap metadata access
extern "C" void* get_cose_algorithm(const void* ctx, const char* field_name, void* user_data) {
    std::cout << "  📝 [GETTER CALLED] get_cose_algorithm" << std::endl;
    
    // Extract CoseObject pointer from context
    auto result = regorus_lazy_context_get_u64(const_cast<void*>(ctx), "_cose_ptr");
    if (result.status != RegorusStatus::Ok) {
        std::cout << "     - ERROR: failed to get _cose_ptr from context" << std::endl;
        regorus_result_drop(result);
        return nullptr;
    }
    CoseObject* cose = reinterpret_cast<CoseObject*>(static_cast<uintptr_t>(result.u64_value));
    regorus_result_drop(result);
    
    if (!cose) {
        std::cout << "     - ERROR: null cose object" << std::endl;
        return nullptr;
    }
    
    std::cout << "     - Algorithm: " << cose->algorithm << std::endl;
    // Create Value on stack, then clone the underlying Rust pointer
    Value temp_value = Value::String(cose->algorithm);
    RegorusResult clone_result = regorus_value_clone(temp_value.get_ptr());
    if (clone_result.status != RegorusStatus::Ok) {
        std::cout << "     - ERROR: Failed to clone value" << std::endl;
        regorus_result_drop(clone_result);
        return nullptr;
    }
    void* cloned_ptr = clone_result.pointer_value;
    clone_result.pointer_value = nullptr;  // Transfer ownership
    regorus_result_drop(clone_result);
    std::cout << "     - Value cloned successfully, returning: " << cloned_ptr << std::endl;
    return cloned_ptr;
}

// Register the COSE schema once (like a real application would do at startup)
// In real usage, this would be called once when the application starts
void register_cose_schema() {
    std::cout << "--- Registering COSE Schema ---" << std::endl;
    std::cout << "This is done ONCE at application startup\n" << std::endl;
    
    // Register schema with callback-based field getters
    // Note: user_data is nullptr here because we'll pass it when creating instances
    // This is just registering the TYPE and its field getters
    CallbackSchemaBuilder("CoseObject")
        .add_field("payload", get_cose_payload, nullptr)
        .add_field("issuer", get_cose_issuer, nullptr)
        .add_field("algorithm", get_cose_algorithm, nullptr)
        .add_field("verified", get_cose_verified, nullptr)
        .build();
    
    std::cout << "✓ COSE schema registered with lazy field getters\n" << std::endl;
}

int main() {
    std::cout << "=== Regorus C++ COSE Lazy Evaluation Example ===" << std::endl;
    std::cout << "Demonstrates lazy signature verification - only verified when policy needs it\n" << std::endl;

    try {
        // Register schema ONCE at startup (like a real application)
        register_cose_schema();
        
        // Create COSE object with container image metadata
        CoseObject cose_image(
            R"({"image":"nginx:1.21","registry":"docker.io","tags":["latest","stable"]})",
            "docker.io"
        );
        g_cose_object = &cose_image;

        // Policy that conditionally verifies signatures based on registry
        const std::string policy = R"(
            package container_policy

            # Scenario 1: Trusted registry - allow without signature verification
            allow_trusted if {
                input.image.issuer == "internal-registry.company.com"
                # No need to check signature for internal registry!
            }

            # Scenario 2: External registry - require signature verification
            allow_verified if {
                input.image.issuer != "internal-registry.company.com"
                input.image.verified == true
                # Signature verification only happens when this rule is evaluated
            }

            # Final allow decision
            allow if { allow_trusted }
            allow if { allow_verified }

            # Get image metadata (doesn't trigger verification)
            metadata := {
                "issuer": input.image.issuer,
                "algorithm": input.image.algorithm,
                "payload": input.image.payload
            }

            # Decision details
            decision := {
                "allowed": allow,
                "reason": reason
            }

            reason := "trusted_registry" if allow_trusted
            reason := "verified_signature" if { allow_verified; not allow_trusted }
            reason := "verification_failed" if { not allow }
        )";

        // Create engine and add policy
        Engine engine;
        auto add_result = engine.add_policy("container_policy.rego", policy.c_str());
        if (!add_result) {
            std::cerr << "Failed to add policy: " << add_result.error() << std::endl;
            return 1;
        }
        std::cout << "✓ Policy added\n" << std::endl;

        // ========================================
        // Scenario 1: External Registry (docker.io)
        // ========================================
        std::cout << "=== Scenario 1: External Registry (docker.io) ===" << std::endl;
        std::cout << "Expected: Signature verification WILL be triggered\n" << std::endl;
        
        cose_image.verified = false; // Reset verification status
        
        // Create lazy COSE object with pointer stored in context
        TypeId type_id1("CoseObject");
        LazyContext context1;
        // Store the CoseObject pointer in the context so field getters can access it
        context1.insert_u64("_cose_ptr", static_cast<uint64_t>(reinterpret_cast<uintptr_t>(&cose_image)));
        auto lazy_cose1 = LazyObject::create(std::move(type_id1), std::move(context1));
        
        // Create input with COSE as a subobject
        auto input1 = Value::Object();
        input1.object_insert("image", std::move(lazy_cose1).to_value());
        
        engine.set_input_value(input1);
        
        // Evaluate metadata first (should NOT trigger verification)
        std::cout << "1. Accessing metadata only:" << std::endl;
        auto metadata_result1 = engine.eval_query("data.container_policy.metadata");
        if (metadata_result1) {
            std::cout << "   ✓ Metadata: " << metadata_result1.output() << std::endl;
        }
        
        // Evaluate allow (WILL trigger verification for external registry)
        std::cout << "\n2. Evaluating allow (requires verification for external registry):" << std::endl;
        auto allow_result1 = engine.eval_query("data.container_policy.allow");
        if (allow_result1) {
            std::cout << "   ✓ Allow result: " << allow_result1.output() << std::endl;
        }
        
        // Get decision details
        auto decision_result1 = engine.eval_query("data.container_policy.decision");
        if (decision_result1) {
            std::cout << "   ✓ Decision: " << decision_result1.output() << std::endl;
        }

        // ========================================
        // Scenario 2: Trusted Internal Registry
        // ========================================
        std::cout << "\n\n=== Scenario 2: Trusted Internal Registry ===" << std::endl;
        std::cout << "Expected: Signature verification will NOT be triggered\n" << std::endl;
        
        // Create new COSE object from internal registry
        CoseObject cose_internal(
            R"({"image":"app-server:v2.1","service":"backend"})",
            "internal-registry.company.com"
        );
        
        // Create lazy object using the same schema (registered once at startup)
        TypeId type_id2("CoseObject");
        LazyContext context2;
        // Store the CoseObject pointer in the context
        context2.insert_u64("_cose_ptr", static_cast<uint64_t>(reinterpret_cast<uintptr_t>(&cose_internal)));
        auto lazy_cose2 = LazyObject::create(std::move(type_id2), std::move(context2));
        
        auto input2 = Value::Object();
        input2.object_insert("image", std::move(lazy_cose2).to_value());
        
        engine.set_input_value(input2);
        
        // Evaluate allow (should NOT trigger verification for internal registry)
        std::cout << "1. Evaluating allow (no verification needed for trusted registry):" << std::endl;
        auto allow_result2 = engine.eval_query("data.container_policy.allow");
        if (allow_result2) {
            std::cout << "   ✓ Allow result: " << allow_result2.output() << std::endl;
        }
        
        // Get decision details
        auto decision_result2 = engine.eval_query("data.container_policy.decision");
        if (decision_result2) {
            std::cout << "   ✓ Decision: " << decision_result2.output() << std::endl;
        }
        
        std::cout << "\n📊 Verification Count: " << (cose_internal.verified ? 1 : 0) 
                  << " (should be 0 for trusted registry!)" << std::endl;

        std::cout << "\n✅ COSE Lazy Evaluation Demo Complete!" << std::endl;
        
        return 0;

    } catch (const std::exception& e) {
        std::cerr << "❌ Exception: " << e.what() << std::endl;
        return 1;
    }
}
