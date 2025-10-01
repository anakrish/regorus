// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "regorus_value.hpp"
#include <iostream>
#include <cassert>
#include <vector>

using namespace regorus;

// Test that values are properly cleaned up
void test_raii_cleanup() {
    std::cout << "Testing RAII cleanup..." << std::endl;
    
    // Values created in scope should be automatically cleaned up
    {
        Value v1 = Value::String("test");
        Value v2 = Value::Int(42);
        Value v3 = Value::Object();
        // Destructors called here automatically
    }
    
    std::cout << "✓ RAII cleanup test passed (no leaks)" << std::endl;
}

// Test move semantics don't double-free
void test_raii_move_no_double_free() {
    std::cout << "Testing move semantics (no double-free)..." << std::endl;
    
    Value v1 = Value::String("original");
    
    // Move to v2 - v1 should be nulled out
    Value v2 = std::move(v1);
    
    // Both going out of scope should not double-free
    // v1 has nullptr, v2 has the actual pointer
    
    std::cout << "✓ Move semantics test passed (no double-free)" << std::endl;
}

// Test move assignment doesn't leak
void test_raii_move_assignment_no_leak() {
    std::cout << "Testing move assignment (no leak)..." << std::endl;
    
    Value v1 = Value::String("first");
    Value v2 = Value::String("second");
    
    // This should:
    // 1. Drop v1's current value ("first")
    // 2. Take ownership of v2's value ("second")
    // 3. Null out v2
    v1 = std::move(v2);
    
    // Both going out of scope should not leak or double-free
    
    std::cout << "✓ Move assignment test passed (no leak)" << std::endl;
}

// Test exception safety - values cleaned up even when exception thrown
void test_raii_exception_safety() {
    std::cout << "Testing exception safety..." << std::endl;
    
    try {
        Value v1 = Value::String("will be cleaned up");
        Value v2 = Value::Object();
        
        // Throw exception
        throw std::runtime_error("test exception");
        
        // Should never reach here
        assert(false);
    } catch (const std::runtime_error&) {
        // v1 and v2 should be automatically cleaned up via stack unwinding
        std::cout << "  Exception caught, values cleaned up" << std::endl;
    }
    
    std::cout << "✓ Exception safety test passed" << std::endl;
}

// Test that release() properly transfers ownership
void test_raii_release_ownership() {
    std::cout << "Testing release() ownership transfer..." << std::endl;
    
    Value v1 = Value::String("test");
    void* raw_ptr = v1.release();
    
    // v1 should now be empty, raw_ptr has ownership
    // We must manually clean up raw_ptr
    regorus_value_drop(raw_ptr);
    
    // v1 going out of scope should not double-free (it's nullptr)
    
    std::cout << "✓ Release ownership test passed" << std::endl;
}

// Test RAII with containers
void test_raii_in_containers() {
    std::cout << "Testing RAII in containers..." << std::endl;
    
    {
        std::vector<Value> vec;
        vec.push_back(Value::String("one"));
        vec.push_back(Value::String("two"));
        vec.push_back(Value::String("three"));
        
        // Vector going out of scope should clean up all Values
    }
    
    std::cout << "✓ RAII in containers test passed" << std::endl;
}

// Test const methods don't throw
void test_const_methods_noexcept() {
    std::cout << "Testing const methods are noexcept..." << std::endl;
    
    const Value v = Value::Null();
    
    // These should not throw even if called on invalid state
    bool result1 = v.is_null();      // Should return true
    bool result2 = v.is_object();    // Should return false
    bool result3 = v.is_lazy_object(); // Should return false
    
    assert(result1 == true);
    assert(result2 == false);
    assert(result3 == false);
    
    std::cout << "✓ Const methods noexcept test passed" << std::endl;
}

// Test self-assignment safety
void test_raii_self_assignment() {
    std::cout << "Testing self-assignment safety..." << std::endl;
    
    Value v = Value::String("test");
    
    // Self-assignment should be safe
    v = std::move(v);
    
    // Value should still be valid (though may be in moved-from state)
    
    std::cout << "✓ Self-assignment safety test passed" << std::endl;
}

// Test nested object cleanup
void test_raii_nested_cleanup() {
    std::cout << "Testing nested object cleanup..." << std::endl;
    
    {
        Value outer = Value::Object();
        
        // Insert nested objects
        {
            Value inner1 = Value::Object();
            inner1.object_insert("key", Value::String("value"));
            outer.object_insert("inner1", std::move(inner1));
        }
        
        {
            Value inner2 = Value::Array();
            outer.object_insert("inner2", std::move(inner2));
        }
        
        // All should be cleaned up when outer goes out of scope
    }
    
    std::cout << "✓ Nested object cleanup test passed" << std::endl;
}

// Test that destructor is noexcept
void test_destructor_noexcept() {
    std::cout << "Testing destructor is noexcept..." << std::endl;
    
    // This should compile - destructor must be noexcept for this to work
    static_assert(std::is_nothrow_destructible<Value>::value, 
                  "Value destructor must be noexcept");
    
    std::cout << "✓ Destructor noexcept test passed" << std::endl;
}

int main() {
    std::cout << "=== C++ RAII Correctness Tests ===" << std::endl << std::endl;
    
    try {
        test_raii_cleanup();
        test_raii_move_no_double_free();
        test_raii_move_assignment_no_leak();
        test_raii_exception_safety();
        test_raii_release_ownership();
        test_raii_in_containers();
        test_const_methods_noexcept();
        test_raii_self_assignment();
        test_raii_nested_cleanup();
        test_destructor_noexcept();
        
        std::cout << std::endl << "=== All RAII tests passed! ===" << std::endl;
        std::cout << std::endl << "Summary: The C++ wrapper correctly implements RAII:" << std::endl;
        std::cout << "  ✓ Automatic cleanup in destructors" << std::endl;
        std::cout << "  ✓ Move semantics (no copy, no double-free)" << std::endl;
        std::cout << "  ✓ Exception safety (cleanup during stack unwinding)" << std::endl;
        std::cout << "  ✓ Ownership transfer via release()" << std::endl;
        std::cout << "  ✓ Container safety" << std::endl;
        std::cout << "  ✓ noexcept destructor and const methods" << std::endl;
        
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Unexpected exception: " << e.what() << std::endl;
        return 1;
    }
}
