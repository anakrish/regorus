// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

var regorus = require('./pkg/regorusjs');

console.log('=== Regorus WASM + RVM Test ===\n');

// Test data
const policyData = {
    "message": "World!",
    "users": ["alice", "bob", "admin"],
    "config": {
        "debug": true,
        "timeout": 30
    }
};

const inputData = {
    "message": "Hello",
    "user": "alice",
    "action": "read"
};

// Create an engine.
var engine = new regorus.Engine();
engine.setEnableCoverage(true);

// Add Rego policy.
var pkg = engine.addPolicy(
    'test.rego',
    `
  package test

  x := 10

  # Join messages
  message := concat(", ", [input.message, data.message])
  
  # User validation
  allow := true if {
    input.user in data.users
    input.action == "read"
  }
  
  # Complex calculation
  calculate := x * 2 if input.user != "admin"
  calculate := x * 3 if input.user == "admin"
  
  # Object construction
  response := {
    "allowed": allow,
    "message": message,
    "calculation": calculate,
    "debug": data.config.debug
  }
`);

console.log('Package:', pkg);

// Set policy data and input
engine.addDataJson(JSON.stringify(policyData));
engine.setInputJson(JSON.stringify(inputData));

console.log('\n=== Interpreter Evaluation ===');

// Test interpreter with different rules
const testRules = [
    'data.test.message',
    'data.test.allow', 
    'data.test.calculate',
    'data.test.response'
];

const interpreterResults = {};
for (const rule of testRules) {
    const value = engine.evalRule(rule);
    const parsed = JSON.parse(value);
    interpreterResults[rule] = parsed;
    console.log(`${rule}:`, parsed);
}

console.log('\n=== RVM Compilation and Execution ===');

// Compile policy to RVM
const compiledPolicy = engine.compileWithEntrypoint('data.test.response');
console.log('Entry point:', compiledPolicy.getEntrypoint());

// Test interpreter evaluation via compiled policy
const interpCompiledResult = compiledPolicy.evalWithInput(JSON.stringify(inputData));
const interpCompiledParsed = JSON.parse(interpCompiledResult);
console.log('Interpreter (compiled):', interpCompiledParsed);

// Create RVM program with multiple entry points
const rvmProgram = compiledPolicy.compileToRvmProgram(testRules);
console.log('RVM Program Info:');
console.log('  Instructions:', rvmProgram.getInstructionCount());
console.log('  Entry Points:', rvmProgram.getEntryPointCount());
console.log('  Entry Point Names:', rvmProgram.getEntryPointNames());

// Create and configure RVM
const vm = new regorus.RegoVM();
vm.loadProgram(rvmProgram);
vm.setData(JSON.stringify(policyData));
vm.setInput(JSON.stringify(inputData));

// Execute RVM - main entry point
const rvmResult = vm.execute();
const rvmParsed = JSON.parse(rvmResult);
console.log('RVM Main Result:', rvmParsed);

console.log('\n=== Individual Entry Point Execution ===');

// Execute each entry point individually
const rvmResults = {};
const entryPointNames = vm.getEntryPointNames();
console.log('Available entry points:', entryPointNames);

for (let i = 0; i < entryPointNames.length; i++) {
    const entryPointName = entryPointNames[i];
    try {
        // Execute by index
        const resultByIndex = vm.executeEntryPointByIndex(i);
        const parsedByIndex = JSON.parse(resultByIndex);
        
        // Execute by name
        const resultByName = vm.executeEntryPointByName(entryPointName);
        const parsedByName = JSON.parse(resultByName);
        
        rvmResults[entryPointName] = parsedByIndex;
        
        console.log(`Entry Point ${i} (${entryPointName}):`);
        console.log('  By Index:', parsedByIndex);
        console.log('  By Name:', parsedByName);
        
        // Verify both methods produce the same result
        if (JSON.stringify(parsedByIndex) === JSON.stringify(parsedByName)) {
            console.log('  ✅ Index and name execution match');
        } else {
            console.log('  ❌ Index and name execution differ!');
        }
    } catch (error) {
        console.log(`  ❌ Error executing ${entryPointName}:`, error.toString());
        rvmResults[entryPointName] = null;
    }
}

console.log('\n=== Results Comparison ===');

// Compare interpreter vs RVM results for each entry point
let allMatch = true;
for (const rule of testRules) {
    const interpreterResult = interpreterResults[rule];
    const rvmResult = rvmResults[rule];
    
    console.log(`\n${rule}:`);
    console.log('  Interpreter:', JSON.stringify(interpreterResult, null, 2));
    console.log('  RVM:', JSON.stringify(rvmResult, null, 2));
    
    if (JSON.stringify(interpreterResult) === JSON.stringify(rvmResult)) {
        console.log('  ✅ Results match!');
    } else {
        console.log('  ❌ Results differ!');
        allMatch = false;
    }
}

if (allMatch) {
    console.log('\n🎉 All entry points match between Interpreter and RVM!');
} else {
    console.log('\n⚠️  Some entry points have mismatched results.');
}

console.log('\n=== Standalone RVM Compilation Test ===');

// Test standalone compilation function
const standaloneModule = new regorus.PolicyModule(
    'standalone.rego',
    `
    package standalone
    
    greeting := sprintf("Hello %s from standalone!", [input.name])
    math_result := input.a + input.b * 2
    
    complex := {
        "greeting": greeting,
        "math": math_result,
        "timestamp": time.now_ns(),
        "input_keys": object.keys(input)
    }
    `
);

const standaloneProgram = regorus.compileToRvmProgram(
    JSON.stringify({}), // empty data
    [standaloneModule],
    ['data.standalone.complex']
);

const standaloneVm = new regorus.RegoVM();
standaloneVm.loadProgram(standaloneProgram);
standaloneVm.setInput(JSON.stringify({
    "name": "RVM",
    "a": 10,
    "b": 5
}));

const standaloneResult = standaloneVm.execute();
const standaloneParsed = JSON.parse(standaloneResult);
console.log('Standalone RVM result:', standaloneParsed);

console.log('\n=== Performance Test ===');

// Simple performance comparison
const iterations = 100;

console.log(`Running ${iterations} iterations...`);

// Time interpreter
const startInterp = Date.now();
for (let i = 0; i < iterations; i++) {
    engine.setInputJson(JSON.stringify({...inputData, iteration: i}));
    engine.evalRule('data.test.response');
}
const interpTime = Date.now() - startInterp;

// Time RVM
const startRvm = Date.now();
for (let i = 0; i < iterations; i++) {
    vm.setInput(JSON.stringify({...inputData, iteration: i}));
    vm.execute();
}
const rvmTime = Date.now() - startRvm;

console.log(`Interpreter: ${interpTime}ms`);
console.log(`RVM: ${rvmTime}ms`);
console.log(`Speedup: ${(interpTime / rvmTime).toFixed(2)}x`);

console.log('\n=== Coverage Report ===');
const coverageReport = engine.getCoverageReportPretty();
console.log(coverageReport);

console.log('\n=== RBAC Tests ===');

// Test 1: Basic RBAC Policy
console.log('\n--- Test 1: Basic RBAC Policy ---');

const rbacPolicy1 = {
    "version": "1.0",
    "roleDefinitions": [{
        "id": "reader",
        "name": "Reader",
        "permissions": [{
            "actions": ["read", "list"],
            "notActions": [],
            "dataActions": [],
            "notDataActions": []
        }],
        "assignableScopes": ["/"]
    }],
    "roleAssignments": [{
        "id": "assignment1",
        "principalId": "user1",
        "principalType": "User",
        "roleDefinitionId": "reader",
        "scope": "/"
    }]
};

const rbacContext1 = {
    "principal": {
        "id": "user1",
        "principalType": "User"
    },
    "resource": {
        "scope": "/subscriptions/sub1"
    },
    "action": "read"
};

// Test RbacPolicy parsing and compilation
const policy1 = new regorus.RbacPolicy(JSON.stringify(rbacPolicy1));
console.log('Policy Version:', policy1.getVersion());
console.log('Role Definitions:', policy1.getRoleDefinitionCount());
console.log('Role Assignments:', policy1.getRoleAssignmentCount());

// Test RbacEngine
const rbacEngine1 = new regorus.RbacEngine();
rbacEngine1.loadPolicyFromJson(JSON.stringify(rbacPolicy1));

const allowed1 = rbacEngine1.evaluate(JSON.stringify(rbacContext1));
console.log('Action "read" allowed for user1:', allowed1);

const detailed1 = rbacEngine1.evaluateDetailed(JSON.stringify(rbacContext1));
console.log('Detailed result:', JSON.parse(detailed1));

// Test deny case
const rbacContext1Deny = {
    "principal": {
        "id": "user2", // Different user
        "principalType": "User"
    },
    "resource": {
        "scope": "/subscriptions/sub1"
    },
    "action": "read"
};

const denied1 = rbacEngine1.evaluate(JSON.stringify(rbacContext1Deny));
console.log('Action "read" allowed for user2:', denied1, '(should be false)');

// Test 2: RBAC Policy with Conditions
console.log('\n--- Test 2: RBAC Policy with Conditions ---');

const rbacPolicy2 = {
    "version": "1.0",
    "roleDefinitions": [{
        "id": "conditional-reader",
        "name": "Conditional Reader",
        "permissions": [{
            "actions": ["read"],
            "notActions": [],
            "dataActions": [],
            "notDataActions": []
        }],
        "assignableScopes": ["/"]
    }],
    "roleAssignments": [{
        "id": "assignment1",
        "principalId": "user1",
        "principalType": "User",
        "roleDefinitionId": "conditional-reader",
        "scope": "/",
        "condition": {
            "version": "2.0",
            "expression": "@Resource[name] StringEquals 'allowed-resource'"
        }
    }]
};

// Test with matching condition
const rbacContext2Allow = {
    "principal": {
        "id": "user1",
        "principalType": "User"
    },
    "resource": {
        "scope": "/subscriptions/sub1",
        "attributes": {
            "name": "allowed-resource"
        }
    },
    "action": "read"
};

const allowed2 = regorus.evaluateRbacPolicy(
    JSON.stringify(rbacPolicy2),
    JSON.stringify(rbacContext2Allow)
);
console.log('Condition matches (name=allowed-resource):', allowed2);

// Test with non-matching condition
const rbacContext2Deny = {
    "principal": {
        "id": "user1",
        "principalType": "User"
    },
    "resource": {
        "scope": "/subscriptions/sub1",
        "attributes": {
            "name": "forbidden-resource"
        }
    },
    "action": "read"
};

const denied2 = regorus.evaluateRbacPolicy(
    JSON.stringify(rbacPolicy2),
    JSON.stringify(rbacContext2Deny)
);
console.log('Condition does not match (name=forbidden-resource):', denied2, '(should be false)');

// Test 3: Complex RBAC Policy with Azure Storage
console.log('\n--- Test 3: Azure Storage RBAC Policy ---');

const rbacPolicy3 = {
    "version": "1.0",
    "roleDefinitions": [{
        "id": "storage-blob-contributor",
        "name": "Storage Blob Data Contributor",
        "permissions": [{
            "actions": [],
            "notActions": [],
            "dataActions": [
                "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read",
                "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write"
            ],
            "notDataActions": []
        }],
        "assignableScopes": ["/"]
    }],
    "roleAssignments": [{
        "id": "assignment1",
        "principalId": "app1",
        "principalType": "ServicePrincipal",
        "roleDefinitionId": "storage-blob-contributor",
        "scope": "/subscriptions/sub1/resourceGroups/rg1",
        "condition": {
            "version": "2.0",
            "expression": "(@Request[Microsoft.Storage/storageAccounts/blobServices/containers/blobs:prefix] StringStartsWith 'public/') OR (@Resource[Microsoft.Storage/storageAccounts/blobServices/containers:name] StringEquals 'public')"
        }
    }]
};

// Test allowed - prefix matches
const rbacContext3Allow = {
    "principal": {
        "id": "app1",
        "principalType": "ServicePrincipal"
    },
    "resource": {
        "scope": "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/storage1"
    },
    "action": "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read",
    "request": {
        "attributes": {
            "prefix": "public/documents"
        }
    }
};

const rbacEngine3 = new regorus.RbacEngine();
rbacEngine3.loadPolicyFromJson(JSON.stringify(rbacPolicy3));

const allowed3 = rbacEngine3.evaluate(JSON.stringify(rbacContext3Allow));
console.log('Storage blob read with prefix "public/documents":', allowed3);

// Test denied - prefix doesn't match
const rbacContext3Deny = {
    "principal": {
        "id": "app1",
        "principalType": "ServicePrincipal"
    },
    "resource": {
        "scope": "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/storage1",
        "attributes": {
            "name": "private"
        }
    },
    "action": "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read",
    "request": {
        "attributes": {
            "prefix": "private/secrets"
        }
    }
};

const denied3 = rbacEngine3.evaluate(JSON.stringify(rbacContext3Deny));
console.log('Storage blob read with prefix "private/secrets":', denied3, '(should be false)');

// Test 4: RVM Compilation for RBAC
console.log('\n--- Test 4: RBAC RVM Compilation ---');

const rbacProgram = regorus.compileRbacToRvmProgram(
    JSON.stringify(rbacPolicy1),
    JSON.stringify(rbacContext1)
);

console.log('RBAC RVM Program Instructions:', rbacProgram.getInstructionCount());

const rbacVm = new regorus.RegoVM();
rbacVm.loadProgram(rbacProgram);
rbacVm.setInput(JSON.stringify({
    "principalId": "user1",
    "resource": "/subscriptions/sub1",
    "action": "read"
}));
rbacVm.setData(JSON.stringify({}));

const rbacRvmResult = rbacVm.execute();
console.log('RBAC RVM Result:', JSON.parse(rbacRvmResult));

console.log('\n✅ All RBAC tests completed successfully!');

console.log('\n=== Test Complete ===');
