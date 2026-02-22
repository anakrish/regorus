// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

const assert = require('node:assert/strict');
var regorus = require('./pkg/regorusjs');

// Create an engine.
var engine = new regorus.Engine();

// Enable code coverage
engine.setEnableCoverage(true);

// Add Rego policy.
var pkg = engine.addPolicy(
    // Associate this file name with policy
    'hello.rego',
    
    // Rego policy
`
  package test

  x = 10

  # Join messages
  message = concat(", ", [input.message, data.message])
`);

console.log(pkg);
// data.test

// Set policy data
engine.addDataJson(`
 {
    "message" : "World!"
 }
`);

// Set policy input
engine.setInputJson(`
 {
	"message" : "Hello"
 }
`);

// Eval rule as json
var value = engine.evalRule('data.test.message');
value = JSON.parse(value);

// Display value 
console.log(value);
// Hello, World!

// Eval query
results = engine.evalQuery('data.test.message');

// Display
console.log(results);
// {
//   "result": [
//     {
//       "expressions": [
//         {
//           "value": "Hello, World!",
//           "text": "data.test.message",
//           "location": {
//             "row": 1,
//             "col": 1
//           }
//         }
//       ]
//     }
//   ]
// }

// Convert results to object
results = JSON.parse(results);

// Process result
console.log(results.result[0].expressions[0].value);
// Hello, World!

// Print coverage report
report = engine.getCoverageReport();
console.log(report);

// Print pretty report.
report = engine.getCoverageReportPretty();
console.log(report);

// RVM regular example
{
const policy = `
package demo
import rego.v1

default allow := false

allow if {
  input.user == "alice"
  input.active == true
}
`;

const modules = JSON.stringify([
  { id: "demo.rego", content: policy }
]);
const entryPoints = JSON.stringify(["data.demo.allow"]);

const program = regorus.Program.compileFromModules(
  "{}",
  modules,
  entryPoints
);
assert.equal(program.hasHostAwait, false, 'regular rego program should not require host await');

console.log(program.generateListing());

const binary = program.serializeBinary();
const deserialized = regorus.Program.deserializeBinary(binary);
if (deserialized.isPartial) {
  throw new Error("Deserialized program marked partial");
}
const rehydrated = deserialized.program();

const vm = new regorus.Rvm();
vm.loadProgram(rehydrated);
vm.setInputJson('{"user":"alice","active":true}');
console.log(vm.execute());
}

// RVM HostAwait example
{
const policy = `
package demo
import rego.v1

default allow := false

allow if {
  input.account.active == true
  details := __builtin_host_await(input.account.id, "account")
  details.tier == "gold"
}
`;

const modules = JSON.stringify([
  { id: "await.rego", content: policy }
]);
const entryPoints = JSON.stringify(["data.demo.allow"]);

const program = regorus.Program.compileFromModules(
  "{}",
  modules,
  entryPoints
);
assert.equal(program.hasHostAwait, true, 'host-await policy should advertise host await presence');

const vm = new regorus.Rvm();
if (program.hasHostAwait) {
  vm.setExecutionMode(1);
}
vm.loadProgram(program);
vm.setInputJson('{"account":{"id":"acct-1","active":true}}');
vm.execute();
console.log(vm.getExecutionState());
console.log(vm.resume('{"tier":"gold"}'));
}

// Cedar example
{
const cedarPolicy = `
permit(principal in User::"admins", action == Action::"view", resource == File::"budget")
when { context.ip like "10.*" };
`;

const policies = JSON.stringify([
  { id: "policy.cedar", content: cedarPolicy }
]);

const program = regorus.Program.compileCedarPolicies(policies);
console.log(program.generateListing());

const vm = new regorus.Rvm();
vm.loadProgram(program);
vm.setInputJson(`
{
  "principal": "User::alice",
  "action": "Action::view",
  "resource": "File::budget",
  "context": { "ip": "10.1.2.3" },
  "entities": {
    "User::alice": { "parents": ["User::admins"], "attrs": {} },
    "User::admins": { "parents": [], "attrs": {} }
  }
}
`);

const decision = JSON.parse(vm.executeEntryPoint("cedar.authorize"));
if (decision !== 1) {
  throw new Error(`Unexpected Cedar decision: ${decision}`);
}
}

// Azure Policy rule compilation API example
{
const policyRule = JSON.stringify({
  if: {
    field: "type",
    equals: "Microsoft.Compute/virtualMachines"
  },
  then: {
    effect: "deny"
  }
});

const azureProgram = regorus.Program.compileAzurePolicyRule(policyRule, undefined);
const listing = azureProgram.generateListing();
assert.ok(listing.length > 0, 'azure rule listing should not be empty');
assert.equal(azureProgram.hasHostAwait, false, 'azure rule compile path should not emit host await yet');

const binary = azureProgram.serializeBinary();
const rehydrated = regorus.Program.deserializeBinary(binary).program();

const vm = new regorus.Rvm();
vm.loadProgram(rehydrated);
vm.setInputJson(JSON.stringify({
  resource: {
    type: "Microsoft.Compute/virtualMachines"
  },
  context: {},
  parameters: {}
}));

const result = JSON.parse(vm.execute());
assert.equal(result, 'deny', 'matching resource should evaluate to deny');
}

// Azure Policy definition compilation API example (parameter defaults)
{
const policyDefinition = JSON.stringify({
  properties: {
    parameters: {
      effect: {
        type: "String",
        defaultValue: "deny",
        allowedValues: ["deny", "audit"]
      }
    },
    policyRule: {
      if: {
        field: "type",
        equals: "Microsoft.Compute/virtualMachines"
      },
      then: {
        effect: "[parameters('effect')]"
      }
    }
  }
});

const azureProgram = regorus.Program.compileAzurePolicyDefinition(policyDefinition, undefined);
const listing = azureProgram.generateListing();
assert.ok(listing.length > 0, 'azure definition listing should not be empty');
assert.equal(azureProgram.hasHostAwait, false, 'azure definition compile path should not emit host await yet');

const vm = new regorus.Rvm();
vm.loadProgram(azureProgram);
vm.setInputJson(JSON.stringify({
  resource: {
    type: "Microsoft.Compute/virtualMachines"
  },
  context: {},
  parameters: {}
}));

const defaultResult = JSON.parse(vm.execute());
assert.equal(defaultResult, 'deny', 'default parameter value should be used when missing');

vm.setInputJson(JSON.stringify({
  resource: {
    type: "Microsoft.Compute/virtualMachines"
  },
  context: {},
  parameters: {
    effect: "audit"
  }
}));

const overrideResult = JSON.parse(vm.execute());
assert.equal(overrideResult, 'audit', 'provided parameter value should override default');
}

console.log('WASM JS tests completed successfully.');
