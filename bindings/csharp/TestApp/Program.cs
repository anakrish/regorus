// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Diagnostics;


long nanosecPerTick = (1000L * 1000L * 1000L) / Stopwatch.Frequency;
var w = new Stopwatch();


// Force load of modules.
{
    var _e = new Regorus.Engine();
#if NET8_0_OR_GREATER
    var _j = System.Text.Json.JsonDocument.Parse("{}");
#endif
}

w.Restart();

var engine = new Regorus.Engine();
engine.SetRegoV0(true);

w.Stop();
var newEngineTicks = w.ElapsedTicks;


w.Restart();

// Load policies and data.
engine.AddPolicyFromFile("../../../tests/aci/framework.rego");
engine.AddPolicyFromFile("../../../tests/aci/api.rego");
engine.AddPolicyFromFile("../../../tests/aci/policy.rego");
engine.AddDataFromJsonFile("../../../tests/aci/data.json");


w.Stop();
var loadPoliciesTicks = w.ElapsedTicks;


w.Restart();

// Set input and eval rule.
engine.SetInputFromJsonFile("../../../tests/aci/input.json");
var value = engine.EvalRule("data.framework.mount_overlay")
    ?? throw new System.InvalidOperationException("Expected EvalRule to return a JSON value.");

#if NET8_0_OR_GREATER
var valueDoc = System.Text.Json.JsonDocument.Parse(value);

w.Stop();
var evalTicks = w.ElapsedTicks;

Console.WriteLine("{0}", valueDoc);
#else
w.Stop();
var evalTicks = w.ElapsedTicks;
#endif


Console.WriteLine("Engine creation took {0} msecs", (newEngineTicks * nanosecPerTick) / (1000.0 * 1000.0));
Console.WriteLine("Load policies and data took {0} msecs", (loadPoliciesTicks * nanosecPerTick) / (1000.0 * 1000.0));
Console.WriteLine("EvalRule took {0} msecs", (evalTicks * nanosecPerTick) / (1000.0 * 1000.0));

engine = new Regorus.Engine();
engine.AddPolicy(
  "test.rego",
  "package test\nx = 1\nmessage = `Hello`");

engine.SetEnableCoverage(true);
Console.WriteLine("data.test.message: {0}", engine.EvalRule("data.test.message"));
Console.WriteLine("Coverage Report:\n{0}", engine.GetCoverageReportPretty());

if (engine.EvalRule("data.test.message") != "\"Hello\"")
{
    Console.WriteLine("Failure.");
    System.Environment.Exit(1);
}
else
{
    Console.WriteLine("Success.");
}

// ── Causality / Explanation demo ──────────────────────────────────────
Console.WriteLine();
Console.WriteLine("=== Causality Demo ===");

var causalEngine = new Regorus.Engine();
causalEngine.AddPolicy("authz.rego", @"
package authz

default allow = false

allow if {
    input.role == ""admin""
}

allow if {
    input.role == ""editor""
    input.action == ""read""
}
");

// Enable explanation capture with full (unredacted) values.
causalEngine.SetExplanationSettings(
    true,
    Regorus.ExplanationValueMode.Full,
    Regorus.ExplanationConditionMode.AllContributing);

// Evaluate with an admin role.
causalEngine.SetInputJson("""{"role": "admin"}""");
causalEngine.EvalRule("data.authz.allow");

var report = causalEngine.TakeCausalityReport();
Console.WriteLine("Causality report (admin):");
Console.WriteLine(report);

// Evaluate with an editor doing a read.
causalEngine.SetInputJson("""{"role": "editor", "action": "read"}""");
causalEngine.EvalRule("data.authz.allow");

report = causalEngine.TakeCausalityReport();
Console.WriteLine("Causality report (editor+read):");
Console.WriteLine(report);

// Evaluate a denied case.
causalEngine.SetInputJson("""{"role": "viewer"}""");
causalEngine.EvalRule("data.authz.allow");

report = causalEngine.TakeCausalityReport();
Console.WriteLine("Causality report (viewer - denied):");
Console.WriteLine(report);

