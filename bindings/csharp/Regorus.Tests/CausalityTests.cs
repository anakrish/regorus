// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Regorus;

namespace Regorus.Tests;

[TestClass]
public class CausalityTests
{
    private const string Policy = @"
package test

default allow = false

allow if {
    input.role == ""admin""
}

allow if {
    input.role == ""editor""
    input.action == ""read""
}
";

    [TestMethod]
    public void Causality_report_is_empty_when_disabled()
    {
        using var engine = new Engine();
        engine.AddPolicy("test.rego", Policy);
        engine.SetInputJson("""{"role": "admin"}""");
        engine.EvalRule("data.test.allow");

        var report = engine.TakeCausalityReport();
        Assert.IsNotNull(report);

        var doc = JsonNode.Parse(report);
        Assert.IsNotNull(doc);

        // When explanations are disabled, emissions list should be empty.
        var emissions = doc!["emissions"]?.AsArray();
        Assert.IsNotNull(emissions);
        Assert.AreEqual(0, emissions!.Count);
    }

    [TestMethod]
    public void Causality_report_captures_explanations_when_enabled()
    {
        using var engine = new Engine();
        engine.AddPolicy("test.rego", Policy);
        engine.SetExplanationSettings(true);
        engine.SetInputJson("""{"role": "admin"}""");
        engine.EvalRule("data.test.allow");

        var report = engine.TakeCausalityReport();
        Assert.IsNotNull(report);

        var doc = JsonNode.Parse(report);
        Assert.IsNotNull(doc);

        var emissions = doc!["emissions"]?.AsArray();
        Assert.IsNotNull(emissions);
        Assert.IsTrue(emissions!.Count > 0, "Expected at least one emission in the causality report.");
    }

    [TestMethod]
    public void Causality_report_with_full_value_mode()
    {
        using var engine = new Engine();
        engine.AddPolicy("test.rego", Policy);
        engine.SetExplanationSettings(true, ExplanationValueMode.Full);
        engine.SetInputJson("""{"role": "admin"}""");
        engine.EvalRule("data.test.allow");

        var report = engine.TakeCausalityReport();
        Assert.IsNotNull(report);

        var doc = JsonNode.Parse(report);
        Assert.IsNotNull(doc);

        var emissions = doc!["emissions"]?.AsArray();
        Assert.IsNotNull(emissions);
        Assert.IsTrue(emissions!.Count > 0, "Expected at least one emission with Full value mode.");
    }

    [TestMethod]
    public void Causality_report_with_all_contributing_conditions()
    {
        using var engine = new Engine();
        engine.AddPolicy("test.rego", Policy);
        engine.SetExplanationSettings(
            true,
            ExplanationValueMode.Full,
            ExplanationConditionMode.AllContributing);
        engine.SetInputJson("""{"role": "editor", "action": "read"}""");
        engine.EvalRule("data.test.allow");

        var report = engine.TakeCausalityReport();
        Assert.IsNotNull(report);

        var doc = JsonNode.Parse(report);
        Assert.IsNotNull(doc);

        var emissions = doc!["emissions"]?.AsArray();
        Assert.IsNotNull(emissions);
        Assert.IsTrue(emissions!.Count > 0, "Expected at least one emission with AllContributing mode.");
    }

    [TestMethod]
    public void Causality_report_resets_after_take()
    {
        using var engine = new Engine();
        engine.AddPolicy("test.rego", Policy);
        engine.SetExplanationSettings(true);

        // First evaluation and take.
        engine.SetInputJson("""{"role": "admin"}""");
        engine.EvalRule("data.test.allow");
        var report1 = engine.TakeCausalityReport();
        Assert.IsNotNull(report1);
        var emissions1 = JsonNode.Parse(report1)!["emissions"]!.AsArray();
        Assert.IsTrue(emissions1.Count > 0);

        // Second take without evaluation should be empty.
        var report2 = engine.TakeCausalityReport();
        Assert.IsNotNull(report2);
        var emissions2 = JsonNode.Parse(report2)!["emissions"]!.AsArray();
        Assert.AreEqual(0, emissions2.Count);
    }

    [TestMethod]
    public void Causality_report_denied_shows_failure_outcome()
    {
        using var engine = new Engine();
        engine.AddPolicy("test.rego", Policy);
        engine.SetExplanationSettings(true, ExplanationValueMode.Full);
        engine.SetInputJson("""{"role": "viewer"}""");
        engine.EvalRule("data.test.allow");

        var report = engine.TakeCausalityReport();
        Assert.IsNotNull(report);

        var doc = JsonNode.Parse(report);
        Assert.IsNotNull(doc);

        // The report should be valid JSON even for a denied evaluation.
        var emissions = doc!["emissions"]?.AsArray();
        Assert.IsNotNull(emissions);
    }

    [TestMethod]
    public void Disable_explanations_after_enabling()
    {
        using var engine = new Engine();
        engine.AddPolicy("test.rego", Policy);

        // Enable, evaluate, take.
        engine.SetExplanationSettings(true);
        engine.SetInputJson("""{"role": "admin"}""");
        engine.EvalRule("data.test.allow");
        var report1 = engine.TakeCausalityReport();
        var emissions1 = JsonNode.Parse(report1!)!["emissions"]!.AsArray();
        Assert.IsTrue(emissions1.Count > 0);

        // Disable, evaluate, take - should be empty.
        engine.SetExplanationSettings(false);
        engine.SetInputJson("""{"role": "admin"}""");
        engine.EvalRule("data.test.allow");
        var report2 = engine.TakeCausalityReport();
        var emissions2 = JsonNode.Parse(report2!)!["emissions"]!.AsArray();
        Assert.AreEqual(0, emissions2.Count);
    }
}
