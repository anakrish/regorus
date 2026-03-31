// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.IO;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Regorus.Tests;

[TestClass]
public sealed class AzurePolicyTests
{
    /// <summary>
    /// Minimal Azure Policy definition: deny when resource type equals Microsoft.Compute/virtualMachines.
    /// Uses the "unwrapped" format (properties contents directly).
    /// </summary>
    private const string DenyVmPolicy = """
{
  "policyRule": {
    "if": {
      "field": "type",
      "equals": "Microsoft.Compute/virtualMachines"
    },
    "then": {
      "effect": "deny"
    }
  }
}
""";

    /// <summary>
    /// Simple Azure Policy with parameters.
    /// </summary>
    private const string DenyByTagPolicy = """
{
  "parameters": {
    "tagName": {
      "type": "String",
      "metadata": {
        "displayName": "Tag Name",
        "description": "Name of the tag to check"
      }
    }
  },
  "policyRule": {
    "if": {
      "field": "[concat('tags[', parameters('tagName'), ']')]",
      "exists": "false"
    },
    "then": {
      "effect": "deny"
    }
  }
}
""";

    /// <summary>
    /// A VM resource for testing.
    /// </summary>
    private const string VmResource = """
{
  "type": "Microsoft.Compute/virtualMachines",
  "name": "myVM",
  "location": "eastus",
  "properties": {
    "hardwareProfile": {
      "vmSize": "Standard_DS1_v2"
    }
  }
}
""";

    /// <summary>
    /// A storage account resource for testing (should not match the VM deny policy).
    /// </summary>
    private const string StorageResource = """
{
  "type": "Microsoft.Storage/storageAccounts",
  "name": "myStorage",
  "location": "eastus",
  "properties": {
    "supportsHttpsTrafficOnly": true
  }
}
""";

    private static string GetTestAliasesPath()
    {
        // The test project copies tests/** to output — see the csproj ItemGroup
        return Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "tests", "azure_policy", "aliases", "test_aliases.json");
    }

    // -----------------------------------------------------------
    // AliasRegistry tests
    // -----------------------------------------------------------

    [TestMethod]
    public void AliasRegistry_create_and_dispose()
    {
        using var registry = new AliasRegistry();
        Assert.AreEqual(0L, registry.Length, "Empty registry should have length 0");
    }

    [TestMethod]
    public void AliasRegistry_load_json_succeeds()
    {
        var path = GetTestAliasesPath();
        if (!File.Exists(path))
        {
            Assert.Inconclusive($"Test alias file not found at {path}");
            return;
        }

        var json = File.ReadAllText(path);
        using var registry = new AliasRegistry();
        registry.LoadJson(json);
        Assert.IsTrue(registry.Length > 0, "Registry should have loaded resource types");
    }

    [TestMethod]
    public void AliasRegistry_load_json_bad_data_throws()
    {
        using var registry = new AliasRegistry();
        Assert.ThrowsException<InvalidOperationException>(() => registry.LoadJson("not valid json"));
    }

    // -----------------------------------------------------------
    // AzurePolicyCompiler – compile without aliases
    // -----------------------------------------------------------

    [TestMethod]
    public void AzurePolicyCompiler_compile_simple_deny_without_aliases()
    {
        using var program = AzurePolicyCompiler.CompileDefinition(DenyVmPolicy);
        var listing = program.GenerateListing();
        Assert.IsFalse(string.IsNullOrWhiteSpace(listing), "Should generate a listing");
    }

    [TestMethod]
    public void AzurePolicyCompiler_compile_invalid_json_throws()
    {
        Assert.ThrowsException<InvalidOperationException>(() =>
            AzurePolicyCompiler.CompileDefinition("not json"));
    }

    [TestMethod]
    public void AzurePolicyCompiler_compile_null_throws()
    {
        Assert.ThrowsException<ArgumentNullException>(() =>
            AzurePolicyCompiler.CompileDefinition(null!));
    }

    // -----------------------------------------------------------
    // AzurePolicyCompiler – compile with aliases
    // -----------------------------------------------------------

    [TestMethod]
    public void AzurePolicyCompiler_compile_with_aliases()
    {
        var aliasPath = GetTestAliasesPath();
        if (!File.Exists(aliasPath))
        {
            Assert.Inconclusive($"Test alias file not found at {aliasPath}");
            return;
        }

        var aliasJson = File.ReadAllText(aliasPath);
        using var registry = new AliasRegistry();
        registry.LoadJson(aliasJson);

        using var program = AzurePolicyCompiler.CompileDefinition(DenyVmPolicy, registry);
        var listing = program.GenerateListing();
        Assert.IsFalse(string.IsNullOrWhiteSpace(listing), "Should generate a listing");
    }

    // -----------------------------------------------------------
    // End-to-end: compile → normalize → execute
    // -----------------------------------------------------------

    [TestMethod]
    public void EndToEnd_deny_vm_policy_matching_resource_returns_deny()
    {
        var aliasPath = GetTestAliasesPath();
        if (!File.Exists(aliasPath))
        {
            Assert.Inconclusive($"Test alias file not found at {aliasPath}");
            return;
        }

        // 1. Load aliases
        var aliasJson = File.ReadAllText(aliasPath);
        using var registry = new AliasRegistry();
        registry.LoadJson(aliasJson);

        // 2. Compile the policy
        using var program = AzurePolicyCompiler.CompileDefinition(DenyVmPolicy, registry);

        // 3. Normalize the matching resource into the input envelope
        var inputJson = registry.NormalizeAndWrap(VmResource, "2024-03-01", "{}", "{}");
        Assert.IsNotNull(inputJson, "NormalizeAndWrap should return a JSON string");

        // 4. Execute
        using var vm = new Rvm();
        vm.LoadProgram(program);
        vm.SetInputJson(inputJson!);

        var result = vm.Execute();
        Assert.IsNotNull(result, "Execute should return a result");
        Assert.IsTrue(result!.Contains("\"deny\""), $"Expected deny effect, got: {result}");
    }

    [TestMethod]
    public void EndToEnd_deny_vm_policy_non_matching_resource_returns_no_effect()
    {
        var aliasPath = GetTestAliasesPath();
        if (!File.Exists(aliasPath))
        {
            Assert.Inconclusive($"Test alias file not found at {aliasPath}");
            return;
        }

        // 1. Load aliases
        var aliasJson = File.ReadAllText(aliasPath);
        using var registry = new AliasRegistry();
        registry.LoadJson(aliasJson);

        // 2. Compile the policy
        using var program = AzurePolicyCompiler.CompileDefinition(DenyVmPolicy, registry);

        // 3. Normalize a non-matching resource (storage account, not VM)
        var inputJson = registry.NormalizeAndWrap(StorageResource, "2024-03-01", "{}", "{}");
        Assert.IsNotNull(inputJson, "NormalizeAndWrap should return a JSON string");

        // 4. Execute — should NOT produce a deny effect
        using var vm = new Rvm();
        vm.LoadProgram(program);
        vm.SetInputJson(inputJson!);

        var result = vm.Execute();
        // For non-matching resources, the VM returns undefined (no effect)
        Assert.IsTrue(result is null || !result.Contains("\"deny\""),
            $"Non-matching resource should not produce deny effect, got: {result}");
    }

    [TestMethod]
    public void EndToEnd_program_serialize_deserialize_roundtrip()
    {
        using var program = AzurePolicyCompiler.CompileDefinition(DenyVmPolicy);

        // Serialize to binary
        var binary = program.SerializeBinary();
        Assert.IsTrue(binary.Length > 0, "Binary should not be empty");

        // Deserialize
        using var restored = Program.DeserializeBinary(binary, out var isPartial);
        Assert.IsFalse(isPartial, "Should not be a partial deserialization");

        // Verify listing still works
        var listing = restored.GenerateListing();
        Assert.IsFalse(string.IsNullOrWhiteSpace(listing), "Restored program should produce a listing");
    }

    // -----------------------------------------------------------
    // Denormalize roundtrip tests
    // -----------------------------------------------------------

    [TestMethod]
    public void Denormalize_roundtrip_preserves_resource()
    {
        var aliasPath = GetTestAliasesPath();
        if (!File.Exists(aliasPath))
        {
            Assert.Inconclusive($"Test alias file not found at {aliasPath}");
            return;
        }

        var aliasJson = File.ReadAllText(aliasPath);
        using var registry = new AliasRegistry();
        registry.LoadJson(aliasJson);

        // 1. Normalize the VM resource
        var inputJson = registry.NormalizeAndWrap(VmResource, "2024-03-01", "{}", "{}");
        Assert.IsNotNull(inputJson, "NormalizeAndWrap should return JSON");

        // 2. Extract the "resource" field from the envelope
        var envelope = System.Text.Json.JsonDocument.Parse(inputJson!);
        var normalizedResourceJson = envelope.RootElement.GetProperty("resource").GetRawText();

        // 3. Denormalize back to ARM format
        var denormalizedJson = registry.Denormalize(normalizedResourceJson, "2024-03-01");
        Assert.IsNotNull(denormalizedJson, "Denormalize should return JSON");

        // Verify the denormalized resource has a type field matching the original
        var denormalized = System.Text.Json.JsonDocument.Parse(denormalizedJson!);
        var resourceType = denormalized.RootElement.GetProperty("type").GetString();
        Assert.AreEqual(
            "microsoft.compute/virtualmachines",
            resourceType?.ToLowerInvariant(),
            "Denormalized resource should preserve the resource type");

        // 4. Re-normalize and compare: the normalized resource should match the original
        var reInputJson = registry.NormalizeAndWrap(denormalizedJson!, "2024-03-01", "{}", "{}");
        Assert.IsNotNull(reInputJson, "Re-normalization should return JSON");

        var reEnvelope = System.Text.Json.JsonDocument.Parse(reInputJson!);
        var reNormalizedResourceJson = reEnvelope.RootElement.GetProperty("resource").GetRawText();

        Assert.AreEqual(
            normalizedResourceJson,
            reNormalizedResourceJson,
            "Denormalize → re-normalize should produce identical normalized resource");
    }

    [TestMethod]
    public void Denormalize_storage_roundtrip_preserves_resource()
    {
        var aliasPath = GetTestAliasesPath();
        if (!File.Exists(aliasPath))
        {
            Assert.Inconclusive($"Test alias file not found at {aliasPath}");
            return;
        }

        var aliasJson = File.ReadAllText(aliasPath);
        using var registry = new AliasRegistry();
        registry.LoadJson(aliasJson);

        // Normalize a storage account
        var inputJson = registry.NormalizeAndWrap(StorageResource, "2024-03-01", "{}", "{}");
        Assert.IsNotNull(inputJson);

        var envelope = System.Text.Json.JsonDocument.Parse(inputJson!);
        var normalizedResourceJson = envelope.RootElement.GetProperty("resource").GetRawText();

        // Denormalize
        var denormalizedJson = registry.Denormalize(normalizedResourceJson, "2024-03-01");
        Assert.IsNotNull(denormalizedJson);

        // Re-normalize and compare
        var reInputJson = registry.NormalizeAndWrap(denormalizedJson!, "2024-03-01", "{}", "{}");
        var reEnvelope = System.Text.Json.JsonDocument.Parse(reInputJson!);
        var reNormalizedResourceJson = reEnvelope.RootElement.GetProperty("resource").GetRawText();

        Assert.AreEqual(
            normalizedResourceJson,
            reNormalizedResourceJson,
            "Storage account denormalize → re-normalize roundtrip should match");
    }
}
