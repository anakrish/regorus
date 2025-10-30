// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace Regorus.Tests;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Nodes;
using Microsoft.EntityFrameworkCore;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Regorus;

[TestClass]
public class RegorusTests
{
  public TestContext TestContext { get; set; } = default!;

  private void Log(string message)
  {
    if (message is null)
    {
      return;
    }

    TestContext?.WriteLine(message);
    Console.WriteLine(message);
  }

  [TestMethod]
  public void Basic_evaluation_succeeds()
  {
    using var engine = new Engine();
    engine.AddPolicy(
      "test.rego",
      "package test\nx = 1\nmessage = `Hello`");

    var result = engine.EvalRule("data.test.message");

    Assert.AreEqual("\"Hello\"", result);
  }

  [TestMethod]
  public void Evaluation_using_file_policies_succeeds()
  {
    using var engine = new Engine();
    engine.SetRegoV0(true);

    engine.AddPolicyFromFile("tests/aci/framework.rego");
    engine.AddPolicyFromFile("tests/aci/api.rego");
    engine.AddPolicyFromFile("tests/aci/policy.rego");
    engine.AddDataFromJsonFile("tests/aci/data.json");

    engine.SetInputFromJsonFile("tests/aci/input.json");
    var result = engine.EvalRule("data.framework.mount_overlay");

    var expected = """
{
  "allowed": true,
  "metadata": [
    {
      "action": "add",
      "key": "container0",
      "name": "matches",
      "value": [
        {
          "allow_elevated": true,
          "allow_stdio_access": false,
          "capabilities": {
            "ambient": [
              "CAP_SYS_ADMIN"
            ],
            "bounding": [
              "CAP_SYS_ADMIN"
            ],
            "effective": [
              "CAP_SYS_ADMIN"
            ],
            "inheritable": [
              "CAP_SYS_ADMIN"
            ],
            "permitted": [
              "CAP_SYS_ADMIN"
            ]
          },
          "command": [
            "rustc",
            "--help"
          ],
          "env_rules": [
            {
              "pattern": "PATH=/usr/local/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
              "required": true,
              "strategy": "string"
            },
            {
              "pattern": "RUSTUP_HOME=/usr/local/rustup",
              "required": true,
              "strategy": "string"
            },
            {
              "pattern": "CARGO_HOME=/usr/local/cargo",
              "required": true,
              "strategy": "string"
            },
            {
              "pattern": "RUST_VERSION=1.52.1",
              "required": true,
              "strategy": "string"
            },
            {
              "pattern": "TERM=xterm",
              "required": false,
              "strategy": "string"
            },
            {
              "pattern": "PREFIX_.+=.+",
              "required": false,
              "strategy": "re2"
            }
          ],
          "exec_processes": [
            {
              "command": [
                "top"
              ],
              "signals": []
            }
          ],
          "layers": [
            "fe84c9d5bfddd07a2624d00333cf13c1a9c941f3a261f13ead44fc6a93bc0e7a",
            "4dedae42847c704da891a28c25d32201a1ae440bce2aecccfa8e6f03b97a6a6c",
            "41d64cdeb347bf236b4c13b7403b633ff11f1cf94dbc7cf881a44d6da88c5156",
            "eb36921e1f82af46dfe248ef8f1b3afb6a5230a64181d960d10237a08cd73c79",
            "e769d7487cc314d3ee748a4440805317c19262c7acd2fdbdb0d47d2e4613a15c",
            "1b80f120dbd88e4355d6241b519c3e25290215c469516b49dece9cf07175a766"
          ],
          "mounts": [
            {
              "destination": "/container/path/one",
              "options": [
                "rbind",
                "rshared",
                "rw"
              ],
              "source": "sandbox:///host/path/one",
              "type": "bind"
            },
            {
              "destination": "/container/path/two",
              "options": [
                "rbind",
                "rshared",
                "ro"
              ],
              "source": "sandbox:///host/path/two",
              "type": "bind"
            }
          ],
          "no_new_privileges": true,
          "seccomp_profile_sha256": "",
          "signals": [],
          "user": {
            "group_idnames": [
              {
                "pattern": "",
                "strategy": "any"
              }
            ],
            "umask": "0022",
            "user_idname": {
              "pattern": "",
              "strategy": "any"
            }
          },
          "working_dir": "/home/user"
        }
      ]
    },
    {
      "action": "add",
      "key": "/run/gcs/c/container0/rootfs",
      "name": "overlayTargets",
      "value": true
    }
  ]
}
""";

    Assert.IsTrue(JsonNode.DeepEquals(JsonNode.Parse(expected), JsonNode.Parse(result!)), $"Actual: {result}");
  }

  [TestMethod]
  public void GetPolicyPackageNames_succeeds()
  {
    using var engine = new Engine();
    engine.AddPolicy(
      "test.rego",
      "package test\nx = 1\nmessage = `Hello`");

    engine.AddPolicy(
      "test.rego",
      "package test.nested.name\nx = 1\nmessage = `Hello`");

    var result = engine.GetPolicyPackageNames();
    var packageNames = JsonNode.Parse(result!);

    Assert.AreEqual("test", packageNames![0]["package_name"].ToString());
    Assert.AreEqual("test.nested.name", packageNames![1]["package_name"].ToString());
  }

  [TestMethod]
  public void GetPolicyParameters_succeeds()
  {
    using var engine = new Engine();
    engine.AddPolicy(
      "test.rego",
      "package test\n default parameters.a = 5\nparameters.b = 10\nx = 1\nmessage = `Hello`");

    var result = engine.GetPolicyParameters();
    var parameters = JsonNode.Parse(result!);

    Assert.AreEqual(1, parameters![0]["parameters"].AsArray().Count);
    Assert.AreEqual(1, parameters![0]["modifiers"].AsArray().Count);

    Assert.AreEqual("a", parameters![0]["parameters"][0]["name"].ToString());
    Assert.AreEqual("b", parameters![0]["modifiers"][0]["name"].ToString());
  }

  [TestMethod]
  public void Lazy_callback_schema_defers_linq_queries()
  {
    var typeName = $"OrderUser_{Guid.NewGuid():N}";
    var databaseName = Guid.NewGuid().ToString();
    var repository = new OrderRepository(databaseName, 1_000m, Log);

    repository.Seed(new[]
    {
      new OrderRecord { Id = 1, UserId = "alice", Amount = 1_200m },
      new OrderRecord { Id = 2, UserId = "alice", Amount = 75m },
      new OrderRecord { Id = 3, UserId = "bob", Amount = 90m },
    });

    LazySchema.RegisterCallbackSchema(
      typeName,
      new LazyCallbackField(
        "has_high_value_purchases",
        static (context, _, userData) =>
        {
          if (userData is not CallbackState state)
          {
            throw new InvalidOperationException("Expected callback state in user data.");
          }

          var userId = context.GetString("user_id");
          state.Logger($"[lazy-callback] Resolving has_high_value_purchases lazily for user '{userId}' using deferred LINQ query");
          var hasHighValue = state.Repository.HasHighValuePurchase(userId);
          state.Logger($"[lazy-callback] Deferred query result for '{userId}': {hasHighValue}");
          return Value.Bool(hasHighValue);
        },
        new CallbackState(repository, Log)));

    using var engine = new Engine();
    engine.AddPolicy(
      "orders.rego",
      "package decision\n" +
      "default allow := false\n" +
      "allow := true if { input.request.route == \"orders/read\" }\n" +
      "allow := true if { input.request.route == \"orders/refund\"\n  input.user.has_high_value_purchases == false }");

    bool Evaluate(string route, string userId)
    {
      Log($"[test] Evaluating route '{route}' for user '{userId}' (deferred query count = {repository.QueryCount})");

      using var typeId = TypeId.Create(typeName);
      using var context = new LazyContext();
      context.Insert("user_id", userId);

      using var lazyUser = LazyObject.Create(typeId, context);
      using var userValue = Value.FromLazyObject(lazyUser);

      using var request = Value.Object();
      request.ObjectInsert("route", Value.String(route));

      using var input = Value.Object();
      input.ObjectInsert("request", request);
      input.ObjectInsert("user", userValue);

      engine.SetInputValue(input);

      using var allow = engine.EvalRuleAsValue("data.decision.allow");
      var decision = allow.AsBool();
      Log($"[test] Decision for route '{route}', user '{userId}': {decision} (deferred query count = {repository.QueryCount})");
      return decision;
    }

    var readAllowed = Evaluate("orders/read", "alice");
    Assert.IsTrue(readAllowed);
    Assert.AreEqual(0, repository.QueryCount, "Lazy field should not be evaluated for read route.");

    var aliceRefundAllowed = Evaluate("orders/refund", "alice");
    Assert.IsFalse(aliceRefundAllowed);
    Assert.AreEqual(1, repository.QueryCount, "High-value check should run once for Alice refund.");

    var bobRefundAllowed = Evaluate("orders/refund", "bob");
    Assert.IsTrue(bobRefundAllowed);
    Assert.AreEqual(2, repository.QueryCount, "Repository queries should increment for each refund evaluation.");
  }

  [TestMethod]
  public void Lazy_callback_schema_tracks_field_access_and_supports_hydration()
  {
    static Value ResolveTrackedField(LazyCallbackContext context, string fieldName, object? userData)
    {
      if (userData is not FieldHydrationState state)
      {
        throw new InvalidOperationException("Expected FieldHydrationState in user data.");
      }

      var userId = context.GetString("user_id");
      var scopeId = context.GetString("scope_id");
      state.RecordRequest(scopeId, fieldName);

      if (state.TryGetResolved(userId, fieldName, out var resolved))
      {
        state.Logger($"[lazy-callback] Returning hydrated value for '{userId}.{fieldName}': {resolved}");
        return FieldHydrationState.CreateValue(resolved);
      }

      state.Logger($"[lazy-callback] Field '{userId}.{fieldName}' not yet hydrated; returning undefined");
      return Value.Undefined();
    }

    var typeName = $"CustomerProfile_{Guid.NewGuid():N}";
    var tracker = new FieldHydrationState(Log);

    LazySchema.RegisterCallbackSchema(
      typeName,
      new LazyCallbackField("profile_ready", ResolveTrackedField, tracker),
      new LazyCallbackField("trust_score", ResolveTrackedField, tracker));

    using var engine = new Engine();
    engine.AddPolicy(
      "customer_access.rego",
      "package customer.access\n" +
      "default allow := false\n" +
      "allow := true if {\n" +
      "  input.request.feature == \"account-overview\"\n" +
      "}\n" +
      "allow := true if {\n" +
      "  input.request.feature == \"premium-dashboard\"\n" +
      "  input.customer.profile.profile_ready\n" +
      "  input.customer.profile.trust_score >= 80\n" +
      "}");

    (bool Decision, string ScopeId) Evaluate(string feature, string userId)
    {
      Log($"[test] Evaluating feature '{feature}' for user '{userId}'");

      var scopeId = tracker.CreateScope(userId);

      using var typeId = TypeId.Create(typeName);
      using var context = new LazyContext();
      context.Insert("user_id", userId);
      context.Insert("scope_id", scopeId);

      using var lazyProfile = LazyObject.Create(typeId, context);

      using var request = Value.Object();
      request.ObjectInsert("feature", Value.String(feature));

      using var customer = Value.Object();
      using var profileValue = Value.FromLazyObject(lazyProfile);
      customer.ObjectInsert("profile", profileValue);

      using var input = Value.Object();
      input.ObjectInsert("request", request);
      input.ObjectInsert("customer", customer);

      engine.SetInputValue(input);

      using var allow = engine.EvalRuleAsValue("data.customer.access.allow");
      var decision = allow.AsBool();
      Log($"[test] Decision for '{feature}' and user '{userId}': {decision}");
      return (decision, scopeId);
    }

    var userId = "alice";

    var (overviewAllowed, overviewScope) = Evaluate("account-overview", userId);
    Assert.IsTrue(overviewAllowed, "Account overview should not require premium profile data.");
    Assert.AreEqual(0, tracker.GetMissingFields(overviewScope).Count, "No fields should be requested for account overview scenario.");
    tracker.CompleteScope(overviewScope);

    var feature = "premium-dashboard";

    var (firstAttempt, firstScope) = Evaluate(feature, userId);
    Assert.IsFalse(firstAttempt, "Policy should fail when required fields are undefined.");

    var missingFields = tracker.GetMissingFields(firstScope).ToList();
    CollectionAssert.AreEquivalent(new[] { "profile_ready" }, missingFields);
    tracker.CompleteScope(firstScope);

    Log($"[test] Hydrating profile readiness for '{userId}'");
    tracker.SetResolved(userId, "profile_ready", true);

    var (secondAttempt, secondScope) = Evaluate(feature, userId);
    Assert.IsFalse(secondAttempt, "Policy should still fail until trust score is available.");

    var missingAfterProfile = tracker.GetMissingFields(secondScope).ToList();
    CollectionAssert.AreEquivalent(new[] { "trust_score" }, missingAfterProfile);
    tracker.CompleteScope(secondScope);

    Log($"[test] Hydrating trust score for '{userId}'");
    tracker.SetResolved(userId, "trust_score", 92);

    var (finalAttempt, finalScope) = Evaluate(feature, userId);
    Assert.IsTrue(finalAttempt, "Policy should succeed after all requested fields are hydrated.");

    Assert.AreEqual(0, tracker.GetMissingFields(finalScope).Count, "All requested fields should be satisfied after the final evaluation.");
    tracker.CompleteScope(finalScope);
  }

  private sealed class OrdersDbContext : DbContext
  {
    public OrdersDbContext(DbContextOptions<OrdersDbContext> options)
      : base(options)
    {
    }

    public DbSet<OrderRecord> Orders => Set<OrderRecord>();
  }

  private sealed class OrderRecord
  {
    public int Id { get; set; }
    public string UserId { get; set; } = string.Empty;
    public decimal Amount { get; set; }
  }

  private sealed class OrderRepository
  {
    private readonly DbContextOptions<OrdersDbContext> _options;
    private readonly decimal _threshold;
    private readonly Action<string> _log;

    public OrderRepository(string databaseName, decimal threshold, Action<string> log)
    {
      _threshold = threshold;
      _log = log ?? (_ => { });
      _options = new DbContextOptionsBuilder<OrdersDbContext>()
        .UseInMemoryDatabase(databaseName)
        .Options;
    }

    public int QueryCount { get; private set; }

    public void Seed(IEnumerable<OrderRecord> records)
    {
      using var context = new OrdersDbContext(_options);
      context.Database.EnsureDeleted();
      context.Database.EnsureCreated();
      context.Orders.AddRange(records);
      context.SaveChanges();
      QueryCount = 0;
    }

    public bool HasHighValuePurchase(string userId)
    {
      QueryCount++;
      _log($"[repo] Executing deferred LINQ query #{QueryCount} for '{userId}': Orders.Any(o => o.UserId == {userId} && o.Amount >= {_threshold})");
      using var context = new OrdersDbContext(_options);
      return context.Orders.Any(o => o.UserId == userId && o.Amount >= _threshold);
    }
  }

  private sealed class CallbackState
  {
    public CallbackState(OrderRepository repository, Action<string> logger)
    {
      Repository = repository ?? throw new ArgumentNullException(nameof(repository));
      Logger = logger ?? (_ => { });
    }

    public OrderRepository Repository { get; }

    public Action<string> Logger { get; }
  }

  private sealed class FieldHydrationState
  {
    private sealed class ScopeInfo
    {
      public ScopeInfo(string userId)
      {
        UserId = userId;
      }

      public string UserId { get; }

      public HashSet<string> Requested { get; } = new(StringComparer.Ordinal);
    }

    private readonly object _sync = new();
    private readonly Dictionary<string, ScopeInfo> _scopes = new(StringComparer.Ordinal);
    private readonly Dictionary<string, Dictionary<string, object>> _resolved = new(StringComparer.Ordinal);

    public FieldHydrationState(Action<string> logger)
    {
      Logger = logger ?? (_ => { });
    }

    public Action<string> Logger { get; }

    public string CreateScope(string userId)
    {
      if (userId is null)
      {
        throw new ArgumentNullException(nameof(userId));
      }

      var scopeId = $"{userId}:{Guid.NewGuid():N}";

      lock (_sync)
      {
        _scopes[scopeId] = new ScopeInfo(userId);
      }

      return scopeId;
    }

    public void CompleteScope(string scopeId)
    {
      if (scopeId is null)
      {
        throw new ArgumentNullException(nameof(scopeId));
      }

      lock (_sync)
      {
        _scopes.Remove(scopeId);
      }
    }

    public void RecordRequest(string scopeId, string fieldName)
    {
      if (scopeId is null)
      {
        throw new ArgumentNullException(nameof(scopeId));
      }

      if (fieldName is null)
      {
        throw new ArgumentNullException(nameof(fieldName));
      }

      lock (_sync)
      {
        if (!_scopes.TryGetValue(scopeId, out var scope))
        {
          throw new InvalidOperationException($"Scope '{scopeId}' is not registered.");
        }

        scope.Requested.Add(fieldName);
      }
    }

    public bool TryGetResolved(string userId, string fieldName, out object value)
    {
      if (userId is null)
      {
        throw new ArgumentNullException(nameof(userId));
      }

      if (fieldName is null)
      {
        throw new ArgumentNullException(nameof(fieldName));
      }

      lock (_sync)
      {
        if (_resolved.TryGetValue(userId, out var fields) && fields.TryGetValue(fieldName, out var resolved))
        {
          value = resolved;
          return true;
        }
      }

      value = default!;
      return false;
    }

    public void SetResolved(string userId, string fieldName, object value)
    {
      if (userId is null)
      {
        throw new ArgumentNullException(nameof(userId));
      }

      if (fieldName is null)
      {
        throw new ArgumentNullException(nameof(fieldName));
      }

      if (value is null)
      {
        throw new ArgumentNullException(nameof(value));
      }

      lock (_sync)
      {
        if (!_resolved.TryGetValue(userId, out var fields))
        {
          fields = new Dictionary<string, object>(StringComparer.Ordinal);
          _resolved[userId] = fields;
        }

        fields[fieldName] = value;
      }
    }

    public void SetResolved(string userId, IDictionary<string, object> values)
    {
      if (values is null)
      {
        throw new ArgumentNullException(nameof(values));
      }

      foreach (var kvp in values)
      {
        SetResolved(userId, kvp.Key, kvp.Value);
      }
    }

    public IReadOnlyCollection<string> GetMissingFields(string scopeId)
    {
      if (scopeId is null)
      {
        throw new ArgumentNullException(nameof(scopeId));
      }

      lock (_sync)
      {
        if (!_scopes.TryGetValue(scopeId, out var scope) || scope.Requested.Count == 0)
        {
          return Array.Empty<string>();
        }

        if (!_resolved.TryGetValue(scope.UserId, out var resolved) || resolved.Count == 0)
        {
          return scope.Requested.ToArray();
        }

        var missing = new List<string>();
        foreach (var field in scope.Requested)
        {
          if (!resolved.ContainsKey(field))
          {
            missing.Add(field);
          }
        }

        return missing;
      }
    }

    public static Value CreateValue(object value)
    {
      return value switch
      {
        bool b => Value.Bool(b),
        int i => Value.Int(i),
        long l => Value.Int(l),
        double d => Value.Float(d),
        decimal m => Value.Float((double)m),
        string s => Value.String(s),
        _ => throw new InvalidOperationException($"Unsupported resolved value type: {value.GetType()}"),
      };
    }
  }

  private sealed class FunctionCallHydrationState
  {
    public sealed record FunctionCallRequest(string FieldName, string Parameters, bool Resolved);

    public sealed class ShippingOption
    {
      public ShippingOption(string service, double cost)
      {
        Service = service ?? throw new ArgumentNullException(nameof(service));
        Cost = cost;
      }

      public string Service { get; }

      public double Cost { get; }
    }

    public sealed class FunctionCallResult
    {
      public FunctionCallResult(string selectedService, IReadOnlyList<ShippingOption> options)
      {
        if (string.IsNullOrWhiteSpace(selectedService))
        {
          throw new ArgumentException("Selected service must be provided.", nameof(selectedService));
        }

        SelectedService = selectedService;
        Options = options ?? throw new ArgumentNullException(nameof(options));
        if (Options.Count == 0)
        {
          throw new ArgumentException("At least one option must be supplied.", nameof(options));
        }

        JsonPayload = System.Text.Json.JsonSerializer.Serialize(new
        {
          selected_service = SelectedService,
          options = Options.Select(static option => new { service = option.Service, cost = option.Cost }),
        });
      }

      public string SelectedService { get; }

      public IReadOnlyList<ShippingOption> Options { get; }

      public string JsonPayload { get; }
    }

    private sealed class ScopeInfo
    {
      public ScopeInfo(string orderId)
      {
        OrderId = orderId;
      }

      public string OrderId { get; }

      public List<FunctionCallRequest> Requests { get; } = new();
    }

    private readonly object _sync = new();
    private readonly Dictionary<string, ScopeInfo> _scopes = new(StringComparer.Ordinal);
    private readonly Dictionary<string, FunctionCallResult> _resolved = new(StringComparer.Ordinal);

    public FunctionCallHydrationState(Action<string> logger)
    {
      Logger = logger ?? (_ => { });
    }

    public Action<string> Logger { get; }

    public string CreateScope(string orderId)
    {
      if (orderId is null)
      {
        throw new ArgumentNullException(nameof(orderId));
      }

      var scopeId = $"{orderId}:scope:{Guid.NewGuid():N}";

      lock (_sync)
      {
        _scopes[scopeId] = new ScopeInfo(orderId);
      }

      return scopeId;
    }

    public void CompleteScope(string scopeId)
    {
      if (scopeId is null)
      {
        throw new ArgumentNullException(nameof(scopeId));
      }

      lock (_sync)
      {
        _scopes.Remove(scopeId);
      }
    }

    public void RecordCall(string orderId, string scopeId, string fieldName, string parameters, bool resolved)
    {
      if (orderId is null)
      {
        throw new ArgumentNullException(nameof(orderId));
      }

      if (scopeId is null)
      {
        throw new ArgumentNullException(nameof(scopeId));
      }

      if (fieldName is null)
      {
        throw new ArgumentNullException(nameof(fieldName));
      }

      if (parameters is null)
      {
        throw new ArgumentNullException(nameof(parameters));
      }

      lock (_sync)
      {
        if (!_scopes.TryGetValue(scopeId, out var scope))
        {
          throw new InvalidOperationException($"Scope '{scopeId}' is not registered.");
        }

        scope.Requests.Add(new FunctionCallRequest(fieldName, parameters, resolved));
      }
    }

    public IReadOnlyCollection<FunctionCallRequest> GetPendingCalls(string scopeId)
    {
      if (scopeId is null)
      {
        throw new ArgumentNullException(nameof(scopeId));
      }

      lock (_sync)
      {
        if (!_scopes.TryGetValue(scopeId, out var scope) || scope.Requests.Count == 0)
        {
          return Array.Empty<FunctionCallRequest>();
        }

        var pending = scope.Requests.Where(static request => !request.Resolved).ToArray();
        return pending.Length == 0 ? Array.Empty<FunctionCallRequest>() : pending;
      }
    }

    public bool TryGetResolved(string orderId, out FunctionCallResult result)
    {
      if (orderId is null)
      {
        throw new ArgumentNullException(nameof(orderId));
      }

      lock (_sync)
      {
        return _resolved.TryGetValue(orderId, out result!);
      }
    }

    public void SetResult(string orderId, FunctionCallResult result)
    {
      if (orderId is null)
      {
        throw new ArgumentNullException(nameof(orderId));
      }

      if (result is null)
      {
        throw new ArgumentNullException(nameof(result));
      }

      lock (_sync)
      {
        _resolved[orderId] = result;
      }
    }

    public FunctionCallResult? GetResolvedResult(string orderId)
    {
      if (orderId is null)
      {
        throw new ArgumentNullException(nameof(orderId));
      }

      lock (_sync)
      {
        return _resolved.TryGetValue(orderId, out var result) ? result : null;
      }
    }
  }
}
