// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// ------------------------------------------------------------

namespace Microsoft.WindowsAzure.Governance.Policy.Provider.Components.Copilot.PolicyCopilotServiceDelegates
{
    using System;
    using System.Collections.Generic;
    using System.Globalization;
    using System.Linq;
    using System.Text;
    using System.Text.RegularExpressions;
    using Microsoft.WindowsAzure.Governance.Activity; // Added for Activity logging
    using Microsoft.WindowsAzure.Governance.Policy.Common.Configuration;
    using Microsoft.Z3;
    using Newtonsoft.Json.Linq;

    /// <summary>
    /// Converts Azure Policy JSON conditions/expressions into Z3 expressions and performs logical comparisons between policies.
    /// </summary>
    public class PolicyToZ3 : IDisposable
    {
        /// <summary>
        /// String constant representing exact equality relationship between two policies.
        /// </summary>
        public static readonly string ExactEquals = "===";

        /// <summary>
        /// String constant representing logical equivalence relationship between two policies.
        /// </summary>
        public static readonly string LogicalEquivalence = "<=>";

        /// <summary>
        /// String constant representing that the comparison timed out.
        /// </summary>
        public static readonly string Timeout = "timeout";

        /// <summary>
        /// String constant representing that the first policy implies the second.
        /// </summary>
        public static readonly string Implies = "=>";

        /// <summary>
        /// String constant representing that the first policy is implied by the second.
        /// </summary>
        public static readonly string ImpliedBy = "<=";

        /// <summary>
        /// String constant representing that the policies are not equal.
        /// </summary>
        public static readonly string NotEqual = "=/=";

        /// <summary>
        /// String constant representing that the first policy implies the second regarding location.
        /// </summary>
        public static readonly string ImpliesLocation = "=>location";

        /// <summary>
        /// String constant representing that the first policy implies the second regarding type.
        /// </summary>
        public static readonly string ImpliesType = "=>type";

        /// <summary>
        /// String constant representing that the first policy is implied by the second regarding location.
        /// </summary>
        public static readonly string ImpliedByLocation = "<=location";

        /// <summary>
        /// String constant representing that the first policy is implied by the second regarding type.
        /// </summary>
        public static readonly string ImpliedByType = "<=type";

        /// <summary>
        /// String constant suffix for location-only comparison.
        /// </summary>
        public static readonly string LocationOnlySuffix = "location-only";

        /// <summary>
        /// String constant suffix for type-only comparison.
        /// </summary>
        public static readonly string TypeOnlySuffix = "type-only";

        /// <summary>
        /// Gets the number of policies to attempt to generate to compare and find a consensus.
        /// </summary>
        private static readonly int timeoutMs = CachedCloudConfigurationManager.GetConfigurationNumber(
            "Microsoft.WindowsAzure.Governance.Policy.Provider.PolicyToZ3.TimeoutMs",
            defaultValue: 500);

        private readonly Context Z3;
        private readonly Dictionary<string, string> VariableCaseNormalize;
        private readonly HashSet<FuncDecl> CountFunctions;
        private static readonly Regex IntegerRegex = new("^\\d+$", RegexOptions.Compiled);
        private static readonly Regex ArrayRegex = new("^\\[.*\\]$", RegexOptions.Compiled);
        private static readonly Regex LengthFieldRegex = new("^length\\(field\\('.+'\\)\\)$", RegexOptions.Compiled);
        private static readonly Regex ParametersRegex = new("^parameters\\('.+'\\)$", RegexOptions.Compiled);
        private readonly FuncDecl Meet;
        private readonly FuncDecl Join;
        private readonly FuncDecl CountAll;

        /// <summary>
        /// Delegate representing a conversion from a JSON condition node to a Z3 BoolExpr.
        /// </summary>
        private delegate BoolExpr ConditionConverter(JToken cond, JToken value, string context, string label, Activity parentActivity);

        /// <summary>
        /// Delegate representing a conversion from a JSON expression node to a Z3 Expr of a given sort.
        /// </summary>
        private delegate Expr ExpressionConverter(JToken exp, JToken sort, string context, Activity parentActivity);

        /// <summary>
        /// Delegate representing lifting a set of arithmetic expressions into a single arithmetic expression for counting semantics.
        /// </summary>
        private delegate ArithExpr LiftFunction(IReadOnlyList<ArithExpr> args, Expr contextExpr);

        private readonly Dictionary<string, ConditionConverter> ConditionConverters;
        private readonly Dictionary<string, ExpressionConverter> ExpressionConverters;
        private readonly Dictionary<string, LiftFunction> ConditionLifters;

        /// <summary>
        /// Constructor initializing Z3 context and conversion mappings.
        /// </summary>
        public PolicyToZ3()
        {
            this.Z3 = new Context();
            this.VariableCaseNormalize = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            this.CountFunctions = new HashSet<FuncDecl>();
            this.Meet = this.Z3.MkFuncDecl("meet", new[] { this.Z3.IntSort, this.Z3.IntSort }, this.Z3.IntSort);
            this.Join = this.Z3.MkFuncDecl("join", new[] { this.Z3.IntSort, this.Z3.IntSort }, this.Z3.IntSort);
            this.CountAll = this.Z3.MkFuncDecl("count-all", this.Z3.StringSort, this.Z3.IntSort);

            this.ConditionConverters = new Dictionary<string, ConditionConverter>(StringComparer.OrdinalIgnoreCase)
            {
                { "allOf", this.ConvertAnd },
                { "anyOf", this.ConvertOr },
                { "not", this.ConvertNot },
                { "equals", this.ConvertEquals },
                { "notEquals", this.ConvertNotEquals },
                { "like", this.ConvertLike },
                { "notLike", this.ConvertNotLike },
                { "match", this.ConvertMatch },
                { "notMatch", this.ConvertNotMatch },
                { "in", this.ConvertIn },
                { "notIn", this.ConvertNotIn },
                { "exists", this.ConvertExists },
                { "contains", this.ConvertContains },
                { "notContains", this.ConvertNotContains },
                { "containsKey", this.ConvertContainsKey },
                { "notContainsKey", this.ConvertNotContainsKey },
                { "greaterOrEquals", this.ConvertGreaterOrEquals },
                { "greater", this.ConvertGreater },
                { "lessOrEquals", this.ConvertLessOrEquals },
                { "less", this.ConvertLess }
            };

            this.ExpressionConverters = new Dictionary<string, ExpressionConverter>(StringComparer.OrdinalIgnoreCase)
            {
                { "count", this.ConvertCount },
                { "field", this.GetFieldAttribute },
                { "value", this.GetFieldAttribute }
            };

            this.ConditionLifters = new Dictionary<string, LiftFunction>(StringComparer.OrdinalIgnoreCase)
            {
                { "and", this.LiftAnd },
                { "or", this.LiftOr },
                { "not", this.LiftNot }
            };
        }

        /// <inheritdoc/>
        public void Dispose()
        {
            this.Meet?.Dispose();
            this.Join?.Dispose();
            this.CountAll?.Dispose();

            if (this.CountFunctions != null)
            {
                foreach (var func in this.CountFunctions)
                {
                    func.Dispose();
                }
                this.CountFunctions.Clear();
            }

            this.Z3?.Dispose();
        }

        /// <summary>
        /// Compares two policies to determine logical relationships between their if conditions.
        /// </summary>
        /// <param name="policyIf1">First policy rule if json</param>
        /// <param name="policyIf2">Second policy rule if json</param>
        /// <param name="parentActivity">Parent parentActivity for logging instrumentation.</param>
        public static string Discriminate(JObject policyIf1, JObject policyIf2, Activity parentActivity)
        {
            using var instance = new PolicyToZ3();
            return instance.DiscriminateInternal(policyIf1, policyIf2, parentActivity);
        }

        private string DiscriminateInternal(JObject policyIf1, JObject policyIf2, Activity parentActivity)
        {
            if (JObject.DeepEquals(policyIf1, policyIf2))
            {
                return PolicyToZ3.ExactEquals;
            }

            this.CountFunctions.Clear();
            var expr1 = this.ConvertCond(cond: policyIf1, context: "", label: "", parentActivity: parentActivity);
            var expr2 = this.ConvertCond(cond: policyIf2, context: "", label: "", parentActivity: parentActivity);

            Status r1, r2;

            using (var solver = CreateSolverWithCountAssumptions())
            {
                solver.Push();
                solver.Add(this.Z3.MkAnd(expr1, this.Z3.MkNot(expr2)));
                r1 = this.InvokeSmt(solver: solver, parentActivity: parentActivity);
                solver.Pop();

                solver.Push();
                solver.Add(this.Z3.MkAnd(expr2, this.Z3.MkNot(expr1)));
                r2 = this.InvokeSmt(solver: solver, parentActivity: parentActivity);
                solver.Pop();
            }

            if (r1 == Status.UNKNOWN || r2 == Status.UNKNOWN)
            {
                return PolicyToZ3.Timeout;
            }

            if (r1 == Status.UNSATISFIABLE && r2 == Status.UNSATISFIABLE)
            {
                return PolicyToZ3.LogicalEquivalence;
            }

            if (r1 == Status.UNSATISFIABLE && r2 == Status.SATISFIABLE)
            {
                if (this.CheckLabelImplication(left: policyIf1, right: policyIf2, label: "location", parentActivity: parentActivity))
                {
                    return PolicyToZ3.ImpliesLocation;
                }

                if (this.CheckLabelImplication(left: policyIf1, right: policyIf2, label: "type", parentActivity: parentActivity))
                {
                    return PolicyToZ3.ImpliesType;
                }

                return PolicyToZ3.Implies;
            }

            if (r1 == Status.SATISFIABLE && r2 == Status.UNSATISFIABLE)
            {
                if (this.CheckLabelImplication(left: policyIf2, right: policyIf1, label: "location", parentActivity: parentActivity))
                {
                    return PolicyToZ3.ImpliedByLocation;
                }

                if (this.CheckLabelImplication(left: policyIf2, right: policyIf1, label: "type", parentActivity: parentActivity))
                {
                    return PolicyToZ3.ImpliedByType;
                }

                return PolicyToZ3.ImpliedBy;
            }

            var locationOnly = this.CompareLabelOnly(left: policyIf1, right: policyIf2, label: "location", parentActivity: parentActivity);
            if (!string.IsNullOrEmpty(locationOnly))
            {
                return string.Concat(locationOnly, PolicyToZ3.LocationOnlySuffix);
            }

            var typeOnly = this.CompareLabelOnly(left: policyIf1, right: policyIf2, label: "type", parentActivity: parentActivity);
            if (!string.IsNullOrEmpty(typeOnly))
            {
                return string.Concat(typeOnly, PolicyToZ3.TypeOnlySuffix);
            }

            return PolicyToZ3.NotEqual;
        }

        /// <summary>
        /// Converts a JSON condition object to a Z3 boolean expression recursively.
        /// </summary>
        /// <param name="cond">The JSON token representing the condition.</param>
        /// <param name="context">Context string used for relative field name trimming.</param>
        /// <param name="label">Optional label used for special label-only evaluation.</param>
        /// <param name="parentActivity">The parent activity</param>
        /// <returns>Z3 BoolExpr representing the condition.</returns>
        internal BoolExpr ConvertCond(JToken cond, string context, string label, Activity parentActivity)
        {
            var methodMonitor = ActivityMonitorFactory.Instance.CreateActivityMonitor(
               activityName: "PolicyToZ3.ConvertCond",
               parentActivity: parentActivity,
               inheritParentProperties: false);
            methodMonitor.OnStart();

            if (cond is not JObject obj)
            {
                methodMonitor.Activity["PolicyToZ3.Warn"] = $"cond not handled non-object token: {cond}";
                methodMonitor.OnCompleted();
                return this.Z3.MkTrue();
            }

            foreach (var property in obj.Properties())
            {
                if (this.ConditionConverters.TryGetValue(property.Name, out var converter))
                {
                    methodMonitor.OnCompleted();
                    return converter(cond: cond, value: property.Value, context: context, label: label, parentActivity: parentActivity);
                }
            }

            methodMonitor.Activity["PolicyToZ3.Warn"] = $"cond not handled (no recognized operator): {cond}";
            methodMonitor.OnCompleted();
            return this.Z3.MkTrue();
        }

        /// <summary>
        /// Converts a JSON expression node to a Z3 expression based on its type (count, field, value).
        /// </summary>
        /// <param name="exp">Expression JSON token.</param>
        /// <param name="sort">Token providing sort or value context.</param>
        /// <param name="context">Field context for trimming prefixes.</param>
        /// <param name="parentActivity">The parent activity</param>
        /// <returns>Z3 expression or Not Yet Implemented(NYI) sentinel.</returns>
        internal Expr ConvertExp(JToken exp, JToken sort, string context, Activity parentActivity)
        {
            var methodMonitor = ActivityMonitorFactory.Instance.CreateActivityMonitor(
                activityName: "PolicyToZ3.ConvertExp",
                parentActivity: parentActivity,
                inheritParentProperties: false);
            methodMonitor.OnStart();

            if (exp is not JObject obj)
            {
                methodMonitor.Activity["PolicyToZ3.Warn"] = $"expression not handled non-object token: {exp}";
                methodMonitor.OnCompleted();
                return this.Z3.MkString("NYI");
            }

            foreach (var property in obj.Properties())
            {
                if (this.ExpressionConverters.TryGetValue(property.Name, out var converter))
                {
                    var sortToken = property.Name.Equals("count", StringComparison.OrdinalIgnoreCase) ? property.Value : sort;
                    methodMonitor.OnCompleted();
                    return converter(exp: exp, sort: sortToken, context: context, parentActivity: parentActivity);
                }
            }

            methodMonitor.Activity["PolicyToZ3.Warn"] = $"expression not handled (no recognized operator): {exp}";
            methodMonitor.OnCompleted();
            return this.Z3.MkString("NYI");
        }

        /// <summary>
        /// Creates a solver instance and injects general count assumptions for cardinality functions.
        /// </summary>
        /// <returns>Configured Z3 solver.</returns>
        internal Solver CreateSolverWithCountAssumptions()
        {
            var solver = this.Z3.MkSolver();
            var x = this.Z3.MkConst("x", this.Z3.StringSort);
            solver.Add(this.Z3.MkForall(new[] { x }, this.Z3.MkGe((ArithExpr)this.Z3.MkApp(CountAll, x), this.Z3.MkInt(0))));

            foreach (var func in this.CountFunctions)
            {
                var varName = this.Z3.MkConst($"x_{func.Name}", this.Z3.StringSort);
                var app = (ArithExpr)this.Z3.MkApp(func, varName);
                var constraint = this.Z3.MkAnd(
                    this.Z3.MkGe(app, this.Z3.MkInt(0)),
                    this.Z3.MkLe(app, (ArithExpr)this.Z3.MkApp(CountAll, varName)));
                solver.Add(this.Z3.MkForall(new[] { varName }, constraint));
            }

            return solver;
        }

        /// <summary>
        /// Determines whether right implies left for a specific label-only comparison context.
        /// </summary>
        /// <param name="left">Left policy JSON object.</param>
        /// <param name="right">Right policy JSON object.</param>
        /// <param name="label">Label name (e.g., location, type).</param>
        /// <param name="parentActivity">The parent activity</param>
        /// <returns>True if implication holds under the label context.</returns>
        internal bool CheckLabelImplication(JObject left, JObject right, string label, Activity parentActivity)
        {
            var exprLeft = this.ConvertCond(cond: left, context: "", label: label, parentActivity: parentActivity);
            var exprRight = this.ConvertCond(cond: right, context: "", label: label, parentActivity: parentActivity);
            using (var solver = this.CreateSolverWithCountAssumptions())
            {
                solver.Add(this.Z3.MkAnd(exprRight, this.Z3.MkNot(exprLeft)));
                return this.InvokeSmt(solver: solver, parentActivity: parentActivity) == Status.UNSATISFIABLE;
            }
        }

        /// <summary>
        /// Compares two policies using only a specific label context and returns relationship symbol.
        /// </summary>
        /// <param name="left">Left policy JSON.</param>
        /// <param name="right">Right policy JSON.</param>
        /// <param name="label">Label to isolate.</param>
        /// <param name="parentActivity">The parent activity</param>
        /// <returns>Relationship symbol or null if incomparable.</returns>
        internal string CompareLabelOnly(JObject left, JObject right, string label, Activity parentActivity)
        {
            var exprLeft = this.ConvertCond(cond: left, context: "", label: label, parentActivity: parentActivity);
            var exprRight = this.ConvertCond(cond: right, context: "", label: label, parentActivity: parentActivity);

            Status r1, r2;

            using (var solver = this.CreateSolverWithCountAssumptions())
            {
                solver.Push();
                solver.Add(this.Z3.MkAnd(exprLeft, this.Z3.MkNot(exprRight)));
                r1 = this.InvokeSmt(solver: solver, parentActivity: parentActivity);
                solver.Pop();

                solver.Push();
                solver.Add(this.Z3.MkAnd(exprRight, this.Z3.MkNot(exprLeft)));
                r2 = this.InvokeSmt(solver: solver, parentActivity: parentActivity);
                solver.Pop();
            }

            if (r1 == Status.UNKNOWN || r2 == Status.UNKNOWN)
            {
                return PolicyToZ3.Timeout;
            }

            if (r1 == Status.UNSATISFIABLE && r2 == Status.UNSATISFIABLE)
            {
                return PolicyToZ3.LogicalEquivalence;
            }

            if (r1 == Status.UNSATISFIABLE && r2 == Status.SATISFIABLE)
            {
                return PolicyToZ3.Implies;
            }

            if (r1 == Status.SATISFIABLE && r2 == Status.UNSATISFIABLE)
            {
                return PolicyToZ3.ImpliedBy;
            }

            return null;
        }

        /// <summary>
        /// Executes the SMT solver, applying timeout parameters if configured.
        /// </summary>
        /// <param name="solver">Solver instance to check.</param>
        /// <param name="parentActivity">The parent activity</param>
        /// <returns>Status of the solver check (SAT/UNSAT/UNKNOWN).</returns>
        internal Status InvokeSmt(Solver solver, Activity parentActivity)
        {
            var methodMonitor = ActivityMonitorFactory.Instance.CreateActivityMonitor(
                activityName: "PolicyToZ3.InvokeSmt",
                parentActivity: parentActivity,
                inheritParentProperties: false);
            methodMonitor.OnStart();

            var parameters = this.Z3.MkParams();
            _ = parameters.Add("timeout", (uint)timeoutMs);
            solver.Parameters = parameters;

            var result = solver.Check();
            if (result == Status.UNKNOWN)
            {
                methodMonitor.Activity["PolicyToZ3.Warn"] = $"Timeout for solver query: {solver}";
            }

            methodMonitor.OnCompleted();
            return result;
        }

        /// <summary>
        /// Returns or creates a normalized case string constant for a given field name.
        /// </summary>
        /// <param name="value">Original field or value string.</param>
        /// <returns>Z3 string expression representing the canonical variable name.</returns>
        private SeqExpr StringVar(string value)
        {
            if (string.IsNullOrEmpty(value))
            {
                value = "__empty";
            }

            var key = value.ToLowerInvariant();
            if (!this.VariableCaseNormalize.TryGetValue(key, out var canonical))
            {
                canonical = value;
                this.VariableCaseNormalize[key] = canonical;
            }

            return (SeqExpr)this.Z3.MkConst(canonical, this.Z3.StringSort);
        }

        /// <summary>
        /// Converts an allOf JSON condition (logical AND) to a BoolExpr.
        /// </summary>
        /// <param name="cond">Parent condition token.</param>
        /// <param name="value">Array of child conditions.</param>
        /// <param name="context">Field context.</param>
        /// <param name="label">Label-only evaluation marker.</param>
        /// <param name="parentActivity">The parent activity</param>
        /// <returns>Conjunction BoolExpr.</returns>
        private BoolExpr ConvertAnd(JToken cond, JToken value, string context, string label, Activity parentActivity)
        {
            var parts = value.Children().Select(child => this.ConvertCond(cond: child, context: context, label: label, parentActivity: parentActivity)).ToArray();
            return parts.Length == 1 ? parts[0] : this.Z3.MkAnd(parts);
        }

        /// <summary>
        /// Converts an anyOf JSON condition (logical OR) to a BoolExpr.
        /// </summary>
        /// <param name="cond">Parent condition token.</param>
        /// <param name="value">Array of child conditions.</param>
        /// <param name="context">Field context.</param>
        /// <param name="label">Label-only evaluation marker.</param>
        /// <param name="parentActivity">The parent activity</param>
        /// <returns>Disjunction BoolExpr.</returns>
        private BoolExpr ConvertOr(JToken cond, JToken value, string context, string label, Activity parentActivity)
        {
            var parts = value.Children().Select(child => this.ConvertCond(cond: child, context: context, label: label, parentActivity: parentActivity)).ToArray();
            return parts.Length == 1 ? parts[0] : this.Z3.MkOr(parts);
        }

        /// <summary>
        /// Converts a not JSON condition to its negated BoolExpr.
        /// </summary>
        /// <param name="cond">Parent condition token.</param>
        /// <param name="value">Child condition to negate.</param>
        /// <param name="context">Field context.</param>
        /// <param name="label">Label-only evaluation marker.</param>
        /// <param name="parentActivity">The parent activity</param>
        /// <returns>Negated BoolExpr.</returns>
        private BoolExpr ConvertNot(JToken cond, JToken value, string context, string label, Activity parentActivity)
            => this.Z3.MkNot(this.ConvertCond(cond: value, context: context, label: label, parentActivity: parentActivity));

        /// <summary>
        /// Converts an equals JSON condition to a BoolExpr comparing two expressions.
        /// </summary>
        /// <param name="cond">Condition token containing field/value.</param>
        /// <param name="value">Value token for comparison.</param>
        /// <param name="context">Field context.</param>
        /// <param name="label">Label-only evaluation marker.</param>
        /// <param name="parentActivity">The parent activity</param>
        /// <returns>Equality BoolExpr.</returns>
        private BoolExpr ConvertEquals(JToken cond, JToken value, string context, string label, Activity parentActivity)
            => this.ConvertEqualsBase(cond: cond, value: value, context: context, label: label, parentActivity: parentActivity);

        /// <summary>
        /// Converts a notEquals JSON condition to a BoolExpr representing inequality.
        /// </summary>
        /// <param name="cond">Condition token.</param>
        /// <param name="value">Value token.</param>
        /// <param name="context">Field context.</param>
        /// <param name="label">Label-only evaluation marker.</param>
        /// <param name="parentActivity">The parent activity</param>
        /// <returns>Inequality BoolExpr.</returns>
        private BoolExpr ConvertNotEquals(JToken cond, JToken value, string context, string label, Activity parentActivity)
            => this.Z3.MkNot(this.ConvertEqualsBase(cond: cond, value: value, context: context, label: label, parentActivity: parentActivity));

        /// <summary>
        /// Converts a contains JSON condition to a BoolExpr asserting substring containment.
        /// </summary>
        /// <param name="cond">Condition token.</param>
        /// <param name="value">Substring token.</param>
        /// <param name="context">Field context.</param>
        /// <param name="label">Label-only evaluation marker.</param>
        /// <param name="parentActivity">The parent activity</param>
        /// <returns>Contains BoolExpr.</returns>
        private BoolExpr ConvertContains(JToken cond, JToken value, string context, string label, Activity parentActivity)
            => this.ConvertContainsBase(cond: cond, value: value, context: context, parentActivity: parentActivity);

        /// <summary>
        /// Converts a notContains JSON condition to a BoolExpr asserting absence of substring.
        /// </summary>
        /// <param name="cond">Condition token.</param>
        /// <param name="value">Substring token.</param>
        /// <param name="context">Field context.</param>
        /// <param name="label">Label-only evaluation marker.</param>
        /// <param name="parentActivity">The parent activity</param>
        /// <returns>Negated contains BoolExpr.</returns>
        private BoolExpr ConvertNotContains(JToken cond, JToken value, string context, string label, Activity parentActivity)
            => this.Z3.MkNot(this.ConvertContainsBase(cond: cond, value: value, context: context, parentActivity: parentActivity));

        /// <summary>
        /// Converts a containsKey JSON condition to BoolExpr for key presence modeling.
        /// </summary>
        /// <param name="cond">Condition token.</param>
        /// <param name="value">Key token.</param>
        /// <param name="context">Field context.</param>
        /// <param name="label">Label-only evaluation marker.</param>
        /// <param name="parentActivity">The parent activity</param>
        /// <returns>ContainsKey BoolExpr.</returns>
        private BoolExpr ConvertContainsKey(JToken cond, JToken value, string context, string label, Activity parentActivity)
            => this.ConvertContainsKeyBase(cond: cond, value: value, context: context, parentActivity: parentActivity);

        /// <summary>
        /// Converts a notContainsKey JSON condition to BoolExpr for key absence.
        /// </summary>
        /// <param name="cond">Condition token.</param>
        /// <param name="value">Key token.</param>
        /// <param name="context">Field context.</param>
        /// <param name="label">Label-only evaluation marker.</param>
        /// <param name="parentActivity">The parent activity</param>
        /// <returns>Negated containsKey BoolExpr.</returns>
        private BoolExpr ConvertNotContainsKey(JToken cond, JToken value, string context, string label, Activity parentActivity)
            => this.Z3.MkNot(this.ConvertContainsKeyBase(cond: cond, value: value, context: context, parentActivity: parentActivity));

        /// <summary>
        /// Converts an in JSON condition to a BoolExpr as a disjunction of equals comparisons.
        /// </summary>
        /// <param name="cond">Condition token.</param>
        /// <param name="values">Collection token.</param>
        /// <param name="context">Field context.</param>
        /// <param name="label">Label-only evaluation marker.</param>
        /// <param name="parentActivity">The parent activity</param>
        /// <returns>In BoolExpr.</returns>
        private BoolExpr ConvertIn(JToken cond, JToken values, string context, string label, Activity parentActivity)
            => this.ConvertInBase(cond: cond, values: values, context: context, label: label, parentActivity: parentActivity);

        /// <summary>
        /// Converts a notIn JSON condition to BoolExpr representing exclusion from collection.
        /// </summary>
        /// <param name="cond">Condition token.</param>
        /// <param name="values">Collection token.</param>
        /// <param name="context">Field context.</param>
        /// <param name="label">Label-only evaluation marker.</param>
        /// <param name="parentActivity">The parent activity</param>
        /// <returns>Negated in BoolExpr.</returns>
        private BoolExpr ConvertNotIn(JToken cond, JToken values, string context, string label, Activity parentActivity)
            => this.Z3.MkNot(this.ConvertInBase(cond: cond, values: values, context: context, label: label, parentActivity: parentActivity));

        /// <summary>
        /// Converts a like JSON condition (wildcard * semantics) to a BoolExpr using regex inclusion.
        /// </summary>
        /// <param name="cond">Condition token.</param>
        /// <param name="like">Pattern token.</param>
        /// <param name="context">Field context.</param>
        /// <param name="label">Label-only evaluation marker.</param>
        /// <param name="parentActivity">The parent activity</param>
        /// <returns>Like BoolExpr.</returns>
        private BoolExpr ConvertLike(JToken cond, JToken like, string context, string label, Activity parentActivity)
        {
            var field = (SeqExpr)this.GetFieldAttribute(node: cond, sort: like, context: context, parentActivity: parentActivity);
            var pattern = this.ConvertWildcardPattern(pattern: like.Value<string>() ?? like.ToString());
            return this.Z3.MkInRe(field, pattern);
        }

        /// <summary>
        /// Converts a notLike JSON condition to a BoolExpr asserting pattern mismatch.
        /// </summary>
        /// <param name="cond">Condition token.</param>
        /// <param name="like">Pattern token.</param>
        /// <param name="context">Field context.</param>
        /// <param name="label">Label-only evaluation marker.</param>
        /// <param name="parentActivity">The parent activity</param>
        /// <returns>Negated like BoolExpr.</returns>
        private BoolExpr ConvertNotLike(JToken cond, JToken like, string context, string label, Activity parentActivity)
        {
            var field = (SeqExpr)this.GetFieldAttribute(node: cond, sort: like, context: context, parentActivity: parentActivity);
            var pattern = this.ConvertWildcardPattern(pattern: like.Value<string>() ?? like.ToString());
            return this.Z3.MkNot(this.Z3.MkInRe(field, pattern));
        }

        /// <summary>
        /// Converts a match JSON condition (policy match semantics with ?,#,*,.) to BoolExpr using regex.
        /// </summary>
        /// <param name="cond">Condition token.</param>
        /// <param name="like">Pattern token.</param>
        /// <param name="context">Field context.</param>
        /// <param name="label">Label-only evaluation marker.</param>
        /// <param name="parentActivity">The parent activity</param>
        /// <returns>Match BoolExpr.</returns>
        private BoolExpr ConvertMatch(JToken cond, JToken like, string context, string label, Activity parentActivity)
        {
            var field = (SeqExpr)this.GetFieldAttribute(node: cond, sort: like, context: context, parentActivity: parentActivity);
            var pattern = this.ConvertMatchPattern(pattern: like.Value<string>() ?? like.ToString());
            return this.Z3.MkInRe(field, pattern);
        }

        /// <summary>
        /// Converts a notMatch JSON condition to BoolExpr asserting regex mismatch.
        /// </summary>
        /// <param name="cond">Condition token.</param>
        /// <param name="like">Pattern token.</param>
        /// <param name="context">Field context.</param>
        /// <param name="label">Label-only evaluation marker.</param>
        /// <param name="parentActivity">The parent activity</param>
        /// <returns>Negated match BoolExpr.</returns>
        private BoolExpr ConvertNotMatch(JToken cond, JToken like, string context, string label, Activity parentActivity)
        {
            var field = (SeqExpr)this.GetFieldAttribute(node: cond, sort: like, context: context, parentActivity: parentActivity);
            var pattern = this.ConvertMatchPattern(pattern: like.Value<string>() ?? like.ToString());
            return this.Z3.MkNot(this.Z3.MkInRe(field, pattern));
        }

        /// <summary>
        /// Converts an exists JSON condition to BoolExpr checking presence/absence of a field or value.
        /// </summary>
        /// <param name="cond">Condition token.</param>
        /// <param name="value">Boolean token specifying expected existence.</param>
        /// <param name="context">Field context.</param>
        /// <param name="label">Label-only evaluation marker.</param>
        /// <param name="parentActivity">The parent activity</param>
        /// <returns>Exists BoolExpr.</returns>
        private BoolExpr ConvertExists(JToken cond, JToken value, string context, string label, Activity parentActivity)
        {
            var methodMonitor = ActivityMonitorFactory.Instance.CreateActivityMonitor(
                activityName: "PolicyToZ3.ConvertExists",
                parentActivity: parentActivity,
                inheritParentProperties: false);
            methodMonitor.OnStart();

            string name = cond["field"]?.Value<string>();
            if (name == null && cond["value"] != null)
            {
                var raw = cond["value"]!.Value<string>() ?? cond["value"]!.ToString();
                if (raw.StartsWith("[field(", StringComparison.OrdinalIgnoreCase))
                {
                    name = raw[7..^2];
                }
            }

            if (name == null)
            {
                methodMonitor.Activity["PolicyToZ3.Z3.Warn"] = $"exists not handled (missing field/value): {cond}";
                methodMonitor.OnCompleted();
                return this.Z3.MkTrue();
            }

            name = name.ToLowerInvariant().Trim();
            if (name == context)
            {
                methodMonitor.OnCompleted();
                return this.Z3.MkBool(value.ToString().Equals("true", StringComparison.OrdinalIgnoreCase));
            }

            if (!string.IsNullOrEmpty(context) && name.StartsWith(context + ".", StringComparison.OrdinalIgnoreCase))
            {
                name = name[(context.Length + 1)..];
            }

            var field = this.StringVar(value: name);
            var valueString = value.Value<string>() ?? value.ToString();
            if (valueString.Equals("true", StringComparison.OrdinalIgnoreCase))
            {
                methodMonitor.OnCompleted();
                return this.Z3.MkNot(this.Z3.MkEq(field, this.Z3.MkString(string.Empty)));
            }

            if (valueString.Equals("false", StringComparison.OrdinalIgnoreCase))
            {
                methodMonitor.OnCompleted();
                return this.Z3.MkEq(field, this.Z3.MkString(string.Empty));
            }

            methodMonitor.Activity["PolicyToZ3.Warn"] = $"exists not handled (unexpected value token): {cond}";
            methodMonitor.OnCompleted();
            return this.Z3.MkTrue();
        }

        /// <summary>
        /// Core implementation for contains comparisons on string fields.
        /// </summary>
        /// <param name="cond">Condition token.</param>
        /// <param name="value">Substring token.</param>
        /// <param name="context">Field context.</param>
        /// <param name="parentActivity">The parent activity</param>
        /// <returns>Contains BoolExpr or true if unsupported.</returns>
        private BoolExpr ConvertContainsBase(JToken cond, JToken value, string context, Activity parentActivity)
        {
            var methodMonitor = ActivityMonitorFactory.Instance.CreateActivityMonitor(
                activityName: "PolicyToZ3.ConvertContainsBase",
                parentActivity: parentActivity,
                inheritParentProperties: false);
            methodMonitor.OnStart();

            var field = this.GetFieldAttribute(node: cond, sort: value, context: context, parentActivity: parentActivity);
            if (field.Sort.SortKind != Z3_sort_kind.Z3_SEQ_SORT)
            {
                methodMonitor.Activity["PolicyToZ3.Warn"] = "Contains only implemented for string sequence sorts.";
                methodMonitor.OnCompleted();
                return this.Z3.MkTrue();
            }

            var substring = value.Value<string>() ?? value.ToString();
            methodMonitor.OnCompleted();
            return this.Z3.MkContains((SeqExpr)field, this.Z3.MkString(substring));
        }

        /// <summary>
        /// Core implementation for containsKey modeling generating equality on artificial key notes.
        /// </summary>
        /// <param name="cond">Condition token.</param>
        /// <param name="value">Key token.</param>
        /// <param name="context">Field context.</param>
        /// <param name="parentActivity">The parent activity</param>
        /// <returns>ContainsKey BoolExpr or true if unsupported.</returns>
        private BoolExpr ConvertContainsKeyBase(JToken cond, JToken value, string context, Activity parentActivity)
        {
            var methodMonitor = ActivityMonitorFactory.Instance.CreateActivityMonitor(
                activityName: "PolicyToZ3.ConvertContainsKeyBase",
                parentActivity: parentActivity,
                inheritParentProperties: false);
            methodMonitor.OnStart();

            var name = cond["field"]?.Value<string>();
            if (name == null)
            {
                methodMonitor.Activity["PolicyToZ3.Warn"] = "field not found in containsKey condition.";
                methodMonitor.OnCompleted();
                return this.Z3.MkTrue();
            }

            if (!string.IsNullOrEmpty(context) && name.StartsWith(context + ".", StringComparison.OrdinalIgnoreCase))
            {
                name = name[(context.Length + 1)..];
            }

            var field = this.StringVar(value: $"{name}.{value}");
            methodMonitor.OnCompleted();
            return this.Z3.MkEq(field, this.Z3.MkString(string.Empty));
        }

        /// <summary>
        /// Core implementation for in comparisons producing an OR of equals cases.
        /// </summary>
        /// <param name="cond">Condition token.</param>
        /// <param name="values">Values array or string array literal.</param>
        /// <param name="context">Field context.</param>
        /// <param name="label">Label-only evaluation marker.</param>
        /// <param name="parentActivity">The parent activity</param>
        /// <returns>In BoolExpr.</returns>
        private BoolExpr ConvertInBase(JToken cond, JToken values, string context, string label, Activity parentActivity)
        {
            var methodMonitor = ActivityMonitorFactory.Instance.CreateActivityMonitor(
                activityName: "PolicyToZ3.ConvertInBase",
                parentActivity: parentActivity,
                inheritParentProperties: false);
            methodMonitor.OnStart();

            IEnumerable<BoolExpr> BuildOptions()
            {
                if (values is JArray array)
                {
                    foreach (var child in array)
                    {
                        yield return this.ConvertEquals(cond: cond, value: child, context: context, label: label, parentActivity: parentActivity);
                    }
                    yield break;
                }

                if (values.Type == JTokenType.String && ArrayRegex.IsMatch(values.Value<string>()!))
                {
                    var trimmed = values.Value<string>()![1..^1];
                    foreach (var entry in trimmed.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                    {
                        yield return this.ConvertEquals(cond: cond, value: JToken.FromObject(entry), context: context, label: label, parentActivity: parentActivity);
                    }
                    yield break;
                }

                methodMonitor.Activity["PolicyToZ3.Warn"] = $"in not handled value format: {values}";
                yield return this.Z3.MkTrue();
            }

            var disjuncts = BuildOptions().ToArray();
            methodMonitor.OnCompleted();
            return disjuncts.Length == 1 ? disjuncts[0] : this.Z3.MkOr(disjuncts);
        }

        /// <summary>
        /// Core implementation for equals producing a comparison expression handling special label cases.
        /// </summary>
        /// <param name="cond">Condition token.</param>
        /// <param name="value">Value token.</param>
        /// <param name="context">Field context.</param>
        /// <param name="label">Label-only evaluation marker.</param>
        /// <param name="parentActivity">The parent activity</param>
        /// <returns>Equality BoolExpr.</returns>
        private BoolExpr ConvertEqualsBase(JToken cond, JToken value, string context, string label, Activity parentActivity)
        {
            var field = this.ConvertExp(exp: cond, sort: value, context: context, parentActivity: parentActivity);
            if (field.ToString().Trim('"').Equals(label, StringComparison.OrdinalIgnoreCase))
            {
                return this.Z3.MkEq(this.StringVar(value: label), this.Z3.MkString("trivial"));
            }

            var target = this.ExtractValue(value: value, context: context);
            if (field.Sort.SortKind != target.Sort.SortKind)
            {
                return this.Z3.MkEq(this.StringVar(value: cond.ToString()), this.Z3.MkString("???"));
            }

            return this.Z3.MkEq(field, target);
        }

        /// <summary>
        /// Extracts and constructs the appropriate Z3 expression for a field/value reference node.
        /// </summary>
        /// <param name="node">Expression node containing field/value.</param>
        /// <param name="sort">Sort indicator token.</param>
        /// <param name="context">Context for trimming prefixes.</param>
        /// <param name="parentActivity">The parent activity</param>
        /// <returns>Field expression of inferred sort.</returns>
        private Expr GetFieldAttribute(JToken node, JToken sort, string context, Activity parentActivity)
        {
            string value = node["field"]?.Value<string>();
            if (value == null)
            {
                var raw = node["value"]?.Value<string>() ?? node["value"]?.ToString();
                if (raw != null && raw.StartsWith("[field(", StringComparison.OrdinalIgnoreCase))
                {
                    value = raw[7..^2];
                }
                else if (raw != null)
                {
                    value = raw;
                }
            }

            if (value == null)
            {
                throw new InvalidOperationException("Field/value missing on expression node.");
            }

            if (!string.IsNullOrEmpty(context) && value.StartsWith(context + ".", StringComparison.OrdinalIgnoreCase))
            {
                value = value[(context.Length + 1)..];
            }

            if (int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out _))
            {
                return this.Z3.MkIntConst(value);
            }

            if (sort != null && sort.Type == JTokenType.Boolean)
            {
                return this.Z3.MkBoolConst(value);
            }

            if (sort != null && sort.Type == JTokenType.String)
            {
                var parsed = this.ParseStringValue(raw: sort.Value<string>()!, context: context);
                return this.BuildFieldSort(exemplar: parsed, name: value);
            }

            return this.StringVar(value: value);
        }

        /// <summary>
        /// Builds a field expression of the same sort as an exemplar expression.
        /// </summary>
        /// <param name="exemplar">Exemplar expression used for sort inference.</param>
        /// <param name="name">Field name.</param>
        /// <returns>Z3 expression for the field.</returns>
        private Expr BuildFieldSort(Expr exemplar, string name)
        {
            return exemplar.Sort.SortKind switch
            {
                Z3_sort_kind.Z3_INT_SORT => this.Z3.MkIntConst(name),
                Z3_sort_kind.Z3_BOOL_SORT => this.Z3.MkBoolConst(name),
                Z3_sort_kind.Z3_SEQ_SORT => this.StringVar(value: name),
                _ => this.StringVar(value: name)
            };
        }

        /// <summary>
        /// Extracts a literal or complex value token and converts to a Z3 expression of appropriate sort.
        /// </summary>
        /// <param name="value">Value token.</param>
        /// <param name="context">Context for nested field trimming.</param>
        /// <returns>Z3 expression representing the value.</returns>
        private Expr ExtractValue(JToken value, string context)
        {
            return value.Type switch
            {
                JTokenType.Boolean => this.Z3.MkBool(value.Value<bool>()),
                JTokenType.Integer => this.Z3.MkInt(value.Value<int>()),
                JTokenType.Float => this.Z3.MkReal(value.Value<double>().ToString(CultureInfo.InvariantCulture)),
                JTokenType.String => this.ParseStringValue(raw: value.Value<string>()!, context: context),
                _ => this.StringVar(value: value.ToString())
            };
        }

        /// <summary>
        /// Parses a raw string token into an appropriate Z3 expression, handling numbers, arrays, length constructs, parameters, and booleans.
        /// </summary>
        /// <param name="raw">Raw string value.</param>
        /// <param name="context">Field context.</param>
        /// <returns>Z3 expression representing parsed value.</returns>
        private Expr ParseStringValue(string raw, string context)
        {
            var s = raw.ToLowerInvariant().Trim();

            if (IntegerRegex.IsMatch(s))
            {
                return this.Z3.MkInt(int.Parse(s, CultureInfo.InvariantCulture));
            }

            if (ArrayRegex.IsMatch(s))
            {
                var inner = s[1..^1];
                var values = inner.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                if (values.Length == 1)
                {
                    return this.ParseStringValue(raw: values[0], context: context);
                }

                return this.Z3.MkString(s);
            }

            if (LengthFieldRegex.IsMatch(s))
            {
                var fieldName = s.Substring(14, s.Length - 17);
                var field = this.ConvertCountField(field: fieldName, context: context);
                return (ArithExpr)this.Z3.MkApp(CountAll, field);
            }

            if (ParametersRegex.IsMatch(s))
            {
                return this.StringVar(value: "parameters(X)");
            }

            if (bool.TryParse(s, out var boolValue))
            {
                return this.Z3.MkBool(boolValue);
            }

            return this.Z3.MkString(s);
        }

        /// <summary>
        /// Converts a count expression (with optional where filter) into an arithmetic expression with lifted counting semantics.
        /// </summary>
        /// <param name="exp">Count expression node.</param>
        /// <param name="value">Value/sort token hosting field/where.</param>
        /// <param name="context">Parent context.</param>
        /// <param name="parentActivity">The parent activity</param>
        /// <returns>Arithmetic expression representing count.</returns>
        private Expr ConvertCount(JToken exp, JToken value, string context, Activity parentActivity)
        {
            var methodMonitor = ActivityMonitorFactory.Instance.CreateActivityMonitor(
                activityName: "PolicyToZ3.ConvertCount",
                parentActivity: parentActivity,
                inheritParentProperties: false);
            methodMonitor.OnStart();

            var fieldToken = value["field"] ?? value["value"];
            if (fieldToken == null)
            {
                methodMonitor.Activity["PolicyToZ3.Warn"] = $"count not handled missing field/value: {value}";
                methodMonitor.OnCompleted();
                return this.Z3.MkInt(0);
            }

            var fieldName = fieldToken.Value<string>() ?? fieldToken.ToString();
            var field = this.ConvertCountField(field: fieldName, context: context);

            if (value["where"] != null)
            {
                var whereContext = fieldName;
                var cond = this.ConvertCond(cond: value["where"]!, context: whereContext, label: string.Empty, parentActivity: parentActivity);
                var simplified = (BoolExpr)cond.Simplify();

                if (simplified.IsTrue)
                {
                    methodMonitor.OnCompleted();
                    return (ArithExpr)this.Z3.MkApp(this.CountAll, field);
                }

                if (simplified.IsFalse)
                {
                    methodMonitor.OnCompleted();
                    return this.Z3.MkInt(0);
                }

                methodMonitor.OnCompleted();
                return this.LiftCount(exp: simplified, constraints: true, contextExpr: field);
            }

            methodMonitor.OnCompleted();
            return (ArithExpr)this.Z3.MkApp(this.CountAll, field);
        }

        /// <summary>
        /// Converts a field name into a lowercase sequence expression for counting.
        /// </summary>
        /// <param name="field">Field name.</param>
        /// <param name="context">Context for trimming.</param>
        /// <returns>Sequence expression for count context.</returns>
        private SeqExpr ConvertCountField(string field, string context)
        {
            var name = field;
            if (!string.IsNullOrEmpty(context) && name.StartsWith(context + ".", StringComparison.OrdinalIgnoreCase))
            {
                name = name[(context.Length + 1)..];
            }

            return (SeqExpr)this.Z3.MkString(name.ToLowerInvariant().Trim());
        }

        /// <summary>
        /// Lifts a BoolExpr representing a filtered count into an arithmetic expression via function abstraction.
        /// </summary>
        /// <param name="exp">Boolean expression to lift.</param>
        /// <param name="constraints">Whether to track constraints (currently unused marker).</param>
        /// <param name="contextExpr">Context string expression.</param>
        /// <returns>Arithmetic expression approximating count.</returns>
        private ArithExpr LiftCount(BoolExpr exp, bool constraints, Expr contextExpr)
        {
            var op = exp.FuncDecl?.Name.ToString() ?? string.Empty;
            if (this.ConditionLifters.TryGetValue(op, out var lifter))
            {
                var args = exp.Args.Select(child => LiftCount(exp: (BoolExpr)child, constraints: constraints, contextExpr: contextExpr)).ToList();
                return lifter(args, contextExpr);
            }

            var sanitized = exp.ToString().Replace('\n', ' ').Replace(' ', '_');
            var func = this.Z3.MkFuncDecl($"count-{sanitized}", new[] { this.Z3.StringSort }, this.Z3.IntSort);
            _ = this.CountFunctions.Add(func);
            return (ArithExpr)this.Z3.MkApp(func, contextExpr);
        }

        /// <summary>
        /// Lifts a conjunction of counts using the meet lattice function.
        /// </summary>
        /// <param name="args">List of arithmetic expressions.</param>
        /// <param name="contextExpr">Context field expression.</param>
        /// <returns>Meet applied expression chain.</returns>
        private ArithExpr LiftAnd(IReadOnlyList<ArithExpr> args, Expr contextExpr)
        {
            var value = args[0];
            for (var i = 1; i < args.Count; i++)
            {
                value = (ArithExpr)this.Z3.MkApp(this.Meet, value, args[i]);
            }

            return value;
        }

        /// <summary>
        /// Lifts a disjunction of counts using the join lattice function.
        /// </summary>
        /// <param name="args">List of arithmetic expressions.</param>
        /// <param name="contextExpr">Context field expression.</param>
        /// <returns>Join applied expression chain.</returns>
        private ArithExpr LiftOr(IReadOnlyList<ArithExpr> args, Expr contextExpr)
        {
            var value = args[0];
            for (var i = 1; i < args.Count; i++)
            {
                value = (ArithExpr)this.Z3.MkApp(this.Join, value, args[i]);
            }

            return value;
        }

        /// <summary>
        /// Lifts a negated count by subtracting from total cardinality.
        /// </summary>
        /// <param name="args">Single argument list.</param>
        /// <param name="contextExpr">Context field expression.</param>
        /// <returns>Arithmetic expression modeling negation.</returns>
        private ArithExpr LiftNot(IReadOnlyList<ArithExpr> args, Expr contextExpr)
        {
            var count = (ArithExpr)this.Z3.MkApp(this.CountAll, contextExpr);
            return this.Z3.MkSub(count, args[0]);
        }

        /// <summary>
        /// Converts a greaterOrEquals condition node.
        /// </summary>
        /// <param name="cond">Condition token.</param>
        /// <param name="value">Value token.</param>
        /// <param name="context">Field context.</param>
        /// <param name="label">Label for label-only evaluation.</param>
        /// <param name="parentActivity">The parent activity</param>
        /// <returns>Ge BoolExpr.</returns>
        private BoolExpr ConvertGreaterOrEquals(JToken cond, JToken value, string context, string label, Activity parentActivity)
        {
            var field = this.AsArithExpr(this.ConvertExp(exp: cond, sort: value, context: context, parentActivity: parentActivity));
            var target = this.AsArithExpr(this.ConvertComparableValue(value: value, context: context));
            return this.Z3.MkGe(field, target);
        }

        /// <summary>
        /// Converts a greater condition node.
        /// </summary>
        /// <param name="cond">Condition token.</param>
        /// <param name="value">Value token.</param>
        /// <param name="context">Field context.</param>
        /// <param name="label">Label for label-only evaluation.</param>
        /// <param name="parentActivity">The parent activity</param>
        /// <returns>Gt BoolExpr.</returns>
        private BoolExpr ConvertGreater(JToken cond, JToken value, string context, string label, Activity parentActivity)
        {
            var field = this.AsArithExpr(this.ConvertExp(exp: cond, sort: value, context: context, parentActivity: parentActivity));
            var target = this.AsArithExpr(this.ConvertComparableValue(value: value, context: context));
            return this.Z3.MkGt(field, target);
        }

        /// <summary>
        /// Converts a less condition node.
        /// </summary>
        /// <param name="cond">Condition token.</param>
        /// <param name="value">Value token.</param>
        /// <param name="context">Field context.</param>
        /// <param name="label">Label for label-only evaluation.</param>
        /// <param name="parentActivity">The parent activity</param>
        /// <returns>Lt BoolExpr.</returns>
        private BoolExpr ConvertLess(JToken cond, JToken value, string context, string label, Activity parentActivity)
        {
            var field = this.AsArithExpr(this.ConvertExp(exp: cond, sort: value, context: context, parentActivity: parentActivity));
            var target = this.AsArithExpr(this.ConvertComparableValue(value: value, context: context));
            return this.Z3.MkLt(field, target);
        }

        /// <summary>
        /// Converts a lessOrEquals condition node.
        /// </summary>
        /// <param name="cond">Condition token.</param>
        /// <param name="value">Value token.</param>
        /// <param name="context">Field context.</param>
        /// <param name="label">Label for label-only evaluation.</param>
        /// <param name="parentActivity">The parent activity</param>
        /// <returns>Le BoolExpr.</returns>
        private BoolExpr ConvertLessOrEquals(JToken cond, JToken value, string context, string label, Activity parentActivity)
        {
            var field = this.AsArithExpr(this.ConvertExp(exp: cond, sort: value, context: context, parentActivity: parentActivity));
            var target = this.AsArithExpr(this.ConvertComparableValue(value: value, context: context));
            return this.Z3.MkLe(field, target);
        }

        /// <summary>
        /// Ensures a comparable value is an arithmetic expression, coercing non-numeric sorts where needed.
        /// </summary>
        /// <param name="value">Value token.</param>
        /// <param name="context">Field context.</param>
        /// <returns>Arithmetic expression for comparison.</returns>
        private Expr ConvertComparableValue(JToken value, string context)
        {
            var extracted = this.ExtractValue(value: value, context: context);
            return extracted.Sort.SortKind switch
            {
                Z3_sort_kind.Z3_INT_SORT => extracted,
                Z3_sort_kind.Z3_REAL_SORT => extracted,
                Z3_sort_kind.Z3_BV_SORT => extracted,
                Z3_sort_kind.Z3_RE_SORT => extracted,
                Z3_sort_kind.Z3_SEQ_SORT => this.Z3.MkIntConst(extracted.ToString()),
                _ => this.Z3.MkIntConst(extracted.ToString())
            };
        }

        /// <summary>
        /// Converts a generic expression to an arithmetic expression, coercing strings to int constants when needed.
        /// </summary>
        /// <param name="expr">Original expression.</param>
        /// <returns>Arithmetic expression.</returns>
        private ArithExpr AsArithExpr(Expr expr)
        {
            return expr switch
            {
                ArithExpr arith => arith,
                SeqExpr seq => this.Z3.MkIntConst(seq.ToString()),
                _ => this.Z3.MkIntConst(expr.ToString())
            };
        }

        /// <summary>
        /// Converts a wildcard pattern (with * only) to a Z3 regex expression.
        /// </summary>
        /// <param name="pattern">Pattern string.</param>
        /// <returns>Regex expression.</returns>
        private ReExpr ConvertWildcardPattern(string pattern)
        {
            var pieces = pattern.Split('*')
                .Select(part => string.IsNullOrEmpty(part)
                    ? this.Z3.MkFullRe(this.Z3.MkReSort(this.Z3.StringSort))
                    : this.Z3.MkToRe(this.Z3.MkString(part)))
                .ToArray();

            return pieces.Length == 1 ? pieces[0] : this.Z3.MkConcat(pieces);
        }

        /// <summary>
        /// Splits a string emitting delimiters as tokens.
        /// </summary>
        /// <param name="input">Input string to split.</param>
        /// <param name="delimiters">Delimiter characters to isolate.</param>
        /// <returns>Enumerable of string tokens.</returns>
        private static IEnumerable<string> SplitString(string input, string delimiters)
        {
            var current = new StringBuilder();
            foreach (var ch in input)
            {
                if (delimiters.Contains(ch, StringComparison.OrdinalIgnoreCase))
                {
                    if (current.Length > 0)
                    {
                        yield return current.ToString();
                        _ = current.Clear();
                    }

                    yield return ch.ToString();
                }
                else
                {
                    _ = current.Append(ch);
                }
            }

            if (current.Length > 0)
            {
                yield return current.ToString();
            }
        }

        /// <summary>
        /// Converts a policy match pattern (supports *, ?, #, .) into a Z3 regex expression.
        /// </summary>
        /// <param name="pattern">Match pattern string.</param>
        /// <returns>Regex expression.</returns>
        private ReExpr ConvertMatchPattern(string pattern)
        {
            var pieces = new List<ReExpr>();
            foreach (var token in PolicyToZ3.SplitString(input: pattern, delimiters: "*#?."))
            {
                switch (token)
                {
                    case "*":
                        pieces.Add(this.Z3.MkFullRe(this.Z3.MkReSort(this.Z3.StringSort)));
                        break;
                    case "?":
                        pieces.Add(this.Z3.MkUnion(
                            this.Z3.MkRange(this.Z3.MkString("a"), this.Z3.MkString("z")),
                            this.Z3.MkRange(this.Z3.MkString("A"), this.Z3.MkString("Z"))));
                        break;
                    case "#":
                        pieces.Add(this.Z3.MkRange(this.Z3.MkString("0"), this.Z3.MkString("9")));
                        break;
                    case ".":
                        pieces.Add(this.Z3.MkFullRe(this.Z3.MkReSort(this.Z3.StringSort)));
                        break;
                    default:
                        pieces.Add(this.Z3.MkToRe(this.Z3.MkString(token)));
                        break;
                }
            }

            return pieces.Count == 1 ? pieces[0] : this.Z3.MkConcat(pieces.ToArray());
        }
    }
}
