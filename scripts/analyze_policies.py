#!/usr/bin/env python3
"""Analyze Azure Policy JSON definitions for complexity and feature coverage.

Walks a directory tree of policy JSON files (e.g., the regolator
policyDefinitions/ folder) and produces a structured JSON report with:

  - Per-policy metrics (size, operators, fields, functions, patterns, etc.)
  - Composite complexity score
  - Aggregated summary statistics
  - Auto-flagged candidates for test coverage

Usage:
    python3 scripts/analyze_policies.py <policy_dir> [--out <output.json>] [--top N]

Examples:
    # Analyze all policies, write report, print top 30
    python3 scripts/analyze_policies.py ~/repos/mpf/regolator/policyDefinitions

    # Write report to file
    python3 scripts/analyze_policies.py ~/repos/mpf/regolator/policyDefinitions --out report.json

    # Show top 50 by complexity
    python3 scripts/analyze_policies.py ~/repos/mpf/regolator/policyDefinitions --top 50
"""

import argparse
import json
import math
import os
import re
import sys
from collections import Counter, defaultdict


# ---------------------------------------------------------------------------
# ARM template expression detection
# ---------------------------------------------------------------------------

# Functions we care about detecting in template expressions like
# "[concat('a', parameters('b'))]" or "[if(equals(field('type'), 'X'), ...)]"
ARM_FUNCTIONS = [
    "concat", "if", "field", "parameters", "resourceGroup", "subscription",
    "requestContext", "first", "last", "split", "replace", "toLower",
    "toUpper", "padLeft", "ipRangeContains", "empty", "length", "contains",
    "equals", "not", "and", "or", "less", "lessOrEquals", "greater",
    "greaterOrEquals", "add", "sub", "mul", "div", "mod", "string", "int",
    "base64", "uri", "trim", "substring", "indexOf", "startsWith",
    "endsWith", "current", "utcNow", "dateTimeAdd",
]

# Regex to find "[functionName(...)]" style template expressions
TEMPLATE_EXPR_RE = re.compile(r"\[([a-zA-Z_][a-zA-Z0-9_]*)\s*\(")

# Regex to find function calls inside expressions (including nested)
FUNC_CALL_RE = re.compile(r"([a-zA-Z_][a-zA-Z0-9_]*)\s*\(")


def find_template_expressions(obj):
    """Find all ARM template expression strings in a JSON value.

    Returns a list of expression strings (the contents between [ and ]).
    """
    exprs = []
    if isinstance(obj, str):
        if obj.startswith("[") and obj.endswith("]") and not obj.startswith("[["):
            exprs.append(obj[1:-1])
    elif isinstance(obj, dict):
        for v in obj.values():
            exprs.extend(find_template_expressions(v))
    elif isinstance(obj, list):
        for v in obj:
            exprs.extend(find_template_expressions(v))
    return exprs


def analyze_functions(exprs):
    """Analyze ARM template expressions for function usage.

    Returns:
        func_counts: dict mapping function name -> occurrence count
        max_nesting: maximum nesting depth of function calls
    """
    func_counts = Counter()
    max_nesting = 0

    for expr in exprs:
        # Find all function calls
        for m in FUNC_CALL_RE.finditer(expr):
            fname = m.group(1).lower()
            func_counts[fname] += 1

        # Compute max nesting depth by counting balanced parens
        depth = 0
        local_max = 0
        for ch in expr:
            if ch == "(":
                depth += 1
                local_max = max(local_max, depth)
            elif ch == ")":
                depth = max(0, depth - 1)
        max_nesting = max(max_nesting, local_max)

    return dict(func_counts), max_nesting


# ---------------------------------------------------------------------------
# Condition tree analysis
# ---------------------------------------------------------------------------

def count_condition_nodes(obj, depth=0):
    """Count condition nodes and max nesting depth in a policy rule.

    Returns (total_nodes, max_depth).
    """
    if not isinstance(obj, dict):
        return 0, depth
    total = 0
    max_d = depth
    for k in ("if", "then", "allOf", "anyOf", "not"):
        if k in obj:
            if k in ("allOf", "anyOf") and isinstance(obj[k], list):
                total += len(obj[k])
                for item in obj[k]:
                    c, d = count_condition_nodes(item, depth + 1)
                    total += c
                    max_d = max(max_d, d)
            elif k == "not":
                total += 1
                c, d = count_condition_nodes(obj[k], depth + 1)
                total += c
                max_d = max(max_d, d)
            elif k in ("if", "then"):
                c, d = count_condition_nodes(obj[k], depth + 1)
                total += c
                max_d = max(max_d, d)
    return total, max_d


# ---------------------------------------------------------------------------
# Field analysis
# ---------------------------------------------------------------------------

def find_fields(obj, fields=None):
    """Collect all field references in a JSON value."""
    if fields is None:
        fields = set()
    if isinstance(obj, dict):
        if "field" in obj and isinstance(obj["field"], str):
            fields.add(obj["field"])
        for v in obj.values():
            find_fields(v, fields)
    elif isinstance(obj, list):
        for v in obj:
            find_fields(v, fields)
    return fields


def classify_fields(fields):
    """Classify fields into categories."""
    wildcard = [f for f in fields if "[*]" in f]
    # Fully-qualified alias fields contain "/" (e.g., "Microsoft.Compute/imageOffer")
    fq_alias = [f for f in fields if "/" in f]
    # Short fields are everything else (e.g., "type", "location", "name")
    short = [f for f in fields if "/" not in f and "[*]" not in f]
    # Doubly-nested wildcards: contain [*] more than once
    doubly_nested = [f for f in fields if f.count("[*]") >= 2]
    return {
        "total": len(fields),
        "wildcard": len(wildcard),
        "wildcard_fields": sorted(wildcard),
        "fq_alias": len(fq_alias),
        "short": len(short),
        "doubly_nested_wildcard": len(doubly_nested),
        "doubly_nested_fields": sorted(doubly_nested),
        "all": sorted(fields),
    }


# ---------------------------------------------------------------------------
# Operator analysis
# ---------------------------------------------------------------------------

OPERATORS = [
    "equals", "notEquals", "like", "notLike", "in", "notIn",
    "contains", "notContains", "containsKey", "notContainsKey",
    "less", "lessOrEquals", "greater", "greaterOrEquals",
    "exists", "match", "notMatch", "matchInsensitively", "notMatchInsensitively",
]


def find_operators(obj, ops=None):
    """Count operator usage in a JSON value."""
    if ops is None:
        ops = Counter()
    if isinstance(obj, dict):
        for k in OPERATORS:
            if k in obj:
                ops[k] += 1
        for v in obj.values():
            find_operators(v, ops)
    elif isinstance(obj, list):
        for v in obj:
            find_operators(v, ops)
    return ops


# ---------------------------------------------------------------------------
# Count expression analysis
# ---------------------------------------------------------------------------

def analyze_counts(obj, results=None, inside_count=False):
    """Analyze count expressions in the condition tree.

    Detects:
    - field count (count.field)
    - value count (count.value with name/current())
    - bare count (no where clause)
    - count with where
    - nested count (count inside count.where)
    """
    if results is None:
        results = {
            "field_count": 0,
            "value_count": 0,
            "bare_count": 0,
            "count_with_where": 0,
            "nested_count": 0,
            "max_count_depth": 0,
            "count_in_existence_condition": 0,
        }

    if isinstance(obj, dict):
        if "count" in obj and isinstance(obj["count"], dict):
            count_obj = obj["count"]
            is_value = "value" in count_obj
            is_field = "field" in count_obj
            has_where = "where" in count_obj
            has_name = "name" in count_obj

            if is_value:
                results["value_count"] += 1
            elif is_field:
                results["field_count"] += 1

            if has_where:
                results["count_with_where"] += 1
            else:
                results["bare_count"] += 1

            if inside_count:
                results["nested_count"] += 1

            # Recurse into where clause to detect nested counts
            if has_where:
                analyze_counts(count_obj["where"], results, inside_count=True)

        for k, v in obj.items():
            if k != "count":
                analyze_counts(v, results, inside_count)
    elif isinstance(obj, list):
        for v in obj:
            analyze_counts(v, results, inside_count)

    return results


# ---------------------------------------------------------------------------
# Pattern detection
# ---------------------------------------------------------------------------

def detect_double_negation(obj, inside_not=False, results=None):
    """Detect double-negation patterns (not + notEquals/notIn/notLike/notContains).

    Returns counts of each double-negation combination.
    """
    if results is None:
        results = Counter()

    if isinstance(obj, dict):
        if "not" in obj:
            # We're entering a not block — scan children for negative operators
            detect_double_negation(obj["not"], inside_not=True, results=results)
            return results

        if inside_not:
            for neg_op in ("notEquals", "notIn", "notLike", "notContains",
                           "notMatch", "notMatchInsensitively", "notContainsKey"):
                if neg_op in obj:
                    results[f"not+{neg_op}"] += 1

        for v in obj.values():
            detect_double_negation(v, inside_not, results)
    elif isinstance(obj, list):
        for v in obj:
            detect_double_negation(v, inside_not, results)

    return results


def detect_dynamic_fields(obj, results=None):
    """Detect dynamic field names (field value is a template expression)."""
    if results is None:
        results = []
    if isinstance(obj, dict):
        if "field" in obj and isinstance(obj["field"], str):
            if obj["field"].startswith("[") and obj["field"].endswith("]"):
                results.append(obj["field"])
        for v in obj.values():
            detect_dynamic_fields(v, results)
    elif isinstance(obj, list):
        for v in obj:
            detect_dynamic_fields(v, results)
    return results


def detect_current_usage(obj):
    """Check if current() or current('name') is used anywhere in string values."""
    text = json.dumps(obj)
    return "current(" in text


# ---------------------------------------------------------------------------
# Effect and details analysis
# ---------------------------------------------------------------------------

def analyze_effect(rule):
    """Analyze the effect section of a policy rule."""
    then = rule.get("then", {})
    effect_raw = then.get("effect", "unknown")

    # Determine if effect is parameterized
    is_parameterized = (
        isinstance(effect_raw, str) and
        effect_raw.startswith("[") and
        "parameters(" in effect_raw
    )

    # Normalize effect name
    if is_parameterized:
        effect_name = "parameterized"
        # Try to extract the parameter name for display
        m = re.search(r"parameters\(['\"](\w+)['\"]\)", effect_raw)
        effect_param = m.group(1) if m else "unknown"
    else:
        effect_name = effect_raw.lower() if isinstance(effect_raw, str) else "unknown"
        effect_param = None

    return {
        "raw": effect_raw,
        "name": effect_name,
        "parameterized": is_parameterized,
        "effect_param": effect_param,
    }


def analyze_details(rule):
    """Analyze the details section (for AINE/DINE/Modify/Append effects)."""
    then = rule.get("then", {})
    details = then.get("details", {})

    if not isinstance(details, dict):
        return {"has_details": False}

    result = {
        "has_details": bool(details),
        "type": details.get("type"),
        "name": details.get("name"),
        "has_existence_condition": "existenceCondition" in details,
        "has_deployment": "deployment" in details,
        "role_definition_ids": len(details.get("roleDefinitionIds", [])),
        "conflict_effect": details.get("conflictEffect"),
    }

    # Analyze Modify operations
    operations = details.get("operations", [])
    if operations:
        op_types = Counter()
        conditional_ops = 0
        for op in operations:
            op_types[op.get("operation", "unknown")] += 1
            if "condition" in op:
                conditional_ops += 1
        result["modify_operations"] = len(operations)
        result["modify_op_types"] = dict(op_types)
        result["conditional_operations"] = conditional_ops
    else:
        result["modify_operations"] = 0

    # Analyze existenceCondition
    if "existenceCondition" in details:
        ec = details["existenceCondition"]
        ec_counts = analyze_counts(ec)
        ec_ops = find_operators(ec)
        ec_fields = find_fields(ec)
        result["existence_condition_ops"] = dict(ec_ops)
        result["existence_condition_fields"] = sorted(ec_fields)
        result["existence_condition_has_count"] = ec_counts["field_count"] + ec_counts["value_count"] > 0

    # Analyze deployment template
    if "deployment" in details:
        deploy = details["deployment"]
        template = deploy.get("properties", {}).get("template", {})
        resources = template.get("resources", [])
        deploy_params = deploy.get("properties", {}).get("parameters", {})
        result["deployment_resources"] = len(resources)
        result["deployment_params"] = len(deploy_params)

    return result


# ---------------------------------------------------------------------------
# Parameter analysis
# ---------------------------------------------------------------------------

def analyze_parameters(params):
    """Analyze policy parameters."""
    if not isinstance(params, dict):
        return {"count": 0}

    type_counts = Counter()
    has_allowed_values = 0
    has_default_value = 0

    for name, defn in params.items():
        if isinstance(defn, dict):
            ptype = defn.get("type", "unknown")
            type_counts[ptype.lower()] += 1
            if "allowedValues" in defn:
                has_allowed_values += 1
            if "defaultValue" in defn:
                has_default_value += 1

    return {
        "count": len(params),
        "types": dict(type_counts),
        "with_allowed_values": has_allowed_values,
        "with_default_value": has_default_value,
    }


# ---------------------------------------------------------------------------
# Complexity scoring
# ---------------------------------------------------------------------------

def compute_complexity_score(metrics):
    """Compute a composite complexity score.

    Weights rare/hard-to-compile features higher than common ones.
    Uses log2(nodes) for structural complexity to avoid over-weighting
    large-but-repetitive policies.
    """
    # Structural: log2(condition_nodes) * sqrt(depth)
    nodes = max(metrics["condition_nodes"], 1)
    depth = max(metrics["max_depth"], 1)
    structural = math.log2(nodes) * math.sqrt(depth)

    # Operator diversity: number of distinct operator types used
    op_diversity = len(metrics["operators"]) * 2

    # Field complexity: unique fields + 2x wildcard + 4x doubly-nested
    fc = metrics["fields"]
    field_score = fc["total"] + fc["wildcard"] * 2 + fc["doubly_nested_wildcard"] * 4

    # Function complexity: max nesting depth * 3
    func_score = metrics["function_max_nesting"] * 3

    # Count complexity: weighted by type
    cc = metrics["counts"]
    count_score = (
        cc["bare_count"] * 1 +
        cc["count_with_where"] * 2 +
        cc["value_count"] * 4 +
        cc["nested_count"] * 5
    )

    # Cross-resource complexity
    details = metrics["details"]
    cross_resource = 0
    if details.get("has_existence_condition"):
        cross_resource += 3
        if details.get("existence_condition_has_count"):
            cross_resource += 5
    if details.get("has_deployment"):
        cross_resource += 2

    # Pattern complexity
    pattern_score = 0
    # Double-negation
    dn = metrics["double_negation"]
    pattern_score += sum(dn.values()) * 2
    pattern_score += len(dn) * 3  # bonus for diverse double-negation types

    # Dynamic fields
    pattern_score += len(metrics["dynamic_fields"]) * 3

    # current() usage
    if metrics["uses_current"]:
        pattern_score += 4

    # Modify operations
    if details.get("modify_operations", 0) > 1:
        pattern_score += details["modify_operations"] * 2
    if details.get("conditional_operations", 0) > 0:
        pattern_score += details["conditional_operations"] * 3

    # Function diversity: bonus for rare functions
    rare_funcs = {"iprangecontains", "requestcontext", "first", "last",
                  "replace", "padleft", "empty", "current", "resourcegroup"}
    func_counts = metrics.get("function_counts", {})
    for rf in rare_funcs:
        if rf in func_counts:
            pattern_score += 3

    total = (
        structural +
        op_diversity +
        field_score +
        func_score +
        count_score +
        cross_resource +
        pattern_score
    )

    return {
        "total": round(total, 1),
        "structural": round(structural, 1),
        "operator_diversity": op_diversity,
        "field_score": field_score,
        "function_score": func_score,
        "count_score": count_score,
        "cross_resource": cross_resource,
        "pattern_score": pattern_score,
    }


# ---------------------------------------------------------------------------
# Per-policy analysis
# ---------------------------------------------------------------------------

def analyze_policy(filepath):
    """Analyze a single policy JSON file. Returns a metrics dict or None."""
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            raw = f.read()
        policy = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError, OSError):
        return None

    # Navigate to properties (handle both wrapped and unwrapped formats)
    props = policy.get("properties", policy)
    rule = props.get("policyRule")
    if not rule or not isinstance(rule, dict):
        return None  # Not a policy definition

    if_cond = rule.get("if", {})
    params = props.get("parameters", {})
    display_name = props.get("displayName", "")
    mode = props.get("mode", "")

    # Size metrics
    line_count = raw.count("\n") + 1
    byte_count = len(raw.encode("utf-8"))

    # Condition tree
    condition_nodes, max_depth = count_condition_nodes(if_cond)

    # Fields
    all_fields = find_fields(if_cond)
    fields = classify_fields(all_fields)

    # Operators
    operators = find_operators(if_cond)

    # Count expressions
    counts = analyze_counts(if_cond)
    # Also check existenceCondition for counts
    then_details = rule.get("then", {}).get("details", {})
    if isinstance(then_details, dict) and "existenceCondition" in then_details:
        ec_counts = analyze_counts(then_details["existenceCondition"])
        if ec_counts["field_count"] + ec_counts["value_count"] > 0:
            counts["count_in_existence_condition"] = 1

    # ARM template expressions
    if_exprs = find_template_expressions(if_cond)
    func_counts, func_max_nesting = analyze_functions(if_exprs)

    # Also scan details for template expressions (Modify values, etc.)
    details_exprs = find_template_expressions(rule.get("then", {}).get("details", {}))
    details_func_counts, details_func_nesting = analyze_functions(details_exprs)
    # Merge
    all_func_counts = Counter(func_counts) + Counter(details_func_counts)
    all_func_nesting = max(func_max_nesting, details_func_nesting)

    # Patterns
    double_neg = detect_double_negation(if_cond)
    dynamic_fields = detect_dynamic_fields(if_cond)
    uses_current = detect_current_usage(rule)

    # Effect and details
    effect = analyze_effect(rule)
    details = analyze_details(rule)

    # Parameters
    param_analysis = analyze_parameters(params)

    # Relative path from the input directory
    rel_path = filepath  # Will be adjusted by caller

    metrics = {
        "file": rel_path,
        "display_name": display_name,
        "mode": mode,
        "effect": effect,
        "size": {
            "lines": line_count,
            "bytes": byte_count,
        },
        "condition_nodes": condition_nodes,
        "max_depth": max_depth,
        "fields": fields,
        "operators": dict(operators),
        "operator_count": sum(operators.values()),
        "operator_types": len(operators),
        "counts": counts,
        "function_counts": dict(all_func_counts),
        "function_types": len(all_func_counts),
        "function_max_nesting": all_func_nesting,
        "double_negation": dict(double_neg),
        "dynamic_fields": dynamic_fields,
        "uses_current": uses_current,
        "details": details,
        "parameters": param_analysis,
    }

    # Compute complexity score
    metrics["complexity"] = compute_complexity_score(metrics)

    return metrics


# ---------------------------------------------------------------------------
# Aggregate summary
# ---------------------------------------------------------------------------

def build_summary(policies):
    """Build aggregate summary statistics."""
    total = len(policies)
    if total == 0:
        return {}

    # Effect distribution
    effect_dist = Counter()
    for p in policies:
        ename = p["effect"]["name"]
        if p["effect"]["parameterized"]:
            ename = f"parameterized"
        effect_dist[ename] += 1

    # Operator frequency (across all policies)
    op_freq = Counter()
    for p in policies:
        for op, count in p["operators"].items():
            op_freq[op] += count

    # Operator usage (how many policies use each operator)
    op_usage = Counter()
    for p in policies:
        for op in p["operators"]:
            op_usage[op] += 1

    # Function frequency
    func_freq = Counter()
    for p in policies:
        for func, count in p["function_counts"].items():
            func_freq[func] += count

    func_usage = Counter()
    for p in policies:
        for func in p["function_counts"]:
            func_usage[func] += 1

    # Feature coverage
    features = {
        "has_field_count": sum(1 for p in policies if p["counts"]["field_count"] > 0),
        "has_value_count": sum(1 for p in policies if p["counts"]["value_count"] > 0),
        "has_bare_count": sum(1 for p in policies if p["counts"]["bare_count"] > 0),
        "has_count_with_where": sum(1 for p in policies if p["counts"]["count_with_where"] > 0),
        "has_nested_count": sum(1 for p in policies if p["counts"]["nested_count"] > 0),
        "has_double_negation": sum(1 for p in policies if p["double_negation"]),
        "has_dynamic_fields": sum(1 for p in policies if p["dynamic_fields"]),
        "has_current": sum(1 for p in policies if p["uses_current"]),
        "has_wildcard_fields": sum(1 for p in policies if p["fields"]["wildcard"] > 0),
        "has_doubly_nested_wildcard": sum(1 for p in policies if p["fields"]["doubly_nested_wildcard"] > 0),
        "has_existence_condition": sum(1 for p in policies if p["details"].get("has_existence_condition")),
        "has_deployment": sum(1 for p in policies if p["details"].get("has_deployment")),
        "has_modify_operations": sum(1 for p in policies if p["details"].get("modify_operations", 0) > 0),
        "has_conditional_modify_ops": sum(1 for p in policies if p["details"].get("conditional_operations", 0) > 0),
        "has_count_in_existence_cond": sum(1 for p in policies if p["counts"].get("count_in_existence_condition", 0) > 0),
    }

    # Complexity stats
    scores = [p["complexity"]["total"] for p in policies]
    scores.sort(reverse=True)

    return {
        "total_policies": total,
        "effect_distribution": dict(effect_dist.most_common()),
        "operator_frequency": dict(op_freq.most_common()),
        "operator_usage_by_policy": dict(op_usage.most_common()),
        "function_frequency": dict(func_freq.most_common()),
        "function_usage_by_policy": dict(func_usage.most_common()),
        "feature_coverage": features,
        "complexity_percentiles": {
            "p50": scores[total // 2] if total > 0 else 0,
            "p90": scores[total // 10] if total >= 10 else scores[0],
            "p95": scores[total // 20] if total >= 20 else scores[0],
            "p99": scores[total // 100] if total >= 100 else scores[0],
            "max": scores[0] if scores else 0,
        },
    }


# ---------------------------------------------------------------------------
# Candidate flagging
# ---------------------------------------------------------------------------

def flag_candidates(policies):
    """Flag policies that exercise rare or untested features."""
    candidates = defaultdict(list)

    for p in policies:
        f = p["file"]
        score = p["complexity"]["total"]

        # Value count with current()
        if p["counts"]["value_count"] > 0:
            candidates["value_count"].append({"file": f, "score": score})

        # Nested count
        if p["counts"]["nested_count"] > 0:
            candidates["nested_count"].append({"file": f, "score": score})

        # Count in existenceCondition
        if p["counts"].get("count_in_existence_condition", 0) > 0:
            candidates["count_in_existence_condition"].append({"file": f, "score": score})

        # Doubly-nested wildcards
        if p["fields"]["doubly_nested_wildcard"] > 0:
            candidates["doubly_nested_wildcard"].append({"file": f, "score": score,
                "fields": p["fields"]["doubly_nested_fields"]})

        # Double negation with 3+ types
        if len(p["double_negation"]) >= 3:
            candidates["diverse_double_negation"].append({"file": f, "score": score,
                "types": list(p["double_negation"].keys())})

        # Dynamic fields
        if p["dynamic_fields"]:
            candidates["dynamic_fields"].append({"file": f, "score": score})

        # current() usage
        if p["uses_current"]:
            candidates["uses_current"].append({"file": f, "score": score})

        # 3+ Modify operations
        if p["details"].get("modify_operations", 0) >= 3:
            candidates["multi_modify_ops"].append({"file": f, "score": score,
                "ops": p["details"]["modify_operations"]})

        # Conditional Modify operations
        if p["details"].get("conditional_operations", 0) > 0:
            candidates["conditional_modify"].append({"file": f, "score": score})

        # Rare functions
        rare = {"iprangecontains", "requestcontext", "first", "last",
                "replace", "padleft", "empty"}
        used_rare = [fn for fn in p["function_counts"] if fn in rare]
        if used_rare:
            candidates["rare_functions"].append({"file": f, "score": score,
                "functions": used_rare})

        # 4+ function nesting depth
        if p["function_max_nesting"] >= 4:
            candidates["deep_function_nesting"].append({"file": f, "score": score,
                "depth": p["function_max_nesting"]})

        # 10+ unique fields
        if p["fields"]["total"] >= 10:
            candidates["many_fields"].append({"file": f, "score": score,
                "count": p["fields"]["total"]})

    # Sort each candidate list by score descending
    for cat in candidates:
        candidates[cat].sort(key=lambda x: x["score"], reverse=True)

    return dict(candidates)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def find_policy_files(directory):
    """Find all .json files in a directory tree."""
    files = []
    for root, dirs, filenames in os.walk(directory):
        for fname in filenames:
            if fname.endswith(".json"):
                files.append(os.path.join(root, fname))
    return sorted(files)


def main():
    parser = argparse.ArgumentParser(
        description="Analyze Azure Policy definitions for complexity and features."
    )
    parser.add_argument("policy_dir", help="Directory containing policy JSON files")
    parser.add_argument("--out", "-o", help="Output JSON file path (default: stdout summary)")
    parser.add_argument("--top", "-t", type=int, default=30,
                        help="Number of top policies to display (default: 30)")
    args = parser.parse_args()

    policy_dir = os.path.expanduser(args.policy_dir)
    if not os.path.isdir(policy_dir):
        print(f"Error: {policy_dir} is not a directory", file=sys.stderr)
        sys.exit(1)

    files = find_policy_files(policy_dir)
    print(f"Found {len(files)} JSON files in {policy_dir}", file=sys.stderr)

    policies = []
    skipped = 0
    for filepath in files:
        metrics = analyze_policy(filepath)
        if metrics is None:
            skipped += 1
            continue
        # Store relative path
        metrics["file"] = os.path.relpath(filepath, policy_dir)
        policies.append(metrics)

    print(f"Analyzed {len(policies)} policies ({skipped} skipped/non-policy)",
          file=sys.stderr)

    # Sort by complexity score descending
    policies.sort(key=lambda p: p["complexity"]["total"], reverse=True)

    # Build report
    summary = build_summary(policies)
    candidates = flag_candidates(policies)

    report = {
        "summary": summary,
        "candidates": candidates,
        "policies": policies,
    }

    # Write full report if --out specified
    if args.out:
        out_path = os.path.expanduser(args.out)
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        print(f"Full report written to {out_path}", file=sys.stderr)

    # Print top N to stdout
    n = min(args.top, len(policies))
    print(f"\n{'='*100}")
    print(f"TOP {n} POLICIES BY COMPLEXITY SCORE")
    print(f"{'='*100}")
    print(f"{'Rank':<5} {'Score':>6} {'Struct':>7} {'OpDiv':>6} {'Field':>6} "
          f"{'Func':>5} {'Count':>6} {'XRes':>5} {'Patt':>5} {'Nodes':>6} "
          f"{'Depth':>5} {'Effect':<12} File")
    print(f"{'-'*5} {'-'*6} {'-'*7} {'-'*6} {'-'*6} "
          f"{'-'*5} {'-'*6} {'-'*5} {'-'*5} {'-'*6} "
          f"{'-'*5} {'-'*12} {'-'*40}")

    for i, p in enumerate(policies[:n]):
        c = p["complexity"]
        print(f"{i+1:<5} {c['total']:>6.1f} {c['structural']:>7.1f} "
              f"{c['operator_diversity']:>6} {c['field_score']:>6} "
              f"{c['function_score']:>5} {c['count_score']:>6} "
              f"{c['cross_resource']:>5} {c['pattern_score']:>5} "
              f"{p['condition_nodes']:>6} {p['max_depth']:>5} "
              f"{p['effect']['name']:<12} {p['file']}")

    # Print feature coverage summary
    print(f"\n{'='*60}")
    print("FEATURE COVERAGE")
    print(f"{'='*60}")
    fc = summary["feature_coverage"]
    total = summary["total_policies"]
    for feat, count in sorted(fc.items()):
        pct = 100 * count / total if total else 0
        bar = "#" * int(pct / 2)
        print(f"  {feat:<35} {count:>5} ({pct:>5.1f}%) {bar}")

    # Print candidate categories
    print(f"\n{'='*60}")
    print("CANDIDATE CATEGORIES (rare features)")
    print(f"{'='*60}")
    for cat, entries in sorted(candidates.items()):
        print(f"\n  {cat} ({len(entries)} policies):")
        for entry in entries[:5]:
            print(f"    [{entry['score']:>5.1f}] {entry['file']}")
        if len(entries) > 5:
            print(f"    ... and {len(entries) - 5} more")

    # Print effect distribution
    print(f"\n{'='*60}")
    print("EFFECT DISTRIBUTION")
    print(f"{'='*60}")
    for effect, count in summary["effect_distribution"].items():
        pct = 100 * count / total if total else 0
        bar = "#" * int(pct / 2)
        print(f"  {effect:<20} {count:>5} ({pct:>5.1f}%) {bar}")

    print(f"\n{'='*60}")
    print("COMPLEXITY PERCENTILES")
    print(f"{'='*60}")
    for pct, val in summary["complexity_percentiles"].items():
        print(f"  {pct:<5} {val:>6.1f}")


if __name__ == "__main__":
    main()
