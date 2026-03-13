// demos.js — Demo definitions for the Policy Intelligence web demo.
// Each demo describes: policy files, compilation strategy, analysis steps.

const P = "policies";
const C = "policies/cedar";

// ─── Operation types ────────────────────────────────────
// "analyze"   → compileProgram → prepareGenerateInput → solve → interpret
// "diff"      → compile two programs → preparePolicyDiff → solve → interpret
// "subsumes"  → compile two programs → preparePolicySubsumes → solve → interpret
// "smt-dump"  → same as analyze, but also show raw SMT + model

export const DEMOS = [
  // ── 0: Overview ──────────────────────────────────────────
  {
    id: "overview", title: "Overview",
    subtitle: "Select a demo to explore Z3-powered policy analysis.",
    overview: true,
  },

  // ── Playground (always last in tab bar) ───────────────
  {
    id: "playground", title: "Playground",
    subtitle: "Paste your own policy and analyze it with Z3.",
    playground: true,
  },

  // ── 1: Rego Input Synthesis ──────────────────────────
  {
    id: "synthesis", title: "Input Synthesis", lang: "rego",
    subtitle: "A simple server infrastructure policy: no HTTP on public servers, no telnet. Can Z3 find a concrete input that violates or satisfies the policy?",
    policyFiles: [
      { name: "allowed_server.rego", file: "allowed_server.rego", lang: "rego" },
    ],
    steps: [
      {
        label: "Find a violating input (allow = false)",
        op: "analyze",
        compile: { type: "rego", files: [`${P}/allowed_server.rego`] },
        entryPoint: "data.example.allow",
        desiredOutput: "false",
        config: {
          max_loop_depth: 3,
          example_input: `${P}/allowed_server_input.json`,
          input_schema: `${P}/allowed_server_schema.json`,
        },
        // CLI equivalent for display
        args: ["analyze", "-d", `${P}/allowed_server.rego`, "-e", "data.example.allow", "-o", "false",
               "-i", `${P}/allowed_server_input.json`, "-s", `${P}/allowed_server_schema.json`, "--max-loops", "3"],
        insight: "Z3 synthesized a concrete input with a server running the telnet protocol \u2014 the exact combination that triggers denial.",
        highlights: ["http", "telnet", "public"]
      },
      {
        label: "Find a compliant input (allow = true)",
        op: "analyze",
        compile: { type: "rego", files: [`${P}/allowed_server.rego`] },
        entryPoint: "data.example.allow",
        desiredOutput: "true",
        config: {
          max_loop_depth: 3,
          example_input: `${P}/allowed_server_input.json`,
          input_schema: `${P}/allowed_server_schema.json`,
        },
        args: ["analyze", "-d", `${P}/allowed_server.rego`, "-e", "data.example.allow", "-o", "true",
               "-i", `${P}/allowed_server_input.json`, "-s", `${P}/allowed_server_schema.json`, "--max-loops", "3"],
        insight: "Z3 found a fully compliant infrastructure \u2014 all HTTPS, no telnet, no public exposure.",
        highlights: ["https", "public"]
      },
      {
        label: "Targeted: public HTTP violation only (no telnet)",
        op: "analyze",
        compile: { type: "rego", files: [`${P}/allowed_server.rego`] },
        entryPoint: "data.example.allow",
        desiredOutput: "false",
        config: {
          max_loop_depth: 3,
          example_input: `${P}/allowed_server_input.json`,
          input_schema: `${P}/allowed_server_schema.json`,
          cover_lines: ["allowed_server.rego:11"],
          avoid_lines: ["allowed_server.rego:16"],
        },
        args: ["analyze", "-d", `${P}/allowed_server.rego`, "-e", "data.example.allow", "-o", "false",
               "-i", `${P}/allowed_server_input.json`, "-s", `${P}/allowed_server_schema.json`, "--max-loops", "3",
               "--cover-line", `${P}/allowed_server.rego:11`,
               "--avoid-line", `${P}/allowed_server.rego:16`],
        insight: "With --cover-line and --avoid-line, Z3 was forced through the public-HTTP path while avoiding the telnet path \u2014 surgical precision over which violation fires.",
        highlights: ["http", "public"]
      },
    ],
  },

  // ── 2: Cedar Authorization ───────────────────────────
  {
    id: "cedar", title: "Authorization", lang: "cedar",
    subtitle: "Cedar is Amazon's authorization policy language. Z3 symbolically solves permit/forbid rules, entity hierarchies, and context constraints to find valid or denied requests.",
    policyFiles: [
      { name: "IAM Zero Trust", file: "cedar/iam_zero_trust/policy.cedar", lang: "cedar" },
      { name: "Financial Trading", file: "cedar/financial_trading/policy.cedar", lang: "cedar" },
      { name: "K8s RBAC", file: "cedar/k8s_rbac/policy.cedar", lang: "cedar" },
    ],
    steps: [
      {
        label: "IAM Zero Trust \u2014 find a PERMITTED login (MFA + internal IP required)",
        op: "analyze",
        compile: { type: "cedar", policies: [`${C}/iam_zero_trust/policy.cedar`], entities: `${C}/iam_zero_trust/entities.json` },
        entryPoint: "cedar.authorize",
        desiredOutput: "1",
        config: {},
        args: ["analyze",
               "-d", `${C}/iam_zero_trust/policy.cedar`,
               "-d", `${C}/iam_zero_trust/entities.json`,
               "-e", "cedar.authorize", "-o", "1"],
        insight: "Z3 discovered the principal must be in the admins group, IP must start with \"10.\", MFA must be true, and suspended must be false \u2014 all from the policy alone.",
        highlights: ["mfa", "admins", "suspended", "10."]
      },
      {
        label: "Financial Trading \u2014 find a PERMITTED trade (tiered limits + geo-fencing)",
        op: "analyze",
        compile: { type: "cedar", policies: [`${C}/financial_trading/policy.cedar`], entities: `${C}/financial_trading/entities.json` },
        entryPoint: "cedar.authorize",
        desiredOutput: "1",
        config: {},
        args: ["analyze",
               "-d", `${C}/financial_trading/policy.cedar`,
               "-d", `${C}/financial_trading/entities.json`,
               "-e", "cedar.authorize", "-o", "1"],
        insight: "Z3 finds a valid trade: either a compliance officer (no value limit) or a trader with trade_value \u2264 limit, region US-*, and market open. It also avoids the SANC-* forbid.",
        highlights: ["trade_value", "SANC", "compliance_officer", "trader"]
      },
      {
        label: "K8s RBAC \u2014 find a PERMITTED K8s action (with forbid on kube-system delete)",
        op: "analyze",
        compile: { type: "cedar", policies: [`${C}/k8s_rbac/policy.cedar`], entities: `${C}/k8s_rbac/entities.json` },
        entryPoint: "cedar.authorize",
        desiredOutput: "1",
        config: {},
        args: ["analyze",
               "-d", `${C}/k8s_rbac/policy.cedar`,
               "-d", `${C}/k8s_rbac/entities.json`,
               "-e", "cedar.authorize", "-o", "1"],
        insight: "Z3 navigates the permit/forbid interplay: cluster-admins can read kube-system but the forbid blocks delete there.",
        highlights: ["kube-system", "delete", "cluster-admins"]
      },
    ],
  },

  // ── 3: Azure Policy Compliance ───────────────────────
  {
    id: "azurepolicy", title: "Compliance", lang: "azure",
    subtitle: "Azure Policy definitions compiled into Rego via regorus. Z3 finds resources that trigger deny effects and compares policy versions.",
    policyFiles: [
      { name: "Storage HTTPS v1", file: "azure_storage_https_v1_definition.json", lang: "json" },
      { name: "Storage HTTPS v2 (+TLS)", file: "azure_storage_https_v2_definition.json", lang: "json" },
    ],
    steps: [
      {
        label: "Find a Storage Account that violates HTTPS-only (deny)",
        op: "analyze",
        compile: { type: "azure", definition: `${P}/azure_storage_https_v1_definition.json`, aliases: `${P}/azure_policy_aliases.json` },
        entryPoint: "main",
        desiredOutput: '"deny"',
        config: {
          max_loop_depth: 3,
          example_input: `${P}/azure_storage_input.json`,
          input_schema: `${P}/azure_storage_schema.json`,
        },
        args: ["analyze",
               "-d", `${P}/azure_storage_https_v1_definition.json`,
               "-e", "main", "-o", "\"deny\"",
               "--azure-aliases", `${P}/azure_policy_aliases.json`,
               "-i", `${P}/azure_storage_input.json`,
               "-s", `${P}/azure_storage_schema.json`, "--max-loops", "3"],
        insight: "Z3 sets supportsHttpsTrafficOnly=false on a Microsoft.Storage/storageAccounts resource \u2014 the minimal trigger for deny.",
        highlights: ["supportsHttpsTrafficOnly", "minimumTlsVersion", "deny", "storageAccounts"]
      },
      {
        label: "Diff v1 vs v2 \u2014 v2 adds minimumTlsVersion \u2265 TLS1_2 requirement",
        op: "diff",
        compile1: { type: "azure", definition: `${P}/azure_storage_https_v1_definition.json`, aliases: `${P}/azure_policy_aliases.json` },
        compile2: { type: "azure", definition: `${P}/azure_storage_https_v2_definition.json`, aliases: `${P}/azure_policy_aliases.json` },
        entryPoint: "main",
        desiredOutput: '"deny"',
        config: {
          max_loop_depth: 3,
          example_input: `${P}/azure_storage_input.json`,
          input_schema: `${P}/azure_storage_schema.json`,
        },
        args: ["diff",
               "--policy1", `${P}/azure_storage_https_v1_definition.json`,
               "--policy2", `${P}/azure_storage_https_v2_definition.json`,
               "-e", "main", "-o", "\"deny\"",
               "--azure-aliases", `${P}/azure_policy_aliases.json`,
               "-i", `${P}/azure_storage_input.json`,
               "-s", `${P}/azure_storage_schema.json`, "--max-loops", "3"],
        insight: "Z3 found a resource with HTTPS enabled but TLS1_0 \u2014 v1 allows it (only checks HTTPS), v2 denies it (requires TLS \u2265 1.2). The new requirement is surfaced precisely.",
        highlights: ["supportsHttpsTrafficOnly", "minimumTlsVersion", "TLS1_0", "TLS1_2", "equivalent", "deny"]
      },
    ],
  },

  // ── 4: Cross-Collection Joins ────────────────────────
  {
    id: "joins", title: "Cross-Collection Joins", lang: "rego",
    subtitle: "Container admission controller with 3-way joins: containers \u00d7 volumes \u00d7 hosts. Z3 navigates the full combinatorial space symbolically.",
    policyFiles: [
      { name: "container_admission.rego", file: "container_admission.rego", lang: "rego" },
    ],
    steps: [
      {
        label: "Find a rejected deployment (allow = false)",
        op: "analyze",
        compile: { type: "rego", files: [`${P}/container_admission.rego`] },
        entryPoint: "data.container_admission.allow",
        desiredOutput: "false",
        config: {
          max_loop_depth: 3,
          example_input: `${P}/container_admission_input.json`,
          input_schema: `${P}/container_admission_schema.json`,
        },
        args: ["analyze", "-d", `${P}/container_admission.rego`, "-e", "data.container_admission.allow", "-o", "false",
               "-i", `${P}/container_admission_input.json`, "-s", `${P}/container_admission_schema.json`, "--max-loops", "3"],
        insight: "Z3 explored containers\u00d7volumes\u00d7hosts and found a deployment that violates the admission policy.",
        highlights: ["privileged", "public", "encrypted", "sensitive"]
      },
      {
        label: "Targeted: violate ONLY via sensitive-container-on-public-host (cover line 101, avoid line 75)",
        op: "analyze",
        compile: { type: "rego", files: [`${P}/container_admission.rego`] },
        entryPoint: "data.container_admission.allow",
        desiredOutput: "false",
        config: {
          max_loop_depth: 3,
          example_input: `${P}/container_admission_input.json`,
          input_schema: `${P}/container_admission_schema.json`,
          cover_lines: ["container_admission.rego:101"],
          avoid_lines: ["container_admission.rego:75"],
        },
        args: ["analyze", "-d", `${P}/container_admission.rego`, "-e", "data.container_admission.allow", "-o", "false",
               "-l", "container_admission.rego:101", "--avoid-line", "container_admission.rego:75",
               "-i", `${P}/container_admission_input.json`, "-s", `${P}/container_admission_schema.json`, "--max-loops", "3"],
        insight: "Z3 synthesized an unencrypted volume on a public host while avoiding the privileged-container path entirely \u2014 surgical precision.",
        highlights: ["privileged", "public", "encrypted", "sensitive"]
      },
    ],
  },

  // ── 5: Test Generation ─────────────────────────────
  {
    id: "testgen", title: "Test Generation", lang: "rego",
    subtitle: "Automatically generate test inputs that cover all reachable source lines and condition branches. Each Z3 call targets an uncovered line, and the model reveals which other lines were also hit — achieving maximum coverage in minimum tests.",
    policyFiles: [
      { name: "allowed_server.rego", file: "allowed_server.rego", lang: "rego" },
    ],
    steps: [
      {
        label: "Generate tests targeting allow = false",
        op: "gen-tests",
        compile: { type: "rego", files: [`${P}/allowed_server.rego`] },
        entryPoint: "data.example.allow",
        desiredOutput: "false",
        maxTests: 10,
        config: {
          max_loop_depth: 3,
          example_input: `${P}/allowed_server_input.json`,
          input_schema: `${P}/allowed_server_schema.json`,
        },
        args: ["gen-tests", "-d", `${P}/allowed_server.rego`, "-e", "data.example.allow", "-o", "false",
               "-i", `${P}/allowed_server_input.json`, "-s", `${P}/allowed_server_schema.json`, "--max-loops", "3", "--max-tests", "10"],
        insight: "Only 2 test cases are needed to cover 100% of reachable lines when targeting allow=false.",
        highlights: ["coverage", "line", "test"]
      },
      {
        label: "Generate tests for all paths (no output constraint)",
        op: "gen-tests",
        compile: { type: "rego", files: [`${P}/allowed_server.rego`] },
        entryPoint: "data.example.allow",
        maxTests: 10,
        config: {
          max_loop_depth: 3,
          example_input: `${P}/allowed_server_input.json`,
          input_schema: `${P}/allowed_server_schema.json`,
        },
        args: ["gen-tests", "-d", `${P}/allowed_server.rego`, "-e", "data.example.allow",
               "-i", `${P}/allowed_server_input.json`, "-s", `${P}/allowed_server_schema.json`, "--max-loops", "3", "--max-tests", "10"],
        insight: "Without an output constraint, the solver explores both allow=true and allow=false paths for broader coverage.",
        highlights: ["coverage", "line", "test"]
      },
      {
        label: "Condition coverage: exercise true & false branches",
        op: "gen-tests",
        compile: { type: "rego", files: [`${P}/allowed_server.rego`] },
        entryPoint: "data.example.allow",
        maxTests: 30,
        conditionCoverage: true,
        config: {
          max_loop_depth: 3,
          example_input: `${P}/allowed_server_input.json`,
          input_schema: `${P}/allowed_server_schema.json`,
        },
        args: ["gen-tests", "-d", `${P}/allowed_server.rego`, "-e", "data.example.allow",
               "-i", `${P}/allowed_server_input.json`, "-s", `${P}/allowed_server_schema.json`, "--max-loops", "3",
               "--condition-coverage", "--max-tests", "30"],
        insight: "After covering all lines (Phase 1), Z3 targets the false-branch of each boolean condition (Phase 2) — so every condition is tested both ways.",
        highlights: ["condition", "coverage", "true", "false"]
      },
    ],
  },

  // ── 6: Policy Diff ──────────────────────────────────
  {
    id: "diff", title: "Policy Diff", lang: "rego",
    subtitle: "Network segmentation v1 \u2192 v2: the refactored v2 dropped the PII encryption rule. Z3 finds the exact input where the two versions disagree.",
    policyFiles: [
      { name: "v1: network_segmentation.rego", file: "network_segmentation.rego", lang: "rego" },
      { name: "v2: network_segmentation_v2.rego", file: "network_segmentation_v2.rego", lang: "rego" },
    ],
    sideBySide: true,
    sideBySideLabels: ["v1 \u2014 network_segmentation.rego", "v2 \u2014 network_segmentation_v2.rego"],
    steps: [
      {
        label: "Find a distinguishing input between v1 and v2",
        op: "diff",
        compile1: { type: "rego", files: [`${P}/network_segmentation.rego`] },
        compile2: { type: "rego", files: [`${P}/network_segmentation_v2.rego`] },
        entryPoint: "data.network_segmentation.compliant",
        config: {
          max_loop_depth: 3,
          example_input: `${P}/network_segmentation_input.json`,
          input_schema: `${P}/network_segmentation_schema.json`,
        },
        args: ["diff", "--policy1", `${P}/network_segmentation.rego`, "--policy2", `${P}/network_segmentation_v2.rego`,
               "-e", "data.network_segmentation.compliant",
               "-i", `${P}/network_segmentation_input.json`, "-s", `${P}/network_segmentation_schema.json`, "--max-loops", "3"],
        insight: "Z3 found a PII-handling service with an unencrypted connection. v1 flags it as non-compliant; v2 allows it because the PII rule was dropped.",
        highlights: ["handles_pii", "encrypted", "equivalent"]
      },
    ],
  },

  // ── 7: Subsumption Proof ────────────────────────────
  {
    id: "subsumption", title: "Subsumption Proof", lang: "rego",
    subtitle: "Prove one policy is strictly more permissive than another \u2014 a \u2200-quantified guarantee over ALL possible inputs.",
    policyFiles: [
      { name: "v1: network_segmentation.rego", file: "network_segmentation.rego", lang: "rego" },
      { name: "v2: network_segmentation_v2.rego", file: "network_segmentation_v2.rego", lang: "rego" },
    ],
    sideBySide: true,
    sideBySideLabels: ["v1 \u2014 network_segmentation.rego", "v2 \u2014 network_segmentation_v2.rego"],
    steps: [
      {
        label: "Does v2 subsume v1? (v2 more permissive \u2192 expect YES)",
        op: "subsumes",
        compileOld: { type: "rego", files: [`${P}/network_segmentation.rego`] },
        compileNew: { type: "rego", files: [`${P}/network_segmentation_v2.rego`] },
        entryPoint: "data.network_segmentation.compliant",
        desiredOutput: "true",
        config: {
          max_loop_depth: 3,
          example_input: `${P}/network_segmentation_input.json`,
          input_schema: `${P}/network_segmentation_schema.json`,
        },
        args: ["subsumes", "--old", `${P}/network_segmentation.rego`, "--new", `${P}/network_segmentation_v2.rego`,
               "-e", "data.network_segmentation.compliant",
               "-i", `${P}/network_segmentation_input.json`, "-s", `${P}/network_segmentation_schema.json`, "--max-loops", "3"],
        insight: "PROVED: every compliant topology under v1 is also compliant under v2. Mathematical guarantee, not sampling.",
        highlights: ["subsumes", "counterexample"]
      },
      {
        label: "Does v1 subsume v2? (v1 stricter \u2192 expect NO with counterexample)",
        op: "subsumes",
        compileOld: { type: "rego", files: [`${P}/network_segmentation_v2.rego`] },
        compileNew: { type: "rego", files: [`${P}/network_segmentation.rego`] },
        entryPoint: "data.network_segmentation.compliant",
        desiredOutput: "true",
        config: {
          max_loop_depth: 3,
          example_input: `${P}/network_segmentation_input.json`,
          input_schema: `${P}/network_segmentation_schema.json`,
        },
        args: ["subsumes", "--old", `${P}/network_segmentation_v2.rego`, "--new", `${P}/network_segmentation.rego`,
               "-e", "data.network_segmentation.compliant",
               "-i", `${P}/network_segmentation_input.json`, "-s", `${P}/network_segmentation_schema.json`, "--max-loops", "3"],
        insight: "DISPROVED: Z3 provides a concrete counterexample \u2014 the PII topology that v2 allows but v1 denies.",
        highlights: ["subsumes", "counterexample", "handles_pii", "encrypted"]
      },
    ],
  },

  // ── 8: Bug Detection ────────────────────────────────
  {
    id: "bugdetect", title: "Bug Detection", lang: "azure",
    subtitle: "Key Vault enterprise hardening: 6 fields, 3 nesting levels. De Morgan refactoring \u2014 flip every operator. Can Z3 verify correctness or catch a subtle allOf\u2194anyOf bug?",
    policyFiles: [
      { name: "Original", file: "azure_keyvault_original_definition.json", lang: "json" },
      { name: "Refactored (correct)", file: "azure_keyvault_refactored_definition.json", lang: "json" },
      { name: "Buggy refactoring", file: "azure_keyvault_buggy_refactor_definition.json", lang: "json" },
    ],
    sideBySide: true,
    sideBySidePairs: [
      { leftIdx: 0, rightIdx: 1, leftLabel: "Original", rightLabel: "Refactored (correct)" },
      { leftIdx: 0, rightIdx: 2, leftLabel: "Original", rightLabel: "Buggy (allOf\u2194anyOf swap)" },
      { leftIdx: 1, rightIdx: 2, leftLabel: "Refactored (correct)", rightLabel: "Buggy (allOf\u2194anyOf swap)" },
    ],
    steps: [
      {
        label: "Diff: original vs correct De Morgan refactoring (expect EQUIVALENT)",
        op: "diff",
        pairIdx: 0,
        compile1: { type: "azure", definition: `${P}/azure_keyvault_original_definition.json`, aliases: `${P}/azure_policy_aliases.json` },
        compile2: { type: "azure", definition: `${P}/azure_keyvault_refactored_definition.json`, aliases: `${P}/azure_policy_aliases.json` },
        entryPoint: "main",
        desiredOutput: '"deny"',
        config: {
          input_schema: `${P}/azure_keyvault_schema.json`,
        },
        args: ["diff",
               "--policy1", `${P}/azure_keyvault_original_definition.json`,
               "--policy2", `${P}/azure_keyvault_refactored_definition.json`,
               "-e", "main", "-o", "\"deny\"",
               "--azure-aliases", `${P}/azure_policy_aliases.json`,
               "-s", `${P}/azure_keyvault_schema.json`],
        insight: "Policies are EQUIVALENT \u2014 the De Morgan refactoring is correct. Every operator flipped and semantics preserved.",
        highlights: ["equivalent"]
      },
      {
        label: "Diff: original vs BUGGY refactoring \u2014 allOf\u2194anyOf swap (expect NOT equivalent)",
        op: "diff",
        pairIdx: 1,
        compile1: { type: "azure", definition: `${P}/azure_keyvault_original_definition.json`, aliases: `${P}/azure_policy_aliases.json` },
        compile2: { type: "azure", definition: `${P}/azure_keyvault_buggy_refactor_definition.json`, aliases: `${P}/azure_policy_aliases.json` },
        entryPoint: "main",
        desiredOutput: '"deny"',
        config: {
          input_schema: `${P}/azure_keyvault_schema.json`,
        },
        args: ["diff",
               "--policy1", `${P}/azure_keyvault_original_definition.json`,
               "--policy2", `${P}/azure_keyvault_buggy_refactor_definition.json`,
               "-e", "main", "-o", "\"deny\"",
               "--azure-aliases", `${P}/azure_policy_aliases.json`,
               "-s", `${P}/azure_keyvault_schema.json`],
        insight: "NOT EQUIVALENT \u2014 Z3 found a concrete input where the buggy version disagrees. The allOf\u2194anyOf swap changed the semantics.",
        highlights: ["equivalent", "softDelete", "purgeProtection", "networkAcls", "deny"]
      },
      {
        label: "Diff: correct refactored vs BUGGY \u2014 spot the exact divergence",
        op: "diff",
        pairIdx: 2,
        compile1: { type: "azure", definition: `${P}/azure_keyvault_refactored_definition.json`, aliases: `${P}/azure_policy_aliases.json` },
        compile2: { type: "azure", definition: `${P}/azure_keyvault_buggy_refactor_definition.json`, aliases: `${P}/azure_policy_aliases.json` },
        entryPoint: "main",
        desiredOutput: '"deny"',
        config: {
          input_schema: `${P}/azure_keyvault_schema.json`,
        },
        args: ["diff",
               "--policy1", `${P}/azure_keyvault_refactored_definition.json`,
               "--policy2", `${P}/azure_keyvault_buggy_refactor_definition.json`,
               "-e", "main", "-o", "\"deny\"",
               "--azure-aliases", `${P}/azure_policy_aliases.json`,
               "-s", `${P}/azure_keyvault_schema.json`],
        insight: "NOT EQUIVALENT \u2014 the only difference between correct and buggy is the allOf\u2194anyOf swap. Z3 pinpoints the exact input that exposes it.",
        highlights: ["equivalent", "softDelete", "purgeProtection", "networkAcls", "deny"]
      },
    ],
  },

  // ── 9: Production Policy ────────────────────────────
  {
    id: "production", title: "Production Policy", lang: "rego",
    subtitle: "Verbatim AGS (Azure Graph Service) group governance policy using fetch() for HTTP calls. --model-fetch maps fetch() to symbolic input so Z3 reasons about all possible API responses.",
    policyFiles: [
      { name: "ags_group_governance_original.rego", file: "ags_group_governance_original.rego", lang: "rego" },
    ],
    steps: [
      {
        label: "Synthesize a deny input for the verbatim production policy",
        op: "analyze",
        compile: { type: "rego", files: [`${P}/ags_group_governance_original.rego`] },
        entryPoint: "data.graph.elm_governance_group_membership_9.deny",
        config: {
          example_input: `${P}/ags_group_governance_original_input.json`,
          input_schema: `${P}/ags_group_governance_original_schema.json`,
          fetch_input_path: "fetchResponse",
        },
        args: ["analyze", "-d", `${P}/ags_group_governance_original.rego`,
               "-e", "data.graph.elm_governance_group_membership_9.deny",
               "-i", `${P}/ags_group_governance_original_input.json`,
               "-s", `${P}/ags_group_governance_original_schema.json`,
               "--model-fetch", "fetchResponse"],
        insight: "Z3 explored all 5 decision paths (allowed-app, enforced, reportOnly, expected-error, unexpected-error) and synthesized a deny scenario.",
        highlights: ["managedState", "enforced", "reportOnly", "fetchResponse", "deny", "appid"]
      },
    ],
  },

  // ── 10: Under the Hood — SMT ────────────────────────
  {
    id: "smt", title: "Under the Hood", lang: "smt",
    subtitle: "Peek behind the curtain: see the actual SMT-LIB encoding that Z3 solves, and the model (variable assignments) it finds. This is what makes formal verification possible.",
    policyFiles: [
      { name: "IAM Zero Trust (Cedar)", file: "cedar/iam_zero_trust/policy.cedar", lang: "cedar" },
    ],
    steps: [
      {
        label: "Dump the SMT encoding for the Cedar IAM policy (compact!)",
        op: "smt-dump",
        compile: { type: "cedar", policies: [`${C}/iam_zero_trust/policy.cedar`], entities: `${C}/iam_zero_trust/entities.json` },
        entryPoint: "cedar.authorize",
        desiredOutput: "1",
        config: {},
        args: ["analyze",
               "-d", `${C}/iam_zero_trust/policy.cedar`,
               "-d", `${C}/iam_zero_trust/entities.json`,
               "-e", "cedar.authorize", "-o", "1",
               "--dump-smt", "/tmp/pi_demo.smt2",
               "--dump-model", "/tmp/pi_demo.model"],
        insight: "The --dump-smt flag writes the SMT-LIB encoding. Cedar policies compile into surprisingly compact SMT. The solver checks satisfiability over all possible inputs.",
        postFetch: ["smt", "model"],
      },
      {
        label: "Dump SMT for the Rego container admission policy (more complex)",
        op: "smt-dump",
        compile: { type: "rego", files: [`${P}/container_admission.rego`] },
        entryPoint: "data.container_admission.allow",
        desiredOutput: "false",
        config: {
          max_loop_depth: 3,
          example_input: `${P}/container_admission_input.json`,
          input_schema: `${P}/container_admission_schema.json`,
          cover_lines: ["container_admission.rego:101"],
          avoid_lines: ["container_admission.rego:75"],
        },
        args: ["analyze",
               "-d", `${P}/container_admission.rego`,
               "-e", "data.container_admission.allow", "-o", "false",
               "-l", "container_admission.rego:101",
               "--avoid-line", "container_admission.rego:75",
               "-i", `${P}/container_admission_input.json`,
               "-s", `${P}/container_admission_schema.json`,
               "--max-loops", "3",
               "--dump-smt", "/tmp/pi_demo.smt2",
               "--dump-model", "/tmp/pi_demo.model"],
        insight: "Rego policies with cross-collection joins produce much larger SMT encodings \u2014 but Z3 still solves them in seconds.",
        postFetch: ["smt", "model"],
      },
    ],
  },
];

// ═══════════════════════════════════════════════════════════
//  OVERVIEW CARD DATA
// ═══════════════════════════════════════════════════════════
export const OVERVIEW_CARDS = [
  { num: "Demo 1", title: "Rego: Input Synthesis", desc: "Find concrete inputs for any desired policy outcome.", tags: ["rego"], tabId: "synthesis" },
  { num: "Demo 2", title: "Cedar: Authorization", desc: "Permit/forbid with entity hierarchies, geo-fencing, RBAC.", tags: ["cedar"], tabId: "cedar" },
  { num: "Demo 3", title: "Azure Policy: Compliance", desc: "Storage HTTPS enforcement, policy version diff.", tags: ["azure"], tabId: "azurepolicy" },
  { num: "Demo 4", title: "Cross-Collection Joins", desc: "3-way joins: containers \u00d7 volumes \u00d7 hosts.", tags: ["rego"], tabId: "joins" },
  { num: "Demo 5", title: "Test Generation", desc: "Auto-generate test inputs for line & condition coverage.", tags: ["rego", "gen"], tabId: "testgen" },
  { num: "Demo 6", title: "Policy Diff", desc: "Find where two policy versions disagree (PII regression).", tags: ["rego", "diff"], tabId: "diff" },
  { num: "Demo 7", title: "Subsumption Proof", desc: "\u2200-quantified: prove one policy subsumes another.", tags: ["rego", "proof"], tabId: "subsumption" },
  { num: "Demo 8", title: "Bug Detection", desc: "Catch allOf\u2194anyOf bug in Key Vault refactoring.", tags: ["azure", "diff"], tabId: "bugdetect" },
  { num: "Demo 9", title: "Production Policy", desc: "Verbatim AGS governance with fetch() as symbolic input.", tags: ["rego", "fetch"], tabId: "production" },
  { num: "Demo 10", title: "Under the Hood: SMT", desc: "See the actual SMT-LIB encoding and Z3 model.", tags: ["smt"], tabId: "smt" },
  { num: "🔬", title: "Playground", desc: "Paste your own policy and run Z3 analysis interactively.", tags: ["rego", "cedar", "azure"], tabId: "playground" },
];

export const TAG_CLASSES = { rego: "tag-rego", azure: "tag-azure", cedar: "tag-cedar", diff: "tag-diff", proof: "tag-proof", gen: "tag-gen", fetch: "tag-fetch", smt: "tag-smt" };
export const LANG_BADGE = { rego: "lang-rego", cedar: "lang-cedar", azure: "lang-azure", smt: "lang-smt" };
