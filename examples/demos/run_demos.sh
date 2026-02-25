#!/usr/bin/env bash
# ============================================================
# Z3 Symbolic Analysis – Interactive Demo Script
# ============================================================
# Showcases how the Z3-backed `analyze` subcommand can
# automatically synthesise concrete inputs that satisfy (or
# violate) Rego and Cedar policies.
#
# Prerequisites:
#   brew install z3          # Z3 SMT solver
#   # Build once:
#   BINDGEN_EXTRA_CLANG_ARGS="-I/opt/homebrew/include" \
#   LIBRARY_PATH="/opt/homebrew/lib" \
#   cargo build --example regorus --features z3-analysis,cedar,azure_policy
# ============================================================

set -euo pipefail
cd "$(dirname "$0")/../.."

BIN="cargo run --example regorus --features z3-analysis,cedar,azure_policy --"
export BINDGEN_EXTRA_CLANG_ARGS="${BINDGEN_EXTRA_CLANG_ARGS:--I/opt/homebrew/include}"
export LIBRARY_PATH="${LIBRARY_PATH:-/opt/homebrew/lib}"

# Helpers
sep()   { printf '\n%s\n' "$(printf '═%.0s' {1..70})"; }
title() { sep; printf '  %s\n' "$@"; sep; }
run()   { printf '\033[36m$ %s\033[0m\n' "$*"; "$@"; echo; }

# ==============================================================
title "DEMO 1 — Container Admission Controller" \
      "Policy: no privileged containers; no unencrypted" \
      "volumes on public hosts."
# ==============================================================

echo "▸ 1a) Find an input where the policy is VIOLATED (allow = false):"
run $BIN analyze \
  -d examples/demos/container_admission.rego \
  -e data.container_admission.allow \
  -o false \
  -i examples/demos/container_admission_input.json \
  -s examples/demos/container_admission_schema.json \
  --max-loops 3

echo "▸ 1b) Find a COMPLIANT input (allow = true):"
run $BIN analyze \
  -d examples/demos/container_admission.rego \
  -e data.container_admission.allow \
  -o true \
  -i examples/demos/container_admission_input.json \
  -s examples/demos/container_admission_schema.json \
  --max-loops 3

echo "▸ 1c) Targeted: violate ONLY via sensitive-container-on-public-host"
echo "   (cover line 101, avoid line 75 — the privileged check):"
run $BIN analyze \
  -d examples/demos/container_admission.rego \
  -e data.container_admission.allow \
  -o false \
  -l container_admission.rego:101 \
  --avoid-line container_admission.rego:75 \
  -i examples/demos/container_admission_input.json \
  -s examples/demos/container_admission_schema.json \
  --max-loops 3

# ==============================================================
title "DEMO 2 — Network Segmentation Compliance" \
      "Policy: DMZ services must not connect to internal DBs;" \
      "PII-handling services need encrypted connections."
# ==============================================================

echo "▸ 2a) Find a topology where compliance FAILS:"
run $BIN analyze \
  -d examples/demos/network_segmentation.rego \
  -e data.network_segmentation.compliant \
  -o false \
  -i examples/demos/network_segmentation_input.json \
  -s examples/demos/network_segmentation_schema.json \
  --max-loops 3

echo "▸ 2b) Targeted: fail ONLY via DMZ→internal-DB (cover line 99,"
echo "   avoid line 126 — the PII rule):"
run $BIN analyze \
  -d examples/demos/network_segmentation.rego \
  -e data.network_segmentation.compliant \
  -o false \
  -l network_segmentation.rego:99 \
  --avoid-line network_segmentation.rego:126 \
  -i examples/demos/network_segmentation_input.json \
  -s examples/demos/network_segmentation_schema.json \
  --max-loops 3

echo "▸ 2c) Targeted: fail ONLY via PII-over-unencrypted (cover line 126,"
echo "   avoid line 99 — the DMZ rule):"
run $BIN analyze \
  -d examples/demos/network_segmentation.rego \
  -e data.network_segmentation.compliant \
  -o false \
  -l network_segmentation.rego:126 \
  --avoid-line network_segmentation.rego:99 \
  -i examples/demos/network_segmentation_input.json \
  -s examples/demos/network_segmentation_schema.json \
  --max-loops 3

# ==============================================================
title "DEMO 3 — Server Infrastructure (classic OPA example)" \
      "Policy: no HTTP on public servers; no telnet anywhere."
# ==============================================================

echo "▸ 3a) Find input where allow = false (a violation exists):"
run $BIN analyze \
  -d examples/server/allowed_server.rego \
  -e data.example.allow \
  -o false \
  -i examples/server/input.json \
  -s examples/server/input_schema.json \
  --max-loops 3

echo "▸ 3b) Find input where allow = true (fully compliant):"
run $BIN analyze \
  -d examples/server/allowed_server.rego \
  -e data.example.allow \
  -o true \
  -i examples/server/input.json \
  -s examples/server/input_schema.json \
  --max-loops 3

# ==============================================================
title "DEMO 4 — Cedar: IAM Zero Trust" \
      "Policy: admin login requires MFA + internal IP." \
      "Forbid overrides if account is suspended."
# ==============================================================

echo "▸ 4a) Find a request that is PERMITTED:"
run $BIN analyze \
  -d examples/cedar/examples/iam_zero_trust/policy.cedar \
  -d examples/cedar/examples/iam_zero_trust/entities.json \
  -e cedar.authorize \
  -o 1

echo "▸ 4b) Insight: Z3 discovers that the principal must be in the"
echo "   admins group, the IP must start with \"10.\", MFA must be true,"
echo "   and suspended must be false — all from the policy alone."

# ==============================================================
title "DEMO 5 — Cedar: Healthcare (HIPAA-inspired)" \
      "Policy: doctors view records during hours with trusted device;" \
      "nurses can too, unless the patient is VIP."
# ==============================================================

echo "▸ 5a) Find a request that is PERMITTED:"
run $BIN analyze \
  -d examples/cedar/examples/hipaa_healthcare/policy.cedar \
  -d examples/cedar/examples/hipaa_healthcare/entities.json \
  -e cedar.authorize \
  -o 1

echo "▸ Insight: Z3 navigates the entity hierarchy (User→Role→Staff),"
echo "   department attribute matching, and numeric hour constraints."

# ==============================================================
title "DEMO 6 — Cedar: Financial Trading Platform" \
      "Policy: tiered trade limits with geo-fencing." \
      "Sanctions forbid all access from SANC-* regions."
# ==============================================================

echo "▸ 6a) Find a request that is PERMITTED (trade goes through):"
run $BIN analyze \
  -d examples/cedar/examples/financial_trading/policy.cedar \
  -d examples/cedar/examples/financial_trading/entities.json \
  -e cedar.authorize \
  -o 1

echo "▸ Insight: Z3 discovers the compliance officer path (no trade value"
echo "   or region constraints), or a trader path with US-* region and"
echo "   trade_value ≤ limit."

# ==============================================================
title "DEMO 7 — Cedar: Kubernetes RBAC" \
      "Policy: tiered namespace access — developers read," \
      "SREs delete with ticket, admins do all. kube-system" \
      "delete is hard-denied for everyone."
# ==============================================================

echo "▸ 7a) Find a request that is PERMITTED:"
run $BIN analyze \
  -d examples/cedar/examples/k8s_rbac/policy.cedar \
  -d examples/cedar/examples/k8s_rbac/entities.json \
  -e cedar.authorize \
  -o 1

echo "▸ Insight: Z3 explores permit/forbid interplay — cluster-admins"
echo "   can read kube-system but the forbid blocks delete there."

# ==============================================================
title "DEMO 8 — SMT / Model File Dump" \
      "Dump the Z3 encoding and model to files for inspection."
# ==============================================================

echo "▸ 8a) Rego: container admission targeted query:"
run $BIN analyze \
  -d examples/demos/container_admission.rego \
  -e data.container_admission.allow \
  -o false \
  -l container_admission.rego:101 \
  --avoid-line container_admission.rego:75 \
  -i examples/demos/container_admission_input.json \
  -s examples/demos/container_admission_schema.json \
  --max-loops 3 \
  --dump-smt /tmp/demo.smt2 \
  --dump-model /tmp/demo.model

echo "SMT file: $(wc -l < /tmp/demo.smt2) lines  →  /tmp/demo.smt2"
echo "Model file: $(wc -l < /tmp/demo.model) lines  →  /tmp/demo.model"
echo
echo "First 15 lines of SMT encoding:"
head -15 /tmp/demo.smt2
echo "..."
echo
echo "First 15 lines of Z3 model (variable assignments):"
head -15 /tmp/demo.model
echo "..."

echo
echo "▸ 8b) Cedar: financial trading SMT encoding:"
run $BIN analyze \
  -d examples/cedar/examples/financial_trading/policy.cedar \
  -d examples/cedar/examples/financial_trading/entities.json \
  -e cedar.authorize \
  -o 1 \
  --dump-smt /tmp/cedar_demo.smt2 \
  --dump-model /tmp/cedar_demo.model

echo "SMT file: $(wc -l < /tmp/cedar_demo.smt2) lines  →  /tmp/cedar_demo.smt2"
echo "Model file: $(wc -l < /tmp/cedar_demo.model) lines  →  /tmp/cedar_demo.model"
echo
echo "Cedar SMT encoding (complete — much more compact than Rego):"
cat /tmp/cedar_demo.smt2
echo

# ==============================================================
# ==============================================================
#                PYTHON Z3 ANALYZER DEMOS
# ==============================================================
# ==============================================================
# The Python analyzer operates on pre-compiled RVM bytecode JSON
# files (checked in alongside the .rego policies).
#
# Prerequisites:
#   pip install z3-solver
#
# To regenerate the bytecode JSON files:
#   regorus compile -d <policy.rego> -e <entrypoint> -o <output.json>
# ==============================================================

DEMOS=examples/demos

title "DEMO 9 — Python Z3 Analyzer: Container Admission" \
      "Same policy as Demo 1, using python3 -m tools.z3analyze"

echo "▸ 9a) Find a VIOLATED input (allow = false):"
run python3 -m tools.z3analyze $DEMOS/container_admission_program.json \
  -e data.container_admission.allow -o false \
  --example-input $DEMOS/container_admission_input.json \
  --schema $DEMOS/container_admission_schema.json \
  --max-loop-depth 3

echo "▸ 9b) Find a COMPLIANT input (allow = true):"
run python3 -m tools.z3analyze $DEMOS/container_admission_program.json \
  -e data.container_admission.allow -o true \
  --example-input $DEMOS/container_admission_input.json \
  --schema $DEMOS/container_admission_schema.json \
  --max-loop-depth 3

echo "▸ 9c) Targeted: violate ONLY via sensitive-container-on-public-host"
echo "   (cover line 101, avoid line 75 — the privileged check):"
run python3 -m tools.z3analyze $DEMOS/container_admission_program.json \
  -e data.container_admission.allow -o false \
  --cover-line container_admission.rego 101 \
  --avoid-line container_admission.rego 75 \
  --example-input $DEMOS/container_admission_input.json \
  --schema $DEMOS/container_admission_schema.json \
  --max-loop-depth 3

# ==============================================================
title "DEMO 10 — Python Z3 Analyzer: Network Segmentation" \
      "Same policy as Demo 2, using python3 -m tools.z3analyze"
# ==============================================================

echo "▸ 10a) Find a non-compliant topology:"
run python3 -m tools.z3analyze $DEMOS/network_segmentation_program.json \
  -e data.network_segmentation.compliant -o false \
  --example-input $DEMOS/network_segmentation_input.json \
  --schema $DEMOS/network_segmentation_schema.json \
  --max-loop-depth 3

echo "▸ 10b) Targeted: fail ONLY via DMZ→internal-DB (cover line 99,"
echo "   avoid line 126 — the PII rule):"
run python3 -m tools.z3analyze $DEMOS/network_segmentation_program.json \
  -e data.network_segmentation.compliant -o false \
  --cover-line network_segmentation.rego 99 \
  --avoid-line network_segmentation.rego 126 \
  --example-input $DEMOS/network_segmentation_input.json \
  --schema $DEMOS/network_segmentation_schema.json \
  --max-loop-depth 3

echo "▸ 10c) Targeted: fail ONLY via PII-over-unencrypted (cover line 126,"
echo "   avoid line 99 — the DMZ rule):"
run python3 -m tools.z3analyze $DEMOS/network_segmentation_program.json \
  -e data.network_segmentation.compliant -o false \
  --cover-line network_segmentation.rego 126 \
  --avoid-line network_segmentation.rego 99 \
  --example-input $DEMOS/network_segmentation_input.json \
  --schema $DEMOS/network_segmentation_schema.json \
  --max-loop-depth 3

# ==============================================================
title "DEMO 11 — Python Z3 Analyzer: Server Infrastructure" \
      "Same policy as Demo 3, using python3 -m tools.z3analyze"
# ==============================================================

echo "▸ 11a) Find input where allow = false (a violation exists):"
run python3 -m tools.z3analyze $DEMOS/allowed_server_program.json \
  -e data.example.allow -o false \
  --example-input examples/server/input.json \
  --schema examples/server/input_schema.json \
  --max-loop-depth 3

echo "▸ 11b) Find input where allow = true (fully compliant):"
run python3 -m tools.z3analyze $DEMOS/allowed_server_program.json \
  -e data.example.allow -o true \
  --example-input examples/server/input.json \
  --schema examples/server/input_schema.json \
  --max-loop-depth 3

# ==============================================================
#            PYTHON Z3 ANALYZER — CEDAR DEMOS
# ==============================================================
# These demos mirror the Rust Cedar demos (4–7) using the Python
# analyzer with pre-compiled Cedar bytecode JSON files.
#
# Cedar bytecode is produced with:
#   regorus cedar compile -p <policy.cedar> -o <output.json>
#
# Entity graphs are passed via --concrete-input entities <file>.
# ==============================================================

CEDAR=examples/cedar/examples

# ==============================================================
title "DEMO 12 — Python Cedar: IAM Zero Trust" \
      "Same policy as Demo 4, using python3 -m tools.z3analyze"
# ==============================================================

echo "▸ 12a) Find a PERMITTED request:"
run python3 -m tools.z3analyze $DEMOS/iam_zero_trust_program.json \
  -e cedar.authorize -o 1 \
  --concrete-input entities $CEDAR/iam_zero_trust/entities.json

echo "▸ 12b) Find a DENIED request:"
run python3 -m tools.z3analyze $DEMOS/iam_zero_trust_program.json \
  -e cedar.authorize -o 0 \
  --concrete-input entities $CEDAR/iam_zero_trust/entities.json

# ==============================================================
title "DEMO 13 — Python Cedar: Healthcare (HIPAA-inspired)" \
      "Same policy as Demo 5, using python3 -m tools.z3analyze"
# ==============================================================

echo "▸ 13a) Find a PERMITTED request:"
run python3 -m tools.z3analyze $DEMOS/hipaa_healthcare_program.json \
  -e cedar.authorize -o 1 \
  --concrete-input entities $CEDAR/hipaa_healthcare/entities.json

# ==============================================================
title "DEMO 14 — Python Cedar: Financial Trading" \
      "Same policy as Demo 6, using python3 -m tools.z3analyze"
# ==============================================================

echo "▸ 14a) Find a PERMITTED trade:"
run python3 -m tools.z3analyze $DEMOS/financial_trading_program.json \
  -e cedar.authorize -o 1 \
  --concrete-input entities $CEDAR/financial_trading/entities.json

# ==============================================================
title "DEMO 15 — Python Cedar: Kubernetes RBAC" \
      "Same policy as Demo 7, using python3 -m tools.z3analyze"
# ==============================================================

echo "▸ 15a) Find a PERMITTED request:"
run python3 -m tools.z3analyze $DEMOS/k8s_rbac_program.json \
  -e cedar.authorize -o 1 \
  --concrete-input entities $CEDAR/k8s_rbac/entities.json

# ==============================================================
# ==============================================================
#           POLICY DIFF / SUBSUMPTION / TEST GEN DEMOS
# ==============================================================
# ==============================================================
# These demos exercise the new diff, subsumes, and gen-tests
# subcommands using the server infrastructure policy.
# ==============================================================

# ==============================================================
title "DEMO 16 — Policy Diff" \
      "Compare allowed_server.rego (v1 — bans telnet)" \
      "with allowed_server_v2.rego (v2 — telnet rule removed)."
# ==============================================================

echo "▸ 16a) Find a distinguishing input between v1 and v2:"
run $BIN diff \
  --policy1 examples/server/allowed_server.rego \
  --policy2 examples/server/allowed_server_v2.rego \
  -e data.example.allow \
  -i examples/server/input.json \
  -s examples/server/input_schema.json \
  --max-loops 3

echo "▸ Insight: Z3 finds an input with a telnet server — v1 denies it"
echo "   but v2 allows it, since v2 removed the telnet ban rule."

# ==============================================================
title "DEMO 17 — Policy Subsumption" \
      "Check whether one policy is at least as permissive" \
      "as another (∀ input: old permits → new permits)."
# ==============================================================

echo "▸ 17a) Does v2 subsume v1? (v2 is more permissive → expect yes):"
run $BIN subsumes \
  --old examples/server/allowed_server.rego \
  --new examples/server/allowed_server_v2.rego \
  -e data.example.allow \
  -i examples/server/input.json \
  -s examples/server/input_schema.json \
  --max-loops 3

echo "▸ 17b) Does v1 subsume v2? (v1 is stricter → expect no):"
run $BIN subsumes \
  --old examples/server/allowed_server_v2.rego \
  --new examples/server/allowed_server.rego \
  -e data.example.allow \
  -i examples/server/input.json \
  -s examples/server/input_schema.json \
  --max-loops 3

echo "▸ Insight: v2⊇v1 holds (every allow under v1 is also allowed under v2)."
echo "   v1⊇v2 fails — Z3 provides a counterexample with a telnet server"
echo "   that v2 allows but v1 denies."

# ==============================================================
title "DEMO 18 — Test Suite Generation" \
      "Automatically generate test inputs that cover all" \
      "reachable source lines in the server policy."
# ==============================================================

echo "▸ 18a) Generate tests targeting allow = false:"
run $BIN gen-tests \
  -d examples/server/allowed_server.rego \
  -e data.example.allow \
  -o false \
  -i examples/server/input.json \
  -s examples/server/input_schema.json \
  --max-loops 3 \
  --max-tests 10

echo "▸ 18b) Generate tests for all paths (no output constraint):"
run $BIN gen-tests \
  -d examples/server/allowed_server.rego \
  -e data.example.allow \
  -i examples/server/input.json \
  -s examples/server/input_schema.json \
  --max-loops 3 \
  --max-tests 10

echo "▸ Insight: With -o false, 2 test cases cover 100% of lines."
echo "   Without -o, a few more tests are needed to also cover the"
echo "   allow=true paths."

# ==============================================================
title "DEMO 19 — Network Segmentation: Diff v1 vs v2" \
      "v2 uses object-comprehension maps, function rules," \
      "and \`every\` — plus drops the PII rule (more permissive)."
# ==============================================================

echo "▸ 19a) Find a distinguishing input between v1 and v2:"
run $BIN diff \
  --policy1 examples/demos/network_segmentation.rego \
  --policy2 examples/demos/network_segmentation_v2.rego \
  -e data.network_segmentation.compliant \
  -i examples/demos/network_segmentation_input.json \
  -s examples/demos/network_segmentation_schema.json \
  --max-loops 3

echo "▸ Insight: Z3 finds a PII-related input — a service handling"
echo "   PII with an unencrypted connection.  v1 flags it, v2 allows it"
echo "   because v2 dropped the PII rule."

# ==============================================================
title "DEMO 20 — Network Segmentation: Subsumption v1 vs v2" \
      "Prove v2 ⊇ v1 (v2 is more permissive) and" \
      "disprove v1 ⊇ v2 (with counterexample)."
# ==============================================================

echo "▸ 20a) Does v2 subsume v1? (v2 is more permissive → expect yes):"
run $BIN subsumes \
  --old examples/demos/network_segmentation.rego \
  --new examples/demos/network_segmentation_v2.rego \
  -e data.network_segmentation.compliant \
  -i examples/demos/network_segmentation_input.json \
  -s examples/demos/network_segmentation_schema.json \
  --max-loops 3

echo "▸ 20b) Does v1 subsume v2? (v1 is stricter → expect no):"
run $BIN subsumes \
  --old examples/demos/network_segmentation_v2.rego \
  --new examples/demos/network_segmentation.rego \
  -e data.network_segmentation.compliant \
  -i examples/demos/network_segmentation_input.json \
  -s examples/demos/network_segmentation_schema.json \
  --max-loops 3

echo "▸ Insight: v2⊇v1 holds — every compliant topology under v1 is also"
echo "   compliant under v2.  v1⊇v2 fails — Z3 provides a counterexample"
echo "   involving a PII service with an unencrypted connection."

# ==============================================================
title "DEMO 21 — Azure Policy: Input Synthesis" \
      "Find a resource that triggers effect=deny" \
      "(requires alias catalog via --azure-aliases)."
# ==============================================================

echo "▸ 21a) Find a Storage Account input that violates HTTPS-only policy (v1):"
run $BIN analyze \
  -d examples/demos/azure_storage_https_v1_definition.json \
  -e main \
  -o '"deny"' \
  --azure-aliases examples/demos/azure_policy_aliases.json \
  -i examples/demos/azure_storage_input.json \
  -s examples/demos/azure_storage_schema.json \
  --max-loops 3

echo "▸ Insight: Z3 drives supportsHttpsTrafficOnly=false while keeping"
echo "   resource.type fixed to Microsoft.Storage/storageAccounts."

# ==============================================================
title "DEMO 22 — Azure Policy Diff (v1 vs v2)" \
      "v2 adds minimumTlsVersion == TLS1_2 requirement" \
      "and should disagree with v1 on TLS-only violations."
# ==============================================================

echo "▸ 22a) Find a distinguishing input where outputs differ (target deny):"
run $BIN diff \
  --policy1 examples/demos/azure_storage_https_v1_definition.json \
  --policy2 examples/demos/azure_storage_https_v2_definition.json \
  -e main \
  -o '"deny"' \
  --azure-aliases examples/demos/azure_policy_aliases.json \
  -i examples/demos/azure_storage_input.json \
  -s examples/demos/azure_storage_schema.json \
  --max-loops 3

# ==============================================================
title "DEMO 23 — Azure Policy Subsumption (v1 vs v2)" \
      "Check strictness relation for deny behavior."
# ==============================================================

echo "▸ 23a) Does v2 subsume v1 for deny? (expect true):"
run $BIN subsumes \
  --old examples/demos/azure_storage_https_v1_definition.json \
  --new examples/demos/azure_storage_https_v2_definition.json \
  -e main \
  -o '"deny"' \
  --azure-aliases examples/demos/azure_policy_aliases.json \
  -i examples/demos/azure_storage_input.json \
  -s examples/demos/azure_storage_schema.json \
  --max-loops 3

echo "▸ 23b) Does v1 subsume v2 for deny? (expect false):"
run $BIN subsumes \
  --old examples/demos/azure_storage_https_v2_definition.json \
  --new examples/demos/azure_storage_https_v1_definition.json \
  -e main \
  -o '"deny"' \
  --azure-aliases examples/demos/azure_policy_aliases.json \
  -i examples/demos/azure_storage_input.json \
  -s examples/demos/azure_storage_schema.json \
  --max-loops 3

# ==============================================================
title "DEMO 24 — Azure Policy Test Generation" \
      "Generate deny-oriented tests for the stricter v2 policy."
# ==============================================================

echo "▸ 24a) Generate test cases targeting output=deny:"
run $BIN gen-tests \
  -d examples/demos/azure_storage_https_v2_definition.json \
  -e main \
  -o '"deny"' \
  --azure-aliases examples/demos/azure_policy_aliases.json \
  -i examples/demos/azure_storage_input.json \
  -s examples/demos/azure_storage_schema.json \
  --max-loops 3 \
  --max-tests 10

# ==============================================================
title "DEMOS 25–28 — SQL Server Hardening (3-Policy Lattice)" \
      "V1: inbound focus (public access)" \
      "V2: outbound focus (restrict outbound)" \
      "V3: balanced (public AND outbound)." \
      "Z3 proves the full subsumption lattice."
# ==============================================================

echo "▸ 25a) Analyze SQL V1 (deny synthesis):"
run $BIN analyze \
  -d examples/demos/azure_sql_v1_definition.json \
  -e main -o '"deny"' \
  --azure-aliases examples/demos/azure_policy_aliases.json \
  -s examples/demos/azure_sql_schema.json

echo "▸ 25b) Analyze SQL V2:"
run $BIN analyze \
  -d examples/demos/azure_sql_v2_definition.json \
  -e main -o '"deny"' \
  --azure-aliases examples/demos/azure_policy_aliases.json \
  -s examples/demos/azure_sql_schema.json

echo "▸ 25c) Analyze SQL V3:"
run $BIN analyze \
  -d examples/demos/azure_sql_v3_definition.json \
  -e main -o '"deny"' \
  --azure-aliases examples/demos/azure_policy_aliases.json \
  -s examples/demos/azure_sql_schema.json

echo "▸ 26) Diff V1 vs V2 (expect not equivalent — orthogonal concerns):"
run $BIN diff \
  --policy1 examples/demos/azure_sql_v1_definition.json \
  --policy2 examples/demos/azure_sql_v2_definition.json \
  -e main -o '"deny"' \
  --azure-aliases examples/demos/azure_policy_aliases.json \
  -s examples/demos/azure_sql_schema.json

echo "▸ 27a) Subsumes: V1 ⊇ V3? (expect true — V1 is stricter):"
run $BIN subsumes \
  --old examples/demos/azure_sql_v3_definition.json \
  --new examples/demos/azure_sql_v1_definition.json \
  -e main -o '"deny"' \
  --azure-aliases examples/demos/azure_policy_aliases.json \
  -s examples/demos/azure_sql_schema.json

echo "▸ 27b) Subsumes: V3 ⊇ V1? (expect false):"
run $BIN subsumes \
  --old examples/demos/azure_sql_v1_definition.json \
  --new examples/demos/azure_sql_v3_definition.json \
  -e main -o '"deny"' \
  --azure-aliases examples/demos/azure_policy_aliases.json \
  -s examples/demos/azure_sql_schema.json

echo "▸ 27c) Subsumes: V2 ⊇ V3? (expect true — V2 is stricter):"
run $BIN subsumes \
  --old examples/demos/azure_sql_v3_definition.json \
  --new examples/demos/azure_sql_v2_definition.json \
  -e main -o '"deny"' \
  --azure-aliases examples/demos/azure_policy_aliases.json \
  -s examples/demos/azure_sql_schema.json

echo "▸ 27d) Subsumes: V1 ⊇ V2? (expect false — incomparable):"
run $BIN subsumes \
  --old examples/demos/azure_sql_v2_definition.json \
  --new examples/demos/azure_sql_v1_definition.json \
  -e main -o '"deny"' \
  --azure-aliases examples/demos/azure_policy_aliases.json \
  -s examples/demos/azure_sql_schema.json

echo "▸ 27e) Subsumes: V2 ⊇ V1? (expect false — incomparable):"
run $BIN subsumes \
  --old examples/demos/azure_sql_v1_definition.json \
  --new examples/demos/azure_sql_v2_definition.json \
  -e main -o '"deny"' \
  --azure-aliases examples/demos/azure_policy_aliases.json \
  -s examples/demos/azure_sql_schema.json

echo "▸ 28) Test generation for SQL V3:"
run $BIN gen-tests \
  -d examples/demos/azure_sql_v3_definition.json \
  -e main \
  --azure-aliases examples/demos/azure_policy_aliases.json \
  -s examples/demos/azure_sql_schema.json \
  --max-loops 3 --max-tests 10

# ==============================================================
title "DEMOS 29–33 — Key Vault Enterprise Hardening" \
      "Migration Safety + Gap Analysis." \
      "6 fields, 3 nesting levels, 3 compliance groups." \
      "Original vs De Morgan refactoring vs buggy vs incomplete."
# ==============================================================

echo "▸ 29) Analyze original Key Vault baseline (deny synthesis):"
run $BIN analyze \
  -d examples/demos/azure_keyvault_original_definition.json \
  -e main -o '"deny"' \
  --azure-aliases examples/demos/azure_policy_aliases.json \
  -s examples/demos/azure_keyvault_schema.json

echo "▸ 30) Migration Safety: diff original vs refactored (expect equivalent):"
echo "   Full De Morgan inversion — every operator at every level is flipped."
run $BIN diff \
  --policy1 examples/demos/azure_keyvault_original_definition.json \
  --policy2 examples/demos/azure_keyvault_refactored_definition.json \
  -e main -o '"deny"' \
  --azure-aliases examples/demos/azure_policy_aliases.json \
  -s examples/demos/azure_keyvault_schema.json

echo "▸ 31) Migration Safety: diff original vs BUGGY refactoring (expect NOT equivalent):"
echo "   Bug: allOf instead of anyOf in access-control group."
run $BIN diff \
  --policy1 examples/demos/azure_keyvault_original_definition.json \
  --policy2 examples/demos/azure_keyvault_buggy_refactor_definition.json \
  -e main -o '"deny"' \
  --azure-aliases examples/demos/azure_policy_aliases.json \
  -s examples/demos/azure_keyvault_schema.json

echo "▸ 32) Gap Analysis: does original subsume incomplete? (expect false):"
echo "   Incomplete policy drops the RBAC requirement for premium vaults."
run $BIN subsumes \
  --old examples/demos/azure_keyvault_original_definition.json \
  --new examples/demos/azure_keyvault_incomplete_definition.json \
  -e main -o '"deny"' \
  --azure-aliases examples/demos/azure_policy_aliases.json \
  -s examples/demos/azure_keyvault_schema.json

echo "▸ 33) Gap Analysis: does incomplete subsume original? (expect true):"
echo "   Original is strictly more restrictive — covers everything incomplete does."
run $BIN subsumes \
  --old examples/demos/azure_keyvault_incomplete_definition.json \
  --new examples/demos/azure_keyvault_original_definition.json \
  -e main -o '"deny"' \
  --azure-aliases examples/demos/azure_policy_aliases.json \
  -s examples/demos/azure_keyvault_schema.json

sep
echo "  All demos completed successfully."
sep
