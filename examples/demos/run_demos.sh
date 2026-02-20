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
#   cargo build --example regorus --features z3-analysis,cedar
# ============================================================

set -euo pipefail
cd "$(dirname "$0")/../.."

BIN="cargo run --example regorus --features z3-analysis,cedar --"
export BINDGEN_EXTRA_CLANG_ARGS="${BINDGEN_EXTRA_CLANG_ARGS:--I/opt/homebrew/include}"
export LIBRARY_PATH="${LIBRARY_PATH:-/opt/homebrew/lib}"

# Helpers
sep()   { printf '\n%s\n' "$(printf '═%.0s' {1..70})"; }
title() { sep; printf '  %s\n' "$@"; sep; }
run()   { printf '\033[36m$ %s\033[0m\n' "$*"; eval "$@"; echo; }

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

sep
echo "  All demos completed successfully."
sep
