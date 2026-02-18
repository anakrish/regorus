#!/usr/bin/env bash
# ============================================================
# Z3 Symbolic Analysis – Interactive Demo Script
# ============================================================
# Showcases how the Z3-backed `analyze` subcommand can
# automatically synthesise concrete inputs that satisfy (or
# violate) complex Rego policies.
#
# Prerequisites:
#   brew install z3          # Z3 SMT solver
#   # Build once:
#   BINDGEN_EXTRA_CLANG_ARGS="-I/opt/homebrew/include" \
#   LIBRARY_PATH="/opt/homebrew/lib" \
#   cargo build --example regorus --features z3-analysis
# ============================================================

set -euo pipefail
cd "$(dirname "$0")/../.."

BIN="cargo run --example regorus --features z3-analysis --"
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
title "DEMO 4 — SMT / Model File Dump" \
      "Dump the Z3 encoding and model to files for inspection."
# ==============================================================

echo "▸ Dumping SMT and model for the container admission targeted query:"
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

sep
echo "  All demos completed successfully."
sep
