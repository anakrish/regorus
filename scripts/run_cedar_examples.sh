#!/usr/bin/env bash
set -euo pipefail

CEDAR_BIN_DEFAULT="$HOME/repos/cedar/target/debug/cedar"
CEDAR_BIN="${CEDAR_BIN:-$CEDAR_BIN_DEFAULT}"
HAVE_CEDAR=0

if [[ -x "$CEDAR_BIN" ]]; then
  HAVE_CEDAR=1
fi

run_case() {
  local name="$1"
  local base_dir="$2"
  local input_file="$3"
  local request_file="$4"
  local entities_file="$5"
  local label="$6"

  echo "== $name ($label) =="

  local regorus_log
  local regorus_out
  local regorus_status
  regorus_log=$(mktemp)
  set +e
  cargo run --example regorus --features cedar -- cedar authorize \
    -p "$base_dir/policy.cedar" \
    --input "$base_dir/$input_file" >"$regorus_log" 2>&1
  regorus_status=$?
  set -e
  regorus_out=$(tail -n 1 "$regorus_log")
  rm -f "$regorus_log"
  echo "regorus: $regorus_out (exit $regorus_status)"

  if [[ "$HAVE_CEDAR" -eq 1 ]]; then
    local cedar_log
    local cedar_out
    local cedar_status
    cedar_log=$(mktemp)
    set +e
    "$CEDAR_BIN" authorize \
      -p "$base_dir/policy.cedar" \
      --request-json "$base_dir/$request_file" \
      --entities "$base_dir/$entities_file" >"$cedar_log" 2>&1
    cedar_status=$?
    set -e
    cedar_out=$(tail -n 1 "$cedar_log")
    rm -f "$cedar_log"
    echo "cedar:   $cedar_out (exit $cedar_status)"

    if [[ "$regorus_out" == "$cedar_out" ]]; then
      echo "compare: OK"
    else
      echo "compare: MISMATCH"
    fi
  else
    echo "cedar:   skipped (CEDAR_BIN not found)"
  fi

  echo
}

run_case "quickstart" "examples/cedar/quickstart" \
  "input.json" "cedar_request.json" "cedar_entities.json" "positive"
run_case "quickstart" "examples/cedar/quickstart" \
  "input_deny.json" "cedar_request_deny.json" "cedar_entities_deny.json" "negative"

for name in iam_zero_trust cloud_resource_access saas_multi_tenant regulated_access content_system deny_overrides group_access resource_owner; do
  base_dir="examples/cedar/examples/$name"
  run_case "$name" "$base_dir" \
    "input.json" "cedar_request.json" "cedar_entities.json" "positive"
  run_case "$name" "$base_dir" \
    "input_deny.json" "cedar_request_deny.json" "cedar_entities_deny.json" "negative"
done
