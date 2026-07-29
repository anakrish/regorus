#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# End-to-end check: compile a small policy to a portable RVM artifact and
# evaluate it with the `regorus` example binary.
#
#   ./examples/rvm_portable/e2e.sh

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

fixtures="examples/rvm_portable"
out_dir="target/rvm-artifacts"
mkdir -p "$out_dir"

artifact="$out_dir/authz.rvmp"
listing="$out_dir/authz.rvmasm"

echo "==> building the regorus example"
cargo build --example regorus

exe="target/debug/examples/regorus"
[ -x "$exe" ] || exe="target/debug/examples/regorus.exe"

echo "==> compile-rvm (portable)"
"$exe" compile-rvm \
    --data "$fixtures/policy.rego" \
    --data "$fixtures/data.json" \
    --entrypoint data.example.authz.allow \
    --entrypoint data.example.authz.user_roles \
    --entrypoint data.example.authz.reason \
    --entrypoint data.example.authz.limits \
    --output "$artifact" \
    --listing "$listing"

echo "==> eval-rvm --info"
"$exe" eval-rvm --info "$artifact"

echo "==> eval-rvm data.example.authz.allow"
allow="$("$exe" eval-rvm \
    --data "$fixtures/data.json" \
    --input "$fixtures/input.json" \
    --entrypoint data.example.authz.allow \
    "$artifact")"
if [ "$allow" != "true" ]; then
    echo "expected 'true', got '$allow'" >&2
    exit 1
fi
echo "allow = $allow"

echo "==> eval-rvm data.example.authz.reason"
"$exe" eval-rvm \
    --data "$fixtures/data.json" \
    --input "$fixtures/input.json" \
    --entrypoint data.example.authz.reason \
    "$artifact"

echo "OK: portable artifact compiled and evaluated end to end."
