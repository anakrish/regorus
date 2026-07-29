# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# End-to-end check: compile a small policy to a portable RVM artifact and
# evaluate it with the `regorus` example binary.
#
#   pwsh examples/rvm_portable/e2e.ps1

$ErrorActionPreference = 'Stop'

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..' '..')
Push-Location $repoRoot
try {
    $fixtures = Join-Path 'examples' 'rvm_portable'
    $outDir = Join-Path 'target' 'rvm-artifacts'
    New-Item -ItemType Directory -Force -Path $outDir | Out-Null

    $artifact = Join-Path $outDir 'authz.rvmp'
    $listing = Join-Path $outDir 'authz.rvmasm'

    Write-Host '==> building the regorus example'
    cargo build --example regorus
    if ($LASTEXITCODE -ne 0) { throw 'cargo build failed' }

    $exe = Join-Path 'target' 'debug' 'examples' 'regorus.exe'
    if (-not (Test-Path $exe)) { $exe = Join-Path 'target' 'debug' 'examples' 'regorus' }

    Write-Host '==> compile-rvm (portable)'
    & $exe compile-rvm `
        --data (Join-Path $fixtures 'policy.rego') `
        --data (Join-Path $fixtures 'data.json') `
        --entrypoint data.example.authz.allow `
        --entrypoint data.example.authz.user_roles `
        --entrypoint data.example.authz.reason `
        --entrypoint data.example.authz.limits `
        --output $artifact `
        --listing $listing
    if ($LASTEXITCODE -ne 0) { throw 'compile-rvm failed' }

    Write-Host '==> eval-rvm --info'
    & $exe eval-rvm --info $artifact
    if ($LASTEXITCODE -ne 0) { throw 'eval-rvm --info failed' }

    Write-Host '==> eval-rvm data.example.authz.allow'
    $allow = & $exe eval-rvm `
        --data (Join-Path $fixtures 'data.json') `
        --input (Join-Path $fixtures 'input.json') `
        --entrypoint data.example.authz.allow `
        $artifact
    if ($LASTEXITCODE -ne 0) { throw 'eval-rvm failed' }
    if ($allow.Trim() -ne 'true') { throw "expected 'true', got '$allow'" }
    Write-Host "allow = $allow"

    Write-Host '==> eval-rvm data.example.authz.reason'
    & $exe eval-rvm `
        --data (Join-Path $fixtures 'data.json') `
        --input (Join-Path $fixtures 'input.json') `
        --entrypoint data.example.authz.reason `
        $artifact
    if ($LASTEXITCODE -ne 0) { throw 'eval-rvm failed' }

    Write-Host 'OK: portable artifact compiled and evaluated end to end.'
}
finally {
    Pop-Location
}
