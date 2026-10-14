# scripts/audit.ps1 — Local supply-chain audit runner (Windows/PowerShell)
# Runs the same checks as CI: secret patterns, cargo audit, cargo deny, cargo vet, OSV Scanner.
# Usage: pwsh scripts/audit.ps1
#Requires -Version 5.1
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$WorkspaceRoot = Split-Path -Parent $ScriptDir
Set-Location $WorkspaceRoot

$Errors = 0

function Write-Pass { param($Msg) Write-Host "[PASS] $Msg" -ForegroundColor Green }
function Write-Warn { param($Msg) Write-Host "[WARN] $Msg" -ForegroundColor Yellow }
function Write-Fail { param($Msg) Write-Host "[FAIL] $Msg" -ForegroundColor Red }

Write-Host "=== SunLitSecurityLibraries Supply-Chain Audit ===" -ForegroundColor Cyan
Write-Host "Workspace: $WorkspaceRoot"
Write-Host ""

# ── Step 0: high-confidence secret patterns ──────────────────────────────────
Write-Host "--- secret pattern scan ---"
$SecretPattern = 'AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|(^|[^[:alnum:]_])gh[pousr]_[A-Za-z0-9_]{36,}|github_pat_[A-Za-z0-9_]{22,}_[A-Za-z0-9_]{59,}|xox[baprs]-[A-Za-z0-9-]{10,}|(^|[^[:alnum:]_])sk-[A-Za-z0-9]{20,}|AIza[0-9A-Za-z_-]{35}|BEGIN (RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY'
$Matches = git grep -n -I -E $SecretPattern -- . ':!Cargo.lock'
if ($LASTEXITCODE -eq 0 -and $Matches) {
    $Matches | ForEach-Object { Write-Host $_ }
    Write-Fail "secret pattern scan — high-confidence matches found"
    $Errors++
} else {
    Write-Pass "secret pattern scan — no high-confidence matches"
}
Write-Host ""

# ── Step 1: cargo audit ───────────────────────────────────────────────────────
Write-Host "--- cargo audit ---"
$cargoAudit = Get-Command cargo-audit -ErrorAction SilentlyContinue
if (-not $cargoAudit) {
    Write-Warn "cargo-audit not installed. Use tools/security-toolchains/README.md for admitted tools"
    $Errors++
} else {
    cargo audit
    if ($LASTEXITCODE -eq 0) {
        Write-Pass "cargo audit — no vulnerabilities"
    } else {
        Write-Fail "cargo audit — advisories found"
        $Errors++
    }
}
Write-Host ""

# ── Step 2: cargo deny ────────────────────────────────────────────────────────
Write-Host "--- cargo deny check ---"
$cargoDeny = Get-Command cargo-deny -ErrorAction SilentlyContinue
if (-not $cargoDeny) {
    Write-Warn "cargo-deny not installed. Use tools/security-toolchains/README.md for admitted tools"
    $Errors++
} else {
    cargo deny check
    if ($LASTEXITCODE -eq 0) {
        Write-Pass "cargo deny — advisories, licenses, bans, sources all ok"
    } else {
        Write-Fail "cargo deny — check failed"
        $Errors++
    }
}
Write-Host ""

# ── Step 3: cargo vet ────────────────────────────────────────────────────────
Write-Host "--- cargo vet ---"
$cargoVet = Get-Command cargo-vet -ErrorAction SilentlyContinue
if (-not $cargoVet) {
    Write-Warn "cargo-vet not installed. Use tools/security-toolchains/README.md for admitted tools"
    $Errors++
} else {
    cargo vet
    if ($LASTEXITCODE -eq 0) {
        Write-Pass "cargo vet — all dependencies vetted"
    } else {
        Write-Fail "cargo vet — unvetted dependencies found"
        $Errors++
    }
}
Write-Host ""

# ── OSV admission (mandatory, pinned bootstrap) ───────────────────────────────
Write-Host "--- OSV dependency admission ---"
python scripts/osv-dependency-gate.py
if ($LASTEXITCODE -eq 0) {
    Write-Pass "OSV — complete resolved graph admitted"
} else {
    Write-Fail "OSV — dependency admission failed"
    $Errors++
}

# cargo-geiger is parked while its latest graph has unpatched advisories.

# ── Summary ──────────────────────────────────────────────────────────────────
Write-Host "=== Audit Summary ===" -ForegroundColor Cyan
if ($Errors -eq 0) {
    Write-Pass "All supply-chain checks passed."
    exit 0
} else {
    Write-Fail "$Errors check(s) failed."
    exit 1
}
