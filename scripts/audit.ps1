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
    Write-Warn "cargo-audit not installed. Run: cargo install cargo-audit"
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
    Write-Warn "cargo-deny not installed. Run: cargo install cargo-deny"
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
    Write-Warn "cargo-vet not installed. Run: cargo install cargo-vet"
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

# ── Step 4: OSV Scanner ─────────────────────────────────────────────────────
Write-Host "--- OSV Scanner ---"
$osvScanner = Get-Command osv-scanner -ErrorAction SilentlyContinue
if (-not $osvScanner) {
    Write-Warn "osv-scanner not installed. Install OSV Scanner v2.3.6 from https://github.com/google/osv-scanner/releases/tag/v2.3.6"
    $Errors++
} else {
    osv-scanner scan source -r .
    if ($LASTEXITCODE -eq 0) {
        Write-Pass "OSV Scanner — no unaccepted dependency vulnerabilities"
    } else {
        Write-Fail "OSV Scanner — unaccepted dependency vulnerabilities found"
        $Errors++
    }
}
Write-Host ""

# ── Step 5: cargo geiger (advisory) ──────────────────────────────────────────
# Surfaces transitive `unsafe` usage in the dependency tree. SunLit source is
# forbid(unsafe_code), so this measures what deps bring in. Advisory: failure
# does not count toward $Errors. JSON artifact is the audit evidence.
#
# cargo-geiger requires a root package (it cannot consume a virtual manifest).
# We use secure_reference_service because it depends on every library crate
# and is the closest analogue to a downstream consumer's BOM.
#
# See docs/dev-guide/unsafe-budget.md.
Write-Host "--- cargo geiger (advisory) ---"
$cargoGeiger = Get-Command cargo-geiger -ErrorAction SilentlyContinue
if (-not $cargoGeiger) {
    Write-Warn "cargo-geiger not installed. Run: cargo install --locked cargo-geiger --version 0.13.0"
} else {
    New-Item -ItemType Directory -Force -Path output | Out-Null
    Push-Location crates/secure_reference_service
    try {
        cargo geiger `
            --all-features `
            --output-format Json `
            --update-readme=false `
            | Out-File -FilePath ../../output/cargo-geiger.json -Encoding utf8
        if ($LASTEXITCODE -eq 0) {
            Write-Pass "cargo geiger — JSON artifact written to output/cargo-geiger.json"
        } else {
            Write-Warn "cargo geiger — non-zero exit (advisory); see output/cargo-geiger.json for details"
        }
    } finally {
        Pop-Location
    }
}
Write-Host ""

# ── Summary ──────────────────────────────────────────────────────────────────
Write-Host "=== Audit Summary ===" -ForegroundColor Cyan
if ($Errors -eq 0) {
    Write-Pass "All supply-chain checks passed."
    exit 0
} else {
    Write-Fail "$Errors check(s) failed."
    exit 1
}
