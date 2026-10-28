<#
.SYNOPSIS
    Automated Browser Integration Test Runner for Windows (Playwright E2E)
.DESCRIPTION
    Usage:
        .\run_e2e.ps1                  # Runs all suites with visible desktop browser (1000ms slowmo)
        .\run_e2e.ps1 -SlowMo 1500     # Custom slowdown pace (e.g. 1500ms)
        .\run_e2e.ps1 -Headless        # Runs all suites headless in background (CI/CD)
        .\run_e2e.ps1 -Fast            # Runs visible browser at full speed
        .\run_e2e.ps1 test_01          # Runs only test_01_auth_and_rbac.py
        .\run_e2e.ps1 test_02          # Runs only test_02_assets_and_remediation.py
        .\run_e2e.ps1 test_03          # Runs only test_03_alerts_lifecycle.py
        .\run_e2e.ps1 test_04          # Runs only test_04_misp_threat_intel.py
        .\run_e2e.ps1 test_05          # Runs only test_05_admin_governance.py
#>

[CmdletBinding()]
param(
    [switch]$Headless,
    [switch]$Fast,
    [int]$SlowMo = 1000,
    [string]$BaseUrl = $env:E2E_BASE_URL,
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$RemainingArgs
)

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# Locate pytest executable (Windows Scripts\ or Unix bin\)
$PytestPaths = @(
    (Join-Path $ScriptDir "backend\venv\Scripts\pytest.exe"),
    (Join-Path $ScriptDir "backend\venv\Scripts\pytest.bat"),
    (Join-Path $ScriptDir "backend\venv\bin\pytest")
)

$PytestCmd = $null
foreach ($path in $PytestPaths) {
    if (Test-Path $path) {
        $PytestCmd = $path
        break
    }
}

if (-not $PytestCmd) {
    $foundInPath = Get-Command pytest -ErrorAction SilentlyContinue
    if ($foundInPath) {
        $PytestCmd = "pytest"
    } else {
        Write-Error "❌ pytest not found in backend\venv\Scripts or system PATH. Please ensure the backend virtual environment is created and dependencies are installed."
        exit 1
    }
}

# Check if playwright is importable
$PythonPaths = @(
    (Join-Path $ScriptDir "backend\venv\Scripts\python.exe"),
    (Join-Path $ScriptDir "backend\venv\bin\python")
)
$PythonCmd = $null
foreach ($p in $PythonPaths) {
    if (Test-Path $p) {
        $PythonCmd = $p
        break
    }
}
if (-not $PythonCmd) {
    $foundPython = Get-Command python -ErrorAction SilentlyContinue
    if ($foundPython) { $PythonCmd = "python" }
}

if ($PythonCmd) {
    & $PythonCmd -c "import playwright" 2>$null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "======================================================================" -ForegroundColor Yellow
        Write-Host "⚠️  The 'playwright' package is not installed in your Python environment." -ForegroundColor Yellow
        Write-Host ""
        Write-Host "Please install it with:"
        Write-Host "  pip install playwright pytest-playwright"
        Write-Host "  python -m playwright install chromium"
        Write-Host "======================================================================" -ForegroundColor Yellow
        exit 1
    }
}

if (-not $BaseUrl) {
    $BaseUrl = "http://localhost:3000"
}
$env:E2E_BASE_URL = $BaseUrl

# Determine headed and slowmo flags
$PytestArgs = @("-v", "-s", "--tb=short")

if ($Headless) {
    $ModeText = "Headless (Background)"
} elseif ($Fast) {
    $PytestArgs += "--headed"
    $ModeText = "Visible Browser on Screen (Fast / No Slowdown)"
} else {
    $PytestArgs += @("--headed", "--slowmo", $SlowMo.ToString())
    $ModeText = "Visible Browser on Screen (--slowmo $SlowMo)"
}

# Resolve target test files from remaining arguments
$TargetArgs = @()
if ($RemainingArgs) {
    foreach ($arg in $RemainingArgs) {
        switch -Regex ($arg) {
            "test_01|auth_and_rbac" {
                $TargetArgs += (Join-Path $ScriptDir "tests_e2e\test_01_auth_and_rbac.py")
            }
            "test_02|assets_and_remediation" {
                $TargetArgs += (Join-Path $ScriptDir "tests_e2e\test_02_assets_and_remediation.py")
            }
            "test_03|alerts_lifecycle" {
                $TargetArgs += (Join-Path $ScriptDir "tests_e2e\test_03_alerts_lifecycle.py")
            }
            "test_04|misp_threat_intel" {
                $TargetArgs += (Join-Path $ScriptDir "tests_e2e\test_04_misp_threat_intel.py")
            }
            "test_05|admin_governance" {
                $TargetArgs += (Join-Path $ScriptDir "tests_e2e\test_05_admin_governance.py")
            }
            Default {
                $TargetArgs += $arg
            }
        }
    }
}

if ($TargetArgs.Count -eq 0) {
    $TargetArgs += (Join-Path $ScriptDir "tests_e2e")
}

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "🚀 Launching Automated Browser Integration Test Suite" -ForegroundColor Cyan
Write-Host "Target Base URL: $BaseUrl"
Write-Host "Mode: $ModeText"
Write-Host "Target: $($TargetArgs -join ' ')"
Write-Host "======================================================================" -ForegroundColor Cyan

& $PytestCmd @TargetArgs @PytestArgs
exit $LASTEXITCODE
