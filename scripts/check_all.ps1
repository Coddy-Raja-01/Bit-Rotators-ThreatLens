$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$python = Join-Path $root ".venv\Scripts\python.exe"

if (-not (Test-Path $python)) {
    $python = "python"
}

Push-Location $root
try {
    & $python -m unittest backend.tests.test_all
    if ($LASTEXITCODE -ne 0) {
        throw "Backend tests failed with exit code $LASTEXITCODE"
    }

    & $python -m compileall -q backend scripts
    if ($LASTEXITCODE -ne 0) {
        throw "Python compile check failed with exit code $LASTEXITCODE"
    }

    Write-Host "ThreatLens checks passed."
}
finally {
    Pop-Location
}
