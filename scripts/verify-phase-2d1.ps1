param(
    [string]$ProjectRoot = "D:\LuanVan\test\cyrp-platform-phase2"
)

$ErrorActionPreference = "Stop"

$required = @(
    "apps\ai-model\src\cyrp_ai_model.py",
    "apps\ai-model\train.py",
    "apps\ai-model\predict.py",
    "apps\ai-model\requirements.txt",
    "scripts\ai-cyrp-train.ps1",
    "scripts\ai-cyrp-export-input.ps1",
    "scripts\ai-cyrp-predict-from-db.ps1",
    "scripts\ai-cyrp-import-predictions.ps1"
)

foreach ($relative in $required) {
    $path = Join-Path $ProjectRoot $relative
    if (-not (Test-Path $path)) {
        throw "Missing file: $relative"
    }
}

Write-Host "Phase 2D.1 files: OK" -ForegroundColor Green

py -3 --version

Write-Host "Checking Python syntax..."
py -3 -m py_compile `
  (Join-Path $ProjectRoot "apps\ai-model\src\cyrp_ai_model.py") `
  (Join-Path $ProjectRoot "apps\ai-model\train.py") `
  (Join-Path $ProjectRoot "apps\ai-model\predict.py")

Write-Host "Phase 2D.1 verification completed." -ForegroundColor Green
