param(
  [string]$ProjectRoot = "D:\LuanVan\test\cyrp-platform-phase2"
)

$ErrorActionPreference = "Stop"

$RequiredPaths = @(
  "apps\ai-model\.venv\Scripts\python.exe",
  "apps\ai-model\cti-collector\scripts\cti_collector.py",
  "apps\ai-model\cti-collector\scripts\extract_cve.py",
  "apps\ai-model\cti-collector\scripts\extract_data_wazuh.py",
  "apps\ai-model\cti-collector\scripts\remediation.py",
  "apps\ai-model\cti-collector\scripts\build_device_recommendations.py",
  "apps\ai-model\cti-collector\data\input",
  "apps\ai-model\cti-collector\data\json_data",
  "apps\ai-model\cti-collector\data\output",
  "scripts\run-cti-wazuh-pipeline.ps1"
)

$Ok = $true

foreach ($Rel in $RequiredPaths) {
  $Path = Join-Path $ProjectRoot $Rel

  if (Test-Path $Path) {
    Write-Host "OK      $Rel" -ForegroundColor Green
  } else {
    Write-Host "MISSING $Rel" -ForegroundColor Red
    $Ok = $false
  }
}

$Py = Join-Path $ProjectRoot "apps\ai-model\.venv\Scripts\python.exe"

if (Test-Path $Py) {
  Write-Host ""
  Write-Host "Checking Python packages..."

  $CheckScript = @"
import importlib

packages = ["requests", "pandas", "openpyxl"]

failed = False

for name in packages:
    try:
        importlib.import_module(name)
        print(f"OK      {name}")
    except Exception as exc:
        print(f"MISSING {name}: {exc}")
        failed = True

raise SystemExit(1 if failed else 0)
"@

  $TempPy = Join-Path $env:TEMP "cyrp_check_cti_packages.py"

  [System.IO.File]::WriteAllText(
    $TempPy,
    $CheckScript,
    [System.Text.UTF8Encoding]::new($false)
  )

  & $Py $TempPy

  Remove-Item $TempPy -Force -ErrorAction SilentlyContinue
}

if (-not $Ok) {
  throw "Verification failed. Missing required files."
}

Write-Host ""
Write-Host "CTI Wazuh pipeline layout looks ready." -ForegroundColor Cyan