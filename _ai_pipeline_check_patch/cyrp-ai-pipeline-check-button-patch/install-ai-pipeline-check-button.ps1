param(
  [string]$ProjectRoot = "D:\LuanVan\test\cyrp-platform-phase2"
)

$ErrorActionPreference = "Stop"
$PatchRoot = Split-Path -Parent $MyInvocation.MyCommand.Path

if (-not (Test-Path $ProjectRoot)) {
  throw "ProjectRoot not found: $ProjectRoot"
}

$PythonCandidates = @(
  (Join-Path $ProjectRoot "apps\ai-model\.venv\Scripts\python.exe"),
  "python"
)

$Python = $PythonCandidates | Where-Object {
  ($_ -eq "python") -or (Test-Path $_)
} | Select-Object -First 1

if (-not $Python) {
  throw "Cannot find Python. Expected apps\ai-model\.venv\Scripts\python.exe or python in PATH."
}

Write-Host "Patching AI pipeline check endpoint and User Web button..." -ForegroundColor Cyan
& $Python (Join-Path $PatchRoot "scripts\patch_ai_pipeline_check.py") $ProjectRoot $PatchRoot

$EnvFile = Join-Path $ProjectRoot ".env"
if (-not (Test-Path $EnvFile)) {
  New-Item -ItemType File -Path $EnvFile -Force | Out-Null
}

function Set-EnvValue {
  param([string]$Name, [string]$Value)
  $Text = Get-Content -Raw -Encoding UTF8 $EnvFile
  $Escaped = [regex]::Escape($Name)
  if ($Text -match "(?m)^$Escaped=") {
    $Text = [regex]::Replace($Text, "(?m)^$Escaped=.*$", "$Name=$Value")
  } else {
    $Text = $Text.TrimEnd() + "`r`n$Name=$Value`r`n"
  }
  [System.IO.File]::WriteAllText($EnvFile, $Text, [System.Text.UTF8Encoding]::new($false))
}

Set-EnvValue "AI_MODEL_VERSION" "CYRP_XGBOOST_CVSS_PERCENTILE_V3"
Set-EnvValue "AI_PIPELINE_MODEL_ROOT" (Join-Path $ProjectRoot "apps\ai-model\model-risk-prediction")
Set-EnvValue "AI_PIPELINE_DATA_USER_DIR" (Join-Path $ProjectRoot "apps\ai-model\model-risk-prediction\Data User")
Set-EnvValue "AI_PIPELINE_PYTHON_PATH" (Join-Path $ProjectRoot "apps\ai-model\.venv\Scripts\python.exe")
Set-EnvValue "AI_PIPELINE_TIMEOUT_MS" "900000"
Set-EnvValue "WAZUH_ACTIVE_SYNC_WINDOW_MINUTES" "1440"

Write-Host "DONE. Next commands:" -ForegroundColor Green
Write-Host "  corepack pnpm --dir apps/api exec tsc -p tsconfig.build.json --noEmit" -ForegroundColor Green
Write-Host "  corepack pnpm --dir apps/user-web exec next build" -ForegroundColor Green
