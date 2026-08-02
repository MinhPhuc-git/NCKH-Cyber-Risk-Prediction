param(
  [string]$ProjectRoot = "D:\LuanVan\test\cyrp-platform-phase2",
  [string]$PatchZip = "D:\LuanVan\handoff-ai-merge\cyrp-new-ai-model-merge-patch.zip",
  [switch]$TrainModel,
  [switch]$NoBackup
)

$ErrorActionPreference = "Stop"

function Write-Step([string]$Message) {
  Write-Host "`n==> $Message" -ForegroundColor Cyan
}

function Stop-Port([int]$Port) {
  $pids = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue |
    Select-Object -ExpandProperty OwningProcess -Unique

  foreach ($pid in $pids) {
    Write-Host "Stopping process on port ${Port}: PID ${pid}" -ForegroundColor Yellow
    Stop-Process -Id $pid -Force -ErrorAction SilentlyContinue
  }
}

if (-not (Test-Path $ProjectRoot)) {
  throw "ProjectRoot does not exist: $ProjectRoot"
}

$ProjectRoot = [System.IO.Path]::GetFullPath($ProjectRoot)
$AiRoot = Join-Path $ProjectRoot "apps\ai-model"
$ModelRoot = Join-Path $AiRoot "model-risk-prediction"

if (-not (Test-Path $AiRoot)) {
  throw "apps\ai-model does not exist: $AiRoot"
}

Write-Step "Stopping running CYRP frontend/backend processes on ports 3001 and 3002"
Stop-Port 3001
Stop-Port 3002

$PatchDir = Join-Path $ProjectRoot "_ai_patch_clean_install"
Remove-Item $PatchDir -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $PatchDir | Out-Null

if (Test-Path $PatchZip) {
  Write-Step "Expanding patch zip"
  Expand-Archive -LiteralPath $PatchZip -DestinationPath $PatchDir -Force
} elseif (Test-Path (Join-Path $ProjectRoot "_ai_patch\apps\ai-model\model-risk-prediction")) {
  Write-Step "PatchZip not found; using existing _ai_patch directory"
  $PatchDir = Join-Path $ProjectRoot "_ai_patch"
} else {
  throw "Patch zip not found: $PatchZip. Put cyrp-new-ai-model-merge-patch.zip at this path or pass -PatchZip <path>."
}

$PatchModelRoot = Join-Path $PatchDir "apps\ai-model\model-risk-prediction"
if (-not (Test-Path $PatchModelRoot)) {
  throw "Patch model folder missing: $PatchModelRoot"
}

if (-not $NoBackup) {
  $BackupRoot = Join-Path $ProjectRoot (".phase-backups\ai-model-clean-before-new-model-" + (Get-Date -Format "yyyyMMdd-HHmmss"))
  Write-Step "Backing up current ai-model without .venv/cache/artifacts data"
  New-Item -ItemType Directory -Force -Path $BackupRoot | Out-Null
  robocopy $AiRoot $BackupRoot /E /XD ".venv" "__pycache__" "artifacts" "data" "json_data" "output" "tmp" /XF "*.pyc" "*.pkl" "*.joblib" "*.onnx" "*.csv" "*.xlsx" | Out-Null
  Write-Host "Backup written to: $BackupRoot" -ForegroundColor Green
}

Write-Step "Removing old AI model folders/files"
$RemovePaths = @(
  (Join-Path $AiRoot "_legacy_before_model_risk_prediction"),
  (Join-Path $AiRoot "_legacy_before_model_risk_prediction_*"),
  (Join-Path $AiRoot "_legacy_before_model_risk_pre*"),
  (Join-Path $AiRoot "runtime"),
  (Join-Path $AiRoot "AI_CYRP_ASSETS.json"),
  (Join-Path $ModelRoot "runtime"),
  (Join-Path $ModelRoot "artifacts"),
  (Join-Path $ModelRoot "samples"),
  (Join-Path $ModelRoot "data\train"),
  (Join-Path $ModelRoot "runtime_old"),
  (Join-Path $ModelRoot "old_runtime"),
  (Join-Path $ModelRoot "runtime.bak"),
  (Join-Path $ModelRoot "requirements.txt")
)

foreach ($path in $RemovePaths) {
  Get-Item -LiteralPath $path -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
  Get-ChildItem -Path (Split-Path $path -Parent) -Filter (Split-Path $path -Leaf) -Force -ErrorAction SilentlyContinue |
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
}

if (Test-Path $ModelRoot) {
  Get-ChildItem $ModelRoot -Recurse -Force -ErrorAction SilentlyContinue |
    Where-Object {
      $_.Name -match "random_forest|decision_tree|linear_regression|train_model\.py|bak-before|__pycache__|\.pyc$|AI_CYRP_XGBOOST_V2|AI_CYRP_BASELINE"
    } |
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Step "Installing new model runtime from patch"
New-Item -ItemType Directory -Force -Path $ModelRoot | Out-Null
Copy-Item -LiteralPath (Join-Path $PatchModelRoot "*") -Destination $ModelRoot -Recurse -Force

Write-Step "Installing patched API/User files from patch when present"
$ApiPatch = Join-Path $PatchDir "apps\api\src\modules\security-data"
if (Test-Path (Join-Path $ApiPatch "ai-model-runtime.service.ts")) {
  Copy-Item -LiteralPath (Join-Path $ApiPatch "ai-model-runtime.service.ts") -Destination (Join-Path $ProjectRoot "apps\api\src\modules\security-data\ai-model-runtime.service.ts") -Force
}
if (Test-Path (Join-Path $ApiPatch "security-data-sync.service.ts")) {
  Copy-Item -LiteralPath (Join-Path $ApiPatch "security-data-sync.service.ts") -Destination (Join-Path $ProjectRoot "apps\api\src\modules\security-data\security-data-sync.service.ts") -Force
}
$UserPatch = Join-Path $PatchDir "apps\user-web\src\components\device-analysis-button.tsx"
if (Test-Path $UserPatch) {
  Copy-Item -LiteralPath $UserPatch -Destination (Join-Path $ProjectRoot "apps\user-web\src\components\device-analysis-button.tsx") -Force
}

Write-Step "Updating .env AI model settings"
$EnvFile = Join-Path $ProjectRoot ".env"
if (Test-Path $EnvFile) {
  $envText = Get-Content -Raw -Encoding UTF8 $EnvFile
} else {
  $envText = ""
}

$Settings = [ordered]@{
  "AI_MODEL_ENABLED" = "true"
  "AI_MODEL_ACTIVE" = "xgboost"
  "AI_MODEL_VERSION" = "CYRP_XGBOOST_CVSS_PERCENTILE_V3"
  "AI_MODEL_PYTHON_PATH" = (Join-Path $AiRoot ".venv\Scripts\python.exe")
  "AI_MODEL_PREDICT_SCRIPT" = (Join-Path $ModelRoot "runtime\predict_one.py")
  "AI_MODEL_RUNTIME_DIR" = $ModelRoot
  "AI_MODEL_TIMEOUT_MS" = "60000"
}

foreach ($key in $Settings.Keys) {
  $value = $Settings[$key]
  $escaped = [regex]::Escape($key)
  if ($envText -match "(?m)^$escaped=") {
    $envText = [regex]::Replace($envText, "(?m)^$escaped=.*$", "$key=$value")
  } else {
    $envText = $envText.TrimEnd() + "`r`n$key=$value`r`n"
  }
}

[System.IO.File]::WriteAllText($EnvFile, $envText, [System.Text.UTF8Encoding]::new($false))

Write-Step "Installing Python requirements"
$Py = Join-Path $AiRoot ".venv\Scripts\python.exe"
$Req = Join-Path $ModelRoot "requirements.txt"
if (-not (Test-Path $Py)) {
  throw "Python venv not found: $Py"
}
if (Test-Path $Req) {
  & $Py -m pip install -r $Req
}

if ($TrainModel) {
  Write-Step "Training new XGBoost model"
  & $Py (Join-Path $ModelRoot "runtime\train_xgboost_new.py") --force
}

Write-Step "Verification: searching old AI references"
$SearchRoots = @(
  (Join-Path $ProjectRoot "apps\api\src"),
  (Join-Path $ProjectRoot "apps\user-web\src"),
  $AiRoot
)

$OldRefs = foreach ($root in $SearchRoots) {
  if (Test-Path $root) {
    Get-ChildItem $root -Recurse -Include *.ts,*.tsx,*.py,*.json,*.env -File -ErrorAction SilentlyContinue |
      Select-String -Pattern "AI_CYRP_XGBOOST_V2|AI_CYRP_BASELINE_FALLBACK_V1|random_forest|decision_tree|linear_regression|_legacy_before|AI_CYRP_ASSETS" -ErrorAction SilentlyContinue |
      Select-Object Path, LineNumber, Line
  }
}

if ($OldRefs) {
  Write-Host "Old references still found; review these lines:" -ForegroundColor Yellow
  $OldRefs | Format-Table -AutoSize
} else {
  Write-Host "No old AI references found in api/user-web/ai-model." -ForegroundColor Green
}

Write-Step "Verification: model artifact folder"
$ArtifactDir = Join-Path $ModelRoot "artifacts\xgboost"
if (Test-Path $ArtifactDir) {
  Get-ChildItem $ArtifactDir -Force | Select-Object Name, Length, LastWriteTime | Format-Table -AutoSize
} else {
  Write-Host "No artifacts yet. Run with -TrainModel or train later:" -ForegroundColor Yellow
  Write-Host "& `"$Py`" `"$(Join-Path $ModelRoot 'runtime\train_xgboost_new.py')`" --force" -ForegroundColor Yellow
}

Write-Step "Next commands"
Write-Host "corepack pnpm --dir apps/api exec tsc -p tsconfig.build.json --noEmit"
Write-Host "Remove-Item .\apps\user-web\.next -Recurse -Force -ErrorAction SilentlyContinue"
Write-Host "corepack pnpm --dir apps/user-web exec next build"
