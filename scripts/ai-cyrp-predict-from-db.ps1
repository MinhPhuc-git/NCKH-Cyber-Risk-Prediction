param(
    [string]$ProjectRoot = "D:\LuanVan\test\cyrp-platform-phase2",
    [string]$DeviceId = "",
    [int]$Limit = 50,
    [ValidateSet("decision_tree", "linear_regression", "random_forest", "xgboost")]
    [string]$Model = "random_forest",
    [switch]$ImportToDatabase
)

$ErrorActionPreference = "Stop"

$AiRoot = Join-Path $ProjectRoot "apps\ai-model"
$Python = Join-Path $AiRoot ".venv\Scripts\python.exe"
$InputPath = Join-Path $AiRoot "runtime\cyrp-model-input.json"
$OutputPath = Join-Path $AiRoot "runtime\cyrp-model-output.json"
$Artifacts = Join-Path $AiRoot "artifacts"

if (-not (Test-Path $Python)) {
    throw "Python virtualenv was not found. Run scripts\ai-cyrp-train.ps1 first."
}

$modelArtifact = Join-Path $Artifacts "$($Model)_model.pkl"
if (-not (Test-Path $modelArtifact)) {
    throw "Model artifact was not found: $modelArtifact. Train the model first."
}

& (Join-Path $ProjectRoot "scripts\ai-cyrp-export-input.ps1") `
  -ProjectRoot $ProjectRoot `
  -DeviceId $DeviceId `
  -Limit $Limit `
  -OutputPath $InputPath

Remove-Item `
  -Path $OutputPath `
  -Force `
  -ErrorAction SilentlyContinue

& $Python `
  (Join-Path $AiRoot "predict.py") `
  predict `
  --input $InputPath `
  --output $OutputPath `
  --model $Model `
  --artifacts $Artifacts

if ($LASTEXITCODE -ne 0) {
    throw "AI model prediction failed with exit code $LASTEXITCODE"
}

if (-not (Test-Path $OutputPath)) {
    throw "AI model prediction did not create output file: $OutputPath"
}

Write-Host "AI model predictions written to: $OutputPath" -ForegroundColor Green

if ($ImportToDatabase) {
    & (Join-Path $ProjectRoot "scripts\ai-cyrp-import-predictions.ps1") `
      -ProjectRoot $ProjectRoot `
      -PredictionJson $OutputPath
}
