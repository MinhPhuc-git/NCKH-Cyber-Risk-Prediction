param(
    [string]$ProjectRoot = "D:\LuanVan\test\cyrp-platform-phase2",
    [string]$DatasetCsv = "",
    [ValidateSet("decision_tree", "linear_regression", "random_forest", "xgboost")]
    [string]$Model = "random_forest",
    [int]$Limit = 0
)

$ErrorActionPreference = "Stop"

$AiRoot = Join-Path $ProjectRoot "apps\ai-model"
$VenvRoot = Join-Path $AiRoot ".venv"
$Python = Join-Path $VenvRoot "Scripts\python.exe"

if (-not $DatasetCsv) {
    $DatasetCsv = Join-Path $AiRoot "datasets\cve_epss_merged_v2_light.csv"
}

if (-not (Test-Path $DatasetCsv)) {
    throw "Dataset CSV was not found: $DatasetCsv"
}

if (-not (Test-Path $Python)) {
    py -3 -m venv $VenvRoot
}

& $Python -m pip install --upgrade pip
& $Python -m pip install -r (Join-Path $AiRoot "requirements.txt")

$Artifacts = Join-Path $AiRoot "artifacts"
New-Item -ItemType Directory -Path $Artifacts -Force | Out-Null

$argsList = @(
    (Join-Path $AiRoot "train.py"),
    "train",
    "--csv", $DatasetCsv,
    "--model", $Model,
    "--out", $Artifacts
)

if ($Limit -gt 0) {
    $argsList += @("--limit", [string]$Limit)
}

& $Python @argsList
