param(
  [string]$ProjectRoot = "D:\LuanVan\test\cyrp-platform-phase2",
  [Parameter(Mandatory = $true)]
  [string]$WazuhCsv,
  [int]$Workers = 5,
  [int]$Retries = 3,
  [double]$Delay = 0.1
)

$ErrorActionPreference = "Stop"

function Write-Step($Message) {
  Write-Host ""
  Write-Host "==> $Message" -ForegroundColor Cyan
}

$Py = Join-Path $ProjectRoot "apps\ai-model\.venv\Scripts\python.exe"
$CtiRoot = Join-Path $ProjectRoot "apps\ai-model\cti-collector"
$Scripts = Join-Path $CtiRoot "scripts"
$InputDir = Join-Path $CtiRoot "data\input"
$JsonDir = Join-Path $CtiRoot "data\json_data"
$OutputDir = Join-Path $CtiRoot "data\output"

if (-not (Test-Path $Py)) { throw "Python venv not found: $Py" }
if (-not (Test-Path $WazuhCsv)) { throw "Wazuh CSV not found: $WazuhCsv" }

New-Item -ItemType Directory -Force -Path $InputDir, $JsonDir, $OutputDir | Out-Null

$Stamp = Get-Date -Format "yyyyMMdd_HHmmss"
$CveList = Join-Path $InputDir "cve_list_$Stamp.csv"
$CtiFull = Join-Path $OutputDir "ket_qua_full_$Stamp.csv"
$Recommendations = Join-Path $OutputDir "device_vulnerability_recommendations_$Stamp.json"

Write-Step "Step 1/4 - Extracting unique CVE list from Wazuh vulnerability CSV"
& $Py (Join-Path $Scripts "extract_data_wazuh.py") `
  $WazuhCsv `
  --out $CveList `
  --unique

if (-not (Test-Path $CveList)) {
  throw "CVE list was not created: $CveList"
}

Write-Step "Step 2/4 - Fetching Wazuh CTI JSON for unique CVEs"
& $Py (Join-Path $Scripts "cti_collector.py") `
  --input $CveList `
  --outdir $JsonDir `
  --workers $Workers `
  --retries $Retries `
  --delay $Delay

Write-Step "Step 3/4 - Flattening CTI JSON to enrichment CSV"
& $Py (Join-Path $Scripts "extract_cve.py") `
  $JsonDir `
  --out $CtiFull `
  --cve-list $CveList `
  --include-missing `
  --workers $Workers

if (-not (Test-Path $CtiFull)) {
  throw "CTI full CSV was not created: $CtiFull"
}

Write-Step "Step 4/4 - Mapping Wazuh vulnerabilities + CTI enrichment into device recommendations JSON"
& $Py (Join-Path $Scripts "build_device_recommendations.py") `
  --wazuh-csv $WazuhCsv `
  --cti-csv $CtiFull `
  --out $Recommendations

Write-Host ""
Write-Host "Pipeline completed." -ForegroundColor Green
Write-Host "CVE list:        $CveList"
Write-Host "CTI full CSV:    $CtiFull"
Write-Host "Recommendations: $Recommendations"