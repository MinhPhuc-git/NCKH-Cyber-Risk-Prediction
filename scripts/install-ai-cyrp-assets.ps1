param(
    [string]$ProjectRoot = "D:\LuanVan\test\cyrp-platform-phase2",
    [string]$AiCyrpZip = "$HOME\Downloads\AI_CYRP.zip",
    [string]$MergeDataZip = "$HOME\Downloads\Merge DATA.zip"
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $AiCyrpZip)) {
    throw "AI_CYRP.zip was not found: $AiCyrpZip"
}

if (-not (Test-Path $MergeDataZip)) {
    throw "Merge DATA.zip was not found: $MergeDataZip"
}

$aiRoot = Join-Path $ProjectRoot "apps\ai-model"
$vendorRoot = Join-Path $aiRoot "vendor"
$datasetRoot = Join-Path $aiRoot "datasets"
$docsRoot = Join-Path $ProjectRoot "docs\ai-model"

New-Item -ItemType Directory -Path $vendorRoot -Force | Out-Null
New-Item -ItemType Directory -Path $datasetRoot -Force | Out-Null
New-Item -ItemType Directory -Path $docsRoot -Force | Out-Null

$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$tempRoot = Join-Path $env:TEMP "cyrp-ai-assets-$timestamp"
Remove-Item $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null

try {
    $aiExtract = Join-Path $tempRoot "ai"
    $mergeExtract = Join-Path $tempRoot "merge"

    Expand-Archive -Path $AiCyrpZip -DestinationPath $aiExtract -Force
    Expand-Archive -Path $MergeDataZip -DestinationPath $mergeExtract -Force

    $aiSource = Get-ChildItem `
      -Path $aiExtract `
      -Recurse `
      -Directory |
      Where-Object {
        (Test-Path (Join-Path $_.FullName "Model\base_model.py")) -and
        (Test-Path (Join-Path $_.FullName "Label\MockData"))
      } |
      Select-Object -First 1

    if (-not $aiSource) {
        throw "Could not find AI_CYRP source directory containing Model\base_model.py."
    }

    $aiDestination = Join-Path $vendorRoot "AI_CYRP"
    Remove-Item $aiDestination -Recurse -Force -ErrorAction SilentlyContinue
    Copy-Item -Path $aiSource.FullName -Destination $aiDestination -Recurse -Force

    $lightCsv = Get-ChildItem `
      -Path $mergeExtract `
      -Recurse `
      -File `
      -Filter "cve_epss_merged_v2_light.csv" |
      Select-Object -First 1

    if (-not $lightCsv) {
        throw "cve_epss_merged_v2_light.csv was not found inside Merge DATA.zip."
    }

    Copy-Item `
      -Path $lightCsv.FullName `
      -Destination (Join-Path $datasetRoot "cve_epss_merged_v2_light.csv") `
      -Force

    $fullCsv = Get-ChildItem `
      -Path $mergeExtract `
      -Recurse `
      -File `
      -Filter "cve_epss_merged_v2.csv" |
      Select-Object -First 1

    if ($fullCsv) {
      Copy-Item `
        -Path $fullCsv.FullName `
        -Destination (Join-Path $datasetRoot "cve_epss_merged_v2.csv") `
        -Force
    }

    $report = Get-ChildItem `
      -Path $mergeExtract `
      -Recurse `
      -File `
      -Filter "bao_cao_merge_cve_epss.md" |
      Select-Object -First 1

    if ($report) {
      Copy-Item `
        -Path $report.FullName `
        -Destination (Join-Path $docsRoot "bao_cao_merge_cve_epss.md") `
        -Force
    }

    $manifest = [PSCustomObject]@{
      installedAt = (Get-Date).ToString("o")
      aiSourceZip = (Resolve-Path $AiCyrpZip).Path
      mergeDataZip = (Resolve-Path $MergeDataZip).Path
      vendorDirectory = $aiDestination
      lightDataset = (Join-Path $datasetRoot "cve_epss_merged_v2_light.csv")
      fullDataset = if ($fullCsv) { (Join-Path $datasetRoot "cve_epss_merged_v2.csv") } else { $null }
      report = if ($report) { (Join-Path $docsRoot "bao_cao_merge_cve_epss.md") } else { $null }
      note = "AI_CYRP original source is stored for reference. CYRP runtime uses apps/ai-model/src/cyrp_ai_model.py as the stable integration adapter."
    }

    $manifest |
      ConvertTo-Json -Depth 10 |
      Set-Content `
        -Path (Join-Path $aiRoot "AI_CYRP_ASSETS.json") `
        -Encoding UTF8

    Write-Host "AI_CYRP assets installed." -ForegroundColor Green
    Write-Host "Vendor source: $aiDestination"
    Write-Host "Light dataset: $(Join-Path $datasetRoot 'cve_epss_merged_v2_light.csv')"
    if ($fullCsv) {
      Write-Host "Full dataset: $(Join-Path $datasetRoot 'cve_epss_merged_v2.csv')"
    }
}
finally {
    Remove-Item $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
}
