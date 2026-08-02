param(
    [string]$ProjectRoot = "D:\LuanVan\test\cyrp-platform-phase2"
)

$ErrorActionPreference = "Stop"

$aiModelPath = Join-Path `
  $ProjectRoot `
  "apps\ai-model\src\cyrp_ai_model.py"

$exportScriptPath = Join-Path `
  $ProjectRoot `
  "scripts\ai-cyrp-export-input.ps1"

$predictScriptPath = Join-Path `
  $ProjectRoot `
  "scripts\ai-cyrp-predict-from-db.ps1"

foreach ($path in @($aiModelPath, $exportScriptPath, $predictScriptPath)) {
  if (-not [IO.File]::Exists($path)) {
    throw "Required file was not found: $path"
  }
}

$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$backupRoot = Join-Path `
  $ProjectRoot `
  ".phase-backups\phase-2d1-bom-exitcode-fix-$timestamp"

[IO.Directory]::CreateDirectory($backupRoot) | Out-Null

[IO.File]::Copy($aiModelPath, (Join-Path $backupRoot "cyrp_ai_model.py"), $true)
[IO.File]::Copy($exportScriptPath, (Join-Path $backupRoot "ai-cyrp-export-input.ps1"), $true)
[IO.File]::Copy($predictScriptPath, (Join-Path $backupRoot "ai-cyrp-predict-from-db.ps1"), $true)

# Patch Python JSON reader to accept UTF-8 with BOM defensively.
$py = [IO.File]::ReadAllText($aiModelPath)

$oldPy = @'
def read_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as stream:
        return json.load(stream)
'@

$newPy = @'
def read_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8-sig") as stream:
        return json.load(stream)
'@

if ($py.Contains($oldPy)) {
  $py = $py.Replace($oldPy, $newPy)
}
elseif (-not $py.Contains('encoding="utf-8-sig"')) {
  throw "Could not patch read_json() in cyrp_ai_model.py"
}

[IO.File]::WriteAllText(
  $aiModelPath,
  $py,
  [Text.UTF8Encoding]::new($false)
)

# Patch PowerShell export to write JSON without BOM.
$export = [IO.File]::ReadAllText($exportScriptPath)

$oldExport = @'
Set-Content -Path $OutputPath -Value $result -Encoding UTF8

Write-Host "Exported AI model input: $OutputPath" -ForegroundColor Green
'@

$newExport = @'
[IO.File]::WriteAllText(
    $OutputPath,
    $result,
    [Text.UTF8Encoding]::new($false)
)

Write-Host "Exported AI model input: $OutputPath" -ForegroundColor Green
'@

if ($export.Contains($oldExport)) {
  $export = $export.Replace($oldExport, $newExport)
}
elseif (-not $export.Contains('[IO.File]::WriteAllText(')) {
  throw "Could not patch ai-cyrp-export-input.ps1 BOM handling."
}

[IO.File]::WriteAllText(
  $exportScriptPath,
  $export,
  [Text.UTF8Encoding]::new($false)
)

# Patch prediction orchestrator to stop after Python failure and never import stale/missing output.
$predict = [IO.File]::ReadAllText($predictScriptPath)

$oldPredict = @'
& $Python `
  (Join-Path $AiRoot "predict.py") `
  predict `
  --input $InputPath `
  --output $OutputPath `
  --model $Model `
  --artifacts $Artifacts

Write-Host "AI model predictions written to: $OutputPath" -ForegroundColor Green

if ($ImportToDatabase) {
'@

$newPredict = @'
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
'@

if ($predict.Contains($oldPredict)) {
  $predict = $predict.Replace($oldPredict, $newPredict)
}
elseif (-not $predict.Contains("AI model prediction failed with exit code")) {
  throw "Could not patch ai-cyrp-predict-from-db.ps1 exit-code handling."
}

[IO.File]::WriteAllText(
  $predictScriptPath,
  $predict,
  [Text.UTF8Encoding]::new($false)
)

Write-Host "Phase 2D.1 BOM and exit-code fix applied." -ForegroundColor Green
Write-Host "Backup: $backupRoot"
