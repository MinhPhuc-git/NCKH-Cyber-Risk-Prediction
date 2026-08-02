param(
  [string]$ProjectRoot = "D:\LuanVan\test\cyrp-platform-phase2"
)

$ErrorActionPreference = "Stop"

$PatchRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$Source = Join-Path $PatchRoot "apps\api\src\modules\security-data\ai-pipeline-data-user-import.service.ts"
$TargetDir = Join-Path $ProjectRoot "apps\api\src\modules\security-data"
$Target = Join-Path $TargetDir "ai-pipeline-data-user-import.service.ts"

if (-not (Test-Path $ProjectRoot)) { throw "ProjectRoot not found: $ProjectRoot" }
if (-not (Test-Path $TargetDir)) { throw "security-data module not found: $TargetDir" }
if (-not (Test-Path $Source)) { throw "Patch source not found: $Source" }

$Ts = Get-Date -Format "yyyyMMdd-HHmmss"
$BackupDir = Join-Path $ProjectRoot ".phase-backups\ai-data-user-import-fix-v2-$Ts"
New-Item -ItemType Directory -Force -Path $BackupDir | Out-Null
if (Test-Path $Target) {
  Copy-Item $Target (Join-Path $BackupDir "ai-pipeline-data-user-import.service.ts") -Force
}

Copy-Item $Source $Target -Force

Write-Host "DONE: installed AI Data User import fix v2." -ForegroundColor Green
Write-Host "Backup saved at: $BackupDir" -ForegroundColor Green
Write-Host "Important: rerun run_pipeline.py to regenerate Data User JSON before importing again." -ForegroundColor Yellow
