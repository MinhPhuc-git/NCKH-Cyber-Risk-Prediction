param([switch]$Execute)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
$SourceAgent = Join-Path $ProjectRoot "apps\agent-windows"
$LegacyRoot = Join-Path $ProjectRoot "legacy"
$TargetAgent = Join-Path $LegacyRoot "custom-agent-windows"
$OldPublicZip = Join-Path $ProjectRoot "apps\user-web\public\downloads\cyrp-agent-windows.zip"
$LegacyArtifacts = Join-Path $LegacyRoot "artifacts"
$BootstrapperRoot = Join-Path $ProjectRoot "apps\bootstrapper-windows"

Write-Host "CYRP legacy Agent migration"
Write-Host "Source: $SourceAgent"
Write-Host "Target: $TargetAgent"

if (-not $Execute) {
    Write-Host "DRY RUN - chưa thay đổi file."
    Write-Host "Chạy lại với -Execute sau khi đã đóng Agent poll."
    exit 0
}

if (Test-Path $TargetAgent) {
    throw "Target already exists: $TargetAgent"
}

New-Item -ItemType Directory -Path $LegacyRoot -Force | Out-Null

if (Test-Path $SourceAgent) {
    Move-Item -Path $SourceAgent -Destination $TargetAgent
    Write-Host "Moved apps\agent-windows to legacy."
} else {
    Write-Host "apps\agent-windows does not exist; skipped."
}

if (Test-Path $OldPublicZip) {
    New-Item -ItemType Directory -Path $LegacyArtifacts -Force | Out-Null
    Move-Item -Path $OldPublicZip -Destination (Join-Path $LegacyArtifacts "cyrp-agent-windows.zip")
    Write-Host "Moved old public Agent ZIP."
}

New-Item -ItemType Directory -Path $BootstrapperRoot -Force | Out-Null
Write-Host "Legacy migration completed."
Write-Host "Tạm xóa nút tải Agent cũ khỏi User Portal."
