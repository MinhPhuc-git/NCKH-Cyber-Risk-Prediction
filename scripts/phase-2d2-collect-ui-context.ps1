param(
  [string]$ProjectRoot = (Get-Location).Path
)

$ErrorActionPreference = "Stop"
Set-Location $ProjectRoot
New-Item -ItemType Directory -Path ".\logs\phase2d2-ui-context" -Force | Out-Null

$patterns = @(
  "Risk model",
  "RISK MODEL",
  "Xác suất",
  "aiPrediction",
  "attackProbability",
  "riskLevel",
  "modelVersion",
  "vulnerabilities",
  "Lỗ hổng"
)

$roots = @(
  ".\apps\user-web",
  ".\apps\portal-web",
  ".\apps\api\src\modules\security-data"
) | Where-Object { Test-Path $_ }

$candidates = New-Object System.Collections.Generic.HashSet[string]
foreach ($root in $roots) {
  Get-ChildItem -Path $root -Recurse -Include *.tsx,*.ts -File | ForEach-Object {
    $file = $_.FullName
    foreach ($pattern in $patterns) {
      $matches = Select-String -Path $file -Pattern $pattern -SimpleMatch -ErrorAction SilentlyContinue
      if ($matches) {
        [void]$candidates.Add($file)
      }
    }
  }
}

$manifest = @()
foreach ($file in $candidates) {
  $relative = Resolve-Path -Path $file -Relative
  $safeName = $relative.TrimStart('.', '\', '/') -replace '[:\\/]', '__'
  $target = Join-Path ".\logs\phase2d2-ui-context" $safeName
  Copy-Item -Path $file -Destination $target -Force
  $manifest += [PSCustomObject]@{
    relativePath = $relative
    copiedAs = $safeName
  }
}

$manifestPath = ".\logs\phase2d2-ui-context\manifest.json"
$manifest | ConvertTo-Json -Depth 10 | Set-Content -Path $manifestPath -Encoding UTF8

$zipPath = ".\logs\phase2d2-ui-context.zip"
Remove-Item $zipPath -Force -ErrorAction SilentlyContinue
Compress-Archive -Path ".\logs\phase2d2-ui-context\*" -DestinationPath $zipPath -Force

Write-Host "[Phase 2D.2] Candidate files: $($candidates.Count)" -ForegroundColor Cyan
Write-Host "[Phase 2D.2] Upload this file if UI still does not show modelVersion: $zipPath" -ForegroundColor Green
$manifest | Format-Table -AutoSize
