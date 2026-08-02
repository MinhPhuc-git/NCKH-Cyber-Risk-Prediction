param(
  [string]$ProjectRoot = (Get-Location).Path,
  [string]$ApiBaseUrl = "http://127.0.0.1:3001/api/v1",
  [string]$Email = "anhdz@gmail.com",
  [int]$Limit = 10
)

$ErrorActionPreference = "Stop"
Set-Location $ProjectRoot
New-Item -ItemType Directory -Path ".\logs" -Force | Out-Null

Write-Host "[Phase 2D.2] Logging in as $Email" -ForegroundColor Cyan
$credential = Get-Credential -UserName $Email -Message "Nhập mật khẩu user CYRP"
$password = ([System.Net.NetworkCredential]::new("", $credential.Password)).Password

$loginBody = @{
  email = $credential.UserName
  password = $password
} | ConvertTo-Json

$login = Invoke-RestMethod `
  -Method Post `
  -Uri "$ApiBaseUrl/auth/login" `
  -ContentType "application/json" `
  -Body $loginBody

$token = @(
  $login.accessToken
  $login.access_token
  $login.token
  $login.data.accessToken
  $login.data.access_token
  $login.data.token
) | Where-Object {
  -not [string]::IsNullOrWhiteSpace([string]$_)
} | Select-Object -First 1

if (-not $token) {
  throw "Không lấy được access token."
}

$headers = @{ Authorization = "Bearer $token" }

$uris = @(
  "$ApiBaseUrl/vulnerabilities?limit=$Limit",
  "$ApiBaseUrl/vulnerabilities?take=$Limit"
)

$response = $null
$usedUri = $null
foreach ($uri in $uris) {
  try {
    $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers
    $usedUri = $uri
    break
  } catch {
    Write-Host "[Phase 2D.2] Failed ${uri}: $($_.Exception.Message)" -ForegroundColor Yellow
  }
}

if (-not $response) {
  throw "Không gọi được endpoint vulnerabilities."
}

$out = ".\logs\phase-2d2-vulnerabilities-api-sample.json"
$response | ConvertTo-Json -Depth 80 | Set-Content -Path $out -Encoding UTF8

Write-Host "[Phase 2D.2] API used: $usedUri" -ForegroundColor Cyan
Write-Host "[Phase 2D.2] Sample saved to: $out" -ForegroundColor Cyan

$sampleText = Get-Content $out -Raw -Encoding UTF8
if ($sampleText -match "AI_CYRP_RANDOM_FOREST_V1") {
  Write-Host "[Phase 2D.2] OK: API response contains AI_CYRP_RANDOM_FOREST_V1" -ForegroundColor Green
} elseif ($sampleText -match "CYRP_BASELINE_V1") {
  Write-Host "[Phase 2D.2] WARNING: API response still contains CYRP_BASELINE_V1" -ForegroundColor Yellow
} else {
  Write-Host "[Phase 2D.2] WARNING: API response does not expose modelVersion clearly" -ForegroundColor Yellow
}

Select-String -Path $out -Pattern "modelVersion|attackProbability|riskLevel|final_priority|official_epss|AI_CYRP|CYRP_BASELINE" -Context 1,2

