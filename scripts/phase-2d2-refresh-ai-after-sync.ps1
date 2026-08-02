param(
  [Parameter(Mandatory = $true)]
  [string]$DeviceId,

  [string]$ProjectRoot = (Get-Location).Path,

  [string]$ApiBaseUrl = "http://127.0.0.1:3001/api/v1",

  [string]$Email = "anhdz@gmail.com",

  [string]$Model = "random_forest",

  [int]$Limit = 300,

  [switch]$SkipSecuritySync
)

$ErrorActionPreference = "Stop"

function Write-Step {
  param([string]$Message)
  Write-Host "[Phase 2D.2] $Message" -ForegroundColor Cyan
}

Set-Location $ProjectRoot

if (-not (Test-Path ".\scripts\ai-cyrp-predict-from-db.ps1")) {
  throw "Không tìm thấy .\scripts\ai-cyrp-predict-from-db.ps1. Hãy chạy script trong CYRP project root."
}

Write-Step "Testing CYRP API at $ApiBaseUrl/health"
try {
  Invoke-RestMethod -Method Get -Uri "$ApiBaseUrl/health" | Out-Null
} catch {
  throw "Không kết nối được CYRP API. Hãy chạy corepack pnpm run dev:api trước. Chi tiết: $($_.Exception.Message)"
}

$headers = @{}
if (-not $SkipSecuritySync) {
  Write-Step "Logging in as $Email"
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
    throw "Không lấy được access token từ $ApiBaseUrl/auth/login."
  }

  $headers = @{ Authorization = "Bearer $token" }

  Write-Step "Running security-sync for device $DeviceId"
  Invoke-RestMethod `
    -Method Post `
    -Uri "$ApiBaseUrl/devices/$DeviceId/security-sync" `
    -Headers $headers | Out-Null
} else {
  Write-Step "Skipping security-sync because -SkipSecuritySync was provided"
}

Write-Step "Running AI_CYRP prediction: model=$Model, limit=$Limit"
powershell `
  -NoProfile `
  -ExecutionPolicy Bypass `
  -File ".\scripts\ai-cyrp-predict-from-db.ps1" `
  -DeviceId $DeviceId `
  -Model $Model `
  -Limit $Limit `
  -ImportToDatabase

Write-Step "Checking ai_predictions summary"
docker compose exec db `
  psql -U cyrp -d cyrp `
  -c "
SELECT
  model_version,
  COUNT(*) AS prediction_count,
  MIN(attack_probability) AS min_probability,
  AVG(attack_probability) AS avg_probability,
  MAX(attack_probability) AS max_probability,
  MAX(predicted_at) AS latest_prediction
FROM ai_predictions
GROUP BY model_version
ORDER BY latest_prediction DESC;
"

Write-Step "Checking top active vulnerabilities for this device"
docker compose exec db `
  psql -U cyrp -d cyrp `
  -c "
SELECT
  dv.cve_id,
  dv.package_name,
  dv.status,
  ap.model_version,
  ap.attack_probability,
  ap.risk_level,
  ap.predicted_at
FROM detected_vulnerabilities dv
LEFT JOIN ai_predictions ap
  ON ap.detected_vulnerability_id = dv.id
WHERE dv.device_id = '$DeviceId'
  AND dv.status = 'ACTIVE'
ORDER BY dv.cvss_base_score DESC NULLS LAST, dv.cve_id
LIMIT 20;
"

Write-Step "Done. Refresh the vulnerability page with Ctrl+F5. Do not press security-sync again before checking the UI."
