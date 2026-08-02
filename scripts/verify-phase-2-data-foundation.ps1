[CmdletBinding()]
param(
    [string]$ApiBaseUrl = "http://localhost:3001/api/v1",
    [string]$AdminEmail = "",
    [string]$DeviceId = "",
    [switch]$RunDeviceSync
)

$ErrorActionPreference = "Stop"
$ApiBaseUrl = $ApiBaseUrl.TrimEnd("/")

if ([string]::IsNullOrWhiteSpace($AdminEmail)) {
    $AdminEmail = Read-Host "Admin email"
}

$securePassword = Read-Host "Admin password" -AsSecureString
$password = [System.Net.NetworkCredential]::new("", $securePassword).Password

function Invoke-CyrpRequest {
    param(
        [Parameter(Mandatory = $true)][string]$Method,
        [Parameter(Mandatory = $true)][string]$Path,
        [object]$Body,
        [string]$AccessToken = ""
    )

    $headers = @{}
    if (-not [string]::IsNullOrWhiteSpace($AccessToken)) {
        $headers.Authorization = "Bearer $AccessToken"
    }

    $parameters = @{
        Method = $Method
        Uri = "$ApiBaseUrl$Path"
        Headers = $headers
        TimeoutSec = 60
    }

    if ($null -ne $Body) {
        $parameters.ContentType = "application/json"
        $parameters.Body = $Body | ConvertTo-Json -Depth 20
    }

    Invoke-RestMethod @parameters
}

Write-Host "[1/7] Logging in..."
$login = Invoke-CyrpRequest -Method "POST" -Path "/auth/login" -Body @{
    email = $AdminEmail
    password = $password
}

if ([string]::IsNullOrWhiteSpace($login.accessToken)) {
    throw "Login response did not contain accessToken"
}

$token = [string]$login.accessToken
$password = $null

Write-Host "[2/7] Checking API and database..."
$health = Invoke-CyrpRequest -Method "GET" -Path "/health"

Write-Host "[3/7] Checking Wazuh Server API..."
$wazuhStatus = Invoke-CyrpRequest -Method "GET" -Path "/wazuh/status" -AccessToken $token

Write-Host "[4/7] Reading Wazuh Agent inventory..."
$agents = $null
$agentsError = $null
try {
    $agents = Invoke-CyrpRequest -Method "GET" -Path "/wazuh/agents?limit=100" -AccessToken $token
}
catch {
    $agentsError = $_.Exception.Message
}

Write-Host "[5/7] Reading Phase 2 system health..."
$systemHealth = Invoke-CyrpRequest -Method "GET" -Path "/admin/system-health" -AccessToken $token

Write-Host "[6/7] Reading endpoints and bindings..."
$devices = Invoke-CyrpRequest -Method "GET" -Path "/admin/devices?limit=100" -AccessToken $token
$bindings = Invoke-CyrpRequest -Method "GET" -Path "/admin/wazuh-bindings" -AccessToken $token

$syncResult = $null
if ($RunDeviceSync) {
    if ([string]::IsNullOrWhiteSpace($DeviceId)) {
        throw "-DeviceId is required when -RunDeviceSync is set"
    }

    Write-Host "[7/7] Running one endpoint synchronization..."
    $syncResult = Invoke-CyrpRequest -Method "POST" -Path "/admin/devices/$DeviceId/data-sync" -AccessToken $token
}
else {
    Write-Host "[7/7] Device synchronization skipped. Use -RunDeviceSync -DeviceId <uuid> to test it."
}

$report = [ordered]@{
    checkedAt = (Get-Date).ToUniversalTime().ToString("o")
    apiBaseUrl = $ApiBaseUrl
    api = $health
    wazuh = $wazuhStatus
    agents = if ($null -ne $agents) {
        [ordered]@{
            total = $agents.total
            returned = @($agents.items).Count
            active = @($agents.items | Where-Object { $_.status -eq "active" }).Count
        }
    }
    else {
        [ordered]@{
            error = $agentsError
        }
    }
    phase2 = $systemHealth
    devices = [ordered]@{
        total = $devices.total
        returned = @($devices.items).Count
    }
    bindings = [ordered]@{
        total = @($bindings).Count
    }
    deviceSync = $syncResult
}

$outputDirectory = Join-Path (Get-Location) "artifacts"
New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
$outputPath = Join-Path $outputDirectory ("phase2-verification-{0}.json" -f (Get-Date -Format "yyyyMMdd-HHmmss"))
$report | ConvertTo-Json -Depth 30 | Set-Content -Path $outputPath -Encoding UTF8

Write-Host ""
Write-Host "Phase 2 verification completed."
Write-Host "Report: $outputPath"
Write-Host "Wazuh connected: $($wazuhStatus.connected)"
Write-Host "Live agents returned: $(@($agents.items).Count)"
Write-Host "CYRP bindings: $(@($bindings).Count)"
