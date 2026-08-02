[CmdletBinding()]
param(
    [string]$ApiBaseUrl = "http://localhost:3001/api/v1",
    [string]$AdminEmail = "",
    [string]$DeviceId = "",
    [switch]$RefreshAllAgentStatuses,
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
        TimeoutSec = 120
    }

    if ($null -ne $Body) {
        $parameters.ContentType = "application/json"
        $parameters.Body = $Body | ConvertTo-Json -Depth 20
    }

    Invoke-RestMethod @parameters
}

Write-Host "[1/6] Logging in..."
$login = Invoke-CyrpRequest -Method "POST" -Path "/auth/login" -Body @{
    email = $AdminEmail
    password = $password
}

if ([string]::IsNullOrWhiteSpace($login.accessToken)) {
    throw "Login response did not contain accessToken"
}

$token = [string]$login.accessToken
$password = $null

Write-Host "[2/6] Reading Phase 2.1 system health..."
$health = Invoke-CyrpRequest -Method "GET" -Path "/admin/system-health" -AccessToken $token

if ($health.synchronization.syncLock.strategy -ne "DATABASE_LEASE") {
    throw "Unexpected sync lock strategy: $($health.synchronization.syncLock.strategy)"
}

Write-Host "[3/6] Reading bindings..."
$bindings = Invoke-CyrpRequest -Method "GET" -Path "/admin/wazuh-bindings" -AccessToken $token

$statusRefresh = $null
if ($RefreshAllAgentStatuses) {
    Write-Host "[4/6] Refreshing all bound Agent statuses..."
    $statusRefresh = Invoke-CyrpRequest -Method "POST" -Path "/wazuh-bindings/status-refresh" -AccessToken $token
}
else {
    Write-Host "[4/6] Agent status refresh skipped. Use -RefreshAllAgentStatuses to execute it."
}

$deviceSync = $null
if ($RunDeviceSync) {
    if ([string]::IsNullOrWhiteSpace($DeviceId)) {
        throw "-DeviceId is required when -RunDeviceSync is set"
    }

    Write-Host "[5/6] Running one endpoint data synchronization..."
    $deviceSync = Invoke-CyrpRequest -Method "POST" -Path "/admin/devices/$DeviceId/data-sync" -AccessToken $token
}
else {
    Write-Host "[5/6] Device synchronization skipped."
}

Write-Host "[6/6] Reading final health state..."
$finalHealth = Invoke-CyrpRequest -Method "GET" -Path "/admin/system-health" -AccessToken $token

$report = [ordered]@{
    checkedAt = (Get-Date).ToUniversalTime().ToString("o")
    apiBaseUrl = $ApiBaseUrl
    initialHealth = $health
    bindings = [ordered]@{
        total = @($bindings).Count
        failures = @($bindings | Where-Object { $_.consecutiveStatusFailures -gt 0 }).Count
    }
    statusRefresh = $statusRefresh
    deviceSync = $deviceSync
    finalHealth = $finalHealth
}

$outputDirectory = Join-Path (Get-Location) "artifacts"
New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
$outputPath = Join-Path $outputDirectory ("phase2-1-agent-runtime-{0}.json" -f (Get-Date -Format "yyyyMMdd-HHmmss"))
$report | ConvertTo-Json -Depth 40 | Set-Content -Path $outputPath -Encoding UTF8

Write-Host ""
Write-Host "Phase 2.1 runtime verification completed."
Write-Host "Report: $outputPath"
Write-Host "Bindings: $(@($bindings).Count)"
Write-Host "Database lease strategy: $($finalHealth.synchronization.syncLock.strategy)"
Write-Host "Agent status scheduler enabled: $($finalHealth.agentRuntime.enabled)"
