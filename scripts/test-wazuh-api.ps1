param(
    [Parameter(Mandatory = $true)]
    [string]$BaseUrl
)

$ErrorActionPreference = "Stop"
$BaseUrl = $BaseUrl.TrimEnd("/")

$curl = Get-Command curl.exe -ErrorAction SilentlyContinue

if (-not $curl) {
    throw "Khong tim thay curl.exe. Hay kiem tra bang lenh: curl.exe --version"
}

$username = Read-Host "Wazuh Server API username [wazuh]"

if ([string]::IsNullOrWhiteSpace($username)) {
    $username = "wazuh"
}

Write-Host ""
Write-Host "curl.exe se yeu cau mat khau cua user '$username'."
Write-Host "Mat khau khong hien ky tu khi nhap."
Write-Host ""

$token = & curl.exe `
    --silent `
    --show-error `
    --fail `
    --http1.1 `
    --insecure `
    --user $username `
    --request POST `
    "$BaseUrl/security/user/authenticate?raw=true"

if ($LASTEXITCODE -ne 0) {
    throw "Wazuh API authentication request failed. curl exit code: $LASTEXITCODE"
}

$token = ($token | Out-String).Trim().Trim('"')

if ([string]::IsNullOrWhiteSpace($token)) {
    throw "Wazuh API returned an empty token."
}

if (-not $token.StartsWith("eyJ")) {
    throw "Wazuh API did not return a JWT. Response: $token"
}

Write-Host "Authentication: OK"

$managerJson = & curl.exe `
    --silent `
    --show-error `
    --fail `
    --http1.1 `
    --insecure `
    --header "Authorization: Bearer $token" `
    "$BaseUrl/manager/info"

if ($LASTEXITCODE -ne 0) {
    throw "Manager info request failed. curl exit code: $LASTEXITCODE"
}

Write-Host "Manager info: OK"

try {
    $managerJson |
        ConvertFrom-Json |
        ConvertTo-Json -Depth 20
}
catch {
    Write-Host $managerJson
}

$agentsJson = & curl.exe `
    --silent `
    --show-error `
    --fail `
    --http1.1 `
    --insecure `
    --header "Authorization: Bearer $token" `
    "$BaseUrl/agents?limit=5"

if ($LASTEXITCODE -ne 0) {
    throw "Agent list request failed. curl exit code: $LASTEXITCODE"
}

Write-Host "Agent list: OK"

try {
    $agentsJson |
        ConvertFrom-Json |
        ConvertTo-Json -Depth 20
}
catch {
    Write-Host $agentsJson
}

$token = $null
