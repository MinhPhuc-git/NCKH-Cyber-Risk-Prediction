param(
    [Parameter(Mandatory = $true)]
    [string]$BaseUrl,

    [switch]$AllowSelfSigned
)

$ErrorActionPreference = "Stop"
$BaseUrl = $BaseUrl.TrimEnd("/")

$oldSecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol
$oldCertificateCallback = [System.Net.ServicePointManager]::ServerCertificateValidationCallback

try {
    [System.Net.ServicePointManager]::SecurityProtocol = `
        [System.Net.SecurityProtocolType]::Tls12

    if ($AllowSelfSigned) {
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {
            param(
                $sender,
                $certificate,
                $chain,
                $sslPolicyErrors
            )

            return $true
        }
    }

    $credential = Get-Credential `
        -Message "Nhap tai khoan Wazuh Server API (thuong la user: wazuh)"

    $username = $credential.UserName
    $password = $credential.GetNetworkCredential().Password

    $basicValue = [Convert]::ToBase64String(
        [Text.Encoding]::UTF8.GetBytes(
            "$username`:$password"
        )
    )

    $authResponse = Invoke-WebRequest `
        -UseBasicParsing `
        -Method Post `
        -Uri "$BaseUrl/security/user/authenticate?raw=true" `
        -Headers @{
            Authorization = "Basic $basicValue"
            Accept = "application/json"
        }

    $token = $authResponse.Content.Trim().Trim('"')

    if ([string]::IsNullOrWhiteSpace($token)) {
        throw "Wazuh API authentication returned an empty token."
    }

    Write-Host "Authentication: OK"

    $bearerHeaders = @{
        Authorization = "Bearer $token"
        Accept = "application/json"
    }

    $manager = Invoke-RestMethod `
        -UseBasicParsing `
        -Method Get `
        -Uri "$BaseUrl/manager/info" `
        -Headers $bearerHeaders

    Write-Host "Manager info: OK"
    $manager | ConvertTo-Json -Depth 20

    $agents = Invoke-RestMethod `
        -UseBasicParsing `
        -Method Get `
        -Uri "$BaseUrl/agents?limit=5" `
        -Headers $bearerHeaders

    Write-Host "Agent list: OK"
    $agents | ConvertTo-Json -Depth 20
}
catch {
    Write-Error $_
    exit 1
}
finally {
    [System.Net.ServicePointManager]::SecurityProtocol = $oldSecurityProtocol
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = `
        $oldCertificateCallback

    $password = $null
    $token = $null
}
