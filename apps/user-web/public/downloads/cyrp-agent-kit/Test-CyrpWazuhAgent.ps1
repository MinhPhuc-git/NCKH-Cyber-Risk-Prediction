[CmdletBinding()]
param(
    [string]$ExpectedAgentId,
    [string]$ExpectedManagerAddress,
    [int]$ExpectedManagerPort = 1514
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-WazuhInstallDirectory {
    $programFilesX86 = [Environment]::GetEnvironmentVariable('ProgramFiles(x86)')
    $programFiles = [Environment]::GetEnvironmentVariable('ProgramFiles')

    foreach ($candidate in @(
        if ($programFilesX86) { Join-Path $programFilesX86 'ossec-agent' }
        if ($programFiles) { Join-Path $programFiles 'ossec-agent' }
    )) {
        if ([IO.File]::Exists((Join-Path $candidate 'ossec.conf'))) {
            return $candidate
        }
    }

    return $null
}

$installDirectory = Get-WazuhInstallDirectory

if (-not $installDirectory) {
    throw 'Wazuh Agent installation directory was not found.'
}

$service = Get-Service -Name 'WazuhSvc' -ErrorAction SilentlyContinue

if (-not $service) {
    $service = Get-Service -Name 'wazuh' -ErrorAction SilentlyContinue
}

if (-not $service) {
    throw 'Wazuh Agent service was not found.'
}

$configurationPath = Join-Path $installDirectory 'ossec.conf'
$clientKeysPath = Join-Path $installDirectory 'client.keys'
$logPath = Join-Path $installDirectory 'ossec.log'
$configuration = [IO.File]::ReadAllText($configurationPath)

$addressMatch = [regex]::Match($configuration, '(?is)<client\b[^>]*>.*?<address>(.*?)</address>')
$portMatch = [regex]::Match($configuration, '(?is)<client\b[^>]*>.*?<port>(.*?)</port>')
$protocolMatch = [regex]::Match($configuration, '(?is)<client\b[^>]*>.*?<protocol>(.*?)</protocol>')

$clientIdentity = $null

if ([IO.File]::Exists($clientKeysPath)) {
    $clientKeyLine = [IO.File]::ReadAllText($clientKeysPath).Trim()

    if ($clientKeyLine) {
        $parts = $clientKeyLine -split '\s+', 4

        if ($parts.Count -ge 2) {
            $clientIdentity = [PSCustomObject]@{
                AgentId = $parts[0]
                AgentName = $parts[1]
            }
        }
    }
}

$latestConnectionLine = $null
$latestErrorLine = $null

if ([IO.File]::Exists($logPath)) {
    $recentLines = Get-Content -LiteralPath $logPath -Tail 200 -ErrorAction SilentlyContinue
    $latestConnectionLine = $recentLines | Where-Object { $_ -match 'Connected to the server' } | Select-Object -Last 1
    $latestErrorLine = $recentLines | Where-Object { $_ -match 'Unable to connect|Authentication error|Wrong key|corrupt payload' } | Select-Object -Last 1
}

$result = [PSCustomObject]@{
    InstallDirectory = $installDirectory
    ServiceName = $service.Name
    ServiceStatus = $service.Status
    AgentId = if ($clientIdentity) { $clientIdentity.AgentId } else { $null }
    AgentName = if ($clientIdentity) { $clientIdentity.AgentName } else { $null }
    ManagerAddress = if ($addressMatch.Success) { $addressMatch.Groups[1].Value.Trim() } else { $null }
    ManagerPort = if ($portMatch.Success) { $portMatch.Groups[1].Value.Trim() } else { $null }
    Protocol = if ($protocolMatch.Success) { $protocolMatch.Groups[1].Value.Trim() } else { $null }
    Connected = [bool]$latestConnectionLine
    LatestConnectionLine = $latestConnectionLine
    LatestErrorLine = $latestErrorLine
}

$result

if ($service.Status -ne [ServiceProcess.ServiceControllerStatus]::Running) {
    throw 'Wazuh Agent service is not running.'
}

if ($ExpectedAgentId -and $result.AgentId -ne $ExpectedAgentId) {
    throw "Expected Agent ID $ExpectedAgentId, but found $($result.AgentId)."
}

if ($ExpectedManagerAddress -and $result.ManagerAddress -ne $ExpectedManagerAddress) {
    throw "Expected manager $ExpectedManagerAddress, but found $($result.ManagerAddress)."
}

if ($ExpectedManagerPort -and [int]$result.ManagerPort -ne $ExpectedManagerPort) {
    throw "Expected manager port $ExpectedManagerPort, but found $($result.ManagerPort)."
}

if (-not $result.Connected) {
    throw 'No successful Wazuh manager connection was found in the recent agent log.'
}
