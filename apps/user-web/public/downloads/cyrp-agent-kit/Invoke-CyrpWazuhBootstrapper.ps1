[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$BackendBaseUrl,

    [string]$EnrollmentCode,

    [string]$MsiPath,

    [ValidatePattern('^[A-Fa-f0-9]{64}$')]
    [string]$ExpectedMsiSha256,

    [string]$AgentVersion = 'phase-2b2',

    [switch]$ForceReenroll,

    [ValidateRange(30, 900)]
    [int]$ConnectionTimeoutSeconds = 180
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw 'This bootstrapper can only run on Windows.'
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)

if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run PowerShell as Administrator before executing this script.'
}

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$installerScript = Join-Path $scriptRoot 'Install-CyrpWazuhFromEnrollmentFile.ps1'

if (-not [IO.File]::Exists($installerScript)) {
    throw "Bootstrapper component is missing: $installerScript"
}

if ([string]::IsNullOrWhiteSpace($EnrollmentCode)) {
    $EnrollmentCode = Read-Host 'Enter the one-time CYRP enrollment code'
}

$EnrollmentCode = $EnrollmentCode.Trim().ToUpperInvariant()

if ([string]::IsNullOrWhiteSpace($EnrollmentCode)) {
    throw 'Enrollment code cannot be empty.'
}

$programDataRoot = Join-Path $env:ProgramData 'CYRP'
$stateDirectory = Join-Path $programDataRoot 'State'
$pendingDirectory = Join-Path $env:LOCALAPPDATA 'CYRP\Phase2B2'

[IO.Directory]::CreateDirectory($stateDirectory) | Out-Null
[IO.Directory]::CreateDirectory($pendingDirectory) | Out-Null

$installationIdPath = Join-Path $stateDirectory 'installation-id.txt'

if ([IO.File]::Exists($installationIdPath)) {
    $installationId = [IO.File]::ReadAllText($installationIdPath).Trim()
}
else {
    $installationId = [guid]::NewGuid().ToString()
    [IO.File]::WriteAllText(
        $installationIdPath,
        $installationId,
        [Text.UTF8Encoding]::new($false)
    )
}

$operatingSystem = Get-CimInstance Win32_OperatingSystem
$architecture = if ([Environment]::Is64BitOperatingSystem) { 'x86_64' } else { 'x86' }

$body = @{
    enrollmentCode = $EnrollmentCode
    installationId = $installationId
    hostname = $env:COMPUTERNAME
    operatingSystem = $operatingSystem.Caption
    architecture = $architecture
    agentVersion = $AgentVersion
} | ConvertTo-Json

$enrollUri = ('{0}/agents/enroll' -f $BackendBaseUrl.TrimEnd('/'))

Write-Host 'Requesting CYRP Device and Wazuh Agent enrollment...'
$enrollmentResponse = Invoke-RestMethod `
    -Method Post `
    -Uri $enrollUri `
    -ContentType 'application/json' `
    -Body $body

$requiredResponsePaths = @(
    $enrollmentResponse.deviceId,
    $enrollmentResponse.agentToken,
    $enrollmentResponse.wazuh.agentId,
    $enrollmentResponse.wazuh.agentName,
    $enrollmentResponse.wazuh.clientKey,
    $enrollmentResponse.wazuh.managerAddress,
    $enrollmentResponse.wazuh.managerPort,
    $enrollmentResponse.wazuh.protocol
)

if ($requiredResponsePaths -contains $null) {
    throw 'The CYRP enrollment response is incomplete.'
}

$pendingFile = Join-Path $pendingDirectory ("wazuh-enrollment-{0}.clixml" -f $enrollmentResponse.deviceId)

$protectedEnrollment = [PSCustomObject]@{
    DeviceId = [string]$enrollmentResponse.deviceId
    InstallationId = $installationId
    AgentId = [string]$enrollmentResponse.wazuh.agentId
    AgentName = [string]$enrollmentResponse.wazuh.agentName
    ManagerAddress = [string]$enrollmentResponse.wazuh.managerAddress
    ManagerPort = [int]$enrollmentResponse.wazuh.managerPort
    Protocol = [string]$enrollmentResponse.wazuh.protocol
    AgentToken = ConvertTo-SecureString ([string]$enrollmentResponse.agentToken) -AsPlainText -Force
    ClientKey = ConvertTo-SecureString ([string]$enrollmentResponse.wazuh.clientKey) -AsPlainText -Force
}

$protectedEnrollment | Export-Clixml -LiteralPath $pendingFile

Write-Host ("Created Wazuh Agent {0} ({1}). Installing and configuring the endpoint..." -f $protectedEnrollment.AgentId, $protectedEnrollment.AgentName)

$installParameters = @{
    EnrollmentFile = $pendingFile
    ConnectionTimeoutSeconds = $ConnectionTimeoutSeconds
}

if ($MsiPath) {
    $installParameters.MsiPath = $MsiPath
}

if ($ExpectedMsiSha256) {
    $installParameters.ExpectedMsiSha256 = $ExpectedMsiSha256
}

if ($ForceReenroll) {
    $installParameters.ForceReenroll = $true
}

try {
    & $installerScript @installParameters
}
catch {
    Write-Warning "Enrollment was created, but endpoint configuration failed. Retry with: $pendingFile"
    throw
}
finally {
    $body = $null
    $enrollmentResponse = $null
    $protectedEnrollment = $null
    $EnrollmentCode = $null
}
