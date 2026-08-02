[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$EnrollmentFile,

    [string]$MsiPath,

    [ValidatePattern('^[A-Fa-f0-9]{64}$')]
    [string]$ExpectedMsiSha256,

    [switch]$ForceReenroll,

    [switch]$KeepEnrollmentFile,

    [ValidateRange(30, 900)]
    [int]$ConnectionTimeoutSeconds = 180
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-WindowsAdministrator {
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
        throw 'This bootstrapper can only run on Windows.'
    }

    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)

    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run PowerShell as Administrator before executing this script.'
    }
}

function ConvertFrom-CyrpSecureString {
    param(
        [Parameter(Mandatory = $true)]
        [Security.SecureString]$SecureValue
    )

    $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureValue)

    try {
        return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
    }
    finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
    }
}

function Set-CyrpRestrictedFileAcl {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $systemSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    $administratorsSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
    $systemAccount = $systemSid.Translate([Security.Principal.NTAccount])
    $administratorsAccount = $administratorsSid.Translate([Security.Principal.NTAccount])

    $acl = [Security.AccessControl.FileSecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner($administratorsAccount)

    foreach ($account in @($systemAccount, $administratorsAccount)) {
        $rule = [Security.AccessControl.FileSystemAccessRule]::new(
            $account,
            [Security.AccessControl.FileSystemRights]::FullControl,
            [Security.AccessControl.AccessControlType]::Allow
        )

        [void]$acl.AddAccessRule($rule)
    }

    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Protect-CyrpAgentToken {
    param(
        [Parameter(Mandatory = $true)]
        [string]$AgentToken,

        [Parameter(Mandatory = $true)]
        [string]$Destination
    )

    $plainBytes = [Text.Encoding]::UTF8.GetBytes($AgentToken)
    $entropy = [Text.Encoding]::UTF8.GetBytes('CYRP-AgentToken-v1')

    try {
        $protectedBytes = [Security.Cryptography.ProtectedData]::Protect(
            $plainBytes,
            $entropy,
            [Security.Cryptography.DataProtectionScope]::LocalMachine
        )

        [IO.File]::WriteAllBytes($Destination, $protectedBytes)
        Set-CyrpRestrictedFileAcl -Path $Destination
    }
    finally {
        if ($plainBytes) {
            [Array]::Clear($plainBytes, 0, $plainBytes.Length)
        }
    }
}

function Get-WazuhInstallDirectory {
    $programFilesX86 = [Environment]::GetEnvironmentVariable('ProgramFiles(x86)')
    $programFiles = [Environment]::GetEnvironmentVariable('ProgramFiles')

    $candidates = @(
        if ($programFilesX86) { Join-Path $programFilesX86 'ossec-agent' }
        if ($programFiles) { Join-Path $programFiles 'ossec-agent' }
    )

    foreach ($candidate in $candidates) {
        if (
            [IO.File]::Exists((Join-Path $candidate 'manage_agents.exe')) -and
            [IO.File]::Exists((Join-Path $candidate 'ossec.conf'))
        ) {
            return $candidate
        }
    }

    return $null
}

function Get-WazuhService {
    foreach ($serviceName in @('WazuhSvc', 'wazuh')) {
        $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue

        if ($service) {
            return $service
        }
    }

    return $null
}

function Install-WazuhAgentPackage {
    param(
        [Parameter(Mandatory = $true)]
        [string]$InstallerPath,

        [string]$ExpectedSha256,

        [Parameter(Mandatory = $true)]
        [string]$LogPath
    )

    $resolvedInstaller = (Resolve-Path -LiteralPath $InstallerPath).Path

    if ([IO.Path]::GetExtension($resolvedInstaller) -ne '.msi') {
        throw 'MsiPath must point to a Wazuh .msi package.'
    }

    if ($ExpectedSha256) {
        $actualHash = (Get-FileHash -LiteralPath $resolvedInstaller -Algorithm SHA256).Hash

        if ($actualHash -ne $ExpectedSha256.ToUpperInvariant()) {
            throw "Wazuh MSI SHA-256 mismatch. Actual: $actualHash"
        }
    }
    else {
        Write-Warning 'ExpectedMsiSha256 was not supplied. The package signature/hash was not pinned by CYRP.'
    }

    $arguments = @(
        '/i',
        ('"{0}"' -f $resolvedInstaller),
        '/qn',
        '/norestart',
        '/l*v',
        ('"{0}"' -f $LogPath)
    )

    Write-Host 'Installing the Wazuh Agent package without automatic enrollment...'

    $process = Start-Process `
        -FilePath 'msiexec.exe' `
        -ArgumentList $arguments `
        -Wait `
        -PassThru

    if ($process.ExitCode -notin @(0, 3010)) {
        throw "Wazuh MSI installation failed with exit code $($process.ExitCode). Log: $LogPath"
    }

    if ($process.ExitCode -eq 3010) {
        Write-Warning 'The MSI requested a reboot. Continue only if the Wazuh service and files are available.'
    }
}

function Set-WazuhTagValue {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Block,

        [Parameter(Mandatory = $true)]
        [string]$Tag,

        [Parameter(Mandatory = $true)]
        [string]$Value
    )

    $escapedValue = [Security.SecurityElement]::Escape($Value)
    $pattern = "(?is)<$Tag\b[^>]*>.*?</$Tag>"
    $replacement = "<$Tag>$escapedValue</$Tag>"

    if ([regex]::IsMatch($Block, $pattern)) {
        $tagRegex = [regex]::new($pattern)
        return $tagRegex.Replace($Block, $replacement, 1)
    }

    $serverCloseRegex = [regex]::new('(?is)</server>')
    return $serverCloseRegex.Replace(
        $Block,
        "  $replacement`r`n</server>",
        1
    )
}

function Set-WazuhManagerConfiguration {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ConfigurationPath,

        [Parameter(Mandatory = $true)]
        [string]$ManagerAddress,

        [Parameter(Mandatory = $true)]
        [int]$ManagerPort,

        [Parameter(Mandatory = $true)]
        [ValidateSet('tcp', 'udp')]
        [string]$Protocol
    )

    $content = [IO.File]::ReadAllText($ConfigurationPath)
    $clientMatch = [regex]::Match($content, '(?is)<client\b[^>]*>.*?</client>')

    if ($clientMatch.Success) {
        $clientBlock = $clientMatch.Value
        $serverMatch = [regex]::Match($clientBlock, '(?is)<server\b[^>]*>.*?</server>')

        if ($serverMatch.Success) {
            $serverBlock = $serverMatch.Value
            $serverBlock = Set-WazuhTagValue -Block $serverBlock -Tag 'address' -Value $ManagerAddress
            $serverBlock = Set-WazuhTagValue -Block $serverBlock -Tag 'port' -Value ([string]$ManagerPort)
            $serverBlock = Set-WazuhTagValue -Block $serverBlock -Tag 'protocol' -Value $Protocol

            $clientBlock = $clientBlock.Remove($serverMatch.Index, $serverMatch.Length)
            $clientBlock = $clientBlock.Insert($serverMatch.Index, $serverBlock)
        }
        else {
            $serverBlock = @"
  <server>
    <address>$([Security.SecurityElement]::Escape($ManagerAddress))</address>
    <port>$ManagerPort</port>
    <protocol>$Protocol</protocol>
  </server>
"@
            $clientCloseRegex = [regex]::new('(?is)</client>')
            $clientBlock = $clientCloseRegex.Replace(
                $clientBlock,
                "$serverBlock</client>",
                1
            )
        }

        $content = $content.Remove($clientMatch.Index, $clientMatch.Length)
        $content = $content.Insert($clientMatch.Index, $clientBlock)
    }
    else {
        $clientBlock = @"
  <client>
    <server>
      <address>$([Security.SecurityElement]::Escape($ManagerAddress))</address>
      <port>$ManagerPort</port>
      <protocol>$Protocol</protocol>
    </server>
  </client>
"@

        if ($content -notmatch '(?is)</ossec_config>') {
            throw 'The Wazuh ossec.conf file has no closing ossec_config element.'
        }

        $configCloseRegex = [regex]::new('(?is)</ossec_config>')
        $content = $configCloseRegex.Replace(
            $content,
            "$clientBlock</ossec_config>",
            1
        )
    }

    $utf8WithoutBom = [Text.UTF8Encoding]::new($false)
    [IO.File]::WriteAllText($ConfigurationPath, $content, $utf8WithoutBom)
}

function Test-TcpPort {
    param(
        [Parameter(Mandatory = $true)]
        [string]$HostName,

        [Parameter(Mandatory = $true)]
        [int]$Port,

        [ValidateRange(1, 30)]
        [int]$TimeoutSeconds = 5
    )

    $client = [Net.Sockets.TcpClient]::new()

    try {
        $asyncResult = $client.BeginConnect($HostName, $Port, $null, $null)

        if (-not $asyncResult.AsyncWaitHandle.WaitOne([TimeSpan]::FromSeconds($TimeoutSeconds))) {
            return $false
        }

        $client.EndConnect($asyncResult)
        return $true
    }
    catch {
        return $false
    }
    finally {
        $client.Dispose()
    }
}

function Wait-WazuhConnection {
    param(
        [Parameter(Mandatory = $true)]
        [string]$LogPath,

        [Parameter(Mandatory = $true)]
        [int]$TimeoutSeconds,

        [long]$InitialLogLength = 0
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $lastErrorLine = $null

    do {
        $service = Get-WazuhService

        if (-not $service) {
            throw 'The Wazuh Agent service disappeared after configuration.'
        }

        $service.Refresh()

        if ($service.Status -eq [ServiceProcess.ServiceControllerStatus]::Stopped) {
            throw 'The Wazuh Agent service stopped while waiting for a manager connection.'
        }

        if ([IO.File]::Exists($LogPath)) {
            $fileInfo = Get-Item -LiteralPath $LogPath
            $readOffset = if ($fileInfo.Length -ge $InitialLogLength) {
                $InitialLogLength
            }
            else {
                0
            }

            $stream = [IO.File]::Open(
                $LogPath,
                [IO.FileMode]::Open,
                [IO.FileAccess]::Read,
                [IO.FileShare]::ReadWrite
            )

            try {
                [void]$stream.Seek($readOffset, [IO.SeekOrigin]::Begin)
                $reader = [IO.StreamReader]::new($stream, [Text.Encoding]::UTF8, $true, 4096, $true)

                try {
                    $newLogText = $reader.ReadToEnd()
                }
                finally {
                    $reader.Dispose()
                }
            }
            finally {
                $stream.Dispose()
            }

            if ($newLogText -match 'Connected to the server') {
                return $true
            }

            $lastErrorLine = ($newLogText -split "`r?`n") |
                Where-Object {
                    $_ -match 'Unable to connect|Authentication error|Wrong key|corrupt payload'
                } |
                Select-Object -Last 1
        }

        Start-Sleep -Seconds 5
    }
    while ((Get-Date) -lt $deadline)

    if ($lastErrorLine) {
        Write-Warning "Latest Wazuh connection error: $lastErrorLine"
    }

    return $false
}

Assert-WindowsAdministrator

$resolvedEnrollmentFile = (Resolve-Path -LiteralPath $EnrollmentFile).Path
$enrollment = Import-Clixml -LiteralPath $resolvedEnrollmentFile

$requiredProperties = @(
    'DeviceId',
    'InstallationId',
    'AgentId',
    'AgentName',
    'ManagerAddress',
    'ManagerPort',
    'Protocol',
    'AgentToken',
    'ClientKey'
)

foreach ($propertyName in $requiredProperties) {
    if (-not $enrollment.PSObject.Properties[$propertyName]) {
        throw "Enrollment file is missing property: $propertyName"
    }
}

$protocol = ([string]$enrollment.Protocol).Trim().ToLowerInvariant()

if ($protocol -notin @('tcp', 'udp')) {
    throw "Unsupported Wazuh protocol: $protocol"
}

$managerAddress = ([string]$enrollment.ManagerAddress).Trim()
$managerPort = [int]$enrollment.ManagerPort
$agentId = ([string]$enrollment.AgentId).Trim()
$agentName = ([string]$enrollment.AgentName).Trim()

if ([string]::IsNullOrWhiteSpace($managerAddress)) {
    throw 'ManagerAddress is empty in the enrollment file.'
}

if ($protocol -eq 'tcp') {
    if (-not (Test-TcpPort -HostName $managerAddress -Port $managerPort -TimeoutSeconds 5)) {
        throw "Cannot reach Wazuh manager at ${managerAddress}:$managerPort over TCP. No local files were changed."
    }
}
else {
    Write-Warning 'UDP connectivity cannot be confirmed with the bootstrapper preflight check.'
}

$programDataRoot = Join-Path $env:ProgramData 'CYRP'
$logDirectory = Join-Path $programDataRoot 'Logs'
$stateDirectory = Join-Path $programDataRoot 'State'
$secretDirectory = Join-Path $programDataRoot 'Secrets'
$backupDirectory = Join-Path $programDataRoot ("Backups\{0}" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))

foreach ($directory in @($logDirectory, $stateDirectory, $secretDirectory, $backupDirectory)) {
    [IO.Directory]::CreateDirectory($directory) | Out-Null
}

$installLogPath = Join-Path $logDirectory ("wazuh-msi-{0}.log" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
$installDirectory = Get-WazuhInstallDirectory

if (-not $installDirectory) {
    if ([string]::IsNullOrWhiteSpace($MsiPath)) {
        throw 'Wazuh Agent is not installed. Supply -MsiPath with the official Wazuh Windows MSI.'
    }

    Install-WazuhAgentPackage `
        -InstallerPath $MsiPath `
        -ExpectedSha256 $ExpectedMsiSha256 `
        -LogPath $installLogPath

    $deadline = (Get-Date).AddSeconds(60)

    do {
        Start-Sleep -Seconds 2
        $installDirectory = Get-WazuhInstallDirectory
    }
    while (-not $installDirectory -and (Get-Date) -lt $deadline)

    if (-not $installDirectory) {
        throw "Wazuh Agent files were not found after MSI installation. Log: $installLogPath"
    }
}

$service = Get-WazuhService

if (-not $service) {
    throw 'Wazuh Agent files exist, but the WazuhSvc service was not found.'
}

$configurationPath = Join-Path $installDirectory 'ossec.conf'
$clientKeysPath = Join-Path $installDirectory 'client.keys'
$manageAgentsPath = Join-Path $installDirectory 'manage_agents.exe'
$agentLogPath = Join-Path $installDirectory 'ossec.log'

foreach ($path in @($configurationPath, $manageAgentsPath)) {
    if (-not [IO.File]::Exists($path)) {
        throw "Required Wazuh file was not found: $path"
    }
}

if ($service.Status -ne [ServiceProcess.ServiceControllerStatus]::Stopped) {
    Stop-Service -Name $service.Name -Force
    $service.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds(30))
}

[IO.File]::Copy($configurationPath, (Join-Path $backupDirectory 'ossec.conf'), $true)

$existingClientKey = $null

if ([IO.File]::Exists($clientKeysPath)) {
    [IO.File]::Copy($clientKeysPath, (Join-Path $backupDirectory 'client.keys'), $true)
    $existingClientKey = [IO.File]::ReadAllText($clientKeysPath).Trim()
}

$clientKey = ConvertFrom-CyrpSecureString -SecureValue $enrollment.ClientKey
$agentToken = ConvertFrom-CyrpSecureString -SecureValue $enrollment.AgentToken

try {
    if (
        -not [string]::IsNullOrWhiteSpace($existingClientKey) -and
        $existingClientKey -ne $clientKey -and
        -not $ForceReenroll
    ) {
        $existingParts = $existingClientKey -split '\s+', 3
        $existingIdentity = if ($existingParts.Count -ge 2) {
            "$($existingParts[0])/$($existingParts[1])"
        }
        else {
            'unknown'
        }

        throw "This endpoint is already enrolled as $existingIdentity. Re-run with -ForceReenroll only when replacing that identity is intentional."
    }

    Set-WazuhManagerConfiguration `
        -ConfigurationPath $configurationPath `
        -ManagerAddress $managerAddress `
        -ManagerPort $managerPort `
        -Protocol $protocol

    if ($existingClientKey -ne $clientKey) {
        Write-Host "Importing Wazuh client key for Agent $agentId ($agentName)..."
        $importOutput = @('y') | & $manageAgentsPath '-i' $clientKey 2>&1
        $importExitCode = $LASTEXITCODE

        if ($importExitCode -ne 0) {
            $safeOutput = ($importOutput | Out-String).Trim()
            throw "manage_agents.exe failed with exit code $importExitCode. Output: $safeOutput"
        }
    }
    else {
        Write-Host 'The intended Wazuh client key is already installed. Skipping key import.'
    }

    $agentTokenPath = Join-Path $secretDirectory 'agent-token.dpapi'
    Protect-CyrpAgentToken -AgentToken $agentToken -Destination $agentTokenPath

    $statePath = Join-Path $stateDirectory 'bootstrapper-state.json'
    $state = [ordered]@{
        version = 1
        deviceId = [string]$enrollment.DeviceId
        installationId = [string]$enrollment.InstallationId
        wazuhAgentId = $agentId
        wazuhAgentName = $agentName
        managerAddress = $managerAddress
        managerPort = $managerPort
        protocol = $protocol
        configuredAt = (Get-Date).ToUniversalTime().ToString('o')
        agentTokenPath = $agentTokenPath
    }

    $stateJson = $state | ConvertTo-Json -Depth 5
    [IO.File]::WriteAllText($statePath, $stateJson, [Text.UTF8Encoding]::new($false))
    Set-CyrpRestrictedFileAcl -Path $statePath

    $initialLogLength = if ([IO.File]::Exists($agentLogPath)) {
        (Get-Item -LiteralPath $agentLogPath).Length
    }
    else {
        0
    }

    Start-Service -Name $service.Name
    $service.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Running, [TimeSpan]::FromSeconds(30))

    $connected = Wait-WazuhConnection `
        -LogPath $agentLogPath `
        -TimeoutSeconds $ConnectionTimeoutSeconds `
        -InitialLogLength $initialLogLength

    if (-not $connected) {
        throw "Wazuh Agent is running but did not confirm a manager connection within $ConnectionTimeoutSeconds seconds. Enrollment file was retained for retry. Log: $agentLogPath"
    }

    if (-not $KeepEnrollmentFile) {
        Remove-Item -LiteralPath $resolvedEnrollmentFile -Force
    }

    [PSCustomObject]@{
        Success = $true
        DeviceId = [string]$enrollment.DeviceId
        WazuhAgentId = $agentId
        WazuhAgentName = $agentName
        ManagerAddress = $managerAddress
        ManagerPort = $managerPort
        Protocol = $protocol
        ServiceName = $service.Name
        ServiceStatus = (Get-Service -Name $service.Name).Status
        InstallDirectory = $installDirectory
        StateFile = $statePath
        EnrollmentFileRemoved = (-not $KeepEnrollmentFile)
        BackupDirectory = $backupDirectory
    }
}
finally {
    $clientKey = $null
    $agentToken = $null
    $enrollment = $null
}
