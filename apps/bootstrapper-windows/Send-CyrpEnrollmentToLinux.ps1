[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$EnrollmentFile,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Za-z0-9._@:-]+$')]
    [string]$LinuxHost,

    [string]$ProjectRoot = (Get-Location).Path,

    [ValidatePattern('^[A-Za-z0-9._/-]+$')]
    [string]$RemoteDirectory = '.cyrp/phase2b2',

    [string]$SshExecutable = 'ssh.exe',

    [string]$ScpExecutable = 'scp.exe',

    [switch]$KeepLocalTransferFile
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

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

    $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $currentAccount = $currentIdentity.User.Translate(
        [Security.Principal.NTAccount]
    )

    $systemSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    $systemAccount = $systemSid.Translate(
        [Security.Principal.NTAccount]
    )

    $acl = [Security.AccessControl.FileSecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner($currentAccount)

    foreach ($account in @($currentAccount, $systemAccount)) {
        $rule = [Security.AccessControl.FileSystemAccessRule]::new(
            $account,
            [Security.AccessControl.FileSystemRights]::FullControl,
            [Security.AccessControl.AccessControlType]::Allow
        )

        [void]$acl.AddAccessRule($rule)
    }

    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Assert-CommandAvailable {
    param(
        [Parameter(Mandatory = $true)]
        [string]$CommandName
    )

    $command = Get-Command $CommandName -ErrorAction SilentlyContinue

    if (-not $command) {
        throw "Required executable was not found: $CommandName"
    }

    return $command.Source
}

if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw 'Run this transfer helper on the Windows machine that created the Phase 2B.1 DPAPI enrollment file.'
}

$resolvedEnrollmentFile = (Resolve-Path -LiteralPath $EnrollmentFile).Path
$resolvedProjectRoot = (Resolve-Path -LiteralPath $ProjectRoot).Path

$linuxInstaller = Join-Path `
    $resolvedProjectRoot `
    'apps\bootstrapper-linux\Install-CyrpWazuhFromEnrollmentFile.sh'

$linuxTester = Join-Path `
    $resolvedProjectRoot `
    'apps\bootstrapper-linux\Test-CyrpWazuhAgent.sh'

foreach ($requiredFile in @($linuxInstaller, $linuxTester)) {
    if (-not [IO.File]::Exists($requiredFile)) {
        throw "Required Phase 2B.2-Linux file was not found: $requiredFile"
    }
}

$sshPath = Assert-CommandAvailable -CommandName $SshExecutable
$scpPath = Assert-CommandAvailable -CommandName $ScpExecutable

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

if ($enrollment.AgentToken -isnot [Security.SecureString]) {
    throw 'Enrollment AgentToken is not a DPAPI SecureString.'
}

if ($enrollment.ClientKey -isnot [Security.SecureString]) {
    throw 'Enrollment ClientKey is not a DPAPI SecureString.'
}

if ([string]$enrollment.AgentId -notmatch '^\d{3,}$') {
    throw "Unexpected Wazuh Agent ID: $($enrollment.AgentId)"
}

if ([string]$enrollment.Protocol -notin @('tcp', 'udp')) {
    throw "Unexpected Wazuh protocol: $($enrollment.Protocol)"
}

$agentToken = $null
$clientKey = $null
$payloadJson = $null
$tempDirectory = $null
$localPayloadPath = $null

try {
    $agentToken = ConvertFrom-CyrpSecureString `
        -SecureValue $enrollment.AgentToken

    $clientKey = ConvertFrom-CyrpSecureString `
        -SecureValue $enrollment.ClientKey

    if ([string]::IsNullOrWhiteSpace($agentToken)) {
        throw 'The CYRP agent token is empty.'
    }

    if ([string]::IsNullOrWhiteSpace($clientKey)) {
        throw 'The Wazuh client key is empty.'
    }

    $transferPayload = [ordered]@{
        version          = 1
        deviceId         = [string]$enrollment.DeviceId
        installationId   = [string]$enrollment.InstallationId
        agentId          = [string]$enrollment.AgentId
        agentName        = [string]$enrollment.AgentName
        managerAddress   = [string]$enrollment.ManagerAddress
        managerPort      = [int]$enrollment.ManagerPort
        protocol         = [string]$enrollment.Protocol
        agentToken       = $agentToken
        clientKey        = $clientKey
        transferredAtUtc = [DateTime]::UtcNow.ToString('o')
    }

    $payloadJson = $transferPayload |
        ConvertTo-Json -Depth 5 -Compress

    $tempDirectory = Join-Path `
        $env:TEMP `
        ("CYRP\Phase2B2Linux\" + [Guid]::NewGuid().ToString('N'))

    [IO.Directory]::CreateDirectory($tempDirectory) | Out-Null

    $payloadFileName = "enrollment-agent-$($enrollment.AgentId).json"
    $localPayloadPath = Join-Path $tempDirectory $payloadFileName

    $utf8WithoutBom = [Text.UTF8Encoding]::new($false)
    [IO.File]::WriteAllText(
        $localPayloadPath,
        $payloadJson,
        $utf8WithoutBom
    )

    Set-CyrpRestrictedFileAcl -Path $localPayloadPath

    $prepareRemoteCommand = (
        "umask 077 && " +
        "mkdir -p -- '$RemoteDirectory' && " +
        "chmod 700 -- '$RemoteDirectory'"
    )

    & $sshPath $LinuxHost $prepareRemoteCommand

    if ($LASTEXITCODE -ne 0) {
        throw "Unable to prepare remote directory through SSH. Exit code: $LASTEXITCODE"
    }

    $remoteTarget = "${LinuxHost}:$RemoteDirectory/"

    & $scpPath `
        $localPayloadPath `
        $linuxInstaller `
        $linuxTester `
        $remoteTarget

    if ($LASTEXITCODE -ne 0) {
        throw "SCP transfer failed. Exit code: $LASTEXITCODE"
    }

    $secureRemoteCommand = (
        "chmod 600 -- '$RemoteDirectory/$payloadFileName' && " +
        "chmod 700 -- '$RemoteDirectory/Install-CyrpWazuhFromEnrollmentFile.sh' && " +
        "chmod 700 -- '$RemoteDirectory/Test-CyrpWazuhAgent.sh'"
    )

    & $sshPath $LinuxHost $secureRemoteCommand

    if ($LASTEXITCODE -ne 0) {
        throw "Unable to secure transferred files. Exit code: $LASTEXITCODE"
    }

    Write-Host ''
    Write-Host 'CYRP Phase 2B.2-Linux transfer completed.' -ForegroundColor Green
    Write-Host "Linux endpoint: $LinuxHost"
    Write-Host "Remote directory: ~/$RemoteDirectory"
    Write-Host "Enrollment file: ~/$RemoteDirectory/$payloadFileName"
    Write-Host ''
    Write-Host 'Run the following from Termius on the Ubuntu Agent VM:'
    Write-Host ''
    Write-Host "cd ~/$RemoteDirectory"
    Write-Host 'sudo bash ./Install-CyrpWazuhFromEnrollmentFile.sh \'
    Write-Host "  --enrollment-file './$payloadFileName' \"
    Write-Host '  --force-reenroll \'
    Write-Host "  --expected-old-agent-id '002' \"
    Write-Host '  --connection-timeout-seconds 180'
    Write-Host ''
    Write-Host 'The installer deletes the remote enrollment JSON after a successful migration.'
}
finally {
    $agentToken = $null
    $clientKey = $null
    $payloadJson = $null

    if (
        $localPayloadPath -and
        [IO.File]::Exists($localPayloadPath) -and
        -not $KeepLocalTransferFile
    ) {
        [IO.File]::Delete($localPayloadPath)
    }

    if (
        $tempDirectory -and
        [IO.Directory]::Exists($tempDirectory) -and
        -not $KeepLocalTransferFile
    ) {
        [IO.Directory]::Delete($tempDirectory, $true)
    }
}
