param(
    [string]$ProjectRoot = (Get-Location).Path
)

$ErrorActionPreference = 'Stop'

$requiredFiles = @(
    'apps\bootstrapper-windows\Send-CyrpEnrollmentToLinux.ps1',
    'apps\bootstrapper-linux\Install-CyrpWazuhFromEnrollmentFile.sh',
    'apps\bootstrapper-linux\Test-CyrpWazuhAgent.sh',
    'apps\bootstrapper-linux\README.md',
    'apps\api\src\modules\agents\agents.service.ts'
)

foreach ($relativePath in $requiredFiles) {
    $fullPath = Join-Path $ProjectRoot $relativePath

    if (-not [IO.File]::Exists($fullPath)) {
        throw "Missing Phase 2B.2-Linux file: $relativePath"
    }
}

$agentsService = Join-Path `
    $ProjectRoot `
    'apps\api\src\modules\agents\agents.service.ts'

$agentsText = [IO.File]::ReadAllText($agentsService)

if (
    $agentsText -notmatch 'wazuhAgentBinding' -or
    $agentsText -notmatch 'provisionedAgent'
) {
    throw 'Phase 2B.1 automatic Wazuh enrollment is not present.'
}

$transferScript = Join-Path `
    $ProjectRoot `
    'apps\bootstrapper-windows\Send-CyrpEnrollmentToLinux.ps1'

$tokens = $null
$errors = $null

[System.Management.Automation.Language.Parser]::ParseFile(
    $transferScript,
    [ref]$tokens,
    [ref]$errors
) | Out-Null

if ($errors.Count -gt 0) {
    $details = (
        $errors |
        ForEach-Object { $_.Message }
    ) -join '; '

    throw "PowerShell parse failure: $details"
}

Write-Host 'Parsed: apps\bootstrapper-windows\Send-CyrpEnrollmentToLinux.ps1'

$installerPath = Join-Path `
    $ProjectRoot `
    'apps\bootstrapper-linux\Install-CyrpWazuhFromEnrollmentFile.sh'

$installerText = [IO.File]::ReadAllText($installerPath)

foreach ($requiredPattern in @(
    'manage_agents',
    'ForceReenroll|force-reenroll',
    'client\.keys',
    'ossec\.conf',
    'wazuh-agentd\.state',
    'on_exit|Restoring Wazuh Agent files',
    'agent-token'
)) {
    if ($installerText -notmatch $requiredPattern) {
        throw "Linux bootstrapper requirement is missing: $requiredPattern"
    }
}

Write-Host 'Static Linux bootstrapper requirements: OK'

$bashCommand = Get-Command bash.exe -ErrorAction SilentlyContinue

if (-not $bashCommand) {
    $bashCommand = Get-Command bash -ErrorAction SilentlyContinue
}

$bashUsable = $false

if ($bashCommand) {
    $isWindowsWslLauncher = (
        $bashCommand.Source -match '\\Windows\\System32\\bash\.exe$'
    )

    if ($isWindowsWslLauncher) {
        Write-Warning (
            'Windows WSL bash launcher was found, but Bash syntax checking is ' +
            'skipped here. Validate the shell scripts on the Ubuntu Agent VM.'
        )
    }
    else {
        & $bashCommand.Source -lc 'exit 0' *> $null

        if ($LASTEXITCODE -eq 0) {
            $bashUsable = $true
        }
        else {
            Write-Warning (
                'A bash command was found but is not usable. ' +
                'Validate the shell scripts on the Ubuntu Agent VM.'
            )
        }
    }
}
else {
    Write-Warning (
        'bash was not found. Validate the shell scripts on the Ubuntu Agent VM.'
    )
}

if ($bashUsable) {
    $linuxScripts = @(
        'apps/bootstrapper-linux/Install-CyrpWazuhFromEnrollmentFile.sh',
        'apps/bootstrapper-linux/Test-CyrpWazuhAgent.sh'
    )

    Push-Location $ProjectRoot

    try {
        foreach ($relativePath in $linuxScripts) {
            $bashRelativePath = $relativePath -replace '\\', '/'

            & $bashCommand.Source -n $bashRelativePath

            if ($LASTEXITCODE -ne 0) {
                throw "Bash syntax validation failed: $relativePath"
            }

            Write-Host "Bash syntax: $relativePath"
        }
    }
    finally {
        Pop-Location
    }
}

Write-Host ''
Write-Host 'CYRP Phase 2B.2-Linux verification completed.' -ForegroundColor Green
Write-Host 'No Prisma migration and no NestJS restart are required.'
Write-Host 'Run scripts/verify-phase-2b2-linux.sh on the Ubuntu Agent VM after transfer.'
