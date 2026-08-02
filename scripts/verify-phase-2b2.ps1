param(
    [string]$ProjectRoot = (Get-Location).Path
)

$ErrorActionPreference = 'Stop'

$requiredFiles = @(
    'apps\bootstrapper-windows\README.md',
    'apps\bootstrapper-windows\Install-CyrpWazuhFromEnrollmentFile.ps1',
    'apps\bootstrapper-windows\Invoke-CyrpWazuhBootstrapper.ps1',
    'apps\bootstrapper-windows\Test-CyrpWazuhAgent.ps1',
    'apps\api\src\modules\agents\agents.service.ts'
)

foreach ($relativePath in $requiredFiles) {
    $fullPath = Join-Path $ProjectRoot $relativePath

    if (-not [IO.File]::Exists($fullPath)) {
        throw "Missing Phase 2B.2 file: $relativePath"
    }
}

$agentsService = Join-Path $ProjectRoot 'apps\api\src\modules\agents\agents.service.ts'
$agentsText = [IO.File]::ReadAllText($agentsService)

if ($agentsText -notmatch 'wazuhAgentBinding' -or $agentsText -notmatch 'provisionedAgent') {
    throw 'Phase 2B.1 automatic Wazuh enrollment is not present.'
}

$scriptFiles = @(
    'apps\bootstrapper-windows\Install-CyrpWazuhFromEnrollmentFile.ps1',
    'apps\bootstrapper-windows\Invoke-CyrpWazuhBootstrapper.ps1',
    'apps\bootstrapper-windows\Test-CyrpWazuhAgent.ps1'
)

foreach ($relativePath in $scriptFiles) {
    $fullPath = Join-Path $ProjectRoot $relativePath
    $tokens = $null
    $errors = $null

    [System.Management.Automation.Language.Parser]::ParseFile(
        $fullPath,
        [ref]$tokens,
        [ref]$errors
    ) | Out-Null

    if ($errors.Count -gt 0) {
        $details = ($errors | ForEach-Object { $_.Message }) -join '; '
        throw "PowerShell parse failure in ${relativePath}: $details"
    }

    Write-Host "Parsed: $relativePath"
}

$installerPath = Join-Path $ProjectRoot 'apps\bootstrapper-windows\Install-CyrpWazuhFromEnrollmentFile.ps1'
$installerText = [IO.File]::ReadAllText($installerPath)

foreach ($requiredPattern in @(
    'manage_agents\.exe',
    'WazuhSvc',
    'ProtectedData',
    'ForceReenroll',
    'Connected to the server'
)) {
    if ($installerText -notmatch $requiredPattern) {
        throw "Bootstrapper requirement is missing: $requiredPattern"
    }
}

$fullBootstrapperPath = Join-Path $ProjectRoot 'apps\bootstrapper-windows\Invoke-CyrpWazuhBootstrapper.ps1'
$fullBootstrapperText = [IO.File]::ReadAllText($fullBootstrapperPath)

if ($fullBootstrapperText -notmatch '/api/v1/agents/enroll') {
    throw 'Full bootstrapper does not call the Phase 2B.1 enrollment endpoint.'
}

Write-Host ''
Write-Host 'CYRP Phase 2B.2 verification completed.' -ForegroundColor Green
Write-Host 'No database migration is required.'
