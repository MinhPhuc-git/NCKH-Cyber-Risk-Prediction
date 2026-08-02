[CmdletBinding()]
param(
    [string]$ProjectRoot = (Split-Path -Parent $PSScriptRoot),
    [string]$OutputDirectory,
    [switch]$KeepStaging
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$source = (Resolve-Path -LiteralPath $ProjectRoot).Path
$projectName = Split-Path -Leaf $source
$parentDirectory = Split-Path -Parent $source

if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = $parentDirectory
}

$outputRoot = [IO.Path]::GetFullPath($OutputDirectory)
[IO.Directory]::CreateDirectory($outputRoot) | Out-Null

$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$stageRoot = Join-Path $env:TEMP ("cyrp-review-stage-{0}-{1}" -f $PID, $timestamp)
$stageProject = Join-Path $stageRoot $projectName
$output = Join-Path $outputRoot ("{0}-review-{1}.zip" -f $projectName, $timestamp)

$excludedDirectories = @(
    'node_modules',
    '.git',
    '.next',
    'dist',
    'build',
    'coverage',
    'venv',
    '.venv',
    '__pycache__',
    '.pytest_cache',
    '.idea',
    '.vscode',
    'logs',
    'tmp',
    '.phase-backups',
    '.review-output',
    'artifacts',
    'backups'
)

$excludedFiles = @(
    '*.log',
    '*.pem',
    '*.key',
    '*.p12',
    '*.pfx',
    '*.jks',
    '*.sqlite',
    '*.db',
    '*.dump',
    '*.backup',
    '*.bak',
    '*.tsbuildinfo',
    '*.zip',
    'credentials.json',
    'identity.json',
    'latest-scan.json',
    'scan-*.json'
)

try {
    Remove-Item -LiteralPath $stageRoot -Recurse -Force -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Path $stageProject -Force | Out-Null

    $robocopyArguments = @(
        $source,
        $stageProject,
        '/E',
        '/XJ',
        '/R:2',
        '/W:2',
        '/NFL',
        '/NDL',
        '/NP',
        '/XD'
    ) + $excludedDirectories + @('/XF') + $excludedFiles

    & robocopy @robocopyArguments
    $robocopyExitCode = $LASTEXITCODE

    # Robocopy codes 0-7 represent success or non-fatal copy differences.
    if ($robocopyExitCode -ge 8) {
        throw "Robocopy failed with exit code $robocopyExitCode"
    }

    # Keep examples, but remove every real/local environment file.
    Get-ChildItem -LiteralPath $stageProject -Recurse -Force -File |
        Where-Object {
            $_.Name -eq '.env' -or
            ($_.Name -like '.env.*' -and $_.Name -notlike '*.example')
        } |
        Remove-Item -Force

    # Defense in depth for the archived legacy collector.
    $legacyRuntimePaths = @(
        (Join-Path $stageProject 'legacy\custom-agent-windows\config.json'),
        (Join-Path $stageProject 'legacy\custom-agent-windows\data\credentials.json'),
        (Join-Path $stageProject 'legacy\custom-agent-windows\data\identity.json'),
        (Join-Path $stageProject 'legacy\custom-agent-windows\data\latest-scan.json')
    )

    foreach ($runtimePath in $legacyRuntimePaths) {
        Remove-Item -LiteralPath $runtimePath -Force -ErrorAction SilentlyContinue
    }

    Get-ChildItem `
        -LiteralPath (Join-Path $stageProject 'legacy\custom-agent-windows\data') `
        -Filter 'scan-*.json' `
        -File `
        -ErrorAction SilentlyContinue |
        Remove-Item -Force

    $forbiddenNames = @(
        '.env',
        '.env.local',
        '.env.production',
        'credentials.json',
        'identity.json',
        'latest-scan.json',
        'config.json'
    )

    $forbiddenFiles = Get-ChildItem -LiteralPath $stageProject -Recurse -Force -File |
        Where-Object {
            $forbiddenNames -contains $_.Name -or
            $_.Name -like 'scan-*.json' -or
            $_.Extension -in @('.pem', '.key', '.p12', '.pfx', '.jks')
        }

    if ($forbiddenFiles) {
        $paths = ($forbiddenFiles.FullName -join [Environment]::NewLine)
        throw "Sensitive or runtime files remain in staging:`n$paths"
    }

    $privateKeyMatches = Get-ChildItem -LiteralPath $stageProject -Recurse -Force -File |
        Where-Object { $_.Length -le 5MB } |
        Select-String -Pattern '-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----' -List -ErrorAction SilentlyContinue

    if ($privateKeyMatches) {
        $paths = ($privateKeyMatches.Path -join [Environment]::NewLine)
        throw "Private key material remains in staging:`n$paths"
    }

    Remove-Item -LiteralPath $output -Force -ErrorAction SilentlyContinue

    Compress-Archive `
        -Path $stageProject `
        -DestinationPath $output `
        -CompressionLevel Optimal `
        -Force

    $archive = Get-Item -LiteralPath $output

    Write-Host ''
    Write-Host 'Review archive created successfully:' -ForegroundColor Green
    Write-Host $archive.FullName
    Write-Host ("Size: {0:N2} MB" -f ($archive.Length / 1MB))
}
finally {
    if (-not $KeepStaging) {
        Remove-Item -LiteralPath $stageRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
    else {
        Write-Host "Staging retained at: $stageRoot"
    }
}
