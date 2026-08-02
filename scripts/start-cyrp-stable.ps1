[CmdletBinding()]
param(
    [ValidateSet("CaptureBaseline", "Check", "Start")]
    [string]$Mode = "Check",

    [string]$ProjectRoot = "D:\LuanVan\test\cyrp-platform-phase2",
    [string]$BackupBase = "D:\LuanVan\backup\CYRP",
    [string]$BaselinePath = "",

    [string]$PgContainer = "cyrp-platform-phase2-db-1",
    [string]$DbUser = "cyrp",
    [string]$DbName = "cyrp",

    [int]$ApiPort = 3001,
    [int]$UserWebPort = 3002,
    [int]$PortalPort = 3000,
    [switch]$StartPortal
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Write-Step {
    param([string]$Message)
    Write-Host ""
    Write-Host "==> $Message" -ForegroundColor Cyan
}

function Invoke-Docker {
    param([Parameter(Mandatory = $true)][string[]]$ArgumentList)

    & docker.exe @ArgumentList
    $ExitCode = $LASTEXITCODE

    if ($ExitCode -ne 0) {
        throw "docker.exe failed with exit code ${ExitCode}: $($ArgumentList -join ' ')"
    }
}

function Invoke-PsqlScalar {
    param([Parameter(Mandatory = $true)][string]$Sql)

    $Arguments = @(
        "exec",
        "-i",
        $PgContainer,
        "psql",
        "-X",
        "-t",
        "-A",
        "-v",
        "ON_ERROR_STOP=1",
        "-U",
        $DbUser,
        "-d",
        $DbName
    )

    $Output = $Sql | & docker.exe @Arguments
    $ExitCode = $LASTEXITCODE

    if ($ExitCode -ne 0) {
        throw "psql failed with exit code ${ExitCode}."
    }

    return ($Output | Out-String).Trim()
}

function Get-EnvValue {
    param(
        [string[]]$Lines,
        [string]$Name
    )

    $Match = $Lines |
        Where-Object {
            $_ -match "^\s*$([regex]::Escape($Name))\s*="
        } |
        Select-Object -Last 1

    if (-not $Match) {
        return $null
    }

    return (($Match -split "=", 2)[1]).Trim()
}


function Convert-ToFlatDeviceArray {
    param(
        [Parameter(Mandatory = $false)]
        [object]$InputObject
    )

    $Result = New-Object System.Collections.ArrayList

    function Add-DeviceValue {
        param([object]$Value)

        if ($null -eq $Value) {
            return
        }

        $DeviceIdProperty = $Value.PSObject.Properties["device_id"]
        if ($null -ne $DeviceIdProperty) {
            [void]$Result.Add($Value)
            return
        }

        if (
            $Value -is [System.Collections.IEnumerable] -and
            -not ($Value -is [string])
        ) {
            foreach ($Child in $Value) {
                Add-DeviceValue -Value $Child
            }
        }
    }

    Add-DeviceValue -Value $InputObject
    return ,$Result.ToArray()
}

function Get-ObjectPropertyValue {
    param(
        [Parameter(Mandatory = $false)]
        [object]$InputObject,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    if ($null -eq $InputObject) {
        return $null
    }

    $Property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $Property) {
        return $null
    }

    return $Property.Value
}

function Test-PortListening {
    param([int]$Port)

    return [bool](
        Get-NetTCPConnection `
            -LocalPort $Port `
            -State Listen `
            -ErrorAction SilentlyContinue
    )
}

function Wait-Http {
    param(
        [string]$Uri,
        [int]$TimeoutSeconds = 90
    )

    $Deadline = (Get-Date).AddSeconds($TimeoutSeconds)

    do {
        try {
            $Response = Invoke-WebRequest `
                -UseBasicParsing `
                -Uri $Uri `
                -TimeoutSec 5

            if ($Response.StatusCode -ge 200 -and $Response.StatusCode -lt 500) {
                return
            }
        }
        catch {
            Start-Sleep -Seconds 2
        }
    } while ((Get-Date) -lt $Deadline)

    throw "Service did not become ready within $TimeoutSeconds seconds: $Uri"
}

function Start-CmdWindow {
    param(
        [string]$Title,
        [string]$Command
    )

    $FullCommand = "title $Title && $Command"

    Start-Process `
        -FilePath "cmd.exe" `
        -ArgumentList @("/k", $FullCommand) `
        -WorkingDirectory $ProjectRoot |
        Out-Null
}

if ([string]::IsNullOrWhiteSpace($BaselinePath)) {
    $BaselinePath = Join-Path $BackupBase "CYRP-RUNTIME-BASELINE.json"
}

if (-not (Test-Path -LiteralPath $ProjectRoot -PathType Container)) {
    throw "Project root does not exist: $ProjectRoot"
}

if (-not (Get-Command docker.exe -ErrorAction SilentlyContinue)) {
    throw "Docker CLI was not found. Start Docker Desktop first."
}

Write-Step "Verify Docker engine"

& docker.exe info *> $null
if ($LASTEXITCODE -ne 0) {
    throw "Docker engine is not ready. Open Docker Desktop and wait until it reports Running."
}

Write-Step "Start PostgreSQL without deleting or recreating volumes"

Push-Location $ProjectRoot
try {
    Invoke-Docker -ArgumentList @(
        "compose",
        "up",
        "-d",
        "db"
    )
}
finally {
    Pop-Location
}

$Deadline = (Get-Date).AddSeconds(90)
do {
    & docker.exe exec $PgContainer `
        pg_isready -U $DbUser -d $DbName *> $null

    if ($LASTEXITCODE -eq 0) {
        break
    }

    Start-Sleep -Seconds 2
} while ((Get-Date) -lt $Deadline)

if ($LASTEXITCODE -ne 0) {
    throw "PostgreSQL did not become ready in 90 seconds."
}

Write-Step "Verify PostgreSQL persistent mount"

$Inspect = (& docker.exe inspect $PgContainer | Out-String) |
    ConvertFrom-Json

$Container = $Inspect | Select-Object -First 1
$DataMount = $Container.Mounts |
    Where-Object {
        $_.Destination -eq "/var/lib/postgresql/data" -or
        $_.Destination -like "/var/lib/postgresql/data/*"
    } |
    Select-Object -First 1

if (-not $DataMount) {
    throw @"
PostgreSQL has no persistent mount at /var/lib/postgresql/data.
Do not start CYRP because data would not be durable.
"@
}

Write-Host "Mount type:   $($DataMount.Type)"
Write-Host "Mount name:   $($DataMount.Name)"
Write-Host "Mount source: $($DataMount.Source)"
Write-Host "Destination:  $($DataMount.Destination)"

$EnvPath = Join-Path $ProjectRoot ".env"
if (-not (Test-Path -LiteralPath $EnvPath -PathType Leaf)) {
    throw ".env is missing: $EnvPath"
}

$EnvLines = Get-Content -LiteralPath $EnvPath
$RequiredTrueFlags = @(
    "WAZUH_INTEGRATION_ENABLED",
    "WAZUH_ACTIVE_SYNC_ENABLED",
    "WAZUH_DATA_SYNC_ENABLED",
    "WAZUH_AGENT_STATUS_SYNC_ENABLED",
    "AI_MODEL_ENABLED"
)

Write-Step "Verify runtime flags"

foreach ($Flag in $RequiredTrueFlags) {
    $Value = Get-EnvValue -Lines $EnvLines -Name $Flag

    if ($Value -ne "true") {
        throw "$Flag must be true before CYRP starts. Current value: '$Value'"
    }

    Write-Host "$Flag=true" -ForegroundColor Green
}

$StateSql = @'
SELECT COALESCE(
  json_agg(row_to_json(state_row) ORDER BY state_row.email, state_row.device_id),
  '[]'::json
)::text
FROM (
  SELECT
    u.email,
    d.id AS device_id,
    d.hostname,
    wab.wazuh_agent_id,
    wab.wazuh_agent_name,
    wab.last_known_status,
    COALESCE(vc.vulnerability_rows, 0)::int AS vulnerability_rows,
    COALESCE(pc.prediction_rows, 0)::int AS prediction_rows,
    COALESCE(sc.sync_run_rows, 0)::int AS sync_run_rows
  FROM devices d
  JOIN users u
    ON u.id = d.user_id
  LEFT JOIN wazuh_agent_bindings wab
    ON wab.device_id = d.id
  LEFT JOIN (
    SELECT device_id, COUNT(*) AS vulnerability_rows
    FROM detected_vulnerabilities
    GROUP BY device_id
  ) vc
    ON vc.device_id = d.id
  LEFT JOIN (
    SELECT dv.device_id, COUNT(ap.id) AS prediction_rows
    FROM detected_vulnerabilities dv
    LEFT JOIN ai_predictions ap
      ON ap.detected_vulnerability_id = dv.id
    GROUP BY dv.device_id
  ) pc
    ON pc.device_id = d.id
  LEFT JOIN (
    SELECT device_id, COUNT(*) AS sync_run_rows
    FROM sync_runs
    WHERE device_id IS NOT NULL
    GROUP BY device_id
  ) sc
    ON sc.device_id = d.id
) state_row;
'@

$CurrentStateJson = Invoke-PsqlScalar -Sql $StateSql
$ParsedCurrentState = ConvertFrom-Json -InputObject $CurrentStateJson
$CurrentDevices = @(
    Convert-ToFlatDeviceArray -InputObject $ParsedCurrentState
)

if ($CurrentDevices.Count -eq 0) {
    throw "The CYRP database returned no device records. Startup was blocked."
}

if ($Mode -eq "CaptureBaseline") {
    Write-Step "Capture stable runtime baseline"

    New-Item `
        -ItemType Directory `
        -Path (Split-Path -Parent $BaselinePath) `
        -Force |
        Out-Null

    $Baseline = [ordered]@{
        version = 1
        capturedAt = (Get-Date).ToString("o")
        projectRoot = $ProjectRoot
        postgres = [ordered]@{
            container = $PgContainer
            database = $DbName
            mountType = $DataMount.Type
            mountName = $DataMount.Name
            mountSource = $DataMount.Source
            mountDestination = $DataMount.Destination
        }
        requiredFlags = [ordered]@{}
        devices = $CurrentDevices
    }

    foreach ($Flag in $RequiredTrueFlags) {
        $Baseline.requiredFlags[$Flag] = "true"
    }

    $Baseline |
        ConvertTo-Json -Depth 8 |
        Set-Content `
            -LiteralPath $BaselinePath `
            -Encoding UTF8

    Write-Host "Baseline saved:" -ForegroundColor Green
    Write-Host $BaselinePath
    Write-Host ""
    Write-Host "Do not overwrite this baseline until the restored system has been tested." `
        -ForegroundColor Yellow

    return
}

if (-not (Test-Path -LiteralPath $BaselinePath -PathType Leaf)) {
    throw @"
Runtime baseline is missing:
$BaselinePath

After restoring and validating the database, run:
  -Mode CaptureBaseline
"@
}

Write-Step "Compare current database with stable baseline"

$BaselineData = Get-Content `
    -LiteralPath $BaselinePath `
    -Raw |
    ConvertFrom-Json

if ($BaselineData.postgres.mountDestination -ne $DataMount.Destination) {
    throw "PostgreSQL mount destination differs from the stable baseline."
}

if (
    $BaselineData.postgres.mountName -and
    $DataMount.Name -and
    $BaselineData.postgres.mountName -ne $DataMount.Name
) {
    throw @"
PostgreSQL is using a different Docker volume.
Expected: $($BaselineData.postgres.mountName)
Current:  $($DataMount.Name)

Do not start API/Web until the correct volume is attached.
"@
}

$Problems = New-Object System.Collections.Generic.List[string]
$ExpectedDevices = @(
    Convert-ToFlatDeviceArray -InputObject $BaselineData.devices
)

if ($ExpectedDevices.Count -eq 0) {
    throw "The runtime baseline contains no valid device records. Do not overwrite it."
}

foreach ($Expected in $ExpectedDevices) {
    $ExpectedDeviceId = Get-ObjectPropertyValue `
        -InputObject $Expected `
        -Name "device_id"

    $ExpectedHostname = Get-ObjectPropertyValue `
        -InputObject $Expected `
        -Name "hostname"

    $Current = $CurrentDevices |
        Where-Object {
            $CurrentDeviceId = Get-ObjectPropertyValue `
                -InputObject $_ `
                -Name "device_id"

            $CurrentDeviceId -eq $ExpectedDeviceId
        } |
        Select-Object -First 1

    if (-not $Current) {
        $Problems.Add(
            "Missing device $ExpectedDeviceId ($ExpectedHostname)"
        )
        continue
    }

    $ExpectedAgentId = Get-ObjectPropertyValue `
        -InputObject $Expected `
        -Name "wazuh_agent_id"

    $CurrentAgentId = Get-ObjectPropertyValue `
        -InputObject $Current `
        -Name "wazuh_agent_id"

    if ($ExpectedAgentId) {
        if (-not $CurrentAgentId) {
            $Problems.Add(
                "Binding missing for $ExpectedHostname; expected agent $ExpectedAgentId"
            )
        }
        elseif ($CurrentAgentId -ne $ExpectedAgentId) {
            $Problems.Add(
                "Binding changed for ${ExpectedHostname}: expected $ExpectedAgentId, current $CurrentAgentId"
            )
        }
    }

    $ExpectedVulnerabilities = [int](
        Get-ObjectPropertyValue `
            -InputObject $Expected `
            -Name "vulnerability_rows"
    )

    $CurrentVulnerabilities = [int](
        Get-ObjectPropertyValue `
            -InputObject $Current `
            -Name "vulnerability_rows"
    )

    if (
        $ExpectedVulnerabilities -gt 0 -and
        $CurrentVulnerabilities -eq 0
    ) {
        $Problems.Add(
            "Vulnerability data disappeared for $ExpectedHostname"
        )
    }

    $ExpectedPredictions = [int](
        Get-ObjectPropertyValue `
            -InputObject $Expected `
            -Name "prediction_rows"
    )

    $CurrentPredictions = [int](
        Get-ObjectPropertyValue `
            -InputObject $Current `
            -Name "prediction_rows"
    )

    if (
        $ExpectedPredictions -gt 0 -and
        $CurrentPredictions -eq 0
    ) {
        $Problems.Add(
            "AI prediction data disappeared for $ExpectedHostname"
        )
    }
}

if ($Problems.Count -gt 0) {
    Write-Host ""
    Write-Host "CYRP startup guard blocked service startup:" `
        -ForegroundColor Red

    foreach ($Problem in $Problems) {
        Write-Host " - $Problem" -ForegroundColor Red
    }

    throw @"
Database integrity check failed.
API and Web were not started.
Restore the stable database or investigate before continuing.
"@
}

Write-Host "Database bindings and retained data match the baseline." `
    -ForegroundColor Green

if ($Mode -eq "Check") {
    Write-Host ""
    Write-Host "Check completed. Services were not started." `
        -ForegroundColor Green
    return
}

Write-Step "Start CYRP API"

if (-not (Test-PortListening -Port $ApiPort)) {
    Start-CmdWindow `
        -Title "CYRP API" `
        -Command "corepack pnpm --dir apps/api run start:dev"
}

Wait-Http `
    -Uri "http://127.0.0.1:$ApiPort/api/v1/health" `
    -TimeoutSeconds 120

Write-Host "API ready on port $ApiPort." -ForegroundColor Green

Write-Step "Start CYRP User Web"

$UserNext = Join-Path $ProjectRoot "apps\user-web\.next"
if (-not (Test-Path -LiteralPath $UserNext -PathType Container)) {
    Push-Location $ProjectRoot
    try {
        & corepack pnpm --dir apps/user-web exec next build

        if ($LASTEXITCODE -ne 0) {
            throw "User Web build failed."
        }
    }
    finally {
        Pop-Location
    }
}

if (-not (Test-PortListening -Port $UserWebPort)) {
    Start-CmdWindow `
        -Title "CYRP User Web" `
        -Command "corepack pnpm --dir apps/user-web exec next start -H 0.0.0.0 -p $UserWebPort"
}

Wait-Http `
    -Uri "http://127.0.0.1:$UserWebPort/login" `
    -TimeoutSeconds 120

Write-Host "User Web ready on port $UserWebPort." `
    -ForegroundColor Green

if ($StartPortal) {
    Write-Step "Start CYRP Admin Portal"

    $PortalPackage = Join-Path $ProjectRoot "apps\portal-web\package.json"
    if (-not (Test-Path -LiteralPath $PortalPackage -PathType Leaf)) {
        throw "Portal package does not exist: $PortalPackage"
    }

    $PortalNext = Join-Path $ProjectRoot "apps\portal-web\.next"
    if (-not (Test-Path -LiteralPath $PortalNext -PathType Container)) {
        Push-Location $ProjectRoot
        try {
            & corepack pnpm --dir apps/portal-web exec next build

            if ($LASTEXITCODE -ne 0) {
                throw "Admin Portal build failed."
            }
        }
        finally {
            Pop-Location
        }
    }

    if (-not (Test-PortListening -Port $PortalPort)) {
        Start-CmdWindow `
            -Title "CYRP Admin Portal" `
            -Command "corepack pnpm --dir apps/portal-web exec next start -H 0.0.0.0 -p $PortalPort"
    }

    Wait-Http `
        -Uri "http://127.0.0.1:$PortalPort/login" `
        -TimeoutSeconds 120

    Write-Host "Admin Portal ready on port $PortalPort." `
        -ForegroundColor Green
}

Write-Host ""
Write-Host "CYRP stable startup completed." -ForegroundColor Green
Write-Host "PostgreSQL volume and database integrity were verified first." `
    -ForegroundColor Green
