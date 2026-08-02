param(
    [string]$ProjectRoot = (Get-Location).Path
)

$ErrorActionPreference = 'Stop'

function Invoke-PhaseStep {
    param(
        [string]$Name,
        [scriptblock]$Action
    )

    Write-Host "`n==> $Name" -ForegroundColor Cyan
    & $Action

    if ($LASTEXITCODE -ne 0) {
        throw "$Name failed with exit code $LASTEXITCODE"
    }
}

$requiredFiles = @(
    'database\prisma\schema.prisma',
    'apps\api\src\modules\security-data\security-data-sync.service.ts',
    'apps\api\src\modules\security-data\security-data.service.ts',
    'apps\api\src\modules\security-data\dto\list-device-packages-query.dto.ts',
    'apps\api\src\modules\security-data\security-data.controller.ts',
    'apps\api\src\modules\security-data\admin-security-data.controller.ts',
    'apps\user-web\src\lib\security-data-types.ts',
    'apps\user-web\src\app\vulnerabilities\vulnerabilities-client.tsx',
    'apps\user-web\src\app\vulnerabilities\[id]\vulnerability-detail-client.tsx'
)

foreach ($relativePath in $requiredFiles) {
    $fullPath = Join-Path $ProjectRoot $relativePath

    if (-not [IO.File]::Exists($fullPath)) {
        throw "Missing Phase 2C file: $relativePath"
    }
}

$schemaPath = Join-Path $ProjectRoot 'database\prisma\schema.prisma'
$syncPath = Join-Path $ProjectRoot 'apps\api\src\modules\security-data\security-data-sync.service.ts'
$servicePath = Join-Path $ProjectRoot 'apps\api\src\modules\security-data\security-data.service.ts'

$requiredSchemaPatterns = @(
    '^model DevicePackage',
    '^model VulnerabilityFeatureVector',
    '^model AiPrediction',
    '^model PredictionHistory'
)

foreach ($pattern in $requiredSchemaPatterns) {
    if (-not (Select-String -LiteralPath $schemaPath -Pattern $pattern -Quiet)) {
        throw "Missing schema pattern: $pattern"
    }
}

$requiredCodePatterns = @(
    'upsertDevicePackages',
    'refreshFeatureVectorsAndPredictions',
    'CYRP_BASELINE_V1',
    'baselinePrediction'
)

foreach ($pattern in $requiredCodePatterns) {
    if (-not (Select-String -LiteralPath $syncPath -Pattern $pattern -Quiet)) {
        throw "Missing sync code pattern: $pattern"
    }
}

if (-not (Select-String -LiteralPath $servicePath -Pattern 'listUserDevicePackages' -Quiet)) {
    throw 'Device package listing service is missing.'
}

Write-Host 'Phase 2C files: OK' -ForegroundColor Green

Push-Location $ProjectRoot
try {
    Invoke-PhaseStep 'Prisma validate' {
        & corepack pnpm exec prisma validate --schema database/prisma/schema.prisma
    }

    Invoke-PhaseStep 'Prisma generate' {
        & corepack pnpm exec prisma generate --schema database/prisma/schema.prisma
    }

    Invoke-PhaseStep 'API lint' {
        & corepack pnpm run lint:api
    }

    Invoke-PhaseStep 'API typecheck' {
        & corepack pnpm run typecheck:api
    }

    Invoke-PhaseStep 'API unit tests' {
        & corepack pnpm run test:api
    }

    Invoke-PhaseStep 'API build' {
        & corepack pnpm run build:api
    }

    Invoke-PhaseStep 'User Portal lint' {
        & corepack pnpm run lint:user
    }

    Invoke-PhaseStep 'User Portal build' {
        & corepack pnpm run build:user
    }
}
finally {
    Pop-Location
}

Write-Host "`nCYRP Phase 2C verification completed." -ForegroundColor Green
