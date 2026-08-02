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
    'apps\api\src\modules\security-snapshots\security-snapshots.module.ts',
    'apps\api\src\modules\security-snapshots\security-snapshots.controller.ts',
    'apps\api\src\modules\security-snapshots\security-snapshots.service.ts',
    'apps\user-web\src\app\dashboard\dashboard-overview-client.tsx',
    'apps\user-web\src\app\api\dashboard\security-overview\route.ts',
    'apps\user-web\src\app\api\devices\[deviceId]\security-snapshot\route.ts',
    'apps\user-web\src\lib\security-snapshot-types.ts'
)

foreach ($relativePath in $requiredFiles) {
    $fullPath = Join-Path $ProjectRoot $relativePath

    if (-not [IO.File]::Exists($fullPath)) {
        throw "Missing Phase 2B.3 file: $relativePath"
    }
}

$schemaPath = Join-Path $ProjectRoot 'database\prisma\schema.prisma'
$appModulePath = Join-Path $ProjectRoot 'apps\api\src\app.module.ts'

if (-not (Select-String -LiteralPath $schemaPath -Pattern '^model DeviceSecuritySnapshot' -Quiet)) {
    throw 'DeviceSecuritySnapshot Prisma model is missing.'
}

if (-not (Select-String -LiteralPath $appModulePath -Pattern 'SecuritySnapshotsModule' -Quiet)) {
    throw 'SecuritySnapshotsModule is not registered.'
}

Write-Host 'Phase 2B.3 files: OK' -ForegroundColor Green

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
        & corepack pnpm --filter './apps/user-web' run lint
    }

    Invoke-PhaseStep 'User Portal build' {
        & corepack pnpm --filter './apps/user-web' run build
    }
}
finally {
    Pop-Location
}

Write-Host "`nCYRP Phase 2B.3 verification completed." -ForegroundColor Green
