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
    'apps\api\src\modules\agents\agents.service.ts',
    'apps\api\src\modules\agents\agents.module.ts',
    'apps\api\src\modules\agents\dto\enroll-agent-response.dto.ts',
    'apps\api\src\modules\wazuh\wazuh.service.ts',
    'apps\api\src\modules\wazuh\wazuh.types.ts'
)

foreach ($relativePath in $requiredFiles) {
    $fullPath = Join-Path $ProjectRoot $relativePath

    if (-not [IO.File]::Exists($fullPath)) {
        throw "Missing Phase 2B.1 file: $relativePath"
    }
}

$agentsService = Join-Path $ProjectRoot 'apps\api\src\modules\agents\agents.service.ts'
$wazuhService = Join-Path $ProjectRoot 'apps\api\src\modules\wazuh\wazuh.service.ts'
$responseDto = Join-Path $ProjectRoot 'apps\api\src\modules\agents\dto\enroll-agent-response.dto.ts'

if (-not (Select-String -LiteralPath $agentsService -Pattern 'wazuhAgentBinding' -Quiet)) {
    throw 'AgentsService does not create WazuhAgentBinding.'
}

if (-not (Select-String -LiteralPath $wazuhService -Pattern 'async createAgent' -Quiet)) {
    throw 'WazuhService.createAgent is missing.'
}

if (-not (Select-String -LiteralPath $wazuhService -Pattern 'async deleteAgent' -Quiet)) {
    throw 'WazuhService.deleteAgent is missing.'
}

if (-not (Select-String -LiteralPath $responseDto -Pattern 'clientKey' -Quiet)) {
    throw 'Enrollment response does not include the one-time Wazuh client key.'
}

Write-Host 'Phase 2B.1 files: OK' -ForegroundColor Green

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
}
finally {
    Pop-Location
}

Write-Host "`nCYRP Phase 2B.1 verification completed." -ForegroundColor Green
