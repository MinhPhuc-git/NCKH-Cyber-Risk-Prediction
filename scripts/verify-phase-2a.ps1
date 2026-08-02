$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path `
    -Parent `
    $PSScriptRoot

Set-Location $ProjectRoot

$requiredFiles = @(
    ".\apps\api\src\modules\wazuh\wazuh.service.ts",
    ".\apps\api\src\modules\wazuh-bindings\wazuh-bindings.module.ts",
    ".\apps\api\src\modules\analysis-runs\analysis-runs.module.ts",
    ".\apps\user-web\src\components\device-analysis-button.tsx",
    ".\apps\user-web\src\app\api\devices\[deviceId]\analysis-runs\route.ts"
)

foreach ($file in $requiredFiles) {
    if (-not (Test-Path -LiteralPath $file)) {
        throw "Missing Phase 2A file: $file"
    }
}

Write-Host "Required files: OK"

corepack pnpm exec prisma validate `
  --schema database/prisma/schema.prisma

corepack pnpm exec prisma generate `
  --schema database/prisma/schema.prisma

$rootPackage = Get-Content `
    .\package.json `
    -Raw |
    ConvertFrom-Json

function Invoke-PackageScript(
    [string]$ScriptName,
    [string[]]$FallbackArguments
) {
    if (
        $null -ne $rootPackage.scripts.$ScriptName
    ) {
        corepack pnpm run $ScriptName
    }
    else {
        & corepack pnpm @FallbackArguments
    }
}

Invoke-PackageScript `
    "lint:api" `
    @("--filter", "@cyrp/api", "run", "lint")

Invoke-PackageScript `
    "typecheck:api" `
    @("--filter", "@cyrp/api", "run", "typecheck")

Invoke-PackageScript `
    "test:api" `
    @("--filter", "@cyrp/api", "run", "test")

Invoke-PackageScript `
    "build:api" `
    @("--filter", "@cyrp/api", "run", "build")

corepack pnpm `
    --filter "./apps/user-web" `
    run lint

corepack pnpm `
    --filter "./apps/user-web" `
    run build

Write-Host "CYRP Phase 2A verification completed." -ForegroundColor Green
