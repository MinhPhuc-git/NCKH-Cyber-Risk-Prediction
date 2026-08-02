param(
  [string]$ProjectRoot = "D:\LuanVan\test\cyrp-platform-phase2"
)

$ErrorActionPreference = "Stop"

function Write-Step($Message) {
  Write-Host "`n=== $Message ===" -ForegroundColor Cyan
}

function Add-Once {
  param(
    [string]$Path,
    [string]$Pattern,
    [string]$InsertText,
    [string]$BeforePattern
  )

  $Text = Get-Content -Raw -Encoding UTF8 $Path

  if ($Text -match [regex]::Escape($Pattern)) {
    return
  }

  $Text = [regex]::Replace($Text, $BeforePattern, "$InsertText`r`n`$0", 1)
  [System.IO.File]::WriteAllText($Path, $Text, [System.Text.UTF8Encoding]::new($false))
}

function Set-EnvValue {
  param(
    [string]$Path,
    [string]$Name,
    [string]$Value
  )

  if (-not (Test-Path $Path)) {
    New-Item -ItemType File -Path $Path -Force | Out-Null
  }

  $Text = Get-Content -Raw -Encoding UTF8 $Path
  $Escaped = [regex]::Escape($Name)

  if ($Text -match "(?m)^$Escaped=") {
    $Text = [regex]::Replace($Text, "(?m)^$Escaped=.*$", "$Name=$Value")
  } else {
    $Text = $Text.TrimEnd() + "`r`n$Name=$Value`r`n"
  }

  [System.IO.File]::WriteAllText($Path, $Text, [System.Text.UTF8Encoding]::new($false))
}

$PatchRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$SecurityDataDir = Join-Path $ProjectRoot "apps\api\src\modules\security-data"
$ServiceSource = Join-Path $PatchRoot "apps\api\src\modules\security-data\ai-pipeline-data-user-import.service.ts"
$ServiceTarget = Join-Path $SecurityDataDir "ai-pipeline-data-user-import.service.ts"
$ModuleFile = Join-Path $SecurityDataDir "security-data.module.ts"
$UserControllerFile = Join-Path $SecurityDataDir "security-data.controller.ts"
$AdminControllerFile = Join-Path $SecurityDataDir "admin-security-data.controller.ts"
$EnvFile = Join-Path $ProjectRoot ".env"
$DataUserDir = Join-Path $ProjectRoot "apps\ai-model\model-risk-prediction\Data User"

Write-Step "Validate project"
if (-not (Test-Path $ProjectRoot)) { throw "ProjectRoot not found: $ProjectRoot" }
if (-not (Test-Path $SecurityDataDir)) { throw "security-data module not found: $SecurityDataDir" }
if (-not (Test-Path $ServiceSource)) { throw "Patch service not found: $ServiceSource" }

Write-Step "Backup current security-data files"
$Ts = Get-Date -Format "yyyyMMdd-HHmmss"
$BackupDir = Join-Path $ProjectRoot ".phase-backups\ai-data-user-import-$Ts"
New-Item -ItemType Directory -Force -Path $BackupDir | Out-Null
Copy-Item $ModuleFile (Join-Path $BackupDir "security-data.module.ts") -Force
Copy-Item $UserControllerFile (Join-Path $BackupDir "security-data.controller.ts") -Force
Copy-Item $AdminControllerFile (Join-Path $BackupDir "admin-security-data.controller.ts") -Force
if (Test-Path $ServiceTarget) { Copy-Item $ServiceTarget (Join-Path $BackupDir "ai-pipeline-data-user-import.service.ts") -Force }

Write-Step "Install AiPipelineDataUserImportService"
Copy-Item $ServiceSource $ServiceTarget -Force

Write-Step "Patch security-data.module.ts"
$Text = Get-Content -Raw -Encoding UTF8 $ModuleFile
if ($Text -notmatch "ai-pipeline-data-user-import\.service") {
  $Text = $Text -replace "import \{ AiModelRuntimeService \} from './ai-model-runtime.service';", "import { AiModelRuntimeService } from './ai-model-runtime.service';`r`nimport { AiPipelineDataUserImportService } from './ai-pipeline-data-user-import.service';"
}
if ($Text -notmatch "AiPipelineDataUserImportService,") {
  $Text = $Text -replace "AiModelRuntimeService,\r?\n\s*\],", "AiModelRuntimeService,`r`n    AiPipelineDataUserImportService,`r`n  ],"
  $Text = $Text -replace "AiModelRuntimeService,\r?\n\s*\],\r?\n\}\)", "AiModelRuntimeService,`r`n    AiPipelineDataUserImportService,`r`n  ],`r`n})"
}
[System.IO.File]::WriteAllText($ModuleFile, $Text, [System.Text.UTF8Encoding]::new($false))

Write-Step "Patch user security-data.controller.ts"
$Text = Get-Content -Raw -Encoding UTF8 $UserControllerFile
if ($Text -notmatch "ai-pipeline-data-user-import\.service") {
  $Text = $Text -replace "import \{ SecurityDataSyncService \} from './security-data-sync.service';", "import { AiPipelineDataUserImportService } from './ai-pipeline-data-user-import.service';`r`nimport { SecurityDataSyncService } from './security-data-sync.service';"
}
if ($Text -notmatch "private readonly aiPipelineImport") {
  $Text = $Text -replace "private readonly syncService: SecurityDataSyncService,", "private readonly syncService: SecurityDataSyncService,`r`n    private readonly aiPipelineImport: AiPipelineDataUserImportService,"
}
if ($Text -notmatch "importAiPredictionsFromDataUser") {
  $Method = @'

  @Post('devices/:deviceId/ai-predictions/import-data-user')
  @ApiOperation({
    summary: 'Import kết quả AI pipeline từ Data User JSON vào database',
  })
  importAiPredictionsFromDataUser(
    @CurrentUser() user: AuthenticatedUser,
    @Param('deviceId', new ParseUUIDPipe()) deviceId: string,
  ) {
    return this.aiPipelineImport.importForUserDevice(user.id, deviceId);
  }
'@
  $Text = [regex]::Replace($Text, "\r?\n\}\r?\n?$", "$Method`r`n}`r`n", 1)
}
[System.IO.File]::WriteAllText($UserControllerFile, $Text, [System.Text.UTF8Encoding]::new($false))

Write-Step "Patch admin-security-data.controller.ts"
$Text = Get-Content -Raw -Encoding UTF8 $AdminControllerFile
if ($Text -notmatch "ai-pipeline-data-user-import\.service") {
  $Text = $Text -replace "import \{ SecurityDataSyncService \} from './security-data-sync.service';", "import { AiPipelineDataUserImportService } from './ai-pipeline-data-user-import.service';`r`nimport { SecurityDataSyncService } from './security-data-sync.service';"
}
if ($Text -notmatch "private readonly aiPipelineImport") {
  $Text = $Text -replace "private readonly syncService: SecurityDataSyncService,", "private readonly syncService: SecurityDataSyncService,`r`n    private readonly aiPipelineImport: AiPipelineDataUserImportService,"
}
if ($Text -notmatch "importAiPredictionsFromDataUser") {
  $Method = @'

  @Post('ai-predictions/import-data-user')
  @ApiOperation({
    summary: 'Import kết quả AI pipeline từ Data User JSON vào database',
  })
  importAiPredictionsFromDataUser() {
    return this.aiPipelineImport.importAllForAdmin();
  }
'@
  $Text = [regex]::Replace($Text, "\r?\n\}\r?\n?$", "$Method`r`n}`r`n", 1)
}
[System.IO.File]::WriteAllText($AdminControllerFile, $Text, [System.Text.UTF8Encoding]::new($false))

Write-Step "Update .env"
New-Item -ItemType Directory -Force -Path $DataUserDir | Out-Null
Set-EnvValue -Path $EnvFile -Name "AI_PIPELINE_DATA_USER_DIR" -Value $DataUserDir
Set-EnvValue -Path $EnvFile -Name "AI_MODEL_VERSION" -Value "CYRP_XGBOOST_CVSS_PERCENTILE_V3"

Write-Step "Verify patched files"
Select-String -Path $ModuleFile -Pattern "AiPipelineDataUserImportService" | Select-Object Path,LineNumber,Line
Select-String -Path $UserControllerFile -Pattern "import-data-user|AiPipelineDataUserImportService" | Select-Object Path,LineNumber,Line
Select-String -Path $AdminControllerFile -Pattern "import-data-user|AiPipelineDataUserImportService" | Select-Object Path,LineNumber,Line

Write-Host "`nDONE. Backup saved at: $BackupDir" -ForegroundColor Green
Write-Host "Next: run typecheck, restart API, then POST /api/v1/admin/ai-predictions/import-data-user" -ForegroundColor Green
