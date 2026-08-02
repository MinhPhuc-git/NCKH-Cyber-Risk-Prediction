from pathlib import Path
import re
import shutil
from datetime import datetime

root = Path(__import__('sys').argv[1])
patch_root = Path(__import__('sys').argv[2])
backup_dir = root / '.phase-backups' / ('ai-pipeline-check-button-' + datetime.now().strftime('%Y%m%d-%H%M%S'))
backup_dir.mkdir(parents=True, exist_ok=True)

def backup(path: Path):
    if path.exists():
        dest = backup_dir / path.relative_to(root).as_posix().replace('/', '__')
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, dest)

# Copy new files
service_src = patch_root / 'apps' / 'api' / 'src' / 'modules' / 'security-data' / 'ai-pipeline-check.service.ts'
service_dst = root / 'apps' / 'api' / 'src' / 'modules' / 'security-data' / 'ai-pipeline-check.service.ts'
route_src = patch_root / 'apps' / 'user-web' / 'src' / 'app' / 'api' / 'devices' / '[deviceId]' / 'ai-pipeline-check' / 'route.ts'
route_dst = root / 'apps' / 'user-web' / 'src' / 'app' / 'api' / 'devices' / '[deviceId]' / 'ai-pipeline-check' / 'route.ts'

for src, dst in [(service_src, service_dst), (route_src, route_dst)]:
    if not src.exists():
        raise SystemExit(f'Patch source missing: {src}')
    backup(dst)
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)

# Patch security-data.module.ts
module_path = root / 'apps' / 'api' / 'src' / 'modules' / 'security-data' / 'security-data.module.ts'
backup(module_path)
module_path.write_text("""import { Module } from '@nestjs/common';

import { DatabaseModule } from '../../database/database.module';
import { SecuritySnapshotsModule } from '../security-snapshots/security-snapshots.module';
import { WazuhBindingsModule } from '../wazuh-bindings/wazuh-bindings.module';
import { WazuhModule } from '../wazuh/wazuh.module';
import { AdminSecurityDataController } from './admin-security-data.controller';
import { AiModelRuntimeService } from './ai-model-runtime.service';
import { AiPipelineCheckService } from './ai-pipeline-check.service';
import { AiPipelineDataUserImportService } from './ai-pipeline-data-user-import.service';
import { DeviceSyncLockService } from './device-sync-lock.service';
import { SecurityDataController } from './security-data.controller';
import { SecurityDataSyncService } from './security-data-sync.service';
import { SecurityDataService } from './security-data.service';

@Module({
  imports: [
    DatabaseModule,
    WazuhModule,
    WazuhBindingsModule,
    SecuritySnapshotsModule,
  ],
  controllers: [SecurityDataController, AdminSecurityDataController],
  providers: [
    SecurityDataService,
    SecurityDataSyncService,
    DeviceSyncLockService,
    AiModelRuntimeService,
    AiPipelineDataUserImportService,
    AiPipelineCheckService,
  ],
  exports: [
    SecurityDataService,
    SecurityDataSyncService,
    DeviceSyncLockService,
    AiModelRuntimeService,
    AiPipelineDataUserImportService,
    AiPipelineCheckService,
  ],
})
export class SecurityDataModule {}
""", encoding='utf-8')

# Patch security-data.controller.ts
controller_path = root / 'apps' / 'api' / 'src' / 'modules' / 'security-data' / 'security-data.controller.ts'
backup(controller_path)
text = controller_path.read_text(encoding='utf-8')

if "./ai-pipeline-check.service" not in text:
    text = text.replace("import { SecurityDataSyncService } from './security-data-sync.service';", "import { AiPipelineCheckService } from './ai-pipeline-check.service';\nimport { SecurityDataSyncService } from './security-data-sync.service';")

if "private readonly aiPipelineCheck" not in text:
    text = text.replace("private readonly syncService: SecurityDataSyncService,", "private readonly syncService: SecurityDataSyncService,\n    private readonly aiPipelineCheck: AiPipelineCheckService,")

if "runAiPipelineCheck" not in text:
    method = """

  @Post('devices/:deviceId/ai-pipeline-check')
  @ApiOperation({
    summary: 'Chạy pipeline AI cho thiết bị: Wazuh CVE export, XGBoost inference, import DB',
  })
  runAiPipelineCheck(
    @CurrentUser() user: AuthenticatedUser,
    @Param('deviceId', new ParseUUIDPipe()) deviceId: string,
  ) {
    return this.aiPipelineCheck.runForUserDevice(user.id, deviceId);
  }
"""
    text = re.sub(r"\n}\s*$", method + "\n}\n", text, count=1)

controller_path.write_text(text, encoding='utf-8')

# Patch device-analysis-button.tsx syncNow only.
component_path = root / 'apps' / 'user-web' / 'src' / 'components' / 'device-analysis-button.tsx'
backup(component_path)
text = component_path.read_text(encoding='utf-8')

new_sync = r'''  async function syncNow(): Promise<void> {
    setIsModalOpen(true);
    setIsRunning(true);
    setError('');
    setExpandedId(null);

    try {
      const response = await fetch(
        `/api/devices/${deviceId}/ai-pipeline-check`,
        {
          method: 'POST',
          cache: 'no-store',
        },
      );
      const payload = await response.json().catch(() => null) as
        | ApiErrorResponse
        | null;

      if (!response.ok) {
        if (response.status === 409) {
          setError(
            errorMessage(
              payload as ApiErrorResponse,
              'Thiết bị đang chạy AI pipeline. Chờ phiên hiện tại hoàn tất rồi bấm kiểm tra lại.',
            ),
          );

          await loadLatest().catch(() => undefined);
          await loadVulnerabilities().catch(() => undefined);
          return;
        }

        throw new Error(
          errorMessage(
            payload as ApiErrorResponse,
            'Không thể chạy kiểm tra AI pipeline',
          ),
        );
      }

      await loadLatest().catch(() => undefined);
      await loadVulnerabilities();
    } catch (caught: unknown) {
      setError(
        caught instanceof Error
          ? caught.message
          : 'Không thể kiểm tra máy bằng AI pipeline',
      );

      await loadLatest().catch(() => undefined);
      await loadVulnerabilities().catch(() => undefined);
    } finally {
      setIsRunning(false);
    }
  }
'''
text2, n = re.subn(r"  async function syncNow\(\): Promise<void> \{[\s\S]*?\n  \}\n\n  function closeModal", new_sync + "\n  function closeModal", text, count=1)
if n != 1:
    raise SystemExit('Could not replace syncNow() in device-analysis-button.tsx')
text = text2

# Ensure model label for V3 if missing.
if "CYRP_XGBOOST_CVSS_PERCENTILE_V3" not in text:
    needle = "  if (modelVersion === 'AI_CYRP_XGBOOST_V2') {\n    return 'AI_CYRP XGBoost';\n  }"
    insert = "  if (modelVersion === 'CYRP_XGBOOST_CVSS_PERCENTILE_V3') {\n    return 'CYRP XGBoost CVSS Percentile';\n  }\n\n" + needle
    text = text.replace(needle, insert)

component_path.write_text(text, encoding='utf-8')

# Patch validation.schema.ts to avoid future strict validation issues.
validation_path = root / 'apps' / 'api' / 'src' / 'config' / 'validation.schema.ts'
if validation_path.exists():
    backup(validation_path)
    text = validation_path.read_text(encoding='utf-8')
    if 'AI_PIPELINE_MODEL_ROOT' not in text:
        insert = """

  AI_MODEL_VERSION: Joi.string().trim().optional(),
  AI_MODEL_PYTHON_PATH: Joi.string().trim().optional(),
  AI_PIPELINE_MODEL_ROOT: Joi.string().trim().default('apps/ai-model/model-risk-prediction'),
  AI_PIPELINE_DATA_USER_DIR: Joi.string().trim().default('apps/ai-model/model-risk-prediction/Data User'),
  AI_PIPELINE_PYTHON_PATH: Joi.string().trim().optional(),
  AI_PIPELINE_TIMEOUT_MS: Joi.number().integer().min(30000).max(3600000).default(900000),
"""
        text = text.replace("\n});", insert + "\n});")
        validation_path.write_text(text, encoding='utf-8')

print('DONE')
print(f'Backup: {backup_dir}')
