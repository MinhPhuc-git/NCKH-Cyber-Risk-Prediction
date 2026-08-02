from pathlib import Path
from datetime import datetime
import shutil

path = Path(r"D:\LuanVan\test\cyrp-platform-phase2\apps\api\src\modules\security-data\ai-pipeline-check.service.ts")

if not path.exists():
    raise SystemExit(f"Không tìm thấy file: {path}")

backup = path.with_suffix(path.suffix + ".bak-add-sync-run-for-ai-check-" + datetime.now().strftime("%Y%m%d-%H%M%S"))
shutil.copy2(path, backup)

text = path.read_text(encoding="utf-8")

# 1. Bổ sung enum cần dùng.
text = text.replace(
    "import { VulnerabilityLifecycleStatus } from '@prisma/client';",
    """import {
  SyncRunStatus,
  SyncSourceType,
  VulnerabilityLifecycleStatus,
} from '@prisma/client';""",
)

# 2. Tạo SyncRun ngay sau startedAt.
old = """    const startedAt = new Date();
    const steps: PipelineStepResult[] = [];"""

new = """    const startedAt = new Date();
    const steps: PipelineStepResult[] = [];

    const syncRun = await this.database.syncRun.create({
      data: {
        deviceId,
        sourceType: SyncSourceType.WAZUH_VULNERABILITIES,
        status: SyncRunStatus.RUNNING,
        trigger: 'USER_AI_PIPELINE_CHECK',
        startedAt,
        sourceManifest: {
          kind: 'AI_PIPELINE_CHECK',
          wazuhAgentId,
          modelRoot: this.modelRoot,
          dataUserDir: this.dataUserDir,
        },
        metadata: {
          userId,
          deviceId,
          wazuhAgentId,
          action: 'machine_check_ai_pipeline',
        },
      },
      select: { id: true },
    });"""

if old not in text:
    raise SystemExit("Không tìm thấy block startedAt/steps để chèn syncRun.")

text = text.replace(old, new, 1)

# 3. Nhánh không có CVE mới: vẫn ghi 1 dòng lịch sử completed.
old = """      const completedAt = new Date();

      return {
        deviceId,"""

new = """      const completedAt = new Date();

      await this.database.syncRun.update({
        where: { id: syncRun.id },
        data: {
          status: SyncRunStatus.COMPLETED,
          completedAt,
          recordsRead: activeVulnerabilities,
          recordsWritten: 0,
          recordsUpdated: topPredictions.length,
          recordsRejected: 0,
          checkpointAfter: {
            skippedBecauseNoNewCve: true,
            activeVulnerabilities,
            topPredictions: topPredictions.length,
            delta,
          },
          metadata: {
            userId,
            deviceId,
            wazuhAgentId,
            action: 'machine_check_ai_pipeline',
            skippedBecauseNoNewCve: true,
          },
          errorSummary: null,
        },
      });

      return {
        deviceId,"""

if old not in text:
    raise SystemExit("Không tìm thấy nhánh completedAt đầu tiên để update syncRun.")

text = text.replace(old, new, 1)

# 4. Nhánh có chạy pipeline/import: ghi kết quả import vào syncRun.
old = """    const completedAt = new Date();

    const result: AiPipelineCheckResult = {
      deviceId,"""

new = """    const completedAt = new Date();

    await this.database.syncRun.update({
      where: { id: syncRun.id },
      data: {
        status: importResult.errors.length > 0
          ? SyncRunStatus.PARTIAL
          : SyncRunStatus.COMPLETED,
        completedAt,
        recordsRead: importResult.recordsRead,
        recordsWritten: importResult.recordsImported,
        recordsUpdated: importResult.historyRowsCreated,
        recordsRejected: importResult.errors.length,
        checkpointAfter: {
          filesFound: importResult.filesFound,
          filesDeleted: importResult.filesDeleted,
          recordsRead: importResult.recordsRead,
          recordsImported: importResult.recordsImported,
          vulnerabilitiesCreated: importResult.vulnerabilitiesCreated,
          historyRowsCreated: importResult.historyRowsCreated,
          skipped: importResult.skipped.length,
          errors: importResult.errors.length,
          activeVulnerabilities,
          topPredictions: topPredictions.length,
          delta,
        },
        metadata: {
          userId,
          deviceId,
          wazuhAgentId,
          action: 'machine_check_ai_pipeline',
          shouldRunPipeline: true,
          durationMs: completedAt.getTime() - startedAt.getTime(),
        },
        errorSummary: importResult.errors.length > 0
          ? importResult.errors
              .map((item) => `${item.file}: ${item.message}`)
              .join('; ')
              .slice(0, 2000)
          : null,
      },
    });

    const result: AiPipelineCheckResult = {
      deviceId,"""

if old not in text:
    raise SystemExit("Không tìm thấy nhánh completedAt/result thứ hai để update syncRun.")

text = text.replace(old, new, 1)

path.write_text(text, encoding="utf-8")

print("Patched:", path)
print("Backup:", backup)
