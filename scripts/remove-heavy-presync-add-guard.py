from pathlib import Path
from datetime import datetime
import shutil
import re

path = Path(r"D:\LuanVan\test\cyrp-platform-phase2\apps\api\src\modules\security-data\ai-pipeline-check.service.ts")

if not path.exists():
    raise SystemExit(f"Không tìm thấy file: {path}")

backup = path.with_suffix(path.suffix + ".bak-remove-heavy-presync-" + datetime.now().strftime("%Y%m%d-%H%M%S"))
shutil.copy2(path, backup)

text = path.read_text(encoding="utf-8")

text = re.sub(
    r"^import \{ SecurityDataSyncService \} from './security-data-sync\.service';\r?\n",
    "",
    text,
    flags=re.MULTILINE,
)

text = re.sub(
    r"\r?\n\s*private readonly syncService: SecurityDataSyncService,",
    "",
    text,
)

text = re.sub(
    r"\n\s*const wazuhSyncStartedAt = Date\.now\(\);\s*"
    r"\n\s*const wazuhSyncResult = await this\.syncService\.syncForUser\(userId, deviceId\);\s*"
    r"\n\s*steps\.push\(\{\s*"
    r"\n\s*step: 'wazuh-full-sync-before-ai',[\s\S]*?"
    r"\n\s*\}\);\s*\n",
    "\n",
    text,
    count=1,
)

guard = """    const enrichedVulnerabilityRows = await this.database.detectedVulnerability.count({
      where: {
        deviceId,
        wazuhAgentId,
        status: VulnerabilityLifecycleStatus.ACTIVE,
        sourceIndex: {
          not: 'ai-pipeline-data-user',
        },
        packageName: {
          not: null,
        },
      },
    });

    if (enrichedVulnerabilityRows === 0) {
      const completedAt = new Date();

      await this.database.syncRun.update({
        where: { id: syncRun.id },
        data: {
          status: SyncRunStatus.FAILED,
          completedAt,
          recordsRead: 0,
          recordsWritten: 0,
          recordsUpdated: 0,
          recordsRejected: 0,
          errorSummary:
            'WAZUH_SYNC_REQUIRED: Thiet bi chua co du lieu Wazuh vulnerability day du trong DB. Hay chay dong bo Wazuh truoc khi chay AI.',
          checkpointAfter: {
            code: 'WAZUH_SYNC_REQUIRED',
            deviceId,
            wazuhAgentId,
          },
        },
      });

      throw new ServiceUnavailableException({
        code: 'WAZUH_SYNC_REQUIRED',
        message:
          'Thiet bi chua co du lieu Wazuh vulnerability day du trong database. Hay chay dong bo Wazuh truoc, sau do moi chay AI.',
        deviceId,
        wazuhAgentId,
      });
    }

    steps.push({
      step: 'wazuh-data-guard',
      command: 'database.detectedVulnerability.count',
      skipped: false,
      durationMs: 0,
      stdoutTail: JSON.stringify({ enrichedVulnerabilityRows }),
      stderrTail: '',
    });

"""

if "step: 'wazuh-data-guard'" not in text:
    marker = "    const delta = await"
    idx = text.find(marker)

    if idx < 0:
        raise SystemExit("Không tìm thấy 'const delta = await' để chèn guard.")

    text = text[:idx] + guard + text[idx:]

path.write_text(text, encoding="utf-8")

print("Patched:", path)
print("Backup:", backup)
print("Removed heavy pre-sync:", "wazuh-full-sync-before-ai" not in text)
print("Has guard:", "step: 'wazuh-data-guard'" in text)
print("syncService remains:", "syncService" in text)
