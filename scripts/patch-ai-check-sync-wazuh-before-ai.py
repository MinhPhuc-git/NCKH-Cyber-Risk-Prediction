from pathlib import Path
from datetime import datetime
import shutil
import re

path = Path(r"D:\LuanVan\test\cyrp-platform-phase2\apps\api\src\modules\security-data\ai-pipeline-check.service.ts")

if not path.exists():
    raise SystemExit(f"Không tìm thấy file: {path}")

backup = path.with_suffix(path.suffix + ".bak-sync-wazuh-before-ai-" + datetime.now().strftime("%Y%m%d-%H%M%S"))
shutil.copy2(path, backup)

text = path.read_text(encoding="utf-8")

# 1. Import SecurityDataSyncService nếu chưa có.
if "import { SecurityDataSyncService } from './security-data-sync.service';" not in text:
    marker = "import { CveLifecycleDeltaService } from './cve-lifecycle-delta.service';"
    if marker in text:
        text = text.replace(
            marker,
            marker + "\nimport { SecurityDataSyncService } from './security-data-sync.service';",
            1,
        )
    else:
        # Chèn gần các import local cuối cùng.
        local_imports = list(re.finditer(r"^import .* from './.*';$", text, flags=re.MULTILINE))
        if not local_imports:
            raise SystemExit("Không tìm được vị trí chèn import SecurityDataSyncService.")
        last = local_imports[-1]
        text = text[:last.end()] + "\nimport { SecurityDataSyncService } from './security-data-sync.service';" + text[last.end():]

# 2. Thêm dependency vào constructor.
if "private readonly syncService: SecurityDataSyncService" not in text:
    # Chèn trước config: ConfigService vì config thường là param cuối.
    pattern = r"(\n\s*)config: ConfigService,"
    if re.search(pattern, text):
        text = re.sub(
            pattern,
            r"\1private readonly syncService: SecurityDataSyncService,\1config: ConfigService,",
            text,
            count=1,
        )
    else:
        raise SystemExit("Không tìm thấy 'config: ConfigService,' trong constructor để chèn syncService.")

# 3. Chèn bước Wazuh sync trước delta/pipeline.
sync_step = """    const wazuhSyncStartedAt = Date.now();
    const wazuhSyncResult = await this.syncService.syncForUser(userId, deviceId);

    steps.push({
      step: 'wazuh-full-sync-before-ai',
      command: 'SecurityDataSyncService.syncForUser',
      skipped: false,
      durationMs: Date.now() - wazuhSyncStartedAt,
      stdoutTail: JSON.stringify({
        status: wazuhSyncResult.status,
        wazuhAgentId: wazuhSyncResult.wazuhAgentId,
        vulnerabilities: wazuhSyncResult.components.vulnerabilities.status,
        endpointContext: wazuhSyncResult.components.endpointContext.status,
      }),
      stderrTail: '',
    });

"""

if "wazuh-full-sync-before-ai" not in text:
    marker = "    const delta = await"
    idx = text.find(marker)
    if idx < 0:
        raise SystemExit("Không tìm thấy 'const delta = await' để chèn bước sync trước AI.")
    text = text[:idx] + sync_step + text[idx:]

path.write_text(text, encoding="utf-8")

print("Patched:", path)
print("Backup:", backup)
print("Has SecurityDataSyncService import:", "SecurityDataSyncService" in text)
print("Has pre-sync step:", "wazuh-full-sync-before-ai" in text)
