from pathlib import Path
from datetime import datetime
import shutil
import re

path = Path(r"D:\LuanVan\test\cyrp-platform-phase2\apps\api\src\modules\security-data\ai-pipeline-check.service.ts")

if not path.exists():
    raise SystemExit(f"Không tìm thấy file: {path}")

backup = path.with_suffix(path.suffix + ".bak-sync-wazuh-before-ai-robust-" + datetime.now().strftime("%Y%m%d-%H%M%S"))
shutil.copy2(path, backup)

text = path.read_text(encoding="utf-8")

def find_matching_paren(source: str, open_index: int) -> int:
    depth = 0
    quote = None
    escape = False
    i = open_index

    while i < len(source):
        ch = source[i]

        if quote:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == quote:
                quote = None
            i += 1
            continue

        if ch in ("'", '"', "`"):
            quote = ch
            i += 1
            continue

        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return i

        i += 1

    return -1

# 1. Import SecurityDataSyncService nếu chưa có.
if "SecurityDataSyncService" not in text:
    marker = "import { CveLifecycleDeltaService } from './cve-lifecycle-delta.service';"
    if marker in text:
        text = text.replace(
            marker,
            marker + "\nimport { SecurityDataSyncService } from './security-data-sync.service';",
            1,
        )
    else:
        local_imports = list(re.finditer(r"^import .* from './.*';$", text, flags=re.MULTILINE))
        if not local_imports:
            raise SystemExit("Không tìm được vị trí chèn import SecurityDataSyncService.")
        last = local_imports[-1]
        text = text[:last.end()] + "\nimport { SecurityDataSyncService } from './security-data-sync.service';" + text[last.end():]
elif "import { SecurityDataSyncService } from './security-data-sync.service';" not in text:
    # Có chữ SecurityDataSyncService ở đâu đó nhưng chưa có import chuẩn.
    local_imports = list(re.finditer(r"^import .* from './.*';$", text, flags=re.MULTILINE))
    if not local_imports:
        raise SystemExit("Không tìm được vị trí chèn import SecurityDataSyncService.")
    last = local_imports[-1]
    text = text[:last.end()] + "\nimport { SecurityDataSyncService } from './security-data-sync.service';" + text[last.end():]

# 2. Chèn dependency vào constructor bằng cách tìm dấu ngoặc constructor(...).
if "private readonly syncService: SecurityDataSyncService" not in text:
    ctor_match = re.search(r"constructor\s*\(", text)
    if not ctor_match:
        raise SystemExit("Không tìm thấy constructor trong ai-pipeline-check.service.ts.")

    open_paren = text.find("(", ctor_match.start())
    close_paren = find_matching_paren(text, open_paren)

    if close_paren < 0:
        raise SystemExit("Không tìm thấy dấu ')' kết thúc constructor.")

    params = text[open_paren + 1:close_paren]

    insert_param = "\n    private readonly syncService: SecurityDataSyncService,"

    if params.strip() == "":
        new_params = insert_param + "\n  "
    else:
        # Nếu param cuối chưa có dấu phẩy thì thêm phẩy.
        stripped = params.rstrip()
        trailing = params[len(stripped):]
        if not stripped.endswith(","):
            stripped += ","
        new_params = stripped + insert_param + trailing

    text = text[:open_paren + 1] + new_params + text[close_paren:]

# 3. Chèn bước full Wazuh sync trước delta.
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
print("SecurityDataSyncService import:", "import { SecurityDataSyncService } from './security-data-sync.service';" in text)
print("Constructor injection:", "private readonly syncService: SecurityDataSyncService" in text)
print("Pre-sync step:", "wazuh-full-sync-before-ai" in text)
