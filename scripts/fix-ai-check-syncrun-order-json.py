from pathlib import Path
from datetime import datetime
import shutil

path = Path(r"D:\LuanVan\test\cyrp-platform-phase2\apps\api\src\modules\security-data\ai-pipeline-check.service.ts")

if not path.exists():
    raise SystemExit(f"Không tìm thấy file: {path}")

backup = path.with_suffix(path.suffix + ".bak-fix-syncrun-order-json-" + datetime.now().strftime("%Y%m%d-%H%M%S"))
shutil.copy2(path, backup)

text = path.read_text(encoding="utf-8")

def matching_paren(source: str, open_index: int) -> int:
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

# 1. Xóa block syncRun.create đang bị đặt sai vị trí.
start = text.find("    const syncRun = await this.database.syncRun.create({")

if start >= 0:
    open_paren = text.find("(", start)
    close_paren = matching_paren(text, open_paren)

    if close_paren < 0:
        raise SystemExit("Không tìm được điểm kết thúc của syncRun.create.")

    end = close_paren + 1

    if end < len(text) and text[end] == ";":
        end += 1

    while end < len(text) and text[end] in "\r\n":
        end += 1

    text = text[:start] + text[end:]
    print("Removed old misplaced syncRun block.")
else:
    print("Không thấy syncRun block cũ, sẽ chỉ kiểm tra/chèn lại nếu cần.")

# 2. Chèn syncRun.create sau khi wazuhAgentId đã có, ngay trước delta.prepareForAgent.
sync_block = """    const syncRun = await this.database.syncRun.create({
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
    });

"""

if "const syncRun = await this.database.syncRun.create" not in text:
    marker = "    const delta = await"

    insert_index = text.find(marker)

    if insert_index < 0:
        raise SystemExit("Không tìm thấy vị trí 'const delta = await' để chèn syncRun.")

    text = text[:insert_index] + sync_block + text[insert_index:]
    print("Inserted syncRun block before delta.")
else:
    print("syncRun block đã tồn tại sau khi cleanup.")

# 3. Sửa delta trong checkpointAfter thành JSON-safe object.
text = text.replace(
    "            delta,\n",
    "            delta: JSON.parse(JSON.stringify(delta)),\n",
)

text = text.replace(
    "          delta,\n",
    "          delta: JSON.parse(JSON.stringify(delta)),\n",
)

path.write_text(text, encoding="utf-8")

print("Patched:", path)
print("Backup:", backup)
print("syncRun create count:", text.count("const syncRun = await this.database.syncRun.create"))
print("raw 'delta,' remains:", "delta," in text)
