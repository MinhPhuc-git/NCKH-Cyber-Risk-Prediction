from pathlib import Path
from datetime import datetime
import shutil
import re

path = Path(r"D:\LuanVan\test\cyrp-platform-phase2\apps\user-web\src\components\device-analysis-button.tsx")

if not path.exists():
    raise SystemExit(f"Không tìm thấy file: {path}")

current = path.read_text(encoding="utf-8")

if re.search(r"\n\s*(async\s+)?function\s+syncNow\s*\(", current):
    print("File hiện tại đã có function syncNow, không cần khôi phục.")
    raise SystemExit(0)

def matching_brace(source: str, open_index: int) -> int:
    depth = 0
    quote = None
    escape = False
    line_comment = False
    block_comment = False
    i = open_index

    while i < len(source):
        ch = source[i]
        nxt = source
    i = open_index

    while i < len(source):
        ch = source[i]
        nxt = source[i + 1] if i + 1 < len(source) else ""

        if line_comment:
            if ch == "\n":
                line_comment = False
            i += 1
            continue

        if block_comment:
            if ch == "*" and nxt == "/":
                block_comment = False
                i += 2
            else:
                i += 1
            continue

        if quote:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == quote:
                quote = None
            i += 1
            continue

        if ch == "/" and nxt == "/":
            line_comment = True
            i += 2
            continue

        if ch == "/" and nxt == "*":
            block_comment = True
            i += 2
            continue

        if ch in ("'", '"', "`"):
            quote = ch
            i += 1
            continue

        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return i

        i += 1

    return -1

def extract_sync_now(source: str) -> str | None:
    match = re.search(r"\n  (?:async\s+)?function\s+syncNow\s*\([^)]*\)\s*\{", source)

    if not match:
        return None

    start = match.start() + 1
    open_brace = source.find("{", match.start())

    if open_brace < 0:
        return None

    close_brace = matching_brace(source, open_brace)

    if close_brace < 0:
        return None

    return source[start:close_brace + 1].rstrip() + "\n\n"

backups = sorted(
    path.parent.glob(path.name + ".bak*"),
    key=lambda item: item.stat().st_mtime,
    reverse=True,
)

sync_block = None
source_backup = None

for backup in backups:
    text = backup.read_text(encoding="utf-8", errors="ignore")
    block = extract_sync_now(text)

    if block:
        sync_block = block
        source_backup = backup
        break

if not sync_block:
    print("Không tìm thấy syncNow trong các backup sau:")
    for item in backups[:20]:
        print(" -", item)
    raise SystemExit("Cần gửi đoạn quanh onClick và các backup hiện có.")

# Chèn thêm refresh highest summary nếu syncNow cũ chưa có.
if "loadDeviceHighestAiSummary" in current and "await loadDeviceHighestAiSummary();" not in sync_block:
    sync_block = sync_block.replace(
        "await loadVulnerabilities();",
        "await loadVulnerabilities();\n      await loadDeviceHighestAiSummary();",
        1,
    )

insert_marker = "  const cyrpDisplayAgentId ="

insert_index = current.find(insert_marker)

if insert_index < 0:
    insert_marker = "  return ("
    insert_index = current.find(insert_marker)

if insert_index < 0:
    raise SystemExit("Không tìm thấy vị trí chèn syncNow trước return.")

backup_current = path.with_suffix(path.suffix + ".bak-restore-syncnow-" + datetime.now().strftime("%Y%m%d-%H%M%S"))
shutil.copy2(path, backup_current)

new_text = current[:insert_index] + sync_block + current[insert_index:]

path.write_text(new_text, encoding="utf-8")

print("Đã khôi phục syncNow từ:", source_backup)
print("Backup file hiện tại:", backup_current)
