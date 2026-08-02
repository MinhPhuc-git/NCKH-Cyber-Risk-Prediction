from pathlib import Path
from datetime import datetime
import shutil
import re

path = Path(r"D:\LuanVan\test\cyrp-platform-phase2\apps\user-web\src\app\ai-predictions\ai-predictions-client.tsx")

if not path.exists():
    raise SystemExit(f"Không tìm thấy file: {path}")

backup = path.with_suffix(path.suffix + ".bak-remove-debug-leftover-" + datetime.now().strftime("%Y%m%d-%H%M%S"))
shutil.copy2(path, backup)

text = path.read_text(encoding="utf-8")

# Xóa state debug nếu còn.
text = re.sub(
    r"\r?\n\s*const\s+\[debugInfo,\s*setDebugInfo\]\s*=\s*useState\(''\);",
    "",
    text,
)

# Xóa block debugTop + setDebugInfo còn sót.
text = re.sub(
    r"\r?\n\s*const\s+debugTop\s*=\s*sortedItems\[0\];\r?\n\s*setDebugInfo\(`CYRP_AI_DEBUG[\s\S]*?`\);",
    "",
    text,
)

# Xóa block render debugInfo nếu còn.
text = re.sub(
    r"\r?\n\s*\{debugInfo\s*\?\s*\([\s\S]*?\)\s*:\s*null\}\s*",
    "\n",
    text,
)

path.write_text(text, encoding="utf-8")

print("Removed debug leftovers.")
print("Backup:", backup)
print("setDebugInfo count:", text.count("setDebugInfo"))
print("CYRP_AI_DEBUG count:", text.count("CYRP_AI_DEBUG"))
print("debugInfo count:", text.count("debugInfo"))
