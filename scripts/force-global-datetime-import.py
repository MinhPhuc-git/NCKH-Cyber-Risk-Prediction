from pathlib import Path
import shutil
from datetime import datetime

path = Path(r"D:\LuanVan\test\cyrp-platform-phase2\apps\ai-model\model-risk-prediction\CTI Collector\Extract_Data_Wazuh.py")

backup = path.with_suffix(".py.bak-force-global-datetime-import-" + datetime.now().strftime("%Y%m%d-%H%M%S"))
shutil.copy2(path, backup)

text = path.read_text(encoding="utf-8")
lines = text.splitlines()

# Kiểm tra có import global thật sự chưa: dòng không thụt đầu dòng.
has_global_import = any(
    line == "from datetime import datetime, timezone"
    for line in lines[:80]
)

if not has_global_import:
    # Chèn sau cụm import đầu file.
    insert_at = 0
    for i, line in enumerate(lines[:80]):
        stripped = line.strip()

        if stripped.startswith("import ") or stripped.startswith("from "):
            insert_at = i + 1
            continue

        if stripped == "":
            continue

        break

    lines.insert(insert_at, "from datetime import datetime, timezone")
    text = "\n".join(lines) + "\n"
    path.write_text(text, encoding="utf-8")

print(f"Patched: {path}")
print(f"Backup:  {backup}")
