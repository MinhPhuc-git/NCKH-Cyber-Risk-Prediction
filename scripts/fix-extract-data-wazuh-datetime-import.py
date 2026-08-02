from pathlib import Path
import shutil
from datetime import datetime

path = Path(r"D:\LuanVan\test\cyrp-platform-phase2\apps\ai-model\model-risk-prediction\CTI Collector\Extract_Data_Wazuh.py")

backup = path.with_suffix(".py.bak-fix-missing-datetime-import-" + datetime.now().strftime("%Y%m%d-%H%M%S"))
shutil.copy2(path, backup)

text = path.read_text(encoding="utf-8")

if "from datetime import datetime, timezone" not in text:
    lines = text.splitlines()
    insert_at = 0

    # Chèn sau block import đầu file.
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("import ") or stripped.startswith("from "):
            insert_at = i + 1
        elif stripped == "":
            continue
        else:
            break

    lines.insert(insert_at, "from datetime import datetime, timezone")
    text = "\n".join(lines) + "\n"

path.write_text(text, encoding="utf-8")

print(f"Patched: {path}")
print(f"Backup:  {backup}")
