from pathlib import Path
from datetime import datetime
import shutil

path = Path(r"D:\LuanVan\test\cyrp-platform-phase2\apps\user-web\src\app\ai-predictions\ai-predictions-client.tsx")

if not path.exists():
    raise SystemExit(f"Không tìm thấy file: {path}")

backup = path.with_suffix(path.suffix + ".bak-fix-rowPercentile-scope-" + datetime.now().strftime("%Y%m%d-%H%M%S"))
shutil.copy2(path, backup)

text = path.read_text(encoding="utf-8")

text = text.replace(
    "percentileBandClass(rowPercentile)",
    "percentileBandClass(percentile)",
)

text = text.replace(
    "percentileBandStyle(rowPercentile)",
    "percentileBandStyle(percentile)",
)

path.write_text(text, encoding="utf-8")

print("Patched:", path)
print("Backup:", backup)
print("rowPercentile remains:", "rowPercentile" in text)
