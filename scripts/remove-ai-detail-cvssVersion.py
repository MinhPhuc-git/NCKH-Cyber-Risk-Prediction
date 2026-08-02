from pathlib import Path
from datetime import datetime
import shutil

path = Path(r"D:\LuanVan\test\cyrp-platform-phase2\apps\user-web\src\app\ai-predictions\[id]\ai-prediction-detail-client.tsx")

if not path.exists():
    raise SystemExit(f"Không tìm thấy file: {path}")

backup = path.with_suffix(path.suffix + ".bak-remove-cvssVersion-" + datetime.now().strftime("%Y%m%d-%H%M%S"))
shutil.copy2(path, backup)

text = path.read_text(encoding="utf-8")

print("Before count item.featureVector?.cvssVersion =", text.count("item.featureVector?.cvssVersion"))

text = text.replace(" ?? item.featureVector?.cvssVersion", "")
text = text.replace("?? item.featureVector?.cvssVersion", "")
text = text.replace("item.featureVector?.cvssVersion ?? ", "")
text = text.replace("item.featureVector?.cvssVersion", "")

# Sửa fallback bị mojibake nếu còn.
text = text.replace("'â€”'", "'-'")
text = text.replace('"â€”"', '"-"')
text = text.replace("'—'", "'-'")
text = text.replace('"—"', '"-"')

path.write_text(text, encoding="utf-8")

print("After count item.featureVector?.cvssVersion =", text.count("item.featureVector?.cvssVersion"))
print("Backup:", backup)
