from pathlib import Path
from datetime import datetime
import shutil
import re

path = Path(r"D:\LuanVan\test\cyrp-platform-phase2\apps\user-web\src\app\ai-predictions\[id]\ai-prediction-detail-client.tsx")

if not path.exists():
    raise SystemExit(f"Không tìm thấy file: {path}")

backup = path.with_suffix(path.suffix + ".bak-remove-cvss-vector-row-" + datetime.now().strftime("%Y%m%d-%H%M%S"))
shutil.copy2(path, backup)

text = path.read_text(encoding="utf-8")

# 1. Xóa biến cvssVector vì không còn dùng.
text = re.sub(
    r"""  const cvssVector =
    getString\(item, \[
      \['featureVector', 'vector'\],
      \['featureVector', 'vectorString'\],
      \['cve', 'cvssMetrics', '0', 'vectorString'\],
      \['cve', 'cvssMetrics', '0', 'cvssVector'\],
    \]\) \?\? '—';

""",
    "",
    text,
    count=1,
)

# 2. Xóa dòng hiển thị Vector trong panel CVSS vector.
text = text.replace(
    '            <KeyValueRow label="Vector" value={cvssVector} />\n',
    "",
)

path.write_text(text, encoding="utf-8")

print("Patched:", path)
print("Backup:", backup)
print("cvssVector count:", text.count("const cvssVector"))
print("render Vector row:", '<KeyValueRow label="Vector"' in text)
