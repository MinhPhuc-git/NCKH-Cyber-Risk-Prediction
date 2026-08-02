from pathlib import Path
from datetime import datetime
import shutil
import re

root = Path(r"D:\LuanVan\test\cyrp-platform-phase2")
path = root / "apps" / "user-web" / "src" / "components" / "device-analysis-button.tsx"

backup = path.with_suffix(".tsx.bak-runtime-null-array-fix-" + datetime.now().strftime("%Y%m%d-%H%M%S"))
shutil.copy2(path, backup)

text = path.read_text(encoding="utf-8")

# 1. Chèn safe arrays ngay trước return của DeviceAnalysisButton.
marker = "CYRP_SAFE_DEVICE_ANALYSIS_ARRAYS"

if marker not in text:
    func_index = text.find("export function DeviceAnalysisButton")
    if func_index == -1:
        raise SystemExit("Không tìm thấy export function DeviceAnalysisButton")

    return_index = text.find("\n  return (", func_index)
    if return_index == -1:
        raise SystemExit("Không tìm thấy return trong DeviceAnalysisButton")

    safe_block = """
  // CYRP_SAFE_DEVICE_ANALYSIS_ARRAYS
  const safeTopRules = Array.isArray(snapshot?.topRules)
    ? snapshot.topRules
    : [];

  const safeLatestAlerts = Array.isArray(snapshot?.latestAlerts)
    ? snapshot.latestAlerts
    : [];

"""
    text = text[:return_index] + safe_block + text[return_index:]

# 2. Thay các chỗ gọi .length/.slice trực tiếp trên snapshot arrays.
replacements = {
    "snapshot.topRules.length": "safeTopRules.length",
    "snapshot?.topRules.length": "safeTopRules.length",
    "snapshot.topRules?.length": "safeTopRules.length",
    "snapshot?.topRules?.length": "safeTopRules.length",
    "snapshot.topRules.slice(": "safeTopRules.slice(",
    "snapshot?.topRules?.slice(": "safeTopRules.slice(",

    "snapshot.latestAlerts.length": "safeLatestAlerts.length",
    "snapshot?.latestAlerts.length": "safeLatestAlerts.length",
    "snapshot.latestAlerts?.length": "safeLatestAlerts.length",
    "snapshot?.latestAlerts?.length": "safeLatestAlerts.length",
    "snapshot.latestAlerts.slice(": "safeLatestAlerts.slice(",
    "snapshot?.latestAlerts?.slice(": "safeLatestAlerts.slice(",
}

for old, new in replacements.items():
    text = text.replace(old, new)

# 3. Khi API /api/vulnerabilities chưa trả items, không set undefined vào state.
text = re.sub(
    r"setVulnerabilities\(\s*payload\.items\s*(?:\?\?\s*\[\])?\s*\);",
    "setVulnerabilities(Array.isArray(payload.items) ? payload.items : []);",
    text,
)

# 4. Nếu còn payload.items.length trực tiếp thì đổi sang dạng an toàn.
text = re.sub(
    r"(?<!Array\.isArray\()payload\.items\.length",
    "(Array.isArray(payload.items) ? payload.items.length : 0)",
    text,
)

# 5. Nếu còn unsafe snapshot length thì báo dừng.
unsafe_patterns = [
    "snapshot.topRules.length",
    "snapshot.latestAlerts.length",
    "snapshot?.topRules.length",
    "snapshot?.latestAlerts.length",
]

remaining = [pattern for pattern in unsafe_patterns if pattern in text]
if remaining:
    raise SystemExit("Vẫn còn unsafe .length: " + ", ".join(remaining))

path.write_text(text, encoding="utf-8")

print("Patched:", path)
print("Backup:", backup)
