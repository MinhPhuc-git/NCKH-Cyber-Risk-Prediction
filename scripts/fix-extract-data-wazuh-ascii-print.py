from pathlib import Path
import shutil
from datetime import datetime

path = Path(r"D:\LuanVan\test\cyrp-platform-phase2\apps\ai-model\model-risk-prediction\CTI Collector\Extract_Data_Wazuh.py")

backup = path.with_suffix(".py.bak-fix-ascii-print-" + datetime.now().strftime("%Y%m%d-%H%M%S"))
shutil.copy2(path, backup)

text = path.read_text(encoding="utf-8")

text = text.replace(
    'print("[i] LIST_CVE_ID.csv không có CVE cần xử lý. Đây là bình thường nếu delta scan chỉ có CVE đã biết còn mới.")',
    'print("[i] LIST_CVE_ID.csv has no CVE to process. This is normal when delta scan only contains known fresh CVEs.")'
)

# Fallback nếu file đang bị mojibake hoặc escape lẫn lộn.
text = text.replace(
    'print("[i] LIST_CVE_ID.csv kh�ng c� CVE cần xử lý. Đây là bình thường nếu delta scan chỉ có CVE đã biết còn mới.")',
    'print("[i] LIST_CVE_ID.csv has no CVE to process. This is normal when delta scan only contains known fresh CVEs.")'
)

path.write_text(text, encoding="utf-8")

print(f"Patched: {path}")
print(f"Backup:  {backup}")
