from pathlib import Path
from datetime import datetime
import re
import shutil

path = Path(r"D:\LuanVan\test\cyrp-platform-phase2\apps\user-web\src\components\device-analysis-button.tsx")

if not path.exists():
    raise SystemExit(f"Không tìm thấy file: {path}")

backup = path.with_suffix(path.suffix + ".bak-fix-highest-ai-state-" + datetime.now().strftime("%Y%m%d-%H%M%S"))
shutil.copy2(path, backup)

text = path.read_text(encoding="utf-8")

# Bảo đảm type Pagination được import nếu loader đang dùng Pagination<VulnerabilityItem>.
if "Pagination<" in text:
    pattern = r"import type \{([\s\S]*?)\} from '@/lib/security-data-types';"
    match = re.search(pattern, text)

    if match and "Pagination" not in match.group(1):
        body = match.group(1).rstrip()
        new_body = body + "\n  Pagination,"
        text = text[:match.start(1)] + new_body + text[match.end(1):]

# Thêm state highestAiSummary ngay trước hàm loadDeviceHighestAiSummary.
state_line = "  const [highestAiSummary, setHighestAiSummary] = useState<DeviceHighestAiSummary | null>(null);\n\n"

if "const [highestAiSummary, setHighestAiSummary]" not in text:
    marker = "  async function loadDeviceHighestAiSummary"

    if marker not in text:
        raise SystemExit("Không tìm thấy async function loadDeviceHighestAiSummary trong file.")

    text = text.replace(marker, state_line + marker, 1)

path.write_text(text, encoding="utf-8")

print("Patched:", path)
print("Backup:", backup)
