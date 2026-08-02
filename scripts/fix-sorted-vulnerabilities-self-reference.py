from pathlib import Path
from datetime import datetime
import shutil
import re

path = Path(r"D:\LuanVan\test\cyrp-platform-phase2\apps\user-web\src\components\device-analysis-button.tsx")

backup = path.with_suffix(".tsx.bak-fix-sorted-self-reference-" + datetime.now().strftime("%Y%m%d-%H%M%S"))
shutil.copy2(path, backup)

text = path.read_text(encoding="utf-8")

pattern = re.compile(
    r"(const sortedVulnerabilities = useMemo\(\s*\(\) => \{\s*return \[\.\.\.)sortedVulnerabilities(\]\.sort\([\s\S]*?\);\s*\},\s*)\[sortedVulnerabilities\](,\s*\);)",
    re.MULTILINE,
)

new_text, count = pattern.subn(
    r"\1vulnerabilities\2[vulnerabilities]\3",
    text,
    count=1,
)

if count == 0:
    print("[WARN] Regex không match. Chạy fallback replace trong vùng sortedVulnerabilities.")

    start = text.find("const sortedVulnerabilities = useMemo(")
    end = text.find("const strongestPrediction", start)

    if start == -1 or end == -1:
        raise SystemExit("Không tìm thấy block sortedVulnerabilities. Gửi lại lines 585-620 của device-analysis-button.tsx.")

    block = text[start:end]
    fixed = block.replace("[...sortedVulnerabilities]", "[...vulnerabilities]")
    fixed = fixed.replace("[sortedVulnerabilities],", "[vulnerabilities],")

    new_text = text[:start] + fixed + text[end:]

path.write_text(new_text, encoding="utf-8")

print(f"Patched: {path}")
print(f"Backup:  {backup}")
