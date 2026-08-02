from pathlib import Path
import re
import shutil
from datetime import datetime

path = Path(r"D:\LuanVan\test\cyrp-platform-phase2\apps\ai-model\model-risk-prediction\CTI Collector\Extract_Data_Wazuh.py")
backup = path.with_suffix(".py.bak-encoding-fix-" + datetime.now().strftime("%Y%m%d-%H%M%S"))
shutil.copy2(path, backup)

text = path.read_text(encoding="utf-8")

helper = r'''
def open_text_auto(path):
    path = Path(path)
    data = path.read_bytes()

    if data.startswith(b"\xff\xfe") or data.startswith(b"\xfe\xff"):
        return data.decode("utf-16")

    for encoding in ("utf-8-sig", "utf-8", "cp1258", "cp1252"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue

    return data.decode("utf-8", errors="replace")
'''

if "def open_text_auto(" not in text:
    insert_after = "requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)\n"
    text = text.replace(insert_after, insert_after + helper + "\n")

# Replace direct open in read_existing_pairs if present.
text = re.sub(
    r"with\s+open\(([^,\n]+),\s*newline=\"\",\s*encoding=\"utf-8-sig\"\)\s+as\s+f:\s*\n\s*reader\s*=\s*csv\.DictReader\(f\)",
    r"from io import StringIO\n    reader = csv.DictReader(StringIO(open_text_auto(\1)))",
    text,
    count=1,
)

# Fallback: if the regex did not match because function layout differs, inject a safer full read_existing_pairs.
if "def read_existing_pairs(" in text:
    start = text.find("def read_existing_pairs(")
    next_def = text.find("\ndef ", start + 1)
    if next_def != -1:
        replacement = r'''def read_existing_pairs(path):
    from io import StringIO

    existing = {}

    if not path:
        return existing

    csv_text = open_text_auto(path)
    reader = csv.DictReader(StringIO(csv_text))

    for row in reader:
        cve_id = normalize_cve(
            row.get("CVE_ID")
            or row.get("cve_id")
            or row.get("cve")
        )
        agent_id = str(
            row.get("agent_id")
            or row.get("wazuh_agent_id")
            or row.get("agent.id")
            or ""
        ).strip()

        if not cve_id or not agent_id:
            continue

        existing[(cve_id, agent_id)] = {
            "status": (row.get("status") or "").strip().upper(),
            "last_processed_at": (
                row.get("last_processed_at")
                or row.get("predicted_at")
                or row.get("last_seen_at")
                or ""
            ).strip(),
        }

    return existing

'''
        text = text[:start] + replacement + text[next_def+1:]

path.write_text(text, encoding="utf-8")

print(f"Patched: {path}")
print(f"Backup:  {backup}")
