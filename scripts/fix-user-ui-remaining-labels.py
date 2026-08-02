from pathlib import Path
from datetime import datetime
import shutil
import re

ROOT = Path(r"D:\LuanVan\test\cyrp-platform-phase2")
SRC = ROOT / "apps" / "user-web" / "src"
STAMP = datetime.now().strftime("%Y%m%d-%H%M%S")
BACKUP = ROOT / ".phase-backups" / f"ui-fix-remaining-labels-{STAMP}"
BACKUP.mkdir(parents=True, exist_ok=True)

changed = []

def backup_file(path: Path):
    rel = path.relative_to(ROOT)
    dst = BACKUP / rel
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(path, dst)

def save(path: Path, old: str, new: str, reason: str):
    if old != new:
        backup_file(path)
        path.write_text(new, encoding="utf-8")
        changed.append((str(path.relative_to(ROOT)), reason))

files = list(SRC.rglob("*.tsx")) + list(SRC.rglob("*.ts"))

for path in files:
    old = path.read_text(encoding="utf-8")
    new = old

    # Label còn sót ở card ưu tiên.
    new = new.replace("RỦI RO KHAI THÁC", "PERCENTILE")
    new = new.replace("RỦI RO BỊ KHAI THÁC", "PERCENTILE")

    # Label agent trong JSX/string literal.
    new = new.replace(">AGENT<", ">WAZUH AGENT<")
    new = new.replace("'AGENT'", "'WAZUH AGENT'")
    new = new.replace('"AGENT"', '"WAZUH AGENT"')
    new = new.replace("`AGENT`", "`WAZUH AGENT`")

    # Label thiết bị còn sót.
    new = new.replace(">THIẾT BỊ<", ">TÊN THIẾT BỊ<")
    new = new.replace("'THIẾT BỊ'", "'TÊN THIẾT BỊ'")
    new = new.replace('"THIẾT BỊ"', '"TÊN THIẾT BỊ"')

    save(path, old, new, "remaining labels")

print("Backup:", BACKUP)
print("Changed files:")
for item, reason in changed:
    print("-", item, reason)

print("Done.")
