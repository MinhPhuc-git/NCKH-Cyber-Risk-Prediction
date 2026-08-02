from pathlib import Path
from datetime import datetime
import shutil
import re

ROOT = Path(r"D:\LuanVan\test\cyrp-platform-phase2")

TARGETS = [
    ROOT / "apps" / "user-web" / "src" / "app" / "ai-predictions" / "ai-predictions-client.tsx",
    ROOT / "apps" / "user-web" / "src" / "app" / "vulnerabilities" / "vulnerabilities-client.tsx",
]

def patch_file(path: Path, marker: str):
    backup = path.with_suffix(".tsx.bak-header-refresh-" + datetime.now().strftime("%Y%m%d-%H%M%S"))
    shutil.copy2(path, backup)

    text = path.read_text(encoding="utf-8")
    old = text

    if marker in text:
        print(f"[SKIP] {path.name}: already has marker")
        return

    button = f"""
          {{/* {marker} */}}
          <button
            className={{styles.secondaryButton}}
            type="button"
            onClick={{() => {{
              setPage(1);
              void load();
            }}}}
            disabled={{loading}}
          >
            {{loading ? 'Đang tải...' : 'Làm mới'}}
          </button>"""

    pattern = re.compile(
        r"(<span[^>]*>\s*\{data\?\.total \?\? 0\}\s*bản ghi\s*</span>)",
        flags=re.DOTALL,
    )

    text, count = pattern.subn(r"\1" + button, text, count=1)

    if count == 0:
        print(f"[WARN] Không tìm thấy badge bản ghi trong {path}")
        print(f"       Backup: {backup}")
        return

    path.write_text(text, encoding="utf-8")
    print(f"[OK] Patched {path}")
    print(f"     Backup: {backup}")

patch_file(TARGETS[0], "AI_PREDICTIONS_HEADER_REFRESH")
patch_file(TARGETS[1], "VULNERABILITIES_HEADER_REFRESH")
