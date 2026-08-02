from pathlib import Path
from datetime import datetime
import shutil
import re

ROOT = Path(r"D:\LuanVan\test\cyrp-platform-phase2")
TSX = ROOT / "apps" / "user-web" / "src" / "app" / "vulnerabilities" / "vulnerabilities-client.tsx"
CSS = ROOT / "apps" / "user-web" / "src" / "components" / "security-console.module.css"

shutil.copy2(TSX, TSX.with_suffix(".tsx.bak-vuln-layout-" + datetime.now().strftime("%Y%m%d-%H%M%S")))
shutil.copy2(CSS, CSS.with_suffix(".css.bak-vuln-layout-" + datetime.now().strftime("%Y%m%d-%H%M%S")))

text = TSX.read_text(encoding="utf-8")

# 1) Thêm class riêng cho cụm header của Vulnerable Detection.
marker = "VULNERABILITIES_HEADER_REFRESH"
idx = text.find(marker)

if idx != -1:
    div_start = text.rfind("<div", 0, idx)
    div_end = text.find(">", div_start)

    if div_start != -1 and div_end != -1:
        opening = text[div_start:div_end + 1]

        if "vulnerabilityHeaderActions" not in opening:
            if "className={styles.headerActions}" in opening:
                new_opening = opening.replace(
                    "className={styles.headerActions}",
                    "className={`${styles.headerActions} ${styles.vulnerabilityHeaderActions}`}",
                )
            elif "className={`" in opening:
                new_opening = opening.replace(
                    "className={`",
                    "className={`${styles.vulnerabilityHeaderActions} ",
                    1,
                )
            else:
                new_opening = opening[:-1] + " className={styles.vulnerabilityHeaderActions}>"

            text = text[:div_start] + new_opening + text[div_end + 1:]
else:
    print("[WARN] Không tìm thấy marker VULNERABILITIES_HEADER_REFRESH. Nút Làm mới vẫn có thể đang ở header nhưng chưa có marker.")

# 2) Đảm bảo span Trang hiện tại có class riêng.
text = re.sub(
    r"<span(?: className=\{styles\.paginationCurrent\})?>\s*Trang\s*\{page\}\s*</span>",
    "<span className={styles.paginationCurrent}>Trang {page}</span>",
    text,
    count=1,
)

TSX.write_text(text, encoding="utf-8")

css = CSS.read_text(encoding="utf-8")

patch = """

/* CYRP patch: Vulnerable Detection header refresh + pagination spacing */
.vulnerabilityHeaderActions {
  display: flex;
  flex-direction: column;
  align-items: flex-end;
  gap: 10px;
}

.vulnerabilityHeaderActions button {
  order: 1;
}

.vulnerabilityHeaderActions span {
  order: 2;
}

.paginationCurrent {
  display: inline-flex;
  align-items: center;
  margin: 0 18px;
  white-space: nowrap;
}
"""

if "CYRP patch: Vulnerable Detection header refresh + pagination spacing" not in css:
    css = css.rstrip() + patch + "\n"

CSS.write_text(css, encoding="utf-8")

print("Patched Vulnerable Detection layout.")
