from pathlib import Path
from datetime import datetime
import shutil
import re

ROOT = Path(r"D:\LuanVan\test\cyrp-platform-phase2")
TSX = ROOT / "apps" / "user-web" / "src" / "app" / "vulnerabilities" / "vulnerabilities-client.tsx"
CSS = ROOT / "apps" / "user-web" / "src" / "components" / "security-console.module.css"

backup_tsx = TSX.with_suffix(".tsx.bak-pagination-class-" + datetime.now().strftime("%Y%m%d-%H%M%S"))
backup_css = CSS.with_suffix(".css.bak-pagination-class-" + datetime.now().strftime("%Y%m%d-%H%M%S"))

shutil.copy2(TSX, backup_tsx)
shutil.copy2(CSS, backup_css)

tsx = TSX.read_text(encoding="utf-8")
css = CSS.read_text(encoding="utf-8")

pos = tsx.find("Trang trước")
if pos == -1:
    raise SystemExit("Không tìm thấy chữ Trang trước trong vulnerabilities-client.tsx")

window = tsx[max(0, pos - 900): pos + 900]
classes = list(dict.fromkeys(re.findall(r"styles\.([A-Za-z0-9_]+)", window)))

extra_css = """

/* CYRP patch: force Vulnerable Detection pagination spacing */
"""

for class_name in classes:
    extra_css += f"""
.{class_name} {{
  gap: 12px;
}}

.{class_name} > * {{
  margin-right: 10px;
}}

.{class_name} > *:last-child {{
  margin-right: 0;
}}
"""

# Thêm class riêng nếu JSX đang không có parent rõ ràng.
if "styles.vulnerabilityPaginationFix" not in window:
    # Bọc parent gần nhất nếu tìm được div chứa Trang trước.
    start = tsx.rfind("<div", 0, pos)
    end = tsx.find("</div>", pos)

    if start != -1 and end != -1:
      opening_end = tsx.find(">", start)
      opening = tsx[start:opening_end + 1]

      if "className=" in opening:
          new_opening = re.sub(
              r"className=\{([^}]+)\}",
              r"className={`${\1} ${styles.vulnerabilityPaginationFix}`}",
              opening,
              count=1,
          )
      else:
          new_opening = opening[:-1] + " className={styles.vulnerabilityPaginationFix}>"

      tsx = tsx[:start] + new_opening + tsx[opening_end + 1:]

extra_css += """
.vulnerabilityPaginationFix {
  display: flex;
  align-items: center;
  gap: 12px;
  flex-wrap: wrap;
}

.vulnerabilityPaginationFix > * {
  margin-right: 10px;
}

.vulnerabilityPaginationFix > *:last-child {
  margin-right: 0;
}
"""

if "CYRP patch: force Vulnerable Detection pagination spacing" not in css:
    css = css.rstrip() + extra_css + "\n"

TSX.write_text(tsx, encoding="utf-8")
CSS.write_text(css, encoding="utf-8")

print("Patched pagination classes:", ", ".join(classes))
print("Backup TSX:", backup_tsx)
print("Backup CSS:", backup_css)
