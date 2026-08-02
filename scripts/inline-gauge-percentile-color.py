from pathlib import Path
from datetime import datetime
import shutil
import re

root = Path(r"D:\LuanVan\test\cyrp-platform-phase2")
tsx = root / "apps/user-web/src/components/device-analysis-button.tsx"
css = root / "apps/user-web/src/components/device-analysis-button.module.css"

if not tsx.exists():
    raise SystemExit(f"Không tìm thấy file: {tsx}")

if not css.exists():
    raise SystemExit(f"Không tìm thấy file: {css}")

tsx_backup = tsx.with_suffix(tsx.suffix + ".bak-inline-gauge-color-" + datetime.now().strftime("%Y%m%d-%H%M%S"))
css_backup = css.with_suffix(css.suffix + ".bak-inline-gauge-color-" + datetime.now().strftime("%Y%m%d-%H%M%S"))

shutil.copy2(tsx, tsx_backup)
shutil.copy2(css, css_backup)

text = tsx.read_text(encoding="utf-8")

# 1. Thêm import CSSProperties nếu chưa có.
if "CSSProperties" not in text:
    text = text.replace(
        "import {",
        "import type { CSSProperties } from 'react';\nimport {",
        1,
    )

# 2. Thêm helper màu theo percentile nếu chưa có.
helper_marker = "function formatPercentile"
if helper_marker not in text:
    helper_marker = "function formatPercent"

if helper_marker not in text:
    raise SystemExit("Không tìm thấy vị trí chèn helper màu gauge.")

helper = """function percentileGaugeColor(value: number | null): string {
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    return '#64748b';
  }

  const percent = value <= 1 ? value * 100 : value;

  if (percent >= 85) {
    return '#f87171';
  }

  if (percent >= 65) {
    return '#fb923c';
  }

  if (percent >= 45) {
    return '#facc15';
  }

  return '#34d399';
}

"""

if "function percentileGaugeColor(" not in text:
    text = text.replace(helper_marker, helper + helper_marker, 1)

# 3. Tìm biến percentile cao nhất.
candidates = [
    "cyrpDisplayHighestPercentile",
    "displayHighestPercentile",
    "aiRiskSummary?.highestPercentile",
    "highestAiSummary?.highestPercentile",
]

percentile_source = None
for candidate in candidates:
    if candidate in text:
        percentile_source = candidate
        break

if percentile_source is None:
    raise SystemExit("Không tìm thấy biến percentile cao nhất trong device-analysis-button.tsx.")

# 4. Chèn biến gaugeAccentColor/gaugeStyle trước return chính.
style_block = f"""  const gaugeAccentColor = percentileGaugeColor({percentile_source});

  const gaugeStyle = {{
    '--gauge-accent': gaugeAccentColor,
    '--gauge-color': gaugeAccentColor,
    '--ring-color': gaugeAccentColor,
  }} as CSSProperties;

"""

if "const gaugeAccentColor = percentileGaugeColor(" not in text:
    return_index = text.find("  return (")
    if return_index < 0:
        raise SystemExit("Không tìm thấy return chính để chèn gaugeStyle.")
    text = text[:return_index] + style_block + text[return_index:]

# 5. Thêm style={gaugeStyle} vào div gauge.
# Trường hợp phổ biến hiện tại: className={styles.gauge}
if "className={styles.gauge}" in text and "style={gaugeStyle}" not in text:
    text = text.replace(
        "className={styles.gauge}",
        "className={styles.gauge}\n              style={gaugeStyle}",
        1,
    )
elif "style={gaugeStyle}" not in text:
    # Trường hợp className template string nhưng không gọi gaugeClass.
    text, count = re.subn(
        r"""className=\{`\$\{styles\.gauge\}`\}""",
        """className={styles.gauge}
              style={gaugeStyle}""",
        text,
        count=1,
    )

    if count == 0:
        raise SystemExit("Không tìm thấy className gauge để thêm style. Cần gửi đoạn Select-String quanh styles.gauge.")

tsx.write_text(text, encoding="utf-8")

# 6. CSS: ép .gauge dùng biến --gauge-accent cho conic-gradient.
css_text = css.read_text(encoding="utf-8")

patch = """

/* CYRP patch: gauge uses inline percentile color */
.gauge {
  --gauge-accent: var(--gauge-accent, #64748b);
}

.gauge::before,
.gauge::after {
  border-color: var(--gauge-accent) !important;
}

.gauge {
  color: var(--gauge-accent) !important;
}
"""

if "CYRP patch: gauge uses inline percentile color" not in css_text:
    css_text = css_text.rstrip() + patch + "\n"

# Thay các màu vàng hard-code thường gặp trong gauge bằng var.
css_text = css_text.replace("#facc15", "var(--gauge-accent)")
css_text = css_text.replace("#fbbf24", "var(--gauge-accent)")
css_text = css_text.replace("#f59e0b", "var(--gauge-accent)")
css_text = css_text.replace("rgb(250, 204, 21)", "var(--gauge-accent)")
css_text = css_text.replace("rgb(251, 191, 36)", "var(--gauge-accent)")

css.write_text(css_text, encoding="utf-8")

print("Patched TSX:", tsx)
print("Patched CSS:", css)
print("Backup TSX:", tsx_backup)
print("Backup CSS:", css_backup)
print("Percentile source:", percentile_source)
print("Expected 84% color: #fb923c")
