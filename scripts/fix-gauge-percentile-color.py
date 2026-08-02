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

tsx_backup = tsx.with_suffix(tsx.suffix + ".bak-gauge-percentile-color-" + datetime.now().strftime("%Y%m%d-%H%M%S"))
css_backup = css.with_suffix(css.suffix + ".bak-gauge-percentile-color-" + datetime.now().strftime("%Y%m%d-%H%M%S"))

shutil.copy2(tsx, tsx_backup)
shutil.copy2(css, css_backup)

text = tsx.read_text(encoding="utf-8")

# Tìm biến percentile cao nhất đang có trong file.
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

# Bảo đảm có helper đổi 84 -> 0.84.
if "function percentileAsRiskScale(" not in text:
    marker = "function formatPercentile"
    if marker not in text:
        marker = "function formatPercent"

    if marker not in text:
        raise SystemExit("Không tìm thấy vị trí chèn percentileAsRiskScale.")

    helper = """function percentileAsRiskScale(value: number | null): number | null {
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    return null;
  }

  return value > 1 ? value / 100 : value;
}

"""
    text = text.replace(marker, helper + marker, 1)

# Bảo đảm gaugeClass dùng ngưỡng 0.45 / 0.65 / 0.85.
text = re.sub(
    r"""function gaugeClass\([^)]*\): string \{
[\s\S]*?
\}
""",
    """function gaugeClass(value: number | null): string {
  if (value === null) {
    return styles.gaugeNeutral;
  }

  if (value >= 0.85) {
    return styles.gaugeCritical;
  }

  if (value >= 0.65) {
    return styles.gaugeHigh;
  }

  if (value >= 0.45) {
    return styles.gaugeMedium;
  }

  return styles.gaugeLow;
}
""",
    text,
    count=1,
)

# Nếu chưa có gaugeClass thì chèn mới.
if "function gaugeClass(" not in text:
    marker = "function formatPercentile"
    if marker not in text:
        marker = "function formatPercent"

    helper = """function gaugeClass(value: number | null): string {
  if (value === null) {
    return styles.gaugeNeutral;
  }

  if (value >= 0.85) {
    return styles.gaugeCritical;
  }

  if (value >= 0.65) {
    return styles.gaugeHigh;
  }

  if (value >= 0.45) {
    return styles.gaugeMedium;
  }

  return styles.gaugeLow;
}

"""
    text = text.replace(marker, helper + marker, 1)

gauge_source = f"percentileAsRiskScale({percentile_source})"

# Sửa className của gauge để lấy màu từ percentile, không lấy từ attack probability.
text, replaced = re.subn(
    r"""className=\{`\$\{styles\.gauge\}\s+\$\{gaugeClass\([\s\S]*?\)\}`\}""",
    f"""className={{`${{styles.gauge}} ${{gaugeClass({gauge_source})}}`}}""",
    text,
    count=1,
)

if replaced == 0:
    raise SystemExit("Không tìm thấy className của gauge để thay.")

# Sửa nhãn dưới 84% dùng cùng nguồn percentile.
text = re.sub(
    r"""riskBandLabel\([\s\S]*?\)""",
    f"""riskBandLabel({gauge_source})""",
    text,
    count=1,
)

tsx.write_text(text, encoding="utf-8")

css_text = css.read_text(encoding="utf-8")

patch = """

/* CYRP gauge color bands by percentile */
.gaugeLow {
  --gauge-accent: #34d399 !important;
  --gauge-color: #34d399 !important;
  --ring-color: #34d399 !important;
}

.gaugeMedium {
  --gauge-accent: #facc15 !important;
  --gauge-color: #facc15 !important;
  --ring-color: #facc15 !important;
}

.gaugeHigh {
  --gauge-accent: #fb923c !important;
  --gauge-color: #fb923c !important;
  --ring-color: #fb923c !important;
}

.gaugeCritical {
  --gauge-accent: #f87171 !important;
  --gauge-color: #f87171 !important;
  --ring-color: #f87171 !important;
}
"""

if "CYRP gauge color bands by percentile" not in css_text:
    css_text = css_text.rstrip() + patch + "\n"

css.write_text(css_text, encoding="utf-8")

print("Patched TSX:", tsx)
print("Patched CSS:", css)
print("Backup TSX:", tsx_backup)
print("Backup CSS:", css_backup)
print("Gauge source:", gauge_source)
print("Gauge className replaced:", replaced)
