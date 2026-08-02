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

tsx_backup = tsx.with_suffix(tsx.suffix + ".bak-force-gauge-percentile-source-" + datetime.now().strftime("%Y%m%d-%H%M%S"))
css_backup = css.with_suffix(css.suffix + ".bak-force-gauge-percentile-source-" + datetime.now().strftime("%Y%m%d-%H%M%S"))

shutil.copy2(tsx, tsx_backup)
shutil.copy2(css, css_backup)

text = tsx.read_text(encoding="utf-8")

def find_matching_brace(source: str, open_index: int) -> int:
    depth = 0
    quote = None
    escape = False
    i = open_index

    while i < len(source):
        ch = source[i]

        if quote:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == quote:
                quote = None
            i += 1
            continue

        if ch in ("'", '"', "`"):
            quote = ch
            i += 1
            continue

        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return i

        i += 1

    return -1

def remove_function(source: 1
            if depth == 0:
                return i

        i += 1

    return -1

def remove_function(source: str, name: str) -> str:
    while True:
        start = source.find(f"function {name}(")
        if start < 0:
            return source

        open_brace = source.find("{", start)
        if open_brace < 0:
            return source

        close_brace = find_matching_brace(source, open_brace)
        if close_brace < 0:
            return source

        end = close_brace + 1
        while end < len(source) and source[end] in "\r\n":
            end += 1

        source = source[:start] + source[end:]

# 1. Xóa các hàm gauge cũ để tránh dùng nhầm ngưỡng.
for fn in ["percentileAsRiskScale", "gaugeClass", "riskBandLabel"]:
    text = remove_function(text, fn)

# 2. Chèn lại hàm màu theo đúng ngưỡng percentile.
insert_marker = "function formatPercentile"
if insert_marker not in text:
    insert_marker = "function formatPercent"

if insert_marker not in text:
    raise SystemExit("Không tìm thấy vị trí chèn helper gauge.")

helpers = """function percentileAsRiskScale(value: number | null): number | null {
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    return null;
  }

  return value > 1 ? value / 100 : value;
}

function gaugeClass(value: number | null): string {
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

function riskBandLabel(value: number | null): string {
  if (value === null) {
    return 'Chưa đủ dữ liệu';
  }

  if (value >= 0.85) {
    return 'Nguy cơ nghiêm trọng';
  }

  if (value >= 0.65) {
    return 'Nguy cơ cao';
  }

  if (value >= 0.45) {
    return 'Nguy cơ trung bình';
  }

  return 'Nguy cơ thấp';
}

"""

text = text.replace(insert_marker, helpers + insert_marker, 1)

# 3. Tìm đúng biến percentile cao nhất đang có trong file.
candidates = [
    "cyrpDisplayHighestPercentile",
    "displayHighestPercentile",
    "highestAiSummary?.highestPercentile",
    "aiRiskSummary?.highestPercentile",
]

percentile_source = None
for candidate in candidates:
    if candidate in text:
        percentile_source = candidate
        break

if percentile_source is None:
    raise SystemExit("Không tìm thấy biến percentile cao nhất trong device-analysis-button.tsx.")

gauge_source = f"percentileAsRiskScale({percentile_source})"

# 4. Ép className của gauge dùng percentile, không dùng attackProbability.
text, replaced = re.subn(
    r"""className=\{`\$\{styles\.gauge\}\s+\$\{gaugeClass\([^)]*\)\}`\}""",
    f"""className={{`${{styles.gauge}} ${{gaugeClass({gauge_source})}}`}}""",
    text,
    count=1,
)

if replaced == 0:
    raise SystemExit("Không tìm thấy className gauge để thay.")

# 5. Ép nhãn nguy cơ dưới số 84% cũng dùng percentile.
text = re.sub(
    r"""riskBandLabel\([^)]*\)""",
    f"""riskBandLabel({gauge_source})""",
    text,
    count=1,
)

tsx.write_text(text, encoding="utf-8")

# 6. CSS: ép màu class gaugeHigh là cam, critical là đỏ.
css_text = css.read_text(encoding="utf-8")

patch = """

/* CYRP force modal gauge colors by percentile */
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

.gaugeHigh::before,
.gaugeHigh::after {
  border-color: #fb923c !important;
}

.gaugeCritical::before,
.gaugeCritical::after {
  border-color: #f87171 !important;
}
"""

if "CYRP force modal gauge colors by percentile" not in css_text:
    css_text = css_text.rstrip() + patch + "\n"

css.write_text(css_text, encoding="utf-8")

print("Patched TSX:", tsx)
print("Patched CSS:", css)
print("Backup TSX:", tsx_backup)
print("Backup CSS:", css_backup)
print("Gauge source:", gauge_source)
print("Gauge className replaced:", replaced)
