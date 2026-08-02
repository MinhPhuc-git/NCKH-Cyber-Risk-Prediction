from pathlib import Path
from datetime import datetime
import shutil

root = Path(r"D:\LuanVan\test\cyrp-platform-phase2")
tsx = root / "apps/user-web/src/components/device-analysis-button.tsx"
css = root / "apps/user-web/src/components/device-analysis-button.module.css"

if not tsx.exists():
    raise SystemExit(f"Không tìm thấy file: {tsx}")

if not css.exists():
    raise SystemExit(f"Không tìm thấy file: {css}")

tsx_backup = tsx.with_suffix(tsx.suffix + ".bak-fix-gauge-call-source-" + datetime.now().strftime("%Y%m%d-%H%M%S"))
css_backup = css.with_suffix(css.suffix + ".bak-fix-gauge-call-source-" + datetime.now().strftime("%Y%m%d-%H%M%S"))

shutil.copy2(tsx, tsx_backup)
shutil.copy2(css, css_backup)

text = tsx.read_text(encoding="utf-8")

def matching_paren(source: str, open_index: int) -> int:
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

        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return i

        i += 1

    return -1

def matching_brace(source: str, open_index: int) -> int:
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

def remove_function(source: str, name: str) -> str:
    while True:
        start = source.find(f"function {name}(")

        if start < 0:
            return source

        open_brace = source.find("{", start)

        if open_brace < 0:
            return source

        close_brace = matching_brace(source, open_brace)

        if close_brace < 0:
            return source

        end = close_brace + 1

        while end < len(source) and source[end] in "\r\n":
            end += 1

        source = source[:start] + source[end:]

def replace_call_argument(source: str, name: str, new_argument: str):
    replaced = 0
    pos = 0
    target = f"{name}("

    while True:
        start = source.find(target, pos)

        if start < 0:
            break

        prefix = source[max(0, start - 16):start]

        if "function " in prefix:
            pos = start + len(target)
            continue

        open_paren = start + len(name)
        close_paren = matching_paren(source, open_paren)

        if close_paren < 0:
            pos = start + len(target)
            continue

        source = source[:open_paren + 1] + new_argument + source[close_paren:]
        replaced += 1
        pos = open_paren + 1 + len(new_argument) + 1

    return source, replaced

# Tìm biến percentile cao nhất đang tồn tại trong file.
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

# Xóa và chèn lại các helper đúng ngưỡng.
for fn in ["percentileAsRiskScale", "gaugeClass", "riskBandLabel"]:
    text = remove_function(text, fn)

marker = "function formatPercentile"

if marker not in text:
    marker = "function formatPercent"

if marker not in text:
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

text = text.replace(marker, helpers + marker, 1)

gauge_source = f"percentileAsRiskScale({percentile_source})"

text, gauge_replaced = replace_call_argument(text, "gaugeClass", gauge_source)
text, label_replaced = replace_call_argument(text, "riskBandLabel", gauge_source)

tsx.write_text(text, encoding="utf-8")

css_text = css.read_text(encoding="utf-8")

css_patch = """

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
    css_text = css_text.rstrip() + css_patch + "\n"

css.write_text(css_text, encoding="utf-8")

print("Patched TSX:", tsx)
print("Patched CSS:", css)
print("Backup TSX:", tsx_backup)
print("Backup CSS:", css_backup)
print("Gauge source:", gauge_source)
print("gaugeClass calls replaced:", gauge_replaced)
print("riskBandLabel calls replaced:", label_replaced)
