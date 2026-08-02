from pathlib import Path
from datetime import datetime
import shutil
import re

root = Path(r"D:\LuanVan\test\cyrp-platform-phase2")

ai_client = root / "apps/user-web/src/app/ai-predictions/ai-predictions-client.tsx"
security_css = root / "apps/user-web/src/components/security-console.module.css"
device_button = root / "apps/user-web/src/components/device-analysis-button.tsx"
device_css = root / "apps/user-web/src/components/device-analysis-button.module.css"

def backup(path: Path):
    if path.exists():
        dst = path.with_suffix(path.suffix + ".bak-force-percentile-color-" + datetime.now().strftime("%Y%m%d-%H%M%S"))
        shutil.copy2(path, dst)
        print("Backup:", dst)

def remove_function(source: str, name: str) -> str:
    start = source.find(f"function {name}(")
    if start < 0:
        return source

    open_brace = source.find("{", start)
    if open_brace < 0:
        return source

    depth = 0
    i = open_brace
    while i < len(source):
        if source[i] == "{":
            depth += 1
        elif source[i] == "}":
            depth -= 1
            if depth == 0:
                end = i + 1
                while end < len(source) and source[end] in "\r\n":
                    end += 1
                return source[:start] + source[end:]
        i += 1

    return source

for p in [ai_client, security_css, device_button, device_css]:
    backup(p)

# =========================================================
# 1. AI Predictions table: force percentile color by number.
# =========================================================
text = ai_client.read_text(encoding="utf-8")

text = remove_function(text, "percentileClass")
text = remove_function(text, "percentileBandClass")
text = remove_function(text, "percentileBandStyle")

helper = """function percentileBandValue(value: number | null): number | null {
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    return null;
  }

  return value <= 1 ? value * 100 : value;
}

function percentileBandClass(value: number | null): string {
  const percent = percentileBandValue(value);

  if (percent === null) {
    return styles.severityUnknown;
  }

  if (percent >= 85) {
    return styles.percentileCritical;
  }

  if (percent >= 65) {
    return styles.percentileHigh;
  }

  if (percent >= 45) {
    return styles.percentileMedium;
  }

  return styles.percentileLow;
}

function percentileBandStyle(value: number | null) {
  const percent = percentileBandValue(value);

  if (percent === null) {
    return {};
  }

  if (percent >= 85) {
    return {
      color: '#f87171',
      backgroundColor: 'rgba(239, 68, 68, 0.16)',
      borderColor: 'rgba(239, 68, 68, 0.42)',
    };
  }

  if (percent >= 65) {
    return {
      color: '#fb923c',
      backgroundColor: 'rgba(251, 146, 60, 0.16)',
      borderColor: 'rgba(251, 146, 60, 0.38)',
    };
  }

  if (percent >= 45) {
    return {
      color: '#facc15',
      backgroundColor: 'rgba(250, 204, 21, 0.14)',
      borderColor: 'rgba(250, 204, 21, 0.34)',
    };
  }

  return {
    color: '#34d399',
    backgroundColor: 'rgba(52, 211, 153, 0.14)',
    borderColor: 'rgba(52, 211, 153, 0.34)',
  };
}

"""

marker = "function statusClass("
if marker not in text:
    marker = "function severityClass("

if marker not in text:
    raise SystemExit("Không tìm thấy vị trí chèn percentile helper trong ai-predictions-client.tsx")

text = text.replace(marker, helper + marker, 1)

if "const rowPercentile = predictionPercentile(row);" not in text:
    text = text.replace(
        "const level = normalizedAiRiskLevel(row);",
        "const level = normalizedAiRiskLevel(row);\n                  const rowPercentile = predictionPercentile(row);",
        1,
    )

span_pattern = re.compile(
    r"""<span\s+className=\{`\$\{styles\.statusPill\}\s+\$\{(?:severityClass\(level\)|percentileClass\(rowPercentile\)|percentileBandClass\(rowPercentile\))\}`\}(?:\s+style=\{[^}]+\})?>\s*\{formatPercentile\((?:rowPercentile|predictionPercentile\(row\))\)\}\s*</span>""",
    re.MULTILINE,
)

span_replacement = """<span
                          className={`${styles.statusPill} ${percentileBandClass(rowPercentile)}`}
                          style={percentileBandStyle(rowPercentile)}
                        >
                          {formatPercentile(rowPercentile)}
                        </span>"""

text, count = span_pattern.subn(span_replacement, text, count=1)

if count == 0:
    print("WARNING: Không thay được span percentile bằng regex. Sẽ thử replace mềm.")
    text = text.replace(
        "{formatPercentile(predictionPercentile(row))}",
        "{formatPercentile(rowPercentile)}",
    )
    text = text.replace(
        "className={`${styles.statusPill} ${severityClass(level)}`}",
        "className={`${styles.statusPill} ${percentileBandClass(rowPercentile)}`}\n                          style={percentileBandStyle(rowPercentile)}",
        1,
    )
    text = text.replace(
        "className={`${styles.statusPill} ${percentileClass(rowPercentile)}`}",
        "className={`${styles.statusPill} ${percentileBandClass(rowPercentile)}`}\n                          style={percentileBandStyle(rowPercentile)}",
        1,
    )

ai_client.write_text(text, encoding="utf-8")

# CSS classes for table fallback.
css = security_css.read_text(encoding="utf-8")

patch_css = """

/* CYRP force percentile color bands */
.percentileLow {
  color: #34d399 !important;
  background: rgba(52, 211, 153, 0.14) !important;
  border-color: rgba(52, 211, 153, 0.34) !important;
}

.percentileMedium {
  color: #facc15 !important;
  background: rgba(250, 204, 21, 0.14) !important;
  border-color: rgba(250, 204, 21, 0.34) !important;
}

.percentileHigh {
  color: #fb923c !important;
  background: rgba(251, 146, 60, 0.16) !important;
  border-color: rgba(251, 146, 60, 0.38) !important;
}

.percentileCritical {
  color: #f87171 !important;
  background: rgba(239, 68, 68, 0.16) !important;
  border-color: rgba(239, 68, 68, 0.42) !important;
}
"""

if "CYRP force percentile color bands" not in css:
    css = css.rstrip() + patch_css + "\n"

security_css.write_text(css, encoding="utf-8")

# =========================================================
# 2. Machine check modal gauge: color by highest percentile.
# =========================================================
button = device_button.read_text(encoding="utf-8")

button = remove_function(button, "percentileAsRiskScale")
button = remove_function(button, "gaugeClass")
button = remove_function(button, "riskBandLabel")

helper_marker = "function formatPercentile"
if helper_marker not in button:
    helper_marker = "function formatPercent"

if helper_marker not in button:
    raise SystemExit("Không tìm thấy vị trí chèn gauge helper trong device-analysis-button.tsx")

gauge_helpers = """function percentileAsRiskScale(value: number | null): number | null {
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    return null;
  }

  return value > 1 ? value / 100 : value;
}

function gaugeClass(probability: number | null): string {
  if (probability === null) {
    return styles.gaugeNeutral;
  }

  if (probability >= 0.85) {
    return styles.gaugeCritical;
  }

  if (probability >= 0.65) {
    return styles.gaugeHigh;
  }

  if (probability >= 0.45) {
    return styles.gaugeMedium;
  }

  return styles.gaugeLow;
}

function riskBandLabel(probability: number | null): string {
  if (probability === null) {
    return 'Chưa đủ dữ liệu';
  }

  if (probability >= 0.85) {
    return 'Nguy cơ nghiêm trọng';
  }

  if (probability >= 0.65) {
    return 'Nguy cơ cao';
  }

  if (probability >= 0.45) {
    return 'Nguy cơ trung bình';
  }

  return 'Nguy cơ thấp';
}

"""

button = button.replace(helper_marker, gauge_helpers + helper_marker, 1)

percentile_var = None
for candidate in [
    "cyrpDisplayHighestPercentile",
    "displayHighestPercentile",
    "highestPercentile",
]:
    if candidate in button:
        percentile_var = candidate
        break

if not percentile_var:
    raise SystemExit("Không tìm thấy biến highest percentile trong device-analysis-button.tsx")

button = re.sub(
    r"""className=\{`\$\{styles\.gauge\}\s+\$\{gaugeClass\([^}]+\)\}`\}""",
    f"""className={{`${{styles.gauge}} ${{gaugeClass(percentileAsRiskScale({percentile_var}))}}`}}""",
    button,
    count=1,
)

device_button.write_text(button, encoding="utf-8")

dcss = device_css.read_text(encoding="utf-8")

gauge_css = """

/* CYRP force gauge color by percentile bands */
.gaugeLow {
  --gauge-accent: #34d399 !important;
  --gauge-color: #34d399 !important;
  --ring-color: #34d399 !important;
  color: #34d399 !important;
}

.gaugeMedium {
  --gauge-accent: #facc15 !important;
  --gauge-color: #facc15 !important;
  --ring-color: #facc15 !important;
  color: #facc15 !important;
}

.gaugeHigh {
  --gauge-accent: #fb923c !important;
  --gauge-color: #fb923c !important;
  --ring-color: #fb923c !important;
  color: #fb923c !important;
}

.gaugeCritical {
  --gauge-accent: #f87171 !important;
  --gauge-color: #f87171 !important;
  --ring-color: #f87171 !important;
  color: #f87171 !important;
}
"""

if "CYRP force gauge color by percentile bands" not in dcss:
    dcss = dcss.rstrip() + gauge_css + "\n"

device_css.write_text(dcss, encoding="utf-8")

print("DONE")
print("AI table percentile span patched:", count)
print("Gauge percentile variable:", percentile_var)
print("Expected: 68/74/79/82/84 = HIGH orange, 85+ = CRITICAL red")
