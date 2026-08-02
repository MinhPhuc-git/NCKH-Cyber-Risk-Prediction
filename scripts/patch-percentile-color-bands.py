from pathlib import Path
from datetime import datetime
import shutil
import re

root = Path(r"D:\LuanVan\test\cyrp-platform-phase2")

ai_client = root / "apps/user-web/src/app/ai-predictions/ai-predictions-client.tsx"
security_css = root / "apps/user-web/src/components/security-console.module.css"
device_button = root / "apps/user-web/src/components/device-analysis-button.tsx"
device_css = root / "apps/user-web/src/components/device-analysis-button.module.css"

for path in [ai_client, security_css, device_button, device_css]:
    if path.exists():
        backup = path.with_suffix(path.suffix + ".bak-percentile-color-band-" + datetime.now().strftime("%Y%m%d-%H%M%S"))
        shutil.copy2(path, backup)
        print("Backup:", backup)

# 1. CSS cho bảng AI Predictions.
css = security_css.read_text(encoding="utf-8")

css_patch = r"""

/* CYRP patch: percentile color bands
   LOW: 0-45, MEDIUM: 45-65, HIGH: 65-85, CRITICAL: 85-100 */
.percentileLow {
  color: #22c55e !important;
  background: rgba(34, 197, 94, 0.14) !important;
  border-color: rgba(34, 197, 94, 0.34) !important;
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
  color: #ef4444 !important;
  background: rgba(239, 68, 68, 0.16) !important;
  border-color: rgba(239, 68, 68, 0.42) !important;
}
"""

if "CYRP patch: percentile color bands" not in css:
    css = css.rstrip() + css_patch + "\n"

security_css.write_text(css, encoding="utf-8")

# 2. TSX: thêm percentileClass() và đổi ô Percentile dùng class theo số percentile.
text = ai_client.read_text(encoding="utf-8")

helper = r"""
function percentileClass(value: number | null): string {
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    return styles.severityUnknown;
  }

  const percent = value <= 1 ? value * 100 : value;

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
"""

if "function percentileClass(" not in text:
    marker = "function statusClass(status: string | null | undefined): string {"
    if marker not in text:
        raise SystemExit("Không tìm thấy vị trí chèn percentileClass trong ai-predictions-client.tsx")
    text = text.replace(marker, helper + "\n" + marker, 1)

text = text.replace(
    "const level = normalizedAiRiskLevel(row);",
    "const level = normalizedAiRiskLevel(row);\n                  const rowPercentile = predictionPercentile(row);",
    1,
)

old_span = """<span className={`${styles.statusPill} ${severityClass(level)}`}>
                          {formatPercentile(predictionPercentile(row))}
                        </span>"""

new_span = """<span className={`${styles.statusPill} ${percentileClass(rowPercentile)}`}>
                          {formatPercentile(rowPercentile)}
                        </span>"""

if old_span in text:
    text = text.replace(old_span, new_span, 1)
else:
    text = re.sub(
        r"""<span className=\{`\$\{styles\.statusPill\} \$\{severityClass\(level\)\}`\}>\s*\r?\n\s*\{formatPercentile\(predictionPercentile\(row\)\)\}\s*\r?\n\s*</span>""",
        new_span,
        text,
        count=1,
    )

ai_client.write_text(text, encoding="utf-8")

# 3. Modal kiểm tra máy: đổi gauge/risk label theo percentile thresholds.
button = device_button.read_text(encoding="utf-8")

button = re.sub(
    r"""function gaugeClass\(
  probability: number \| null,
\): string \{
[\s\S]*?
\}
""",
    r"""function gaugeClass(
  probability: number | null,
): string {
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
""",
    button,
    count=1,
)

button = re.sub(
    r"""function riskBandLabel\(
  probability: number \| null,
\): string \{
[\s\S]*?
\}
""",
    r"""function riskBandLabel(
  probability: number | null,
): string {
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
""",
    button,
    count=1,
)

button = button.replace(
    "className={`${styles.gauge} ${gaugeClass(highestAttackProbability)}`}",
    "className={`${styles.gauge} ${gaugeClass(percentileAsProbabilityScale(cyrpDisplayHighestPercentile))}`}",
)

device_button.write_text(button, encoding="utf-8")

# 4. CSS phụ cho modal nếu class gauge dùng biến màu.
if device_css.exists():
    dcss = device_css.read_text(encoding="utf-8")

    dcss_patch = r"""

/* CYRP patch: gauge percentile color bands */
.gaugeLow {
  --gauge-accent: #22c55e;
  --gauge-color: #22c55e;
}

.gaugeMedium {
  --gauge-accent: #facc15;
  --gauge-color: #facc15;
}

.gaugeHigh {
  --gauge-accent: #fb923c;
  --gauge-color: #fb923c;
}

.gaugeCritical {
  --gauge-accent: #ef4444;
  --gauge-color: #ef4444;
}
"""

    if "CYRP patch: gauge percentile color bands" not in dcss:
        dcss = dcss.rstrip() + dcss_patch + "\n"

    device_css.write_text(dcss, encoding="utf-8")

print("DONE: patched percentile color bands")
print("Expected bands: LOW <45, MEDIUM 45-65, HIGH 65-85, CRITICAL >=85")
