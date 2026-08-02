from pathlib import Path
from datetime import datetime
import shutil
import re

path = Path(r"D:\LuanVan\test\cyrp-platform-phase2\apps\user-web\src\components\device-analysis-button.tsx")

if not path.exists():
    raise SystemExit(f"Không tìm thấy file: {path}")

backup = path.with_suffix(path.suffix + ".bak-fix-cyrp-percentile-gauge-class-" + datetime.now().strftime("%Y%m%d-%H%M%S"))
shutil.copy2(path, backup)

text = path.read_text(encoding="utf-8")

pattern = r"""function cyrpPercentileGaugeClass\(value: number \| null \| undefined\): string \{
[\s\S]*?
\}
"""

replacement = """function cyrpPercentileGaugeClass(value: number | null | undefined): string {
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    return styles.gaugeNeutral;
  }

  const percent = value <= 1 ? value * 100 : value;

  if (percent >= 85) {
    return styles.gaugeCritical;
  }

  if (percent >= 65) {
    return styles.gaugeHigh;
  }

  if (percent >= 45) {
    return styles.gaugeMedium;
  }

  return styles.gaugeLow;
}
"""

new_text, count = re.subn(pattern, replacement, text, count=1)

if count != 1:
    raise SystemExit("Không thay được hàm cyrpPercentileGaugeClass. Cần kiểm tra lại file.")

path.write_text(new_text, encoding="utf-8")

print("Patched:", path)
print("Backup:", backup)
print("Replaced:", count)
