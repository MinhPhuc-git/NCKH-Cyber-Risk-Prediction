from pathlib import Path
from datetime import datetime
import shutil

path = Path(r"D:\LuanVan\test\cyrp-platform-phase2\apps\user-web\src\app\ai-predictions\[id]\ai-prediction-detail-client.tsx")

if not path.exists():
    raise SystemExit(f"Không tìm thấy file: {path}")

backup = path.with_suffix(path.suffix + ".bak-cvss-na-vector-paths-" + datetime.now().strftime("%Y%m%d-%H%M%S"))
shutil.copy2(path, backup)

text = path.read_text(encoding="utf-8")

old_format_score = """function formatScore(value: number | null): string {
  if (value === null || Number.isNaN(value)) {
    return '—';
  }

  return value.toFixed(1);
}"""

new_format_score = """function formatScore(value: number | null): string {
  if (value === null || Number.isNaN(value) || value < 0) {
    return 'N/A';
  }

  return value.toFixed(1);
}"""

if old_format_score not in text:
    raise SystemExit("Không tìm thấy function formatScore cũ.")

text = text.replace(old_format_score, new_format_score, 1)

old_cvss_version = """  const cvssVersion =
    getString(item, [['cve', 'cvssMetrics', '0', 'cvssVersion']]) ??
    getString(item, [['featureVector', 'severity']]) ??
    '—';"""

new_cvss_version = """  const cvssVersion =
    getString(item, [
      ['cve', 'cvssMetrics', '0', 'cvssVersion'],
      ['cve', 'cvssMetrics', '0', 'version'],
      ['rawPayload', 'vulnerability', 'cvss', 'version'],
      ['rawPayload', 'cvss', 'version'],
      ['raw_payload', 'vulnerability', 'cvss', 'version'],
      ['raw_payload', 'cvss', 'version'],
    ]) ?? 'N/A';

  const cvssVersionLabel =
    cvssVersion === 'N/A'
      ? 'CVSS version: N/A'
      : `CVSS ${cvssVersion}`;"""

if old_cvss_version not in text:
    raise SystemExit("Không tìm thấy block const cvssVersion cũ.")

text = text.replace(old_cvss_version, new_cvss_version, 1)

text = text.replace(
    "hint={`CVSS ${cvssVersion}`}",
    "hint={cvssVersionLabel}",
)

path.write_text(text, encoding="utf-8")

print("Patched:", path)
print("Backup:", backup)
