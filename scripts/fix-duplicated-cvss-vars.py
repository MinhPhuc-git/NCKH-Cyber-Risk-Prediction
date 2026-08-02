from pathlib import Path
from datetime import datetime
import shutil
import re

path = Path(r"D:\LuanVan\test\cyrp-platform-phase2\apps\user-web\src\app\ai-predictions\[id]\ai-prediction-detail-client.tsx")

if not path.exists():
    raise SystemExit(f"Không tìm thấy file: {path}")

backup = path.with_suffix(path.suffix + ".bak-fix-duplicated-cvss-vars-" + datetime.now().strftime("%Y%m%d-%H%M%S"))
shutil.copy2(path, backup)

text = path.read_text(encoding="utf-8")

# 1. Đảm bảo helper đọc rawPayload.rawPrediction.Reasons tồn tại.
helper_marker = "function formatDateTime(value: unknown): string {"

helpers = """function getRawPredictionReasonValue(source: unknown, featureName: string): unknown {
  const reasons =
    getValue(source, ['rawPayload', 'rawPrediction', 'Reasons']) ??
    getValue(source, ['raw_payload', 'rawPrediction', 'Reasons']) ??
    getValue(source, ['rawPrediction', 'Reasons']) ??
    getValue(source, ['aiPrediction', 'explanation', 'Reasons']);

  if (!Array.isArray(reasons)) {
    return null;
  }

  const found = reasons.find((item) => {
    const record = asRecord(item);
    return record.feature === featureName;
  });

  return found ? asRecord(found).value : null;
}

function getRawPredictionReasonString(source: unknown, featureName: string): string | null {
  const value = getRawPredictionReasonValue(source, featureName);

  if (typeof value === 'string' && value.trim()) {
    return value.trim();
  }

  if (typeof value === 'number' && Number.isFinite(value)) {
    return String(value);
  }

  return null;
}

function getRawPredictionReasonNumber(source: unknown, featureName: string): number | null {
  const value = getRawPredictionReasonValue(source, featureName);

  if (typeof value === 'number' && Number.isFinite(value)) {
    return value;
  }

  if (typeof value === 'string' && value.trim()) {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : null;
  }

  return null;
}

"""

if "function getRawPredictionReasonValue" not in text:
    if helper_marker not in text:
        raise SystemExit("Không tìm thấy vị trí chèn helper.")
    text = text.replace(helper_marker, helpers + helper_marker, 1)

# 2. Sửa formatScore: null, NaN, số âm => N/A.
text = re.sub(
    r"""function formatScore\(value: number \| null\): string \{
[\s\S]*?
\}
""",
    """function formatScore(value: number | null): string {
  if (value === null || Number.isNaN(value) || value < 0) {
    return 'N/A';
  }

  return value.toFixed(1);
}
""",
    text,
    count=1,
)

# 3. Chuẩn hóa block CVSS base score + version.
score_start = text.find("  const cvssBaseScore =")
percentile_marker = "  const percentile ="

if score_start < 0:
    raise SystemExit("Không tìm thấy const cvssBaseScore.")

score_end = text.find(percentile_marker, score_start)

if score_end < 0:
    raise SystemExit("Không tìm thấy const percentile sau cvssBaseScore.")

score_block = """  const cvssBaseScore =
    getNumber(item, [
      ['cvssBaseScore'],
      ['featureVector', 'baseScore'],
      ['cve', 'cvssMetrics', '0', 'baseScore'],
    ]) ?? getRawPredictionReasonNumber(item, 'CVSS_base_score');

  const cvssVersion =
    getString(item, [
      ['cve', 'cvssMetrics', '0', 'cvssVersion'],
      ['cve', 'cvssMetrics', '0', 'version'],
      ['rawPayload', 'vulnerability', 'cvss', 'version'],
      ['raw_payload', 'vulnerability', 'cvss', 'version'],
    ]) ?? getRawPredictionReasonString(item, 'CVSS_cvss_version') ?? 'N/A';

 cvss', 'version'],
    ]) ?? getRawPredictionReasonString(item, 'CVSS_cvss_version') ?? 'N/A';

  const cvssVersionLabel =
    cvssVersion === 'N/A'
      ? 'CVSS version: N/A'
      : `CVSS ${cvssVersion}`;

"""

text = text[:score_start] + score_block + text[score_end:]

# 4. Xóa mọi block CVSS vector bị trùng từ const cvssVector đến trước const firstSeen.
first_seen_marker = "  const firstSeen ="
vector_start = text.find("  const cvssVector =")
first_seen = text.find(first_seen_marker)

if first_seen < 0:
    raise SystemExit("Không tìm thấy const firstSeen.")

vector_block = """  const cvssVector =
    getString(item, [
      ['featureVector', 'vector'],
      ['featureVector', 'vectorString'],
      ['cve', 'cvssMetrics', '0', 'vectorString'],
      ['cve', 'cvssMetrics', '0', 'cvssVector'],
    ]) ?? '—';

  const cvssAttackVector =
    getString(item, [
      ['featureVector', 'attackVector'],
      ['cve', 'cvssMetrics', '0', 'attackVector'],
    ]) ?? getRawPredictionReasonString(item, 'CVSS_attack_vector') ?? '—';

  const cvssAttackComplexity =
    getString(item, [
      ['featureVector', 'attackComplexity'],
      ['cve', 'cvssMetrics', '0', 'attackComplexity'],
    ]) ?? getRawPredictionReasonString(item, 'CVSS_attack_complexity') ?? '—';

  const cvssPrivilegesRequired =
    getString(item, [
      ['featureVector', 'privilegesRequired'],
      ['cve', 'cvssMetrics', '0', 'privilegesRequired'],
    ]) ?? getRawPredictionReasonString(item, 'CVSS_privileges_required') ?? '—';

  const cvssUserInteraction =
    getString(item, [
      ['featureVector', 'userInteraction'],
      ['cve', 'cvssMetrics', '0', 'userInteraction'],
    ]) ?? getRawPredictionReasonString(item, 'CVSS_user_interaction') ?? '—';

  const cvssConfidentiality =
    getString(item, [
      ['featureVector', 'confidentialityImpact'],
      ['cve', 'cvssMetrics', '0', 'confidentialityImpact'],
    ]) ?? getRawPredictionReasonString(item, 'CVSS_confidentiality') ?? '—';

  const cvssIntegrity =
    getString(item, [
      ['featureVector', 'integrityImpact'],
      ['cve', 'cvssMetrics', '0', 'integrityImpact'],
    ]) ?? getRawPredictionReasonString(item, 'CVSS_integrity') ?? '—';

  const cvssAvailability =
    getString(item, [
      ['featureVector', 'availabilityImpact'],
      ['cve', 'cvssMetrics', '0', 'availabilityImpact'],
    ]) ?? getRawPredictionReasonString(item, 'CVSS_availability') ?? '—';

  const cvssCia = `${cvssConfidentiality} / ${cvssIntegrity} / ${cvssAvailability}`;

"""

if vector_start >= 0 and vector_start < first_seen:
    text = text[:vector_start] + vector_block + text[first_seen:]
else:
    text = text[:first_seen] + vector_block + text[first_seen:]

# 5. Đảm bảo card CVSS dùng cvssVersionLabel.
text = text.replace(
    "hint={`CVSS ${cvssVersion}`}",
    "hint={cvssVersionLabel}",
)

# 6. Đảm bảo render CVSS vector dùng biến duy nhất.
text = re.sub(
    r"""<KeyValueRow label="Vector" value=\{[\s\S]*?\} />""",
    """<KeyValueRow label="Vector" value={cvssVector} />""",
    text,
    count=1,
)

text = re.sub(
    r"""<KeyValueRow label="Attack vector" value=\{[\s\S]*?\} />""",
    """<KeyValueRow label="Attack vector" value={cvssAttackVector} />""",
    text,
    count=1,
)

text = re.sub(
    r"""<KeyValueRow label="Attack complexity" value=\{[\s\S]*?\} />""",
    """<KeyValueRow label="Attack complexity" value={cvssAttackComplexity} />""",
    text,
    count=1,
)

text = re.sub(
    r"""<KeyValueRow label="Privileges required" value=\{[\s\S]*?\} />""",
    """<KeyValueRow label="Privileges required" value={cvssPrivilegesRequired} />""",
    text,
    count=1,
)

text = re.sub(
    r"""<KeyValueRow label="User interaction" value=\{[\s\S]*?\} />""",
    """<KeyValueRow label="User interaction" value={cvssUserInteraction} />""",
    text,
    count=1,
)

text = re.sub(
    r"""<KeyValueRow
\s+label="C / I / A"
\s+value=\{[\s\S]*?\}
\s+/>""",
    """<KeyValueRow
              label="C / I / A"
              value={cvssCia}
            />""",
    text,
    count=1,
)

path.write_text(text, encoding="utf-8")

print("Patched:", path)
print("Backup:", backup)
print("cvssVector count:", text.count("const cvssVector"))
print("cvssAttackVector count:", text.count("const cvssAttackVector"))
print("cvssAttackComplexity count:", text.count("const cvssAttackComplexity"))
print("cvssPrivilegesRequired count:", text.count("const cvssPrivilegesRequired"))
print("cvssUserInteraction count:", text.count("const cvssUserInteraction"))
print("cvssCia count:", text.count("const cvssCia"))
