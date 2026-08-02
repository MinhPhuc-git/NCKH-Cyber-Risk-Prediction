from pathlib import Path
from datetime import datetime
import shutil
import re

path = Path(r"D:\LuanVan\test\cyrp-platform-phase2\apps\user-web\src\app\ai-predictions\[id]\ai-prediction-detail-client.tsx")

if not path.exists():
    raise SystemExit(f"Không tìm thấy file: {path}")

backup = path.with_suffix(path.suffix + ".bak-display-cvss-from-raw-reasons-" + datetime.now().strftime("%Y%m%d-%H%M%S"))
shutil.copy2(path, backup)

text = path.read_text(encoding="utf-8")

# 1. Thêm helper đọc rawPayload.rawPrediction.Reasons nếu chưa có.
marker = """function formatDateTime(value: unknown): string {"""

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
    if marker not in text:
        raise SystemExit("Không tìm thấy vị trí chèn helper trước formatDateTime.")
    text = text.replace(marker, helpers + marker, 1)

# 2. Sửa formatScore: null hoặc số âm thì hiện N/A.
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

# 3. Thay block CVSS base score + version bằng bản có fallback từ rawPrediction.Reasons.
text = re.sub(
    r"""  const cvssBaseScore =
[\s\S]*?
  const cvssVersion =
[\s\S]*?
    '.*?';

""",
    """  const cvssBaseScore =
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

  const cvssVersionLabel =
    cvssVersion === 'N/A'
      ? 'CVSS version: N/A'
      : `CVSS ${cvssVersion}`;

""",
    text,
    count=1,
)

# 4. Sửa hint card CVSS để dùng cvssVersionLabel.
text = text.replace(
    "hint={`CVSS ${cvssVersion}`}",
    "hint={cvssVersionLabel}",
)

# 5. Xóa block biến CVSS vector cũ nếu đã có, rồi chèn block mới trước firstSeen.
text = re.sub(
    r"""  const cvssVector =
[\s\S]*?
  const cvssCia = [^\n]*;

""",
    "",
    text,
    count=1,
)

insert_marker = "  const firstSeen = getString(item, [['firstSeenAt']]);"

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

if insert_marker not in text:
    raise SystemExit("Không tìm thấy vị trí chèn biến CVSS trước firstSeen.")

text = text.replace(insert_marker, vector_block + insert_marker, 1)

# 6. Bảo đảm phần render CVSS vector dùng biến mới.
render_replacements = {
    """<KeyValueRow label="Vector" value={getString(item, [['featureVector', 'vector']]) ?? '—'} />""":
    """<KeyValueRow label="Vector" value={cvssVector} />""",

    """<KeyValueRow label="Attack vector" value={getString(item, [['featureVector', 'attackVector']]) ?? '—'} />""":
    """<KeyValueRow label="Attack vector" value={cvssAttackVector} />""",

    """<KeyValueRow label="Attack complexity" value={getString(item, [['featureVector', 'attackComplexity']]) ?? '—'} />""":
    """<KeyValueRow label="Attack complexity" value={cvssAttackComplexity} />""",

    """<KeyValueRow label="Privileges required" value={getString(item, [['featureVector', 'privilegesRequired']]) ?? '—'} />""":
    """<KeyValueRow label="Privileges required" value={cvssPrivilegesRequired} />""",

    """<KeyValueRow label="User interaction" value={getString(item, [['featureVector', 'userInteraction']]) ?? '—'} />""":
    """<KeyValueRow label="User interaction" value={cvssUserInteraction} />""",
}

for old, new in render_replacements.items():
    text = text.replace(old, new)

# Nếu file đã có biến cvss từ patch trước, vẫn ép render sang biến đúng.
text = text.replace("""<KeyValueRow label="Vector" value={cvssVector} />""", """<KeyValueRow label="Vector" value={cvssVector} />""")
text = text.replace("""<KeyValueRow label="Attack vector" value={cvssAttackVector} />""", """<KeyValueRow label="Attack vector" value={cvssAttackVector} />""")
text = text.replace("""<KeyValueRow label="Attack complexity" value={cvssAttackComplexity} />""", """<KeyValueRow label="Attack complexity" value={cvssAttackComplexity} />""")
text = text.replace("""<KeyValueRow label="Privileges required" value={cvssPrivilegesRequired} />""", """<KeyValueRow label="Privileges required" value={cvssPrivilegesRequired} />""")
text = text.replace("""<KeyValueRow label="User interaction" value={cvssUserInteraction} />""", """<KeyValueRow label="User interaction" value={cvssUserInteraction} />""")

text = re.sub(
    r"""<KeyValueRow
\s+label="C / I / A"
\s+value=\{`[\s\S]*?`\}
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
