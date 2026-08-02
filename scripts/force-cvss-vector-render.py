from pathlib import Path
from datetime import datetime
import shutil
import re

path = Path(r"D:\LuanVan\test\cyrp-platform-phase2\apps\user-web\src\app\ai-predictions\[id]\ai-prediction-detail-client.tsx")

if not path.exists():
    raise SystemExit(f"Không tìm thấy file: {path}")

backup = path.with_suffix(path.suffix + ".bak-force-cvss-vector-render-" + datetime.now().strftime("%Y%m%d-%H%M%S"))
shutil.copy2(path, backup)

text = path.read_text(encoding="utf-8")

# 1. Thêm helper đọc Reasons nếu chưa có.
if "function getReasonValue" not in text:
    marker = "function externalLinks"

    if marker not in text:
        marker = "function KeyValueRow"

    if marker not in text:
        raise SystemExit("Không tìm thấy vị trí chèn helper getReasonValue.")

    helper = """function getReasonValue(source: unknown, featureName: string): unknown {
  const candidates = [
    getValue(source, ['aiPrediction', 'explanation', 'Reasons']),
    getValue(source, ['aiPrediction', 'explanation', 'reasons']),
    getValue(source, ['rawPayload', 'rawPrediction', 'Reasons']),
    getValue(source, ['raw_payload', 'rawPrediction', 'Reasons']),
    getValue(source, ['rawPrediction', 'Reasons']),
  ];

  for (const candidate of candidates) {
    if (!Array.isArray(candidate)) {
      continue;
    }

    const found = candidate.find((entry) => {
      const record = asRecord(entry);
      return record.feature === featureName;
    });

    if (found) {
      return asRecord(found).value;
    }
  }

  return null;
}

function getReasonString(source: unknown, featureName: string): string | null {
  const value = getReasonValue(source, featureName);

  if (typeof value === 'string' && value.trim()) {
    return value.trim();
  }

  if (typeof value === 'number' && Number.isFinite(value)) {
    return String(value);
  }

  return null;
}

function getReasonNumber(source: unknown, featureName: string): number | null {
  const value = getReasonValue(source, featureName);

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
    text = text.replace(marker, helper + marker, 1)

# 2. Sửa formatScore để không hiện -1.0.
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

# 3. Chèn hoặc thay block biến CVSS chính.
start = text.find("  const cvssBaseScore =")
end_marker = "  const firstSeen ="
end = text.find(end_marker)

if start < 0:
    raise SystemExit("Không tìm thấy const cvssBaseScore.")

if end < 0:
    raise SystemExit("Không tìm thấy const firstSeen.")

if end <= start:
    raise SystemExit("Vị trí const firstSeen không hợp lệ. Cần gửi file hiện tại.")

block = """  const cvssBaseScore =
    getNumber(item, [
      ['cvssBaseScore'],
      ['featureVector', 'baseScore'],
      ['cve', 'cvssMetrics', '0', 'baseScore'],
    ]) ?? getReasonNumber(item, 'CVSS_base_score');

  const cvssVersion =
    getString(item, [
      ['cve', 'cvssMetrics', '0', 'cvssVersion'],
      ['cve', 'cvssMetrics', '0', 'version'],
    ]) ?? getReasonString(item, 'CVSS_cvss_version') ?? 'N/A';

  const cvssVersionLabel =
    cvssVersion === 'N/A'
      ? 'CVSS version: N/A'
      : `CVSS ${cvssVersion}`;

  const percentile =
    getNumber(item, [
      ['aiPrediction', 'predictedPercentile'],
      ['aiPrediction', 'explanation', 'Percentile'],
    ]);

  const probability =
    getNumber(item, [
      ['aiPrediction', 'attackProbability'],
      ['aiPrediction', 'explanation', 'Probability'],
    ]);

  const riskLevel = normalizeRiskLevel(getString(item, [['aiPrediction', 'riskLevel']]));
  const modelVersion = getString(item, [['aiPrediction', 'modelVersion']]) ?? '—';
  const predictedAt = getString(item, [['aiPrediction', 'predictedAt']]);

  const description =
    getString(item, [['cve', 'description'], ['description']]) ??
    'Chưa có mô tả CVE.';

  const cvssVector =
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
    ]) ?? getReasonString(item, 'CVSS_attack_vector') ?? '—';

  const cvssAttackComplexity =
    getString(item, [
      ['featureVector', 'attackComplexity'],
      ['cve', 'cvssMetrics', '0', 'attackComplexity'],
    ]) ?? getReasonString(item, 'CVSS_attack_complexity') ?? '—';

  const cvssPrivilegesRequired =
    getString(item, [
      ['featureVector', 'privilegesRequired'],
      ['cve', 'cvssMetrics', '0', 'privilegesRequired'],
    ]) ?? getReasonString(item, 'CVSS_privileges_required') ?? '—';

  const cvssUserInteraction =
    getString(item, [
      ['featureVector', 'userInteraction'],
      ['cve', 'cvssMetrics', '0', 'userInteraction'],
    ]) ?? getReasonString(item, 'CVSS_user_interaction') ?? '—';

  const cvssConfidentiality =
    getString(item, [
      ['featureVector', 'confidentialityImpact'],
      ['cve', 'cvssMetrics', '0', 'confidentialityImpact'],
    ]) ?? getReasonString(item, 'CVSS_confidentiality') ?? '—';

  const cvssIntegrity =
    getString(item, [
      ['featureVector', 'integrityImpact'],
      ['cve', 'cvssMetrics', '0', 'integrityImpact'],
    ]) ?? getReasonString(item, 'CVSS_integrity') ?? '—';

  const cvssAvailability =
    getString(item, [
      ['featureVector', 'availabilityImpact'],
      ['cve', 'cvssMetrics', '0', 'availabilityImpact'],
    ]) ?? getReasonString(item, 'CVSS_availability') ?? '—';

  const cvssCia = `${cvssConfidentiality} / ${cvssIntegrity} / ${cvssAvailability}`;

"""

text = text[:start] + block + text[end:]

# 4. Bảo đảm card CVSS base score dùng label version mới.
text = text.replace(
    "hint={`CVSS ${cvssVersion}`}",
    "hint={cvssVersionLabel}",
)

# 5. Ép panel CVSS vector render từ biến mới.
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
print("getReasonValue count:", text.count("function getReasonValue"))
print("cvssAttackVector count:", text.count("const cvssAttackVector"))
print("CVSS_attack_vector count:", text.count("CVSS_attack_vector"))
print("render cvssAttackVector count:", text.count("value={cvssAttackVector}"))
