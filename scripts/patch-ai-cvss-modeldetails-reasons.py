from pathlib import Path
from datetime import datetime
import shutil
import re

path = Path(r"D:\LuanVan\test\cyrp-platform-phase2\apps\user-web\src\app\ai-predictions\[id]\ai-prediction-detail-client.tsx")

if not path.exists():
    raise SystemExit(f"Không tìm thấy file: {path}")

backup = path.with_suffix(path.suffix + ".bak-ai-cvss-modeldetails-reasons-" + datetime.now().strftime("%Y%m%d-%H%M%S"))
shutil.copy2(path, backup)

text = path.read_text(encoding="utf-8")

# 1. Thêm helper riêng, tránh đụng helper cũ.
marker = "function formatDateTime(value: unknown): string {"

helper = """function getAiCvssReasonValue(source: unknown, featureName: string): unknown {
  const candidates = [
    getValue(source, ['aiPrediction', 'explanation', 'modelDetails', 'reasons']),
    getValue(source, ['aiPrediction', 'explanation', 'modelDetails', 'rawPrediction', 'Reasons']),
    getValue(source, ['aiPrediction', 'explanation', 'modelDetails', 'rawPrediction', 'reasons']),
    getValue(source, ['aiPrediction', 'explanation', 'rawPrediction', 'Reasons']),
    getValue(source, ['aiPrediction', 'explanation', 'rawPrediction', 'reasons']),
    getValue(source, ['aiPrediction', 'explanation', 'Reasons']),
    getValue(source, ['aiPrediction', 'explanation', 'reasons']),
    getValue(source, ['rawPayload', 'rawPrediction', 'Reasons']),
    getValue(source, ['raw_payload', 'rawPrediction', 'Reasons']),
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

function getAiCvssReasonString(source: unknown, featureName: string): string | null {
  const value = getAiCvssReasonValue(source, featureName);

  if (typeof value === 'string' && value.trim()) {
    return value.trim();
  }

  if (typeof value === 'number' && Number.isFinite(value)) {
    return String(value);
  }

  return null;
}

function getAiCvssReasonNumber(source: unknown, featureName: string): number | null {
  const value = getAiCvssReasonValue(source, featureName);

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

if "function getAiCvssReasonValue" not in text:
    if marker not in text:
        raise SystemExit("Không tìm thấy vị trí chèn helper trước formatDateTime.")
    text = text.replace(marker, helper + marker, 1)

# 2. Sửa formatScore: không có hoặc âm thì N/A.
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

# 3. Ghi lại block CVSS/AI sạch từ cvssBaseScore đến trước firstSeen.
start = text.find("  const cvssBaseScore =")
end_marker = "  const firstSeen ="
end = text.find(end_marker)

if start < 0:
    raise SystemExit("Không tìm thấy const cvssBaseScore.")

if end < 0:
    raise SystemExit("Không tìm thấy const firstSeen.")

if end <= start:
    raise SystemExit("Vị trí firstSeen không hợp lệ.")

block = """  const cvssBaseScore =
    getNumber(item, [
      ['cvssBaseScore'],
      ['featureVector', 'baseScore'],
      ['cve', 'cvssMetrics', '0', 'baseScore'],
      ['aiPrediction', 'explanation', 'baseScore'],
      ['aiPrediction', 'explanation', 'input', 'base_score'],
    ]) ?? getAiCvssReasonNumber(item, 'CVSS_base_score');

  const cvssVersion =
    getString(item, [
      ['cve', 'cvssMetrics', '0', 'cvssVersion'],
      ['cve', 'cvssMetrics', '0', 'version'],
      ['aiPrediction', 'explanation', 'input', 'cvss_version'],
    ]) ?? getAiCvssReasonString(item, 'CVSS_cvss_version') ?? 'N/A';

  const cvssVersionLabel =
    cvssVersion === 'N/A'
      ? 'CVSS version: N/A'
      : `CVSS ${cvssVersion}`;

  const percentile =
    getNumber(item, [
      ['aiPrediction', 'predictedPercentile'],
      ['aiPrediction', 'explanation', 'predictedPercentile'],
      ['aiPrediction', 'explanation', 'predicted_percentile'],
      ['aiPrediction', 'explanation', 'modelDetails', 'rawPrediction', 'Percentile'],
    ]);

  const probability =
    getNumber(item, [
      ['aiPrediction', 'attackProbability'],
      ['aiPrediction', 'explanation', 'Probability'],
      ['aiPrediction', 'explanation', 'modelDetails', 'rawPrediction', 'Probability'],
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
      ['featureVector', 'rawFeatures', 'attackVector'],
      ['cve', 'cvssMetrics', '0', 'attackVector'],
      ['aiPrediction', 'explanation', 'input', 'av_label'],
    ]) ?? getAiCvssReasonString(item, 'CVSS_attack_vector') ?? '—';

  const cvssAttackComplexity =
    getString(item, [
      ['featureVector', 'attackComplexity'],
      ['featureVector', 'rawFeatures', 'attackComplexity'],
      ['cve', 'cvssMetrics', '0', 'attackComplexity'],
      ['aiPrediction', 'explanation', 'input', 'ac_label'],
    ]) ?? getAiCvssReasonString(item, 'CVSS_attack_complexity') ?? '—';

  const cvssPrivilegesRequired =
    getString(item, [
      ['featureVector', 'privilegesRequired'],
      ['featureVector', 'rawFeatures', 'privilegesRequired'],
      ['cve', 'cvssMetrics', '0', 'privilegesRequired'],
      ['aiPrediction', 'explanation', 'input', 'pr_label'],
    ]) ?? getAiCvssReasonString(item, 'CVSS_privileges_required') ?? '—';

  const cvssUserInteraction =
    getString(item, [
      ['featureVector', 'userInteraction'],
      ['featureVector', 'rawFeatures', 'userInteraction'],
      ['cve', 'cvssMetrics', '0', 'userInteraction'],
      ['aiPrediction', 'explanation', 'input', 'ui_label'],
    ]) ?? getAiCvssReasonString(item, 'CVSS_user_interaction') ?? '—';

  const cvssConfidentiality =
    getString(item, [
      ['featureVector', 'confidentialityImpact'],
      ['featureVector', 'rawFeatures', 'confidentialityImpact'],
      ['cve', 'cvssMetrics', '0', 'confidentialityImpact'],
      ['aiPrediction', 'explanation', 'input', 'c_label'],
    ]) ?? getAiCvssReasonString(item, 'CVSS_confidentiality') ?? '—';

  const cvssIntegrity =
    getString(item, [
      ['featureVector', 'integrityImpact'],
      ['featureVector', 'rawFeatures', 'integrityImpact'],
      ['cve', 'cvssMetrics', '0', 'integrityImpact'],
      ['aiPrediction', 'explanation', 'input', 'i_label'],
    ]) ?? getAiCvssReasonString(item, 'CVSS_integrity') ?? '—';

  const cvssAvailability =
    getString(item, [
      ['featureVector', 'availabilityImpact'],
      ['featureVector', 'rawFeatures', 'availabilityImpact'],
      ['cve', 'cvssMetrics', '0', 'availabilityImpact'],
      ['aiPrediction', 'explanation', 'input', 'a_label'],
    ]) ?? getAiCvssReasonString(item, 'CVSS_availability') ?? '—';

  const cvssCia = `${cvssConfidentiality} / ${cvssIntegrity} / ${cvssAvailability}`;

"""

text = text[:start] + block + text[end:]

# 4. Đảm bảo card CVSS dùng version label.
text = text.replace(
    "hint={`CVSS ${cvssVersion}`}",
    "hint={cvssVersionLabel}",
)

# 5. Đảm bảo render CVSS vector dùng biến mới.
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
print("getAiCvssReasonValue count:", text.count("function getAiCvssReasonValue"))
print("modelDetails.rawPrediction.Reasons path:", "modelDetails', 'rawPrediction', 'Reasons" in text)
print("cvssAttackVector render:", "value={cvssAttackVector}" in text)
