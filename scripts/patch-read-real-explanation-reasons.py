from pathlib import Path
from datetime import datetime
import shutil
import re

path = Path(r"D:\LuanVan\test\cyrp-platform-phase2\apps\user-web\src\app\ai-predictions\[id]\ai-prediction-detail-client.tsx")

if not path.exists():
    raise SystemExit(f"Không tìm thấy file: {path}")

backup = path.with_suffix(path.suffix + ".bak-read-real-explanation-reasons-" + datetime.now().strftime("%Y%m%d-%H%M%S"))
shutil.copy2(path, backup)

text = path.read_text(encoding="utf-8")

# 1. Thay hoặc chèn helper đọc đúng aiPrediction.explanation.reasons / rawModelOutput.Reasons.
helper = """function getAiCvssReasonValue(source: unknown, featureName: string): unknown {
  const candidates = [
    getValue(source, ['aiPrediction', 'explanation', 'reasons']),
    getValue(source, ['aiPrediction', 'explanation', 'Reasons']),
    getValue(source, ['aiPrediction', 'explanation', 'rawModelOutput', 'Reasons']),
    getValue(source, ['aiPrediction', 'explanation', 'rawModelOutput', 'reasons']),
    getValue(source, ['aiPrediction', 'explanation', 'modelDetails', 'reasons']),
    getValue(source, ['aiPrediction', 'explanation', 'modelDetails', 'rawPrediction', 'Reasons']),
    getValue(source, ['aiPrediction', 'explanation', 'rawPrediction', 'Reasons']),
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

start = text.find("function getAiCvssReasonValue")
if start >= 0:
    end = text.find("function formatDateTime", start)
    if end < 0:
        raise SystemExit("Tìm thấy getAiCvssReasonValue nhưng không tìm thấy formatDateTime để thay helper.")
    text = text[:start] + helper + text[end:]
else:
    marker = "function formatDateTime(value: unknown): string {"
    if marker not in text:
        raise SystemExit("Không tìm thấy vị trí chèn helper trước formatDateTime.")
    text = text.replace(marker, helper + marker, 1)

# 2. Sửa formatScore: không có hoặc số âm thì N/A.
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

# 3. Ghi lại block CVSS/AI sạch, KHÔNG thêm dòng Vector nữa.
block_start = text.find("  const cvssBaseScore =")
block_end_marker = "  const firstSeen ="
block_end = text.find(block_end_marker)

if block_start < 0:
    raise SystemExit("Không tìm thấy const cvssBaseScore.")

if block_end < 0:
    raise SystemExit("Không tìm thấy const firstSeen.")

if block_end <= block_start:
    raise SystemExit("Vị trí const firstSeen không hợp lệ.")

clean_block = """  const cvssBaseScore =
    getNumber(item, [
      ['cve', 'cvssMetrics', '0', 'baseScore'],
      ['cvssBaseScore'],
      ['featureVector', 'baseScore'],
      ['aiPrediction', 'explanation', 'rawModelOutput', 'CVSS_base_score'],
    ]) ?? getAiCvssReasonNumber(item, 'CVSS_base_score');

  const cvssVersion =
    getString(item, [
      ['cve', 'cvssMetrics', '0', 'cvssVersion'],
      ['cve', 'cvssMetrics', '0', 'version'],
      ['aiPrediction', 'explanation', 'rawModelOutput', 'CVSS_cvss_version'],
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
      ['aiPrediction', 'explanation', 'rawModelOutput', 'Percentile'],
    ]);

  const probability =
    getNumber(item, [
      ['aiPrediction', 'attackProbability'],
      ['aiPrediction', 'explanation', 'probability'],
      ['aiPrediction', 'explanation', 'rawModelOutput', 'Probability'],
    ]);

  const riskLevel = normalizeRiskLevel(getString(item, [['aiPrediction', 'riskLevel']]));
  const modelVersion = getString(item, [['aiPrediction', 'modelVersion']]) ?? '—';
  const predictedAt = getString(item, [['aiPrediction', 'predictedAt']]);

  const description =
    getString(item, [
      ['cve', 'description'],
      ['description'],
      ['aiPrediction', 'explanation', 'remediation', 'cve_description'],
      ['aiPrediction', 'explanation', 'rawModelOutput', 'Remediation', 'cve_description'],
    ]) ?? 'Chưa có mô tả CVE.';

  const cvssAttackVector =
    getString(item, [
      ['cve', 'cvssMetrics', '0', 'attackVector'],
      ['featureVector', 'attackVector'],
      ['featureVector', 'rawFeatures', 'attackVector'],
    ]) ?? getAiCvssReasonString(item, 'CVSS_attack_vector') ?? '—';

  const cvssAttackComplexity =
    getString(item, [
      ['cve', 'cvssMetrics', '0', 'attackComplexity'],
      ['featureVector', 'attackComplexity'],
      ['featureVector', 'rawFeatures', 'attackComplexity'],
    ]) ?? getAiCvssReasonString(item, 'CVSS_attack_complexity') ?? '—';

  const cvssPrivilegesRequired =
    getString(item, [
      ['cve', 'cvssMetrics', '0', 'privilegesRequired'],
      ['featureVector', 'privilegesRequired'],
      ['featureVector', 'rawFeatures', 'privilegesRequired'],
    ]) ?? getAiCvssReasonString(item, 'CVSS_privileges_required') ?? '—';

  const cvssUserInteraction =
    getString(item, [
      ['cve', 'cvssMetrics', '0', 'userInteraction'],
      ['featureVector', 'userInteraction'],
      ['featureVector', 'rawFeatures', 'userInteraction'],
    ]) ?? getAiCvssReasonString(item, 'CVSS_user_interaction') ?? '—';

  const cvssConfidentiality =
    getString(item, [
      ['cve', 'cvssMetrics', '0', 'confidentialityImpact'],
      ['featureVector', 'confidentialityImpact'],
      ['featureVector', 'rawFeatures', 'confidentialityImpact'],
    ]) ?? getAiCvssReasonString(item, 'CVSS_confidentiality') ?? '—';

  const cvssIntegrity =
    getString(item, [
      ['cve', 'cvssMetrics', '0', 'integrityImpact'],
      ['featureVector', 'integrityImpact'],
      ['featureVector', 'rawFeatures', 'integrityImpact'],
    ]) ?? getAiCvssReasonString(item, 'CVSS_integrity') ?? '—';

  const cvssAvailability =
    getString(item, [
      ['cve', 'cvssMetrics', '0', 'availabilityImpact'],
      ['featureVector', 'availabilityImpact'],
      ['featureVector', 'rawFeatures', 'availabilityImpact'],
    ]) ?? getAiCvssReasonString(item, 'CVSS_availability') ?? '—';

  const cvssCia = `${cvssConfidentiality} / ${cvssIntegrity} / ${cvssAvailability}`;

"""

text = text[:block_start] + clean_block + text[block_end:]

# 4. Sửa hint CVSS base score.
text = text.replace(
    "hint={`CVSS ${cvssVersion}`}",
    "hint={cvssVersionLabel}",
)

# 5. Xóa dòng Vector nếu còn.
text = re.sub(
    r"""\s*<KeyValueRow label="Vector" value=\{[\s\S]*?\} />\n""",
    "",
    text,
    count=1,
)

# 6. Ép render CVSS vector dùng biến mới.
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
print("aiPrediction.explanation.reasons path:", "['aiPrediction', 'explanation', 'reasons']" in text)
print("rawModelOutput.Reasons path:", "['aiPrediction', 'explanation', 'rawModelOutput', 'Reasons']" in text)
print("Vector row still exists:", '<KeyValueRow label=\"Vector\"' in text)
print("render cvssAttackVector:", 'value={cvssAttackVector}' in text)
