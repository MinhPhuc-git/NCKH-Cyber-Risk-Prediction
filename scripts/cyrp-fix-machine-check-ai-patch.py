from pathlib import Path
from datetime import datetime
import shutil
import re
import sys

ROOT = Path.cwd()
STAMP = datetime.now().strftime('%Y%m%d-%H%M%S')


def backup(path: Path) -> Path:
    if not path.exists():
        raise SystemExit(f'Không tìm thấy file: {path}')
    out = path.with_suffix(path.suffix + f'.bak-cyrp-fix-{STAMP}')
    shutil.copy2(path, out)
    return out


def read(path: Path) -> str:
    return path.read_text(encoding='utf-8')


def write(path: Path, text: str):
    path.write_text(text, encoding='utf-8')


def find_matching_brace(text: str, open_index: int) -> int:
    depth = 0
    quote = None
    escape = False
    line_comment = False
    block_comment = False
    i = open_index
    while i < len(text):
        ch = text[i]
        nxt = text[i + 1] if i + 1 < len(text) else ''
        if line_comment:
            if ch in '\r\n':
                line_comment = False
            i += 1
            continue
        if block_comment:
            if ch == '*' and nxt == '/':
                block_comment = False
                i += 2
                continue
            i += 1
            continue
        if quote:
            if escape:
                escape = False
            elif ch == '\\':
                escape = True
            elif ch == quote:
                quote = None
            i += 1
            continue
        if ch == '/' and nxt == '/':
            line_comment = True
            i += 2
            continue
        if ch == '/' and nxt == '*':
            block_comment = True
            i += 2
            continue
        if ch in ("'", '"', '`'):
            quote = ch
            i += 1
            continue
        if ch == '{':
            depth += 1
        elif ch == '}':
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


def replace_function(text: str, signature: str, replacement: str) -> str:
    start = text.find(signature)
    if start < 0:
        raise SystemExit(f'Không tìm thấy function signature: {signature}')
    open_brace = text.find('{', start)
    if open_brace < 0:
        raise SystemExit(f'Không tìm thấy dấu {{ sau: {signature}')
    close_brace = find_matching_brace(text, open_brace)
    if close_brace < 0:
        raise SystemExit(f'Không tìm thấy dấu }} đóng function: {signature}')
    end = close_brace + 1
    return text[:start] + replacement.rstrip() + text[end:]


def patch_importer():
    path = ROOT / 'apps/api/src/modules/security-data/ai-pipeline-data-user-import.service.ts'
    backup(path)
    text = read(path)

    old_start = text.find('    await this.database.cve.upsert({')
    old_end_marker = "    return { detection, created: true, reason: 'CREATED_DETECTED_VULNERABILITY' };"
    old_end = text.find(old_end_marker, old_start)
    if old_start < 0 or old_end < 0:
        print('[WARN] importer fallback block không tìm thấy hoặc đã được sửa trước đó')
    else:
        old_end = text.find('\n', old_end) + 1
        replacement = """    return {
      detection: null,
      created: false,
      reason:
        `WAZUH_VULNERABILITY_NOT_FOUND: Không tìm thấy detected_vulnerabilities từ Wazuh cho ${record.cveId}/agent=${agentId}. AI importer không tạo fallback ai-pipeline-data-user để tránh thiếu package/CVSS. Hãy chạy đồng bộ Wazuh vulnerabilities trước.`,
    };
"""
        text = text[:old_start] + replacement + text[old_end:]

    write(path, text)
    print('[OK] patched importer:', path)


def patch_delta():
    path = ROOT / 'apps/api/src/modules/security-data/cve-lifecycle-delta.service.ts'
    backup(path)
    text = read(path)
    old = """        const lastProcessedAt =
          row.aiPrediction?.predictedAt ??
          row.lastSeenAt ??
          row.firstSeenAt ??
          null;
"""
    new = """        const lastProcessedAt = row.aiPrediction?.predictedAt ?? null;
"""
    if old in text:
        text = text.replace(old, new, 1)
    elif 'const lastProcessedAt = row.aiPrediction?.predictedAt ?? null;' in text:
        print('[SKIP] delta lastProcessedAt đã được sửa')
    else:
        raise SystemExit('Không tìm thấy block lastProcessedAt trong cve-lifecycle-delta.service.ts')
    write(path, text)
    print('[OK] patched delta:', path)


def patch_security_data_sync():
    path = ROOT / 'apps/api/src/modules/security-data/security-data-sync.service.ts'
    backup(path)
    text = read(path)

    if 'reasons: this.cvssReasons(features, input),' not in text:
        text = text.replace(
            """        baseScore: features.baseScore,
        severity: features.severity,
        cweId: features.cweIdGrouped,
        input,
""",
            """        baseScore: features.baseScore,
        severity: features.severity,
        cweId: features.cweIdGrouped,
        reasons: this.cvssReasons(features, input),
        rawModelOutput: {
          Probability: attackProbability,
          Percentile: result.predictedPercentile,
          Reasons: this.cvssReasons(features, input),
        },
        input,
""",
            1,
        )

    if 'reasons: this.cvssReasons(features)' not in text:
        text = text.replace(
            """        maxRuleLevel24h: features.maxRuleLevel24h,
      },
    };
  }
""",
            """        maxRuleLevel24h: features.maxRuleLevel24h,
        reasons: this.cvssReasons(features),
      },
    };
  }
""",
            1,
        )

    if 'private cvssReasons(' not in text:
        helper = """

  private cvssReasons(
    features: CvePredictionFeatures,
    input?: AiModelRuntimeInput,
  ): Array<{ feature: string; value: string | number | boolean }> {
    const entries: Array<{ feature: string; value: string | number | boolean | null | undefined }> = [
      { feature: 'CVSS_cvss_version', value: input?.cvss_version ?? null },
      { feature: 'CVSS_base_score', value: features.baseScore },
      { feature: 'CVSS_attack_vector', value: features.attackVector },
      { feature: 'CVSS_attack_complexity', value: features.attackComplexity },
      { feature: 'CVSS_privileges_required', value: features.privilegesRequired },
      { feature: 'CVSS_user_interaction', value: features.userInteraction },
      { feature: 'CVSS_scope', value: features.scope },
      { feature: 'CVSS_confidentiality', value: features.confidentialityImpact },
      { feature: 'CVSS_integrity', value: features.integrityImpact },
      { feature: 'CVSS_availability', value: features.availabilityImpact },
      { feature: 'CVSS_exploitability_score', value: input?.exploitability_score ?? null },
      { feature: 'CVSS_impact_score', value: input?.impact_score ?? null },
    ];

    return entries.filter(
      (entry): entry is { feature: string; value: string | number | boolean } =>
        entry.value !== null && entry.value !== undefined && entry.value !== '',
    );
  }
"""
        marker = '  private cyrpIsRecord(value: unknown): value is Record<string, unknown> {'
        idx = text.find(marker)
        if idx < 0:
            raise SystemExit('Không tìm thấy vị trí chèn cvssReasons trong security-data-sync.service.ts')
        text = text[:idx] + helper + '\n' + text[idx:]

    # widen baselinePrediction type so helper can read full CVSS fields
    text = text.replace(
        """  private baselinePrediction(features: {
    severity: string | null;
    baseScore: number | null;
    epssScore: number | null;
    epssPercentile: number | null;
    isKnownExploited: boolean;
    maxRuleLevel24h: number | null;
  }): PersistedPrediction {
""",
        """  private baselinePrediction(features: CvePredictionFeatures): PersistedPrediction {
""",
    )

    write(path, text)
    print('[OK] patched security-data-sync:', path)


def patch_security_data_service():
    path = ROOT / 'apps/api/src/modules/security-data/security-data.service.ts'
    backup(path)
    text = read(path)

    # Add featureVector CVSS field types to the explicit structural type in mapVulnerability.
    map_start = text.find('  private mapVulnerability')
    map_end = text.find('  private async groupSeverity', map_start)
    if map_start < 0 or map_end < 0:
        raise SystemExit('Không tìm thấy mapVulnerability trong security-data.service.ts')

    feature_vector_start = text.find('    featureVector: {', map_start, map_end)
    ai_prediction_start = text.find('    aiPrediction:', feature_vector_start, map_end)
    feature_vector_block = text[feature_vector_start:ai_prediction_start]

    if 'attackVector: string | null;' not in feature_vector_block:
        local = feature_vector_block.replace(
            """      severity: string | null;
      epssScore: number | null;
""",
            """      severity: string | null;
      attackVector: string | null;
      attackComplexity: string | null;
      privilegesRequired: string | null;
      userInteraction: string | null;
      scope: string | null;
      confidentialityImpact: string | null;
      integrityImpact: string | null;
      availabilityImpact: string | null;
      epssScore: number | null;
""",
            1,
        )
        if local == feature_vector_block:
            raise SystemExit('Không chèn được các field CVSS vào featureVector type')
        text = text[:feature_vector_start] + local + text[ai_prediction_start:]

    if 'cvssVector:' not in text[text.find('  private mapVulnerability'):text.find('  private async groupSeverity')]:
        text = text.replace(
            """      cve: item.cve,
      featureVector: item.featureVector,
""",
            """      cve: item.cve,
      cvssVector: {
        vectorString: item.cve.cvssMetrics[0]?.vectorString ?? null,
        attackVector: item.featureVector?.attackVector ?? item.cve.cvssMetrics[0]?.attackVector ?? null,
        attackComplexity: item.featureVector?.attackComplexity ?? item.cve.cvssMetrics[0]?.attackComplexity ?? null,
        privilegesRequired: item.featureVector?.privilegesRequired ?? item.cve.cvssMetrics[0]?.privilegesRequired ?? null,
        userInteraction: item.featureVector?.userInteraction ?? item.cve.cvssMetrics[0]?.userInteraction ?? null,
        scope: item.featureVector?.scope ?? item.cve.cvssMetrics[0]?.scope ?? null,
        confidentialityImpact: item.featureVector?.confidentialityImpact ?? item.cve.cvssMetrics[0]?.confidentialityImpact ?? null,
        integrityImpact: item.featureVector?.integrityImpact ?? item.cve.cvssMetrics[0]?.integrityImpact ?? null,
        availabilityImpact: item.featureVector?.availabilityImpact ?? item.cve.cvssMetrics[0]?.availabilityImpact ?? null,
      },
      featureVector: item.featureVector,
""",
            1,
        )

    write(path, text)
    print('[OK] patched security-data.service:', path)


def patch_device_analysis_button():
    path = ROOT / 'apps/user-web/src/components/device-analysis-button.tsx'
    backup(path)
    text = read(path)

    new_load_ai = """  async function loadAiRiskSummary() {
    const distribution = {
      LOW: 0,
      MEDIUM: 0,
      HIGH: 0,
      CRITICAL: 0,
    };

    let loaded = 0;
    let total = 0;
    let highestAttackProbability: number | null = null;
    let highestPercentile: number | null = null;

    function normalizeRiskLevel(value: unknown): keyof typeof distribution | null {
      const level = String(value ?? '').trim().toUpperCase();

      if (level === 'LOW' || level === 'THẤP') return 'LOW';
      if (level === 'MEDIUM' || level === 'TRUNG BÌNH' || level === 'TRUNG_BINH') return 'MEDIUM';
      if (level === 'HIGH' || level === 'CAO') return 'HIGH';

      if (
        level === 'CRITICAL' ||
        level === 'VERY_HIGH' ||
        level === 'VERY HIGH' ||
        level === 'RẤT CAO' ||
        level === 'RAT CAO'
      ) {
        return 'CRITICAL';
      }

      return null;
    }

    function toNumber(value: unknown): number | null {
      if (typeof value === 'number' && Number.isFinite(value)) return value;

      if (typeof value === 'string' && value.trim()) {
        const parsed = Number(value);
        return Number.isFinite(parsed) ? parsed : null;
      }

      return null;
    }

    function percentileRiskLevel(value: unknown): keyof typeof distribution | null {
      const numberValue = toNumber(value);

      if (numberValue === null) {
        return null;
      }

      const percent = numberValue <= 1 ? numberValue * 100 : numberValue;

      if (percent >= 85) return 'CRITICAL';
      if (percent >= 65) return 'HIGH';
      if (percent >= 45) return 'MEDIUM';
      return 'LOW';
    }

    function asRecord(value: unknown): Record<string, unknown> {
      return value && typeof value === 'object' && !Array.isArray(value)
        ? (value as Record<string, unknown>)
        : {};
    }

    for (let pageNumber = 1; pageNumber <= 20; pageNumber += 1) {
      const params = new URLSearchParams({
        deviceId,
        status: 'ACTIVE',
        limit: '100',
        page: String(pageNumber),
      });

      const response = await fetch(`/api/vulnerabilities?${params.toString()}`, {
        method: 'GET',
        cache: 'no-store',
        credentials: 'same-origin',
      });

      if (!response.ok) break;

      const payload = await response.json().catch(() => null);
      const payloadRecord = asRecord(payload);
      const items = Array.isArray(payloadRecord.items)
        ? payloadRecord.items.filter(
            (item): item is Record<string, unknown> =>
              item !== null && typeof item === 'object' && !Array.isArray(item),
          )
        : [];

      if (pageNumber === 1) {
        total = toNumber(payloadRecord.total) ?? items.length;
      }

      for (const item of items) {
        const prediction = asRecord(item.aiPrediction);

        if (Object.keys(prediction).length === 0) {
          continue;
        }

        const percentile = toNumber(
          prediction.predictedPercentile ??
          prediction.predicted_percentile ??
          prediction.percentile,
        );
        const level = percentileRiskLevel(percentile) ?? normalizeRiskLevel(prediction.riskLevel);

        if (level) {
          distribution[level] += 1;
        }

        const attackProbability = toNumber(
          prediction.attackProbability ??
          prediction.attack_probability ??
          prediction.probability,
        );
        if (attackProbability !== null) {
          highestAttackProbability =
            highestAttackProbability === null
              ? attackProbability
              : Math.max(highestAttackProbability, attackProbability);
        }

        if (percentile !== null) {
          highestPercentile =
            highestPercentile === null
              ? percentile
              : Math.max(highestPercentile, percentile);
        }
      }

      loaded += items.length;

      if (items.length === 0 || loaded >= total) {
        break;
      }
    }

    const aiTotal = distribution.LOW + distribution.MEDIUM + distribution.HIGH + distribution.CRITICAL;

    setAiRiskSummary({
      total: aiTotal,
      loaded,
      distribution,
      highestAttackProbability,
      highestPercentile,
      calculatedAt: new Date().toISOString(),
    });
  }"""
    text = replace_function(text, '  async function loadAiRiskSummary()', new_load_ai)

    text = text.replace(
        """      const params = new URLSearchParams({
        page: String(pageNumber),
        limit: String(fetchLimit),
        status: 'ACTIVE',
      });
""",
        """      const params = new URLSearchParams({
        deviceId,
        page: String(pageNumber),
        limit: String(fetchLimit),
        status: 'ACTIVE',
      });
""",
        1,
    )

    text = text.replace(
        "CYRP đang đồng bộ Wazuh snapshot, lấy lỗ hổng active và chạy mô hình XGBoost để dự đoán nguy cơ khai thác.",
        "CYRP đang chạy AI trên dữ liệu Wazuh vulnerability đã đồng bộ để dự đoán nguy cơ khai thác.",
    )

    write(path, text)
    print('[OK] patched device-analysis-button:', path)


def patch_ai_predictions_client():
    path = ROOT / 'apps/user-web/src/app/ai-predictions/ai-predictions-client.tsx'
    backup(path)
    text = read(path)

    replacement = """function riskLevelFromPercentile(value: number | null): string | null {
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    return null;
  }

  const percent = value <= 1 ? value * 100 : value;

  if (percent >= 85) return 'CRITICAL';
  if (percent >= 65) return 'HIGH';
  if (percent >= 45) return 'MEDIUM';
  return 'LOW';
}

function riskLevel(item: VulnerabilityItem): string {
  return (
    riskLevelFromPercentile(predictionPercentile(item))
    ?? item.aiPrediction?.riskLevel
    ?? stringFromUnknown(predictionExplanation(item.aiPrediction?.explanation).risk_level)
    ?? stringFromUnknown(predictionExplanation(item.aiPrediction?.explanation).riskLevel)
    ?? 'UNKNOWN'
  ).toUpperCase();
}"""
    if 'function riskLevelFromPercentile(' in text:
        text = re.sub(r"function riskLevelFromPercentile\([\s\S]*?\n\}\n\nfunction riskLevel\(item: VulnerabilityItem\): string \{[\s\S]*?\n\}", replacement, text, count=1)
    else:
        text = replace_function(text, 'function riskLevel(item: VulnerabilityItem): string', replacement)

    write(path, text)
    print('[OK] patched ai-predictions-client:', path)


def patch_ai_prediction_detail_client():
    path = ROOT / 'apps/user-web/src/app/ai-predictions/[id]/ai-prediction-detail-client.tsx'
    backup(path)
    text = read(path)

    if 'function riskLevelFromPercentile(' not in text:
        helper = """
function riskLevelFromPercentile(value: number | null): string | null {
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    return null;
  }

  const percent = value <= 1 ? value * 100 : value;

  if (percent >= 85) return 'CRITICAL';
  if (percent >= 65) return 'HIGH';
  if (percent >= 45) return 'MEDIUM';
  return 'LOW';
}

function cvssVectorMetricLabel(vector: string | null, key: string): string | null {
  if (!vector) {
    return null;
  }

  const token = vector.split('/').find((part) => part.startsWith(`${key}:`));
  const code = token?.split(':')[1]?.trim().toUpperCase();

  const maps: Record<string, Record<string, string>> = {
    AV: { N: 'NETWORK', A: 'ADJACENT', L: 'LOCAL', P: 'PHYSICAL' },
    AC: { L: 'LOW', H: 'HIGH' },
    PR: { N: 'NONE', L: 'LOW', H: 'HIGH' },
    UI: { N: 'NONE', R: 'REQUIRED' },
    S: { U: 'UNCHANGED', C: 'CHANGED' },
    C: { H: 'HIGH', L: 'LOW', N: 'NONE' },
    I: { H: 'HIGH', L: 'LOW', N: 'NONE' },
    A: { H: 'HIGH', L: 'LOW', N: 'NONE' },
  };

  return code ? maps[key]?.[code] ?? code : null;
}

"""
        marker = 'function severityClass(value: string | null): string {'
        idx = text.find(marker)
        if idx < 0:
            raise SystemExit('Không tìm thấy vị trí chèn helper trong ai-prediction-detail-client.tsx')
        text = text[:idx] + helper + text[idx:]

    text = text.replace(
        """  const riskLevel = normalizeRiskLevel(getString(item, [['aiPrediction', 'riskLevel']]));
""",
        """  const riskLevel =
    riskLevelFromPercentile(percentile) ??
    normalizeRiskLevel(getString(item, [['aiPrediction', 'riskLevel']]));
""",
        1,
    )

    if 'const cvssVectorString =' not in text:
        text = text.replace(
            """  const cvssAttackVector =
    getString(item, [
""",
            """  const cvssVectorString =
    getString(item, [
      ['cvssVector', 'vectorString'],
      ['cve', 'cvssMetrics', '0', 'vectorString'],
    ]);

  const cvssAttackVector =
    getString(item, [
      ['cvssVector', 'attackVector'],
""",
            1,
        )
    else:
        text = text.replace(
            """  const cvssAttackVector =
    getString(item, [
""",
            """  const cvssAttackVector =
    getString(item, [
      ['cvssVector', 'attackVector'],
""",
            1,
        )

    # Add cvssVector paths and vectorString parser fallbacks for every CVSS field.
    replacements = [
        ("""    ]) ?? getAiCvssReasonString(item, 'CVSS_attack_vector') ?? '—';""", """    ]) ?? cvssVectorMetricLabel(cvssVectorString, 'AV') ?? getAiCvssReasonString(item, 'CVSS_attack_vector') ?? '—';"""),
        ("""    ]) ?? getAiCvssReasonString(item, 'CVSS_attack_complexity') ?? '—';""", """    ]) ?? cvssVectorMetricLabel(cvssVectorString, 'AC') ?? getAiCvssReasonString(item, 'CVSS_attack_complexity') ?? '—';"""),
        ("""    ]) ?? getAiCvssReasonString(item, 'CVSS_privileges_required') ?? '—';""", """    ]) ?? cvssVectorMetricLabel(cvssVectorString, 'PR') ?? getAiCvssReasonString(item, 'CVSS_privileges_required') ?? '—';"""),
        ("""    ]) ?? getAiCvssReasonString(item, 'CVSS_user_interaction') ?? '—';""", """    ]) ?? cvssVectorMetricLabel(cvssVectorString, 'UI') ?? getAiCvssReasonString(item, 'CVSS_user_interaction') ?? '—';"""),
        ("""    ]) ?? getAiCvssReasonString(item, 'CVSS_confidentiality') ?? '—';""", """    ]) ?? cvssVectorMetricLabel(cvssVectorString, 'C') ?? getAiCvssReasonString(item, 'CVSS_confidentiality') ?? '—';"""),
        ("""    ]) ?? getAiCvssReasonString(item, 'CVSS_integrity') ?? '—';""", """    ]) ?? cvssVectorMetricLabel(cvssVectorString, 'I') ?? getAiCvssReasonString(item, 'CVSS_integrity') ?? '—';"""),
        ("""    ]) ?? getAiCvssReasonString(item, 'CVSS_availability') ?? '—';""", """    ]) ?? cvssVectorMetricLabel(cvssVectorString, 'A') ?? getAiCvssReasonString(item, 'CVSS_availability') ?? '—';"""),
    ]
    for old, new in replacements:
        text = text.replace(old, new, 1)

    path_lines = [
        ("""      ['cve', 'cvssMetrics', '0', 'attackComplexity'],""", """      ['cvssVector', 'attackComplexity'],\n      ['cve', 'cvssMetrics', '0', 'attackComplexity'],"""),
        ("""      ['cve', 'cvssMetrics', '0', 'privilegesRequired'],""", """      ['cvssVector', 'privilegesRequired'],\n      ['cve', 'cvssMetrics', '0', 'privilegesRequired'],"""),
        ("""      ['cve', 'cvssMetrics', '0', 'userInteraction'],""", """      ['cvssVector', 'userInteraction'],\n      ['cve', 'cvssMetrics', '0', 'userInteraction'],"""),
        ("""      ['cve', 'cvssMetrics', '0', 'confidentialityImpact'],""", """      ['cvssVector', 'confidentialityImpact'],\n      ['cve', 'cvssMetrics', '0', 'confidentialityImpact'],"""),
        ("""      ['cve', 'cvssMetrics', '0', 'integrityImpact'],""", """      ['cvssVector', 'integrityImpact'],\n      ['cve', 'cvssMetrics', '0', 'integrityImpact'],"""),
        ("""      ['cve', 'cvssMetrics', '0', 'availabilityImpact'],""", """      ['cvssVector', 'availabilityImpact'],\n      ['cve', 'cvssMetrics', '0', 'availabilityImpact'],"""),
    ]
    for old, new in path_lines:
        if new not in text:
            text = text.replace(old, new, 1)

    write(path, text)
    print('[OK] patched ai-prediction-detail-client:', path)


def main():
    print('Project root:', ROOT)
    patch_importer()
    patch_delta()
    patch_security_data_sync()
    patch_security_data_service()
    patch_device_analysis_button()
    patch_ai_predictions_client()
    patch_ai_prediction_detail_client()
    print('\nDONE. Run typecheck/build next.')

if __name__ == '__main__':
    main()
