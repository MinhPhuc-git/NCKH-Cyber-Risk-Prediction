from pathlib import Path
from datetime import datetime
import shutil
import re

root = Path(r"D:\LuanVan\test\cyrp-platform-phase2")
path = root / "apps" / "user-web" / "src" / "components" / "device-analysis-button.tsx"

backup = path.with_suffix(".tsx.bak-ai-distribution-safe-" + datetime.now().strftime("%Y%m%d-%H%M%S"))
shutil.copy2(path, backup)

text = path.read_text(encoding="utf-8")

if "loaded?: number" not in text and "interface AiRiskSummaryResponse" in text:
    text = text.replace(
        "total: number;",
        "total: number;\n  loaded?: number;",
        1,
    )

replacement = r'''async function loadAiRiskSummary() {
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

    function normalizeLevel(value: unknown): keyof typeof distribution | null {
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

    function numberValue(value: unknown): number | null {
      if (typeof value === 'number' && Number.isFinite(value)) return value;

      if (typeof value === 'string' && value.trim()) {
        const parsed = Number(value);
        return Number.isFinite(parsed) ? parsed : null;
      }

      return null;
    }

    function recordOf(value: unknown): Record<string, unknown> {
      return value && typeof value === 'object' && !Array.isArray(value)
        ? (value as Record<string, unknown>)
        : {};
    }

    function arrayOf(payload: unknown): Array<Record<string, unknown>> {
      const record = recordOf(payload);
      const candidates = [
        record.items,
        record.data,
        record.results,
        record.rows,
        record.records,
        record.vulnerabilities,
      ];

      for (const candidate of candidates) {
        if (Array.isArray(candidate)) {
          return candidate.filter(
            (item): item is Record<string, unknown> =>
              item !== null && typeof item === 'object' && !Array.isArray(item),
          );
        }
      }

      return [];
    }

    function totalOf(payload: unknown, fallback: number): number {
      const record = recordOf(payload);

      return (
        numberValue(record.total) ??
        numberValue(record.count) ??
        numberValue(record.totalItems) ??
        numberValue(record.totalRecords) ??
        fallback
      );
    }

    for (let page = 1; page <= 20; page += 1) {
      const params = new URLSearchParams({
        status: 'ACTIVE',
        limit: '100',
        page: String(page),
      });

      const response = await fetch(`/api/vulnerabilities?${params.toString()}`, {
        method: 'GET',
        cache: 'no-store',
        credentials: 'same-origin',
      });

      if (!response.ok) break;

      const payload = await response.json().catch(() => null);
      const items = arrayOf(payload);

      if (page === 1) {
        total = totalOf(payload, items.length);
      }

      for (const item of items) {
        const aiPrediction = recordOf(
          item.aiPrediction ?? item.ai_prediction ?? item.prediction,
        );

        const level = normalizeLevel(
          aiPrediction.riskLevel ??
            aiPrediction.risk_level ??
            item.riskLevel ??
            item.risk_level ??
            item.aiRiskLevel ??
            item.ai_risk_level,
        );

        if (level) {
          distribution[level] += 1;
        }

        const attackProbability = numberValue(
          aiPrediction.attackProbability ??
            aiPrediction.attack_probability ??
            item.attackProbability ??
            item.attack_probability,
        );

        if (attackProbability !== null) {
          highestAttackProbability =
            highestAttackProbability === null
              ? attackProbability
              : Math.max(highestAttackProbability, attackProbability);
        }

        const percentile = numberValue(
          aiPrediction.predictedPercentile ??
            aiPrediction.predicted_percentile ??
            aiPrediction.percentile ??
            item.predictedPercentile ??
            item.predicted_percentile ??
            item.percentile,
        );

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

    setAiRiskSummary({
      total: total || loaded,
      loaded,
      distribution,
      highestAttackProbability,
      highestPercentile,
      calculatedAt: new Date().toISOString(),
    });
  }

  useEffect(() => {'''

pattern = r"async function loadAiRiskSummary\(\) \{[\s\S]*?\n  \}\n\n  useEffect\(\(\) => \{"
new_text, count = re.subn(pattern, replacement, text, count=1)

if count == 0:
    raise SystemExit("Không tìm thấy block loadAiRiskSummary để thay. Cần gửi đoạn quanh function loadAiRiskSummary.")

text = new_text

start = text.find("const aiDistribution = useMemo")
end = text.find("const maxDistributionCount", start)

if start == -1 or end == -1:
    raise SystemExit("Không tìm thấy block aiDistribution.")

distribution_block = r'''const aiDistribution = useMemo<RiskBucketRow[]>(
    () => {
      const counts = aiRiskSummary?.distribution ?? {
        LOW: 0,
        MEDIUM: 0,
        HIGH: 0,
        CRITICAL: 0,
      };

      return [
        { key: 'LOW', label: 'Thấp', count: counts.LOW },
        { key: 'MEDIUM', label: 'Trung bình', count: counts.MEDIUM },
        { key: 'HIGH', label: 'Cao', count: counts.HIGH },
        { key: 'CRITICAL', label: 'Rất cao', count: counts.CRITICAL },
      ];
    },
    [aiRiskSummary],
  );

  '''

text = text[:start] + distribution_block + text[end:]

path.write_text(text, encoding="utf-8")

print("Patched:", path)
print("Backup:", backup)
