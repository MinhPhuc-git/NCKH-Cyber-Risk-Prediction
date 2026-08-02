from pathlib import Path
from datetime import datetime
import shutil
import re

root = Path(r"D:\LuanVan\test\cyrp-platform-phase2")
path = root / "apps" / "user-web" / "src" / "components" / "device-analysis-button.tsx"

backup = path.with_suffix(".tsx.bak-final-distribution-from-vulnerabilities-" + datetime.now().strftime("%Y%m%d-%H%M%S"))
shutil.copy2(path, backup)

text = path.read_text(encoding="utf-8")

if "loaded?: number" not in text and "interface AiRiskSummaryResponse" in text:
    text = text.replace("total: number;", "total: number;\n  loaded?: number;", 1)

replacement = '''async function loadAiRiskSummary() {
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

    function asRecord(value: unknown): Record<string, unknown> {
      return value && typeof value === 'object' && !Array.isArray(value)
        ? (value as Record<string, unknown>)
        : {};
    }

    for (let pageNumber = 1; pageNumber <= 20; pageNumber += 1) {
      const params = new URLSearchParams({
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

        const level = normalizeRiskLevel(prediction.riskLevel);

        if (level) {
          distribution[level] += 1;
        }

        const attackProbability = toNumber(prediction.attackProbability);
        if (attackProbability !== null) {
          highestAttackProbability =
            highestAttackProbability === null
              ? attackProbability
              : Math.max(highestAttackProbability, attackProbability);
        }

        const percentile = toNumber(prediction.predictedPercentile);
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
text, count = re.subn(pattern, replacement, text, count=1)

if count == 0:
    raise SystemExit("Không tìm thấy block loadAiRiskSummary.")

start = text.find("const aiDistribution = useMemo")
end = text.find("const maxDistributionCount", start)

if start == -1 or end == -1:
    raise SystemExit("Không tìm thấy block aiDistribution.")

distribution_block = '''const aiDistribution = useMemo<RiskBucketRow[]>(
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
