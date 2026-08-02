from pathlib import Path
from datetime import datetime
import re
import shutil

ROOT = Path(r"D:\LuanVan\test\cyrp-platform-phase2")
button = ROOT / "apps" / "user-web" / "src" / "components" / "device-analysis-button.tsx"
devices_page = ROOT / "apps" / "user-web" / "src" / "app" / "devices" / "devices-page-client.tsx"

for path in [button, devices_page]:
    if not path.exists():
        raise SystemExit(f"Không tìm thấy file: {path}")

def backup(path: Path):
    bak = path.with_suffix(path.suffix + ".bak-percentile-agent-" + datetime.now().strftime("%Y%m%d-%H%M%S"))
    shutil.copy2(path, bak)
    print(f"Backup: {bak}")

def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")

def write(path: Path, text: str):
    path.write_text(text, encoding="utf-8")

backup(button)
backup(devices_page)

text = read(button)

# 1. Mở rộng props để nhận Agent ID / Agent name từ trang Devices.
text = text.replace(
"""interface DeviceAnalysisButtonProps {
  deviceId: string;
  variant?: 'default' | 'repairOrb';
}
""",
"""interface DeviceAnalysisButtonProps {
  deviceId: string;
  variant?: 'default' | 'repairOrb';
  wazuhAgentId?: string | null;
  wazuhAgentName?: string | null;
}
"""
)

text = re.sub(
    r"export function DeviceAnalysisButton\(\{\s*deviceId,\s*variant = 'default',?\s*\}: DeviceAnalysisButtonProps\)",
    """export function DeviceAnalysisButton({
  deviceId,
  variant = 'default',
  wazuhAgentId: propWazuhAgentId = null,
  wazuhAgentName: propWazuhAgentName = null,
}: DeviceAnalysisButtonProps)""",
    text,
    count=1,
)

# 2. Thêm helper đọc percentile/probability trực tiếp từ aiPrediction.
helper_marker = "type JsonRecord = Record<string, unknown>;"
helper = r"""
type DeviceHighestAiSummary = {
  total: number;
  highestPercentile: number | null;
  highestAttackProbability: number | null;
  topCveId: string | null;
  topPackageName: string | null;
  topRiskLevel: string | null;
  topPredictedAt: string | null;
};

function cyrpNumber(value: unknown): number | null {
  if (typeof value === 'number' && Number.isFinite(value)) {
    return value;
  }

  if (typeof value === 'string' && value.trim()) {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : null;
  }

  return null;
}

function cyrpRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === 'object'
    ? (value as Record<string, unknown>)
    : {};
}

function cyrpPredictionRecord(
  item: VulnerabilityItem | null | undefined,
): Record<string, unknown> {
  return cyrpRecord(item?.aiPrediction);
}

function cyrpExplanationRecord(
  item: VulnerabilityItem | null | undefined,
): Record<string, unknown> {
  return cyrpRecord(cyrpPredictionRecord(item).explanation);
}

function cyrpPredictedPercentile(
  item: VulnerabilityItem | null | undefined,
): number | null {
  const prediction = cyrpPredictionRecord(item);
  const explanation = cyrpExplanationRecord(item);

  return cyrpNumber(prediction.predictedPercentile)
    ?? cyrpNumber(prediction.predicted_percentile)
    ?? cyrpNumber(prediction.percentile)
    ?? cyrpNumber(explanation.predictedPercentile)
    ?? cyrpNumber(explanation.predicted_percentile)
    ?? cyrpNumber(explanation.Percentile)
    ?? null;
}

function cyrpAttackProbability(
  item: VulnerabilityItem | null | undefined,
): number | null {
  const prediction = cyrpPredictionRecord(item);
  const explanation = cyrpExplanationRecord(item);

  return cyrpNumber(prediction.attackProbability)
    ?? cyrpNumber(prediction.attack_probability)
    ?? cyrpNumber(prediction.probability)
    ?? cyrpNumber(explanation.attackProbability)
    ?? cyrpNumber(explanation.attack_probability)
    ?? cyrpNumber(explanation.Probability)
    ?? null;
}

function cyrpRiskLevel(
  item: VulnerabilityItem | null | undefined,
): string | null {
  const prediction = cyrpPredictionRecord(item);
  const explanation = cyrpExplanationRecord(item);

  const value =
    prediction.riskLevel
    ?? prediction.risk_level
    ?? explanation.riskLevel
    ?? explanation.risk_level
    ?? explanation.Risk;

  return typeof value === 'string' && value.trim()
    ? value.trim().toUpperCase()
    : null;
}

function cyrpPercentileSortValue(
  item: VulnerabilityItem | null | undefined,
): number {
  const percentile = cyrpPredictedPercentile(item);

  if (typeof percentile === 'number' && Number.isFinite(percentile)) {
    return percentile <= 1 ? percentile * 100 : percentile;
  }

  const probability = cyrpAttackProbability(item);

  if (typeof probability === 'number' && Number.isFinite(probability)) {
    return probability <= 1 ? probability * 100 : probability;
  }

  return -1;
}

function formatPercentileDisplay(value: number | null | undefined): string {
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    return '—';
  }

  const percent = value <= 1 ? value * 100 : value;
  return `${Math.round(percent)}%`;
}

function percentileAsProbabilityScale(value: number | null | undefined): number | null {
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    return null;
  }

  return value <= 1 ? value : value / 100;
}

"""
if helper not in text:
    if helper_marker not in text:
        raise SystemExit("Không tìm thấy marker type JsonRecord để chèn helper.")
    text = text.replace(helper_marker, helper_marker + "\n" + helper, 1)

# 3. Thêm state highest AI summary.
if "const [highestAiSummary, setHighestAiSummary]" not in text:
    text = text.replace(
        "const [error, setError] = useState('');",
        "const [error, setError] = useState('');\n  const [highestAiSummary, setHighestAiSummary] = useState<DeviceHighestAiSummary | null>(null);",
        1,
    )

# 4. Thêm loader fetch toàn bộ vulnerabilities active rồi lấy percentile cao nhất.
loader = r"""async function loadDeviceHighestAiSummary(): Promise<void> {
    const fetchLimit = 100;
    const allItems: VulnerabilityItem[] = [];

    let apiTotal = 0;
    let apiTotalPages = 1;

    for (let pageNumber = 1; pageNumber <= apiTotalPages && pageNumber <= 50; pageNumber += 1) {
      const params = new URLSearchParams({
        page: String(pageNumber),
        limit: String(fetchLimit),
        status: 'ACTIVE',
      });

      const response = await fetch(`/api/vulnerabilities?${params.toString()}`, {
        method: 'GET',
        cache: 'no-store',
        credentials: 'same-origin',
        headers: browserAuthorizationHeaders(),
      });

      const payload = (await response.json().catch(() => null)) as
        | (Pagination<VulnerabilityItem> & { message?: string })
        | null;

      if (!response.ok || !payload || typeof payload !== 'object') {
        return;
      }

      const pageItems = Array.isArray(payload.items) ? payload.items : [];
      allItems.push(...pageItems);

      if (pageNumber === 1) {
        apiTotal = typeof payload.total === 'number' ? payload.total : pageItems.length;
        apiTotalPages =
          typeof payload.totalPages === 'number' && payload.totalPages > 0
            ? payload.totalPages
            : Math.max(1, Math.ceil(apiTotal / fetchLimit));
      }

      if (pageItems.length === 0 || allItems.length >= apiTotal) {
        break;
      }
    }

    const sorted = [...allItems].sort(
      (left, right) => cyrpPercentileSortValue(right) - cyrpPercentileSortValue(left),
    );

    const top = sorted[0] ?? null;

    setHighestAiSummary({
      total: sorted.length,
      highestPercentile: cyrpPredictedPercentile(top),
      highestAttackProbability: cyrpAttackProbability(top),
      topCveId: top?.cveId ?? null,
      topPackageName: top?.packageName ?? null,
      topRiskLevel: cyrpRiskLevel(top),
      topPredictedAt: top?.aiPrediction?.predictedAt ?? null,
    });
  }

  """

if "async function loadDeviceHighestAiSummary" not in text:
    marker = "const sortedVulnerabilities = useMemo("
    idx = text.find(marker)
    if idx == -1:
        raise SystemExit("Không tìm thấy const sortedVulnerabilities = useMemo để chèn loader.")
    text = text[:idx] + loader + text[idx:]

# 5. Khi modal mở thì tự refresh highest summary.
effect = r"""useEffect(() => {
    if (!isModalOpen) {
      return;
    }

    void loadDeviceHighestAiSummary().catch(() => {
      // Keep the current summary if refresh fails.
    });
  }, [isModalOpen]);

  """

if "void loadDeviceHighestAiSummary().catch" not in text:
    marker = "const sortedVulnerabilities = useMemo("
    idx = text.find(marker)
    if idx == -1:
        raise SystemExit("Không tìm thấy sortedVulnerabilities để chèn useEffect.")
    text = text[:idx] + effect + text[idx:]

# 6. Sau khi bấm Kiểm tra máy và pipeline chạy xong, refresh lại highest summary.
if "await loadDeviceHighestAiSummary();" not in text:
    text = text.replace(
        "await loadVulnerabilities();",
        "await loadVulnerabilities();\n      await loadDeviceHighestAiSummary();",
        1,
    )

# 7. Tạo biến hiển thị agent và percentile trước return.
display_block = r"""  const cyrpDisplayAgentId =
    snapshot?.wazuhAgentId ??
    propWazuhAgentId ??
    null;

  const cyrpDisplayAgentName =
    snapshot?.agentName ??
    propWazuhAgentName ??
    (cyrpDisplayAgentId ? `Agent ${cyrpDisplayAgentId}` : 'Chưa có agent');

  const cyrpDisplayAgentMeta =
    cyrpDisplayAgentId
      ? `${cyrpDisplayAgentName} · ID ${cyrpDisplayAgentId}`
      : cyrpDisplayAgentName;

  const cyrpDisplayHighestPercentile =
    highestAiSummary?.highestPercentile ??
    cyrpPredictedPercentile(strongestPrediction) ??
    null;

  const cyrpDisplayHighestAttackProbability =
    highestAiSummary?.highestAttackProbability ??
    cyrpAttackProbability(strongestPrediction) ??
    null;

"""

if "const cyrpDisplayHighestPercentile" not in text:
    marker = "  return (\n"
    idx = text.find(marker)
    if idx == -1:
        raise SystemExit("Không tìm thấy return chính trong DeviceAnalysisButton.")
    text = text[:idx] + display_block + text[idx:]

# 8. Sửa hiển thị card/gauge.
text = text.replace(
    "<span>Xác suất cao nhất</span>",
    "<span>Percentile cao nhất</span>",
)

text = text.replace(
    "<strong>{formatProbability(highestAttackProbability)}</strong>",
    "<strong>{formatPercentileDisplay(cyrpDisplayHighestPercentile)}</strong>",
)

text = text.replace(
    "<small>{riskBandLabel(highestAttackProbability)}</small>",
    "<small>{riskBandLabel(percentileAsProbabilityScale(cyrpDisplayHighestPercentile))}</small>",
)

text = text.replace(
    "<strong>{formatProbability(modelExploitRiskValue(strongestPrediction))}</strong>",
    "<strong>{formatPercentileDisplay(cyrpDisplayHighestPercentile)}</strong>",
)

text = text.replace(
    "Percentile AI · cập nhật {formatDate(strongestPrediction?.aiPrediction?.predictedAt ?? snapshot.calculatedAt)}",
    "Percentile AI cao nhất · cập nhật {formatDate(highestAiSummary?.topPredictedAt ?? strongestPrediction?.aiPrediction?.predictedAt ?? snapshot.calculatedAt)}",
)

# 9. Sửa hiển thị agent trong modal.
text = text.replace(
    "{snapshot.agentName ?? `Agent ${snapshot.wazuhAgentId}`}",
    "{cyrpDisplayAgentName}",
)

text = text.replace(
    "<span>Agent: {snapshot.wazuhAgentId}</span>",
    "<span>Agent: {cyrpDisplayAgentMeta}</span>",
)

write(button, text)

# 10. Truyền Agent ID / Agent name từ devices-page-client vào DeviceAnalysisButton.
page = read(devices_page)

old_call = '<DeviceAnalysisButton deviceId={device.id} variant="repairOrb" />'
new_call = """<DeviceAnalysisButton
              deviceId={device.id}
              variant="repairOrb"
              wazuhAgentId={(device as { wazuhBinding?: { wazuhAgentId?: string | null; wazuhAgentName?: string | null } | null }).wazuhBinding?.wazuhAgentId ?? null}
              wazuhAgentName={(device as { wazuhBinding?: { wazuhAgentId?: string | null; wazuhAgentName?: string | null } | null }).wazuhBinding?.wazuhAgentName ?? null}
            />"""

if old_call in page:
    page = page.replace(old_call, new_call, 1)
else:
    print("Không thấy call DeviceAnalysisButton dạng một dòng; bỏ qua patch devices-page-client.")

write(devices_page, page)

print("DONE: patched highest percentile and agent display.")
