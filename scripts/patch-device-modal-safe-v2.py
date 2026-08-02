from pathlib import Path
from datetime import datetime
import shutil
import re

ROOT = Path(r"D:\LuanVan\test\cyrp-platform-phase2")
button = ROOT / "apps" / "user-web" / "src" / "components" / "device-analysis-button.tsx"

if not button.exists():
    raise SystemExit(f"Không tìm thấy file: {button}")

backup = button.with_suffix(button.suffix + ".bak-modal-final-safe-" + datetime.now().strftime("%Y%m%d-%H%M%S"))
shutil.copy2(button, backup)

text = button.read_text(encoding="utf-8")

# 1. Type summary thêm topItems/latestPredictedAt.
old_type = """type DeviceHighestAiSummary = {
  total: number;
  highestPercentile: number | null;
  highestAttackProbability: number | null;
  topCveId: string | null;
  topPackageName: string | null;
  topRiskLevel: string | null;
  topPredictedAt: string | null;
};"""

new_type = """type DeviceHighestAiSummary = {
  total: number;
  highestPercentile: number | null;
  highestAttackProbability: number | null;
  topCveId: string | null;
  topPackageName: string | null;
  topRiskLevel: string | null;
  topPredictedAt: string | null;
  latestPredictedAt: string | null;
  topItems: VulnerabilityItem[];
};"""

if old_type in text:
    text = text.replace(old_type, new_type, 1)

# 2. Thêm gauge class theo percentile.
if "function cyrpPercentileGaugeClass" not in text:
    marker_end = "  return value <= 1 ? value : value / 100;\n}\n\n"
    idx = text.find(marker_end)

    if idx == -1:
        raise SystemExit("Không tìm thấy cuối function percentileAsProbabilityScale.")

    idx += len(marker_end)

    helper = """function cyrpPercentileGaugeClass(value: number | null | undefined): string {
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    return styles.gaugeNeutral;
  }

  const percent = value <= 1 ? value * 100 : value;

  if (percent >= 90) {
    return styles.gaugeCritical;
  }

  if (percent >= 70) {
    return styles.gaugeMedium;
  }

  return styles.gaugeLow;
}

"""

    text = text[:idx] + helper + text[idx:]

# 3. setHighestAiSummary lưu topItems/latestPredictedAt.
old_summary = """    setHighestAiSummary({
      total: sorted.length,
      highestPercentile: cyrpPredictedPercentile(top),
      highestAttackProbability: cyrpAttackProbability(top),
      topCveId: top?.cveId ?? null,
      topPackageName: top?.packageName ?? null,
      topRiskLevel: cyrpRiskLevel(top),
      topPredictedAt: top?.aiPrediction?.predictedAt ?? null,
    });"""

new_summary = """    const latestPredictedAt =
      sorted
        .map((item) => item.aiPrediction?.predictedAt ?? null)
        .filter((value): value is string => typeof value === 'string' && value.trim().length > 0)
        .sort((left, right) => new Date(right).getTime() - new Date(left).getTime())[0] ?? null;

    setHighestAiSummary({
      total: sorted.length,
      highestPercentile: cyrpPredictedPercentile(top),
      highestAttackProbability: cyrpAttackProbability(top),
      topCveId: top?.cveId ?? null,
      topPackageName: top?.packageName ?? null,
      topRiskLevel: cyrpRiskLevel(top),
      topPredictedAt: top?.aiPrediction?.predictedAt ?? null,
      latestPredictedAt,
      topItems: sorted.slice(0, 8),
    });"""

if old_summary in text:
    text = text.replace(old_summary, new_summary, 1)
elif "topItems: sorted.slice(0, 8)" not in text:
    raise SystemExit("Không tìm thấy block setHighestAiSummary cũ.")

# 4. Thêm cyrpPriorityVulnerabilities và cyrpTopPrediction sau strongestPrediction.
if "const cyrpPriorityVulnerabilities" not in text:
    strongest_block = """  const strongestPrediction = useMemo(
    () => {
      return sortedVulnerabilities[0] ?? null;
    },
    [sortedVulnerabilities],
  );
"""

    replacement = """  const strongestPrediction = useMemo(
    () => {
      return sortedVulnerabilities[0] ?? null;
    },
    [sortedVulnerabilities],
  );

  const cyrpPriorityVulnerabilities = useMemo(
    () => {
      return highestAiSummary?.topItems?.length
        ? highestAiSummary.topItems
        : sortedVulnerabilities;
    },
    [highestAiSummary, sortedVulnerabilities],
  );

  const cyrpTopPrediction = cyrpPriorityVulnerabilities[0] ?? null;
"""

    if strongest_block not in text:
        raise SystemExit("Không tìm thấy block strongestPrediction.")
    text = text.replace(strongest_block, replacement, 1)

# 5. Thay quickActions bằng cách cắt từ const quickActions đến trước function kế tiếp.
quick_start = text.find("  const quickActions =")

if quick_start == -1:
    raise SystemExit("Không tìm thấy const quickActions.")

quick_end = text.find("\n  function ", quick_start)

if quick_end == -1:
    raise SystemExit("Không tìm thấy function kế tiếp sau quickActions.")

new_quick = """  const quickActions = (() => {
    const actions: string[] = [];

    if (cyrpTopPrediction) {
      actions.push(
        `Ưu tiên xử lý ${cyrpTopPrediction.cveId} vì đang có percentile AI ${formatPercentileDisplay(cyrpPredictedPercentile(cyrpTopPrediction))} và xác suất khai thác ${formatProbability(cyrpAttackProbability(cyrpTopPrediction))}.`,
      );
    }

    if ((snapshot?.criticalCount ?? 0) > 0) {
      actions.push(
        `Wazuh ghi nhận ${snapshot?.criticalCount ?? 0} cảnh báo critical trong 24 giờ gần nhất, nên kiểm tra nhật ký và rule liên quan.`,
      );
    }

    if (vulnerabilityTotal > cyrpPriorityVulnerabilities.length) {
      actions.push(
        `Hiện chỉ đang hiển thị ${cyrpPriorityVulnerabilities.length}/${vulnerabilityTotal} lỗ hổng ưu tiên cao nhất, nhấn vào chi tiết để xem thêm khi cần.`,
      );
    } else if (vulnerabilityTotal > 0) {
      actions.push(
        `Thiết bị hiện có ${vulnerabilityTotal} lỗ hổng active cần được theo dõi và vá theo mức ưu tiên.`,
      );
    }

    if (!actions.length) {
      actions.push('Chưa có hành động khẩn cấp nổi bật. Có thể tiếp tục theo dõi ở lần kiểm tra tiếp theo.');
    }

    return actions;
  })();

"""

text = text[:quick_start] + new_quick + text[quick_end + 1:]

# 6. Thay block display để lấy agent từ snapshot/props/top vulnerability.
display_start = text.find("  const cyrpDisplayAgentId =")
display_end_marker = "  return (\n"

if display_start == -1:
    raise SystemExit("Không tìm thấy const cyrpDisplayAgentId.")

display_end = text.find(display_end_marker, display_start)

if display_end == -1:
    raise SystemExit("Không tìm thấy return sau display block.")

new_display = """  const cyrpDisplayAgentId =
    snapshot?.wazuhAgentId ??
    propWazuhAgentId ??
    null;

  const cyrpTopRecord = cyrpTopPrediction as
    | (VulnerabilityItem & {
        device?: { hostname?: string | null } | null;
        deviceName?: string | null;
        hostname?: string | null;
      })
    | null;

  const cyrpTopDeviceName =
    cyrpTopRecord?.device?.hostname ??
    cyrpTopRecord?.deviceName ??
    cyrpTopRecord?.hostname ??
    null;

  const cyrpDisplayAgentName =
    snapshot?.agentName ??
    propWazuhAgentName ??
    cyrpTopDeviceName ??
    (cyrpDisplayAgentId ? `Agent ${cyrpDisplayAgentId}` : 'Thiết bị đã liên kết');

  const cyrpDisplayAgentMeta =
    cyrpDisplayAgentId
      ? `${cyrpDisplayAgentName} · ID ${cyrpDisplayAgentId}`
      : cyrpDisplayAgentName;

  const cyrpDisplayHighestPercentile =
    highestAiSummary?.highestPercentile ??
    cyrpPredictedPercentile(cyrpTopPrediction) ??
    cyrpPredictedPercentile(strongestPrediction) ??
    null;

  const cyrpDisplayHighestAttackProbability =
    highestAiSummary?.highestAttackProbability ??
    cyrpAttackProbability(cyrpTopPrediction) ??
    cyrpAttackProbability(strongestPrediction) ??
    null;

"""

text = text[:display_start] + new_display + text[display_end:]

# 7. Render dùng biến mới.
text = text.replace(
    "summaryMessage(highestAttackProbability, vulnerabilityTotal, snapshot.alertCount)",
    "summaryMessage(percentileAsProbabilityScale(cyrpDisplayHighestPercentile), vulnerabilityTotal, snapshot.alertCount)",
)

text = text.replace(
    "gaugeClass(highestAttackProbability)",
    "cyrpPercentileGaugeClass(cyrpDisplayHighestPercentile)",
)

text = text.replace(
    "modelLabel(strongestPrediction?.aiPrediction?.modelVersion)",
    "modelLabel(cyrpTopPrediction?.aiPrediction?.modelVersion)",
)

text = text.replace(
    "{sortedVulnerabilities.length ? (",
    "{cyrpPriorityVulnerabilities.length ? (",
)

text = text.replace(
    "{sortedVulnerabilities.slice(0, 5).map((item) => {",
    "{cyrpPriorityVulnerabilities.slice(0, 5).map((item) => {",
)

text = text.replace(
    "{formatProbability(modelExploitRiskValue(item))}",
    "{formatPercentileDisplay(cyrpPredictedPercentile(item))}",
)

text = text.replace(
    "Percentile AI cao nhất · cập nhật {formatDate(highestAiSummary?.topPredictedAt ?? strongestPrediction?.aiPrediction?.predictedAt ?? snapshot.calculatedAt)}",
    "Percentile AI cao nhất · cập nhật {formatDate(highestAiSummary?.topPredictedAt ?? highestAiSummary?.latestPredictedAt ?? cyrpTopPrediction?.aiPrediction?.predictedAt ?? snapshot.calculatedAt)}",
)

# 8. Sửa dòng lần kiểm tra gần nhất theo nhiều dạng phổ biến.
text = re.sub(
    r"Lần kiểm tra gần nhất:\s*\{formatDate\([^}]+\)\}",
    "Lần kiểm tra gần nhất: {formatDate(highestAiSummary?.latestPredictedAt ?? highestAiSummary?.topPredictedAt ?? snapshot?.calculatedAt ?? null)}",
    text,
)

button.write_text(text, encoding="utf-8")

print("Patched:", button)
print("Backup:", backup)
