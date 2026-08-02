from pathlib import Path
from datetime import datetime
import re
import shutil

ROOT = Path(r"D:\LuanVan\test\cyrp-platform-phase2")
button = ROOT / "apps" / "user-web" / "src" / "components" / "device-analysis-button.tsx"
devices_page = ROOT / "apps" / "user-web" / "src" / "app" / "devices" / "devices-page-client.tsx"

if not button.exists():
    raise SystemExit(f"Không tìm thấy file: {button}")

backup = button.with_suffix(button.suffix + ".bak-fix-modal-priority-list-color-agent-time-" + datetime.now().strftime("%Y%m%d-%H%M%S"))
shutil.copy2(button, backup)

text = button.read_text(encoding="utf-8")

# 1. Mở rộng summary để giữ luôn danh sách top vulnerabilities sau khi global sort.
text = text.replace(
"""type DeviceHighestAiSummary = {
  total: number;
  highestPercentile: number | null;
  highestAttackProbability: number | null;
  topCveId: string | null;
  topPackageName: string | null;
  topRiskLevel: string | null;
  topPredictedAt: string | null;
};""",
"""type DeviceHighestAiSummary = {
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
)

# 2. Thêm class gauge theo percentile: >=90 đỏ, 70-89 vàng, <70 xanh.
helper_marker = "function percentileAsProbabilityScale(value: number | null | undefined): number | null {"
insert_after_function = r"""function cyrpPercentileGaugeClass(value: number | null | undefined): string {
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

if "function cyrpPercentileGaugeClass" not in text:
    idx = text.find(helper_marker)
    if idx == -1:
        raise SystemExit("Không tìm thấy percentileAsProbabilityScale để chèn cyrpPercentileGaugeClass.")

    # tìm hết function percentileAsProbabilityScale bằng cách tìm dòng return null; rồi dấu } kế tiếp
    end_marker = "  return value <= 1 ? value : value / 100;\n}\n\n"
    end_idx = text.find(end_marker, idx)
    if end_idx == -1:
        raise SystemExit("Không tìm thấy cuối percentileAsProbabilityScale.")

    end_idx = end_idx + len(end_marker)
    text = text[:end_idx] + insert_after_function + text[end_idx:]

# 3. Trong loader, lưu topItems + latestPredictedAt.
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

if old_summary not in text:
    raise SystemExit("Không tìm thấy block setHighestAiSummary cũ để thay.")
text = text.replace(old_summary, new_summary, 1)

# 4. Tạo danh sách ưu tiên dùng global sort thay vì page cũ.
strongest_block = """  const strongestPrediction = useMemo(
    () => {
      return sortedVulnerabilities[0] ?? null;
    },
    [sortedVulnerabilities],
  );
"""

priority_block = """  const strongestPrediction = useMemo(
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
    raise SystemExit("Không tìm thấy block strongestPrediction để chèn cyrpPriorityVulnerabilities.")
text = text.replace(strongest_block, priority_block, 1)

# 5. Quick actions phải lấy CVE top theo global sort.
quick_pattern = r"""  const quickActions = useMemo\(
    \(\) => \{
      const actions: string\[\] = \[\];
[\s\S]*?
      return actions;
    \},
    \[[\s\S]*?\],
  \);
"""

quick_replacement = """  const quickActions = (() => {
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

text, quick_count = re.subn(quick_pattern, quick_replacement, text, count=1)
if quick_count != 1:
    raise SystemExit("Không thay được quickActions. Cần gửi đoạn quanh const quickActions.")

# 6. Cập nhật block display agent/percentile trước return.
display_pattern = r"""  const cyrpDisplayAgentId =
[\s\S]*?
  const cyrpDisplayHighestAttackProbability =
    highestAiSummary\?\.highestAttackProbability \?\?
    cyrpAttackProbability\(strongestPrediction\) \?\?
    null;

"""

display_replacement = """  const cyrpDisplayAgentId =
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

text, display_count = re.subn(display_pattern, display_replacement, text, count=1)
if display_count != 1:
    raise SystemExit("Không thay được block cyrpDisplayAgentId/cyrpDisplayHighestPercentile.")

# 7. Hero summary + pill/model dùng top global sort.
text = text.replace(
    "summaryMessage(highestAttackProbability, vulnerabilityTotal, snapshot.alertCount)",
    "summaryMessage(percentileAsProbabilityScale(cyrpDisplayHighestPercentile), vulnerabilityTotal, snapshot.alertCount)",
)

text = text.replace(
    "gaugeClass(highestAttackProbability)",
    "cyrpPercentileGaugeClass(cyrpDisplayHighestPercentile)",
)

text = text.replace(
    "strongestPrediction ? (finalPriorityLevel(strongestPrediction) ?? strongestPrediction.aiPrediction?.riskLevel) : null",
    "cyrpTopPrediction ? (finalPriorityLevel(cyrpTopPrediction) ?? cyrpTopPrediction.aiPrediction?.riskLevel) : null",
)

text = text.replace(
    "strongestPrediction\n                          ? finalPriorityLevel(strongestPrediction) ?? strongestPrediction.aiPrediction?.riskLevel ?? '—'\n                          : 'Chưa có dữ liệu'",
    "cyrpTopPrediction\n                          ? finalPriorityLevel(cyrpTopPrediction) ?? cyrpTopPrediction.aiPrediction?.riskLevel ?? '—'\n                          : 'Chưa có dữ liệu'",
)

text = text.replace(
    "modelLabel(strongestPrediction?.aiPrediction?.modelVersion)",
    "modelLabel(cyrpTopPrediction?.aiPrediction?.modelVersion)",
)

# 8. Danh sách lỗ hổng ưu tiên dùng cyrpPriorityVulnerabilities, không dùng sortedVulnerabilities cũ.
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

# 9. Lần kiểm tra gần nhất lấy thời gian AI prediction mới nhất nếu có.
text = re.sub(
    r"Lần kiểm tra gần nhất:\s*\{formatDate\([^}]+\)\}",
    "Lần kiểm tra gần nhất: {formatDate(highestAiSummary?.latestPredictedAt ?? highestAiSummary?.topPredictedAt ?? snapshot?.calculatedAt ?? null)}",
    text,
)

# 10. Dòng cập nhật ở card Percentile.
text = re.sub(
    r"Percentile AI cao nhất · cập nhật \{formatDate\([\s\S]*?\)\}",
    "Percentile AI cao nhất · cập nhật {formatDate(highestAiSummary?.topPredictedAt ?? highestAiSummary?.latestPredictedAt ?? cyrpTopPrediction?.aiPrediction?.predictedAt ?? snapshot.calculatedAt)}",
    text,
    count=1,
)

button.write_text(text, encoding="utf-8")
print("Patched:", button)
print("Backup:", backup)

# 11. Cố gắng truyền Wazuh Agent binding từ Devices page sang button nếu call đang ở dạng phổ biến.
if devices_page.exists():
    page_backup = devices_page.with_suffix(devices_page.suffix + ".bak-pass-wazuh-agent-to-button-" + datetime.now().strftime("%Y%m%d-%H%M%S"))
    shutil.copy2(devices_page, page_backup)
    page = devices_page.read_text(encoding="utf-8")

    one_line = '<DeviceAnalysisButton deviceId={device.id} variant="repairOrb" />'
    multi_line_pattern = r"""<DeviceAnalysisButton\s+
\s*deviceId=\{device\.id\}\s+
\s*variant="repairOrb"\s*
/>"""

    replacement = """<DeviceAnalysisButton
              deviceId={device.id}
              variant="repairOrb"
              wazuhAgentId={(device as { wazuhBinding?: { wazuhAgentId?: string | null; wazuhAgentName?: string | null } | null }).wazuhBinding?.wazuhAgentId ?? null}
              wazuhAgentName={(device as { wazuhBinding?: { wazuhAgentId?: string | null; wazuhAgentName?: string | null } | null }).wazuhBinding?.wazuhAgentName ?? null}
            />"""

    if one_line in page:
        page = page.replace(one_line, replacement, 1)
        devices_page.write_text(page, encoding="utf-8")
        print("Patched Devices page one-line call:", devices_page)
    else:
        page, count = re.subn(multi_line_pattern, replacement, page, count=1)
        if count:
            devices_page.write_text(page, encoding="utf-8")
            print("Patched Devices page multi-line call:", devices_page)
        else:
            print("Không tìm thấy call DeviceAnalysisButton trong devices-page-client.tsx; agent vẫn fallback từ top vulnerability/device.")
            print("Backup devices page:", page_backup)
