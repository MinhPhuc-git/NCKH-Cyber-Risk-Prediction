from pathlib import Path
import re
import shutil
from datetime import datetime

root = Path(r"D:\LuanVan\test\cyrp-platform-phase2")
tsx = root / "apps" / "user-web" / "src" / "components" / "device-analysis-button.tsx"

if not tsx.exists():
    raise SystemExit(f"File not found: {tsx}")

text = tsx.read_text(encoding="utf-8")

backup_dir = root / ".phase-backups" / ("device-analysis-ui-ai-percentile-" + datetime.now().strftime("%Y%m%d-%H%M%S"))
backup_dir.mkdir(parents=True, exist_ok=True)
shutil.copy2(tsx, backup_dir / "device-analysis-button.tsx")

# 1. Add model label for new model version.
needle = "  if (modelVersion === 'AI_CYRP_RANDOM_FOREST_V1') {"
insert = """  if (modelVersion === 'CYRP_XGBOOST_CVSS_PERCENTILE_V3') {
    return 'CYRP XGBoost CVSS Percentile';
  }

"""
if "CYRP_XGBOOST_CVSS_PERCENTILE_V3" not in text and needle in text:
    text = text.replace(needle, insert + needle)

# 2. Add helper functions after formatProbability.
helper_marker = """function formatProbability(
  value: number | null | undefined,
): string {
  if (typeof value !== 'number' || Number.isNaN(value)) {
    return '—';
  }

  return `${Math.round(value * 100)}%`;
}
"""
helper_code = helper_marker + """

function normalizeProbabilityLikeValue(
  value: number | null | undefined,
): number | null {
  if (typeof value !== 'number' || Number.isNaN(value)) {
    return null;
  }

  if (value > 1) {
    return Math.max(0, Math.min(1, value / 100));
  }

  return Math.max(0, Math.min(1, value));
}

function modelExploitRiskValue(
  item: VulnerabilityItem | null | undefined,
): number | null {
  const percentile = normalizeProbabilityLikeValue(
    item?.aiPrediction?.predictedPercentile,
  );

  if (percentile !== null) {
    return percentile;
  }

  return normalizeProbabilityLikeValue(
    item?.aiPrediction?.attackProbability,
  );
}
"""
if "function modelExploitRiskValue(" not in text:
    text = text.replace(helper_marker, helper_code)

# 3. Sort vulnerabilities by AI percentile first, then probability.
text = re.sub(
    r"""const sortedVulnerabilities = useMemo\(\s*\(\) => \{\s*return \[\.\.\.vulnerabilities\]\.sort\(\s*\(left, right\) =>\s*\(right\.aiPrediction\?\.attackProbability \?\? -1\) -\s*\(left\.aiPrediction\?\.attackProbability \?\? -1\),\s*\);\s*\},\s*\[vulnerabilities\],\s*\);""",
    """const sortedVulnerabilities = useMemo(
    () => {
      return [...vulnerabilities].sort(
        (left, right) =>
          (modelExploitRiskValue(right) ?? -1) -
          (modelExploitRiskValue(left) ?? -1),
      );
    },
    [vulnerabilities],
  );""",
    text,
    flags=re.S,
)

# 4. Replace highestAttackProbability calculation with percentile-aware value.
text = re.sub(
    r"""const highestAttackProbability = useMemo\(\s*\(\) => \{\s*const values = vulnerabilities\s*\.map\(\(item\) =>\s*item\.aiPrediction\?\.attackProbability \?\? null,\s*\)\s*\.filter\(\s*\(value\): value is number =>\s*typeof value === 'number' &&\s*Number\.isFinite\(value\),\s*\);\s*return values\.length\s*\? Math\.max\(\.\.\.values\)\s*: null;\s*\},\s*\[vulnerabilities\],\s*\);""",
    """const highestAttackProbability = useMemo(
    () => {
      const values = vulnerabilities
        .map((item) => modelExploitRiskValue(item))
        .filter(
          (value): value is number =>
            typeof value === 'number' &&
            Number.isFinite(value),
        );

      return values.length
        ? Math.max(...values)
        : null;
    },
    [vulnerabilities],
  );""",
    text,
    flags=re.S,
)

# 5. Remove Wazuh tracking paragraph from hero section.
text = re.sub(
    r"""\s*<p>\s*\{snapshot\.agentName \?\? `Agent \$\{snapshot\.wazuhAgentId\}`\} đang được theo dõi qua Wazuh\.\s*Kết quả dưới đây tập trung vào các điểm cần chú ý nhất để bạn không bị ngợp bởi quá nhiều log kỹ thuật\.\s*</p>""",
    "",
    text,
    flags=re.S,
)

# 6. Replace operational risk card with AI predicted percentile card.
text = re.sub(
    r"""<article className=\{styles\.summaryCard\}>\s*<span>Điểm rủi ro vận hành</span>\s*<strong>\{snapshot\.riskScore\}</strong>\s*<small>\s*\{snapshot\.riskLabel\} · cập nhật \{formatDate\(snapshot\.calculatedAt\)\}\s*</small>\s*</article>""",
    """<article className={styles.summaryCard}>
                    <span>Rủi ro bị khai thác</span>
                    <strong>{formatProbability(modelExploitRiskValue(strongestPrediction))}</strong>
                    <small>
                      Percentile AI · cập nhật {formatDate(strongestPrediction?.aiPrediction?.predictedAt ?? snapshot.calculatedAt)}
                    </small>
                  </article>""",
    text,
    flags=re.S,
)

# 7. Quick action should use percentile-aware risk value.
text = text.replace(
    "formatProbability(strongestPrediction.aiPrediction?.attackProbability)",
    "formatProbability(modelExploitRiskValue(strongestPrediction))",
)

# 8. Replace card label and value for individual CVE.
text = text.replace(
    "<span>Xác suất AI</span>\n                                  <strong>{formatProbability(item.aiPrediction?.attackProbability)}</strong>",
    "<span>Rủi ro khai thác</span>\n                                  <strong>{formatProbability(modelExploitRiskValue(item))}</strong>",
)

# 9. Replace gauge explanation.
text = text.replace(
    "Đây là xác suất AI cao nhất trong các lỗ hổng ưu tiên của thiết bị ở lần kiểm tra hiện tại.",
    "Đây là percentile AI cao nhất trong các lỗ hổng active chưa khắc phục của thiết bị ở lần kiểm tra hiện tại.",
)

tsx.write_text(text, encoding="utf-8")

print(f"Patched: {tsx}")
print(f"Backup:  {backup_dir}")
