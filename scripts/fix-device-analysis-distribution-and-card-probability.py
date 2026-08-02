from pathlib import Path
from datetime import datetime
import shutil
import re

ROOT = Path(r"D:\LuanVan\test\cyrp-platform-phase2")
PATH = ROOT / "apps" / "user-web" / "src" / "components" / "device-analysis-button.tsx"

STAMP = datetime.now().strftime("%Y%m%d-%H%M%S")
BACKUP = PATH.with_suffix(".tsx.bak-fix-distribution-and-cve-attack-probability-" + STAMP)

shutil.copy2(PATH, BACKUP)

text = PATH.read_text(encoding="utf-8")
old_text = text

# 1) Remove wrongutil.copy2(PATH, BACKUP)

text = PATH.read_text(encoding=" top-level ATTACK PROBABILITY summary card.
text = re.sub(
    r"""\s+<article className=\{styles\.summaryCard\}>\s*
\s*<span>Attack probability</span>\s*
\s*<strong>\{formatProbability\(modelAttackProbabilityValue\(strongestPrediction\)\)\}</strong>\s*
\s*<small>\s*
\s*Attack probability AI · cập nhật \{formatDate\(strongestPrediction\?\.aiPrediction\?\.predictedAt \?\? snapshot\.calculatedAt\)\}\s*
\s*</small>\s*
\s*</article>""",
    "",
    text,
    flags=re.MULTILINE,
)

# 2) Ensure helper exists.
if "function modelAttackProbabilityValue(" not in text:
    marker = "function modelExploitRiskValue("
    idx = text.find(marker)
    if idx == -1:
        raise SystemExit("Không tìm thấy function modelExploitRiskValue để chèn helper.")
    helper = """function modelAttackProbabilityValue(
  item: VulnerabilityItem | null | undefined,
): number | null {
  return normalizeProbabilityLikeValue(
    item?.aiPrediction?.attackProbability,
  );
}

"""
    text = text[:idx] + helper + text[idx:]

# 3) Add ATTACK PROBABILITY stat chip next to PERCENTILE in each CVE card.
if "<span>Attack probability</span>" not in text:
    # Pattern after previous label patch: Percentile chip.
    old_chip = """<div className={styles.statChip}>
                                  <span>Percentile</span>
                                  <strong>{formatProbability(modelExploitRiskValue(item))}</strong>
                                </div>"""

    new_chip = """<div className={styles.statChip}>
                                  <span>Percentile</span>
                                  <strong>{formatProbability(modelExploitRiskValue(item))}</strong>
                                </div>
                                <div className={styles.statChip}>
                                  <span>Attack probability</span>
                                  <strong>{formatProbability(modelAttackProbabilityValue(item))}</strong>
                                </div>"""

    if old_chip not in text:
        # Fallback for original label still present.
        old_chip_2 = """<div className={styles.statChip}>
                                  <span>Rủi ro khai thác</span>
                                  <strong>{formatProbability(modelExploitRiskValue(item))}</strong>
                                </div>"""
        if old_chip_2 in text:
            text = text.replace(old_chip_2, new_chip)
        else:
            raise SystemExit("Không tìm thấy statChip Percentile/Rủi ro khai thác trong CVE card. Gửi lại lines 1015-1030.")
    else:
        text = text.replace(old_chip, new_chip)

# 4) Create a full prediction source. It must use API result.topPredictions, not preview vulnerabilities.
# Try common state names used in this component.
if "const allAiPredictionItems = useMemo" not in text:
    insert_marker = "const sortedVulnerabilities = useMemo("
    idx = text.find(insert_marker)
    if idx == -1:
        raise SystemExit("Không tìm thấy sortedVulnerabilities để chèn allAiPredictionItems.")

    helper_block = """const allAiPredictionItems = useMemo(
    () => {
      const source =
        result?.topPredictions ??
        analysisResult?.topPredictions ??
        latestResult?.topPredictions ??
        [];

      return Array.isArray(source) ? source : [];
    },
    [result, analysisResult, latestResult],
  );

  """

    text = text[:idx] + helper_block + text[idx:]

# 5) Make AI distribution count from allAiPredictionItems.
pattern = re.compile(
    r"""const aiDistribution = useMemo<RiskBucketRow\[]>\(
\s*\(\) => \{
\s*const counts: Record<RiskBucketKey, number> = \{
\s*LOW: 0,
\s*MEDIUM: 0,
\s*HIGH: 0,
\s*CRITICAL: 0,
\s*\};
\s*
\s*for \(const item of [^)]+?\) \{
\s*const level = item\.aiPrediction\?\.riskLevel\?\.toUpperCase\(\);
\s*if \(level === 'LOW' \|\| level === 'MEDIUM' \|\| level === 'HIGH' \|\| level === 'CRITICAL'\) \{
\s*counts\[level\] \+= 1;
\s*\}
\s*\}
""",
    flags=re.MULTILINE,
)

replacement = """const aiDistribution = useMemo<RiskBucketRow[]>(
    () => {
      const counts: Record<RiskBucketKey, number> = {
        LOW: 0,
        MEDIUM: 0,
        HIGH: 0,
        CRITICAL: 0,
      };

      for (const item of allAiPredictionItems) {
        const level = String(item?.aiPrediction?.riskLevel ?? item?.riskLevel ?? '').toUpperCase();

        if (level === 'LOW' || level === 'MEDIUM' || level === 'HIGH' || level === 'CRITICAL') {
          counts[level] += 1;
        }
      }
"""

text, count = pattern.subn(replacement, text, count=1)

if count == 0:
    print("[WARN] Không match toàn bộ aiDistribution block, vá fallback từng dòng.")
    text = text.replace(
        "for (const item of sortedVulnerabilities) {",
        "for (const item of allAiPredictionItems) {",
    )
    text = text.replace(
        "const level = item.aiPrediction?.riskLevel?.toUpperCase();",
        "const level = String(item?.aiPrediction?.riskLevel ?? item?.riskLevel ?? '').toUpperCase();",
    )

# 6) Update dependency array of aiDistribution only, not sortedVulnerabilities.
dist_start = text.find("const aiDistribution = useMemo")
dist_end = text.find("const maxDistributionCount", dist_start)
if dist_start != -1 and dist_end != -1:
    block = text[dist_start:dist_end]
    block = block.replace("[sortedVulnerabilities],", "[allAiPredictionItems],")
    block = block.replace("[vulnerabilities],", "[allAiPredictionItems],")
    text = text[:dist_start] + block + text[dist_end:]

# 7) Keep sortedVulnerabilities initialized from vulnerabilities, not from itself.
sort_start = text.find("const sortedVulnerabilities = useMemo(")
sort_end = text.find("const strongestPrediction", sort_start)
if sort_start != -1 and sort_end != -1:
    block = text[sort_start:sort_end]
    block = block.replace("[...sortedVulnerabilities]", "[...vulnerabilities]")
    block = block.replace("[sortedVulnerabilities],", "[vulnerabilities],")
    text = text[:sort_start] + block + text[sort_end:]

# 8) Update small hint from 8 preview items to full prediction count.
text = text.replace(
    "{sortedVulnerabilities.length} lỗ hổng có AI prediction đang được tổng hợp",
    "{allAiPredictionItems.length} lỗ hổng có AI prediction đang được tổng hợp"
)
text = text.replace(
    "{vulnerabilities.length} lỗ hổng ưu tiên đang hiển thị",
    "{allAiPredictionItems.length} lỗ hổng có AI prediction đang được tổng hợp"
)

PATH.write_text(text, encoding="utf-8")

print("Patched:", PATH)
print("Backup:", BACKUP)
print("Changed:", old_text != text)
