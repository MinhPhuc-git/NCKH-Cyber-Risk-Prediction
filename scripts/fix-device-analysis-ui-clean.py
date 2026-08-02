from pathlib import Path
from datetime import datetime
import shutil
import re

ROOT = Path(r"D:\LuanVan\test\cyrp-platform-phase2")
PATH = ROOT / "apps" / "user-web" / "src" / "components" / "device-analysis-button.tsx"

STAMP = datetime.now().strftime("%Y%m%d-%H%M%S")
BACKUP = PATH.with_suffix(".tsx.bak-clean-ui-fix-" + STAMP)

shutil.copy2(PATH, BACKUP)

text = PATH.read_text(encoding="utf-8")
old_text = text

# Remove a previously inserted full-prediction helper if it exists.
text = re.sub(
    r"\n\s*const allAiPredictionItems = useMemo\([\s\S]*?\n\s*\);\s*\n\s*(?=const sortedVulnerabilities = useMemo\()",
    "\n\n  ",
    text,
    count=1,
)

# Remove wrong top-level ATTACK PROBABILITY summary card.
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

# Ensure helper exists.
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

# Make vulnerabilities fetch larger so distribution is not based on a tiny preview list.
text = re.sub(
    r"params\.set\('limit',\s*'\d+'\);",
    "params.set('limit', '500');",
    text,
)

text = re.sub(
    r'params\.set\("limit",\s*"\d+"\);',
    'params.set("limit", "500");',
    text,
)

# Keep sortedVulnerabilities based on vulnerabilities, not on itself.
sort_start = text.find("const sortedVulnerabilities = useMemo(")
sort_end = text.find("const strongestPrediction", sort_start)

if sort_start != -1 and sort_end != -1:
    block = text[sort_start:sort_end]
    block = block.replace("[...sortedVulnerabilities]", "[...vulnerabilities]")
    block = block.replace("[sortedVulnerabilities],", "[vulnerabilities],")
    text = text[:sort_start] + block + text[sort_end:]

# Keep aiDistribution based on vulnerabilities after increasing API limit.
dist_start = text.find("const aiDistribution = useMemo")
dist_end = text.find("const maxDistributionCount", dist_start)

if dist_start != -1 and dist_end != -1:
    block = text[dist_start:dist_end]
    block = block.replace("for (const item of sortedVulnerabilities) {", "for (const item of vulnerabilities) {")
    block = block.replace("for (const item of allAiPredictionItems) {", "for (const item of vulnerabilities) {")
    block = block.replace(
        "const level = String(item?.aiPrediction?.riskLevel ?? item?.riskLevel ?? '').toUpperCase();",
        "const level = item.aiPrediction?.riskLevel?.toUpperCase();",
    )
    block = block.replace("[sortedVulnerabilities],", "[vulnerabilities],")
    block = block.replace("[allAiPredictionItems],", "[vulnerabilities],")
    text = text[:dist_start] + block + text[dist_end:]

# Fix possible malformed spread from previous patches.
text = text.replace("Math.max(1, .aiDistribution.map", "Math.max(1, ...aiDistribution.map")

# Add Attack probability stat chip next to Percentile inside each CVE card.
if "<span>Attack probability</span>" not in text:
    chip_pattern = re.compile(
        r"""<div className=\{styles\.statChip\}>\s*
\s*<span>(?:Rủi ro khai thác|Rủi ro bị khai thác|PERCENTILE|Percentile)</span>\s*
\s*<strong>\{formatProbability\(modelExploitRiskValue\(item\)\)\}</strong>\s*
\s*</div>""",
        flags=re.MULTILINE,
    )

    replacement = """<div className={styles.statChip}>
                                  <span>Percentile</span>
                                  <strong>{formatProbability(modelExploitRiskValue(item))}</strong>
                                </div>
                                <div className={styles.statChip}>
                                  <span>Attack probability</span>
                                  <strong>{formatProbability(modelAttackProbabilityValue(item))}</strong>
                                </div>"""

    text, replaced = chip_pattern.subn(replacement, text, count=1)

    if replaced == 0:
        print("[WARN] Không tìm thấy statChip Percentile/Rủi ro khai thác để thêm Attack probability.")

# Ensure top summary label is Percentile.
text = text.replace("<span>Rủi ro bị khai thác</span>", "<span>Percentile</span>")
text = text.replace("<span>Rủi ro khai thác</span>", "<span>Percentile</span>")

# Update hint text if present.
text = text.replace(
    "Chỉ hiển thị ngắn gọn các mục cần quan tâm nhất. Nhấn “Xem chi tiết” để đọc thêm.",
    "Chỉ hiển thị ngắn gọn các mục cần quan tâm nhất. Phân bố AI phía trên được tính từ danh sách active đã tải.",
)

PATH.write_text(text, encoding="utf-8")

print("Patched:", PATH)
print("Backup:", BACKUP)
print("Changed:", old_text != text)
