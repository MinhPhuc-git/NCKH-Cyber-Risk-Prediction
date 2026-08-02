from pathlib import Path
from datetime import datetime
import shutil
import re

ROOT = Path(r"D:\LuanVan\test\cyrp-platform-phase2")
STAMP = datetime.now().strftime("%Y%m%d-%H%M%S")
BACKUP = ROOT / ".phase-backups" / f"fix-user-ui-real-files-{STAMP}"
BACKUP.mkdir(parents=True, exist_ok=True)

changed = []

def backup_file(path: Path):
    rel = path.relative_to(ROOT)
    dst = BACKUP / rel
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(path, dst)

def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")

def write(path: Path, text: str):
    path.write_text(text, encoding="utf-8")

def save(path: Path, old: str, new: str, reason: str):
    if old != new:
        backup_file(path)
        write(path, new)
        changed.append((str(path.relative_to(ROOT)), reason))

def fix_vulnerabilities_client_build():
    path = ROOT / "apps" / "user-web" / "src" / "app" / "vulnerabilities" / "vulnerabilities-client.tsx"
    if not path.exists():
        print("[WARN] missing:", path)
        return

    old = read(path)
    new = old

    # Nếu file đang dùng riskLevel/setRiskLevel trong JSX nhưng thiếu useState thì thêm lại.
    if "riskLevel" in new and "setRiskLevel" in new and "const [riskLevel, setRiskLevel]" not in new:
        # Chèn sau query/page state phổ biến.
        patterns = [
            r"(const \[query,\s*setQuery\]\s*=\s*useState\([^;]*\);\s*)",
            r"(const \[page,\s*setPage\]\s*=\s*useState\([^;]*\);\s*)",
            r"(const \[status,\s*setStatus\]\s*=\s*useState\([^;]*\);\s*)",
        ]

        inserted = False
        for pattern in patterns:
            match = re.search(pattern, new)
            if match:
                insert_at = match.end()
                new = new[:insert_at] + "\n  const [riskLevel, setRiskLevel] = useState('');" + new[insert_at:]
                inserted = True
                break

        if not inserted:
            # Chèn sau dòng export function nếu không tìm được state nào.
            new = re.sub(
                r"(export function [A-Za-z0-9_]+\([^)]*\)\s*\{\s*)",
                r"\1\n  const [riskLevel, setRiskLevel] = useState('');\n",
                new,
                count=1,
            )

    save(path, old, new, "fix missing riskLevel state")

def fix_devices_page_agent_card():
    path = ROOT / "apps" / "user-web" / "src" / "app" / "devices" / "devices-page-client.tsx"
    if not path.exists():
        print("[WARN] missing:", path)
        return

    old = read(path)
    new = old

    new = new.replace("<span>Agent</span>", "<span>Wazuh Agent</span>")

    old_block = """<strong>{device.agentVersion}</strong>"""

    new_block = """<strong>
                  {device.wazuhBinding?.wazuhAgentId
                    ? `ID ${device.wazuhBinding.wazuhAgentId}`
                    : device.agentVersion && !device.agentVersion.toLowerCase().includes('phase')
                      ? device.agentVersion
                      : 'CYRP Agent'}
                </strong>"""

    new = new.replace(old_block, new_block)

    # Nếu TypeScript type của device chưa có wazuhBinding trong file này thì fallback qua any để tránh build fail.
    if "device.wazuhBinding?.wazuhAgentId" in new and "const displayWazuhAgentId" not in new:
        # Đổi expression trực tiếp sang optional access qua any.
        new = new.replace(
            "device.wazuhBinding?.wazuhAgentId\n                    ? `ID ${device.wazuhBinding.wazuhAgentId}`",
            "(device as { wazuhBinding?: { wazuhAgentId?: string | null } | null }).wazuhBinding?.wazuhAgentId\n                    ? `ID ${(device as { wazuhBinding?: { wazuhAgentId?: string | null } | null }).wazuhBinding?.wazuhAgentId}`"
        )

    save(path, old, new, "device hero Wazuh Agent card")

def fix_device_analysis_button():
    path = ROOT / "apps" / "user-web" / "src" / "components" / "device-analysis-button.tsx"
    if not path.exists():
        print("[WARN] missing:", path)
        return

    old = read(path)
    new = old

    # 1) Summary card label.
    new = new.replace("<span>Thiết bị</span>", "<span>Tên thiết bị agent</span>")
    new = new.replace("<span>Rủi ro bị khai thác</span>", "<span>Percentile</span>")
    new = new.replace("<span>Rủi ro khai thác</span>", "<span>Percentile</span>")

    # 2) Thêm helper attackProbability nếu chưa có.
    if "function modelAttackProbabilityValue(" not in new:
        marker = "function modelExploitRiskValue("
        idx = new.find(marker)
        if idx != -1:
            helper = """function modelAttackProbabilityValue(
  item: VulnerabilityItem | null | undefined,
): number | null {
  return normalizeProbabilityLikeValue(
    item?.aiPrediction?.attackProbability,
  );
}

"""
            new = new[:idx] + helper + new[idx:]

    # 3) Thêm card ATTACK PROBABILITY sau card Percentile ở summaryGrid nếu chưa có.
    if "Attack probability AI" not in new:
        summary_card_pattern = re.compile(
            r"""(\s+<article className=\{styles\.summaryCard\}>\s*
\s*<span>Percentile</span>\s*
\s*<strong>\{formatProbability\(modelExploitRiskValue\(strongestPrediction\)\)\}</strong>\s*
\s*<small>\s*
\s*Percentile AI · cập nhật \{formatDate\(strongestPrediction\?\.aiPrediction\?\.predictedAt \?\? snapshot\.calculatedAt\)\}\s*
\s*</small>\s*
\s*</article>)""",
            re.MULTILINE,
        )

        match = summary_card_pattern.search(new)

        if match:
            block = match.group(1)
            attack_block = """
                  <article className={styles.summaryCard}>
                    <span>Attack probability</span>
                    <strong>{formatProbability(modelAttackProbabilityValue(strongestPrediction))}</strong>
                    <small>
                      Attack probability AI · cập nhật {formatDate(strongestPrediction?.aiPrediction?.predictedAt ?? snapshot.calculatedAt)}
                    </small>
                  </article>"""
            new = new[:match.end()] + attack_block + new[match.end():]
        else:
            print("[WARN] Could not auto-insert summary Attack probability card. Will still patch item cards.")

    # 4) Thêm statChip ATTACK PROBABILITY trong từng CVE card nếu chưa có.
    if "<span>Attack probability</span>" not in new:
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

        new = new.replace(old_chip, new_chip)

    # 5) Phân bố AI: đếm từ sortedVulnerabilities nếu có nhiều hơn, thay vì biến vulnerabilities có thể là preview.
    new = new.replace("for (const item of vulnerabilities) {", "for (const item of sortedVulnerabilities) {")
    new = new.replace("[vulnerabilities],", "[sortedVulnerabilities],")

    # 6) Dòng mô tả số hiển thị.
    new = new.replace(
        "{vulnerabilities.length} lỗ hổng ưu tiên đang hiển thị",
        "{sortedVulnerabilities.length} lỗ hổng có AI prediction đang được tổng hợp"
    )

    save(path, old, new, "device analysis UI cards and distribution")

def fix_css_centering():
    path = ROOT / "apps" / "user-web" / "src" / "components" / "device-analysis-button.module.css"
    if not path.exists():
        print("[WARN] missing:", path)
        return

    old = read(path)
    new = old

    patch = """

/* CYRP patch: center analysis metric cards */
.summaryCard,
.statChip {
  text-align: center;
  align-items: center;
  justify-content: center;
}

.summaryCard span,
.summaryCard strong,
.summaryCard small,
.statChip span,
.statChip strong {
  text-align: center;
}
"""

    if "CYRP patch: center analysis metric cards" not in new:
        new = new.rstrip() + patch + "\n"

    save(path, old, new, "center summary/stat chips")

fix_vulnerabilities_client_build()
fix_devices_page_agent_card()
fix_device_analysis_button()
fix_css_centering()

print("Backup:", BACKUP)
print("Changed:")
for file, reason in changed:
    print("-", file, "[" + reason + "]")
