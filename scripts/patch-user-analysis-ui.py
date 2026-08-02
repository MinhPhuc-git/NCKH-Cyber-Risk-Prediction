from pathlib import Path
from datetime import datetime
import re
import shutil

ROOT = Path(r"D:\LuanVan\test\cyrp-platform-phase2")
USER_SRC = ROOT / "apps" / "user-web" / "src"
API_SRC = ROOT / "apps" / "api" / "src"

STAMP = datetime.now().strftime("%Y%m%d-%H%M%S")
BACKUP_ROOT = ROOT / ".phase-backups" / f"user-analysis-ui-{STAMP}"
BACKUP_ROOT.mkdir(parents=True, exist_ok=True)

changed = []
warnings = []

def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")

def write_text(path: Path, text: str):
    path.write_text(text, encoding="utf-8")

def backup(path: Path):
    rel = path.relative_to(ROOT)
    dst = BACKUP_ROOT / rel
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(path, dst)

def save_if_changed(path: Path, old: str, new: str, reason: str):
    if old != new:
        backup(path)
        write_text(path, new)
        changed.append((str(path.relative_to(ROOT)), reason))

def patch_label_text():
    for path in list(USER_SRC.rglob("*.tsx")) + list(USER_SRC.rglob("*.ts")):
        old = read_text(path)
        new = old

        replacements = {
            "KIẾN TRÚC": "KIẾN TRÚC CPU",
            "RỦI RO BỊ KHAI THÁC": "PERCENTILE",
            "THIẾT BỊ": "TÊN THIẾT BỊ",
        }

        for src, dst in replacements.items():
            new = new.replace(src, dst)

        # Chỉ đổi label AGENT dạng chữ in hoa, tránh đụng biến agent.
        new = re.sub(r'(?<![A-Za-z0-9_])AGENT(?![A-Za-z0-9_])', 'WAZUH AGENT', new)

        save_if_changed(path, old, new, "label text")

def patch_phase_agent_fallback():
    files = [
        p for p in USER_SRC.rglob("*.tsx")
        if "phase-2b2" in read_text(p)
    ]

    for path in files:
        old = read_text(path)
        new = old

        # Trường hợp hard-code trực tiếp trong JSX.
        new = new.replace(
            ">phase-2b2<",
            ">{device?.wazuhAgentId ?? device?.wazuhBinding?.wazuhAgentId ?? device?.agentId ?? '—'}<"
        )

        # Trường hợp fallback string trong biểu thức.
        new = new.replace("'phase-2b2'", "'—'")
        new = new.replace('"phase-2b2"', '"—"')

        save_if_changed(path, old, new, "remove phase-2b2 fallback")

        if "phase-2b2" in read_text(path):
            warnings.append(f"Still contains phase-2b2: {path.relative_to(ROOT)}")

def patch_backend_top_predictions_count():
    service = API_SRC / "modules" / "security-data" / "ai-pipeline-check.service.ts"
    if not service.exists():
        warnings.append("Cannot find ai-pipeline-check.service.ts")
        return

    old = read_text(service)
    new = old

    # Cho frontend có đủ dữ liệu để tính phân bố, thay vì chỉ top 8/10.
    new = new.replace("take: 10,", "take: 500,")
    new = new.replace(".slice(0, 10)", ".slice(0, 500)")
    new = new.replace(".slice(0, 8)", ".slice(0, 500)")

    save_if_changed(service, old, new, "backend topPredictions count")

def patch_distribution_logic():
    candidate_files = []
    for path in USER_SRC.rglob("*.tsx"):
        text = read_text(path)
        if "Phân bố mức rủi ro AI" in text or "topPredictions" in text or "predictedPercentile" in text:
            candidate_files.append(path)

    if not candidate_files:
        warnings.append("No TSX file found for AI risk distribution.")
        return

    for path in candidate_files:
        old = read_text(path)
        new = old

        # Thêm helper nếu file đang xử lý kết quả AI prediction.
        if ("topPredictions" in new or "predictedPercentile" in new) and "function buildAiRiskDistribution" not in new:
            insert = r'''
function normalizeAiRiskLevel(value: unknown): 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | 'UNKNOWN' {
  const level = String(value ?? '').trim().toUpperCase();

  if (level === 'LOW' || level === 'THẤP') {
    return 'LOW';
  }

  if (level === 'MEDIUM' || level === 'TRUNG BÌNH' || level === 'TRUNG_BINH') {
    return 'MEDIUM';
  }

  if (level === 'HIGH' || level === 'CAO') {
    return 'HIGH';
  }

  if (
    level === 'CRITICAL' ||
    level === 'VERY_HIGH' ||
    level === 'VERY HIGH' ||
    level === 'RẤT CAO' ||
    level === 'RAT CAO'
  ) {
    return 'CRITICAL';
  }

  return 'UNKNOWN';
}

function buildAiRiskDistribution(items: Array<{ riskLevel?: unknown }>) {
  const result = {
    low: 0,
    medium: 0,
    high: 0,
    critical: 0,
  };

  for (const item of items ?? []) {
    const level = normalizeAiRiskLevel(item.riskLevel);

    if (level === 'LOW') {
      result.low += 1;
    } else if (level === 'MEDIUM') {
      result.medium += 1;
    } else if (level === 'HIGH') {
      result.high += 1;
    } else if (level === 'CRITICAL') {
      result.critical += 1;
    }
  }

  return result;
}

function toPercent(value: unknown, mode: 'probability' | 'percentile' = 'probability') {
  const numberValue = Number(value);

  if (!Number.isFinite(numberValue)) {
    return null;
  }

  if (mode === 'probability') {
    return numberValue <= 1 ? numberValue * 100 : numberValue;
  }

  return numberValue;
}

'''

            # Chèn helper sau cụm import cuối cùng.
            matches = list(re.finditer(r"^import .+?;\s*$", new, flags=re.MULTILINE))
            if matches:
                pos = matches[-1].end()
                new = new[:pos] + "\n" + insert + new[pos:]
            else:
                new = insert + "\n" + new

        # Nếu file đang có distribution tính từ mảng preview/priority, đổi sang topPredictions.
        new = re.sub(
            r"buildAiRiskDistribution\((priorityVulnerabilities|visibleVulnerabilities|displayedVulnerabilities|shownVulnerabilities)\)",
            "buildAiRiskDistribution(topPredictions)",
            new,
        )

        # Nếu có biến distribution thủ công đếm từ priority list, ít nhất đánh dấu warning để vá tiếp.
        if "Phân bố mức rủi ro AI" in new and "buildAiRiskDistribution(topPredictions)" not in new and "aiRiskDistribution" not in new:
            warnings.append(
                f"Distribution file needs manual check: {path.relative_to(ROOT)}"
            )

        save_if_changed(path, old, new, "distribution helpers")

def patch_attack_probability_card():
    candidates = []
    for path in USER_SRC.rglob("*.tsx"):
        text = read_text(path)
        if "PERCENTILE" in text or "predictedPercentile" in text:
            candidates.append(path)

    if not candidates:
        warnings.append("No TSX file found for PERCENTILE / predictedPercentile.")
        return

    for path in candidates:
        old = read_text(path)
        new = old

        if "ATTACK PROBABILITY" in new:
            continue

        # Cố gắng tìm block stat card có PERCENTILE và nhân bản thành ATTACK PROBABILITY.
        # Đây là patch có kiểm soát: chỉ chạy nếu thấy block rõ ràng.
        pattern = re.compile(
            r"(?P<block><(?P<tag>div|article|section)[^>]*className=\{[^}]*\}[^>]*>\s*"
            r"(?:(?!</(?P=tag)>).)*?PERCENTILE(?:(?!</(?P=tag)>).)*?</(?P=tag)>)",
            flags=re.DOTALL,
        )

        match = pattern.search(new)

        if not match:
            warnings.append(f"Could not auto-insert ATTACK PROBABILITY card: {path.relative_to(ROOT)}")
            continue

        block = match.group("block")

        # Tạo block mới. Ưu tiên biến topPredictions[0].attackProbability nếu nằm trong scope.
        attack_block = block
        attack_block = attack_block.replace("PERCENTILE", "ATTACK PROBABILITY")

        # Thay phần % trong block nếu có biểu thức percentile phổ biến.
        attack_block = attack_block.replace("predictedPercentile", "attackProbability")
        attack_block = attack_block.replace("highestPercentile", "highestAttackProbability")
        attack_block = attack_block.replace("maxPercentile", "maxAttackProbability")

        # Nếu vẫn không có attackProbability thì thêm warning, nhưng vẫn insert để người dùng thấy cần kiểm tra.
        if "attackProbability" not in attack_block and "highestAttackProbability" not in attack_block:
            warnings.append(f"Inserted ATTACK PROBABILITY label but value expression may need manual edit: {path.relative_to(ROOT)}")

        insert_at = match.end()
        new = new[:insert_at] + "\n" + attack_block + new[insert_at:]

        save_if_changed(path, old, new, "attack probability card")
        break

def patch_css_center_blocks():
    css_files = list(USER_SRC.rglob("*.css")) + list(USER_SRC.rglob("*.scss"))
    if not css_files:
        warnings.append("No CSS/SCSS file found under user-web src.")
        return

    target_files = []
    for path in css_files:
        text = read_text(path)
        if any(name in text for name in [
            "statCard",
            "metricCard",
            "summaryCard",
            "statsGrid",
            "analysis",
            "distribution",
        ]):
            target_files.append(path)

    if not target_files:
        target_files = css_files[:1]

    css_patch = r'''

/* CYRP UI patch: center metric/stat blocks */
.statCard,
.metricCard,
.summaryCard,
.deviceStatCard,
.analysisStatCard,
.riskCard,
.scoreCard {
  text-align: center;
  align-items: center;
  justify-content: center;
}

.statCard span,
.statCard strong,
.statCard small,
.metricCard span,
.metricCard strong,
.metricCard small,
.summaryCard span,
.summaryCard strong,
.summaryCard small,
.deviceStatCard span,
.deviceStatCard strong,
.deviceStatCard small,
.analysisStatCard span,
.analysisStatCard strong,
.analysisStatCard small,
.riskCard span,
.riskCard strong,
.riskCard small,
.scoreCard span,
.scoreCard strong,
.scoreCard small {
  text-align: center;
}

.statsGrid,
.metricGrid,
.analysisStatsGrid {
  align-items: stretch;
}
'''

    for path in target_files:
        old = read_text(path)
        if "CYRP UI patch: center metric/stat blocks" in old:
            continue

        new = old.rstrip() + "\n" + css_patch + "\n"
        save_if_changed(path, old, new, "center stat cards css")

def print_contexts():
    print("\n=== Files containing target UI labels ===")
    for path in USER_SRC.rglob("*.tsx"):
        text = read_text(path)
        if any(s in text for s in [
            "KIẾN TRÚC CPU",
            "WAZUH AGENT",
            "TÊN THIẾT BỊ",
            "PERCENTILE",
            "ATTACK PROBABILITY",
            "Phân bố mức rủi ro AI",
            "phase-2b2",
        ]):
            print(path.relative_to(ROOT))

patch_label_text()
patch_phase_agent_fallback()
patch_backend_top_predictions_count()
patch_distribution_logic()
patch_attack_probability_card()
patch_css_center_blocks()

print(f"\nBackup root: {BACKUP_ROOT}")

print("\n=== Changed files ===")
for item, reason in changed:
    print(f"- {item} [{reason}]")

if not changed:
    print("- No files changed.")

print("\n=== Warnings ===")
if warnings:
    for warning in warnings:
        print(f"- {warning}")
else:
    print("- None")

print_contexts()
