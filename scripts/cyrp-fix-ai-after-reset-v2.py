from pathlib import Path
from datetime import datetime
import shutil
import re

ROOT = Path(r"D:\LuanVan\test\cyrp-platform-phase2")


def backup(path: Path) -> Path:
    b = path.with_suffix(path.suffix + ".bak-ai-after-reset-v2-" + datetime.now().strftime("%Y%m%d-%H%M%S"))
    shutil.copy2(path, b)
    return b


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def write(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")


def patch_delta_service() -> None:
    path = ROOT / "apps/api/src/modules/security-data/cve-lifecycle-delta.service.ts"
    if not path.exists():
        raise SystemExit(f"Không tìm thấy file: {path}")
    b = backup(path)
    text = read(path)

    # Fix accidental duplicated split if present.
    text = text.replace(
        ".split(/\\r?\\n/)\n      .split(/\\r?\\n/)",
        ".split(/\\r?\\n/)",
    )

    # Existing pairs must mean AI-processed pairs only. If a row has no aiPrediction,
    # it must be queued again after reset.
    old = """        status: {
          in: [
            VulnerabilityLifecycleStatus.ACTIVE,
            VulnerabilityLifecycleStatus.UNDER_EVALUATION,
          ],
        },
"""
    new = """        status: {
          in: [
            VulnerabilityLifecycleStatus.ACTIVE,
            VulnerabilityLifecycleStatus.UNDER_EVALUATION,
          ],
        },
        aiPrediction: { isNot: null },
"""
    if "aiPrediction: { isNot: null }" not in text:
        if old not in text:
            raise SystemExit("Không tìm thấy where.status block trong cve-lifecycle-delta.service.ts")
        text = text.replace(old, new, 1)

    text = re.sub(
        r"const lastProcessedAt =\s*row\.aiPrediction\?\.predictedAt \?\?\s*row\.lastSeenAt \?\?\s*row\.firstSeenAt \?\?\s*null;",
        "const lastProcessedAt = row.aiPrediction?.predictedAt ?? null;",
        text,
        count=1,
    )

    # Add a DB-side safety net: append active Wazuh rows without AI prediction to LIST_CVE_ID.csv.
    if "appendMissingAiPredictionRows" not in text:
        marker = "    const queueCount = await this.countCsvRows(listCvePath);"
        replacement = """    const missingAiRowsQueued = await this.appendMissingAiPredictionRows(agentId, listCvePath);
    const queueCount = await this.countCsvRows(listCvePath);
"""
        if marker not in text:
            raise SystemExit("Không tìm thấy queueCount marker trong cve-lifecycle-delta.service.ts")
        text = text.replace(marker, replacement, 1)

        method_marker = "  private async applyResolvedPairs("
        method = r'''
  private async appendMissingAiPredictionRows(
    agentId: string,
    listCvePath: string,
  ): Promise<number> {
    const rows = await this.database.detectedVulnerability.findMany({
      where: {
        wazuhAgentId: agentId,
        status: {
          in: [
            VulnerabilityLifecycleStatus.ACTIVE,
            VulnerabilityLifecycleStatus.UNDER_EVALUATION,
          ],
        },
        sourceIndex: { not: 'ai-pipeline-data-user' },
        aiPrediction: null,
      },
      select: {
        cveId: true,
        wazuhAgentId: true,
      },
      orderBy: [
        { wazuhAgentId: 'asc' },
        { cveId: 'asc' },
      ],
    });

    if (rows.length === 0) {
      return 0;
    }

    const existingText = await this.readTextIfExists(listCvePath);
    const pairs = new Map<string, { cveId: string; agentId: string }>();

    const lines = existingText
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter(Boolean);

    if (lines.length > 1) {
      const header = lines[0].replace(/^\ufeff/, '').split(',').map((item) => item.trim().toLowerCase());
      const cveIndex = header.findIndex((item) => ['cve_id', 'cve', 'cveid'].includes(item));
      const agentIndex = header.findIndex((item) => ['agent_id', 'wazuh_agent_id', 'agent.id'].includes(item));

      if (cveIndex >= 0) {
        for (const line of lines.slice(1)) {
          const cols = line.split(',').map((item) => item.replace(/^"|"$/g, '').trim());
          const cveId = cols[cveIndex]?.toUpperCase();
          const rowAgentId = agentIndex >= 0 ? cols[agentIndex] : agentId;

          if (cveId?.startsWith('CVE-')) {
            pairs.set(`${rowAgentId}|${cveId}`, { cveId, agentId: rowAgentId });
          }
        }
      }
    }

    let added = 0;

    for (const row of rows) {
      const cveId = row.cveId.toUpperCase();
      const rowAgentId = row.wazuhAgentId;
      const key = `${rowAgentId}|${cveId}`;

      if (!pairs.has(key)) {
        pairs.set(key, { cveId, agentId: rowAgentId });
        added += 1;
      }
    }

    const outputRows = [...pairs.values()].sort((left, right) => {
      const byAgent = left.agentId.localeCompare(right.agentId);
      return byAgent !== 0 ? byAgent : left.cveId.localeCompare(right.cveId);
    });

    const csv = [
      'CVE_ID,agent_id',
      ...outputRows.map((row) => [this.csvCell(row.cveId), this.csvCell(row.agentId)].join(',')),
    ].join('\n');

    await writeFile(listCvePath, csv, 'utf8');

    const compatPath = join(dirname(listCvePath), 'List_CVE_ID.csv');
    await writeFile(compatPath, csv, 'utf8');

    if (added > 0) {
      this.logger.log(`Queued ${added} active Wazuh vulnerability row(s) without AI prediction for agent=${agentId}`);
    }

    return added;
  }

'''
        if method_marker not in text:
            raise SystemExit("Không tìm thấy vị trí chèn appendMissingAiPredictionRows")
        text = text.replace(method_marker, method + method_marker, 1)

    write(path, text)
    print(f"Patched delta service: {path}")
    print(f"Backup: {b}")


def patch_importer_no_fallback() -> None:
    path = ROOT / "apps/api/src/modules/security-data/ai-pipeline-data-user-import.service.ts"
    if not path.exists():
        raise SystemExit(f"Không tìm thấy file: {path}")
    b = backup(path)
    text = read(path)

    if "AI_IMPORT_SKIPPED_NO_WAZUH_ROW" not in text:
        start = text.find("    await this.database.cve.upsert({")
        end_marker = "    return { detection, created: true, reason: 'CREATED_DETECTED_VULNERABILITY' };"
        end = text.find(end_marker, start)

        if start < 0 or end < 0:
            raise SystemExit("Không tìm thấy fallback create block trong ai-pipeline-data-user-import.service.ts")

        end = end + len(end_marker)
        replacement = """    return {
      detection: null,
      created: false,
      reason:
        `AI_IMPORT_SKIPPED_NO_WAZUH_ROW: Không tìm thấy detected_vulnerabilities từ Wazuh cho ${record.cveId}/${agentId}. Hãy đồng bộ Wazuh trước; importer không tạo fallback ai-pipeline-data-user.`,
    };"""
        text = text[:start] + replacement + text[end:]

    write(path, text)
    print(f"Patched importer no fallback: {path}")
    print(f"Backup: {b}")


def patch_user_modal_distribution() -> None:
    path = ROOT / "apps/user-web/src/components/device-analysis-button.tsx"
    if not path.exists():
        raise SystemExit(f"Không tìm thấy file: {path}")
    b = backup(path)
    text = read(path)

    if "function percentileBucketKey" not in text:
        insert_after = "function toPercent(value: unknown, mode: 'probability' | 'percentile' = 'probability') {"
        idx = text.find(insert_after)
        if idx < 0:
            raise SystemExit("Không tìm thấy function toPercent để chèn percentileBucketKey")
        # Put helper before toPercent.
        helper = """function percentileBucketKey(value: number | null): 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | null {
  if (value === null || !Number.isFinite(value)) {
    return null;
  }

  const percent = value <= 1 ? value * 100 : value;

  if (percent >= 85) {
    return 'CRITICAL';
  }

  if (percent >= 65) {
    return 'HIGH';
  }

  if (percent >= 45) {
    return 'MEDIUM';
  }

  return 'LOW';
}

"""
        text = text[:idx] + helper + text[idx:]

    if "let aiPredictionTotal = 0;" not in text:
        text = text.replace(
            "    let loaded = 0;\n    let total = 0;\n    let highestAttackProbability: number | null = null;",
            "    let loaded = 0;\n    let total = 0;\n    let aiPredictionTotal = 0;\n    let highestAttackProbability: number | null = null;",
            1,
        )

    old_block = """        const level = normalizeRiskLevel(prediction.riskLevel);

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
"""
    new_block = """        aiPredictionTotal += 1;

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

          const percentileBand = percentileBucketKey(percentile);
          if (percentileBand) {
            distribution[percentileBand] += 1;
          }
        } else {
          const level = normalizeRiskLevel(prediction.riskLevel);
          if (level) {
            distribution[level] += 1;
          }
        }
"""
    if old_block in text:
        text = text.replace(old_block, new_block, 1)

    text = text.replace("      total: total || loaded,", "      total: aiPredictionTotal,")

    # The loading text previously claimed full snapshot sync; make it accurate.
    text = text.replace(
        "CYRP đang đồng bộ Wazuh snapshot, lấy lỗ hổng active và chạy mô hình XGBoost để dự đoán nguy cơ khai thác.",
        "CYRP đang kiểm tra danh sách CVE active đã đồng bộ và chạy mô hình XGBoost để dự đoán nguy cơ khai thác.",
    )

    write(path, text)
    print(f"Patched user modal distribution: {path}")
    print(f"Backup: {b}")


patch_delta_service()
patch_importer_no_fallback()
patch_user_modal_distribution()
print("Done. Run API typecheck and user-web build next.")
