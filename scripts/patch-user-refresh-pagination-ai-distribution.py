from pathlib import Path
from datetime import datetime
import shutil
import re

ROOT = Path(r"D:\LuanVan\test\cyrp-platform-phase2")
STAMP = datetime.now().strftime("%Y%m%d-%H%M%S")
BACKUP_ROOT = ROOT / ".phase-backups" / f"refresh-pagination-ai-distribution-{STAMP}"
BACKUP_ROOT.mkdir(parents=True, exist_ok=True)

changed = []

def backup(path: Path):
    if not path.exists():
        return

    rel = path.relative_to(ROOT)
    dst = BACKUP_ROOT / rel
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(path, dst)

def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")

def write(path: Path, text: str):
    path.write_text(text, encoding="utf-8")

def save(path: Path, old: str, new: str, reason: str):
    if old != new:
        backup(path)
        write(path, new)
        changed.append((str(path.relative_to(ROOT)), reason))

def patch_backend_summary_proxy():
    target = ROOT / "apps" / "user-web" / "src" / "app" / "api" / "vulnerabilities" / "ai-risk-summary" / "route.ts"
    target.parent.mkdir(parents=True, exist_ok=True)

    old = read(target) if target.exists() else ""

    new = """import { NextResponse } from 'next/server';
import { proxyUserRequest } from '../../authenticated-proxy';

export async function GET() {
  return proxyUserRequest('/vulnerabilities/ai-risk-summary', {
    method: 'GET',
    cache: 'no-store',
  });
}
"""

    save(target, old, new, "user-web proxy ai-risk-summary")

def patch_api_controller_and_service():
    controller = ROOT / "apps" / "api" / "src" / "modules" / "security-data" / "vulnerabilities.controller.ts"
    service = ROOT / "apps" / "api" / "src" / "modules" / "security-data" / "vulnerabilities.service.ts"

    if not controller.exists():
        print("[WARN] Missing vulnerabilities.controller.ts")
    else:
        old = read(controller)
        new = old

        if "ai-risk-summary" not in new:
            # Chèn method trước dấu } cuối class.
            method = """
  @Get('ai-risk-summary')
  getAiRiskSummary(@CurrentUser() user: AuthenticatedUser) {
    return this.vulnerabilitiesService.getAiRiskSummaryForUser(user.id);
  }

"""
            idx = new.rfind("\n}")
            if idx == -1:
                raise SystemExit("Không tìm thấy cuối class trong vulnerabilities.controller.ts")
            new = new[:idx] + method + new[idx:]

        save(controller, old, new, "api vulnerabilities ai-risk-summary route")

    if not service.exists():
        print("[WARN] Missing vulnerabilities.service.ts")
    else:
        old = read(service)
        new = old

        if "getAiRiskSummaryForUser" not in new:
            method = """
  async getAiRiskSummaryForUser(userId: string) {
    const rows = await this.database.detectedVulnerability.findMany({
      where: {
        status: 'ACTIVE',
        device: {
          userId,
        },
        aiPrediction: {
          isNot: null,
        },
      },
      select: {
        aiPrediction: {
          select: {
            riskLevel: true,
            attackProbability: true,
            predictedPercentile: true,
          },
        },
      },
    });

    const distribution = {
      LOW: 0,
      MEDIUM: 0,
      HIGH: 0,
      CRITICAL: 0,
    };

    let highestAttackProbability: number | null = null;
    let highestPercentile: number | null = null;

    for (const row of rows) {
      const level = row.aiPrediction?.riskLevel?.toUpperCase();

      if (
        level === 'LOW' ||
        level === 'MEDIUM' ||
        level === 'HIGH' ||
        level === 'CRITICAL'
      ) {
        distribution[level] += 1;
      }

      const probability = row.aiPrediction?.attackProbability;
      if (typeof probability === 'number' && Number.isFinite(probability)) {
        highestAttackProbability =
          highestAttackProbability === null
            ? probability
            : Math.max(highestAttackProbability, probability);
      }

      const percentile = row.aiPrediction?.predictedPercentile;
      if (typeof percentile === 'number' && Number.isFinite(percentile)) {
        highestPercentile =
          highestPercentile === null
            ? percentile
            : Math.max(highestPercentile, percentile);
      }
    }

    return {
      total: rows.length,
      distribution,
      highestAttackProbability,
      highestPercentile,
      calculatedAt: new Date().toISOString(),
    };
  }

"""
            idx = new.rfind("\n}")
            if idx == -1:
                raise SystemExit("Không tìm thấy cuối class trong vulnerabilities.service.ts")
            new = new[:idx] + method + new[idx:]

        save(service, old, new, "api vulnerabilities ai-risk-summary service")

def patch_device_analysis_button():
    path = ROOT / "apps" / "user-web" / "src" / "components" / "device-analysis-button.tsx"
    old = read(path)
    new = old

    # Type for summary.
    if "interface AiRiskSummaryResponse" not in new:
        insert = """interface AiRiskSummaryResponse {
  total: number;
  distribution: {
    LOW: number;
    MEDIUM: number;
    HIGH: number;
    CRITICAL: number;
  };
  highestAttackProbability: number | null;
  highestPercentile: number | null;
  calculatedAt: string;
}

"""
        marker = "interface DeviceAnalysisButtonProps"
        idx = new.find(marker)
        if idx == -1:
            raise SystemExit("Không tìm thấy interface DeviceAnalysisButtonProps")
        new = new[:idx] + insert + new[idx:]

    # Add state.
    if "const [aiRiskSummary, setAiRiskSummary]" not in new:
        marker = "const [vulnerabilities, setVulnerabilities]"
        idx = new.find(marker)
        if idx == -1:
            raise SystemExit("Không tìm thấy vulnerabilities state trong device-analysis-button.tsx")
        line_end = new.find("\n", idx)
        new = new[:line_end + 1] + "  const [aiRiskSummary, setAiRiskSummary] = useState<AiRiskSummaryResponse | null>(null);\n" + new[line_end + 1:]

    # Add loader.
    if "async function loadAiRiskSummary" not in new:
        marker = "const sortedVulnerabilities = useMemo("
        idx = new.find(marker)
        if idx == -1:
            raise SystemExit("Không tìm thấy sortedVulnerabilities để chèn loadAiRiskSummary")
        loader = """async function loadAiRiskSummary() {
    const response = await fetch('/api/vulnerabilities/ai-risk-summary', {
      method: 'GET',
      cache: 'no-store',
      credentials: 'same-origin',
    });

    const payload = (await response.json().catch(() => null)) as
      | AiRiskSummaryResponse
      | ApiErrorResponse
      | null;

    if (!response.ok) {
      return;
    }

    if (
      payload &&
      typeof payload === 'object' &&
      'distribution' in payload &&
      'total' in payload
    ) {
      setAiRiskSummary(payload as AiRiskSummaryResponse);
    }
  }

  """
        new = new[:idx] + loader + new[idx:]

    # Call loader after modal/latest result loads. Put it in existing useEffect by adding a simple second effect.
    if "void loadAiRiskSummary().catch" not in new:
        marker = "const sortedVulnerabilities = useMemo("
        idx = new.find(marker)
        effect = """useEffect(() => {
    if (!isModalOpen) {
      return;
    }

    void loadAiRiskSummary().catch(() => {
      // Keep existing distribution if summary refresh fails.
    });
  }, [isModalOpen]);

  """
        new = new[:idx] + effect + new[idx:]

    # Force risk distribution to use backend summary.
    dist_start = new.find("const aiDistribution = useMemo")
    dist_end = new.find("const maxDistributionCount", dist_start)

    if dist_start != -1 and dist_end != -1:
        replacement = """const aiDistribution = useMemo<RiskBucketRow[]>(
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

  """
        new = new[:dist_start] + replacement + new[dist_end:]

    # Fix maxDistributionCount if old bad text remains.
    new = new.replace(
        "Math.max(1, .aiDistribution.map((item) => item.count))",
        "Math.max(1, ...aiDistribution.map((item) => item.count))",
    )

    # Update hint to use aiRiskSummary total.
    new = new.replace(
        "Đây là phân bố theo AI prediction, không phải theo CVSS.",
        "Đây là phân bố theo toàn bộ AI prediction active, không phải theo CVSS."
    )

    new = new.replace(
        "{sortedVulnerabilities.length} lỗ hổng có AI prediction đang được tổng hợp",
        "{aiRiskSummary?.total ?? sortedVulnerabilities.length} lỗ hổng có AI prediction đang được tổng hợp"
    )

    # Ensure Attack probability is next to Percentile in each CVE card.
    if "<span>Attack probability</span>" not in new:
        if "function modelAttackProbabilityValue(" not in new:
            marker = "function modelExploitRiskValue("
            idx = new.find(marker)
            helper = """function modelAttackProbabilityValue(
  item: VulnerabilityItem | null | undefined,
): number | null {
  return normalizeProbabilityLikeValue(
    item?.aiPrediction?.attackProbability,
  );
}

"""
            new = new[:idx] + helper + new[idx:]

        pattern = re.compile(
            r"""<div className=\{styles\.statChip\}>\s*
\s*<span>(?:Percentile|Rủi ro khai thác|Rủi ro bị khai thác)</span>\s*
\s*<strong>\{formatProbability\(modelExploitRiskValue\(item\)\)\}</strong>\s*
\s*</div>""",
            re.MULTILINE,
        )

        replacement = """<div className={styles.statChip}>
                                  <span>Percentile</span>
                                  <strong>{formatProbability(modelExploitRiskValue(item))}</strong>
                                </div>
                                <div className={styles.statChip}>
                                  <span>Attack probability</span>
                                  <strong>{formatProbability(modelAttackProbabilityValue(item))}</strong>
                                </div>"""

        new, _ = pattern.subn(replacement, new, count=1)

    save(path, old, new, "device analysis backend AI distribution and CVE attack probability")

def patch_ai_predictions_refresh_button():
    path = ROOT / "apps" / "user-web" / "src" / "app" / "ai-predictions" / "ai-predictions-client.tsx"
    old = read(path)
    new = old

    # Add refresh button near filter submit if absent.
    if "Làm mới" not in new:
        target = """        <button className={styles.primaryButton} type="submit">
          Tìm kiếm
        </button>"""
        replacement = """        <button className={styles.primaryButton} type="submit">
          Tìm kiếm
        </button>

        <button
          className={styles.secondaryButton}
          type="button"
          onClick={() => {
            setPage(1);
            void load();
          }}
          disabled={loading}
        >
          {loading ? 'Đang tải...' : 'Làm mới'}
        </button>"""
        new = new.replace(target, replacement)

    save(path, old, new, "ai predictions refresh button")

def patch_vulnerabilities_refresh_pagination():
    path = ROOT / "apps" / "user-web" / "src" / "app" / "vulnerabilities" / "vulnerabilities-client.tsx"
    old = read(path)
    new = old

    # Fix missing riskLevel state from previous patch if needed.
    if "riskLevel" in new and "setRiskLevel" in new and "const [riskLevel, setRiskLevel]" not in new:
        match = re.search(r"(const \[status,\s*setStatus\]\s*=\s*useState\([^;]*\);\s*)", new)
        if match:
            new = new[:match.end()] + "\n  const [riskLevel, setRiskLevel] = useState('');" + new[match.end():]
        else:
            match = re.search(r"(const \[page,\s*setPage\]\s*=\s*useState\([^;]*\);\s*)", new)
            if match:
                new = new[:match.end()] + "\n  const [riskLevel, setRiskLevel] = useState('');" + new[match.end():]

    # Add refresh button next to record count in header.
    header_pill = """        <span className={`${styles.statusPill} ${styles.statusNeutral}`}>
          {data?.total ?? 0} bản ghi
        </span>"""

    header_replacement = """        <div className={styles.headerActions}>
          <span className={`${styles.statusPill} ${styles.statusNeutral}`}>
            {data?.total ?? 0} bản ghi
          </span>
          <button
            className={styles.secondaryButton}
            type="button"
            onClick={() => {
              setPage(1);
              void load();
            }}
            disabled={loading}
          >
            {loading ? 'Đang tải...' : 'Làm mới'}
          </button>
        </div>"""

    if header_pill in new and "headerActions" not in new[new.find("<header className={styles.pageHeader}"):new.find("</header>", new.find("<header className={styles.pageHeader}"))]:
        new = new.replace(header_pill, header_replacement)

    # Add refresh button to filter row if header pattern not matched.
    if "Làm mới" not in new:
        target = """        <button className={styles.primaryButton} type="submit">
          Tìm kiếm
        </button>"""
        replacement = """        <button className={styles.primaryButton} type="submit">
          Tìm kiếm
        </button>

        <button
          className={styles.secondaryButton}
          type="button"
          onClick={() => {
            setPage(1);
            void load();
          }}
          disabled={loading}
        >
          {loading ? 'Đang tải...' : 'Làm mới'}
        </button>"""
        new = new.replace(target, replacement)

    save(path, old, new, "vulnerabilities refresh button")

def patch_pagination_css():
    path = ROOT / "apps" / "user-web" / "src" / "components" / "security-console.module.css"
    if not path.exists():
        print("[WARN] missing security-console.module.css")
        return

    old = read(path)
    new = old

    patch = """

/* CYRP patch: pagination and header actions spacing */
.pagination,
.paginationRow,
.tablePagination {
  display: flex;
  align-items: center;
  gap: 12px;
  flex-wrap: wrap;
}

.pagination span,
.paginationRow span,
.tablePagination span {
  display: inline-flex;
  align-items: center;
  padding: 0 4px;
  white-space: nowrap;
}

.headerActions {
  display: flex;
  align-items: center;
  gap: 12px;
  flex-wrap: wrap;
  justify-content: flex-end;
}

.secondaryButton {
  min-height: 40px;
}
"""

    if "CYRP patch: pagination and header actions spacing" not in new:
        new = new.rstrip() + patch + "\n"

    save(path, old, new, "pagination/header css spacing")

patch_backend_summary_proxy()
patch_api_controller_and_service()
patch_device_analysis_button()
patch_ai_predictions_refresh_button()
patch_vulnerabilities_refresh_pagination()
patch_pagination_css()

print("Backup:", BACKUP_ROOT)
print("Changed files:")
for item, reason in changed:
    print("-", item, "[" + reason + "]")
