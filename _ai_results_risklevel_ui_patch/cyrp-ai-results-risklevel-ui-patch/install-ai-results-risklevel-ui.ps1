param(
  [string]$ProjectRoot = "D:\LuanVan\test\cyrp-platform-phase2"
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $ProjectRoot)) {
  throw "ProjectRoot not found: $ProjectRoot"
}

$ScriptsDir = Join-Path $ProjectRoot "scripts"
New-Item -ItemType Directory -Force -Path $ScriptsDir | Out-Null

$PatchScript = Join-Path $ScriptsDir "patch-ai-results-risklevel-ui.py"

@'
from pathlib import Path
import re
import shutil
from datetime import datetime

PROJECT_ROOT = Path(r"__PROJECT_ROOT__")
USER_SRC = PROJECT_ROOT / "apps" / "user-web" / "src"

if not USER_SRC.exists():
    raise SystemExit(f"user-web src not found: {USER_SRC}")

candidates = []
for path in USER_SRC.rglob("*.tsx"):
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        continue
    if (
        "Mọi severity" in text
        and ("Risk level" in text or "riskLevel" in text or "aiPrediction" in text)
        and ("Kết quả AI" in text or "AI_CYRP" in text or "Kết quả chấm điểm" in text or "vulnerabilities" in str(path).lower())
    ):
        candidates.append(path)

if not candidates:
    raise SystemExit("No AI/vulnerability result TSX file containing 'Mọi severity' was found. Run Select-String to locate the file first.")

backup_root = PROJECT_ROOT / ".phase-backups" / ("ai-results-risklevel-ui-" + datetime.now().strftime("%Y%m%d-%H%M%S"))
backup_root.mkdir(parents=True, exist_ok=True)

patched_files = []

HELPERS = r'''
function normalizedAiRiskLevel(item: VulnerabilityItem): string {
  return (item.aiPrediction?.riskLevel ?? finalPriorityLevel(item) ?? '').toUpperCase();
}

function aiRiskLevelRank(level: string | null | undefined): number {
  switch (level?.toUpperCase()) {
    case 'CRITICAL':
      return 4;
    case 'HIGH':
      return 3;
    case 'MEDIUM':
      return 2;
    case 'LOW':
      return 1;
    default:
      return 0;
  }
}

function sortAndFilterByAiRiskLevel(
  items: VulnerabilityItem[],
  riskLevel: string,
): VulnerabilityItem[] {
  const normalizedFilter = riskLevel.trim().toUpperCase();

  return [...items]
    .filter((item) => {
      if (!normalizedFilter) return true;
      return normalizedAiRiskLevel(item) === normalizedFilter;
    })
    .sort((left, right) => {
      const rankDelta =
        aiRiskLevelRank(normalizedAiRiskLevel(right)) -
        aiRiskLevelRank(normalizedAiRiskLevel(left));

      if (rankDelta !== 0) return rankDelta;

      return (right.aiPrediction?.predictedPercentile ?? right.aiPrediction?.attackProbability ?? -1) -
        (left.aiPrediction?.predictedPercentile ?? left.aiPrediction?.attackProbability ?? -1);
    });
}
'''

for path in candidates:
    original = path.read_text(encoding="utf-8")
    text = original

    shutil.copy2(path, backup_root / path.name)

    text = text.replace("const [severity, setSeverity] = useState('');", "const [riskLevel, setRiskLevel] = useState('');")
    text = text.replace("const [status, setStatus] = useState('ACTIVE');\n", "")

    if "function sortAndFilterByAiRiskLevel(" not in text:
        m = re.search(r"function statusClass\([^)]*\)\s*:\s*string\s*\{.*?\n\}\n", text, flags=re.S)
        if m:
            text = text[:m.end()] + "\n" + HELPERS + "\n" + text[m.end():]
        else:
            text = text.replace("export function", HELPERS + "\nexport function", 1)

    text = text.replace("if (severity) params.set('severity', severity);", "if (riskLevel) params.set('riskLevel', riskLevel);\n      params.set('status', 'ACTIVE');")
    text = text.replace("if (status) params.set('status', status);\n", "")

    old_set = """      setData(payload);
      setError('');"""
    new_set = """      const filteredItems = sortAndFilterByAiRiskLevel(payload.items ?? [], riskLevel);
      setData({
        ...payload,
        items: filteredItems,
        total: riskLevel ? filteredItems.length : payload.total,
      });
      setError('');"""
    if old_set in text and "sortAndFilterByAiRiskLevel(payload.items" not in text:
        text = text.replace(old_set, new_set)

    text = text.replace("}, [page, query, severity, status]);", "}, [page, query, riskLevel]);")
    text = text.replace("}, [page, query, severity]);", "}, [page, query, riskLevel]);")

    risk_select = '''        <select
          className={styles.select}
          value={riskLevel}
          onChange={(event) => {
            setRiskLevel(event.target.value);
            setPage(1);
          }}
          aria-label="Lọc theo risk level AI"
        >
          <option value="">Mọi risk level</option>
          <option value="CRITICAL">Critical</option>
          <option value="HIGH">High</option>
          <option value="MEDIUM">Medium</option>
          <option value="LOW">Low</option>
        </select>'''

    text = re.sub(
        r"\s*<select\s+className=\{styles\.select\}\s+value=\{severity\}.*?<option value=\"\">Mọi severity</option>.*?</select>",
        "\n" + risk_select,
        text,
        count=1,
        flags=re.S,
    )

    text = re.sub(
        r"\s*<select\s+className=\{styles\.select\}\s+value=\{status\}.*?<option value=\"ACTIVE\">Active</option>.*?</select>",
        "",
        text,
        count=1,
        flags=re.S,
    )
    text = re.sub(
        r"\s*<select\s+className=\{styles\.select\}\s+value=\{status\}.*?aria-label=\"Lọc theo trạng thái\".*?</select>",
        "",
        text,
        count=1,
        flags=re.S,
    )

    text = text.replace("Mọi severity", "Mọi risk level")
    text = text.replace("aria-label=\"Lọc theo severity\"", "aria-label=\"Lọc theo risk level AI\"")

    if text != original:
        path.write_text(text, encoding="utf-8")
        patched_files.append(path)

if not patched_files:
    raise SystemExit("Candidate files found, but no changes were applied. The component structure may be different than expected.")

print("Patched files:")
for path in patched_files:
    print(f"- {path}")
print(f"Backup: {backup_root}")
'@ | Set-Content -Path $PatchScript -Encoding UTF8

$PyText = Get-Content -Raw -Encoding UTF8 $PatchScript
$EscapedRoot = $ProjectRoot.Replace('\\', '\\\\')
$PyText = $PyText.Replace('__PROJECT_ROOT__', $EscapedRoot)
[System.IO.File]::WriteAllText((Resolve-Path $PatchScript), $PyText, [System.Text.UTF8Encoding]::new($false))

python $PatchScript

Write-Host "AI results risk-level UI patch installed." -ForegroundColor Green
Write-Host "Next: run user-web build and restart." -ForegroundColor Cyan
