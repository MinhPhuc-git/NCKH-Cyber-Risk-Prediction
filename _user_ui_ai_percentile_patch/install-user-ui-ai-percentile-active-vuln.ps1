param(
  [string]$ProjectRoot = "D:\LuanVan\test\cyrp-platform-phase2"
)

$ErrorActionPreference = "Stop"

$Component = Join-Path $ProjectRoot "apps\user-web\src\components\device-analysis-button.tsx"
$CssFile = Join-Path $ProjectRoot "apps\user-web\src\components\device-analysis-button.module.css"

if (-not (Test-Path $Component)) {
  throw "Không tìm thấy file component: $Component"
}

$BackupDir = Join-Path $ProjectRoot (".phase-backups\user-ui-ai-percentile-active-vuln-" + (Get-Date -Format "yyyyMMdd-HHmmss"))
New-Item -ItemType Directory -Force -Path $BackupDir | Out-Null
Copy-Item $Component (Join-Path $BackupDir "device-analysis-button.tsx") -Force
if (Test-Path $CssFile) {
  Copy-Item $CssFile (Join-Path $BackupDir "device-analysis-button.module.css") -Force
}

$Text = Get-Content -Raw -Encoding UTF8 $Component

# 1) Add helpers for model predicted percentile. Keep fallback to attackProbability if importer/model does not provide predictedPercentile yet.
$Helper = @'
function normalizePercentile(
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

function formatPercentile(
  value: number | null | undefined,
): string {
  const normalized = normalizePercentile(value);

  if (normalized === null) {
    return '—';
  }

  return `${Math.round(normalized * 100)}%`;
}

function exploitationPercentile(
  item: VulnerabilityItem | null | undefined,
): number | null {
  if (!item) {
    return null;
  }

  return normalizePercentile(item.aiPrediction?.predictedPercentile) ??
    normalizePercentile(item.aiPrediction?.attackProbability);
}

'@

if ($Text -notmatch "function normalizePercentile\(") {
  $Text = $Text -replace "function formatScore\(\r?\n", ($Helper + "function formatScore(`r`n")
}

# 2) Sort priority list by predictedPercentile first, fallback attackProbability.
$OldSort = @'
  const sortedVulnerabilities = useMemo(
    () => {
      return [...vulnerabilities].sort(
        (left, right) =>
          (right.aiPrediction?.attackProbability ?? -1) -
          (left.aiPrediction?.attackProbability ?? -1),
      );
    },
    [vulnerabilities],
  );
'@
$NewSort = @'
  const sortedVulnerabilities = useMemo(
    () => {
      return [...vulnerabilities].sort(
        (left, right) =>
          (exploitationPercentile(right) ?? -1) -
          (exploitationPercentile(left) ?? -1),
      );
    },
    [vulnerabilities],
  );
'@
if ($Text.Contains($OldSort)) {
  $Text = $Text.Replace($OldSort, $NewSort)
} else {
  $Text = [regex]::Replace(
    $Text,
    "(?s)  const sortedVulnerabilities = useMemo\(\s*\(\) => \{\s*return \[\.\.\.vulnerabilities\]\.sort\(\s*\(left, right\) =>\s*\(right\.aiPrediction\?\.attackProbability \?\? -1\) -\s*\(left\.aiPrediction\?\.attackProbability \?\? -1\),\s*\);\s*\},\s*\[vulnerabilities\],\s*\);",
    $NewSort
  )
}

# 3) Add highestExploitPercentile derived from model predictedPercentile.
$HighestBlock = @'
  const strongestPrediction = useMemo(
    () => {
      return sortedVulnerabilities[0] ?? null;
    },
    [sortedVulnerabilities],
  );
'@
$HighestBlockNew = @'
  const strongestPrediction = useMemo(
    () => {
      return sortedVulnerabilities[0] ?? null;
    },
    [sortedVulnerabilities],
  );

  const highestExploitPercentile = useMemo(
    () => {
      const values = vulnerabilities
        .map((item) => exploitationPercentile(item))
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
  );
'@
if ($Text.Contains($HighestBlock) -and $Text -notmatch "highestExploitPercentile") {
  $Text = $Text.Replace($HighestBlock, $HighestBlockNew)
}

# 4) Replace quick action text to use predicted percentile, not only attackProbability.
$Text = $Text -replace "`Ưu tiên xử lý \$\{strongestPrediction\.cveId\} vì đang có xác suất khai thác \$\{formatProbability\(strongestPrediction\.aiPrediction\?\.attackProbability\)\}\.`", "`Ưu tiên xử lý `${strongestPrediction.cveId} vì đang có rủi ro bị khai thác `${formatPercentile(exploitationPercentile(strongestPrediction))}.`"

# 5) Remove the hero paragraph with agentName/wazuh line that user asked to delete.
$Text = [regex]::Replace(
  $Text,
  "(?s)\r?\n\s*<p>\s*\{snapshot\.agentName \?\? `Agent \$\{snapshot\.wazuhAgentId\}`\} đang được theo dõi qua Wazuh\.\s*Kết quả dưới đây tập trung vào các điểm cần chú ý nhất để bạn không bị ngợp bởi quá nhiều log kỹ thuật\.\s*</p>",
  ""
)

# 6) Update gauge copy to mention exploit risk from model.
$Text = $Text.Replace('<span>Xác suất cao nhất</span>', '<span>Rủi ro khai thác cao nhất</span>')
$Text = $Text.Replace('Đây là xác suất AI cao nhất trong các lỗ hổng ưu tiên của thiết bị ở lần kiểm tra hiện tại.', 'Đây là rủi ro bị khai thác cao nhất theo percentile của model trong các lỗ hổng ưu tiên hiện còn chưa khắc phục.')

# 7) Replace the operational risk score card with model predictedPercentile display.
$OldRiskCard = @'
                  <article className={styles.summaryCard}>
                    <span>Điểm rủi ro vận hành</span>
                    <strong>{snapshot.riskScore}</strong>
                    <small>
                      {snapshot.riskLabel} · cập nhật {formatDate(snapshot.calculatedAt)}
                    </small>
                  </article>
'@
$NewRiskCard = @'
                  <article className={styles.summaryCard}>
                    <span>Rủi ro bị khai thác</span>
                    <strong>{formatPercentile(highestExploitPercentile)}</strong>
                    <small>
                      Percentile AI · cập nhật {formatDate(snapshot.calculatedAt)}
                    </small>
                  </article>
'@
if ($Text.Contains($OldRiskCard)) {
  $Text = $Text.Replace($OldRiskCard, $NewRiskCard)
} else {
  $Text = [regex]::Replace(
    $Text,
    "(?s)\s*<article className=\{styles\.summaryCard\}>\s*<span>Điểm rủi ro vận hành</span>\s*<strong>\{snapshot\.riskScore\}</strong>\s*<small>\s*\{snapshot\.riskLabel\} · cập nhật \{formatDate\(snapshot\.calculatedAt\)\}\s*</small>\s*</article>",
    "`r`n" + $NewRiskCard.TrimEnd()
  )
}

# 8) Show percentile in vulnerability cards.
$Text = $Text.Replace('<span>Xác suất AI</span>', '<span>Rủi ro khai thác</span>')
$Text = $Text.Replace('<strong>{formatProbability(item.aiPrediction?.attackProbability)}</strong>', '<strong>{formatPercentile(exploitationPercentile(item))}</strong>')

# 9) Make status wording explicit: ACTIVE/UNDER_EVALUATION means Chưa khắc phục.
$Text = $Text.Replace("{item.status?.toUpperCase() === 'RESOLVED'`r`n                                    ? 'Đã khắc phục'`r`n                                    : 'Chưa khắc phục'}", "{item.status?.toUpperCase() === 'RESOLVED'`r`n                                    ? 'Đã khắc phục'`r`n                                    : 'Chưa khắc phục'}")

[System.IO.File]::WriteAllText(
  $Component,
  $Text,
  [System.Text.UTF8Encoding]::new($false)
)

Write-Host "Patched: $Component" -ForegroundColor Green
Write-Host "Backup: $BackupDir" -ForegroundColor Yellow
Write-Host "Next: run TypeScript/build for user-web." -ForegroundColor Cyan
