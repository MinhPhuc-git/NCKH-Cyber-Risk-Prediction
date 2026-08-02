param(
  [string]$ProjectRoot = 'D:\LuanVan\test\cyrp-platform-phase2',
  [string]$PgContainer = 'cyrp-platform-phase2-db-1',
  [string]$DbUser = 'cyrp',
  [string]$DbName = 'cyrp',
  [string[]]$Hostnames = @('DESKTOP-RCSLUG6'),
  [string[]]$AgentIds = @('025')
)

Set-Location $ProjectRoot

$HostList = ($Hostnames | ForEach-Object { "'" + ($_ -replace "'", "''") + "'" }) -join ','
$AgentList = ($AgentIds | ForEach-Object { "'" + ($_ -replace "'", "''") + "'" }) -join ','

$Sql = @"
\pset pager off

BEGIN;

-- 1. Đánh dấu các sync_run bị kẹt RUNNING là FAILED để UI không hiểu nhầm pipeline còn đang chạy.
UPDATE sync_runs
SET
  status = 'FAILED',
  completed_at = COALESCE(completed_at, now()),
  error_summary = COALESCE(error_summary, 'Manual reset before clean AI retest.')
WHERE status = 'RUNNING'
  AND (
    device_id IN (
      SELECT d.id
      FROM devices d
      LEFT JOIN wazuh_agent_bindings b ON b.device_id = d.id
      WHERE d.hostname IN ($HostList)
         OR b.wazuh_agent_id IN ($AgentList)
    )
  );

-- 2. Xóa các row fallback bẩn do AI importer từng tự tạo thiếu package/CVSS.
WITH bad AS (
  SELECT dv.id
  FROM detected_vulnerabilities dv
  JOIN devices d ON d.id = dv.device_id
  WHERE dv.source_index = 'ai-pipeline-data-user'
     OR dv.wazuh_agent_id IN ($AgentList)
        AND (dv.package_name IS NULL OR trim(dv.package_name) = '' OR dv.cvss_base_score IS NULL)
)
DELETE FROM prediction_history ph
USING bad
WHERE ph.detected_vulnerability_id = bad.id;

WITH bad AS (
  SELECT dv.id
  FROM detected_vulnerabilities dv
  JOIN devices d ON d.id = dv.device_id
  WHERE dv.source_index = 'ai-pipeline-data-user'
     OR dv.wazuh_agent_id IN ($AgentList)
        AND (dv.package_name IS NULL OR trim(dv.package_name) = '' OR dv.cvss_base_score IS NULL)
)
DELETE FROM ai_predictions ap
USING bad
WHERE ap.detected_vulnerability_id = bad.id;

WITH bad AS (
  SELECT dv.id
  FROM detected_vulnerabilities dv
  JOIN devices d ON d.id = dv.device_id
  WHERE dv.source_index = 'ai-pipeline-data-user'
     OR dv.wazuh_agent_id IN ($AgentList)
        AND (dv.package_name IS NULL OR trim(dv.package_name) = '' OR dv.cvss_base_score IS NULL)
)
DELETE FROM vulnerability_feature_vectors fv
USING bad
WHERE fv.detected_vulnerability_id = bad.id;

DELETE FROM detected_vulnerabilities dv
USING devices d
WHERE d.id = dv.device_id
  AND (
    dv.source_index = 'ai-pipeline-data-user'
    OR dv.wazuh_agent_id IN ($AgentList)
       AND (dv.package_name IS NULL OR trim(dv.package_name) = '' OR dv.cvss_base_score IS NULL)
  );

-- 3. Xóa AI prediction/history của thiết bị test để lần bấm Kiểm tra máy chạy lại model thật trên Wazuh rows đã sạch.
WITH target_vulns AS (
  SELECT dv.id
  FROM detected_vulnerabilities dv
  JOIN devices d ON d.id = dv.device_id
  WHERE d.hostname IN ($HostList)
     OR dv.wazuh_agent_id IN ($AgentList)
)
DELETE FROM prediction_history ph
USING target_vulns
WHERE ph.detected_vulnerability_id = target_vulns.id;

WITH target_vulns AS (
  SELECT dv.id
  FROM detected_vulnerabilities dv
  JOIN devices d ON d.id = dv.device_id
  WHERE d.hostname IN ($HostList)
     OR dv.wazuh_agent_id IN ($AgentList)
)
DELETE FROM ai_predictions ap
USING target_vulns
WHERE ap.detected_vulnerability_id = target_vulns.id;

COMMIT;

-- 4. Kiểm tra sau reset.
SELECT
  d.hostname,
  b.wazuh_agent_id,
  COUNT(dv.id) AS vulnerability_rows,
  COUNT(dv.id) FILTER (WHERE dv.source_index = 'ai-pipeline-data-user') AS fallback_rows,
  COUNT(dv.id) FILTER (WHERE dv.package_name IS NULL OR trim(dv.package_name) = '') AS missing_package,
  COUNT(dv.id) FILTER (WHERE dv.cvss_base_score IS NULL) AS missing_cvss,
  COUNT(ap.id) AS ai_prediction_rows
FROM devices d
LEFT JOIN wazuh_agent_bindings b ON b.device_id = d.id
LEFT JOIN detected_vulnerabilities dv ON dv.device_id = d.id
LEFT JOIN ai_predictions ap ON ap.detected_vulnerability_id = dv.id
WHERE d.hostname IN ($HostList)
   OR b.wazuh_agent_id IN ($AgentList)
GROUP BY d.hostname, b.wazuh_agent_id
ORDER BY d.hostname;
"@

$Sql | docker exec -i $PgContainer psql -U $DbUser -d $DbName
