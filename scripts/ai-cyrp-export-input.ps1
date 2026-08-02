param(
    [string]$ProjectRoot = "D:\LuanVan\test\cyrp-platform-phase2",
    [string]$DeviceId = "",
    [int]$Limit = 50,
    [string]$OutputPath = ""
)

$ErrorActionPreference = "Stop"

if (-not $OutputPath) {
    $OutputPath = Join-Path $ProjectRoot "apps\ai-model\runtime\cyrp-model-input.json"
}

New-Item -ItemType Directory -Path (Split-Path -Parent $OutputPath) -Force | Out-Null

$whereDevice = ""
if ($DeviceId) {
    $safeDeviceId = $DeviceId.Replace("'", "''")
    $whereDevice = " AND fv.device_id = '$safeDeviceId'::uuid "
}

$sql = @"
SELECT COALESCE(
  jsonb_pretty(
    jsonb_agg(
      jsonb_build_object(
        'detection_id', fv.detected_vulnerability_id,
        'device_id', fv.device_id,
        'cve_id', fv.cve_id,
        'attack_vector', COALESCE(fv.attack_vector, 'LOCAL'),
        'attack_complexity', COALESCE(fv.attack_complexity, 'HIGH'),
        'privileges_required', COALESCE(fv.privileges_required, 'LOW'),
        'user_interaction', COALESCE(fv.user_interaction, 'NONE'),
        'scope', COALESCE(fv.scope, 'UNCHANGED'),
        'confidentiality', COALESCE(fv.confidentiality_impact, 'LOW'),
        'integrity', COALESCE(fv.integrity_impact, 'LOW'),
        'availability', COALESCE(fv.availability_impact, 'HIGH'),
        'cwe_id_grouped', COALESCE(fv.cwe_id_grouped, 'NVD-CWE-noinfo'),
        'cwe_id', COALESCE(fv.cwe_id_grouped, 'NVD-CWE-noinfo'),
        'base_score', COALESCE(fv.base_score, 5.0),
        'exploitability_score', 3.9,
        'impact_score', 5.9,
        'is_cvss3_or_higher', CASE WHEN fv.is_cvss3_or_higher THEN 1 ELSE 0 END,
        'has_valid_cvss', CASE WHEN fv.base_score IS NULL THEN 0 ELSE 1 END,
        'cwe_is_generic', CASE WHEN fv.cwe_is_generic THEN 1 ELSE 0 END,
        'severity_label', COALESCE(fv.severity, 'UNKNOWN'),
        'official_epss_score', fv.epss_score,
        'official_epss_percentile', fv.epss_percentile,
        'alert_count_24h', fv.alert_count_24h,
        'max_rule_level_24h', fv.max_rule_level_24h,
        'device_package_count', fv.device_package_count
      )
      ORDER BY COALESCE(fv.base_score, 0) DESC, fv.cve_id ASC
    )
  ),
  '[]'
)
FROM (
  SELECT fv.*
  FROM vulnerability_feature_vectors fv
  JOIN detected_vulnerabilities dv
    ON dv.id = fv.detected_vulnerability_id
  WHERE dv.status = 'ACTIVE'
  $whereDevice
  ORDER BY COALESCE(fv.base_score, 0) DESC, fv.cve_id ASC
  LIMIT $Limit
) fv;
"@

$result = docker compose exec -T db psql -U cyrp -d cyrp -qAt -c $sql

if (-not $result) {
    $result = "[]"
}

[IO.File]::WriteAllText(
    $OutputPath,
    $result,
    [Text.UTF8Encoding]::new($false)
)

Write-Host "Exported AI model input: $OutputPath" -ForegroundColor Green
