param(
    [string]$ProjectRoot = (Get-Location).Path,
    [string]$DeviceHostname = ''
)

$ErrorActionPreference = 'Stop'
Push-Location $ProjectRoot
try {
    $where = ''
    if (-not [string]::IsNullOrWhiteSpace($DeviceHostname)) {
        $escaped = $DeviceHostname.Replace("'", "''")
        $where = "WHERE d.hostname = '$escaped'"
    }

    docker compose exec db psql -U cyrp -d cyrp -c "
SELECT
  d.hostname,
  b.wazuh_agent_id,
  COUNT(DISTINCT p.id) AS packages,
  COUNT(DISTINCT v.id) AS vulnerabilities,
  COUNT(DISTINCT fv.id) AS feature_vectors,
  COUNT(DISTINCT ap.id) AS ai_predictions
FROM devices d
LEFT JOIN wazuh_agent_bindings b ON b.device_id = d.id
LEFT JOIN device_packages p ON p.device_id = d.id
LEFT JOIN detected_vulnerabilities v ON v.device_id = d.id
LEFT JOIN vulnerability_feature_vectors fv ON fv.device_id = d.id
LEFT JOIN ai_predictions ap ON ap.detected_vulnerability_id = v.id
$where
GROUP BY d.hostname, b.wazuh_agent_id
ORDER BY d.hostname;
"

    docker compose exec db psql -U cyrp -d cyrp -c "
SELECT
  v.cve_id,
  v.package_name,
  v.severity,
  v.cvss_base_score,
  ap.risk_level,
  ap.attack_probability,
  fv.epss_score,
  fv.epss_percentile,
  fv.max_rule_level_24h,
  ap.predicted_at
FROM detected_vulnerabilities v
LEFT JOIN vulnerability_feature_vectors fv ON fv.detected_vulnerability_id = v.id
LEFT JOIN ai_predictions ap ON ap.detected_vulnerability_id = v.id
ORDER BY ap.attack_probability DESC NULLS LAST, v.cvss_base_score DESC NULLS LAST
LIMIT 20;
"
}
finally {
    Pop-Location
}
