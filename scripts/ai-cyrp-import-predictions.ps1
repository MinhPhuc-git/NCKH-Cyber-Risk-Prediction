param(
    [string]$ProjectRoot = "D:\LuanVan\test\cyrp-platform-phase2",
    [string]$PredictionJson = ""
)

$ErrorActionPreference = "Stop"

if (-not $PredictionJson) {
    $PredictionJson = Join-Path $ProjectRoot "apps\ai-model\runtime\cyrp-model-output.json"
}

if (-not (Test-Path $PredictionJson)) {
    throw "Prediction JSON was not found: $PredictionJson"
}

$predictions = Get-Content -Path $PredictionJson -Raw -Encoding UTF8 | ConvertFrom-Json

if (-not $predictions) {
    Write-Host "No predictions to import."
    exit 0
}

$sqlStatements = New-Object System.Collections.Generic.List[string]

foreach ($prediction in @($predictions)) {
    if (-not $prediction.detection_id) {
        continue
    }

    $detectionId = [string]$prediction.detection_id
    $modelVersion = ([string]$prediction.model_version).Replace("'", "''")
    $probability = [double]$prediction.attack_probability
    $percentile = if ($null -ne $prediction.official_epss_percentile) { [string]([double]$prediction.official_epss_percentile) } else { "NULL" }
    $riskLevel = ([string]$prediction.model_risk_level).Replace("'", "''")
    $json = ($prediction | ConvertTo-Json -Depth 30 -Compress).Replace("'", "''")

    $sqlStatements.Add(@"
INSERT INTO ai_predictions (
  detected_vulnerability_id,
  model_version,
  attack_probability,
  predicted_percentile,
  risk_level,
  explanation,
  predicted_at,
  created_at,
  updated_at
)
VALUES (
  '$detectionId'::uuid,
  '$modelVersion',
  $probability,
  $percentile,
  '$riskLevel',
  '$json'::jsonb,
  NOW(),
  NOW(),
  NOW()
)
ON CONFLICT (detected_vulnerability_id)
DO UPDATE SET
  model_version = EXCLUDED.model_version,
  attack_probability = EXCLUDED.attack_probability,
  predicted_percentile = EXCLUDED.predicted_percentile,
  risk_level = EXCLUDED.risk_level,
  explanation = EXCLUDED.explanation,
  predicted_at = EXCLUDED.predicted_at,
  updated_at = NOW();

INSERT INTO prediction_history (
  detected_vulnerability_id,
  device_id,
  cve_id,
  wazuh_agent_id,
  model_version,
  attack_probability,
  predicted_percentile,
  risk_level,
  feature_hash,
  predicted_at,
  created_at
)
SELECT
  dv.id,
  dv.device_id,
  dv.cve_id,
  dv.wazuh_agent_id,
  '$modelVersion',
  $probability,
  $percentile,
  '$riskLevel',
  fv.feature_hash,
  NOW(),
  NOW()
FROM detected_vulnerabilities dv
LEFT JOIN vulnerability_feature_vectors fv
  ON fv.detected_vulnerability_id = dv.id
WHERE dv.id = '$detectionId'::uuid;
"@)
}

if ($sqlStatements.Count -eq 0) {
    Write-Host "No valid predictions to import."
    exit 0
}

$tempSql = Join-Path $env:TEMP "cyrp-ai-import-$([Guid]::NewGuid()).sql"
[IO.File]::WriteAllText($tempSql, ($sqlStatements -join "`n"), [Text.UTF8Encoding]::new($false))

try {
    Get-Content -Path $tempSql -Raw -Encoding UTF8 |
      docker compose exec -T db psql -U cyrp -d cyrp
}
finally {
    Remove-Item $tempSql -Force -ErrorAction SilentlyContinue
}

Write-Host "Imported $($sqlStatements.Count) AI predictions into PostgreSQL." -ForegroundColor Green
