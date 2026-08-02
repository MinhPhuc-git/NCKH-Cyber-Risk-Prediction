# Phase 2D.1 — AI_CYRP Model Runtime Integration

## Goal

Integrate the user's Python AI_CYRP model with CYRP Phase 2C without changing the existing model logic or breaking the current PostgreSQL schema.

## Important decision

The uploaded model currently trains with:

```text
target = epss
features = CVSS/CWE-derived fields
```

So EPSS is not an input feature. It is the target/pseudo-label during training.

In the CYRP integration, the predicted value is treated as:

```text
AI_CYRP attack_probability / model score
```

not as official EPSS.

Official EPSS from CTI data may be passed as:

```text
official_epss_score
official_epss_percentile
```

and is used only after inference to compute:

```text
final_priority_score
final_priority_level
```

Default formula:

```text
final_priority_score = 0.85 * AI_CYRP_SCORE + 0.15 * OFFICIAL_EPSS
```

If official EPSS is unavailable, final priority equals the model score.

## Runtime flow

```text
Phase 2C PostgreSQL feature vectors
→ scripts/ai-cyrp-export-input.ps1
→ apps/ai-model/runtime/cyrp-model-input.json
→ Python AI_CYRP model
→ apps/ai-model/runtime/cyrp-model-output.json
→ scripts/ai-cyrp-import-predictions.ps1
→ public.ai_predictions + public.prediction_history
→ User/Admin Portal
```

## Training data

Copy the user dataset:

```text
cve_epss_merged_v2_light.csv
```

to:

```text
apps/ai-model/datasets/cve_epss_merged_v2_light.csv
```

or pass `-DatasetCsv` explicitly to the training script.

## Commands

Quick verify:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\verify-phase-2d1.ps1
```

Train quick sample:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\ai-cyrp-train.ps1 `
  -DatasetCsv "D:\path\to\cve_epss_merged_v2_light.csv" `
  -Model random_forest `
  -Limit 30000
```

Full train:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\ai-cyrp-train.ps1 `
  -DatasetCsv "D:\path\to\cve_epss_merged_v2_light.csv" `
  -Model random_forest
```

Predict from Phase 2C DB and import into CYRP:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\ai-cyrp-predict-from-db.ps1 `
  -DeviceId "f29a017a-7e3b-49a9-bea5-5d1301e8d83a" `
  -Limit 20 `
  -Model random_forest `
  -ImportToDatabase
```

## Notes

This phase is deliberately script-based. It validates the model runtime before wiring the model into a NestJS service. The next phase can add:

```text
POST /api/v1/admin/ai-model/predict/device/:deviceId
```

and call the same Python runtime from NestJS.
