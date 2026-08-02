# Phase 2D.1 Hotfix: AI Assets, BOM-safe JSON, and Prediction Exit Codes

This hotfix fixes two problems:

1. PowerShell exported JSON with UTF-8 BOM, while Python used `encoding="utf-8"`.
   The runtime now reads `utf-8-sig`, and the export script writes UTF-8 without BOM.

2. `ai-cyrp-predict-from-db.ps1` continued to import predictions after Python failed.
   It now removes stale output before prediction and stops immediately if Python returns a non-zero exit code.

It also provides `install-ai-cyrp-assets.ps1`, which places the user's original `AI_CYRP.zip` and `Merge DATA.zip` contents into the project:

- `apps/ai-model/vendor/AI_CYRP`
- `apps/ai-model/datasets/cve_epss_merged_v2_light.csv`
- `apps/ai-model/datasets/cve_epss_merged_v2.csv`
- `docs/ai-model/bao_cao_merge_cve_epss.md`

The original user model is preserved for reference. The stable integration adapter remains:

- `apps/ai-model/src/cyrp_ai_model.py`
