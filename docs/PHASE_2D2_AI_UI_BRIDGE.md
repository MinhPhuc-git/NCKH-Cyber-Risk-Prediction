# Phase 2D.2 AI/UI Bridge

This phase stabilizes the temporary workflow after Phase 2D.1:

1. Run Wazuh security sync.
2. Run AI_CYRP random forest prediction after sync.
3. Verify that the API response exposes `AI_CYRP_RANDOM_FOREST_V1`.
4. Collect UI/API source context for the next exact UI patch if needed.

This is not the final backend-integrated AI inference module. It is the bridge step before replacing the manual PowerShell workflow with a NestJS service and UI button.

## Scripts

### phase-2d2-refresh-ai-after-sync.ps1
Runs `security-sync`, then runs the random forest prediction/import script, then prints DB summary.

### phase-2d2-verify-ai-api-contract.ps1
Calls the `/vulnerabilities` API and saves a JSON sample to `logs/phase-2d2-vulnerabilities-api-sample.json`.

### phase-2d2-collect-ui-context.ps1
Collects likely UI/API files that render vulnerability results and produces `logs/phase2d2-ui-context.zip`.
