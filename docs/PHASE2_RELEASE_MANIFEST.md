# CYRP Phase 2 — Release Manifest

Cập nhật: 12/07/2026

## Release identity

```text
Name: CYRP Phase 2 Data Foundation
Target: Research prototype / local integration environment
AI model included: No
Database migration included: Yes
Live Wazuh validation included in build environment: No
```

## Primary deliverables

| Nhóm | Vị trí |
|---|---|
| Prisma schema | `database/prisma/schema.prisma` |
| Phase 2 migration | `database/prisma/migrations/20260712190000_phase2_data_foundation/` |
| CTI importer | `apps/api/scripts/import-cti-csv.ts` |
| Source registry seed | `apps/api/scripts/seed-phase2-data-sources.ts` |
| Wazuh state reader | `apps/api/src/modules/wazuh/wazuh.service.ts` |
| State normalizer | `apps/api/src/modules/security-data/wazuh-state-normalizer.ts` |
| Sync orchestration | `apps/api/src/modules/security-data/security-data-sync.service.ts` |
| Query/API service | `apps/api/src/modules/security-data/security-data.service.ts` |
| User Portal routes | `apps/user-web/src/app/` |
| Admin Portal routes | `apps/portal-web/src/app/` |
| Verification script | `scripts/verify-phase-2-data-foundation.ps1` |
| Wazuh runbook | `docs/WAZUH_INTEGRATION_RUNBOOK.md` |
| Local upgrade checklist | `docs/LOCAL_UPGRADE_CHECKLIST.md` |

## New database entities

```text
cti_sources
cves
cve_cvss_metrics
cwes
cve_cwes
cve_references
cve_affected_products
cve_threat_signals
sync_runs
detected_vulnerabilities
endpoint_context_snapshots
```

## User Portal routes

```text
/dashboard
/devices
/devices/:deviceId
/vulnerabilities
/vulnerabilities/:id
/sync-history
/reports
/settings
```

## Admin Portal routes

```text
/dashboard
/users
/endpoints
/endpoints/:deviceId
/agents
/vulnerabilities
/vulnerabilities/:id
/sync
/cti
/system
```

## Environment variables added

```text
WAZUH_STATE_PAGE_SIZE
WAZUH_STATE_MAX_ITEMS_PER_CATEGORY
WAZUH_DATA_SYNC_ENABLED
WAZUH_DATA_SYNC_INTERVAL_SECONDS
WAZUH_DATA_SYNC_MAX_CONCURRENCY
CTI_CSV_PATH
```

## Acceptance gates on the user machine

1. `corepack pnpm@11.9.0 install --frozen-lockfile`.
2. `db:generate`, `db:validate`, `db:status`, migration and source seed.
3. CTI CSV import twice without duplicates.
4. `corepack pnpm@11.9.0 run verify` passes.
5. Smoke test with Wazuh disabled.
6. Wazuh API/Indexer connectivity with least privilege.
7. One active Agent bound to the correct Device.
8. One manual full sync producing SyncRun/context/vulnerability data.
9. User/Admin visual verification and RBAC/IDOR checks.

## Validation performed before packaging

- Source tree: 320 files, 0 symlink, 0 forbidden build/runtime artifact.
- TypeScript/TSX syntax parse: 187 files, 0 parse errors.
- Project-specific semantic diagnostics after filtering missing dependency declarations: 0 actionable diagnostics across API/Admin/User.
- CSS Module references: 0 missing classes.
- Import-usage heuristic: 0 possible unused imports.
- Duplicate object/JSX key scan: 0 findings.
- JSON/YAML/JS/Python/Bash syntax checks: pass.
- UTF-8/NUL scan: 318 text files, pass.
- Secret/private-key/runtime credential scan: 0 findings.
- Route presence: 18 expected pages, 0 missing.
- Prisma model-to-migration table check: 19 models/tables, 0 missing.

## Validation not performed in the build environment

- Dependency installation/full `pnpm verify` because npm registry DNS returned `EAI_AGAIN`.
- Live PostgreSQL migration.
- Live Wazuh Manager/Indexer/Agent sync.
- PowerShell parser because `pwsh` is unavailable.

The baseline immediately before Phase 2 was fully verified by the user on Windows. Phase 2 is a candidate release until the local acceptance gates above pass.
