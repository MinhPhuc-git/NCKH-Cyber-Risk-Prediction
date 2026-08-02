# CYRP API — Phase 2

NestJS API phục vụ authentication/RBAC, Device–Agent lifecycle, Wazuh integration, CTI, vulnerability/context synchronization và portal data APIs.

## Chạy cục bộ

Từ repository root:

```powershell
Copy-Item .env.example .env
corepack pnpm@11.9.0 install --frozen-lockfile
corepack pnpm@11.9.0 run docker:db:up
corepack pnpm@11.9.0 run db:generate
corepack pnpm@11.9.0 run db:migrate
corepack pnpm@11.9.0 run db:seed:phase2
corepack pnpm@11.9.0 run dev:api
```

`WAZUH_INTEGRATION_ENABLED=false` cho phép chạy auth/device/CTI API mà không cần Wazuh. Chỉ bật Wazuh sau khi API/Indexer credentials và TLS đã được kiểm tra.

## Endpoint groups

- `/api/v1/auth`, `/registration`, `/users`.
- `/api/v1/devices`, `/agents`, `/wazuh`, `/wazuh-bindings`.
- `/api/v1/analysis-runs`, `/security-snapshot`.
- `/api/v1/dashboard/data-overview`.
- `/api/v1/vulnerabilities`.
- `/api/v1/sync-runs`.
- `/api/v1/admin/*` cho operational data plane.

Swagger ở `/api/docs` khi `SWAGGER_ENABLED=true`.

## Phase 2 scripts

```powershell
corepack pnpm@11.9.0 run db:seed:phase2
corepack pnpm@11.9.0 run cti:import:csv -- --file ".\datasets\sample\cve-intelligence-sample.csv"
```

## Kiểm tra

```powershell
corepack pnpm@11.9.0 run lint:api
corepack pnpm@11.9.0 run typecheck:api
corepack pnpm@11.9.0 run test:api
corepack pnpm@11.9.0 run test:e2e:api
corepack pnpm@11.9.0 run build:api
```

E2E mock Prisma và tắt Wazuh scheduler trong `test/setup-env.ts`.

## Giới hạn

- Scheduler/lock vẫn ở API process, chỉ phù hợp một replica.
- NVD/EPSS/CISA KEV adapters chưa tự động chạy.
- `WAZUH_HEURISTIC_V1` không phải AI hoặc exploitation probability.
- Feature/model/risk/recommendation pipeline cố ý chưa thuộc Phase 2.
