# CYRP Phase 2 — Implementation Notes

## 1. Mục tiêu

Phase 2 xây dựng **data plane** cho CYRP trước khi tích hợp mô hình AI. Mục tiêu là biến dữ liệu Wazuh và CTI thành dữ liệu có cấu trúc, truy vết được và hiển thị được trên User/Admin Portal.

Phạm vi triển khai:

```text
Wazuh Agent / Manager / Indexer
        ↓
Device–Agent binding
        ↓
Vulnerability State Sync + Endpoint Context Sync
        ↓
PostgreSQL Phase 2 tables
        ↓
NestJS API
        ↓
User Portal + Admin Portal
```

Không thuộc Phase 2:

```text
Feature Builder → AI Model → Risk Assessment → AI Recommendation
```

## 2. Database migration

Migration mới:

```text
database/prisma/migrations/20260712190000_phase2_data_foundation/migration.sql
```

### 2.1 Registry và observability

#### `cti_sources`

Theo dõi từng nguồn dữ liệu:

- code/name/type;
- enabled/status;
- lần thử gần nhất;
- lần thành công gần nhất;
- lỗi gần nhất.

#### `sync_runs`

Mỗi lần import/sync có một record riêng:

- source/device/trigger;
- RUNNING/COMPLETED/PARTIAL/FAILED;
- records read/written/updated/resolved/rejected;
- checkpoint và source manifest;
- started/completed/error.

### 2.2 CTI normalized tables

- `cves`.
- `cve_cvss_metrics`.
- `cwes`.
- `cve_cwes`.
- `cve_references`.
- `cve_affected_products`.
- `cve_threat_signals`.

Một CVE có thể có nhiều metric/CWE/reference/product/signal. Không dùng quan hệ CVE–CWE một-một.

### 2.3 Endpoint vulnerability

`detected_vulnerabilities` lưu occurrence thực tế trên thiết bị:

```text
device_id
wazuh_agent_id
cve_id
package_name/version/architecture/vendor/type
status/severity/cvss
first_seen_at/last_seen_at/resolved_at
source_index/source_document_id
raw_payload
```

Unique key:

```text
(source_index, source_document_id)
```

Không dùng `UNIQUE(device_id, cve_id)` vì một CVE có thể ảnh hưởng nhiều package/component trên cùng thiết bị.

### 2.4 Endpoint context history

`endpoint_context_snapshots` là append-only:

- agent/host/OS/architecture;
- package/hotfix/port/process/service/system/hardware;
- count và listening port count;
- completeness/truncation/error per category;
- source version;
- `as_of_time`.

Dữ liệu không ghi đè snapshot cũ, giúp tái tạo context theo thời điểm.

## 3. CTI CSV importer

Script:

```text
apps/api/scripts/import-cti-csv.ts
```

Chạy:

```powershell
corepack pnpm@11.9.0 run cti:import:csv -- --file ".\datasets\sample\cve-intelligence-sample.csv"
```

Đặc tính:

- parser hỗ trợ quoted CSV;
- validate CVE/CWE ID;
- upsert idempotent;
- tách `cveDescription` và `cweDescription`;
- ghi SHA-256 source/row;
- ghi SyncRun và source health;
- row không hợp lệ được reject thay vì làm hỏng toàn bộ import.

Trong Phase 2, CSV importer tập trung vào CVE/CVSS/CWE. Các cột product/CPE/reference/EPSS/KEV sẽ do adapter riêng xử lý sau.

## 4. Wazuh vulnerability synchronization

Service:

```text
apps/api/src/modules/security-data/security-data-sync.service.ts
```

Normalizer:

```text
apps/api/src/modules/security-data/wazuh-state-normalizer.ts
```

Flow:

1. Resolve CYRP Device và Wazuh binding.
2. Tạo SyncRun `WAZUH_VULNERABILITIES`.
3. Query state index theo `agent.id`.
4. Chuẩn hóa các field có thể thay đổi theo schema.
5. Upsert CVE và Wazuh CVSS metric.
6. Upsert reference hợp lệ.
7. Upsert `detected_vulnerabilities` theo source document.
8. Nếu kết quả hoàn chỉnh, đánh dấu record cũ không còn xuất hiện là `RESOLVED`.
9. Nếu truncate/reject, SyncRun là `PARTIAL`.
10. Cập nhật source health.

### Resolve safety

Không resolve record cũ khi collection bị truncate. Điều này tránh coi “không được tải vì giới hạn” là “đã được vá”.

## 5. Endpoint context synchronization

Các category:

```text
hardware
hotfixes
packages
ports
processes
services
system
```

Flow:

1. Đọc live Agent từ Wazuh Server API.
2. Query từng inventory state index.
3. Một category lỗi không làm mất toàn bộ context; kết quả chuyển `PARTIAL`.
4. Tạo `EndpointContextSnapshot` mới.
5. Cập nhật current Device/Binding metadata.
6. Ghi completeness, counts, truncation và errors.

## 6. Sync orchestration

### Manual USER

```text
POST /api/v1/devices/:deviceId/data-sync
```

Backend kiểm tra ownership.

### Manual ADMIN

```text
POST /api/v1/admin/devices/:deviceId/data-sync
POST /api/v1/admin/data-sync/all
```

### Scheduler

```env
WAZUH_DATA_SYNC_ENABLED=true
WAZUH_DATA_SYNC_INTERVAL_SECONDS=900
WAZUH_DATA_SYNC_MAX_CONCURRENCY=1
```

Scheduler mặc định tắt. Bản hiện tại chỉ phù hợp một API instance vì lock nằm trong memory.

### Component isolation

Full sync chạy ba component độc lập:

- alert/security snapshot;
- vulnerabilities;
- endpoint context.

Kết quả tổng thể:

- `COMPLETED`: cả ba thành công;
- `PARTIAL`: có cả thành công và lỗi/partial;
- `FAILED`: cả ba thất bại.

## 7. API surface

### USER

| Method | Path | Mục đích |
|---|---|---|
| GET | `/dashboard/data-overview` | Tổng quan Phase 2 |
| GET | `/devices/:id/overview` | Device detail |
| POST | `/devices/:id/data-sync` | Sync thiết bị thuộc user |
| GET | `/devices/:id/context` | Latest endpoint context |
| GET | `/vulnerabilities` | Danh sách CVE occurrence |
| GET | `/vulnerabilities/:id` | Chi tiết occurrence + CTI/context |
| GET | `/sync-runs` | Lịch sử sync của user |

### ADMIN

| Method | Path | Mục đích |
|---|---|---|
| GET | `/admin/dashboard` | Operational dashboard |
| GET | `/admin/devices` | Toàn bộ endpoint |
| GET | `/admin/devices/:id` | Endpoint detail |
| POST | `/admin/devices/:id/data-sync` | Sync một endpoint |
| POST | `/admin/data-sync/all` | Sync mọi binding |
| GET | `/admin/wazuh-bindings` | Danh sách binding |
| GET | `/admin/vulnerabilities` | Toàn bộ occurrence |
| GET | `/admin/vulnerabilities/:id` | Vulnerability detail |
| GET | `/admin/sync-runs` | Sync history |
| GET | `/admin/cti-sources` | CTI registry/statistics |
| GET | `/admin/system-health` | DB/Wazuh/Indexer/scheduler |

Wazuh live endpoints:

```text
GET /wazuh/status
GET /wazuh/agents
POST /wazuh-bindings
DELETE /wazuh-bindings/:deviceId
```

Các path trên nằm sau global prefix `/api/v1`.

## 8. User Portal

Routes:

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

Các visualizations không cần thư viện chart ngoài:

- severity distribution bars;
- device/CVE metric cards;
- freshness/status badges;
- inventory counts;
- vulnerability ranking;
- sync outcome summaries.

## 9. Admin Portal

Routes:

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

Admin có thể:

- xem live Wazuh Agents;
- bind Agent chưa gắn vào Device chưa gắn;
- unbind mà không xóa Agent;
- sync một hoặc toàn bộ endpoint;
- theo dõi source/SyncRun/system health.

## 10. Security controls

- BFF HttpOnly cookie, backend JWT/RBAC.
- Ownership check cho USER device/vulnerability/sync history.
- Wazuh credentials chỉ ở backend.
- TLS verification mặc định bật.
- DTO validation và UUID pipe.
- Không ghi token vào report verification.
- Query pagination/limits để bảo vệ API/Indexer.
- Per-device in-process sync lock.

## 11. Upgrade/rollback

### Upgrade

1. Backup PostgreSQL.
2. Cài dependency.
3. `db:generate`.
4. `db:migrate` hoặc `db:deploy`.
5. `db:seed:phase2`.
6. Import CTI sample.
7. `pnpm verify`.
8. Chạy app với Wazuh disabled.
9. Cấu hình Wazuh và test manual sync.
10. Chỉ bật scheduler sau khi manual sync ổn định.

### Rollback application

Có thể chạy lại source cũ nhưng database đã có table mới. Các table mới không ảnh hưởng source cũ vì đều bổ sung.

### Rollback data

Không nên drop thủ công khi đã có dữ liệu. Khôi phục từ backup là cách an toàn nhất. Prisma `migrate dev` không được dùng để rollback production.
