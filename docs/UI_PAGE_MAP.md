# CYRP Phase 2 — UI Page Map và API Contract

## 1. User Portal

Base URL mặc định: `http://localhost:3002`

| Route | Trạng thái | Dữ liệu chính |
|---|---|---|
| `/dashboard` | Hoàn thành | Device/CVE/severity/freshness/top items |
| `/devices` | Hoàn thành | Device, binding, snapshot, sync action |
| `/devices/:deviceId` | Hoàn thành | Overview, inventory/context, CVE, sync history |
| `/vulnerabilities` | Hoàn thành | Filter/pagination, device–CVE–package |
| `/vulnerabilities/:id` | Hoàn thành | CVE, CVSS, CWE, threat signal, context/evidence |
| `/sync-history` | Hoàn thành | SyncRun outcome/counters/error |
| `/reports` | Hoàn thành | Data-quality/coverage/severity summary |
| `/settings` | Hoàn thành | Account/session/integration guidance |

### User BFF routes

```text
/api/dashboard/data-overview
/api/devices
/api/devices/:deviceId/overview
/api/devices/:deviceId/context
/api/devices/:deviceId/data-sync
/api/vulnerabilities
/api/vulnerabilities/:id
/api/sync-runs
```

BFF lấy HttpOnly cookie và forward Bearer token tới NestJS API.

## 2. Admin Portal

Base URL mặc định: `http://localhost:3000`

| Route | Trạng thái | Chức năng |
|---|---|---|
| `/dashboard` | Hoàn thành | System KPIs, source/sync/vulnerability overview |
| `/users` | Hoàn thành | Danh sách user |
| `/endpoints` | Hoàn thành | Toàn bộ device, owner, Agent, CVE/context freshness |
| `/endpoints/:deviceId` | Hoàn thành | Endpoint operational detail và manual sync |
| `/agents` | Hoàn thành | Live Agent status, runtime refresh, binding/unbinding |
| `/vulnerabilities` | Hoàn thành | Toàn bộ device–CVE occurrence |
| `/vulnerabilities/:id` | Hoàn thành | CTI + endpoint evidence |
| `/sync` | Hoàn thành | Sync all, filtering, live SyncRun status |
| `/cti` | Hoàn thành | Source registry, CTI counts, import guidance |
| `/system` | Hoàn thành | DB/Wazuh API/Indexer/scheduler health |

### Admin BFF routes

```text
/api/admin/dashboard
/api/admin/devices
/api/admin/devices/:deviceId
/api/admin/devices/:deviceId/data-sync
/api/admin/data-sync/all
/api/admin/wazuh-agents
/api/admin/wazuh-status
/api/admin/wazuh-bindings
/api/admin/wazuh-bindings/:deviceId
/api/admin/wazuh-bindings/status-refresh
/api/admin/wazuh-bindings/:deviceId/status-refresh
/api/admin/vulnerabilities
/api/admin/vulnerabilities/:id
/api/admin/sync-runs
/api/admin/cti-sources
/api/admin/system-health
```

## 3. Trạng thái UI bắt buộc

Mỗi data-heavy page phân biệt:

- loading;
- no data;
- Wazuh disabled;
- unavailable/error;
- partial sync;
- stale data;
- complete data.

Không coi `0` là tương đương “chưa sync”.

## 4. Visual language

- Desktop-first responsive layout.
- Dark neutral surfaces + violet brand accent.
- Semantic colors chỉ cho status/severity.
- Label đi cùng màu để hỗ trợ accessibility.
- Metric cards, filter bars, tables, status badges và inline notices.
- Charts dùng CSS/SVG nhẹ và luôn có số/text fallback.

## 5. Navigation completeness

Tất cả mục navigation hiện trỏ đến route thật. Không còn item disabled giả trong User/Admin shell Phase 2.

Search và notification toàn cục vẫn chưa có event/search model nên control được giữ ở trạng thái không gây hiểu nhầm; chúng không phải điều kiện nghiệm thu Phase 2.

## 6. Data contract conventions

- Date/time trả ISO-8601.
- Pagination dùng `page`, `limit`, `total`, `totalPages`.
- Vulnerability list trả occurrence ID, không chỉ CVE ID.
- Device detail trả latest context cùng freshness.
- Sync response chứa status từng component.
- UI không gọi heuristic là AI hoặc probability.

## 7. Kiểm tra quyền

### USER

- USER không truy cập Admin Portal session.
- USER chỉ xem device/vulnerability/sync run có `device.userId` của mình.
- Thay UUID bằng của user khác phải nhận 404/403 tùy endpoint contract.

### ADMIN

- ADMIN xem được toàn bộ hệ thống.
- Binding mutation chỉ có ở Admin.
- Wazuh credentials không được trả về browser.
