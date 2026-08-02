# Kiến trúc CYRP — Phase 2

## 1. Kiến trúc đã triển khai

```mermaid
flowchart LR
    U[USER Browser] --> UW[Next.js User Portal :3002]
    A[ADMIN Browser] --> AW[Next.js Admin Portal :3000]
    UW -->|BFF + HttpOnly JWT cookie| API[NestJS API :3001]
    AW -->|BFF + HttpOnly JWT cookie| API

    API --> PG[(PostgreSQL / Prisma)]
    API --> WM[Wazuh Server API]
    API --> WI[Wazuh Indexer]

    WIN[Windows/Linux Bootstrapper] --> API
    WIN --> WA[Official Wazuh Agent]
    WA --> WM
    WM --> WI

    WI --> ALERT[Alert Snapshot]
    WI --> VULN[Vulnerability State Sync]
    WI --> CTX[Endpoint Context Sync]

    ALERT --> DSS[(device_security_snapshots)]
    VULN --> DV[(detected_vulnerabilities)]
    CTX --> ECS[(endpoint_context_snapshots)]

    CSV[Normalized CTI CSV] --> ETL[CTI CSV Importer]
    ETL --> CTI[(CVE / CVSS / CWE / refs)]

    DSS --> PG
    DV --> PG
    ECS --> PG
    CTI --> PG
```

## 2. Phân tách trách nhiệm

### Wazuh

- Agent thu thập inventory/telemetry endpoint.
- Manager quản lý Agent và phát hiện lỗ hổng.
- Indexer giữ alert và state index.

### CYRP Backend

- Xác thực, RBAC và ownership.
- Quản lý Device–Agent binding.
- Đọc Wazuh bằng service account phía server.
- Chuẩn hóa state documents.
- Đồng bộ idempotent vào PostgreSQL.
- Lưu snapshot lịch sử và metadata sync.
- Phục vụ API cho hai portal.

### PostgreSQL

- Identity/device/binding.
- Current operational snapshot.
- CTI normalized tables.
- Detected vulnerability history/state.
- Endpoint context append-only.
- Sync observability.

### Portal

- Không truy cập trực tiếp Wazuh/Indexer.
- Không giữ JWT trong JavaScript; BFF sử dụng HttpOnly cookie.
- Phân tách USER và ADMIN.

## 3. Luồng đồng bộ một thiết bị

```mermaid
sequenceDiagram
    actor User as USER/ADMIN
    participant UI as Web Portal
    participant API as NestJS API
    participant WAPI as Wazuh API
    participant IDX as Wazuh Indexer
    participant DB as PostgreSQL

    User->>UI: Đồng bộ thiết bị
    UI->>API: POST data-sync
    API->>DB: Kiểm tra ownership/binding + acquire lock
    par Alert summary
      API->>IDX: Query wazuh-alerts-*
      IDX-->>API: Aggregations/latest alerts
      API->>DB: Upsert DeviceSecuritySnapshot
    and Vulnerability state
      API->>IDX: Query wazuh-states-vulnerabilities-*
      IDX-->>API: Device-CVE-package documents
      API->>DB: Upsert CVE + detected_vulnerabilities
      API->>DB: Resolve missing docs only for complete result
    and Endpoint context
      API->>WAPI: Read live Agent status
      API->>IDX: Query inventory state indices
      IDX-->>API: packages/ports/processes/hotfixes/services/system/hardware
      API->>DB: Append EndpointContextSnapshot
    end
    API->>DB: Complete/partial/fail SyncRun
    API-->>UI: Component results + timestamps
```

## 4. Data identity

Một vulnerability occurrence được định danh bằng source document của Wazuh và gắn với:

```text
(device_id, wazuh_agent_id, cve_id, package, source_index, source_document_id)
```

Một endpoint context sample được định danh về mặt nghiên cứu bởi:

```text
(device_id, as_of_time)
```

Khi tích hợp AI sau này, đơn vị feature tối thiểu vẫn là:

```text
(device_id, cve_id, as_of_time)
```

## 5. Safety controls

- Query state có page size và maximum items.
- Kết quả truncate được đánh dấu `PARTIAL`.
- Chỉ resolve vulnerability cũ khi collection hoàn chỉnh.
- Một device không thể chạy hai sync cùng lúc trong cùng API process.
- Scheduler mặc định tắt.
- Credentials Wazuh chỉ ở backend `.env`.
- TLS verification mặc định bật.

## 6. Phần chưa thuộc Phase 2

```mermaid
flowchart LR
    CTI[(CTI)] --> FB[Feature Builder]
    DV[(Detected Vulnerabilities)] --> FB
    EC[(Endpoint Context)] --> FB
    FB --> FV[(Feature Vectors)]
    FV --> MODEL[AI Model Service]
    MODEL --> RA[(Risk Assessments)]
    RA --> REC[(Recommendations)]
```

Phần trên sẽ được tích hợp riêng sau khi prediction target, label, temporal split và model contract được hoàn thành.
