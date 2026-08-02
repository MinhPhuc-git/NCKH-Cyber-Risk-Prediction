# Mô hình dữ liệu đích cho CYRP

Tài liệu này là thiết kế đề xuất, **chưa được áp dụng thành Prisma migration** trong bản reviewed.

## 1. Nguyên tắc

- Đơn vị đánh giá: `(device_id, cve_id, as_of_time)`.
- Dữ liệu lịch sử append-only; current view có thể materialize riêng.
- Một CVE có thể có nhiều CWE, CVSS metric, product range và reference.
- Một CVE có thể ảnh hưởng nhiều package trên cùng device.
- Prediction luôn gắn với feature vector và model version.

## 2. CTI entities

### `cves`

```text
cve_id PK
cve_description
published_at
modified_at
source
source_version
source_document_hash
ingested_at
```

### `cve_cvss_metrics`

```text
id PK
cve_id FK
source
metric_type
cvss_version
vector_string
base_score
base_severity
attack_vector
attack_complexity
privileges_required
user_interaction
scope
confidentiality_impact
integrity_impact
availability_impact
published_at
ingested_at
UNIQUE(cve_id, source, metric_type, vector_string)
```

### `cwes` và `cve_cwes`

```text
cwes(cwe_id PK, name, description, source, modified_at)
cve_cwes(cve_id FK, cwe_id FK, source, PRIMARY KEY(cve_id, cwe_id, source))
```

### `cve_references`

```text
id PK
cve_id FK
url
source
tags JSONB
content_hash
created_at
UNIQUE(cve_id, url)
```

### `cve_affected_products`

```text
id PK
cve_id FK
vendor
product
cpe_uri
version_start_including
version_start_excluding
version_end_including
version_end_excluding
version_criteria JSONB
source
UNIQUE(cve_id, source, cpe_uri, version-range fields)
```

### `cve_threat_signals`

Dùng snapshot theo ngày để tránh dùng thông tin tương lai:

```text
id PK
cve_id FK
signal_date
epss_score
epss_percentile
is_known_exploited
kev_date_added
exploit_evidence JSONB
source_versions JSONB
ingested_at
UNIQUE(cve_id, signal_date)
```

## 3. Endpoint vulnerability

### `detected_vulnerabilities`

```text
id UUID PK
device_id FK
wazuh_agent_id
cve_id FK
package_name
package_version
package_architecture
vulnerability_status
first_seen_at
last_seen_at
resolved_at NULL
source_index
source_document_id
source_updated_at
raw_payload JSONB
sync_run_id FK
created_at
updated_at
UNIQUE(source_index, source_document_id)
INDEX(device_id, cve_id, vulnerability_status)
INDEX(cve_id, last_seen_at)
```

Không dùng `UNIQUE(device_id, cve_id)` vì cùng CVE có thể đi qua nhiều package/component.

## 4. Endpoint context

### `endpoint_context_snapshots`

```text
id UUID PK
device_id FK
observed_at
as_of_time
agent_status
os_name
os_version
firewall_status
internet_exposure
packages JSONB
hotfixes JSONB
ports JSONB
processes JSONB
system_inventory JSONB
source_versions JSONB
sync_run_id FK
created_at
INDEX(device_id, as_of_time DESC)
```

Giai đoạn đầu có thể dùng JSONB có schema version; khi truy vấn ổn định mới tách child tables. Không ghi đè lịch sử.

## 5. Pipeline metadata

### `sync_runs`

```text
id PK
source_type
status
checkpoint_before JSONB
checkpoint_after JSONB
started_at
completed_at
records_read
records_written
records_rejected
error_summary
source_manifest JSONB
```

### `feature_schemas`

```text
id PK
name
version UNIQUE
feature_names JSONB
transform_contract JSONB
created_at
```

### `feature_vectors`

```text
id PK
device_id FK
detected_vulnerability_id FK
cve_id FK
endpoint_context_snapshot_id FK
feature_schema_id FK
as_of_time
features JSONB
label_value NULL
label_observed_at NULL
build_run_id FK
created_at
UNIQUE(detected_vulnerability_id, endpoint_context_snapshot_id, feature_schema_id)
```

## 6. Model và kết quả

### `model_versions`

```text
id PK
model_name
version UNIQUE
algorithm
feature_schema_id FK
training_window_start
training_window_end
artifact_uri
artifact_sha256
metrics JSONB
calibration JSONB
status (CANDIDATE/ACTIVE/RETIRED)
created_at
activated_at NULL
```

Không lưu binary model lớn trực tiếp trong PostgreSQL; lưu artifact URI + hash.

### `risk_assessments`

```text
id PK
device_id FK
detected_vulnerability_id FK
feature_vector_id FK
model_version_id FK NULL
assessment_method
contextual_risk_score
risk_level
exploitation_probability NULL
confidence NULL
explanation JSONB
predicted_at
created_at
INDEX(device_id, predicted_at DESC)
INDEX(detected_vulnerability_id, predicted_at DESC)
```

- Baseline heuristic có thể có `model_version_id = NULL`, `assessment_method = RULE_BASED_V1`.
- Chỉ ghi `exploitation_probability` khi target/label/calibration thực sự hỗ trợ xác suất.
- Bảng này tự nó là history; không cần `ai_predictions` và `prediction_history` trùng nhau.

### `recommendations`

```text
id PK
risk_assessment_id FK
device_id FK
recommendation_type
priority
title
description
evidence JSONB
rule_version
status
acknowledged_at
resolved_at
created_at
updated_at
```

## 7. Current views

Có thể tạo view/materialized view:

- `latest_device_context`;
- `active_detected_vulnerabilities`;
- `latest_risk_assessment_per_device_cve`;
- `open_recommendations`.

Nhờ vậy UI truy vấn nhanh mà vẫn giữ được lịch sử khoa học.

## 8. Migration an toàn từ schema hiện tại

1. Không xóa `device_security_snapshots` ngay; giữ làm operational summary.
2. Thêm các bảng CTI và sync metadata độc lập.
3. Thêm append-only endpoint context.
4. Backfill tối thiểu một context snapshot từ current snapshot, gắn nguồn `LEGACY_CURRENT_SNAPSHOT`.
5. Thêm detected vulnerability sync.
6. Chỉ thêm feature/model/risk tables sau khi feature schema và target được duyệt.
7. Sau khi UI dùng view mới ổn định, cân nhắc deprecate field heuristic cũ.
