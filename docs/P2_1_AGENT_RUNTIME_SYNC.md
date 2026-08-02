# CYRP Phase 2.1 — Agent Runtime and Data Sync Reliability

## Mục tiêu

Phase 2.1 không thêm AI. Bản cập nhật tập trung làm cho Wazuh Agent, binding và pipeline đồng bộ dữ liệu vận hành ổn định hơn trước khi tiếp tục hoàn thiện User Portal và Admin Portal.

## Thành phần mới

### Database-backed device sync lease

Bảng `device_sync_leases` giữ một lease duy nhất cho mỗi Device. Lease có:

- `owner_id` nhận diện API instance và lần chạy;
- `acquired_at`;
- `expires_at`;
- heartbeat gia hạn lease khi đồng bộ còn chạy;
- cleanup lease hết hạn khi API khởi động.

Cơ chế này thay thế lock chỉ nằm trong RAM. Hai API instance không thể đồng bộ cùng một Device tại cùng thời điểm.

### Stale SyncRun recovery

Khi API khởi động, các `SyncRun` còn `RUNNING` quá ngưỡng cấu hình sẽ được chuyển sang `FAILED`. Điều này xử lý trường hợp tiến trình bị tắt đột ngột trước khi cập nhật trạng thái cuối.

### Agent status reconciliation

CYRP có thể làm mới trạng thái của từng binding hoặc toàn bộ binding qua Wazuh Manager API. Kết quả được lưu tại `wazuh_agent_bindings`:

- `last_status_checked_at`;
- `last_status_error`;
- `consecutive_status_failures`;
- `last_known_status`;
- `last_keep_alive_at`.

Scheduler mặc định tắt. Chỉ bật sau khi manual refresh hoạt động ổn định.

### Wazuh request retry

Các request an toàn như GET, Indexer search và authentication được retry có giới hạn khi gặp:

- timeout hoặc lỗi mạng;
- HTTP 408;
- HTTP 425;
- HTTP 429;
- HTTP 500, 502, 503, 504.

Tạo hoặc xóa Wazuh Agent không được tự động retry vì có side effect.

## Endpoint mới

| Method | Endpoint | Quyền | Chức năng |
|---|---|---|---|
| POST | `/api/v1/wazuh-bindings/status-refresh` | ADMIN | Làm mới toàn bộ Agent đã binding |
| POST | `/api/v1/wazuh-bindings/:deviceId/status-refresh` | ADMIN | Làm mới một Agent binding |

## Biến môi trường mới

```env
WAZUH_REQUEST_RETRY_ATTEMPTS=3
WAZUH_REQUEST_RETRY_BASE_DELAY_MS=250

WAZUH_DATA_SYNC_LOCK_TTL_SECONDS=900
WAZUH_DATA_SYNC_STALE_RUN_MINUTES=30

WAZUH_AGENT_STATUS_SYNC_ENABLED=false
WAZUH_AGENT_STATUS_SYNC_INTERVAL_SECONDS=300
WAZUH_AGENT_STATUS_SYNC_MAX_CONCURRENCY=4
```

## Quy tắc vận hành

1. Giữ `WAZUH_AGENT_STATUS_SYNC_ENABLED=false` trong lần chạy đầu.
2. Kiểm tra Manager và Indexer tại Admin `/system`.
3. Chạy manual Agent status refresh tại Admin `/agents`.
4. Chạy manual data sync cho một endpoint.
5. Kiểm tra `SyncRun`, vulnerability và endpoint context.
6. Chỉ bật Agent status scheduler khi manual refresh ổn định.
7. Chỉ bật data scheduler khi manual data sync ổn định.

## Kiểm thử hồi quy

Các E2E test hiện có được cập nhật database mock cho hai tác vụ bootstrap mới: cleanup lease hết hạn và recovery `SyncRun` bị treo. Điều này ngăn module khởi tạo thất bại khi test auth/health/users không dùng PostgreSQL thật.

## Giới hạn còn lại

- Chưa có queue/worker riêng.
- Retry hiện nằm trong API process.
- Chưa có Prometheus/OpenTelemetry.
- Chưa có retention policy cho endpoint snapshots và SyncRun.
- Chưa có AI model, feature builder hoặc risk inference.
