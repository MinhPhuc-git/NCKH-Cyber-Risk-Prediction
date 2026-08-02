# Runbook Wazuh Agent/Manager/Indexer cho CYRP Phase 2

## 1. Mục tiêu

Runbook này giúp xác minh toàn bộ đường đi:

```text
Endpoint → Wazuh Agent → Wazuh Manager → Wazuh Indexer
                                     ↓
                              CYRP Backend
                                     ↓
                           PostgreSQL + Portals
```

## 2. Điều kiện trước khi bật tích hợp

- Wazuh Agent đã cài trên endpoint.
- Agent xuất hiện trong Wazuh Manager và có trạng thái `active`.
- Wazuh vulnerability detection đã bật.
- Syscollector đã thu thập inventory.
- Wazuh Indexer có state indices.
- CYRP Backend truy cập được Wazuh API `55000` và Indexer `9200`.
- Tài khoản API/Indexer riêng, quyền tối thiểu.
- CA/certificate hợp lệ.

## 3. Cấu hình `.env`

```env
WAZUH_INTEGRATION_ENABLED=true

WAZUH_API_BASE_URL=https://WAZUH_MANAGER:55000
WAZUH_API_USERNAME=CYRP_API_ACCOUNT
WAZUH_API_PASSWORD=CHANGE_ME
WAZUH_API_REJECT_UNAUTHORIZED=true
WAZUH_API_TIMEOUT_MS=10000
WAZUH_API_TOKEN_TTL_SECONDS=900

WAZUH_INDEXER_BASE_URL=https://WAZUH_INDEXER:9200
WAZUH_INDEXER_USERNAME=CYRP_INDEXER_READONLY
WAZUH_INDEXER_PASSWORD=CHANGE_ME
WAZUH_INDEXER_REJECT_UNAUTHORIZED=true
WAZUH_INDEXER_TIMEOUT_MS=15000
WAZUH_MAX_RESPONSE_BYTES=10485760

WAZUH_STATE_PAGE_SIZE=250
WAZUH_STATE_MAX_ITEMS_PER_CATEGORY=5000

WAZUH_AGENT_MANAGER_ADDRESS=WAZUH_MANAGER_ADDRESS_REACHABLE_BY_ENDPOINT
WAZUH_AGENT_MANAGER_PORT=1514
WAZUH_AGENT_MANAGER_PROTOCOL=tcp

# Bắt đầu với scheduler tắt
WAZUH_ACTIVE_SYNC_ENABLED=false
WAZUH_DATA_SYNC_ENABLED=false
WAZUH_DATA_SYNC_INTERVAL_SECONDS=900
WAZUH_DATA_SYNC_MAX_CONCURRENCY=1
```

Không commit `.env`.

## 4. Khởi động an toàn

```powershell
corepack pnpm@11.9.0 run dev:api
corepack pnpm@11.9.0 run dev:admin
corepack pnpm@11.9.0 run dev:user
```

Kiểm tra:

```powershell
Invoke-RestMethod http://localhost:3001/api/v1/health
```

Sau đó đăng nhập Admin Portal và mở:

```text
/system
/agents
/sync
```

## 5. Xác minh Wazuh Server API

Admin Portal `/system` phải hiển thị:

- Wazuh API: connected;
- manager name/version;
- thời điểm kiểm tra.

Hoặc chạy verifier:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File `
  .\scripts\verify-phase-2-data-foundation.ps1 `
  -AdminEmail "admin@cyrp.local"
```

Nếu lỗi:

1. Kiểm tra DNS/IP từ máy chạy API.
2. Kiểm tra firewall cổng 55000.
3. Kiểm tra username/password.
4. Kiểm tra CA/certificate hostname.
5. Không tắt TLS verification trong production để “chữa nhanh”.

## 6. Xác minh Agent

Tại Admin `/agents`:

- Agent endpoint phải xuất hiện.
- Không bind Agent `000` vì đó là Manager.
- Trạng thái nên là `active`.
- Last keepalive phải cập nhật.
- OS/version/IP nên có dữ liệu.

Nếu Agent không active:

### Windows

```powershell
Get-Service WazuhSvc
Get-Content "C:\Program Files (x86)\ossec-agent\ossec.log" -Tail 100
```

### Linux

```bash
sudo systemctl status wazuh-agent
sudo tail -n 100 /var/ossec/logs/ossec.log
```

Kiểm tra endpoint có thể kết nối Manager cổng enrollment/communication theo cấu hình Wazuh của bạn.

## 7. Enrollment bằng CYRP

### USER flow

1. USER đăng nhập `/devices`.
2. Tạo enrollment code.
3. Dùng bootstrapper chính thức.
4. Bootstrapper gọi CYRP API để tạo Device/Agent/binding.
5. Wazuh Agent được cài và khởi động.
6. Chờ Agent active.

### Windows bootstrapper

Đọc:

```text
apps/bootstrapper-windows/README.md
```

Entrypoint:

```text
apps/bootstrapper-windows/Invoke-CyrpWazuhBootstrapper.ps1
```

### Linux bootstrapper

Đọc:

```text
apps/bootstrapper-linux/README.md
```

Không lưu enrollment output/client key trong source hoặc ZIP luận văn.

## 8. Binding Agent đã tồn tại

Admin `/agents` hỗ trợ:

1. Chọn Wazuh Agent chưa bind.
2. Chọn CYRP Device chưa bind.
3. Xác nhận binding.

Backend xác minh Agent tồn tại trên Wazuh trước khi upsert binding.

Unbind chỉ xóa quan hệ CYRP:

```text
DELETE /api/v1/wazuh-bindings/:deviceId
```

Wazuh Agent vẫn còn trên Manager.

## 9. Xác minh Indexer

Admin `/system` phải hiển thị:

- connected;
- cluster name/status;
- node/shard summary.

Indexer service account cần read access tối thiểu đến:

```text
wazuh-alerts-*
wazuh-states-vulnerabilities-*
wazuh-states-inventory-hardware-*
wazuh-states-inventory-hotfixes-*
wazuh-states-inventory-packages-*
wazuh-states-inventory-ports-*
wazuh-states-inventory-processes-*
wazuh-states-inventory-services-*
wazuh-states-inventory-system-*
```

Không dùng Indexer admin account cho CYRP.

## 10. Chạy manual sync đầu tiên

1. Chọn một Agent active đã bind.
2. Mở Admin `/endpoints/:deviceId` hoặc `/sync`.
3. Chạy sync một thiết bị.
4. Chờ response component:
   - alerts;
   - vulnerabilities;
   - endpointContext.
5. Mở `/sync` để xem hai SyncRun state.
6. Mở User Device Detail/Vulnerabilities để kiểm tra dữ liệu.

Hoặc dùng script:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File `
  .\scripts\verify-phase-2-data-foundation.ps1 `
  -AdminEmail "admin@cyrp.local" `
  -RunDeviceSync `
  -DeviceId "DEVICE-UUID"
```

## 11. Ý nghĩa trạng thái

### `COMPLETED`

Toàn bộ category trong component được tải đầy đủ trong giới hạn.

### `PARTIAL`

Có thể do:

- một inventory index/category không có hoặc query lỗi;
- dữ liệu vượt `WAZUH_STATE_MAX_ITEMS_PER_CATEGORY`;
- vulnerability row không chuẩn hóa được;
- một component trong full sync thất bại.

Không đồng nghĩa toàn bộ sync vô dụng. Xem `checkpoint_after`, `completeness` và error.

### `FAILED`

Không thể hoàn tất component. Kiểm tra credentials, TLS, permission, index pattern và network.

## 12. Trường hợp không có CVE

Nếu sync thành công nhưng không có vulnerability:

- thiết bị có thể chưa có package dễ bị ảnh hưởng;
- vulnerability detection chưa cập nhật xong;
- inventory chưa được thu thập;
- index state chưa được tạo;
- Agent ID/binding sai;
- service account không có quyền đọc index.

Không dùng số 0 như bằng chứng tuyệt đối rằng thiết bị an toàn. UI hiển thị freshness và sync status để phân biệt “0” với “chưa có dữ liệu”.

## 13. Bật scheduler

Chỉ bật sau khi manual sync nhiều lần ổn định:

```env
WAZUH_DATA_SYNC_ENABLED=true
WAZUH_DATA_SYNC_INTERVAL_SECONDS=900
WAZUH_DATA_SYNC_MAX_CONCURRENCY=1
```

Khởi động lại API. Kiểm tra `/system`:

- configured: true;
- enabled: true;
- running: false khi idle;
- activeDeviceSyncs: 0 khi idle.

Không chạy nhiều API replica với scheduler cùng bật. Giai đoạn production cần queue + distributed lock.

## 14. Data retention

Context snapshot có thể tăng nhanh. Trước khi triển khai dài hạn:

- xác định chu kỳ sync;
- tính dung lượng package/process JSON;
- giữ snapshot full theo ngày hoặc theo thay đổi;
- archive/delete theo retention policy;
- cân nhắc partition theo tháng/device;
- không xóa dữ liệu dùng cho thực nghiệm mà chưa tạo manifest/hash.

## 15. Checklist chấp nhận

- [ ] API health và DB up.
- [ ] Wazuh API connected.
- [ ] Wazuh Indexer connected.
- [ ] Ít nhất một Agent endpoint active.
- [ ] Device–Agent binding đúng.
- [ ] Alert snapshot cập nhật.
- [ ] Vulnerability SyncRun completed/partial có giải thích.
- [ ] Endpoint Context SyncRun completed/partial có giải thích.
- [ ] Context snapshot có package/port/process counts.
- [ ] User chỉ xem được thiết bị của mình.
- [ ] Admin xem được toàn hệ thống.
- [ ] Không có credential trong source/report/ảnh luận văn.
