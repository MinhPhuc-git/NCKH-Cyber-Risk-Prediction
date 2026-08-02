# CYRP Phase 2 — Checklist nâng cấp trên Windows

Cập nhật: 12/07/2026

Tài liệu này dùng khi nâng cấp từ bản `cyrp-platform-reviewed` đã chạy đúng sang bản Phase 2. Thực hiện lần lượt, không ghi đè source cũ và không bật scheduler Wazuh trước khi manual sync thành công.

## 1. Chuẩn bị

- [ ] Giữ nguyên thư mục source đang hoạt động để rollback.
- [ ] Giải nén Phase 2 sang một thư mục mới.
- [ ] Docker Desktop/PostgreSQL đang hoạt động.
- [ ] Node.js là `22.11.0+` trong dòng 22 hoặc dòng 24.
- [ ] Không copy `node_modules`, `.next`, `dist`, `artifacts`, `backups` từ source cũ.
- [ ] Chỉ copy `.env` và hai file `.env.local` sau khi đã kiểm tra không có biến lỗi thời.

Ví dụ:

```powershell
Set-Location "D:\LuanVan\test\cyrp-platform-phase2"
node --version
corepack --version
Test-Path .\package.json
```

## 2. Sao lưu database

Khi PostgreSQL dùng Docker Compose:

```powershell
New-Item -ItemType Directory -Path .\backups -Force | Out-Null
$databaseContainer = docker compose ps -q db
if (-not $databaseContainer) {
    throw "PostgreSQL container is not running"
}

docker compose exec -T db sh -lc `
  "pg_dump -U cyrp -d cyrp -Fc -f /tmp/cyrp-before-phase2.dump"

docker cp `
  "${databaseContainer}:/tmp/cyrp-before-phase2.dump" `
  ".\backups\cyrp-before-phase2.dump"

docker compose exec -T db rm -f /tmp/cyrp-before-phase2.dump
Get-Item .\backups\cyrp-before-phase2.dump
```

Không dùng trực tiếp `pg_dump -Fc > file.dump` trong Windows PowerShell 5.1 vì redirection của shell có thể làm thay đổi byte của file dump nhị phân.

Không đưa file dump vào ZIP chia sẻ hoặc Git.

## 3. Cấu hình môi trường

Copy cấu hình đang chạy từ source cũ, sau đó bổ sung các biến Phase 2 sau vào `.env`:

```env
WAZUH_STATE_PAGE_SIZE=250
WAZUH_STATE_MAX_ITEMS_PER_CATEGORY=5000
WAZUH_MAX_RESPONSE_BYTES=10485760

WAZUH_DATA_SYNC_ENABLED=false
WAZUH_DATA_SYNC_INTERVAL_SECONDS=900
WAZUH_DATA_SYNC_MAX_CONCURRENCY=1

CTI_CSV_PATH=./datasets/sample/cve-intelligence-sample.csv
```

Ở lần khởi động đầu tiên nên giữ:

```env
WAZUH_INTEGRATION_ENABLED=false
WAZUH_ACTIVE_SYNC_ENABLED=false
WAZUH_DATA_SYNC_ENABLED=false
```

Kiểm tra hai portal:

```powershell
Get-Content .\apps\portal-web\.env.local
Get-Content .\apps\user-web\.env.local
```

Giá trị cơ bản:

```env
CYRP_API_BASE_URL=http://localhost:3001/api/v1
CYRP_API_TIMEOUT_MS=10000
```

## 4. Cài dependency và kiểm tra schema

```powershell
corepack pnpm@11.9.0 install --frozen-lockfile
corepack pnpm@11.9.0 run db:generate
corepack pnpm@11.9.0 run db:validate
corepack pnpm@11.9.0 run db:status
```

Không nâng Prisma major trong đợt này.

## 5. Áp dụng migration Phase 2

Máy phát triển local:

```powershell
corepack pnpm@11.9.0 run db:migrate
```

Môi trường chỉ triển khai migration đã commit:

```powershell
corepack pnpm@11.9.0 run db:deploy
```

Sau migration:

```powershell
corepack pnpm@11.9.0 run db:status
```

Migration Phase 2 phải xuất hiện ở trạng thái applied:

```text
20260712190000_phase2_data_foundation
```

## 6. Seed source registry

```powershell
corepack pnpm@11.9.0 run db:seed:phase2
```

Kỳ vọng:

```text
Phase 2 source registry seeded: 6 sources
```

Seed này idempotent và không đổi mật khẩu Admin.

## 7. Import CTI mẫu

```powershell
corepack pnpm@11.9.0 run cti:import:csv -- `
  --file ".\datasets\sample\cve-intelligence-sample.csv"
```

Chạy lại một lần để kiểm tra idempotency:

```powershell
corepack pnpm@11.9.0 run cti:import:csv -- `
  --file ".\datasets\sample\cve-intelligence-sample.csv"
```

Kỳ vọng:

- không tạo CVE/CVSS/CWE trùng;
- có `SyncRun` nguồn `CTI_CSV`;
- trang Admin `/cti` hiển thị source và số bản ghi.

## 8. Full verification khi Wazuh còn tắt

```powershell
corepack pnpm@11.9.0 run verify
```

Chỉ tiếp tục khi Prisma, lint, typecheck, unit/e2e và ba build đều pass.

## 9. Chạy ba ứng dụng

Mở ba PowerShell riêng tại thư mục gốc.

### API

```powershell
corepack pnpm@11.9.0 run dev:api
```

### Admin Portal

```powershell
corepack pnpm@11.9.0 run dev:admin
```

### User Portal

```powershell
corepack pnpm@11.9.0 run dev:user
```

Kiểm tra:

```powershell
Invoke-RestMethod http://localhost:3001/api/v1/health |
  ConvertTo-Json -Depth 10
```

Mở:

```text
http://localhost:3000
http://localhost:3002
```

## 10. Smoke test giao diện khi Wazuh tắt

- [ ] Admin đăng nhập được.
- [ ] User đăng nhập được.
- [ ] Admin `/dashboard`, `/endpoints`, `/agents`, `/vulnerabilities`, `/sync`, `/cti`, `/system` mở được.
- [ ] User `/dashboard`, `/devices`, `/vulnerabilities`, `/sync-history`, `/reports`, `/settings` mở được.
- [ ] `/system` hiển thị Wazuh disabled/offline, không giả vờ healthy.
- [ ] User A không xem được UUID device/vulnerability của User B.

## 11. Bật Wazuh cho manual verification

Cấu hình tài khoản quyền tối thiểu và TLS trước, sau đó:

```env
WAZUH_INTEGRATION_ENABLED=true
WAZUH_ACTIVE_SYNC_ENABLED=false
WAZUH_DATA_SYNC_ENABLED=false
```

Khởi động lại API. Kiểm tra Admin:

```text
/system
/agents
```

Kỳ vọng:

- Wazuh Manager connected;
- Indexer connected;
- Agent endpoint xuất hiện và có keep-alive;
- Agent `000` không được binding.

## 12. Manual sync một thiết bị

Từ Admin Portal, bind một Agent active với đúng CYRP Device rồi chạy sync tại `/endpoints/:deviceId`.

Hoặc dùng verifier:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File `
  .\scripts\verify-phase-2-data-foundation.ps1 `
  -AdminEmail "admin@cyrp.local" `
  -RunDeviceSync `
  -DeviceId "DEVICE-UUID"
```

Kiểm tra:

- [ ] alert/security snapshot có kết quả hoặc lỗi giải thích được;
- [ ] vulnerability SyncRun không FAILED hoàn toàn;
- [ ] endpoint-context SyncRun không FAILED hoàn toàn;
- [ ] có context snapshot mới, không ghi đè lịch sử;
- [ ] CVE occurrence xuất hiện tại User/Admin Portal;
- [ ] chạy lại không tạo duplicate theo source document;
- [ ] kết quả truncate được đánh dấu `PARTIAL` và không resolve nhầm record cũ.

## 13. Chỉ bật scheduler sau manual sync

```env
WAZUH_DATA_SYNC_ENABLED=true
WAZUH_DATA_SYNC_INTERVAL_SECONDS=900
WAZUH_DATA_SYNC_MAX_CONCURRENCY=1
```

Bản hiện tại chỉ phù hợp một API instance. Không bật scheduler đồng thời trên nhiều replica.

## 14. Rollback

Nếu migration hoặc ứng dụng có vấn đề:

1. Dừng ba ứng dụng.
2. Không tự ý xóa migration đã áp dụng trên database dùng chung.
3. Khôi phục database sang một database mới từ backup để xác minh:

```powershell
createdb-command-or-Docker-equivalent
pg_restore-command-or-Docker-equivalent
```

4. Chạy lại source cũ với database cũ/đã restore.
5. Ghi lại log lỗi, `pnpm verify`, Prisma status và SyncRun trước khi sửa tiếp.

## 15. Điều kiện chấp nhận Phase 2

- [ ] `pnpm verify` pass.
- [ ] migration applied.
- [ ] CTI sample import idempotent.
- [ ] Admin/User navigation đầy đủ.
- [ ] Wazuh API và Indexer kết nối bằng tài khoản quyền tối thiểu.
- [ ] ít nhất một Agent active và binding đúng.
- [ ] manual data sync sinh vulnerability/context data.
- [ ] UI phân biệt zero/no-data/partial/error/stale.
- [ ] không có `.env`, token, private key, telemetry thật trong archive.
