# CYRP Phase 2.1 — Acceptance Test

## 1. Kiểm tra source

```powershell
corepack pnpm@11.9.0 run db:validate
corepack pnpm@11.9.0 run lint
corepack pnpm@11.9.0 run typecheck
corepack pnpm@11.9.0 run test:api
corepack pnpm@11.9.0 run test:e2e:api
corepack pnpm@11.9.0 run build
```

Hoặc:

```powershell
corepack pnpm@11.9.0 run verify
```

## 2. Kiểm tra migration

```powershell
corepack pnpm@11.9.0 run db:generate
corepack pnpm@11.9.0 run db:deploy
corepack pnpm@11.9.0 run db:status
```

Migration cần xuất hiện:

```text
20260713223000_p2_1_agent_runtime_sync
```

## 3. Smoke test khi Wazuh tắt

Giữ:

```env
WAZUH_INTEGRATION_ENABLED=false
WAZUH_AGENT_STATUS_SYNC_ENABLED=false
WAZUH_DATA_SYNC_ENABLED=false
```

Khởi động API/Admin/User và kiểm tra:

- API health trả `status=ok`;
- Admin login hoạt động;
- User login hoạt động;
- Admin `/system` không báo service online giả;
- Prisma không báo thiếu bảng `device_sync_leases`.

## 4. Manual runtime test khi Wazuh bật

Bật Wazuh integration nhưng giữ hai scheduler tắt:

```env
WAZUH_INTEGRATION_ENABLED=true
WAZUH_AGENT_STATUS_SYNC_ENABLED=false
WAZUH_DATA_SYNC_ENABLED=false
```

Kiểm tra:

1. Admin `/system` thấy Manager và Indexer online.
2. Admin `/agents` tải được live Agent inventory.
3. Bấm `Đồng bộ trạng thái Agent`.
4. Binding cập nhật `lastStatusCheckedAt`.
5. Agent lỗi phải tăng `consecutiveStatusFailures` và ghi `lastStatusError`.
6. Chạy data sync một endpoint.
7. Trong lúc sync đang chạy, gọi sync lần hai phải nhận HTTP 409.
8. Trong lúc sync đang chạy, thử gỡ binding phải nhận HTTP 409.
9. Sau sync, lease phải được xóa.

## 5. Script kiểm tra runtime

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File `
  .\scripts\verify-phase-2-1-agent-runtime.ps1 `
  -AdminEmail "admin@cyrp.local" `
  -RefreshAllAgentStatuses
```

Kiểm tra thêm data sync:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File `
  .\scripts\verify-phase-2-1-agent-runtime.ps1 `
  -AdminEmail "admin@cyrp.local" `
  -RefreshAllAgentStatuses `
  -RunDeviceSync `
  -DeviceId "DEVICE-UUID"
```

Báo cáo được lưu trong `artifacts/`.

## 6. Điều kiện đạt

- `verify` hoàn tất không lỗi.
- Migration ở trạng thái applied.
- Manager và Indexer online.
- Manual status refresh hoạt động.
- Manual data sync hoạt động.
- Không tạo hai sync đồng thời trên cùng Device.
- Không còn lease sau khi sync hoàn tất.
- Admin Agents hiển thị runtime error/failure count đúng.
