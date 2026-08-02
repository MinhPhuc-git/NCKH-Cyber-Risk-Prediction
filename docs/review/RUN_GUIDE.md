# Hướng dẫn chạy và xác minh CYRP

## 1. Chuẩn bị

- Node.js `^22.11.0` hoặc `^24.0.0`.
- Corepack.
- Internet để tải pnpm/dependency trong lần cài đầu.
- Docker Desktop hoặc PostgreSQL 16.

Kiểm tra:

```powershell
node --version
corepack --version
```

Kích hoạt đúng pnpm:

```powershell
corepack enable
corepack prepare pnpm@11.9.0 --activate
pnpm --version
```

## 2. Cấu hình

```powershell
Copy-Item .env.example .env
Copy-Item apps\portal-web\.env.example apps\portal-web\.env.local
Copy-Item apps\user-web\.env.example apps\user-web\.env.local
```

Đổi ít nhất:

- `POSTGRES_PASSWORD`;
- `DATABASE_URL` tương ứng;
- `JWT_SECRET` ngẫu nhiên ≥ 32 ký tự.

Để chạy mà chưa có Wazuh:

```env
WAZUH_INTEGRATION_ENABLED=false
WAZUH_ACTIVE_SYNC_ENABLED=false
```

## 3. Cài và migrate

```powershell
pnpm install --frozen-lockfile
pnpm docker:db:up
pnpm db:generate
pnpm db:migrate
```

Tạo ADMIN:

```powershell
$env:SEED_ADMIN_EMAIL = "admin@cyrp.local"
$env:SEED_ADMIN_FULL_NAME = "CYRP Administrator"
$env:SEED_ADMIN_PASSWORD = "replace-with-a-strong-password"
pnpm db:seed
```

## 4. Chạy

Terminal 1:

```powershell
pnpm dev:api
```

Terminal 2:

```powershell
pnpm dev:admin
```

Terminal 3:

```powershell
pnpm dev:user
```

URL:

- API: `http://localhost:3001/api/v1`
- Health: `http://localhost:3001/api/v1/health`
- Swagger: `http://localhost:3001/api/docs`
- Admin: `http://localhost:3000`
- User: `http://localhost:3002`

## 5. Bật Wazuh

1. Tạo service account Wazuh Manager API.
2. Tạo Indexer read-only role chỉ cho index cần truy vấn.
3. Cài CA tin cậy vào máy chạy API.
4. Điền `.env` và bật:

```env
WAZUH_INTEGRATION_ENABLED=true
WAZUH_API_REJECT_UNAUTHORIZED=true
WAZUH_INDEXER_REJECT_UNAUTHORIZED=true
```

Chỉ bật active sync trên một API instance:

```env
WAZUH_ACTIVE_SYNC_ENABLED=true
```

Kiểm tra:

```text
GET /api/v1/wazuh/status
GET /api/v1/wazuh/agents
```

## 6. Enrollment Windows

Trong User Portal tạo one-time code. Trên endpoint, mở PowerShell Administrator tại root source và chạy:

```powershell
powershell `
  -NoProfile `
  -ExecutionPolicy Bypass `
  -File .\apps\bootstrapper-windows\Invoke-CyrpWazuhBootstrapper.ps1 `
  -BackendBaseUrl "https://cyrp-api.example.internal" `
  -EnrollmentCode "CYRP-XXXX-XXXX" `
  -MsiPath "D:\Installers\wazuh-agent-compatible.msi"
```

Trong production phải dùng HTTPS và MSI tương thích Wazuh Manager.

## 7. Verification

```powershell
pnpm db:validate
pnpm lint
pnpm typecheck
pnpm test:api
pnpm test:e2e:api
pnpm build
```

Hoặc:

```powershell
pnpm verify
```

Kiểm tra thủ công tối thiểu:

1. ADMIN login được Admin Portal; USER bị 403 và không nhận cookie Admin.
2. USER login được User Portal; ADMIN bị 403.
3. USER A không đọc/sync device của USER B.
4. Enrollment code hết hạn/dùng lại bị từ chối.
5. Khi Wazuh off, API auth/device vẫn khởi động nếu integration disabled.
6. Production response không lộ chi tiết lỗi upstream Wazuh.
7. Search/notification disabled, không tạo control giả.

## 8. Đóng gói review

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\create-review-archive.ps1
```

Giải nén ZIP tạo ra vào thư mục mới và kiểm tra không có `.env`, token, private key, `credentials.json`, `identity.json`, `scan-*.json`, `node_modules` hoặc build output.
