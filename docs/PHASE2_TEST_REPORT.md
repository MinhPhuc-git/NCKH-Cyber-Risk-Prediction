# CYRP Phase 2 — Test Report

Cập nhật: 12/07/2026

## 1. Baseline đã được người dùng xác minh trước Phase 2

Trên máy Windows của người dùng, bản reviewed ngay trước khi mở rộng đã đạt:

| Kiểm tra | Kết quả |
|---|---:|
| Prisma validate | PASS |
| ESLint API/Admin/User | PASS |
| TypeScript API/Admin/User | PASS |
| Unit test | 19/19 PASS |
| API e2e test | 7/7 PASS |
| NestJS build | PASS |
| Admin Next.js build | PASS |
| User Next.js build | PASS |

Đây là baseline đã chạy thật. Kết quả baseline không được dùng để thay thế verification của source Phase 2 sau khi migration/module/page mới được thêm vào.

## 2. Kiểm tra tĩnh thực hiện cho source Phase 2

| Kiểm tra | Phạm vi | Kết quả |
|---|---:|---:|
| TypeScript/TSX parser | 187 file | PASS, 0 parse errors |
| Semantic scan riêng theo project | API/Admin/User | PASS, 0 actionable diagnostics sau khi loại lỗi do dependency declarations chưa cài |
| CSS Module class references | User/Admin UI | PASS, 0 missing classes |
| Import-usage heuristic | TS/TSX | PASS, 0 possible unused imports |
| Duplicate object/JSX key scan | TS/TSX | PASS, 0 findings |
| JSON parse | 12 file | PASS |
| YAML parse | 3 file | PASS |
| JavaScript/MJS/CJS syntax | 8 file | PASS |
| Python compile | 17 file | PASS |
| Bash syntax | 3 file | PASS |
| UTF-8/NUL scan | 318 text files | PASS |
| User/Admin route presence | 18 expected pages | PASS, 0 missing |
| Prisma model-to-migration table check | 19 model/table mappings | PASS, 0 missing |
| Phase 2 required table check | 11 tables | PASS |
| Phase 2 migration FK/index review | 13 FK, 28 indexes | PASS tĩnh |
| Symlink scan | Source tree | PASS, 0 symlinks |
| Runtime secret/private-key scan | Source tree | PASS, 0 findings |
| Forbidden build/runtime artifact scan | Source tree | PASS, 0 findings |

Static semantic checks đã phát hiện và được sửa trong quá trình review:

- biểu thức TSX trộn `??` và `||` không có ngoặc ở User Device Detail;
- `import.meta` không tương thích API CommonJS trong CTI importer;
- query severity rỗng không được chuẩn hóa;
- response endpoint context có nguy cơ trả toàn bộ inventory quá lớn;
- BFF header merge không bao phủ mọi dạng `HeadersInit`;
- Phase 2 seed phụ thuộc không cần thiết vào working directory cố định.

## 3. Kiểm tra runtime chưa thể chạy trong môi trường xử lý

| Kiểm tra | Trạng thái |
|---|---|
| `pnpm install --frozen-lockfile` | Không chạy được; DNS tới npm registry trả `EAI_AGAIN` |
| `prisma validate` bằng Prisma CLI | Chờ máy người dùng |
| Full ESLint/TypeScript/Jest/build | Chờ máy người dùng |
| Wazuh normalizer Jest test | Source đã thêm, chờ local `pnpm verify` |
| Live PostgreSQL migration | Chưa có PostgreSQL runtime dự án |
| Live Wazuh API/Indexer/Agent sync | Chưa có hạ tầng Wazuh |
| PowerShell parser | `pwsh` không có trong môi trường xử lý |

Lần thử cài dependency cuối cùng thất bại tại:

```text
getaddrinfo EAI_AGAIN registry.npmjs.org
```

Do đó, không tuyên bố source Phase 2 đã build hoặc live-sync thành công cho đến khi các acceptance gate trên máy người dùng đạt.

## 4. Verification bắt buộc trên máy người dùng

### 4.1 Backup, dependency và migration

```powershell
corepack pnpm@11.9.0 install --frozen-lockfile
corepack pnpm@11.9.0 run db:generate
corepack pnpm@11.9.0 run db:validate
corepack pnpm@11.9.0 run db:status
corepack pnpm@11.9.0 run db:migrate
corepack pnpm@11.9.0 run db:seed:phase2
```

Trước migration phải tạo database backup. Xem `docs/LOCAL_UPGRADE_CHECKLIST.md`.

### 4.2 Import CTI sample

```powershell
corepack pnpm@11.9.0 run cti:import:csv -- `
  --file ".\datasets\sample\cve-intelligence-sample.csv"
```

Chạy lại cùng lệnh một lần.

Kỳ vọng:

- `SyncRun` nguồn `CTI_CSV` hoàn tất;
- CVE/CVSS/CWE xuất hiện;
- lần chạy thứ hai update/upsert, không duplicate.

### 4.3 Full source verification

```powershell
corepack pnpm@11.9.0 run verify
```

Kỳ vọng:

- Prisma valid;
- lint/typecheck pass;
- unit/e2e pass, bao gồm normalizer mới;
- API/Admin/User build pass.

### 4.4 Smoke test khi Wazuh tắt

```env
WAZUH_INTEGRATION_ENABLED=false
WAZUH_ACTIVE_SYNC_ENABLED=false
WAZUH_DATA_SYNC_ENABLED=false
```

Kỳ vọng:

- API/Admin/User khởi động;
- auth/RBAC hoạt động;
- Admin `/system` hiển thị Wazuh disabled/offline thay vì healthy giả;
- CTI pages đọc được dữ liệu import;
- mọi page navigation Phase 2 mở được.

### 4.5 Live Wazuh verification

Sau khi cấu hình Wazuh và binding đúng:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File `
  .\scripts\verify-phase-2-data-foundation.ps1 `
  -AdminEmail "admin@cyrp.local" `
  -RunDeviceSync `
  -DeviceId "DEVICE-UUID"
```

Kỳ vọng:

- Wazuh connected = true;
- live Agent trả về và Agent endpoint active;
- binding count đúng;
- vulnerability/context sync không FAILED hoàn toàn;
- tạo `SyncRun`, `detected_vulnerabilities`, `endpoint_context_snapshots`;
- dữ liệu xuất hiện ở cả Admin và đúng User owner.

## 5. Acceptance test cases

### Security/RBAC

- [ ] USER không vào Admin Portal.
- [ ] ADMIN không được coi là User Portal session.
- [ ] USER A không đọc Device/Vulnerability/SyncRun của USER B.
- [ ] Agent `000` không bind được.
- [ ] Một Wazuh Agent không bind đồng thời hai Device.
- [ ] Browser không nhận Wazuh credentials.
- [ ] Unbind không xóa Agent trên Wazuh Manager.

### Data sync

- [ ] Chạy lại cùng Wazuh document không duplicate.
- [ ] Truncated result không resolve record cũ.
- [ ] Full result có thể resolve record không còn xuất hiện.
- [ ] Một inventory category lỗi tạo `PARTIAL` và giữ category khác.
- [ ] Hai sync đồng thời cùng Device bị chặn 409.
- [ ] Context tạo snapshot mới thay vì update snapshot cũ.
- [ ] Empty index/no data được phân biệt với query error.
- [ ] Preview API giới hạn 50 item/category nhưng count phản ánh dữ liệu lưu.

### UI

- [ ] 18 route chính mở được.
- [ ] Loading/error/empty/partial/stale hiển thị khác nhau.
- [ ] Filter/pagination hoạt động.
- [ ] Sync button chống double click.
- [ ] Vulnerability detail hiển thị device/package/CVE/CTI/context/source.
- [ ] Admin Agent binding workflow hoạt động.
- [ ] Mobile/tablet không tràn layout quan trọng.

## 6. Warnings không phải lỗi chặn

- Prisma 5 có thể thông báo có major version mới; không nâng major trong đợt này.
- `ts-jest` có thể cảnh báo config `globals` deprecated; cần tách sửa riêng sau Phase 2.
- Một số inventory category có thể không tồn tại trên mọi Wazuh version/OS; sync phải ghi `PARTIAL` và error metadata thay vì làm mất toàn bộ snapshot.

## 7. Kết luận kiểm thử hiện tại

Source Phase 2 đã qua kiểm tra cấu trúc, syntax, route, schema/migration alignment và secret scan. Đây là **candidate release**. Chỉ đổi trạng thái sang locally validated sau khi `pnpm verify`, migration thật, CTI idempotency và live Wazuh verification đều đạt trên máy người dùng.
