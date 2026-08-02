# Báo cáo xác minh kỹ thuật bản reviewed

Ngày kiểm tra: 12/07/2026  
Phạm vi: `/mnt/data/cyrp-platform-reviewed`

## 1. Kết luận

Các kiểm tra tĩnh có thể thực hiện trong môi trường review đều đạt. Source TypeScript/TSX không có lỗi cú pháp hoặc lỗi transpile cơ bản; JSON, YAML, JavaScript, Python, Bash và cấu trúc CSS cơ bản đều hợp lệ. Bản reviewed không còn runtime credential đã phát hiện trong archive gốc, không còn file private key, `.env` thật hoặc các file telemetry legacy đã biết.

Tuy nhiên, đây **không phải xác nhận rằng toàn bộ ứng dụng đã build và chạy end-to-end**. Môi trường review không có `node_modules`, không có Docker và không thể tải pnpm/dependency từ registry. Vì vậy các bước cần dependency như Prisma validation, ESLint, Jest, Nest build và Next build chưa chạy được tại đây.

## 2. Môi trường

```text
Node.js: v22.16.0
npm: 10.9.2
Corepack: 0.32.0
TypeScript dùng cho kiểm tra cú pháp: 5.8.3
Docker: không khả dụng
PowerShell/pwsh: không khả dụng
node_modules: không có trong archive, đúng theo quy trình đóng gói
```

Node.js đáp ứng engine của dự án (`^22.11.0 || ^24.0.0`).

## 3. Kiểm tra đã chạy

| Nhóm | Phạm vi | Kết quả |
|---|---:|---|
| TypeScript/TSX parse + transpile syntax | 119 file | PASS, 0 error |
| JSON parse | 12 file | PASS, 0 error |
| YAML parse | 3 file | PASS, 0 error |
| JavaScript/MJS syntax (`node --check`) | 8 file | PASS, 0 error |
| Python AST syntax | 17 file | PASS, 0 error |
| Bash syntax (`bash -n`) | 3 file | PASS, 0 error |
| CSS brace structure cơ bản | 10 file | PASS, 0 error |
| UTF-8/NUL scan | 221 file văn bản | PASS |
| Forbidden runtime filename scan | toàn bộ tree | PASS |
| Private-key header scan | toàn bộ tree | PASS |
| High-confidence token pattern scan | toàn bộ tree | PASS |
| Đối chiếu secret từ archive gốc | 1 giá trị runtime | PASS, 0 giá trị còn lại |
| Archive path safety | 308 entry đầu vào | PASS sau khi chuẩn hóa dấu `\` |

### Ý nghĩa của TypeScript check

Kiểm tra đã dùng TypeScript parser và `transpileModule` để phát hiện lỗi cú pháp/JSX/decorator cơ bản. Nó **không thay thế** semantic type-check của `tsc`, vì semantic check cần toàn bộ package và type declaration trong `node_modules`.

### Ý nghĩa của CSS check

CSS check chỉ xác minh cấu trúc dấu ngoặc sau khi bỏ comment/string. Nó không thay thế PostCSS/Tailwind/Next production build.

## 4. Kiểm tra chưa chạy được

| Kiểm tra | Trạng thái | Nguyên nhân |
|---|---|---|
| `pnpm install --frozen-lockfile` | NOT RUN | Không có kết nối registry; Corepack không tải được pnpm 11.9.0 |
| `pnpm db:validate` | NOT RUN | Prisma CLI/dependency chưa cài |
| `pnpm lint` | NOT RUN | ESLint và plugin workspace chưa cài |
| `pnpm typecheck` | NOT RUN | Type declaration của Nest/Next/React/Prisma chưa cài |
| `pnpm test:api` | NOT RUN | Jest và dependency chưa cài |
| `pnpm test:e2e:api` | NOT RUN | Jest/Supertest/PostgreSQL chưa sẵn sàng |
| `pnpm build` | NOT RUN | Nest/Next dependency chưa cài |
| Migration trên PostgreSQL 16 | NOT RUN | Docker/PostgreSQL không khả dụng |
| PowerShell parser/runtime test | NOT RUN | `pwsh`/Windows PowerShell không có trong môi trường |
| Wazuh Manager/Indexer integration | NOT RUN | Không có Wazuh test environment và không dùng credential thật |

Lần thử `corepack pnpm --version` trong môi trường review bị dừng bởi lỗi DNS/network khi truy cập npm registry (`EAI_AGAIN`). Không dùng workaround tải dependency từ nguồn không xác định.

## 5. Lệnh bắt buộc chạy trên máy dự án

Tại thư mục gốc của bản reviewed:

```powershell
corepack enable
corepack prepare pnpm@11.9.0 --activate
pnpm install --frozen-lockfile
pnpm verify
```

`pnpm verify` hiện bao gồm:

```text
Prisma validate
ESLint cho API/Admin/User
Type-check cho API/Admin/User
Jest unit test API
Jest e2e test API
Nest build
Next build Admin Portal
Next build User Portal
```

Sau đó kiểm tra migration trên database thử nghiệm, không dùng database production:

```powershell
Copy-Item .env.example .env
pnpm docker:db:up
pnpm db:generate
pnpm db:migrate
```

## 6. Smoke test đề xuất sau khi build

1. USER đăng ký và đăng nhập User Portal.
2. ADMIN đăng nhập Admin Portal; USER phải bị chặn ở Admin Portal.
3. Logout phải xóa cookie và quay về login.
4. USER A không đọc/sync được `deviceId` của USER B.
5. Enrollment code hết hạn hoặc đã dùng phải bị từ chối.
6. Khi `WAZUH_INTEGRATION_ENABLED=false`, API vẫn khởi động và endpoint Wazuh trả trạng thái disabled có kiểm soát.
7. Khi Wazuh bật, dùng tài khoản service/read-only và TLS verification.
8. Response Wazuh vượt giới hạn phải bị hủy, không làm tăng bộ nhớ vô hạn.
9. Dashboard phải phân biệt rõ no data, stale, sync failed và giá trị 0.
10. Risk card hiện tại phải ghi `WAZUH_HEURISTIC_V1`, không được gắn nhãn AI/Attack Probability.

## 7. Tiêu chí chấp nhận trước khi merge

Bản reviewed chỉ nên được coi là đã xác minh để tiếp tục phát triển khi máy dự án có kết quả:

```text
pnpm install --frozen-lockfile  PASS
pnpm verify                    PASS
PostgreSQL migration           PASS
Admin/User smoke test          PASS
Wazuh integration smoke test   PASS hoặc được tắt có chủ ý
PowerShell bootstrapper test   PASS trên Windows test VM
```

Giữ lại log của các lệnh trên làm phụ lục kỹ thuật; không đưa secret, IP thật hoặc token vào log công khai.
