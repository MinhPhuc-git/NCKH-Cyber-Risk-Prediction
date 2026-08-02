# Manifest bản review CYRP

Ngày review: 12/07/2026

## 1. Đầu vào

```text
Archive: cyrp-platform-review-20260712-154239.zip
SHA-256: edd4c3bdb29d54c32fdbe04ea83b80b546f87335e35fa47f82d0aee2e4fe083d
Số entry: 308
Kích thước archive: 432,167 bytes
```

Tất cả entry đầu vào dùng dấu `\` kiểu Windows. Sau khi chuẩn hóa sang `/`, không phát hiện đường dẫn tuyệt đối hoặc path traversal `..`.

## 2. Thành phần source hiện tại

| Thành phần | Công nghệ/chức năng |
|---|---|
| `apps/api` | NestJS API, auth/RBAC, device, enrollment, Wazuh binding, analysis/snapshot |
| `apps/portal-web` | Next.js Admin Portal |
| `apps/user-web` | Next.js User Portal |
| `database/prisma` | Prisma schema và 4 migration PostgreSQL |
| `apps/bootstrapper-windows` | PowerShell Wazuh enrollment/bootstrapper |
| `apps/bootstrapper-linux` | Bash Wazuh enrollment/bootstrapper |
| `legacy/custom-agent-windows` | Custom Python agent cũ, giữ lại để tham chiếu migration |
| `docs/review` | Audit, kiến trúc, data model, UI/UX, security, test và run guide |

Phiên bản chính khai báo trong source:

```text
Node engine: ^22.11.0 || ^24.0.0
pnpm: 11.9.0
NestJS: ^10.2.3
Next.js: 16.2.9
React: 19.2.4
Prisma: 5.22.0
PostgreSQL image: 16
```

## 3. Quy mô code

```text
TypeScript/TSX: 119 file
Prisma migration: 4
Prisma model: 9
Prisma enum: 4
API controller: 10
Unit/e2e spec: 10
Test setup: 1
Admin page: 4
Admin BFF route: 4
User page: 5
User BFF route: 8
```

Các file cần ưu tiên tách nhỏ sau khi có regression test:

```text
apps/api/src/modules/wazuh/wazuh.service.ts                         1,229 dòng
apps/api/src/modules/security-snapshots/security-snapshots.service.ts 1,010+ dòng
apps/portal-web/src/app/users/users-page-client.tsx                  599 dòng
apps/user-web/src/app/devices/devices-page-client.tsx                573 dòng
```

## 4. Mức độ hoàn thiện theo lớp

| Lớp | Hiện trạng |
|---|---|
| Identity/Auth/RBAC | Có prototype hoạt động; đã tăng cường role gate ở BFF |
| Device ownership | Có; cần thêm IDOR integration test |
| Enrollment/Wazuh binding | Có; cần rate limit, queue và orphan reconciliation |
| Wazuh Manager/Indexer access | Có; đã thêm disable flag, timeout và response cap |
| Current alert/inventory snapshot | Có; chỉ giữ trạng thái mới nhất |
| Vulnerability-state sync | Chưa có |
| CTI ETL/normalized CTI schema | Chưa có |
| Endpoint context history | Chưa có |
| Feature vector/label dataset | Chưa có |
| Model registry/inference | Chưa có |
| Append-only risk assessment | Chưa có |
| Recommendation engine | Chưa có |
| Admin/User UI mục tiêu | Mới là skeleton/prototype, chưa đủ sitemap luận văn |

## 5. Tài liệu trong bản reviewed

```text
README.md
README_REVIEW.md
PROJECT_STATUS.md
docs/architecture.md
docs/roadmap.md
docs/review/AUDIT_REPORT.md
docs/review/ARCHITECTURE_NOTES.md
docs/review/TARGET_DATA_MODEL.md
docs/review/UI_UX_SPEC.md
docs/review/SECURITY_REVIEW.md
docs/review/RUN_GUIDE.md
docs/review/TEST_REPORT.md
docs/review/CHANGELOG_REVIEW.md
```

## 6. Hành động ưu tiên sau review

1. Rotate/revoke credential đã từng nằm trong archive gốc.
2. Chạy `pnpm install --frozen-lockfile` và `pnpm verify` trên máy có Internet.
3. Chốt prediction target/label/time window trước khi thêm migration AI.
4. Triển khai CTI schema + vulnerability sync + endpoint context history.
5. Chuyển scheduler sang worker/queue trước khi scale nhiều API replica.
6. Thêm rate limit, origin/CSRF enforcement và audit cho enrollment/auth.
7. Hoàn thiện User/Admin information architecture theo `UI_UX_SPEC.md`.
