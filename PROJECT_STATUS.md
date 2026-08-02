# Trạng thái dự án CYRP

Cập nhật: 12/07/2026 — Phase 2 Data Foundation

## 1. Đã hoàn thành và có thể sử dụng

### Nền tảng

- Monorepo pnpm gồm NestJS API, Admin Portal và User Portal.
- PostgreSQL/Prisma migrations.
- JWT, trạng thái tài khoản, RBAC `ADMIN`/`USER` và ownership theo device.
- Đăng ký USER, seed ADMIN và quản lý danh sách người dùng.

### Device và Wazuh Agent

- One-time enrollment code.
- Tạo Wazuh Agent chính thức và gắn với CYRP Device.
- Windows/Linux bootstrapper.
- Admin xem live Agent, trạng thái Manager và binding.
- Admin có thể bind/unbind Wazuh Agent mà không xóa Agent khỏi Manager.
- Alert analytics, hardware/inventory summary và `DeviceSecuritySnapshot`.

### Phase 2 data foundation

- Registry nguồn CTI và metadata `SyncRun`.
- Schema CVE/CVSS/CWE/reference/affected product/threat signal.
- CLI import CSV CVE/CVSS/CWE idempotent.
- Đồng bộ `detected_vulnerabilities` từ Wazuh Indexer.
- Resolve bản ghi không còn xuất hiện chỉ khi snapshot không bị truncate.
- Append-only `endpoint_context_snapshots` gồm package, hotfix, port, process, service, system và hardware.
- Manual sync một thiết bị, sync toàn bộ và scheduler tùy chọn.
- Theo dõi partial/failure/truncation và độ mới dữ liệu.

### User Portal

- Dashboard data overview.
- Devices list và Device Detail.
- Vulnerability list/detail.
- Sync History.
- Reports/Data Summary.
- Settings/operational guidance.

### Admin Portal

- System Overview.
- Users.
- Endpoints list/detail.
- Wazuh Agents và binding management.
- Vulnerabilities list/detail.
- Data Sync operations/history.
- CTI Sources.
- System Health.

## 2. Cố ý chưa làm trong Phase 2

Theo quyết định của đề tài, phần AI được tách riêng và chưa tích hợp:

- Feature Builder.
- Feature schema/version.
- Dataset và ground-truth label.
- Model training/evaluation.
- Model registry/artifact.
- ML inference.
- Explainability/SHAP.
- `risk_assessments` dựa trên model.
- AI Recommendation Engine.

Chỉ số `WAZUH_HEURISTIC_V1` cũ tiếp tục được ghi rõ là heuristic vận hành, không phải xác suất tấn công.

## 3. Còn ở mức prototype

- Scheduler chạy trong API process; chưa có worker/queue/distributed lock.
- Lock chống duplicate sync chỉ trong một API instance.
- Inventory state dùng giới hạn số bản ghi để bảo vệ tài nguyên; dataset lớn có thể trả `PARTIAL`.
- CTI adapter NVD/EPSS/CISA KEV chưa tự động chạy.
- Package/CPE/product mapping chưa được hoàn thiện.
- Chưa có retention/partitioning cho context snapshots.
- Chưa có audit log đầy đủ cho mọi mutation.
- Chưa thực hiện load test nhiều Agent và backup/restore drill.

## 4. Kiểm tra đã thực hiện trong môi trường xử lý

- Parse/transpile syntax TypeScript/TSX: đạt.
- Kiểm tra JSON: đạt.
- Kiểm tra CSS Module reference: đạt.
- Kiểm tra migration/schema bằng đối chiếu tĩnh: đạt.
- Secret/private-key/runtime credential scan: không phát hiện trong bản phát hành.
- Quy trình đóng gói có kiểm tra ZIP integrity, single-root, path traversal, symlink, secrets và runtime artifacts; kết quả phát hành được ghi trong release manifest/checksum đi kèm archive.

Không có Wazuh Manager/Indexer hoặc PostgreSQL runtime trong môi trường xử lý, nên live sync và full `pnpm verify` phải được chạy trên máy của người dùng. Baseline trước khi thay đổi đã được người dùng xác nhận đạt lint/typecheck/unit/e2e/build.

## 5. Bước kế tiếp sau khi Phase 2 chạy ổn định

1. Chạy migration và `db:seed:phase2` trên database đã sao lưu.
2. Chạy `pnpm verify` trên máy Windows.
3. Cấu hình Wazuh và chạy script verification với một Agent thật.
4. Kiểm tra dữ liệu hiển thị tại User/Admin Portal.
5. Bổ sung NVD/CPE, EPSS và CISA KEV theo snapshot thời gian.
6. Thiết kế retention/queue/worker.
7. Chỉ sau đó mới tích hợp pipeline AI riêng.

## 6. Thuật ngữ bắt buộc

Cho đến khi có target/label và calibration hợp lệ:

- Dùng `Contextual Risk Score`, `Contextual Risk Level`, `Risk Assessment`.
- Không dùng `Attack Probability`.
- Không tuyên bố hệ thống biết trước chắc chắn cuộc tấn công.
