# Báo cáo audit source CYRP

Ngày review: 12/07/2026  
Phạm vi: toàn bộ archive `cyrp-platform-review-20260712-154239.zip`

## 1. Kết luận điều hành

Source hiện tại là một **prototype tích hợp Wazuh có nền tảng tốt**, không phải bản hoàn chỉnh của hệ thống dự đoán rủi ro được mô tả trong luận văn. Luồng auth/RBAC, ownership thiết bị, enrollment một lần, Wazuh binding, dashboard và bootstrapper đã có. Tuy nhiên, data plane CTI/AI cốt lõi chưa tồn tại trong schema và code.

Bản reviewed đã xử lý ngay các lỗi có thể sửa an toàn mà không thay đổi mô hình nghiệp vụ lớn:

- loại bỏ runtime secret/telemetry khỏi gói source;
- chặn USER đăng nhập Admin Portal;
- nối User Portal với phiên thật và thêm logout;
- cho phép tắt Wazuh trong dev/test;
- giới hạn kích thước response Wazuh;
- ẩn chi tiết lỗi upstream ở production;
- bật/tắt Swagger bằng biến môi trường;
- sửa lỗi hiển thị login error;
- sửa hướng dẫn bootstrapper sai đường dẫn;
- bổ sung script đóng gói an toàn, tài liệu chạy và lộ trình.

Không tự ý thêm migration CTI/AI vào database đang dùng. Các bảng đó phụ thuộc vào prediction target, label và time semantics; tạo vội sẽ làm schema khó bảo vệ về mặt khoa học.

## 2. Kiểm kê

- Monorepo pnpm, 3 ứng dụng Node/Next/Nest.
- 231 file trong bản reviewed trước khi tạo bộ tài liệu cuối.
- 119 file TypeScript/TSX.
- 4 Prisma migration, 9 model nghiệp vụ và 4 enum trong schema hiện tại.
- 10 file unit/e2e spec và 1 test setup được phát hiện.
- Windows/Linux Wazuh bootstrapper và một custom agent Python đã được chuyển vào `legacy/`.

## 3. Phát hiện theo mức độ ưu tiên

### CYRP-SEC-001 — Archive chứa credential runtime và telemetry thiết bị

**Mức độ: Critical**  
**Trạng thái: Đã loại khỏi bản reviewed; cần hành động vận hành từ chủ dự án**

Archive ban đầu chứa:

- `legacy/custom-agent-windows/data/credentials.json` với agent token dạng live-looking;
- `identity.json`;
- `latest-scan.json` và nhiều `scan-*.json`;
- `config.json`;
- hostname, IP nội bộ, username, port/process, hardware, file hash và dữ liệu inventory.

Rủi ro không chỉ là lộ token mà còn là lộ sơ đồ bề mặt tấn công của endpoint. `.gitignore` đã chặn các file này trong Git, nhưng quy trình ZIP trước đây vẫn sao chép chúng.

**Đã sửa trong source reviewed:**

- xóa runtime JSON và local config khỏi bản giao;
- thêm lớp ignore ở root;
- thêm `scripts/create-review-archive.ps1` với staging, danh sách loại trừ và kiểm tra private key/runtime file.

**Hành động bắt buộc:**

1. Thu hồi/rotate agent credential tương ứng nếu vẫn còn hiệu lực.
2. Xóa token runtime cũ trên endpoint và re-enroll nếu agent đó còn được sử dụng.
3. Xóa archive cũ khỏi nơi chia sẻ, cloud drive và lịch sử gửi file khi có thể.
4. Không đưa giá trị secret thật vào báo cáo luận văn hoặc screenshot.

### CYRP-AUTH-001 — Admin Portal trước review không bắt buộc role ADMIN tại BFF

**Mức độ: High**  
**Trạng thái: Đã sửa**

Backend `/users` có RBAC đúng, nhưng BFF login của Admin Portal trước review có thể tạo cookie cho một tài khoản USER. Người đó không đọc được endpoint ADMIN, nhưng vẫn vào được shell/dashboard Admin và tạo ra ranh giới quyền mơ hồ.

**Đã sửa:**

- login Admin chỉ đặt cookie khi `payload.user.role === 'ADMIN'`;
- `/api/auth/me` Admin kiểm tra role, trả 403 và xóa cookie nếu sai role;
- User Portal tiếp tục chặn mọi role khác USER.

### CYRP-DATA-001 — Schema hiện tại chưa biểu diễn bài toán luận văn

**Mức độ: High / blocker khoa học**  
**Trạng thái: Chưa triển khai; đã có thiết kế đích**

Schema hiện có chỉ gồm identity, device, enrollment, Wazuh binding, analysis run và latest security snapshot. Các bảng sau chưa có:

- CVE/CVSS/CWE/references/affected products;
- detected vulnerabilities;
- endpoint context có lịch sử;
- feature vectors;
- model versions;
- risk assessments append-only;
- recommendations.

Không thể tuyên bố hệ thống đã thực hiện contextual risk prediction chỉ từ schema hiện tại. Xem `TARGET_DATA_MODEL.md`.

### CYRP-ML-001 — Điểm hiện tại là heuristic cảnh báo Wazuh, không phải AI

**Mức độ: High / blocker về cách tuyên bố**  
**Trạng thái: Code hiện đã ghi chú trung thực; cần giữ nguyên ranh giới này**

Công thức hiện tại dùng số lượng alert theo severity và max rule level, chuẩn hóa về 0–100. API trả:

```text
method = WAZUH_HEURISTIC_V1
note = Điểm tạm tính từ cảnh báo Wazuh, chưa phải kết quả mô hình học máy.
```

Đây là một baseline hợp lệ cho prototype, nhưng không phải exploitation probability. Khi trình bày cần gọi là **Wazuh alert heuristic** hoặc **operational risk indicator**.

### CYRP-DATA-002 — `DeviceSecuritySnapshot` chỉ giữ trạng thái mới nhất

**Mức độ: High đối với dataset/model**  
**Trạng thái: Chưa thay đổi schema; đã đề xuất hướng migration**

`deviceId @unique` khiến mỗi sync ghi đè bản cũ. Hệ thống không thể tái tạo trạng thái endpoint tại một thời điểm lịch sử, không thể tạo dataset `(device, CVE, as_of_time)` và khó audit thay đổi score.

Giữ bảng hiện tại như materialized current view là hợp lý, nhưng cần thêm append-only `endpoint_context_snapshots` và `risk_assessments`.

### CYRP-OPS-001 — Scheduler chạy trong API process

**Mức độ: High khi scale**  
**Trạng thái: Giảm rủi ro bằng cờ tắt; chưa tách worker**

Mỗi API replica sẽ khởi tạo timer riêng. Cờ `syncRunning` chỉ bảo vệ trong cùng process, không phải distributed lock. Khi scale ngang có thể sync trùng, tăng tải Wazuh và ghi đè snapshot.

**Đã sửa:** scheduler chỉ bật khi cả `WAZUH_INTEGRATION_ENABLED` và `WAZUH_ACTIVE_SYNC_ENABLED` là true; ví dụ môi trường mặc định tắt.

**Cần làm:** chuyển ETL/sync/inference sang worker + queue; dùng advisory lock hoặc job uniqueness.

### CYRP-OPS-002 — Analysis run xử lý đồng bộ và có race tạo run

**Mức độ: Medium–High**  
**Trạng thái: Chưa sửa kiến trúc**

Request `POST analysis-runs` chờ Wazuh hoàn tất. Check “active run” và create không nằm trong một cơ chế uniqueness ở DB, nên hai request đồng thời có thể cùng qua check.

**Cần làm:** API chỉ enqueue và trả 202; worker cập nhật trạng thái. Thêm partial unique index cho run active hoặc khóa transaction/advisory lock theo `device_id`.

### CYRP-SEC-002 — Chưa có rate limiting cho login/register/enrollment

**Mức độ: Medium–High**  
**Trạng thái: Chưa triển khai**

`/auth/login`, `/auth/register` và đặc biệt `/agents/enroll` là public. Enrollment code có entropy tốt và TTL 10 phút, đồng thời được tiêu thụ atomically, nhưng thiếu rate limit vẫn tạo rủi ro brute force và resource exhaustion ở Wazuh.

**Cần làm:** rate limit theo IP + account/code fingerprint, backoff, audit failed attempts và reverse-proxy limits.

### CYRP-SEC-003 — Ví dụ Wazuh từng dùng TLS verification off và account Indexer admin

**Mức độ: Medium–High**  
**Trạng thái: Đã sửa example; hạ tầng thật cần kiểm tra**

Bản reviewed dùng `*_REJECT_UNAUTHORIZED=true` và tên account least-privilege. Trong lab self-signed, nên cài CA thay vì tắt verify. Không dùng account `admin` của Indexer cho ứng dụng hoặc Grafana.

### CYRP-SEC-004 — Response Wazuh không có giới hạn và lỗi upstream bị lộ

**Mức độ: Medium**  
**Trạng thái: Đã sửa**

- thêm `WAZUH_MAX_RESPONSE_BYTES` mặc định 5 MiB;
- hủy response quá lớn;
- chỉ trả `detail` trong môi trường không phải production;
- thêm timeout cho BFF gọi backend.

### CYRP-UX-001 — Login error Admin nằm bên trong nút submit

**Mức độ: Medium**  
**Trạng thái: Đã sửa**

Cấu trúc DOM cũ làm thông báo lỗi trở thành nội dung của button và CSS lỗi chỉ tồn tại trong media query mobile. Đã đưa alert ra trước button và áp dụng CSS ở mọi breakpoint.

### CYRP-UX-002 — User shell hiển thị trạng thái giả và thiếu logout

**Mức độ: Medium**  
**Trạng thái: Đã sửa**

Shell cũ luôn hiển thị “Người dùng CYRP / Chưa xác thực phiên” và “Agent chưa kết nối”. Bản reviewed gọi `/api/auth/me`, hiển thị user thật, redirect khi 401/403 và có logout. Search/notification chưa hoạt động được đánh dấu disabled thay vì tạo kỳ vọng sai.

### CYRP-DOC-001 — README/roadmap cũ dừng ở Phase 1

**Mức độ: Medium**  
**Trạng thái: Đã sửa**

Tài liệu cũ không phản ánh hai portal, enrollment, Wazuh và snapshot. Root README, architecture, roadmap và README từng app đã được cập nhật.

### CYRP-CODE-001 — Service/component quá lớn

**Mức độ: Medium / maintainability**  
**Trạng thái: Chưa refactor lớn**

- `wazuh.service.ts`: hơn 1.200 dòng;
- `security-snapshots.service.ts`: hơn 1.000 dòng;
- nhiều page/client component 400–600 dòng.

Nên tách Wazuh API client, Indexer client, mapper, query builder, risk baseline, scheduler và repository. Ở frontend tách data hooks, cards, tables, modal và formatter.

### CYRP-TEST-001 — Chưa chạy được full dependency-based verification trong môi trường review

**Mức độ: Informational**  
**Trạng thái: Đã chạy static syntax/format checks; full build pending**

Môi trường review không có `node_modules` và không truy cập registry để tải pnpm/dependency. Vì vậy không tuyên bố build/test thành công. Chi tiết ở `TEST_REPORT.md`.

## 4. Điểm tốt đáng giữ

- JWT guard đọc user lại từ DB, nên account DISABLED bị chặn ngay cả khi token chưa hết hạn.
- Backend RBAC bằng decorator/guard và ownership query theo `userId` giúp giảm IDOR.
- Password dùng bcrypt cost 12.
- Enrollment code được hash, TTL 10 phút và tiêu thụ bằng `updateMany` có điều kiện.
- Agent token chỉ lưu hash trong PostgreSQL và trả plaintext một lần.
- Wazuh credential nằm ở backend, không xuống portal/endpoint.
- Bootstrapper dùng DPAPI/permissioned secret storage và backup trước khi sửa Agent.
- API hiện ghi rõ heuristic không phải machine learning.

## 5. Thứ tự xử lý đề xuất

1. Rotate/revoke credential đã xuất hiện trong ZIP cũ.
2. Chạy full `pnpm verify` trên máy phát triển có dependency.
3. Tạo CTI schema + snapshot theo thời gian, nhưng chưa train model.
4. Xây vulnerability/context sync có idempotency và quality metrics.
5. Chốt prediction target/label/time horizon và protocol đánh giá.
6. Tách worker/queue, sau đó mới scale.
7. Hoàn thiện Vulnerability Detail, Risk History và Recommendation workflow.
8. Hardening production và kiểm thử nhiều Agent.
