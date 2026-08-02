# Security review CYRP

## 1. Tài sản cần bảo vệ

- Wazuh API/Indexer credentials và client key.
- CYRP JWT, agent token và enrollment code.
- User/device ownership mapping.
- Endpoint telemetry: IP, process, port, package, vulnerability.
- CTI/feature/model artifacts và risk assessment.
- Audit trail và recommendation state.

## 2. Kiểm soát hiện có

- Bcrypt cost 12 cho password.
- JWT guard và kiểm tra user ACTIVE từ DB ở mỗi request.
- RBAC `ADMIN`/`USER`.
- Ownership query theo `userId` cho device/snapshot/analysis.
- HttpOnly, SameSite=Lax, Secure-in-production cookie ở hai BFF.
- Enrollment code hash + TTL + one-time atomic consumption.
- Agent token hash trong DB; plaintext trả một lần.
- Wazuh secrets chỉ ở backend.
- Helmet, validation whitelist và forbid unknown fields.
- Timeout cho Wazuh và BFF; response cap cho Wazuh.
- Security headers cơ bản ở hai Next app.

## 3. Threat scenarios và xử lý

### Credential disclosure

**Scenario:** source ZIP/log/screenshot chứa token hoặc Indexer credential.  
**Hiện trạng:** đã xảy ra với legacy runtime file trong archive gốc.  
**Control:** archive script, ignore rules, secret rotation, CI secret scan, log redaction.

### IDOR

**Scenario:** USER đổi `deviceId` để đọc/sync thiết bị người khác.  
**Control hiện có:** query `findFirst({ id, userId })`; giữ pattern này ở mọi resource mới.  
**Cần thêm:** integration test IDOR cho snapshot, analysis và recommendation.

### Role confusion

**Scenario:** USER nhận session Admin Portal.  
**Control:** role gate ở BFF login/me và backend RBAC. Đã sửa trong review.

### Enrollment abuse

**Scenario:** brute force code, spam create Wazuh Agent, race/replay.  
**Control hiện có:** entropy, TTL, hash, one-time update, cleanup Agent.  
**Cần thêm:** rate limit, failed-attempt audit, per-installation/IP quota, queue và orphan reconciliation.

### SSRF/config abuse

**Scenario:** attacker kiểm soát Wazuh base URL.  
**Hiện trạng:** URL chỉ từ trusted env, không từ request; nguy cơ thấp.  
**Cần thêm:** production allowlist/internal DNS, TLS, egress firewall.

### Upstream resource exhaustion

**Scenario:** Wazuh trả payload lớn hoặc treo.  
**Control:** timeout, max response bytes và bounded alert sample. Đã tăng cường trong review.

### CSRF against BFF mutation

**Scenario:** cross-site hoặc same-site malicious origin gửi POST bằng cookie.  
**Hiện trạng:** SameSite=Lax giảm phần lớn cross-site POST nhưng chưa có token/origin enforcement.  
**Cần thêm:** kiểm tra `Origin`/`Host`, CSRF token cho mutation nhạy cảm, không dùng GET để thay đổi state.

### Data poisoning/telemetry manipulation

**Scenario:** compromised endpoint/Wazuh feed làm sai feature và score.  
**Cần thêm:** provenance, schema validation, outlier checks, source cross-check, immutable dataset/version và audit.

### Model leakage/manipulation

**Scenario:** feature dùng dữ liệu tương lai hoặc model artifact bị thay.  
**Cần thêm:** as-of join, artifact SHA-256/signature, model registry, approval workflow và immutable evaluation report.

## 4. Việc phải làm trước production

### P0

- Rotate credential đã xuất hiện trong archive cũ.
- Bật TLS verification với CA tin cậy.
- Tạo account Wazuh/Indexer quyền tối thiểu.
- Rate limit login/register/enrollment.
- Secret manager; không dùng `.env` plaintext trên server production.

### P1

- Queue/worker và distributed lock.
- Refresh-token rotation/session revocation hoặc access token rất ngắn hạn + re-auth policy.
- CSRF/origin validation.
- Audit log cho login, enrollment, sync, model activation, recommendation changes.
- Dependency/SAST/secret scan trong CI.
- Retention và encryption-at-rest cho endpoint telemetry.

### P2

- Network segmentation, egress allowlist và mTLS nội bộ nếu cần.
- DAST/load test/fuzz API.
- Backup/restore drill.
- Incident response runbook.
- Multi-tenant isolation test nếu mở rộng ngoài một tổ chức.

## 5. Quy trình rotate agent token đã lộ

Không ghi lại token cũ trong ticket hoặc chat.

1. Xác định device/credential tương ứng trong môi trường của bạn.
2. Đặt `agent_credentials.revoked_at = now()` hoặc xóa credential nếu luồng hiện tại không hỗ trợ revoke API.
3. Xóa secret runtime cũ trên endpoint.
4. Tạo enrollment code mới và re-enroll nếu agent token vẫn được dùng.
5. Kiểm tra Wazuh Agent binding/client key; rotate/recreate nếu client key cũng từng bị xuất ra ngoài.
6. Theo dõi audit/log để phát hiện request dùng token cũ.
7. Xóa archive cũ khỏi nơi có thể truy cập và ghi nhận sự cố.

## 6. Chính sách log

Không log:

- JWT/access token;
- agent token;
- Wazuh client key/password;
- Authorization header;
- full raw payload chứa secrets;
- password/form body.

Có thể log:

- correlation ID/job ID;
- user/device/agent ID đã mask theo policy;
- source document ID;
- status, latency, record counts;
- error code đã chuẩn hóa.
