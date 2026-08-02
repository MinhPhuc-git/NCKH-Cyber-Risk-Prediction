# CYRP Phase 2 — Changelog

Cập nhật: 13/07/2026


## Phase 2.1 — Agent runtime and sync reliability

- Thêm migration `20260713223000_p2_1_agent_runtime_sync`.
- Thêm database-backed lease `device_sync_leases` để chặn đồng bộ trùng giữa nhiều API instance.
- Thêm heartbeat, TTL và cleanup lease hết hạn.
- Tự động đánh dấu `SyncRun` bị treo quá ngưỡng thành `FAILED` khi API khởi động.
- Thêm Agent status reconciliation thủ công và scheduler tùy chọn.
- Lưu lần kiểm tra Agent gần nhất, lỗi gần nhất và số lần lỗi liên tiếp trên binding.
- Thêm retry có giới hạn cho Wazuh GET/search/authentication khi gặp timeout, HTTP 429 hoặc HTTP 5xx.
- Không retry thao tác tạo/xóa Agent để tránh lặp side effect.
- Chặn đổi hoặc gỡ binding khi device đang có data sync lease.
- Chặn thay Agent ngầm trên một Device; quản trị viên phải gỡ binding cũ trước.
- Nâng cấp trang Admin Agents và System Health để hiển thị runtime check, lease và retry policy.
- Thêm unit test cho Agent runtime và database-backed sync lease.
- Cập nhật E2E database mocks cho bootstrap cleanup/recovery của Phase 2.1.
- Thêm script `verify-phase-2-1-agent-runtime.ps1`.

## Added — Data foundation

- Thêm migration `20260712190000_phase2_data_foundation`.
- Thêm registry nguồn dữ liệu và provenance qua `cti_sources`, `sync_runs`.
- Thêm CTI schema: CVE, CVSS, CWE, references, affected products và threat signals.
- Thêm `detected_vulnerabilities` theo device/package/CVE/source document.
- Thêm `endpoint_context_snapshots` dạng append-only theo `as_of_time`.
- Thêm CTI CSV importer idempotent và dataset mẫu.
- Thêm seed registry cho 6 nguồn dữ liệu.

## Added — Wazuh/Agent operations

- Query `wazuh-states-vulnerabilities-*` theo `agent.id`.
- Query inventory state cho hardware, hotfixes, packages, ports, processes, services và system.
- Thêm normalizer chịu được một số biến thể field/schema.
- Thêm manual sync cho USER/ADMIN, sync all và scheduler tùy chọn.
- Thêm lock theo device; Phase 2.1 nâng cấp lock này thành database-backed lease.
- Chỉ resolve vulnerability cũ khi collection đầy đủ, không truncate và không có shard failure.
- Thêm trang Admin live Agents, binding và unbinding không xóa Agent trên Wazuh Manager.
- Chặn binding Agent `000`.

## Added — API

- User data overview, device overview/context/data-sync.
- User vulnerability list/detail và sync history.
- Admin dashboard, endpoints, live agents/bindings, vulnerabilities, sync runs, CTI sources và system health.
- BFF proxy cho toàn bộ route mới, giữ token trong HttpOnly cookie.

## Added — User Portal

- Dashboard Phase 2.
- Device Detail với inventory/context/freshness/sync.
- Vulnerability list/detail.
- Sync History.
- Reports/Data Quality.
- Settings/Agent onboarding guidance.

## Added — Admin Portal

- System Overview.
- Endpoints list/detail.
- Wazuh Agents và binding management.
- Vulnerabilities list/detail.
- Data Sync operations/history.
- CTI Sources.
- System Health.

## Changed

- Dashboard và thuật ngữ tránh gọi heuristic là AI hoặc attack probability.
- Tăng chiều dài `devices.architecture` từ 50 lên 80 ký tự.
- Wazuh response limit mặc định tăng lên 10 MiB để phù hợp state pagination.
- API context response chỉ trả preview tối đa 50 item/category trong giao diện; database vẫn lưu snapshot đã thu thập.
- BFF proxy giữ đúng custom headers bằng `Headers` trước khi gắn Bearer token.
- Script đóng gói loại thêm backup, dump và `*.tsbuildinfo`.

## Security

- Ownership được áp dụng cho USER device/vulnerability/sync queries.
- Wazuh credentials không được trả về browser.
- Agent binding mutation chỉ dành cho ADMIN.
- Archive script loại `.env`, private key, runtime telemetry, backup và build output.

## Intentionally deferred

- NVD/EPSS/CISA KEV automated adapters.
- Package/CPE matching hoàn chỉnh.
- Feature Builder và feature versioning.
- Model training/inference/explainability.
- Model-based risk assessments và AI Recommendation Engine.
- Queue/worker riêng, retention/partitioning và production observability.
