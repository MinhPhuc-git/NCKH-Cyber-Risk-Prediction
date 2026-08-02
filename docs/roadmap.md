# Lộ trình CYRP

## Phase 0 — Foundation (hoàn thành)

- [x] NestJS API, Prisma/PostgreSQL, health check.
- [x] JWT authentication và RBAC.
- [x] Admin/User Portal.

## Phase 1 — Device/Wazuh integration (hoàn thành ở mức prototype hoạt động)

- [x] One-time enrollment code.
- [x] Device và Wazuh Agent binding.
- [x] Windows/Linux Wazuh Agent bootstrapper.
- [x] Alert analytics, hardware và inventory summary.
- [x] Current security snapshot và heuristic score.
- [x] Admin live Agent inventory và binding management.
- [ ] Multi-agent load test.
- [ ] Queue/worker và distributed lock.

## Phase 2 — CTI và vulnerability data plane (bản hiện tại)

- [x] Schema CVE/CVSS/CWE/reference/affected product/threat signal.
- [x] Registry nguồn CTI và SyncRun observability.
- [x] Import CSV với `cweDescription` và `cveDescription` tách riêng.
- [x] Vulnerability sync từ `wazuh-states-vulnerabilities-*`.
- [x] Append-only endpoint context snapshot.
- [x] Manual device sync, sync all và scheduler tùy chọn.
- [x] User vulnerability/device/context/sync pages.
- [x] Admin endpoint/Agent/vulnerability/sync/CTI/system pages.
- [ ] NVD/CPE incremental adapter.
- [ ] EPSS daily snapshot adapter.
- [ ] CISA KEV temporal adapter.
- [ ] Package/product/CPE mapping và quality metrics.
- [ ] Retention/partitioning cho context history.

## Phase 2.1 — Production-ready data plane

- [ ] Tách worker/queue khỏi API.
- [ ] Distributed lock.
- [ ] Retry/backoff và dead-letter handling.
- [ ] Incremental checkpoints/source manifests hoàn chỉnh.
- [ ] Audit log cho admin mutation.
- [ ] Metrics/alerts cho sync freshness và failure rate.
- [ ] Backup/restore drill.

## Phase 3 — Dataset và mô hình (tách riêng theo kế hoạch của đề tài)

- [ ] Chốt prediction target và time horizon.
- [ ] Chốt ground-truth label, negative sampling và censoring.
- [ ] Feature schema có version.
- [ ] Feature Builder theo `(device_id, cve_id, as_of_time)`.
- [ ] Time-based train/validation/test split.
- [ ] Baseline và so sánh thuật toán.
- [ ] Precision, Recall, F1, PR-AUC, ROC-AUC và calibration.
- [ ] Leakage testing theo CVE/device/time.
- [ ] Model registry, artifact hash, explainability và drift monitoring.

## Phase 4 — Risk/recommendation workflow

- [ ] Append-only `risk_assessments`.
- [ ] Model contract/API integration.
- [ ] Recommendation workflow có evidence.
- [ ] Risk history và explanation UI.
- [ ] Acknowledge/resolve/dismiss workflow.

## Phase 5 — Hardening và đánh giá luận văn

- [ ] Refresh-token/session hardening.
- [ ] Rate limiting và CSRF/origin hardening.
- [ ] Least-privilege/TLS/secret manager.
- [ ] SAST, dependency scan, DAST và load test.
- [ ] Thực nghiệm nhiều endpoint.
- [ ] Báo cáo giới hạn, threat to validity và reproducibility.
