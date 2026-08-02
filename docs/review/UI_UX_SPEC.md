# Đặc tả UI/UX CYRP

## 1. Định hướng

CYRP nên là **responsive web application, desktop-first**, có ngôn ngữ hình ảnh của security operations/risk management. Không biến dashboard thành landing page marketing và không dùng hiệu ứng làm giảm khả năng đọc bảng dữ liệu.

Mục tiêu của mỗi màn hình là trả lời nhanh:

1. Thiết bị/CVE nào cần xử lý trước?
2. Vì sao rủi ro cao?
3. Dữ liệu được cập nhật lúc nào và có còn mới không?
4. Người dùng cần thực hiện hành động nào?

## 2. Nguyên tắc nội dung

- Không gọi heuristic hiện tại là “AI” hoặc “Attack Probability”.
- Luôn hiển thị `method`, `model version` và `calculated/predicted at`.
- Phân biệt `No data`, `Not synced`, `Sync failed`, `Stale` và giá trị 0.
- Không hiển thị control giả; chức năng chưa có phải disabled và ghi “Sắp có”.
- Severity không chỉ dựa vào màu; luôn có label/icon/text.
- Mọi recommendation phải có evidence và trạng thái.

## 3. Information architecture

### User Portal

```text
Dashboard
Devices
  Device Detail
    Overview
    Vulnerabilities
    Open Ports
    Processes
    Packages
    Hotfixes
    Risk History
    Recommendations
Vulnerabilities
  Vulnerability Detail
Risk Assessments
Recommendations
Analysis History
Profile & Security
```

### Admin Portal

```text
System Overview
Users
Devices
Wazuh Agent Bindings
Vulnerability Sync
CTI Sources
Analysis Runs
Model Versions
Audit Logs
System Health
Settings
```

## 4. Màn hình trọng tâm

### User Dashboard

- KPI: devices total/online/stale, active CVE, critical/high contextual risk, open recommendations.
- “Needs attention”: top device–CVE pairs, không chỉ top devices.
- Freshness banner nếu dữ liệu Wazuh/CTI quá hạn.
- Trend theo time window rõ ràng.
- Baseline/AI badge thể hiện phương pháp đánh giá.

### Device Detail

Header:

- hostname, OS, owner, Agent ID/status;
- last keepalive, last sync, data freshness;
- action “Đồng bộ ngay” có progress và chống double click.

Tabs:

- Overview;
- Vulnerabilities;
- Network exposure;
- Processes/Packages/Hotfixes;
- Risk history;
- Recommendations.

### Vulnerability Detail

Bắt buộc hiển thị:

- CVE ID và mô tả;
- package/version thực tế trên device;
- CVSS vector/score;
- EPSS snapshot date/score;
- KEV status/date;
- port/process/firewall/patch context;
- contextual score + method/model version;
- factor contribution/explanation;
- recommended action và evidence.

### Admin CTI/Sync

- source health;
- last successful run/checkpoint;
- records read/written/rejected;
- schema/source version;
- data freshness;
- retry action có confirm và audit.

## 5. Design system đề xuất

### Theme

- nền tối trung tính, không dùng đen tuyệt đối trên mọi lớp;
- violet/indigo làm brand accent;
- semantic colors chỉ dùng cho trạng thái/risk;
- surface hierarchy bằng border, elevation nhẹ và spacing thay vì gradient quá nhiều.

### Typography

- body tối thiểu 14–16 px trên desktop;
- table metadata không nhỏ hơn 12 px;
- số liệu dùng tabular numerals;
- line-height 1.4–1.6.

### Spacing

Dùng scale 4/8 px; card padding 20–24 px; table row tối thiểu 44 px; target tương tác tối thiểu 40×40 px.

### Components cần chuẩn hóa

- AppShell, PageHeader, Breadcrumb;
- MetricCard, RiskBadge, FreshnessBadge;
- DataTable + filter/sort/pagination;
- EmptyState, ErrorState, LoadingSkeleton;
- SyncStatus, JobProgress;
- EvidencePanel, ExplanationList;
- ConfirmDialog, Toast/InlineAlert;
- Timeline cho risk/recommendation history.

## 6. Accessibility

- WCAG 2.1 AA contrast.
- Focus-visible rõ trên link/button/input.
- Keyboard navigation đầy đủ.
- Table có caption/header scope.
- Chart có text summary và accessible table fallback.
- Modal trap focus, Escape để đóng và trả focus về trigger.
- `aria-live` cho trạng thái sync/analysis.
- Respect `prefers-reduced-motion`.

## 7. Responsive

- Desktop ≥ 1280: sidebar + table/chart đầy đủ.
- Tablet 768–1279: collapsible sidebar, card grid 2 cột.
- Mobile < 768: chỉ giữ overview/alert/recommendation thiết yếu; table chuyển thành stacked rows.
- Admin data-heavy workflow vẫn ưu tiên desktop; mobile không cần có parity tuyệt đối ở proof of concept.

## 8. Những chỉnh sửa UI đã áp dụng trong review

- Admin login error đúng vị trí và đúng breakpoint.
- Admin/User route active hỗ trợ nested path.
- Admin Portal chặn role sai ở BFF.
- User shell dùng user thật, có redirect/logout.
- Search/notification chưa triển khai được đánh dấu disabled.
- Hướng dẫn enrollment trỏ đúng `apps/bootstrapper-windows/Invoke-CyrpWazuhBootstrapper.ps1`.
- Thêm focus-visible cho navigation/button.

## 9. Thứ tự làm giao diện tiếp theo

1. Device Detail và dữ liệu freshness.
2. Vulnerability list/detail sau khi schema sync có thật.
3. Risk Assessment explanation/history.
4. Recommendation workflow.
5. Admin Agent Bindings/Sync Runs/CTI Sources.
6. Search/notification cuối cùng, sau khi có data model và event model.
