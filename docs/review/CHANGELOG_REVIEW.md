# Changelog của bản reviewed

Ngày: 12/07/2026

## Security

- Loại bỏ `.phase-backups` khỏi bản reviewed.
- Loại bỏ legacy runtime `config.json`, credential, identity và scan telemetry.
- Bổ sung ignore rules ở root.
- Thêm script PowerShell đóng gói review có staging và kiểm tra file nhạy cảm.
- Admin BFF bắt buộc role ADMIN ở login và `/auth/me`.
- Wazuh integration có thể tắt hoàn toàn trong dev/test.
- Wazuh raw response có giới hạn `WAZUH_MAX_RESPONSE_BYTES`.
- Chi tiết lỗi Wazuh không trả ra client trong production.
- TLS verification và least-privilege account trở thành default trong env example.
- BFF backend fetch có timeout.
- Next apps có security headers cơ bản và tắt `X-Powered-By`.

## Reliability

- Swagger chỉ khởi tạo khi `SWAGGER_ENABLED` không false.
- Active sync chỉ chạy khi Wazuh integration và sync flag cùng bật.
- Test setup tắt Wazuh và Swagger.
- Root scripts bổ sung build/lint/typecheck cho cả Admin và User Portal.

## UI/UX

- Sửa login alert Admin bị đặt trong submit button.
- Sửa CSS login alert chỉ hoạt động trên mobile.
- User shell tải phiên thật, redirect 401/403 và có logout.
- User profile hiển thị full name/email thật.
- Nested route active state cho hai portal.
- Search và notification chưa hoạt động được disabled rõ ràng.
- Thêm focus-visible.
- Sửa hướng dẫn enrollment sang Wazuh Windows bootstrapper hiện hành.

## Documentation

- Viết lại root README.
- Cập nhật architecture và roadmap.
- Viết README riêng cho API/Admin/User.
- Thêm `PROJECT_STATUS.md`, `README_REVIEW.md`.
- Thêm audit, architecture notes, data model, UI/UX, security, run guide và test report.

## Không thay đổi có chủ ý

- Chưa thêm CTI/AI Prisma migration.
- Chưa đổi heuristic thành model prediction.
- Chưa tách queue/worker.
- Chưa refactor hai service lớn vì cần regression test đầy đủ trước.
