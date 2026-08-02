# CYRP Review Context

## Mục tiêu

Đánh giá source code hiện tại, làm sạch dữ liệu nhạy cảm, sửa các lỗi an toàn/UX có thể xử lý ngay và lập kế hoạch đưa prototype đến kiến trúc luận văn.

## Công nghệ phát hiện từ source

- Node.js 22/24, pnpm workspace.
- NestJS 10, Prisma 5, PostgreSQL 16.
- Next.js 16.2.9, React 19.2.4 cho hai portal.
- Wazuh Manager API và Wazuh Indexer qua HTTP(S).
- PowerShell/Bash bootstrapper cho Wazuh Agent.
- Legacy Python custom agent chỉ để tham khảo.

## Cổng mặc định

- Admin Portal: 3000
- API: 3001
- User Portal: 3002
- PostgreSQL: 5432

## Kết quả review chính

- Archive gốc chứa một agent token dạng runtime và telemetry thiết bị; bản reviewed đã loại bỏ các file đó. Token cũ cần được thu hồi/rotate nếu còn hiệu lực.
- Admin BFF trước review chưa chặn USER nhận cookie của Admin Portal; đã bổ sung role gate.
- User shell trước review hiển thị thông tin phiên giả và không có logout; đã nối `/api/auth/me` và `/api/auth/logout`.
- Wazuh trước review là dependency bắt buộc khi API khởi tạo; đã thêm cờ tắt tích hợp cho dev/test.
- Đã giới hạn kích thước response Wazuh và ẩn chi tiết lỗi upstream trong production.
- Schema hiện tại chưa phải schema nghiên cứu cuối cùng; chưa tự ý tạo migration CTI/AI để tránh đóng băng thiết kế khi label chưa chốt.

## Tài liệu đầu ra

Xem thư mục `docs/review/`.
