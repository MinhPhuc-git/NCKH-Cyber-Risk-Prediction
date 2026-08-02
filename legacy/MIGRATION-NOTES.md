# Legacy custom Agent

`legacy/custom-agent-windows` là Python Agent cũ.

- Không còn là kiến trúc chính.
- Không chạy `poll`.
- Không phát hành cho người dùng mới.
- Không dùng custom agent token trong kiến trúc Wazuh mới.
- Giữ lại để đối chiếu collector, payload và lịch sử Git.

Các bảng cũ như `agent_credentials`, `scans`, `telemetry_records` chưa bị xóa ở W1. Chúng sẽ được xử lý sau khi Wazuh binding và Analysis Run hoạt động ổn định.
