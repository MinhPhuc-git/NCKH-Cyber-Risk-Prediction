# CYRP Windows Agent — Phase 1A

Đây là bản refactor từ `StatusMachine.zip`. Bản này chỉ thu thập dữ liệu khi có lệnh `scan-once` hoặc khi runtime nhận một scan job từ server. Nó không tự quét theo lịch và không tự khởi động cùng Windows.

## Cấu trúc

```text
apps/agent-windows/
├── src/
│   ├── collectors/
│   │   ├── system.py
│   │   ├── network.py
│   │   └── privilege.py
│   ├── api_client.py
│   ├── collector.py
│   ├── config.py
│   ├── identity.py
│   ├── logging_config.py
│   └── runtime.py
├── data/
├── logs/
├── tests/
├── config.example.json
├── requirements.txt
└── run-agent.ps1
```

## Cài đặt

Chạy PowerShell tại thư mục `apps/agent-windows`:

```powershell
python -m venv .venv
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
Copy-Item .\config.example.json .\config.json
```

## Chạy quét một lần

Nên mở PowerShell bằng quyền Administrator để có dữ liệu đầy đủ hơn:

```powershell
.\run-agent.ps1 -Mode scan-once
```

Bỏ qua kiểm kê System32 để kiểm tra nhanh:

```powershell
.\run-agent.ps1 -Mode scan-once -SkipSystem32 -PrintJson
```

Kết quả được lưu vào:

```text
data/latest-scan.json
data/scan-<scan-id>.json
logs/agent.log
```

## Kiểm tra cấu hình

```powershell
.\run-agent.ps1 -Mode show-config
```

## Chạy runtime chờ lệnh từ server

Lệnh sau đã được chuẩn bị nhưng chỉ hoạt động sau khi backend Device/Agent và file `data/credentials.json` được triển khai:

```powershell
.\run-agent.ps1 -Mode poll
```

Runtime ở trạng thái chờ. Nó chỉ chạy collector khi server trả về task có `type = SYSTEM_SCAN`.

## Chạy kiểm thử

```powershell
python -m unittest discover -s tests -v
python -m compileall src tests
```

## Lưu ý bảo mật

- Không commit `config.json`, dữ liệu quét, log hoặc credential.
- Không chạy file `.pkl`/`.joblib` không rõ nguồn gốc trong agent.
- `agentToken` sau này chỉ được lưu cục bộ trong `data/credentials.json` và không được ghi vào log.
