# CYRP CVE Lifecycle Delta Patch

Patch này triển khai bước delta scan theo `CVE_LIFECYCLE_DESIGN.md`:

- CVE mới: ghi vào `LIST_CVE_ID.csv` để chạy pipeline.
- CVE đã biết và còn mới: bỏ qua, không ghi vào `LIST_CVE_ID.csv`.
- CVE đã biết nhưng stale: ghi lại vào `LIST_CVE_ID.csv` để re-predict.
- CVE có trong DB nhưng không còn trong Wazuh scan: ghi ra `resolved_pairs.csv` để backend/DB cập nhật vòng đời.
- Ghi `scan_summary.json` để audit.

Patch không thay đổi đầu ra cuối của `run_pipeline.py`: `final_prediction_results.json` và `Data User/{CVE}_result.json`.

## Install

```powershell
cd D:\LuanVan\test\cyrp-platform-phase2

Expand-Archive "$env:USERPROFILE\Downloads\cyrp-cve-lifecycle-delta-v1.zip" -DestinationPath .\_cve_lifecycle_delta_v1 -Force
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force

.\_cve_lifecycle_delta_v1\scripts\install-cve-lifecycle-delta-v1.ps1 `
  -ProjectRoot "D:\LuanVan\test\cyrp-platform-phase2"
```

## Manual delta test

```powershell
.\scripts\export-existing-cve-pairs.ps1 -ProjectRoot "D:\LuanVan\test\cyrp-platform-phase2" -AgentId "007"

cd D:\LuanVan\test\cyrp-platform-phase2\apps\ai-model\model-risk-prediction

.\..\.venv\Scripts\python.exe ".\CTI Collector\Extract_Data_Wazuh.py" `
  --indexer-url "https://127.0.0.1:19201" `
  --username admin `
  --agent-id 007 `
  --existing-pairs "D:\LuanVan\test\cyrp-platform-phase2\existing_pairs_007.csv" `
  --new-only `
  --resolved-out "D:\LuanVan\test\cyrp-platform-phase2\resolved_pairs_007.csv" `
  --fresh-out "D:\LuanVan\test\cyrp-platform-phase2\fresh_pairs_007.csv" `
  --stale-out "D:\LuanVan\test\cyrp-platform-phase2\stale_pairs_007.csv" `
  --scan-summary-out "D:\LuanVan\test\cyrp-platform-phase2\scan_summary_007.json" `
  --stale-days 7 `
  --force-rescan-days 30 `
  --insecure
```

Nếu `LIST_CVE_ID.csv` không có dòng nào ngoài header thì pipeline có thể skip model inference.

## Apply resolved candidates

Mặc định script dưới đây dùng `auto-resolve`, tức cập nhật `status=RESOLVED` cho các pair mất khỏi Wazuh scan. Chỉ dùng chế độ này khi bạn đã chắc agent đang active.

```powershell
.\scripts\apply-resolved-cve-pairs.ps1 `
  -ProjectRoot "D:\LuanVan\test\cyrp-platform-phase2" `
  -ResolvedPairsPath "D:\LuanVan\test\cyrp-platform-phase2\resolved_pairs_007.csv" `
  -Policy auto-resolve
```

Chế độ an toàn hơn:

```powershell
.\scripts\apply-resolved-cve-pairs.ps1 `
  -ProjectRoot "D:\LuanVan\test\cyrp-platform-phase2" `
  -ResolvedPairsPath "D:\LuanVan\test\cyrp-platform-phase2\resolved_pairs_007.csv" `
  -Policy verification
```

`verification` sẽ giữ record ở `UNDER_EVALUATION` và set `source_status='SCAN_MISSING'`.
