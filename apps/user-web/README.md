# CYRP User Portal — Phase 2

Next.js User Portal chạy mặc định tại `http://localhost:3002`.

## Chạy

```powershell
Copy-Item apps/user-web/.env.example apps/user-web/.env.local
corepack pnpm@11.9.0 run dev:user
```

Portal dùng BFF routes và cookie HttpOnly. Chỉ tài khoản `USER` được cấp phiên.

## Routes

```text
/dashboard
/devices
/devices/:deviceId
/vulnerabilities
/vulnerabilities/:id
/sync-history
/reports
/settings
```

## Chức năng

- Đăng ký/đăng nhập/logout.
- Tạo enrollment code và hướng dẫn bootstrapper.
- Device overview/context/inventory.
- Manual Wazuh data sync cho device thuộc user.
- Vulnerability list/detail theo device/package/CVE.
- CTI/CVSS/CWE/threat-signal display khi đã import.
- Sync history và data-quality reports.

Portal không hiển thị kết quả Phase 2 như AI hoặc attack probability.
