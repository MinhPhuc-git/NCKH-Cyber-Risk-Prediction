# CYRP Admin Portal — Phase 2

Next.js Admin Portal chạy mặc định tại `http://localhost:3000`.

## Chạy

```powershell
Copy-Item apps/portal-web/.env.example apps/portal-web/.env.local
corepack pnpm@11.9.0 run dev:admin
```

Portal dùng BFF routes và cookie HttpOnly. Chỉ tài khoản `ADMIN` được cấp phiên.

## Routes

```text
/dashboard
/users
/endpoints
/endpoints/:deviceId
/agents
/vulnerabilities
/vulnerabilities/:id
/sync
/cti
/system
```

## Chức năng

- Operational dashboard.
- Users và endpoint inventory.
- Live Wazuh Agents.
- Device–Agent bind/unbind.
- Vulnerability list/detail.
- Manual sync một/toàn bộ endpoint.
- SyncRun history.
- CTI registry/statistics.
- DB/Wazuh API/Indexer/scheduler health.

Search/notification toàn cục chưa có event/search model, nhưng mọi mục navigation Phase 2 đều có route hoạt động.
