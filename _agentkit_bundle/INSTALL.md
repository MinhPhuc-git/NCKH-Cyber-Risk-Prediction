# CYRP Agent Kit replacement bundle

Copy these files into your project root `D:\LuanVan\test\cyrp-platform-phase2`.

## Files

- `public/downloads/cyrp-agent-kit.zip`: fixed Windows Agent Kit.
- `public/downloads/cyrp-agent-kit-linux.tar.gz`: Linux Agent Kit.
- `apps/user-web/src/app/devices/devices-page-client.tsx`: patched User Portal devices page showing Windows and Linux download/run commands.

## PowerShell replace commands

```powershell
cd D:\LuanVan\test\cyrp-platform-phase2

New-Item -ItemType Directory -Force .\apps\user-web\public\downloads | Out-Null

Copy-Item "<EXTRACTED_BUNDLE>\public\downloads\cyrp-agent-kit.zip" .\apps\user-web\public\downloads\cyrp-agent-kit.zip -Force
Copy-Item "<EXTRACTED_BUNDLE>\public\downloads\cyrp-agent-kit-linux.tar.gz" .\apps\user-web\public\downloads\cyrp-agent-kit-linux.tar.gz -Force
Copy-Item "<EXTRACTED_BUNDLE>\apps\user-web\src\app\devices\devices-page-client.tsx" .\apps\user-web\src\app\devices\devices-page-client.tsx -Force

Remove-Item .\apps\user-web\.next -Recurse -Force -ErrorAction SilentlyContinue
corepack pnpm --dir apps/user-web exec next build
```

## Windows MSI SHA-256

`88b40d63185d308c898dc237b0d5ba0ee1ca2ab41e6b38db28d1d6b3b20a616d`
