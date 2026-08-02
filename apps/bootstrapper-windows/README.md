# CYRP Phase 2B.2 - Windows Wazuh Bootstrapper

Phase 2B.2 installs the official Wazuh Windows Agent without automatic enrollment, imports the one-time client key created by Phase 2B.1, configures the Wazuh manager address, starts `WazuhSvc`, and verifies a successful manager connection.

## Scripts

- `Install-CyrpWazuhFromEnrollmentFile.ps1`: configure an already-created Wazuh Agent such as Agent `003` from the DPAPI-protected `.clixml` file.
- `Invoke-CyrpWazuhBootstrapper.ps1`: full future flow that consumes a fresh CYRP enrollment code, creates the Device/Wazuh Agent, then installs and configures the endpoint.
- `Test-CyrpWazuhAgent.ps1`: local verification without displaying the client key or agent token.

## Important security behavior

- The Wazuh API password and Indexer password never reach the endpoint.
- The one-time Wazuh client key is not written to logs by the bootstrapper.
- The CYRP agent token is stored with Windows DPAPI LocalMachine protection at `%ProgramData%\CYRP\Secrets\agent-token.dpapi`.
- The non-secret bootstrapper state is stored at `%ProgramData%\CYRP\State\bootstrapper-state.json`.
- Existing `ossec.conf` and `client.keys` are backed up before modification.
- Replacing an existing Wazuh identity requires the explicit `-ForceReenroll` switch.

## Existing Agent 003 flow

Run PowerShell as Administrator on the same Windows account and machine that created the Phase 2B.1 `.clixml` file:

```powershell
$secretFile = Get-ChildItem `
  "$env:LOCALAPPDATA\CYRP\Phase2B1" `
  -Filter "wazuh-enrollment-*.clixml" |
Sort-Object LastWriteTime -Descending |
Select-Object -First 1

$secretFile.FullName
```

If Wazuh Agent is not installed, provide an official MSI package compatible with the manager version:

```powershell
powershell `
  -NoProfile `
  -ExecutionPolicy Bypass `
  -File .\apps\bootstrapper-windows\Install-CyrpWazuhFromEnrollmentFile.ps1 `
  -EnrollmentFile $secretFile.FullName `
  -MsiPath "D:\Installers\wazuh-agent-4.14.5-1.msi" `
  -ConnectionTimeoutSeconds 180
```

If Wazuh Agent is already installed but not enrolled, omit `-MsiPath`.

Do not use `-ForceReenroll` unless intentionally replacing an existing Wazuh identity on that endpoint.

Verify Agent `003`:

```powershell
powershell `
  -NoProfile `
  -ExecutionPolicy Bypass `
  -File .\apps\bootstrapper-windows\Test-CyrpWazuhAgent.ps1 `
  -ExpectedAgentId "003" `
  -ExpectedManagerAddress "192.168.100.247" `
  -ExpectedManagerPort 1514
```

## Full enrollment on a new Windows endpoint

The DPAPI `.clixml` created on one Windows account/machine cannot be decrypted on another endpoint. On a different endpoint, create a new one-time CYRP enrollment code and run:

```powershell
powershell `
  -NoProfile `
  -ExecutionPolicy Bypass `
  -File .\apps\bootstrapper-windows\Invoke-CyrpWazuhBootstrapper.ps1 `
  -BackendBaseUrl "http://192.168.100.10:3001" `
  -MsiPath "D:\Installers\wazuh-agent-4.14.5-1.msi"
```

The script prompts for the one-time CYRP enrollment code. This creates a new Wazuh Agent ID. Remove any unused `never_connected` test Agent only after the new endpoint has connected successfully.

## Recovery

Backups are stored under:

```text
%ProgramData%\CYRP\Backups\YYYYMMDD-HHMMSS
```

MSI logs are stored under:

```text
%ProgramData%\CYRP\Logs
```

Wazuh Agent logs are normally located at:

```text
C:\Program Files (x86)\ossec-agent\ossec.log
```
