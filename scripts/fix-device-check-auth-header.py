from pathlib import Path
import re
import shutil
from datetime import datetime

path = Path(r"D:\LuanVan\test\cyrp-platform-phase2\apps\user-web\src\components\device-analysis-button.tsx")
backup = path.with_suffix(".tsx.bak-auth-header-fix-" + datetime.now().strftime("%Y%m%d-%H%M%S"))
shutil.copy2(path, backup)

text = path.read_text(encoding="utf-8")

helper = r'''
function browserAuthorizationHeaders(): HeadersInit {
  const headers: Record<string, string> = {
    Accept: 'application/json',
  };

  if (typeof window === 'undefined') {
    return headers;
  }

  const tokenKeys = [
    'accessToken',
    'access_token',
    'cyrp_access_token',
    'cyrp_token',
    'authToken',
    'token',
    'auth-storage',
    'cyrp-auth',
  ];

  function normalizeToken(value: string | null | undefined): string | null {
    if (!value) return null;

    const trimmed = value.trim();
    if (!trimmed) return null;
    if (trimmed.startsWith('Bearer ')) return trimmed;
    if (trimmed.split('.').length === 3) return `Bearer ${trimmed}`;

    try {
      const parsed = JSON.parse(trimmed) as Record<string, unknown>;
      const nested =
        parsed.accessToken ??
        parsed.access_token ??
        parsed.token ??
        parsed.jwt ??
        parsed.state;

      if (typeof nested === 'string') {
        return normalizeToken(nested);
      }

      if (nested && typeof nested === 'object') {
        const nestedRecord = nested as Record<string, unknown>;
        const nestedToken =
          nestedRecord.accessToken ??
          nestedRecord.access_token ??
          nestedRecord.token ??
          nestedRecord.jwt;

        if (typeof nestedToken === 'string') {
          return normalizeToken(nestedToken);
        }
      }
    } catch {
      // Ignore non-JSON values.
    }

    return null;
  }

  const storages = [window.localStorage, window.sessionStorage];

  for (const storage of storages) {
    for (const key of tokenKeys) {
      const token = normalizeToken(storage.getItem(key));
      if (token) {
        headers.Authorization = token;
        return headers;
      }
    }

    for (let index = 0; index < storage.length; index += 1) {
      const key = storage.key(index);
      if (!key) continue;

      const token = normalizeToken(storage.getItem(key));
      if (token) {
        headers.Authorization = token;
        return headers;
      }
    }
  }

  return headers;
}

'''

if "function browserAuthorizationHeaders" not in text:
    text = text.replace("interface DeviceAnalysisButtonProps {", helper + "\ninterface DeviceAnalysisButtonProps {")

# Patch only the ai-pipeline-check fetch block.
pattern = r"""const response = await fetch\(
        `/api/devices/\$\{deviceId\}/ai-pipeline-check`,
        \{
          method: 'POST',
          cache: 'no-store',
        \},
      \);"""

replacement = """const response = await fetch(
        `/api/devices/${deviceId}/ai-pipeline-check`,
        {
          method: 'POST',
          cache: 'no-store',
          credentials: 'same-origin',
          headers: browserAuthorizationHeaders(),
        },
      );"""

text = re.sub(pattern, replacement, text)

path.write_text(text, encoding="utf-8")
print(f"Patched: {path}")
print(f"Backup:  {backup}")
