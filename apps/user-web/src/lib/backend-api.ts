const DEFAULT_BACKEND_TIMEOUT_MS = 10_000;

function getBackendBaseUrl(): string {
  const value = process.env.CYRP_API_BASE_URL?.trim();

  if (!value) {
    throw new Error(
      'Missing CYRP_API_BASE_URL environment variable',
    );
  }

  return value.replace(/\/+$/, '');
}

function getBackendTimeoutMs(): number {
  const parsed = Number(
    process.env.CYRP_API_TIMEOUT_MS ??
      DEFAULT_BACKEND_TIMEOUT_MS,
  );

  if (!Number.isInteger(parsed) || parsed < 1_000) {
    return DEFAULT_BACKEND_TIMEOUT_MS;
  }

  return Math.min(parsed, 120_000);
}

export function backendFetch(
  path: string,
  init?: RequestInit,
): Promise<Response> {
  const normalizedPath = path.startsWith('/')
    ? path
    : `/${path}`;

  return fetch(
    `${getBackendBaseUrl()}${normalizedPath}`,
    {
      ...init,
      cache: 'no-store',
      signal:
        init?.signal ??
        AbortSignal.timeout(getBackendTimeoutMs()),
    },
  );
}

export async function readJsonBody(
  response: Response,
): Promise<unknown> {
  const text = await response.text();

  if (!text) {
    return {};
  }

  try {
    return JSON.parse(text) as unknown;
  } catch {
    return {
      message: text,
    };
  }
}
