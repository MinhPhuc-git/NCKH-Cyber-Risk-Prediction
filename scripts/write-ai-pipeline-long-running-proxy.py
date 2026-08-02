from pathlib import Path
import shutil
from datetime import datetime

path = Path(r"D:\LuanVan\test\cyrp-platform-phase2\apps\user-web\src\app\api\devices\[deviceId]\ai-pipeline-check\route.ts")

if path.exists():
    backup = path.with_suffix(".ts.bak-long-running-ai-proxy-" + datetime.now().strftime("%Y%m%d-%H%M%S"))
    shutil.copy2(path, backup)
    print(f"Backup: {backup}")

content = r'''import { cookies } from 'next/headers';
import { NextRequest, NextResponse } from 'next/server';

import {
  USER_ACCESS_TOKEN_COOKIE,
  getExpiredUserTokenCookieOptions,
} from '@/lib/auth-cookie';

export const dynamic = 'force-dynamic';
export const maxDuration = 900;

type RouteContext = {
  params: Promise<{
    deviceId: string;
  }>;
};

function apiBaseUrl(): string {
  const raw =
    process.env.CYRP_API_BASE_URL ??
    process.env.API_BASE_URL ??
    process.env.NEXT_PUBLIC_API_BASE_URL ??
    'http://localhost:3001/api/v1';

  const normalized = raw.replace(/\/+$/, '');

  return normalized.endsWith('/api/v1')
    ? normalized
    : `${normalized}/api/v1`;
}

function timeoutMs(): number {
  const raw = Number(
    process.env.AI_PIPELINE_TIMEOUT_MS ??
      process.env.AI_PIPELINE_PROXY_TIMEOUT_MS ??
      900000,
  );

  return Number.isFinite(raw) && raw >= 60000
    ? raw
    : 900000;
}

function noStore(response: NextResponse): NextResponse {
  response.headers.set('Cache-Control', 'no-store, max-age=0');
  response.headers.set('Pragma', 'no-cache');

  return response;
}

function jsonError(
  status: number,
  code: string,
  message: string,
  extra: Record<string, unknown> = {},
): NextResponse {
  return noStore(
    NextResponse.json(
      {
        code,
        message,
        ...extra,
      },
      { status },
    ),
  );
}

export async function POST(
  _request: NextRequest,
  context: RouteContext,
): Promise<NextResponse> {
  const { deviceId } = await context.params;

  const cookieStore = await cookies();
  const accessToken = cookieStore.get(USER_ACCESS_TOKEN_COOKIE)?.value;

  if (!accessToken) {
    return jsonError(
      401,
      'AUTH_TOKEN_MISSING',
      'Chưa đăng nhập hoặc phiên đã hết hạn.',
    );
  }

  const targetUrl = `${apiBaseUrl()}/devices/${encodeURIComponent(
    deviceId,
  )}/ai-pipeline-check`;

  const controller = new AbortController();
  const timer = setTimeout(() => {
    controller.abort();
  }, timeoutMs());

  try {
    const upstream = await fetch(targetUrl, {
      method: 'POST',
      headers: {
        Accept: 'application/json',
        Authorization: `Bearer ${accessToken}`,
      },
      cache: 'no-store',
      signal: controller.signal,
    });

    const contentType =
      upstream.headers.get('content-type') ?? 'application/json';

    const body = await upstream.text();

    const response = new NextResponse(body || null, {
      status: upstream.status,
      headers: {
        'Content-Type': contentType,
      },
    });

    if (upstream.status === 401 || upstream.status === 403) {
      response.cookies.set(
        USER_ACCESS_TOKEN_COOKIE,
        '',
        getExpiredUserTokenCookieOptions(),
      );
    }

    return noStore(response);
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    const isAbort =
      error instanceof Error &&
      (error.name === 'AbortError' || detail.toLowerCase().includes('abort'));

    return jsonError(
      503,
      isAbort ? 'AI_PIPELINE_PROXY_TIMEOUT' : 'AI_PIPELINE_PROXY_FAILED',
      isAbort
        ? 'AI pipeline chạy quá thời gian chờ của User Web proxy.'
        : 'User Web không gọi được CYRP API ai-pipeline-check.',
      {
        targetUrl,
        detail,
      },
    );
  } finally {
    clearTimeout(timer);
  }
}
'''

path.parent.mkdir(parents=True, exist_ok=True)
path.write_text(content, encoding="utf-8")

print(f"Written: {path}")
