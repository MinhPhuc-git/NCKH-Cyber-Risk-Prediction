import { cookies } from 'next/headers';
import { NextRequest, NextResponse } from 'next/server';

import {
  getExpiredUserTokenCookieOptions,
  USER_ACCESS_TOKEN_COOKIE,
} from '@/lib/auth-cookie';

export const dynamic = 'force-dynamic';
export const revalidate = 0;

type RouteContext = {
  params: Promise<{
    deviceId: string;
    runId: string;
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

export async function GET(
  _request: NextRequest,
  context: RouteContext,
): Promise<NextResponse> {
  const { deviceId, runId } = await context.params;
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
  )}/ai-pipeline-check/${encodeURIComponent(runId)}`;

  try {
    const upstream = await fetch(targetUrl, {
      method: 'GET',
      headers: {
        Accept: 'application/json',
        Authorization: `Bearer ${accessToken}`,
      },
      cache: 'no-store',
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
  } catch (error: unknown) {
    return jsonError(
      503,
      'MACHINE_CHECK_STATUS_FAILED',
      'User Web không thể đọc trạng thái kiểm tra máy.',
      {
        targetUrl,
        detail: error instanceof Error ? error.message : String(error),
      },
    );
  }
}
