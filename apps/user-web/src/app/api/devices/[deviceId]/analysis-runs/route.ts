import { cookies } from 'next/headers';
import {
  type NextRequest,
  NextResponse,
} from 'next/server';

import {
  USER_ACCESS_TOKEN_COOKIE,
  getExpiredUserTokenCookieOptions,
} from '@/lib/auth-cookie';
import {
  backendFetch,
  readJsonBody,
} from '@/lib/backend-api';

interface RouteContext {
  params: Promise<{
    deviceId: string;
  }>;
}

async function proxy(
  method: 'GET' | 'POST',
  request: NextRequest,
  context: RouteContext,
): Promise<NextResponse> {
  const { deviceId } =
    await context.params;

  const cookieStore =
    await cookies();

  const token = cookieStore.get(
    USER_ACCESS_TOKEN_COOKIE,
  )?.value;

  if (!token) {
    return NextResponse.json(
      {
        code:
          'AUTH_TOKEN_MISSING',
        message:
          'Chưa đăng nhập hoặc phiên đã hết hạn',
      },
      {
        status: 401,
      },
    );
  }

  const encodedDeviceId =
    encodeURIComponent(deviceId);

  const path =
    method === 'POST'
      ? `/devices/${encodedDeviceId}/analysis-runs`
      : `/devices/${encodedDeviceId}/analysis-runs/latest`;

  const body =
    method === 'POST'
      ? await request.text()
      : undefined;

  try {
    const upstream =
      await backendFetch(path, {
        method,
        headers: {
          Authorization:
            `Bearer ${token}`,
          ...(body
            ? {
                'Content-Type':
                  'application/json',
              }
            : {}),
        },
        body:
          body || undefined,
      });

    const payload =
      await readJsonBody(
        upstream,
      );

    const response =
      NextResponse.json(
        payload,
        {
          status:
            upstream.status,
        },
      );

    if (
      upstream.status === 401 ||
      upstream.status === 403
    ) {
      response.cookies.set(
        USER_ACCESS_TOKEN_COOKIE,
        '',
        getExpiredUserTokenCookieOptions(),
      );
    }

    return response;
  } catch {
    return NextResponse.json(
      {
        code:
          'BACKEND_UNAVAILABLE',
        message:
          'Không thể kết nối máy chủ CYRP',
      },
      {
        status: 503,
      },
    );
  }
}

export async function GET(
  request: NextRequest,
  context: RouteContext,
) {
  return proxy(
    'GET',
    request,
    context,
  );
}

export async function POST(
  request: NextRequest,
  context: RouteContext,
) {
  return proxy(
    'POST',
    request,
    context,
  );
}
