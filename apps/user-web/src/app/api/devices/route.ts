import { cookies } from 'next/headers';
import { NextResponse } from 'next/server';

import {
  USER_ACCESS_TOKEN_COOKIE,
  getExpiredUserTokenCookieOptions,
} from '@/lib/auth-cookie';
import {
  backendFetch,
  readJsonBody,
} from '@/lib/backend-api';

async function proxyDeviceRequest(
  method: 'GET' | 'POST',
): Promise<NextResponse> {
  const cookieStore = await cookies();

  const accessToken = cookieStore.get(
    USER_ACCESS_TOKEN_COOKIE,
  )?.value;

  if (!accessToken) {
    return NextResponse.json(
      {
        code: 'AUTH_TOKEN_MISSING',
        message:
          'Chưa đăng nhập hoặc phiên đã hết hạn',
      },
      {
        status: 401,
      },
    );
  }

  const backendPath =
    method === 'GET'
      ? '/devices'
      : '/devices/enrollment-codes';

  try {
    const upstreamResponse =
      await backendFetch(backendPath, {
        method,
        headers: {
          Authorization:
            `Bearer ${accessToken}`,
        },
      });

    const payload = await readJsonBody(
      upstreamResponse,
    );

    const response = NextResponse.json(
      payload,
      {
        status: upstreamResponse.status,
      },
    );

    if (
      upstreamResponse.status === 401 ||
      upstreamResponse.status === 403
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
        code: 'BACKEND_UNAVAILABLE',
        message:
          'Không thể kết nối máy chủ CYRP',
      },
      {
        status: 503,
      },
    );
  }
}

export async function GET():
  Promise<NextResponse> {
  return proxyDeviceRequest('GET');
}

export async function POST():
  Promise<NextResponse> {
  return proxyDeviceRequest('POST');
}
