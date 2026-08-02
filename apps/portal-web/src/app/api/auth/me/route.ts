import { cookies } from 'next/headers';
import { NextResponse } from 'next/server';

import type {
  AuthenticatedUser,
} from '@/lib/api-types';
import {
  ACCESS_TOKEN_COOKIE,
  getExpiredCookieOptions,
} from '@/lib/auth-cookie';
import {
  backendFetch,
  readJsonBody,
} from '@/lib/backend-api';

function isAuthenticatedUser(
  value: unknown,
): value is AuthenticatedUser {
  if (
    typeof value !== 'object' ||
    value === null
  ) {
    return false;
  }

  const candidate =
    value as Partial<AuthenticatedUser>;

  return (
    typeof candidate.id === 'string' &&
    typeof candidate.email === 'string' &&
    typeof candidate.fullName === 'string' &&
    (candidate.role === 'ADMIN' || candidate.role === 'USER')
  );
}

export async function GET(): Promise<NextResponse> {
  const cookieStore = await cookies();

  const accessToken = cookieStore.get(
    ACCESS_TOKEN_COOKIE,
  )?.value;

  if (!accessToken) {
    return NextResponse.json(
      {
        code: 'AUTH_TOKEN_MISSING',
        message: 'Chưa đăng nhập hoặc phiên đã hết hạn',
      },
      {
        status: 401,
      },
    );
  }

  try {
    const upstreamResponse =
      await backendFetch('/auth/me', {
        method: 'GET',
        headers: {
          Authorization: `Bearer ${accessToken}`,
        },
      });

    const payload = await readJsonBody(
      upstreamResponse,
    );

    const invalidRole =
      upstreamResponse.ok &&
      (!isAuthenticatedUser(payload) || payload.role !== 'ADMIN');

    const response = NextResponse.json(
      invalidRole
        ? {
            code: 'ADMIN_PORTAL_ROLE_REQUIRED',
            message:
              'Tài khoản không có quyền truy cập Admin Portal',
          }
        : payload,
      {
        status: invalidRole
          ? 403
          : upstreamResponse.status,
      },
    );

    if (
      upstreamResponse.status === 401 ||
      upstreamResponse.status === 403 ||
      invalidRole
    ) {
      response.cookies.set(
        ACCESS_TOKEN_COOKIE,
        '',
        getExpiredCookieOptions(),
      );
    }

    return response;
  } catch {
    return NextResponse.json(
      {
        code: 'BACKEND_UNAVAILABLE',
        message: 'Không thể kết nối máy chủ CYRP',
      },
      {
        status: 503,
      },
    );
  }
}
