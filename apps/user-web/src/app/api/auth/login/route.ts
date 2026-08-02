import { NextResponse } from 'next/server';

import type {
  BackendLoginResponse,
} from '@/lib/api-types';
import {
  USER_ACCESS_TOKEN_COOKIE,
  getUserTokenCookieOptions,
} from '@/lib/auth-cookie';
import {
  backendFetch,
  readJsonBody,
} from '@/lib/backend-api';

interface LoginRequestBody {
  email?: unknown;
  password?: unknown;
  remember?: unknown;
}

function isLoginResponse(
  value: unknown,
): value is BackendLoginResponse {
  if (
    typeof value !== 'object' ||
    value === null
  ) {
    return false;
  }

  const candidate =
    value as Partial<BackendLoginResponse>;

  return (
    typeof candidate.accessToken === 'string' &&
    candidate.accessToken.length > 0 &&
    typeof candidate.user === 'object' &&
    candidate.user !== null
  );
}

export async function POST(
  request: Request,
): Promise<NextResponse> {
  let body: LoginRequestBody;

  try {
    body =
      (await request.json()) as
        LoginRequestBody;
  } catch {
    return NextResponse.json(
      {
        code: 'INVALID_REQUEST_BODY',
        message:
          'Dữ liệu đăng nhập không hợp lệ',
      },
      {
        status: 400,
      },
    );
  }

  if (
    typeof body.email !== 'string' ||
    typeof body.password !== 'string'
  ) {
    return NextResponse.json(
      {
        code: 'INVALID_CREDENTIALS_FORMAT',
        message:
          'Email và mật khẩu là bắt buộc',
      },
      {
        status: 400,
      },
    );
  }

  try {
    const upstreamResponse =
      await backendFetch('/auth/login', {
        method: 'POST',
        headers: {
          'Content-Type':
            'application/json',
        },
        body: JSON.stringify({
          email: body.email,
          password: body.password,
        }),
      });

    const payload = await readJsonBody(
      upstreamResponse,
    );

    if (!upstreamResponse.ok) {
      return NextResponse.json(payload, {
        status: upstreamResponse.status,
      });
    }

    if (!isLoginResponse(payload)) {
      return NextResponse.json(
        {
          code: 'INVALID_BACKEND_RESPONSE',
          message:
            'Phản hồi đăng nhập từ backend không hợp lệ',
        },
        {
          status: 502,
        },
      );
    }

    if (payload.user.role !== 'USER') {
      return NextResponse.json(
        {
          code: 'USER_PORTAL_ROLE_REQUIRED',
          message:
            'Tài khoản này không được phép đăng nhập User Portal',
        },
        {
          status: 403,
        },
      );
    }

    const response = NextResponse.json(
      {
        user: payload.user,
      },
      {
        status: 200,
      },
    );

    response.cookies.set(
      USER_ACCESS_TOKEN_COOKIE,
      payload.accessToken,
      getUserTokenCookieOptions(
        body.remember === true,
      ),
    );

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
