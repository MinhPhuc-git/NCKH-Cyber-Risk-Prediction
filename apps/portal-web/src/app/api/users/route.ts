import { cookies } from 'next/headers';
import {
  type NextRequest,
  NextResponse,
} from 'next/server';

import {
  ACCESS_TOKEN_COOKIE,
  getExpiredCookieOptions,
} from '@/lib/auth-cookie';
import {
  backendFetch,
  readJsonBody,
} from '@/lib/backend-api';

async function getAdminAccessToken(): Promise<string | null> {
  const cookieStore = await cookies();

  return cookieStore.get(
    ACCESS_TOKEN_COOKIE,
  )?.value ?? null;
}

function authMissingResponse(): NextResponse {
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

function expireIfUnauthorized(
  response: NextResponse,
  status: number,
): NextResponse {
  if (status === 401 || status === 403) {
    response.cookies.set(
      ACCESS_TOKEN_COOKIE,
      '',
      getExpiredCookieOptions(),
    );
  }

  return response;
}

export async function GET(
  request: NextRequest,
): Promise<NextResponse> {
  const accessToken = await getAdminAccessToken();

  if (!accessToken) {
    return authMissingResponse();
  }

  const upstreamResponse =
    await backendFetch(
      `/users${request.nextUrl.search}`,
      {
        method: 'GET',
        headers: {
          Authorization:
            `Bearer ${accessToken}`,
        },
      },
    );

  const payload = await readJsonBody(
    upstreamResponse,
  );

  const response = NextResponse.json(
    payload,
    {
      status: upstreamResponse.status,
    },
  );

  return expireIfUnauthorized(
    response,
    upstreamResponse.status,
  );
}

export async function POST(
  request: NextRequest,
): Promise<NextResponse> {
  const accessToken = await getAdminAccessToken();

  if (!accessToken) {
    return authMissingResponse();
  }

  let body: {
    fullName?: unknown;
    email?: unknown;
    password?: unknown;
    confirmPassword?: unknown;
  };

  try {
    body = await request.json();
  } catch {
    return NextResponse.json(
      {
        code: 'INVALID_REQUEST_BODY',
        message:
          'Dữ liệu tạo người dùng không hợp lệ',
      },
      {
        status: 400,
      },
    );
  }

  if (
    typeof body.fullName !== 'string' ||
    typeof body.email !== 'string' ||
    typeof body.password !== 'string' ||
    typeof body.confirmPassword !== 'string'
  ) {
    return NextResponse.json(
      {
        code: 'INVALID_CREATE_USER_FORMAT',
        message:
          'Vui lòng nhập đầy đủ họ tên, email và mật khẩu tạm',
      },
      {
        status: 400,
      },
    );
  }

  if (body.password !== body.confirmPassword) {
    return NextResponse.json(
      {
        code: 'PASSWORD_CONFIRMATION_MISMATCH',
        message:
          'Mật khẩu xác nhận không khớp',
      },
      {
        status: 400,
      },
    );
  }

  if (body.password.length < 12) {
    return NextResponse.json(
      {
        code: 'PASSWORD_TOO_SHORT',
        message:
          'Mật khẩu tạm cần tối thiểu 12 ký tự',
      },
      {
        status: 400,
      },
    );
  }

  const upstreamResponse =
    await backendFetch('/users', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization:
          `Bearer ${accessToken}`,
      },
      body: JSON.stringify({
        fullName: body.fullName.trim(),
        email:
          body.email.trim().toLowerCase(),
        password: body.password,
      }),
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

  return expireIfUnauthorized(
    response,
    upstreamResponse.status,
  );
}
