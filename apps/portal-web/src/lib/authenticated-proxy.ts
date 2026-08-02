import { cookies } from 'next/headers';
import { NextResponse } from 'next/server';

import {
  ACCESS_TOKEN_COOKIE,
  getExpiredCookieOptions,
} from '@/lib/auth-cookie';
import { backendFetch, readJsonBody } from '@/lib/backend-api';

export async function proxyAdminRequest(
  backendPath: string,
  init: RequestInit = {},
): Promise<NextResponse> {
  const cookieStore = await cookies();
  const token = cookieStore.get(ACCESS_TOKEN_COOKIE)?.value;

  if (!token) {
    return NextResponse.json(
      { code: 'AUTH_TOKEN_MISSING', message: 'Chưa đăng nhập hoặc phiên đã hết hạn' },
      { status: 401 },
    );
  }

  try {
    const headers = new Headers(init.headers);
    headers.set('Authorization', `Bearer ${token}`);

    const upstream = await backendFetch(backendPath, {
      ...init,
      headers,
    });
    const payload = await readJsonBody(upstream);
    const response = NextResponse.json(payload, { status: upstream.status });

    if (upstream.status === 401 || upstream.status === 403) {
      response.cookies.set(ACCESS_TOKEN_COOKIE, '', getExpiredCookieOptions());
    }
    return response;
  } catch {
    return NextResponse.json(
      { code: 'BACKEND_UNAVAILABLE', message: 'Không thể kết nối máy chủ CYRP' },
      { status: 503 },
    );
  }
}
