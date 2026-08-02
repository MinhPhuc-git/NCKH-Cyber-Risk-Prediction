import { NextResponse } from 'next/server';

import {
  USER_ACCESS_TOKEN_COOKIE,
  getExpiredUserTokenCookieOptions,
} from '@/lib/auth-cookie';

export async function POST():
  Promise<NextResponse> {
  const response = NextResponse.json({
    success: true,
  });

  response.cookies.set(
    USER_ACCESS_TOKEN_COOKIE,
    '',
    getExpiredUserTokenCookieOptions(),
  );

  return response;
}
