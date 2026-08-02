import { NextResponse } from 'next/server';

import {
  ACCESS_TOKEN_COOKIE,
  getExpiredCookieOptions,
} from '@/lib/auth-cookie';

export async function POST():
  Promise<NextResponse> {
  const response = NextResponse.json({
    success: true,
  });

  response.cookies.set(
    ACCESS_TOKEN_COOKIE,
    '',
    getExpiredCookieOptions(),
  );

  return response;
}