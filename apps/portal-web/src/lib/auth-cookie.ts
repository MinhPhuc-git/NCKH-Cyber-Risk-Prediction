export const ACCESS_TOKEN_COOKIE =
  'cyrp_access_token';

function getTokenTtlSeconds(): number {
  const rawValue =
    process.env
      .CYRP_ACCESS_TOKEN_TTL_SECONDS;

  const parsed = Number(rawValue ?? 900);

  if (
    !Number.isInteger(parsed) ||
    parsed <= 0
  ) {
    return 900;
  }

  return parsed;
}

export function getAccessTokenCookieOptions(
  remember: boolean,
) {
  const baseOptions = {
    httpOnly: true,
    secure: process.env.CYRP_COOKIE_SECURE === 'true',
    sameSite: 'lax' as const,
    path: '/',
  };

  if (!remember) {
    return baseOptions;
  }

  return {
    ...baseOptions,
    maxAge: getTokenTtlSeconds(),
  };
}

export function getExpiredCookieOptions() {
  return {
    httpOnly: true,
    secure: process.env.CYRP_COOKIE_SECURE === 'true',
    sameSite: 'lax' as const,
    path: '/',
    maxAge: 0,
  };
}