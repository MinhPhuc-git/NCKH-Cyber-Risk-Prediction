export const USER_ACCESS_TOKEN_COOKIE =
  'cyrp_user_access_token';

function getTokenTtlSeconds(): number {
  const parsed = Number(
    process.env.CYRP_ACCESS_TOKEN_TTL_SECONDS ?? 900,
  );

  if (!Number.isInteger(parsed) || parsed <= 0) {
    return 900;
  }

  return parsed;
}

export function getUserTokenCookieOptions(
  remember: boolean,
) {
  const options = {
    httpOnly: true,
    secure: process.env.CYRP_COOKIE_SECURE === 'true',
    sameSite: 'lax' as const,
    path: '/',
  };

  if (!remember) {
    return options;
  }

  return {
    ...options,
    maxAge: getTokenTtlSeconds(),
  };
}

export function getExpiredUserTokenCookieOptions() {
  return {
    httpOnly: true,
    secure: process.env.CYRP_COOKIE_SECURE === 'true',
    sameSite: 'lax' as const,
    path: '/',
    maxAge: 0,
  };
}
