import type { NextRequest } from 'next/server';

import { proxyUserRequest } from '@/lib/authenticated-proxy';

export async function GET(
  _request: NextRequest,
  context: { params: Promise<{ id: string }> },
) {
  const { id } = await context.params;

  return proxyUserRequest(`/vulnerabilities/${id}`);
}
