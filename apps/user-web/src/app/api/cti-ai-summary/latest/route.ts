import { NextRequest } from 'next/server';

import { proxyUserRequest } from '@/lib/authenticated-proxy';

export async function GET(request: NextRequest) {
  const search = request.nextUrl.search;

  return proxyUserRequest(`/cti-ai-summary/latest${search}`, {
    method: 'GET',
  });
}