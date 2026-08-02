import type { NextRequest } from 'next/server';
import { proxyUserRequest } from '@/lib/authenticated-proxy';
export async function GET(request: NextRequest) {
  return proxyUserRequest(`/sync-runs${request.nextUrl.search}`);
}
