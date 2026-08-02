import type { NextRequest } from 'next/server';
import { proxyAdminRequest } from '@/lib/authenticated-proxy';
export async function GET(request: NextRequest) { return proxyAdminRequest(`/admin/wazuh-bindings${request.nextUrl.search}`); }

export async function POST(request: NextRequest) {
  const body = await request.text();

  return proxyAdminRequest('/wazuh-bindings', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body,
  });
}
