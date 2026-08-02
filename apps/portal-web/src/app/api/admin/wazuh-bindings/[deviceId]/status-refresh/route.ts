import type { NextRequest } from 'next/server';

import { proxyAdminRequest } from '@/lib/authenticated-proxy';

interface RouteContext {
  params: Promise<{ deviceId: string }>;
}

export async function POST(
  _request: NextRequest,
  context: RouteContext,
) {
  const { deviceId } = await context.params;

  return proxyAdminRequest(
    `/wazuh-bindings/${encodeURIComponent(deviceId)}/status-refresh`,
    { method: 'POST' },
  );
}
