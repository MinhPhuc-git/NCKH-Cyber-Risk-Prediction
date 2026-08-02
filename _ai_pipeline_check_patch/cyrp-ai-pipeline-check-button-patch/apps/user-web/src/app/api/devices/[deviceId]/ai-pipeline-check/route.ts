import { proxyUserRequest } from '@/lib/authenticated-proxy';

interface RouteContext {
  params: Promise<{
    deviceId: string;
  }>;
}

export async function POST(
  _request: Request,
  context: RouteContext,
) {
  const { deviceId } = await context.params;

  return proxyUserRequest(
    `/devices/${encodeURIComponent(deviceId)}/ai-pipeline-check`,
    {
      method: 'POST',
    },
  );
}
