import { proxyUserRequest } from '@/lib/authenticated-proxy';
export async function GET(_request: Request, context: { params: Promise<{ deviceId: string }> }) {
  const { deviceId } = await context.params;
  return proxyUserRequest(`/devices/${encodeURIComponent(deviceId)}/overview`);
}
