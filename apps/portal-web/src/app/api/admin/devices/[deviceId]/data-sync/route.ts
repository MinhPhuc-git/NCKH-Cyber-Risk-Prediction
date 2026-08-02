import { proxyAdminRequest } from '@/lib/authenticated-proxy';
export async function POST(_request: Request, context: { params: Promise<{ deviceId: string }> }) {
  const { deviceId } = await context.params;
  return proxyAdminRequest(`/admin/devices/${encodeURIComponent(deviceId)}/data-sync`, { method: 'POST' });
}
