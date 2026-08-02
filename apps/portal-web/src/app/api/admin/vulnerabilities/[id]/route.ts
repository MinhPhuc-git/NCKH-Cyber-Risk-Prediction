import { proxyAdminRequest } from '@/lib/authenticated-proxy';

export async function GET(
  _request: Request,
  context: { params: Promise<{ id: string }> },
) {
  const { id } = await context.params;
  return proxyAdminRequest(`/admin/vulnerabilities/${encodeURIComponent(id)}`);
}
