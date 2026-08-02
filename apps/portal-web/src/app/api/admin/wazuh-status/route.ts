import { proxyAdminRequest } from '@/lib/authenticated-proxy';

export async function GET() {
  return proxyAdminRequest('/wazuh/status');
}
