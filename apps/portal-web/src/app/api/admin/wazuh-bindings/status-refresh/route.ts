import { proxyAdminRequest } from '@/lib/authenticated-proxy';

export async function POST() {
  return proxyAdminRequest('/wazuh-bindings/status-refresh', {
    method: 'POST',
  });
}
