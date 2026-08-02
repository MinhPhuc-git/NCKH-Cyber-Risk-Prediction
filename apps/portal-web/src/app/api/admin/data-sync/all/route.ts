import { proxyAdminRequest } from '@/lib/authenticated-proxy';
export async function POST() { return proxyAdminRequest('/admin/data-sync/all', { method: 'POST' }); }
