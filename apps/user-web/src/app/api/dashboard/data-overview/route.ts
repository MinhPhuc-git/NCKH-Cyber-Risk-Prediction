import { proxyUserRequest } from '@/lib/authenticated-proxy';
export async function GET() { return proxyUserRequest('/dashboard/data-overview'); }
