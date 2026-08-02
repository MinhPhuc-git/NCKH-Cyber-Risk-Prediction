import type { NextRequest } from 'next/server';
import { proxyAdminRequest } from '@/lib/authenticated-proxy';
export async function GET(request: NextRequest) { return proxyAdminRequest(`/admin/devices${request.nextUrl.search}`); }
