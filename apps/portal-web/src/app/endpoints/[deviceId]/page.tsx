import type { Metadata } from 'next';

import { PortalShell } from '@/components/layout/portal-shell';

import { EndpointDetailClient } from './endpoint-detail-client';

export const metadata: Metadata = { title: 'Chi tiết thiết bị' };

export default async function EndpointDetailPage({ params }: { params: Promise<{ deviceId: string }> }) {
  const { deviceId } = await params;
  return <PortalShell><EndpointDetailClient deviceId={deviceId} /></PortalShell>;
}
