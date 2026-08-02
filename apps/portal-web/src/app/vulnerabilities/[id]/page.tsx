import type { Metadata } from 'next';

import { PortalShell } from '@/components/layout/portal-shell';

import { AdminVulnerabilityDetailClient } from './vulnerability-detail-client';

export const metadata: Metadata = { title: 'Chi tiết lỗ hổng' };

export default async function AdminVulnerabilityDetailPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  return <PortalShell><AdminVulnerabilityDetailClient vulnerabilityId={id} /></PortalShell>;
}
