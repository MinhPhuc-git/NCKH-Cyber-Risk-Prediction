import type { Metadata } from 'next';

import { UserShell } from '@/components/user-shell';

import { VulnerabilityDetailClient } from './vulnerability-detail-client';

export const metadata: Metadata = {
  title: 'Chi tiết lỗ hổng',
};

export default async function VulnerabilityDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;

  return (
    <UserShell>
      <VulnerabilityDetailClient vulnerabilityId={id} />
    </UserShell>
  );
}
