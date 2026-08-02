import type { Metadata } from 'next';

import { UserShell } from '@/components/user-shell';

import { DeviceDetailClient } from './device-detail-client';

export const metadata: Metadata = {
  title: 'Chi tiết thiết bị',
};

export default async function DeviceDetailPage({
  params,
}: {
  params: Promise<{ deviceId: string }>;
}) {
  const { deviceId } = await params;

  return (
    <UserShell>
      <DeviceDetailClient deviceId={deviceId} />
    </UserShell>
  );
}
