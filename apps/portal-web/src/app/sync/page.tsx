import type { Metadata } from 'next';

import { PortalShell } from '@/components/layout/portal-shell';

import { SyncClient } from './sync-client';

export const metadata: Metadata = {
  title: 'Đồng bộ dữ liệu',
};

export default function SyncPage() {
  return (
    <PortalShell>
      <SyncClient />
    </PortalShell>
  );
}
