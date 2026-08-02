import type { Metadata } from 'next';

import { UserShell } from '@/components/user-shell';

import { SyncHistoryClient } from './sync-history-client';

export const metadata: Metadata = {
  title: 'Lịch sử đồng bộ',
};

export default function SyncHistoryPage() {
  return (
    <UserShell>
      <SyncHistoryClient />
    </UserShell>
  );
}
