import type { Metadata } from 'next';

import { UserShell } from '@/components/user-shell';

import { ReportsClient } from './reports-client';

export const metadata: Metadata = { title: 'Báo cáo dữ liệu' };

export default function ReportsPage() {
  return (
    <UserShell>
      <ReportsClient />
    </UserShell>
  );
}
