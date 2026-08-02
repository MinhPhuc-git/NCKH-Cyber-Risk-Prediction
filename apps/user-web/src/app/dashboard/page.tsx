import type { Metadata } from 'next';

import { UserShell } from '@/components/user-shell';

import { DashboardOverviewClient } from './dashboard-overview-client';

export const metadata: Metadata = {
  title: 'Tổng quan bảo mật',
};

export default function DashboardPage() {
  return (
    <UserShell>
      <DashboardOverviewClient />
    </UserShell>
  );
}
