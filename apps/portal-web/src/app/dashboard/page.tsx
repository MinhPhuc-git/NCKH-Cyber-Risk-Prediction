import type { Metadata } from 'next';

import { PortalShell } from '@/components/layout/portal-shell';

import { AdminDashboardClient } from './admin-dashboard-client';

export const metadata: Metadata = { title: 'Tổng quan' };

export default function DashboardPage() {
  return (
    <PortalShell>
      <AdminDashboardClient />
    </PortalShell>
  );
}
