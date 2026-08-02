import type { Metadata } from 'next';

import { PortalShell } from '@/components/layout/portal-shell';

import { SystemHealthClient } from './system-health-client';

export const metadata: Metadata = {
  title: 'Sức khỏe hệ thống',
};

export default function SystemHealthPage() {
  return (
    <PortalShell>
      <SystemHealthClient />
    </PortalShell>
  );
}
