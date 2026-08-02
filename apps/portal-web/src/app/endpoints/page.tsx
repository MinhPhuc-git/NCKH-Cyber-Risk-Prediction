import type { Metadata } from 'next';

import { PortalShell } from '@/components/layout/portal-shell';

import { EndpointsClient } from './endpoints-client';

export const metadata: Metadata = { title: 'Thiết bị' };

export default function EndpointsPage() {
  return (
    <PortalShell>
      <EndpointsClient />
    </PortalShell>
  );
}
