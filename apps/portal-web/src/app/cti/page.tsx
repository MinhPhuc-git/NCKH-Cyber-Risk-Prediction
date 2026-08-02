import type { Metadata } from 'next';

import { PortalShell } from '@/components/layout/portal-shell';

import { CtiClient } from './cti-client';

export const metadata: Metadata = {
  title: 'Thống kê dữ liệu',
};

export default function CtiPage() {
  return (
    <PortalShell>
      <CtiClient />
    </PortalShell>
  );
}
