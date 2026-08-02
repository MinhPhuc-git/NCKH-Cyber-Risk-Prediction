import type { Metadata } from 'next';

import { UserShell } from '@/components/user-shell';
import { VulnerabilitiesClient } from './vulnerabilities-client';

export const metadata: Metadata = { title: 'Lỗ hổng trên thiết bị' };

export default function VulnerabilitiesPage() {
  return (
    <UserShell>
      <VulnerabilitiesClient />
    </UserShell>
  );
}
