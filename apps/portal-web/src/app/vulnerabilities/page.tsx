import type { Metadata } from 'next';

import { PortalShell } from '@/components/layout/portal-shell';

import { AdminVulnerabilitiesClient } from './vulnerabilities-client';

export const metadata: Metadata = { title: 'Lỗ hổng' };

export default function VulnerabilitiesPage() {
  return <PortalShell><AdminVulnerabilitiesClient /></PortalShell>;
}
