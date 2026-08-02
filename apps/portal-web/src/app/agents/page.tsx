import type { Metadata } from 'next';

import { PortalShell } from '@/components/layout/portal-shell';

import { AgentsClient } from './agents-client';

export const metadata: Metadata = { title: 'Wazuh Agents' };

export default function AgentsPage() {
  return <PortalShell><AgentsClient /></PortalShell>;
}
