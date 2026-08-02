import type { Metadata } from 'next';

import { DevicesPageClient } from './devices-page-client';

export const metadata: Metadata = {
  title: 'Thiết bị',
};

export default function DevicesPage() {
  return <DevicesPageClient />;
}
