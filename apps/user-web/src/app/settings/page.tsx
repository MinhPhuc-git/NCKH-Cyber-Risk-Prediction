import type { Metadata } from 'next';

import { UserShell } from '@/components/user-shell';

import { SettingsClient } from './settings-client';

export const metadata: Metadata = { title: 'Cài đặt' };

export default function SettingsPage() {
  return (
    <UserShell>
      <SettingsClient />
    </UserShell>
  );
}
