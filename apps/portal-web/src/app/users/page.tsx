import type { Metadata } from 'next';

import { UsersPageClient } from './users-page-client';

export const metadata: Metadata = {
  title: 'Quản lý người dùng',
};

export default function UsersPage() {
  return <UsersPageClient />;
}