import type { Metadata } from 'next';
import { Geist } from 'next/font/google';

import './globals.css';

const geist = Geist({
  subsets: ['latin'],
});

export const metadata: Metadata = {
  title: {
    default: 'CYRP User Portal',
    template: '%s | CYRP User Portal',
  },
  description: 'CYRP security monitoring portal for end users',
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="vi">
      <body className={geist.className}>{children}</body>
    </html>
  );
}
