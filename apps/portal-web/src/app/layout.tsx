import type { Metadata } from 'next';
import { Geist } from 'next/font/google';
import './globals.css';

const geist = Geist({
  subsets: ['latin'],
  variable: '--font-geist',
});

export const metadata: Metadata = {
  title: {
    default: 'CYRP Platform',
    template: '%s | CYRP Platform',
  },
  description:
    'Cybersecurity Risk Profiling and Management Platform',
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="vi">
      <body className={geist.variable}>{children}</body>
    </html>
  );
}