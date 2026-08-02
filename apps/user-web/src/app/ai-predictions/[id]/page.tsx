import type { Metadata } from 'next';

import { UserShell } from '@/components/user-shell';

import { AiPredictionDetailClient } from './ai-prediction-detail-client';

export const metadata: Metadata = {
  title: 'Chi tiết dự đoán AI',
};

export default async function AiPredictionDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;

  return (
    <UserShell>
      <AiPredictionDetailClient vulnerabilityId={id} />
    </UserShell>
  );
}
