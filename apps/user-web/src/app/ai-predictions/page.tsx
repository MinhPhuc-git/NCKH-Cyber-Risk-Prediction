import { UserShell } from '@/components/user-shell';

import { AiPredictionsClient } from './ai-predictions-client';

export default function AiPredictionsPage() {
  return (
    <UserShell>
      <AiPredictionsClient />
    </UserShell>
  );
}