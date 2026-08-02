from pathlib import Path
import shutil
from datetime import datetime

path = Path(r"D:\LuanVan\test\cyrp-platform-phase2\apps\user-web\src\app\api\devices\[deviceId]\ai-pipeline-check\route.ts")

if path.exists():
    backup = path.with_suffix(".ts.bak-clean-ai-pipeline-route-" + datetime.now().strftime("%Y%m%d-%H%M%S"))
    shutil.copy2(path, backup)
    print(f"Backup: {backup}")

content = r'''import { NextRequest } from 'next/server';

import { proxyUserRequest } from '@/lib/authenticated-proxy';

type RouteContext = {
  params: Promise<{
    deviceId: string;
  }>;
};

function noStore(response: Response): Response {
  response.headers.set('Cache-Control', 'no-store, max-age=0');
  response.headers.set('Pragma', 'no-cache');

  return response;
}

export async function POST(
  _request: NextRequest,
  context: RouteContext,
): Promise<Response> {
  const { deviceId } = await context.params;

  const response = await proxyUserRequest(
    `/devices/${deviceId}/ai-pipeline-check`,
    {
      method: 'POST',
    },
  );

  return noStore(response);
}
'''

path.parent.mkdir(parents=True, exist_ok=True)
path.write_text(content, encoding="utf-8")

print(f"Clean route written: {path}")
