from pathlib import Path
import shutil
from datetime import datetime

path = Path(r"D:\LuanVan\test\cyrp-platform-phase2\apps\user-web\src\app\api\devices\[deviceId]\ai-pipeline-check\route.ts")

if path.exists():
    backup = path.with_suffix(".ts.bak-forward-cookie-auth-" + datetime.now().strftime("%Y%m%d-%H%M%S"))
    shutil.copy2(path, backup)
    print(f"Backup: {backup}")

content = r'''import { NextRequest, NextResponse } from 'next/server';

type RouteContext = {
  params: Promise<{
    deviceId: string;
  }>;
};

function apiBaseUrl(): string {
  const raw =
    process.env.CYRP_API_BASE_URL ??
    process.env.API_BASE_URL ??
    process.env.NEXT_PUBLIC_API_BASE_URL ??
    'http://localhost:3001/api/v1';

  const normalized = raw.replace(/\/+$/, '');

  return normalized.endsWith('/api/v1')
    ? normalized
    : `${normalized}/api/v1`;
}

function noStore(response: Response): Response {
  response.headers.set('Cache-Control', 'no-store, max-age=0');
  response.headers.set('Pragma', 'no-cache');

  return response;
}

export async function POST(
  request: NextRequest,
  context: RouteContext,
): Promise<Response> {
  const { deviceId } = await context.params;

  const targetUrl = `${apiBaseUrl()}/devices/${encodeURIComponent(deviceId)}/ai-pipeline-check`;

  try {
    const headers = new Headers();
    headers.set('Accept', 'application/json');

    const authorization = request.headers.get('authorization');
    if (authorization) {
      headers.set('Authorization', authorization);
    }

    const cookie = request.headers.get('cookie');
    if (cookie) {
      headers.set('Cookie', cookie);
    }

    const upstream = await fetch(targetUrl, {
      method: 'POST',
      headers,
      cache: 'no-store',
    });

    return noStore(upstream);
  } catch (error) {
    return NextResponse.json(
      {
        code: 'AI_PIPELINE_PROXY_FAILED',
        message: 'User Web không gọi được CYRP API ai-pipeline-check.',
        targetUrl,
        detail: error instanceof Error ? error.message : String(error),
      },
      {
        status: 503,
        headers: {
          'Cache-Control': 'no-store, max-age=0',
          Pragma: 'no-cache',
        },
      },
    );
  }
}
'''

path.parent.mkdir(parents=True, exist_ok=True)
path.write_text(content, encoding="utf-8")

print(f"Written: {path}")
