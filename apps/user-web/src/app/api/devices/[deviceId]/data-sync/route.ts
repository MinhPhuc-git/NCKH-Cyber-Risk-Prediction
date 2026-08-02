import { NextRequest, NextResponse } from 'next/server';

import { proxyUserRequest } from '@/lib/authenticated-proxy';

type RouteContext = {
  params: Promise<{
    deviceId: string;
  }>;
};

type SyncPayload = {
  status?: string;
  message?: string;
  components?: Record<string, {
    status?: string;
    message?: string;
  }>;
};

function noStore(response: Response): Response {
  response.headers.set('Cache-Control', 'no-store, max-age=0');
  response.headers.set('Pragma', 'no-cache');
  return response;
}

async function getLatestSnapshot(deviceId: string) {
  const response = await proxyUserRequest(
    `/devices/${deviceId}/security-snapshot`,
    {
      method: 'GET',
    },
  );

  return noStore(response);
}

function failedSyncMessage(payload: SyncPayload | null): string {
  const components = payload?.components ?? {};

  const messages = Object.entries(components)
    .filter(([, value]) => value?.status === 'FAILED')
    .map(([name, value]) => `${name}: ${value?.message ?? 'failed'}`);

  if (messages.length > 0) {
    return `Đồng bộ Wazuh thất bại. ${messages.join(' | ')}`;
  }

  return payload?.message ?? 'Đồng bộ Wazuh thất bại. Không hiển thị kết quả cũ.';
}

export async function POST(
  _request: NextRequest,
  context: RouteContext,
) {
  const { deviceId } = await context.params;

  const syncResponse = await proxyUserRequest(
    `/devices/${deviceId}/data-sync`,
    {
      method: 'POST',
    },
  );

  if (syncResponse.status === 409) {
    return NextResponse.json(
      {
        code: 'DATA_SYNC_ALREADY_RUNNING',
        message: 'Thiết bị đang đồng bộ dữ liệu từ Wazuh. Chờ phiên hiện tại hoàn tất rồi bấm kiểm tra lại.',
      },
      {
        status: 409,
        headers: {
          'Cache-Control': 'no-store, max-age=0',
          Pragma: 'no-cache',
        },
      },
    );
  }

  if (!syncResponse.ok) {
    return noStore(syncResponse);
  }

  let syncPayload: SyncPayload | null = null;

  try {
    syncPayload = await syncResponse.clone().json() as SyncPayload;
  } catch {
    syncPayload = null;
  }

  if (syncPayload?.status === 'FAILED') {
    return NextResponse.json(
      {
        code: 'DATA_SYNC_FAILED',
        message: failedSyncMessage(syncPayload),
        details: syncPayload,
      },
      {
        status: 502,
        headers: {
          'Cache-Control': 'no-store, max-age=0',
          Pragma: 'no-cache',
        },
      },
    );
  }

  return getLatestSnapshot(deviceId);
}