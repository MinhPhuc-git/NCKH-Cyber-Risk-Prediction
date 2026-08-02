import { DeviceStatus } from '@prisma/client';

import { AgentRuntimeService } from './agent-runtime.service';

describe('AgentRuntimeService', () => {
  const database = {
    wazuhAgentBinding: {
      findUnique: jest.fn(),
      findMany: jest.fn(),
      update: jest.fn(),
      updateMany: jest.fn(),
    },
    device: {
      update: jest.fn(),
    },
    $transaction: jest.fn(async (operations: unknown[]) => Promise.all(operations)),
  };
  const wazuh = {
    isIntegrationEnabled: jest.fn(),
    getAgent: jest.fn(),
  };
  const config = {
    get: jest.fn((name: string) => {
      const values: Record<string, unknown> = {
        WAZUH_AGENT_STATUS_SYNC_ENABLED: false,
        WAZUH_AGENT_STATUS_SYNC_INTERVAL_SECONDS: 300,
        WAZUH_AGENT_STATUS_SYNC_MAX_CONCURRENCY: 2,
      };
      return values[name];
    }),
  };

  beforeEach(() => {
    jest.clearAllMocks();
    wazuh.isIntegrationEnabled.mockReturnValue(true);
    database.wazuhAgentBinding.update.mockResolvedValue({ id: 'binding-id' });
    database.wazuhAgentBinding.updateMany.mockResolvedValue({ count: 1 });
    database.device.update.mockResolvedValue({ id: 'device-id' });
  });

  it('refreshes Agent status and endpoint activity metadata', async () => {
    database.wazuhAgentBinding.findUnique.mockResolvedValue({
      deviceId: 'device-id',
      wazuhAgentId: '003',
    });
    wazuh.getAgent.mockResolvedValue({
      id: '003',
      name: 'cyrp-agent',
      status: 'active',
      lastKeepAlive: '2026-07-13T12:00:00.000Z',
    });

    const service = new AgentRuntimeService(
      database as never,
      wazuh as never,
      config as never,
    );
    const result = await service.refreshDevice('device-id');

    expect(result).toMatchObject({
      deviceId: 'device-id',
      wazuhAgentId: '003',
      status: 'COMPLETED',
      agentStatus: 'active',
      error: null,
    });
    expect(database.wazuhAgentBinding.update).toHaveBeenCalledWith({
      where: { deviceId: 'device-id' },
      data: expect.objectContaining({
        lastKnownStatus: 'active',
        lastStatusError: null,
        consecutiveStatusFailures: 0,
      }),
    });
    expect(database.device.update).toHaveBeenCalledWith({
      where: { id: 'device-id' },
      data: expect.objectContaining({
        status: DeviceStatus.IDLE,
        lastSeenAt: expect.any(Date),
      }),
    });
  });

  it('records a failed status check without stopping refresh-all', async () => {
    database.wazuhAgentBinding.findMany.mockResolvedValue([
      { deviceId: 'device-id', wazuhAgentId: '003' },
    ]);
    wazuh.getAgent.mockRejectedValue(new Error('Manager unavailable'));

    const service = new AgentRuntimeService(
      database as never,
      wazuh as never,
      config as never,
    );
    const result = await service.refreshAll();

    expect(result).toMatchObject({ requested: 1, completed: 0, failed: 1 });
    expect(database.wazuhAgentBinding.updateMany).toHaveBeenCalledWith({
      where: { deviceId: 'device-id' },
      data: {
        lastStatusCheckedAt: expect.any(Date),
        lastStatusError: expect.stringContaining('Manager unavailable'),
        consecutiveStatusFailures: { increment: 1 },
      },
    });
  });
});
