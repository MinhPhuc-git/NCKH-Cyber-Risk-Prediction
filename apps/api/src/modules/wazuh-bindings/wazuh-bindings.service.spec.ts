import { ConflictException } from '@nestjs/common';

import { WazuhBindingsService } from './wazuh-bindings.service';

describe('WazuhBindingsService', () => {
  const database = {
    device: {
      findUnique: jest.fn(),
    },
    deviceSyncLease: {
      deleteMany: jest.fn(),
      findUnique: jest.fn(),
    },
    wazuhAgentBinding: {
      findUnique: jest.fn(),
      upsert: jest.fn(),
      delete: jest.fn(),
    },
  };
  const wazuh = {
    getAgent: jest.fn(),
  };

  beforeEach(() => {
    jest.clearAllMocks();
    database.device.findUnique.mockResolvedValue({ id: 'device-id' });
    database.deviceSyncLease.deleteMany.mockResolvedValue({ count: 0 });
    database.deviceSyncLease.findUnique.mockResolvedValue(null);
    database.wazuhAgentBinding.findUnique.mockResolvedValue(null);
  });

  it('rejects replacing a Device binding without an explicit unbind', async () => {
    database.wazuhAgentBinding.findUnique
      .mockResolvedValueOnce({ wazuhAgentId: '003' })
      .mockResolvedValueOnce(null);

    const service = new WazuhBindingsService(
      database as never,
      wazuh as never,
    );

    await expect(
      service.createOrUpdate({ deviceId: 'device-id', wazuhAgentId: '004' }),
    ).rejects.toBeInstanceOf(ConflictException);
    expect(wazuh.getAgent).not.toHaveBeenCalled();
  });

  it('rejects binding changes while a data sync lease is active', async () => {
    database.deviceSyncLease.findUnique.mockResolvedValue({
      expiresAt: new Date(Date.now() + 60_000),
    });

    const service = new WazuhBindingsService(
      database as never,
      wazuh as never,
    );

    await expect(
      service.createOrUpdate({ deviceId: 'device-id', wazuhAgentId: '003' }),
    ).rejects.toBeInstanceOf(ConflictException);
    expect(wazuh.getAgent).not.toHaveBeenCalled();
  });
});
