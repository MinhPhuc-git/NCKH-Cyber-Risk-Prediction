import { DeviceSyncLockService } from './device-sync-lock.service';

describe('DeviceSyncLockService', () => {
  const transaction = {
    deviceSyncLease: {
      deleteMany: jest.fn(),
      create: jest.fn(),
    },
  };
  const database = {
    $transaction: jest.fn(
      async (callback: (value: typeof transaction) => Promise<void>) =>
        callback(transaction),
    ),
    deviceSyncLease: {
      deleteMany: jest.fn(),
      updateMany: jest.fn(),
      findUnique: jest.fn(),
    },
  };
  const config = {
    get: jest.fn((name: string) =>
      name === 'WAZUH_DATA_SYNC_LOCK_TTL_SECONDS' ? 120 : undefined,
    ),
  };

  beforeEach(() => {
    jest.clearAllMocks();
    transaction.deviceSyncLease.deleteMany.mockResolvedValue({ count: 0 });
    transaction.deviceSyncLease.create.mockResolvedValue({ deviceId: 'device-id' });
    database.deviceSyncLease.deleteMany.mockResolvedValue({ count: 0 });
    database.deviceSyncLease.updateMany.mockResolvedValue({ count: 1 });
    database.deviceSyncLease.findUnique.mockResolvedValue(null);
  });

  it('acquires and releases a database-backed lease', async () => {
    const service = new DeviceSyncLockService(
      database as never,
      config as never,
    );

    const result = await service.runWithLock('device-id', async () => 'ok');

    expect(result).toBe('ok');
    expect(transaction.deviceSyncLease.create).toHaveBeenCalledWith({
      data: {
        deviceId: 'device-id',
        ownerId: expect.any(String),
        acquiredAt: expect.any(Date),
        expiresAt: expect.any(Date),
      },
    });
    expect(database.deviceSyncLease.deleteMany).toHaveBeenCalledWith({
      where: {
        deviceId: 'device-id',
        ownerId: expect.any(String),
      },
    });
    expect(service.getStatus()).toMatchObject({
      strategy: 'DATABASE_LEASE',
      ttlSeconds: 120,
      localActiveLeases: 0,
    });
  });

  it('removes expired leases on application bootstrap', async () => {
    database.deviceSyncLease.deleteMany.mockResolvedValue({ count: 2 });
    const service = new DeviceSyncLockService(
      database as never,
      config as never,
    );

    await service.onApplicationBootstrap();

    expect(database.deviceSyncLease.deleteMany).toHaveBeenCalledWith({
      where: { expiresAt: { lte: expect.any(Date) } },
    });
  });
});
