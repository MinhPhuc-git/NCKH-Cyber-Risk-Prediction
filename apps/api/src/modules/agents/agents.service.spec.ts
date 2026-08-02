import {
  BadRequestException,
  ConflictException,
} from '@nestjs/common';
import { DeviceStatus } from '@prisma/client';

import { AgentsService } from './agents.service';

const provisionedAgent = {
  agentId: '003',
  agentName: 'cyrp-testagent0001',
  clientKey: 'client-key',
  managerAddress:
    'wazuh-manager.cyrp.local',
  managerPort: 1514,
  protocol: 'tcp' as const,
};

describe('AgentsService', () => {
  const transaction = {
    deviceEnrollmentCode: {
      updateMany: jest.fn(),
    },
    device: {
      create: jest.fn(),
    },
    agentCredential: {
      create: jest.fn(),
    },
    wazuhAgentBinding: {
      create: jest.fn(),
    },
  };

  const database = {
    deviceEnrollmentCode: {
      findUnique: jest.fn(),
    },
    device: {
      findUnique: jest.fn(),
    },
    $transaction: jest.fn(
      async (
        callback: (
          value: typeof transaction,
        ) => unknown,
      ) => callback(transaction),
    ),
  };

  const wazuh = {
    createAgent: jest.fn(),
    deleteAgent: jest.fn(),
  };

  let service: AgentsService;

  const dto = {
    enrollmentCode:
      'CYRP-A7K9-M2Q4',
    installationId:
      'c6955739-a437-4a48-9f44-5f43defd4767',
    hostname: 'DESKTOP-TEST',
    operatingSystem:
      'Windows 11 Pro',
    architecture: 'AMD64',
    agentVersion: '0.1.0',
  };

  beforeEach(() => {
    jest.clearAllMocks();

    wazuh.createAgent
      .mockResolvedValue(
        provisionedAgent,
      );

    wazuh.deleteAgent
      .mockResolvedValue(undefined);

    service = new AgentsService(
      database as never,
      wazuh as never,
    );
  });

  it('creates a Wazuh Agent, binding and one-time credentials', async () => {
    database.deviceEnrollmentCode
      .findUnique.mockResolvedValue({
        id: 'code-id',
        userId: 'user-id',
        expiresAt: new Date(
          Date.now() + 60_000,
        ),
        usedAt: null,
      });

    database.device.findUnique
      .mockResolvedValue(null);

    transaction.deviceEnrollmentCode
      .updateMany.mockResolvedValue({
        count: 1,
      });

    transaction.device.create
      .mockImplementation(
        ({ data }: { data: { id: string } }) =>
          Promise.resolve({
            id: data.id,
            status: DeviceStatus.IDLE,
          }),
      );

    transaction.agentCredential.create
      .mockResolvedValue({
        id: 'credential-id',
      });

    transaction.wazuhAgentBinding.create
      .mockResolvedValue({
        id: 'binding-id',
      });

    const result =
      await service.enroll(dto);

    expect(result.deviceId).toEqual(
      expect.any(String),
    );

    expect(result.status).toBe(
      DeviceStatus.IDLE,
    );

    expect(result.agentToken).toEqual(
      expect.any(String),
    );

    expect(result.agentToken.length)
      .toBeGreaterThan(30);

    expect(result.wazuh).toEqual(
      provisionedAgent,
    );

    expect(
      wazuh.createAgent,
    ).toHaveBeenCalledWith(
      expect.stringMatching(
        /^cyrp-[a-f0-9]{12}$/,
      ),
    );

    expect(
      transaction.agentCredential.create,
    ).toHaveBeenCalledWith({
      data: {
        deviceId: result.deviceId,
        tokenHash:
          expect.stringMatching(
            /^[a-f0-9]{64}$/,
          ),
      },
    });

    expect(
      transaction.wazuhAgentBinding.create,
    ).toHaveBeenCalledWith({
      data: {
        deviceId: result.deviceId,
        wazuhAgentId: '003',
        wazuhAgentName:
          'cyrp-testagent0001',
        lastKnownStatus:
          'never_connected',
        lastKeepAliveAt: null,
        lastSynchronizedAt:
          expect.any(Date),
      },
    });
  });

  it('rejects an invalid enrollment code before creating a Wazuh Agent', async () => {
    database.deviceEnrollmentCode
      .findUnique.mockResolvedValue(null);

    await expect(
      service.enroll(dto),
    ).rejects.toBeInstanceOf(
      BadRequestException,
    );

    expect(
      wazuh.createAgent,
    ).not.toHaveBeenCalled();
  });

  it('rejects an already enrolled installation before creating a Wazuh Agent', async () => {
    database.deviceEnrollmentCode
      .findUnique.mockResolvedValue({
        id: 'code-id',
        userId: 'user-id',
        expiresAt: new Date(
          Date.now() + 60_000,
        ),
        usedAt: null,
      });

    database.device.findUnique
      .mockResolvedValue({
        id: 'existing-device',
      });

    await expect(
      service.enroll(dto),
    ).rejects.toBeInstanceOf(
      ConflictException,
    );

    expect(
      wazuh.createAgent,
    ).not.toHaveBeenCalled();
  });

  it('removes the provisioned Wazuh Agent when the code loses a race', async () => {
    database.deviceEnrollmentCode
      .findUnique.mockResolvedValue({
        id: 'code-id',
        userId: 'user-id',
        expiresAt: new Date(
          Date.now() + 60_000,
        ),
        usedAt: null,
      });

    database.device.findUnique
      .mockResolvedValue(null);

    transaction.deviceEnrollmentCode
      .updateMany.mockResolvedValue({
        count: 0,
      });

    await expect(
      service.enroll(dto),
    ).rejects.toBeInstanceOf(
      BadRequestException,
    );

    expect(
      wazuh.deleteAgent,
    ).toHaveBeenCalledWith('003');
  });
});
