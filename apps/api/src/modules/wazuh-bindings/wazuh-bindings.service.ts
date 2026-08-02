import {
  BadRequestException,
  ConflictException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';

import { DatabaseService } from '../../database/database.service';
import { WazuhService } from '../wazuh/wazuh.service';
import type { CreateWazuhBindingDto } from './dto/create-wazuh-binding.dto';

@Injectable()
export class WazuhBindingsService {
  constructor(
    private readonly database:
      DatabaseService,
    private readonly wazuh:
      WazuhService,
  ) {}

  async createOrUpdate(
    dto: CreateWazuhBindingDto,
  ) {
    if (dto.wazuhAgentId === '000') {
      throw new BadRequestException({
        code:
          'WAZUH_MANAGER_CANNOT_BE_BOUND',
        message:
          'Agent 000 là Wazuh Manager, không phải endpoint người dùng',
      });
    }

    const device =
      await this.database.device
        .findUnique({
          where: {
            id: dto.deviceId,
          },
          select: {
            id: true,
          },
        });

    if (!device) {
      throw new NotFoundException({
        code: 'DEVICE_NOT_FOUND',
        message:
          'Không tìm thấy CYRP Device',
      });
    }

    await this.assertNoActiveSyncLease(dto.deviceId);

    const bindingForDevice =
      await this.database.wazuhAgentBinding.findUnique({
        where: { deviceId: dto.deviceId },
        select: { wazuhAgentId: true },
      });

    if (
      bindingForDevice &&
      bindingForDevice.wazuhAgentId !== dto.wazuhAgentId
    ) {
      throw new ConflictException({
        code: 'CYRP_DEVICE_ALREADY_BOUND',
        message:
          'CYRP Device đã liên kết với một Wazuh Agent khác. Hãy gỡ binding hiện tại trước khi liên kết Agent mới.',
      });
    }

    const bindingForAgent =
      await this.database
        .wazuhAgentBinding
        .findUnique({
          where: {
            wazuhAgentId:
              dto.wazuhAgentId,
          },
          select: {
            deviceId: true,
          },
        });

    if (
      bindingForAgent &&
      bindingForAgent.deviceId !==
        dto.deviceId
    ) {
      throw new ConflictException({
        code:
          'WAZUH_AGENT_ALREADY_BOUND',
        message:
          'Wazuh Agent đã được liên kết với một CYRP Device khác',
      });
    }

    const agent =
      await this.wazuh.getAgent(
        dto.wazuhAgentId,
      );

    if (!agent.id || !agent.name) {
      throw new BadRequestException({
        code:
          'WAZUH_AGENT_RESPONSE_INVALID',
        message:
          'Wazuh Agent không có đủ ID hoặc tên',
      });
    }

    return this.database
      .wazuhAgentBinding
      .upsert({
        where: {
          deviceId: dto.deviceId,
        },
        create: {
          deviceId: dto.deviceId,
          wazuhAgentId: agent.id,
          wazuhAgentName:
            agent.name,
          lastKnownStatus:
            agent.status ?? null,
          lastKeepAliveAt:
            this.safeDate(
              agent.lastKeepAlive,
            ),
          lastSynchronizedAt:
            new Date(),
          lastStatusCheckedAt:
            new Date(),
          lastStatusError: null,
          consecutiveStatusFailures: 0,
        },
        update: {
          wazuhAgentId: agent.id,
          wazuhAgentName:
            agent.name,
          lastKnownStatus:
            agent.status ?? null,
          lastKeepAliveAt:
            this.safeDate(
              agent.lastKeepAlive,
            ),
          lastSynchronizedAt:
            new Date(),
          lastStatusCheckedAt:
            new Date(),
          lastStatusError: null,
          consecutiveStatusFailures: 0,
        },
        select: {
          id: true,
          deviceId: true,
          wazuhAgentId: true,
          wazuhAgentName: true,
          lastKnownStatus: true,
          lastKeepAliveAt: true,
          lastSynchronizedAt: true,
          lastStatusCheckedAt: true,
          lastStatusError: true,
          consecutiveStatusFailures: true,
        },
      });
  }

  async remove(deviceId: string) {
    await this.assertNoActiveSyncLease(deviceId);

    const binding = await this.database.wazuhAgentBinding.findUnique({
      where: { deviceId },
      select: {
        id: true,
        deviceId: true,
        wazuhAgentId: true,
        wazuhAgentName: true,
      },
    });

    if (!binding) {
      throw new NotFoundException({
        code: 'WAZUH_BINDING_NOT_FOUND',
        message: 'Thiết bị chưa có Wazuh Agent binding',
      });
    }

    await this.database.wazuhAgentBinding.delete({
      where: { deviceId },
    });

    return {
      removed: true,
      binding,
      note: 'Wazuh Agent vẫn tồn tại trên Wazuh Manager',
    };
  }

  private async assertNoActiveSyncLease(deviceId: string): Promise<void> {
    const now = new Date();
    await this.database.deviceSyncLease.deleteMany({
      where: { deviceId, expiresAt: { lte: now } },
    });

    const lease = await this.database.deviceSyncLease.findUnique({
      where: { deviceId },
      select: { expiresAt: true },
    });

    if (lease) {
      throw new ConflictException({
        code: 'DATA_SYNC_ALREADY_RUNNING',
        message:
          'Không thể thay đổi binding khi thiết bị đang đồng bộ dữ liệu',
        leaseExpiresAt: lease.expiresAt,
      });
    }
  }

  private safeDate(
    value: string | undefined,
  ): Date | null {
    if (!value) {
      return null;
    }

    const date = new Date(value);

    return Number.isNaN(
      date.getTime(),
    )
      ? null
      : date;
  }
}
