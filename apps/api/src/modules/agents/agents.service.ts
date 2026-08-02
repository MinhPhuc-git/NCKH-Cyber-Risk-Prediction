import {
  BadRequestException,
  ConflictException,
  Injectable,
  Logger,
} from '@nestjs/common';
import {
  DeviceStatus,
  Prisma,
} from '@prisma/client';
import {
  createHash,
  randomBytes,
  randomUUID,
} from 'node:crypto';

import { DatabaseService } from '../../database/database.service';
import { WazuhService } from '../wazuh/wazuh.service';
import type { WazuhAgentProvisioning } from '../wazuh/wazuh.types';
import type { EnrollAgentDto } from './dto/enroll-agent.dto';
import type { EnrollAgentResponseDto } from './dto/enroll-agent-response.dto';

@Injectable()
export class AgentsService {
  private readonly logger =
    new Logger(AgentsService.name);

  constructor(
    private readonly database: DatabaseService,
    private readonly wazuh: WazuhService,
  ) {}

  async enroll(
    dto: EnrollAgentDto,
  ): Promise<EnrollAgentResponseDto> {
    const normalizedCode =
      dto.enrollmentCode
        .trim()
        .toUpperCase();

    const codeHash = createHash('sha256')
      .update(normalizedCode)
      .digest('hex');

    const enrollmentCode =
      await this.database
        .deviceEnrollmentCode
        .findUnique({
          where: {
            codeHash,
          },
          select: {
            id: true,
            userId: true,
            expiresAt: true,
            usedAt: true,
          },
        });

    if (
      !enrollmentCode ||
      enrollmentCode.usedAt ||
      enrollmentCode.expiresAt <=
        new Date()
    ) {
      throw this.createInvalidCodeError();
    }

    const existingDevice =
      await this.database.device.findUnique({
        where: {
          installationId:
            dto.installationId,
        },
        select: {
          id: true,
        },
      });

    if (existingDevice) {
      throw new ConflictException({
        code: 'AGENT_ALREADY_ENROLLED',
        message:
          'Agent này đã được liên kết với một thiết bị',
      });
    }

    const deviceId = randomUUID();
    const wazuhAgentName =
      this.createWazuhAgentName(
        deviceId,
      );

    const provisionedAgent =
      await this.wazuh.createAgent(
        wazuhAgentName,
      );

    const agentToken = randomBytes(32)
      .toString('base64url');

    const tokenHash = createHash('sha256')
      .update(agentToken)
      .digest('hex');

    try {
      const device =
        await this.database.$transaction(
          async (transaction) => {
            const consumed =
              await transaction
                .deviceEnrollmentCode
                .updateMany({
                  where: {
                    id: enrollmentCode.id,
                    usedAt: null,
                    expiresAt: {
                      gt: new Date(),
                    },
                  },
                  data: {
                    usedAt: new Date(),
                  },
                });

            if (consumed.count !== 1) {
              throw this
                .createInvalidCodeError();
            }

            const createdDevice =
              await transaction.device.create({
                data: {
                  id: deviceId,
                  userId:
                    enrollmentCode.userId,
                  installationId:
                    dto.installationId,
                  hostname:
                    dto.hostname.trim(),
                  operatingSystem:
                    dto.operatingSystem.trim(),
                  architecture:
                    dto.architecture?.trim() ??
                    null,
                  agentVersion:
                    dto.agentVersion.trim(),
                  status:
                    DeviceStatus.IDLE,
                  lastSeenAt: new Date(),
                },
                select: {
                  id: true,
                  status: true,
                },
              });

            await transaction
              .agentCredential
              .create({
                data: {
                  deviceId:
                    createdDevice.id,
                  tokenHash,
                },
              });

            await transaction
              .wazuhAgentBinding
              .create({
                data: {
                  deviceId:
                    createdDevice.id,
                  wazuhAgentId:
                    provisionedAgent.agentId,
                  wazuhAgentName:
                    provisionedAgent.agentName,
                  lastKnownStatus:
                    'never_connected',
                  lastKeepAliveAt: null,
                  lastSynchronizedAt:
                    new Date(),
                },
              });

            return createdDevice;
          },
        );

      return {
        deviceId: device.id,
        agentToken,
        status: device.status,
        wazuh: {
          agentId:
            provisionedAgent.agentId,
          agentName:
            provisionedAgent.agentName,
          clientKey:
            provisionedAgent.clientKey,
          managerAddress:
            provisionedAgent.managerAddress,
          managerPort:
            provisionedAgent.managerPort,
          protocol:
            provisionedAgent.protocol,
        },
      };
    } catch (error: unknown) {
      await this.cleanupProvisionedAgent(
        provisionedAgent,
      );

      if (
        error instanceof
          Prisma
            .PrismaClientKnownRequestError &&
        error.code === 'P2002'
      ) {
        throw new ConflictException({
          code: 'AGENT_ALREADY_ENROLLED',
          message:
            'Agent này đã được liên kết với một thiết bị',
        });
      }

      throw error;
    }
  }

  private createWazuhAgentName(
    deviceId: string,
  ): string {
    const suffix = deviceId
      .replace(/-/g, '')
      .slice(0, 12)
      .toLowerCase();

    return `cyrp-${suffix}`;
  }

  private async cleanupProvisionedAgent(
    agent: WazuhAgentProvisioning,
  ): Promise<void> {
    try {
      await this.wazuh.deleteAgent(
        agent.agentId,
      );
    } catch (cleanupError: unknown) {
      this.logger.error(
        `Không thể xóa Wazuh Agent mồ côi ${agent.agentId}`,
        cleanupError instanceof Error
          ? cleanupError.stack
          : undefined,
      );
    }
  }

  private createInvalidCodeError():
    BadRequestException {
    return new BadRequestException({
      code:
        'ENROLLMENT_CODE_INVALID',
      message:
        'Mã liên kết không hợp lệ, đã hết hạn hoặc đã được sử dụng',
    });
  }
}
