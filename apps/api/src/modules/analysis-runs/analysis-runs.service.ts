import {
  ConflictException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import {
  AnalysisRunStatus,
  Prisma,
} from '@prisma/client';

import { DatabaseService } from '../../database/database.service';
import { WazuhService } from '../wazuh/wazuh.service';
import type { CreateAnalysisRunDto } from './dto/create-analysis-run.dto';

@Injectable()
export class AnalysisRunsService {
  constructor(
    private readonly database:
      DatabaseService,
    private readonly wazuh:
      WazuhService,
  ) {}

  async create(
    userId: string,
    deviceId: string,
    dto: CreateAnalysisRunDto,
  ) {
    const device =
      await this.database.device
        .findFirst({
          where: {
            id: deviceId,
            userId,
          },
          select: {
            id: true,
            wazuhBinding: {
              select: {
                wazuhAgentId: true,
              },
            },
          },
        });

    if (!device) {
      throw new NotFoundException({
        code: 'DEVICE_NOT_FOUND',
        message:
          'Không tìm thấy thiết bị thuộc tài khoản hiện tại',
      });
    }

    if (!device.wazuhBinding) {
      throw new ConflictException({
        code:
          'WAZUH_AGENT_NOT_BOUND',
        message:
          'Thiết bị chưa được liên kết với Wazuh Agent',
      });
    }

    const activeRun =
      await this.database
        .analysisRun
        .findFirst({
          where: {
            deviceId,
            status: {
              in: [
                AnalysisRunStatus.QUEUED,
                AnalysisRunStatus
                  .COLLECTING_EVENTS,
                AnalysisRunStatus
                  .ANALYZING,
              ],
            },
          },
          select: {
            id: true,
          },
        });

    if (activeRun) {
      throw new ConflictException({
        code:
          'ANALYSIS_ALREADY_RUNNING',
        message:
          'Thiết bị đang có một lần phân tích chưa hoàn tất',
        analysisRunId:
          activeRun.id,
      });
    }

    const windowEnd = new Date();
    const windowStart = new Date(
      windowEnd.getTime() -
        dto.windowMinutes *
          60_000,
    );

    const run =
      await this.database
        .analysisRun
        .create({
          data: {
            deviceId,
            status:
              AnalysisRunStatus
                .COLLECTING_EVENTS,
            windowStart,
            windowEnd,
          },
          select: {
            id: true,
          },
        });

    try {
      const agent =
        await this.wazuh.getAgent(
          device.wazuhBinding
            .wazuhAgentId,
        );

      await this.database
        .wazuhAgentBinding
        .update({
          where: {
            deviceId,
          },
          data: {
            wazuhAgentName:
              agent.name ??
              device.wazuhBinding
                .wazuhAgentId,
            lastKnownStatus:
              agent.status ?? null,
            lastKeepAliveAt:
              this.safeDate(
                agent.lastKeepAlive,
              ),
            lastSynchronizedAt:
              new Date(),
          },
        });

      await this.database
        .analysisRun
        .update({
          where: {
            id: run.id,
          },
          data: {
            status:
              AnalysisRunStatus
                .ANALYZING,
          },
        });

      const analytics =
        await this.wazuh
          .analyzeAlerts(
            device.wazuhBinding
              .wazuhAgentId,
            windowStart,
            windowEnd,
          );

      const summary = {
        windowMinutes:
          dto.windowMinutes,
        agent: {
          id:
            agent.id ??
            device.wazuhBinding
              .wazuhAgentId,
          name:
            agent.name ?? null,
          ip:
            agent.ip ?? null,
          status:
            agent.status ?? null,
          version:
            agent.version ?? null,
          lastKeepAlive:
            agent.lastKeepAlive ??
            null,
          os:
            agent.os ?? null,
        },
        severity:
          analytics.severity,
        topRules:
          analytics.topRules,
        latestAlerts:
          analytics.latestAlerts,
      };

      return this.database
        .analysisRun
        .update({
          where: {
            id: run.id,
          },
          data: {
            status:
              AnalysisRunStatus
                .COMPLETED,
            completedAt:
              new Date(),
            eventCount:
              analytics.total,
            maxRuleLevel:
              analytics
                .maxRuleLevel,
            summary:
              summary as unknown as
                Prisma.InputJsonValue,
            errorMessage: null,
          },
          select:
            this.responseSelect(),
        });
    } catch (error: unknown) {
      const message =
        error instanceof Error
          ? error.message
          : 'Unknown analysis error';

      await this.database
        .analysisRun
        .update({
          where: {
            id: run.id,
          },
          data: {
            status:
              AnalysisRunStatus.FAILED,
            completedAt:
              new Date(),
            errorMessage:
              message.slice(0, 2000),
          },
        });

      throw error;
    }
  }

  async latest(
    userId: string,
    deviceId: string,
  ) {
    const device =
      await this.database.device
        .findFirst({
          where: {
            id: deviceId,
            userId,
          },
          select: {
            id: true,
          },
        });

    if (!device) {
      throw new NotFoundException({
        code: 'DEVICE_NOT_FOUND',
        message:
          'Không tìm thấy thiết bị thuộc tài khoản hiện tại',
      });
    }

    return this.database
      .analysisRun
      .findFirst({
        where: {
          deviceId,
        },
        orderBy: {
          requestedAt: 'desc',
        },
        select:
          this.responseSelect(),
      });
  }

  private responseSelect() {
    return {
      id: true,
      deviceId: true,
      status: true,
      windowStart: true,
      windowEnd: true,
      requestedAt: true,
      completedAt: true,
      eventCount: true,
      maxRuleLevel: true,
      summary: true,
      errorMessage: true,
    } as const;
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
