import {
  Injectable,
  Logger,
  NotFoundException,
  OnApplicationBootstrap,
  OnApplicationShutdown,
  ServiceUnavailableException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { DeviceStatus } from '@prisma/client';

import { DatabaseService } from '../../database/database.service';
import { WazuhService } from '../wazuh/wazuh.service';

interface AgentRefreshResult {
  deviceId: string;
  wazuhAgentId: string;
  status: 'COMPLETED' | 'FAILED';
  checkedAt: Date;
  agentStatus: string | null;
  lastKeepAliveAt: Date | null;
  error: string | null;
}

@Injectable()
export class AgentRuntimeService
  implements OnApplicationBootstrap, OnApplicationShutdown
{
  private readonly logger = new Logger(AgentRuntimeService.name);
  private readonly scheduleEnabled: boolean;
  private readonly intervalMs: number;
  private readonly maxConcurrency: number;
  private timer: ReturnType<typeof setInterval> | null = null;
  private initialTimer: ReturnType<typeof setTimeout> | null = null;
  private scheduledRunActive = false;

  constructor(
    private readonly database: DatabaseService,
    private readonly wazuh: WazuhService,
    config: ConfigService,
  ) {
    this.scheduleEnabled = this.booleanValue(
      config.get<unknown>('WAZUH_AGENT_STATUS_SYNC_ENABLED'),
      false,
    );
    this.intervalMs =
      this.integerValue(
        config.get<unknown>('WAZUH_AGENT_STATUS_SYNC_INTERVAL_SECONDS'),
        300,
        60,
        86_400,
      ) * 1_000;
    this.maxConcurrency = this.integerValue(
      config.get<unknown>('WAZUH_AGENT_STATUS_SYNC_MAX_CONCURRENCY'),
      4,
      1,
      16,
    );
  }

  onApplicationBootstrap(): void {
    if (!this.scheduleEnabled || !this.wazuh.isIntegrationEnabled()) {
      this.logger.log('Wazuh Agent status synchronization is disabled');
      return;
    }

    this.initialTimer = setTimeout(() => {
      void this.runScheduledRefresh();
    }, 15_000);

    this.timer = setInterval(() => {
      void this.runScheduledRefresh();
    }, this.intervalMs);
  }

  onApplicationShutdown(): void {
    if (this.initialTimer) {
      clearTimeout(this.initialTimer);
    }

    if (this.timer) {
      clearInterval(this.timer);
    }
  }

  getSchedulerStatus() {
    return {
      integrationEnabled: this.wazuh.isIntegrationEnabled(),
      configured: this.scheduleEnabled,
      enabled: this.scheduleEnabled && this.wazuh.isIntegrationEnabled(),
      running: this.scheduledRunActive,
      intervalSeconds: Math.trunc(this.intervalMs / 1_000),
      maxConcurrency: this.maxConcurrency,
    };
  }

  async refreshDevice(
    deviceId: string,
    trigger = 'ADMIN_MANUAL',
  ): Promise<AgentRefreshResult> {
    this.assertIntegrationEnabled();

    const binding = await this.database.wazuhAgentBinding.findUnique({
      where: { deviceId },
      select: {
        deviceId: true,
        wazuhAgentId: true,
      },
    });

    if (!binding) {
      throw new NotFoundException({
        code: 'WAZUH_BINDING_NOT_FOUND',
        message: 'Thiết bị chưa có Wazuh Agent binding',
      });
    }

    return this.refreshBinding(binding, trigger, true);
  }

  async refreshAll(trigger = 'ADMIN_ALL'): Promise<{
    requested: number;
    completed: number;
    failed: number;
    results: AgentRefreshResult[];
  }> {
    this.assertIntegrationEnabled();

    const bindings = await this.database.wazuhAgentBinding.findMany({
      select: {
        deviceId: true,
        wazuhAgentId: true,
      },
      orderBy: { createdAt: 'asc' },
    });
    const results: AgentRefreshResult[] = [];

    await this.runWithConcurrency(
      bindings,
      this.maxConcurrency,
      async (binding) => {
        results.push(await this.refreshBinding(binding, trigger, false));
      },
    );

    return {
      requested: bindings.length,
      completed: results.filter((item) => item.status === 'COMPLETED').length,
      failed: results.filter((item) => item.status === 'FAILED').length,
      results,
    };
  }

  private async runScheduledRefresh(): Promise<void> {
    if (this.scheduledRunActive) {
      this.logger.warn('Skipped overlapping Wazuh Agent status refresh');
      return;
    }

    this.scheduledRunActive = true;

    try {
      const result = await this.refreshAll('SCHEDULED');
      this.logger.log(
        `Wazuh Agent status refresh completed: ${result.completed}/${result.requested} succeeded`,
      );
    } catch (error: unknown) {
      this.logger.warn(
        `Wazuh Agent status refresh failed: ${this.errorMessage(error)}`,
      );
    } finally {
      this.scheduledRunActive = false;
    }
  }

  private async refreshBinding(
    binding: { deviceId: string; wazuhAgentId: string },
    trigger: string,
    throwOnFailure: boolean,
  ): Promise<AgentRefreshResult> {
    const checkedAt = new Date();

    try {
      const agent = await this.wazuh.getAgent(binding.wazuhAgentId);
      const lastKeepAliveAt = this.safeDate(agent.lastKeepAlive);
      const agentStatus = agent.status ?? null;

      await this.database.$transaction([
        this.database.wazuhAgentBinding.update({
          where: { deviceId: binding.deviceId },
          data: {
            wazuhAgentName: agent.name ?? binding.wazuhAgentId,
            lastKnownStatus: agentStatus,
            lastKeepAliveAt,
            lastStatusCheckedAt: checkedAt,
            lastStatusError: null,
            consecutiveStatusFailures: 0,
          },
        }),
        this.database.device.update({
          where: { id: binding.deviceId },
          data: {
            status:
              agentStatus?.toLowerCase() === 'active'
                ? DeviceStatus.IDLE
                : DeviceStatus.OFFLINE,
            ...(lastKeepAliveAt ? { lastSeenAt: lastKeepAliveAt } : {}),
          },
        }),
      ]);

      return {
        deviceId: binding.deviceId,
        wazuhAgentId: binding.wazuhAgentId,
        status: 'COMPLETED',
        checkedAt,
        agentStatus,
        lastKeepAliveAt,
        error: null,
      };
    } catch (error: unknown) {
      const message = `${trigger}: ${this.errorMessage(error)}`.slice(0, 2_000);

      await this.database.wazuhAgentBinding.updateMany({
        where: { deviceId: binding.deviceId },
        data: {
          lastStatusCheckedAt: checkedAt,
          lastStatusError: message,
          consecutiveStatusFailures: { increment: 1 },
        },
      });

      const result: AgentRefreshResult = {
        deviceId: binding.deviceId,
        wazuhAgentId: binding.wazuhAgentId,
        status: 'FAILED',
        checkedAt,
        agentStatus: null,
        lastKeepAliveAt: null,
        error: message,
      };

      if (throwOnFailure) {
        throw error;
      }

      return result;
    }
  }

  private async runWithConcurrency<T>(
    items: T[],
    concurrency: number,
    worker: (item: T) => Promise<void>,
  ): Promise<void> {
    let nextIndex = 0;
    const workers = Array.from(
      { length: Math.min(concurrency, items.length) },
      async () => {
        while (nextIndex < items.length) {
          const item = items[nextIndex];
          nextIndex += 1;
          await worker(item);
        }
      },
    );

    await Promise.all(workers);
  }

  private assertIntegrationEnabled(): void {
    if (!this.wazuh.isIntegrationEnabled()) {
      throw new ServiceUnavailableException({
        code: 'WAZUH_INTEGRATION_DISABLED',
        message:
          'Tích hợp Wazuh đang tắt. Hãy cấu hình WAZUH_INTEGRATION_ENABLED=true trước khi làm mới trạng thái Agent.',
      });
    }
  }

  private safeDate(value: string | undefined): Date | null {
    if (!value) {
      return null;
    }

    const parsed = new Date(value);
    return Number.isNaN(parsed.getTime()) ? null : parsed;
  }

  private booleanValue(value: unknown, fallback: boolean): boolean {
    if (typeof value === 'boolean') {
      return value;
    }

    if (typeof value === 'string') {
      const normalized = value.trim().toLowerCase();
      if (normalized === 'true') return true;
      if (normalized === 'false') return false;
    }

    return fallback;
  }

  private integerValue(
    value: unknown,
    fallback: number,
    min: number,
    max: number,
  ): number {
    const parsed =
      typeof value === 'number'
        ? value
        : typeof value === 'string' && value.trim() !== ''
          ? Number.parseInt(value, 10)
          : fallback;

    return Number.isInteger(parsed)
      ? Math.min(max, Math.max(min, parsed))
      : fallback;
  }

  private errorMessage(error: unknown): string {
    return error instanceof Error ? error.message : 'Unknown Wazuh error';
  }
}
