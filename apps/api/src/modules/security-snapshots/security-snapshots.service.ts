import {
  HttpException,
  Injectable,
  Logger,
  NotFoundException,
  OnApplicationBootstrap,
  OnApplicationShutdown,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Prisma } from '@prisma/client';

import { DatabaseService } from '../../database/database.service';
import { WazuhService } from '../wazuh/wazuh.service';
import type { WazuhHardwareInfo } from '../wazuh/wazuh.types';

interface BindingTarget {
  deviceId: string;
  wazuhAgentId: string;
  wazuhAgentName: string;
}

interface SnapshotAlert {
  timestamp: string | null;
  ruleId: string | null;
  level: number | null;
  description: string | null;
  groups: string[];
  decoder: string | null;
  location: string | null;
}

@Injectable()
export class SecuritySnapshotsService
implements
  OnApplicationBootstrap,
  OnApplicationShutdown {
  private readonly logger =
    new Logger(
      SecuritySnapshotsService.name,
    );

  private readonly enabled: boolean;
  private readonly intervalMs: number;
  private readonly windowMinutes: number;
  private readonly maxConcurrency: number;
  private timer:
    | ReturnType<typeof setInterval>
    | null = null;
  private initialTimer:
    | ReturnType<typeof setTimeout>
    | null = null;
  private syncRunning = false;

  constructor(
    private readonly database:
      DatabaseService,
    private readonly wazuh:
      WazuhService,
    config: ConfigService,
  ) {
    const integrationEnabled = this.booleanValue(
      config.get<unknown>(
        'WAZUH_INTEGRATION_ENABLED',
      ),
      false,
    );

    this.enabled =
      integrationEnabled &&
      this.booleanValue(
        config.get<unknown>(
          'WAZUH_ACTIVE_SYNC_ENABLED',
        ),
        false,
      );

    this.intervalMs =
      this.integerValue(
        config.get<unknown>(
          'WAZUH_ACTIVE_SYNC_INTERVAL_SECONDS',
        ),
        300,
        60,
      ) * 1000;

    this.windowMinutes =
      this.integerValue(
        config.get<unknown>(
          'WAZUH_ACTIVE_SYNC_WINDOW_MINUTES',
        ),
        1440,
        15,
      );

    this.maxConcurrency =
      this.integerValue(
        config.get<unknown>(
          'WAZUH_ACTIVE_SYNC_MAX_CONCURRENCY',
        ),
        2,
        1,
        8,
      );
  }

  onApplicationBootstrap(): void {
    if (!this.enabled) {
      this.logger.log(
        'Wazuh active sync is disabled',
      );
      return;
    }

    this.logger.log(
      `Wazuh active sync enabled: interval=${this.intervalMs / 1000}s, window=${this.windowMinutes}m, concurrency=${this.maxConcurrency}`,
    );

    this.initialTimer = setTimeout(
      () => {
        void this.syncAll();
      },
      10_000,
    );

    this.timer = setInterval(
      () => {
        void this.syncAll();
      },
      this.intervalMs,
    );
  }

  onApplicationShutdown(): void {
    if (this.initialTimer) {
      clearTimeout(this.initialTimer);
    }

    if (this.timer) {
      clearInterval(this.timer);
    }
  }

  async getSnapshot(
    userId: string,
    deviceId: string,
  ) {
    const device =
      await this.database.device.findFirst({
        where: {
          id: deviceId,
          userId,
        },
        select: {
          id: true,
          securitySnapshot: true,
        },
      });

    if (!device) {
      throw this.deviceNotFound();
    }

    return device.securitySnapshot;
  }

  async syncDevice(
    userId: string,
    deviceId: string,
  ) {
    const device =
      await this.database.device.findFirst({
        where: {
          id: deviceId,
          userId,
        },
        select: {
          id: true,
          wazuhBinding: {
            select: {
              wazuhAgentId: true,
              wazuhAgentName: true,
            },
          },
        },
      });

    if (!device) {
      throw this.deviceNotFound();
    }

    if (!device.wazuhBinding) {
      throw new NotFoundException({
        code: 'WAZUH_AGENT_NOT_BOUND',
        message:
          'Thiết bị chưa được liên kết với Wazuh Agent',
      });
    }

    return this.syncBinding({
      deviceId: device.id,
      wazuhAgentId:
        device.wazuhBinding
          .wazuhAgentId,
      wazuhAgentName:
        device.wazuhBinding
          .wazuhAgentName,
    });
  }

  async syncDeviceAsAdmin(deviceId: string) {
    const device = await this.database.device.findUnique({
      where: {
        id: deviceId,
      },
      select: {
        id: true,
        wazuhBinding: {
          select: {
            wazuhAgentId: true,
            wazuhAgentName: true,
          },
        },
      },
    });

    if (!device) {
      throw this.deviceNotFound();
    }

    if (!device.wazuhBinding) {
      throw new NotFoundException({
        code: 'WAZUH_AGENT_NOT_BOUND',
        message: 'Thiết bị chưa được liên kết với Wazuh Agent',
      });
    }

    return this.syncBinding({
      deviceId: device.id,
      wazuhAgentId: device.wazuhBinding.wazuhAgentId,
      wazuhAgentName: device.wazuhBinding.wazuhAgentName,
    });
  }

  async getOverview(userId: string) {
    const devices =
      await this.database.device.findMany({
        where: {
          userId,
        },
        select: {
          id: true,
          hostname: true,
          operatingSystem: true,
          architecture: true,
          status: true,
          lastSeenAt: true,
          wazuhBinding: {
            select: {
              wazuhAgentId: true,
              wazuhAgentName: true,
              lastKnownStatus: true,
              lastKeepAliveAt: true,
            },
          },
          securitySnapshot: true,
        },
        orderBy: {
          createdAt: 'asc',
        },
      });

    const snapshots = devices
      .flatMap((device) =>
        device.securitySnapshot
          ? [device.securitySnapshot]
          : [],
      );

    const alerts24h = snapshots.reduce(
      (totals, snapshot) => ({
        total:
          totals.total +
          snapshot.alertCount,
        low:
          totals.low +
          snapshot.lowCount,
        medium:
          totals.medium +
          snapshot.mediumCount,
        high:
          totals.high +
          snapshot.highCount,
        critical:
          totals.critical +
          snapshot.criticalCount,
        maxRuleLevel: Math.max(
          totals.maxRuleLevel,
          snapshot.maxRuleLevel ?? 0,
        ),
      }),
      {
        total: 0,
        low: 0,
        medium: 0,
        high: 0,
        critical: 0,
        maxRuleLevel: 0,
      },
    );

    const active = devices.filter(
      (device) =>
        device.wazuhBinding
          ?.lastKnownStatus ===
        'active',
    ).length;

    const disconnected = devices.filter(
      (device) =>
        device.wazuhBinding &&
        device.wazuhBinding
          .lastKnownStatus !==
          'active',
    ).length;

    const topDevices = devices
      .map((device) => ({
        deviceId: device.id,
        hostname: device.hostname,
        operatingSystem:
          device.operatingSystem,
        architecture:
          device.architecture,
        deviceStatus: device.status,
        lastSeenAt: device.lastSeenAt,
        wazuhAgentId:
          device.wazuhBinding
            ?.wazuhAgentId ?? null,
        wazuhAgentName:
          device.wazuhBinding
            ?.wazuhAgentName ?? null,
        agentStatus:
          device.securitySnapshot
            ?.agentStatus ??
          device.wazuhBinding
            ?.lastKnownStatus ??
          null,
        agentIp:
          device.securitySnapshot
            ?.agentIp ?? null,
        lastKeepAliveAt:
          device.securitySnapshot
            ?.lastKeepAliveAt ??
          device.wazuhBinding
            ?.lastKeepAliveAt ??
          null,
        alertCount:
          device.securitySnapshot
            ?.alertCount ?? 0,
        maxRuleLevel:
          device.securitySnapshot
            ?.maxRuleLevel ?? null,
        riskScore:
          device.securitySnapshot
            ?.riskScore ?? 0,
        riskLabel:
          device.securitySnapshot
            ?.riskLabel ??
          'Chưa đồng bộ',
        low:
          device.securitySnapshot
            ?.lowCount ?? 0,
        medium:
          device.securitySnapshot
            ?.mediumCount ?? 0,
        high:
          device.securitySnapshot
            ?.highCount ?? 0,
        critical:
          device.securitySnapshot
            ?.criticalCount ?? 0,
        calculatedAt:
          device.securitySnapshot
            ?.calculatedAt ?? null,
        hardware:
          device.securitySnapshot
            ?.hardware ?? null,
        inventory:
          device.securitySnapshot
            ?.inventory ?? null,
        topRules:
          device.securitySnapshot
            ?.topRules ?? [],
      }))
      .sort(
        (left, right) =>
          right.riskScore -
          left.riskScore,
      );

    const latestAlerts = devices
      .flatMap((device) =>
        this.jsonArray<SnapshotAlert>(
          device.securitySnapshot
            ?.latestAlerts ?? null,
        ).map((alert) => ({
          ...alert,
          deviceId: device.id,
          hostname: device.hostname,
        })),
      )
      .sort((left, right) => {
        const leftTime = left.timestamp
          ? new Date(
              left.timestamp,
            ).getTime()
          : 0;
        const rightTime = right.timestamp
          ? new Date(
              right.timestamp,
            ).getTime()
          : 0;

        return rightTime - leftTime;
      })
      .slice(0, 20);

    const maxRiskScore = topDevices.reduce(
      (score, device) =>
        Math.max(score, device.riskScore),
      0,
    );

    return {
      calculatedAt:
        snapshots
          .map((snapshot) =>
            snapshot.calculatedAt,
          )
          .sort(
            (left, right) =>
              right.getTime() -
              left.getTime(),
          )[0] ?? null,
      devices: {
        total: devices.length,
        active,
        disconnected,
        pending:
          devices.length -
          active -
          disconnected,
      },
      alerts24h,
      risk: {
        score: maxRiskScore,
        label:
          this.riskLabel(
            maxRiskScore,
          ),
        method:
          'WAZUH_HEURISTIC_V1',
        note:
          'Điểm tạm tính từ cảnh báo Wazuh, chưa phải kết quả mô hình học máy.',
      },
      primaryDevice:
        topDevices[0] ?? null,
      topDevices:
        topDevices.slice(0, 10),
      latestAlerts,
    };
  }

  private async syncAll():
    Promise<void> {
    if (this.syncRunning) {
      this.logger.warn(
        'Skipped overlapping Wazuh active sync',
      );
      return;
    }

    this.syncRunning = true;

    try {
      const bindings =
        await this.database
          .wazuhAgentBinding
          .findMany({
            select: {
              deviceId: true,
              wazuhAgentId: true,
              wazuhAgentName: true,
            },
            orderBy: {
              createdAt: 'asc',
            },
          });

      await this.runWithConcurrency(
        bindings,
        this.maxConcurrency,
        async (binding) => {
          try {
            await this.syncBinding(
              binding,
            );
          } catch (error: unknown) {
            this.logger.warn(
              `Wazuh sync failed for agent ${binding.wazuhAgentId}: ${this.errorMessage(error)}`,
            );
          }
        },
      );
    } finally {
      this.syncRunning = false;
    }
  }

  private async syncBinding(
    target: BindingTarget,
  ) {
    const windowEnd = new Date();
    const windowStart = new Date(
      windowEnd.getTime() -
        this.windowMinutes *
          60_000,
    );

    try {
      const [
        agent,
        analytics,
      ] = await Promise.all([
        this.wazuh.getAgent(
          target.wazuhAgentId,
        ).catch((error: unknown) => {
          throw new Error(
            `Wazuh Agent API failed: ${this.errorMessage(error)}`,
          );
        }),
        this.wazuh.analyzeAlerts(
          target.wazuhAgentId,
          windowStart,
          windowEnd,
        ).catch((error: unknown) => {
          throw new Error(
            `Wazuh Indexer analytics failed: ${this.errorMessage(error)}`,
          );
        }),
      ]);

      const [
        hardwareResult,
        inventoryResult,
      ] = await Promise.allSettled([
        this.wazuh.getHardware(
          target.wazuhAgentId,
        ),
        this.wazuh.getInventoryCounts(
          target.wazuhAgentId,
        ),
      ]);

      const hardware =
        hardwareResult.status ===
        'fulfilled'
          ? hardwareResult.value
          : null;

      const inventory =
        inventoryResult.status ===
        'fulfilled'
          ? inventoryResult.value
          : {
              ports: 0,
              packages: 0,
            };

      if (
        hardwareResult.status ===
        'rejected'
      ) {
        this.logger.warn(
          `Optional Wazuh hardware sync failed for agent ${target.wazuhAgentId}: ${this.errorMessage(hardwareResult.reason)}`,
        );
      }

      if (
        inventoryResult.status ===
        'rejected'
      ) {
        this.logger.warn(
          `Optional Wazuh inventory sync failed for agent ${target.wazuhAgentId}: ${this.errorMessage(inventoryResult.reason)}`,
        );
      }

      const riskScore =
        this.calculateRiskScore(
          analytics.severity,
          analytics.maxRuleLevel,
        );

      const now = new Date();
      const lastKeepAliveAt =
        this.safeDate(
          agent.lastKeepAlive,
        );

      await this.database.$transaction([
        this.database
          .wazuhAgentBinding
          .update({
            where: {
              deviceId:
                target.deviceId,
            },
            data: {
              wazuhAgentName:
                agent.name ??
                target.wazuhAgentName,
              lastKnownStatus:
                agent.status ?? null,
              lastKeepAliveAt,
              lastSynchronizedAt:
                now,
            },
          }),
        this.database
          .deviceSecuritySnapshot
          .upsert({
            where: {
              deviceId:
                target.deviceId,
            },
            create: {
              deviceId:
                target.deviceId,
              wazuhAgentId:
                target.wazuhAgentId,
              agentName:
                agent.name ?? null,
              agentStatus:
                agent.status ?? null,
              agentIp:
                agent.ip ?? null,
              lastKeepAliveAt,
              windowMinutes:
                this.windowMinutes,
              alertCount:
                analytics.total,
              maxRuleLevel:
                analytics.maxRuleLevel,
              lowCount:
                analytics.severity.low,
              mediumCount:
                analytics.severity
                  .medium,
              highCount:
                analytics.severity.high,
              criticalCount:
                analytics.severity
                  .critical,
              riskScore,
              riskLabel:
                this.riskLabel(
                  riskScore,
                ),
              topRules:
                analytics.topRules.slice(
                  0,
                  10,
                ) as unknown as Prisma.InputJsonValue,
              latestAlerts:
                analytics.latestAlerts.slice(
                  0,
                  20,
                ) as unknown as Prisma.InputJsonValue,
              hardware:
                this.hardwareJson(
                  hardware,
                ),
              inventory:
                inventory as unknown as Prisma.InputJsonValue,
              calculatedAt: now,
              lastSuccessfulAt:
                now,
              syncError: null,
            },
            update: {
              wazuhAgentId:
                target.wazuhAgentId,
              agentName:
                agent.name ?? null,
              agentStatus:
                agent.status ?? null,
              agentIp:
                agent.ip ?? null,
              lastKeepAliveAt,
              windowMinutes:
                this.windowMinutes,
              alertCount:
                analytics.total,
              maxRuleLevel:
                analytics.maxRuleLevel,
              lowCount:
                analytics.severity.low,
              mediumCount:
                analytics.severity
                  .medium,
              highCount:
                analytics.severity.high,
              criticalCount:
                analytics.severity
                  .critical,
              riskScore,
              riskLabel:
                this.riskLabel(
                  riskScore,
                ),
              topRules:
                analytics.topRules.slice(
                  0,
                  10,
                ) as unknown as Prisma.InputJsonValue,
              latestAlerts:
                analytics.latestAlerts.slice(
                  0,
                  20,
                ) as unknown as Prisma.InputJsonValue,
              hardware:
                this.hardwareJson(
                  hardware,
                ),
              inventory:
                inventory as unknown as Prisma.InputJsonValue,
              calculatedAt: now,
              lastSuccessfulAt:
                now,
              syncError: null,
            },
          }),
      ]);

      return this.database
        .deviceSecuritySnapshot
        .findUnique({
          where: {
            deviceId:
              target.deviceId,
          },
        });
    } catch (error: unknown) {
      const message =
        this.errorMessage(error)
          .slice(0, 2000);

      await this.database
        .deviceSecuritySnapshot
        .upsert({
          where: {
            deviceId:
              target.deviceId,
          },
          create: {
            deviceId:
              target.deviceId,
            wazuhAgentId:
              target.wazuhAgentId,
            agentName:
              target.wazuhAgentName,
            windowMinutes:
              this.windowMinutes,
            alertCount: 0,
            lowCount: 0,
            mediumCount: 0,
            highCount: 0,
            criticalCount: 0,
            riskScore: 0,
            riskLabel:
              'Không xác định',
            topRules:
              [] as unknown as Prisma.InputJsonValue,
            latestAlerts:
              [] as unknown as Prisma.InputJsonValue,
            calculatedAt:
              new Date(),
            syncError: message,
          },
          update: {
            calculatedAt:
              new Date(),
            syncError: message,
          },
        });

      throw error;
    }
  }

  private hardwareJson(
    hardware: WazuhHardwareInfo | null,
  ): Prisma.InputJsonValue {
    if (!hardware) {
      return {
        cpu: null,
        ram: null,
        scanTime: null,
      } as unknown as Prisma.InputJsonValue;
    }

    return {
      cpu: hardware.cpu ?? null,
      ram: hardware.ram ?? null,
      scanTime:
        hardware.scan?.time ?? null,
    } as unknown as Prisma.InputJsonValue;
  }

  private calculateRiskScore(
    severity: {
      low: number;
      medium: number;
      high: number;
      critical: number;
    },
    maxRuleLevel: number | null,
  ): number {
    const weighted =
      severity.low +
      severity.medium * 4 +
      severity.high * 10 +
      severity.critical * 25;

    const volumeScore = Math.min(
      55,
      Math.round(
        Math.log10(weighted + 1) *
          20,
      ),
    );

    const levelScore = maxRuleLevel
      ? Math.round(
          (Math.min(
            maxRuleLevel,
            15,
          ) /
            15) *
            45,
        )
      : 0;

    return Math.min(
      100,
      volumeScore + levelScore,
    );
  }

  private riskLabel(
    score: number,
  ): string {
    if (score >= 75) {
      return 'Nghiêm trọng';
    }

    if (score >= 50) {
      return 'Cao';
    }

    if (score >= 25) {
      return 'Trung bình';
    }

    if (score > 0) {
      return 'Thấp';
    }

    return 'Không xác định';
  }

  private async runWithConcurrency<T>(
    items: T[],
    concurrency: number,
    worker: (item: T) => Promise<void>,
  ): Promise<void> {
    let cursor = 0;

    const runners = Array.from(
      {
        length: Math.min(
          concurrency,
          items.length,
        ),
      },
      async () => {
        while (cursor < items.length) {
          const index = cursor;
          cursor += 1;
          const item = items[index];

          if (item === undefined) {
            return;
          }

          await worker(item);
        }
      },
    );

    await Promise.all(runners);
  }

  private jsonArray<T>(
    value: Prisma.JsonValue | null,
  ): T[] {
    return Array.isArray(value)
      ? (value as unknown as T[])
      : [];
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

  private booleanValue(
    value: unknown,
    fallback: boolean,
  ): boolean {
    if (typeof value === 'boolean') {
      return value;
    }

    if (typeof value === 'string') {
      const normalized =
        value.trim().toLowerCase();

      if (
        ['1', 'true', 'yes', 'on']
          .includes(normalized)
      ) {
        return true;
      }

      if (
        ['0', 'false', 'no', 'off']
          .includes(normalized)
      ) {
        return false;
      }
    }

    return fallback;
  }

  private integerValue(
    value: unknown,
    fallback: number,
    minimum: number,
    maximum = Number.MAX_SAFE_INTEGER,
  ): number {
    const parsed =
      typeof value === 'number'
        ? value
        : typeof value === 'string' &&
            value.trim() !== ''
          ? Number.parseInt(value, 10)
          : fallback;

    if (
      !Number.isInteger(parsed) ||
      parsed < minimum ||
      parsed > maximum
    ) {
      return fallback;
    }

    return parsed;
  }

  private errorMessage(
    error: unknown,
  ): string {
    if (
      error instanceof
        HttpException
    ) {
      const response =
        error.getResponse();

      if (
        typeof response ===
        'string'
      ) {
        return response;
      }

      if (
        response &&
        typeof response ===
          'object'
      ) {
        const body = response as {
          message?:
            | string
            | string[];
          detail?: string;
          code?: string;
        };

        const headline =
          Array.isArray(
            body.message,
          )
            ? body.message.join(
                '; ',
              )
            : body.message ??
              error.message;

        if (
          typeof body.detail ===
            'string' &&
          body.detail.trim()
        ) {
          return `${headline}: ${body.detail}`;
        }

        return headline;
      }
    }

    if (error instanceof Error) {
      return `${error.name}: ${error.message}`;
    }

    return 'Unknown Wazuh sync error';
  }

  private deviceNotFound():
    NotFoundException {
    return new NotFoundException({
      code: 'DEVICE_NOT_FOUND',
      message:
        'Không tìm thấy thiết bị thuộc tài khoản hiện tại',
    });
  }
}
