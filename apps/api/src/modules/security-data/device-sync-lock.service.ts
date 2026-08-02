import {
  ConflictException,
  Injectable,
  Logger,
  OnApplicationBootstrap,
  OnApplicationShutdown,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Prisma } from '@prisma/client';
import { randomUUID } from 'node:crypto';

import { DatabaseService } from '../../database/database.service';

@Injectable()
export class DeviceSyncLockService
  implements OnApplicationBootstrap, OnApplicationShutdown
{
  private readonly logger = new Logger(DeviceSyncLockService.name);
  private readonly instanceId = randomUUID();
  private readonly ttlMs: number;
  private readonly localLeases = new Map<string, string>();

  constructor(
    private readonly database: DatabaseService,
    config: ConfigService,
  ) {
    this.ttlMs =
      this.integerValue(
        config.get<unknown>('WAZUH_DATA_SYNC_LOCK_TTL_SECONDS'),
        900,
        60,
        3_600,
      ) * 1_000;
  }

  async onApplicationBootstrap(): Promise<void> {
    const result = await this.database.deviceSyncLease.deleteMany({
      where: { expiresAt: { lte: new Date() } },
    });

    if (result.count > 0) {
      this.logger.warn(`Removed ${result.count} expired device sync lease(s)`);
    }
  }

  async runWithLock<T>(
    deviceId: string,
    operation: () => Promise<T>,
  ): Promise<T> {
    const ownerId = `${this.instanceId}:${randomUUID()}`;
    await this.acquire(deviceId, ownerId);
    this.localLeases.set(deviceId, ownerId);

    const heartbeat = setInterval(() => {
      void this.extend(deviceId, ownerId);
    }, Math.max(10_000, Math.trunc(this.ttlMs / 3)));
    heartbeat.unref?.();

    try {
      return await operation();
    } finally {
      clearInterval(heartbeat);
      this.localLeases.delete(deviceId);
      await this.release(deviceId, ownerId);
    }
  }

  getStatus() {
    return {
      strategy: 'DATABASE_LEASE',
      ttlSeconds: Math.trunc(this.ttlMs / 1_000),
      localActiveLeases: this.localLeases.size,
      instanceId: this.instanceId,
    };
  }

  async onApplicationShutdown(): Promise<void> {
    const leases = [...this.localLeases.entries()];

    await Promise.allSettled(
      leases.map(([deviceId, ownerId]) => this.release(deviceId, ownerId)),
    );

    this.localLeases.clear();
  }

  private async acquire(deviceId: string, ownerId: string): Promise<void> {
    const now = new Date();
    const expiresAt = new Date(now.getTime() + this.ttlMs);

    try {
      await this.database.$transaction(async (transaction) => {
        await transaction.deviceSyncLease.deleteMany({
          where: {
            deviceId,
            expiresAt: { lte: now },
          },
        });

        await transaction.deviceSyncLease.create({
          data: {
            deviceId,
            ownerId,
            acquiredAt: now,
            expiresAt,
          },
        });
      });
    } catch (error: unknown) {
      if (
        error instanceof Prisma.PrismaClientKnownRequestError &&
        error.code === 'P2002'
      ) {
        const activeLease = await this.database.deviceSyncLease.findUnique({
          where: { deviceId },
          select: { expiresAt: true },
        });

        throw new ConflictException({
          code: 'DATA_SYNC_ALREADY_RUNNING',
          message: 'Thiết bị đang có một phiên đồng bộ dữ liệu khác',
          leaseExpiresAt: activeLease?.expiresAt ?? null,
        });
      }

      throw error;
    }
  }

  private async extend(deviceId: string, ownerId: string): Promise<void> {
    try {
      const result = await this.database.deviceSyncLease.updateMany({
        where: { deviceId, ownerId },
        data: {
          expiresAt: new Date(Date.now() + this.ttlMs),
        },
      });

      if (result.count !== 1) {
        this.logger.warn(
          `Unable to extend device sync lease for ${deviceId}; lease ownership was lost`,
        );
      }
    } catch (error: unknown) {
      this.logger.warn(
        `Unable to extend device sync lease for ${deviceId}: ${this.errorMessage(error)}`,
      );
    }
  }

  private async release(deviceId: string, ownerId: string): Promise<void> {
    try {
      await this.database.deviceSyncLease.deleteMany({
        where: { deviceId, ownerId },
      });
    } catch (error: unknown) {
      this.logger.warn(
        `Unable to release device sync lease for ${deviceId}: ${this.errorMessage(error)}`,
      );
    }
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
    return error instanceof Error ? error.message : 'Unknown database error';
  }
}
