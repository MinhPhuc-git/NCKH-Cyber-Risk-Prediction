import {
  Injectable,
  Logger,
  NotFoundException,
  OnApplicationBootstrap,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
  Prisma,
  SyncRunStatus,
  SyncSourceType,
  VulnerabilityLifecycleStatus,
} from '@prisma/client';

import { DatabaseService } from '../../database/database.service';
import { AiModelRuntimeService } from './ai-model-runtime.service';
import { SecurityDataSyncService } from './security-data-sync.service';

const ASYNC_TRIGGER = 'USER_MACHINE_CHECK_ASYNC';

interface TopPredictionItem {
  cveId: string;
  riskLevel: string | null;
  attackProbability: number | null;
  predictedPercentile: number | null;
  predictedAt: string | null;
}

interface ActiveCheck {
  runId: string;
  promise: Promise<void>;
}

export interface MachineCheckStartResult {
  runId: string;
  deviceId: string;
  wazuhAgentId: string;
  status: 'RUNNING';
  reused: boolean;
  pollAfterMs: number;
  message: string;
}

export interface MachineCheckStatusResult {
  runId: string;
  deviceId: string;
  status: SyncRunStatus;
  phase: string;
  message: string;
  cached: boolean;
  startedAt: string;
  completedAt: string | null;
  durationMs: number | null;
  activeVulnerabilities: number | null;
  predictions: number | null;
  predictionsSkippedUnchanged: number | null;
  topPredictions: TopPredictionItem[];
  error: string | null;
}

@Injectable()
export class AiPipelineCheckService implements OnApplicationBootstrap {
  private readonly logger = new Logger(AiPipelineCheckService.name);
  private readonly activeChecks = new Map<string, ActiveCheck>();
  private readonly freshnessMs: number;
  private readonly pollAfterMs: number;

  constructor(
    private readonly database: DatabaseService,
    private readonly securityDataSync: SecurityDataSyncService,
    private readonly aiModelRuntime: AiModelRuntimeService,
    config: ConfigService,
  ) {
    this.freshnessMs =
      this.integerValue(
        config.get<unknown>('MACHINE_CHECK_FRESHNESS_SECONDS'),
        300,
        0,
        3600,
      ) * 1000;
    this.pollAfterMs = this.integerValue(
      config.get<unknown>('MACHINE_CHECK_POLL_INTERVAL_MS'),
      2000,
      500,
      10000,
    );
  }

  async onApplicationBootstrap(): Promise<void> {
    const completedAt = new Date();
    const orphaned = await this.database.syncRun.updateMany({
      where: {
        trigger: ASYNC_TRIGGER,
        status: SyncRunStatus.RUNNING,
      },
      data: {
        status: SyncRunStatus.FAILED,
        completedAt,
        errorSummary:
          'MACHINE_CHECK_INTERRUPTED: API restarted before the background run completed.',
        metadata: {
          phase: 'FAILED',
          message: 'Lần kiểm tra trước bị gián đoạn do API khởi động lại.',
          cached: false,
        },
      },
    });

    if (orphaned.count > 0) {
      this.logger.warn(
        `Marked ${orphaned.count} orphaned async machine-check run(s) as FAILED`,
      );
    }
  }

  async startForUserDevice(
    userId: string,
    deviceId: string,
  ): Promise<MachineCheckStartResult> {
    const device = await this.database.device.findFirst({
      where: {
        id: deviceId,
        userId,
      },
      include: {
        wazuhBinding: true,
      },
    });

    if (!device) {
      throw new NotFoundException({
        code: 'DEVICE_NOT_FOUND',
        message: 'Không tìm thấy thiết bị thuộc tài khoản hiện tại.',
      });
    }

    const wazuhAgentId = device.wazuhBinding?.wazuhAgentId;

    if (!wazuhAgentId) {
      throw new NotFoundException({
        code: 'WAZUH_AGENT_BINDING_NOT_FOUND',
        message: 'Thiết bị chưa có Wazuh Agent binding.',
      });
    }

    const active = this.activeChecks.get(deviceId);
    if (active) {
      return {
        runId: active.runId,
        deviceId,
        wazuhAgentId,
        status: 'RUNNING',
        reused: true,
        pollAfterMs: this.pollAfterMs,
        message: 'Thiết bị đang có một lần kiểm tra chạy nền.',
      };
    }

    // Any RUNNING row left in the database without an in-memory promise belongs
    // to an interrupted process and must not block a new run.
    await this.database.syncRun.updateMany({
      where: {
        deviceId,
        trigger: ASYNC_TRIGGER,
        status: SyncRunStatus.RUNNING,
      },
      data: {
        status: SyncRunStatus.FAILED,
        completedAt: new Date(),
        errorSummary:
          'MACHINE_CHECK_INTERRUPTED: no active worker exists for this database row.',
      },
    });

    const run = await this.database.syncRun.create({
      data: {
        deviceId,
        sourceType: SyncSourceType.MANUAL,
        status: SyncRunStatus.RUNNING,
        trigger: ASYNC_TRIGGER,
        startedAt: new Date(),
        sourceManifest: {
          kind: 'ASYNC_MACHINE_CHECK',
          deviceId,
          wazuhAgentId,
        },
        metadata: {
          phase: 'QUEUED',
          message: 'Đã tiếp nhận yêu cầu kiểm tra máy.',
          cached: false,
          userId,
          wazuhAgentId,
        },
      },
      select: {
        id: true,
      },
    });

    const promise = this.executeRun(
      userId,
      deviceId,
      wazuhAgentId,
      run.id,
    ).finally(() => {
      const current = this.activeChecks.get(deviceId);
      if (current?.runId === run.id) {
        this.activeChecks.delete(deviceId);
      }
    });

    this.activeChecks.set(deviceId, {
      runId: run.id,
      promise,
    });

    void promise;

    return {
      runId: run.id,
      deviceId,
      wazuhAgentId,
      status: 'RUNNING',
      reused: false,
      pollAfterMs: this.pollAfterMs,
      message: 'CYRP đang kiểm tra máy ở chế độ nền.',
    };
  }

  async getRunForUserDevice(
    userId: string,
    deviceId: string,
    runId: string,
  ): Promise<MachineCheckStatusResult> {
    const device = await this.database.device.findFirst({
      where: {
        id: deviceId,
        userId,
      },
      select: { id: true },
    });

    if (!device) {
      throw new NotFoundException({
        code: 'DEVICE_NOT_FOUND',
        message: 'Không tìm thấy thiết bị thuộc tài khoản hiện tại.',
      });
    }

    const run = await this.database.syncRun.findFirst({
      where: {
        id: runId,
        deviceId,
        trigger: ASYNC_TRIGGER,
      },
    });

    if (!run) {
      throw new NotFoundException({
        code: 'MACHINE_CHECK_RUN_NOT_FOUND',
        message: 'Không tìm thấy lần kiểm tra máy này.',
      });
    }

    const metadata = this.asRecord(run.metadata);
    const topPredictions =
      run.status === SyncRunStatus.RUNNING
        ? []
        : await this.loadTopPredictions(deviceId);

    return {
      runId: run.id,
      deviceId,
      status: run.status,
      phase: this.stringValue(metadata.phase, run.status),
      message: this.stringValue(
        metadata.message,
        run.status === SyncRunStatus.RUNNING
          ? 'CYRP đang xử lý dữ liệu bảo mật.'
          : 'Đã hoàn tất lần kiểm tra máy.',
      ),
      cached: metadata.cached === true,
      startedAt: run.startedAt.toISOString(),
      completedAt: run.completedAt?.toISOString() ?? null,
      durationMs: run.completedAt
        ? run.completedAt.getTime() - run.startedAt.getTime()
        : null,
      activeVulnerabilities: this.nullableNumber(
        metadata.activeVulnerabilities,
      ),
      predictions: this.nullableNumber(metadata.predictions),
      predictionsSkippedUnchanged: this.nullableNumber(
        metadata.predictionsSkippedUnchanged,
      ),
      topPredictions,
      error: run.errorSummary,
    };
  }

  private async executeRun(
    userId: string,
    deviceId: string,
    wazuhAgentId: string,
    runId: string,
  ): Promise<void> {
    try {
      await this.updateRunProgress(runId, 'CHECKING_CACHE', 'Đang kiểm tra độ mới của dữ liệu hiện có.');

      const cached = await this.canUseFreshData(deviceId);
      let syncStatus: 'COMPLETED' | 'PARTIAL' | 'FAILED' = 'COMPLETED';
      let predictions = 0;
      let predictionsSkippedUnchanged = 0;
      let syncSummary: Record<string, unknown> = {};

      if (cached) {
        await this.updateRunProgress(
          runId,
          'USING_CACHE',
          'Dữ liệu Wazuh còn mới; đang dùng kết quả đã đồng bộ gần nhất.',
          true,
        );
      } else {
        await this.updateRunProgress(
          runId,
          'SYNCING_WAZUH',
          'Đang đồng bộ Wazuh, lỗ hổng, endpoint context và dự đoán AI.',
        );

        const syncResult = await this.securityDataSync.syncForUser(
          userId,
          deviceId,
        );
        syncStatus = syncResult.status;
        if (
          syncResult.status === 'FAILED' ||
          syncResult.components.vulnerabilities.status === 'FAILED'
        ) {
          throw new Error(
            syncResult.components.vulnerabilities.message ||
              'Wazuh vulnerability synchronization failed.',
          );
        }
        const vulnerabilityData = this.asRecord(
          syncResult.components.vulnerabilities.data,
        );
        predictions = this.numberValue(vulnerabilityData.predictions);
        predictionsSkippedUnchanged = this.numberValue(
          vulnerabilityData.predictionsSkippedUnchanged,
        );
        syncSummary = {
          alerts: syncResult.components.alerts.status,
          vulnerabilities: syncResult.components.vulnerabilities.status,
          endpointContext: syncResult.components.endpointContext.status,
        };
      }

      await this.updateRunProgress(
        runId,
        'LOADING_RESULTS',
        'Đang tổng hợp kết quả mới nhất cho giao diện.',
        cached,
      );

      const activeVulnerabilities =
        await this.database.detectedVulnerability.count({
          where: {
            deviceId,
            status: VulnerabilityLifecycleStatus.ACTIVE,
            sourceIndex: {
              not: 'ai-pipeline-data-user',
            },
          },
        });

      const finalStatus =
        syncStatus === 'PARTIAL'
          ? SyncRunStatus.PARTIAL
          : SyncRunStatus.COMPLETED;
      const completedAt = new Date();

      await this.database.syncRun.update({
        where: { id: runId },
        data: {
          status: finalStatus,
          completedAt,
          recordsRead: activeVulnerabilities,
          recordsWritten: predictions,
          recordsUpdated: predictionsSkippedUnchanged,
          errorSummary: null,
          checkpointAfter: {
            cached,
            activeVulnerabilities,
            predictions,
            predictionsSkippedUnchanged,
          },
          metadata: {
            phase: finalStatus,
            message: cached
              ? 'Đã mở kết quả gần nhất vì dữ liệu Wazuh vẫn còn mới.'
              : finalStatus === SyncRunStatus.COMPLETED
                ? 'Đã đồng bộ Wazuh và cập nhật kết quả AI.'
                : 'Đã hoàn tất với một số thành phần ở trạng thái chưa đầy đủ.',
            cached,
            userId,
            deviceId,
            wazuhAgentId,
            activeVulnerabilities,
            predictions,
            predictionsSkippedUnchanged,
            syncSummary,
          } as Prisma.InputJsonValue,
        },
      });

      this.logger.log(
        `Async machine check completed run=${runId} device=${deviceId} agent=${wazuhAgentId} cached=${cached} active=${activeVulnerabilities} predictions=${predictions} skipped=${predictionsSkippedUnchanged}`,
      );
    } catch (error: unknown) {
      const message = this.errorMessage(error);
      await this.database.syncRun.update({
        where: { id: runId },
        data: {
          status: SyncRunStatus.FAILED,
          completedAt: new Date(),
          errorSummary: message,
          metadata: {
            phase: 'FAILED',
            message: 'Không thể hoàn tất lần kiểm tra máy.',
            cached: false,
            error: message,
          },
        },
      });

      this.logger.error(
        `Async machine check failed run=${runId} device=${deviceId}: ${message}`,
      );
    }
  }

  private async canUseFreshData(deviceId: string): Promise<boolean> {
    if (this.freshnessMs <= 0) {
      this.logger.debug(
        `Machine check cache disabled for device=${deviceId}`,
      );
      return false;
    }

    const cutoff = new Date(Date.now() - this.freshnessMs);
    const expectedModelVersion = this.aiModelRuntime.isEnabled()
      ? this.aiModelRuntime.configuredModelVersion()
      : 'CYRP_NO_AI_MODEL_RESULT_V1';

    const [recentRuns, stalePredictions] = await Promise.all([
      this.database.syncRun.findMany({
        where: {
          deviceId,
          trigger: ASYNC_TRIGGER,
          status: SyncRunStatus.COMPLETED,
          completedAt: { gte: cutoff },
        },
        orderBy: { completedAt: 'desc' },
        take: 20,
        select: {
          id: true,
          completedAt: true,
          metadata: true,
        },
      }),
      this.database.detectedVulnerability.count({
        where: {
          deviceId,
          status: { not: VulnerabilityLifecycleStatus.RESOLVED },
          sourceIndex: { not: 'ai-pipeline-data-user' },
          OR: [
            { aiPrediction: { is: null } },
            {
              aiPrediction: {
                is: {
                  modelVersion: { not: expectedModelVersion },
                },
              },
            },
          ],
        },
      }),
    ]);

    // A cached run must not extend freshness indefinitely. Only a recent
    // non-cached COMPLETED run can act as the freshness anchor.
    const freshFullRun = recentRuns.find((run) => {
      const metadata = this.asRecord(run.metadata);
      return metadata.cached !== true;
    });
    const cached = Boolean(freshFullRun && stalePredictions === 0);

    this.logger.log(
      `Machine check cache decision device=${deviceId} cached=${cached} ` +
        `freshFullRun=${freshFullRun?.id ?? 'none'} ` +
        `completedAt=${freshFullRun?.completedAt?.toISOString() ?? 'none'} ` +
        `stalePredictions=${stalePredictions} freshnessMs=${this.freshnessMs}`,
    );

    return cached;
  }

  private async updateRunProgress(
    runId: string,
    phase: string,
    message: string,
    cached = false,
  ): Promise<void> {
    await this.database.syncRun.update({
      where: { id: runId },
      data: {
        metadata: {
          phase,
          message,
          cached,
        },
      },
    });
  }

  private async loadTopPredictions(
    deviceId: string,
  ): Promise<TopPredictionItem[]> {
    const items = await this.database.detectedVulnerability.findMany({
      where: {
        deviceId,
        status: VulnerabilityLifecycleStatus.ACTIVE,
        sourceIndex: {
          not: 'ai-pipeline-data-user',
        },
        aiPrediction: { isNot: null },
      },
      take: 500,
      include: {
        aiPrediction: true,
      },
      orderBy: {
        lastSeenAt: 'desc',
      },
    });

    return items
      .sort((left, right) => {
        const leftScore =
          left.aiPrediction?.predictedPercentile ??
          (left.aiPrediction?.attackProbability ?? 0) * 100;
        const rightScore =
          right.aiPrediction?.predictedPercentile ??
          (right.aiPrediction?.attackProbability ?? 0) * 100;
        return rightScore - leftScore;
      })
      .slice(0, 20)
      .map((item) => ({
        cveId: item.cveId,
        riskLevel: item.aiPrediction?.riskLevel ?? null,
        attackProbability: item.aiPrediction?.attackProbability ?? null,
        predictedPercentile: item.aiPrediction?.predictedPercentile ?? null,
        predictedAt: item.aiPrediction?.predictedAt?.toISOString() ?? null,
      }));
  }

  private asRecord(value: unknown): Record<string, unknown> {
    return typeof value === 'object' && value !== null && !Array.isArray(value)
      ? (value as Record<string, unknown>)
      : {};
  }

  private numberValue(value: unknown): number {
    return typeof value === 'number' && Number.isFinite(value) ? value : 0;
  }

  private nullableNumber(value: unknown): number | null {
    return typeof value === 'number' && Number.isFinite(value) ? value : null;
  }

  private stringValue(value: unknown, fallback: string): string {
    return typeof value === 'string' && value.trim() ? value : fallback;
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
        : typeof value === 'string'
          ? Number.parseInt(value, 10)
          : Number.NaN;

    if (!Number.isFinite(parsed)) {
      return fallback;
    }

    return Math.min(Math.max(parsed, min), max);
  }

  private errorMessage(error: unknown): string {
    return error instanceof Error ? error.message : String(error);
  }
}
