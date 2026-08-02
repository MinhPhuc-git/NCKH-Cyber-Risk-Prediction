import {
  Injectable,
  Logger,
  NotFoundException,
  OnApplicationBootstrap,
  OnApplicationShutdown,
  ServiceUnavailableException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
  DeviceStatus,
  Prisma,
  SyncRunStatus,
  SyncSourceType,
  VulnerabilityLifecycleStatus,
} from '@prisma/client';

import { DatabaseService } from '../../database/database.service';
import { SecuritySnapshotsService } from '../security-snapshots/security-snapshots.service';
import { WazuhService } from '../wazuh/wazuh.service';
import type {
  WazuhInventoryCategory,
  WazuhInventoryStateSource,
  WazuhStateCollection,
  WazuhStateDocument,
} from '../wazuh/wazuh.types';
import { AiModelRuntimeService, type AiModelRuntimeInput, type AiModelRuntimeResult } from './ai-model-runtime.service';
import { CtiCvssEnrichmentService } from './cti-cvss-enrichment.service';
import { DeviceSyncLockService } from './device-sync-lock.service';
import {
  countListeningPorts,
  normalizeContextMetadata,
  normalizeVulnerabilityDocument,
  referenceHash,
  safeDate,
  stableHash,
} from './wazuh-state-normalizer';

interface SyncTarget {
  deviceId: string;
  userId: string;
  hostname: string;
  wazuhAgentId: string;
  wazuhAgentName: string;
}

export interface ComponentResult {
  status: 'COMPLETED' | 'PARTIAL' | 'FAILED';
  message: string;
  data?: unknown;
}

export interface FullSyncResult {
  deviceId: string;
  hostname: string;
  wazuhAgentId: string;
  status: 'COMPLETED' | 'PARTIAL' | 'FAILED';
  startedAt: Date;
  completedAt: Date;
  components: {
    alerts: ComponentResult;
    vulnerabilities: ComponentResult;
    endpointContext: ComponentResult;
  };
  timingsMs: {
    total: number;
    alerts: number;
    vulnerabilities: number;
    endpointContext: number;
  };
}

interface CvePredictionFeatures {
  detectionId: string;
  deviceId: string;
  cveId: string;
  packageName: string | null;
  packageVersion: string | null;
  severity: string | null;
  baseScore: number | null;
  attackVector: string | null;
  attackComplexity: string | null;
  privilegesRequired: string | null;
  userInteraction: string | null;
  scope: string | null;
  confidentialityImpact: string | null;
  integrityImpact: string | null;
  availabilityImpact: string | null;
  epssScore: number | null;
  epssPercentile: number | null;
  isKnownExploited: boolean;
  cweIdGrouped: string | null;
  cweIsGeneric: boolean;
  isCvss3OrHigher: boolean;
  alertCount24h: number;
  maxRuleLevel24h: number | null;
  devicePackageCount: number;
  modelInputVersion: string;
}

interface PersistedPrediction {
  artifactPath: string | null;
  modelVersion: string;
  attackProbability: number;
  predictedPercentile: number | null;
  riskLevel: string;
  explanation: Record<string, unknown>;
}

const INVENTORY_CATEGORIES: WazuhInventoryCategory[] = [
  'hardware',
  'hotfixes',
  'packages',
  'ports',
  'processes',
  'services',
  'system',
];

const FEATURE_MODEL_INPUT_VERSION = 'CYRP_FEATURES_V1';
const BASELINE_MODEL_VERSION = 'CYRP_NO_AI_MODEL_RESULT_V1';

@Injectable()
export class SecurityDataSyncService
  implements OnApplicationBootstrap, OnApplicationShutdown
{
  private readonly logger = new Logger(SecurityDataSyncService.name);
  private readonly scheduleEnabled: boolean;
  private readonly intervalMs: number;
  private readonly maxConcurrency: number;
  private readonly inventoryCategoryConcurrency: number;
  private readonly staleRunMs: number;
  private timer: ReturnType<typeof setInterval> | null = null;
  private initialTimer: ReturnType<typeof setTimeout> | null = null;
  private scheduledRunActive = false;

  constructor(
    private readonly database: DatabaseService,
    private readonly wazuh: WazuhService,
    private readonly snapshots: SecuritySnapshotsService,
    private readonly syncLock: DeviceSyncLockService,
    private readonly aiModelRuntime: AiModelRuntimeService,
    private readonly ctiCvssEnrichment: CtiCvssEnrichmentService,
    config: ConfigService,
  ) {
    this.scheduleEnabled = this.booleanValue(
      config.get<unknown>('WAZUH_DATA_SYNC_ENABLED'),
      false,
    );
    this.intervalMs =
      this.integerValue(
        config.get<unknown>('WAZUH_DATA_SYNC_INTERVAL_SECONDS'),
        900,
        300,
        86_400,
      ) * 1000;
    this.maxConcurrency = this.integerValue(
      config.get<unknown>('WAZUH_DATA_SYNC_MAX_CONCURRENCY'),
      1,
      1,
      8,
    );
    this.inventoryCategoryConcurrency = this.integerValue(
      config.get<unknown>('WAZUH_INVENTORY_CATEGORY_CONCURRENCY'),
      2,
      1,
      4,
    );
    this.staleRunMs =
      this.integerValue(
        config.get<unknown>('WAZUH_DATA_SYNC_STALE_RUN_MINUTES'),
        30,
        5,
        1_440,
      ) * 60_000;
  }

  async onApplicationBootstrap(): Promise<void> {
    await this.recoverStaleRuns();

    if (!this.scheduleEnabled || !this.wazuh.isIntegrationEnabled()) {
      this.logger.log('Phase 2 Wazuh state synchronization is disabled');
      return;
    }

    this.logger.log(
      `Phase 2 Wazuh state synchronization enabled: interval=${this.intervalMs / 1000}s, concurrency=${this.maxConcurrency}`,
    );

    this.initialTimer = setTimeout(() => {
      void this.runScheduledSync();
    }, 20_000);

    this.timer = setInterval(() => {
      void this.runScheduledSync();
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

  async syncForUser(userId: string, deviceId: string): Promise<FullSyncResult> {
    this.assertIntegrationEnabled();
    return this.syncLock.runWithLock(deviceId, async () => {
      const target = await this.resolveTarget(deviceId, userId);
      return this.performFullSync(target, 'USER_MANUAL');
    });
  }

  async syncForAdmin(deviceId: string): Promise<FullSyncResult> {
    this.assertIntegrationEnabled();
    return this.syncLock.runWithLock(deviceId, async () => {
      const target = await this.resolveTarget(deviceId);
      return this.performFullSync(target, 'ADMIN_MANUAL');
    });
  }

  getSchedulerStatus() {
    return {
      integrationEnabled: this.wazuh.isIntegrationEnabled(),
      configured: this.scheduleEnabled,
      enabled: this.scheduleEnabled && this.wazuh.isIntegrationEnabled(),
      running: this.scheduledRunActive,
      intervalSeconds: Math.trunc(this.intervalMs / 1000),
      maxConcurrency: this.maxConcurrency,
      inventoryCategoryConcurrency: this.inventoryCategoryConcurrency,
      staleRunMinutes: Math.trunc(this.staleRunMs / 60_000),
      syncLock: this.syncLock.getStatus(),
    };
  }

  async syncAllForAdmin(): Promise<{
    requested: number;
    completed: number;
    partial: number;
    failed: number;
    results: FullSyncResult[];
  }> {
    this.assertIntegrationEnabled();

    const devices = await this.database.device.findMany({
      where: { wazuhBinding: { isNot: null } },
      select: { id: true },
      orderBy: { createdAt: 'asc' },
    });
    const results: FullSyncResult[] = [];

    await this.runWithConcurrency(
      devices,
      this.maxConcurrency,
      async (device) => {
        try {
          results.push(
            await this.syncLock.runWithLock(device.id, async () => {
              const target = await this.resolveTarget(device.id);
              return this.performFullSync(target, 'ADMIN_ALL');
            }),
          );
        } catch (error: unknown) {
          results.push({
            deviceId: device.id,
            hostname: 'Không xác định',
            wazuhAgentId: 'N/A',
            status: 'FAILED',
            startedAt: new Date(),
            completedAt: new Date(),
            components: {
              alerts: this.failedComponent(error),
              vulnerabilities: this.failedComponent(error),
              endpointContext: this.failedComponent(error),
            },
            timingsMs: {
              total: 0,
              alerts: 0,
              vulnerabilities: 0,
              endpointContext: 0,
            },
          });
        }
      },
    );

    return {
      requested: devices.length,
      completed: results.filter((item) => item.status === 'COMPLETED').length,
      partial: results.filter((item) => item.status === 'PARTIAL').length,
      failed: results.filter((item) => item.status === 'FAILED').length,
      results,
    };
  }

  async syncVulnerabilitiesForAdmin(deviceId: string) {
    this.assertIntegrationEnabled();
    return this.syncLock.runWithLock(deviceId, async () => {
      const target = await this.resolveTarget(deviceId);
      return this.syncVulnerabilities(target, 'ADMIN_MANUAL');
    });
  }

  async syncContextForAdmin(deviceId: string) {
    this.assertIntegrationEnabled();
    return this.syncLock.runWithLock(deviceId, async () => {
      const target = await this.resolveTarget(deviceId);
      return this.syncEndpointContext(target, 'ADMIN_MANUAL');
    });
  }

  private async performFullSync(
    target: SyncTarget,
    trigger: string,
  ): Promise<FullSyncResult> {
    const startedAt = new Date();
    const totalStarted = Date.now();
    this.logger.log(
      `Full machine sync started device=${target.deviceId} agent=${target.wazuhAgentId} trigger=${trigger}`,
    );

    // Alert totals and endpoint inventory are model inputs. They must finish
    // before vulnerability feature vectors are built; running all three tasks
    // concurrently can produce predictions from stale snapshot/package data.
    const [snapshotTimed, contextTimed] = await Promise.all([
      this.timedSettled(
        this.snapshots.syncDeviceAsAdmin(target.deviceId),
      ),
      this.timedSettled(
        this.syncEndpointContext(target, trigger),
      ),
    ]);
    const vulnerabilitiesTimed = await this.timedSettled(
      this.syncVulnerabilities(target, trigger),
    );

    const components = {
      alerts: this.componentResult(
        snapshotTimed.result,
        'Đã đồng bộ cảnh báo Wazuh và trạng thái Agent',
      ),
      vulnerabilities: this.componentResult(
        vulnerabilitiesTimed.result,
        'Đã đồng bộ trạng thái lỗ hổng',
      ),
      endpointContext: this.componentResult(
        contextTimed.result,
        'Đã lưu snapshot ngữ cảnh endpoint',
      ),
    };
    const statuses = Object.values(components).map((item) => item.status);
    const status = statuses.every((item) => item === 'COMPLETED')
      ? 'COMPLETED'
      : statuses.every((item) => item === 'FAILED')
        ? 'FAILED'
        : 'PARTIAL';
    const timingsMs = {
      total: Date.now() - totalStarted,
      alerts: snapshotTimed.durationMs,
      vulnerabilities: vulnerabilitiesTimed.durationMs,
      endpointContext: contextTimed.durationMs,
    };

    this.logger.log(
      `Full machine sync timing device=${target.deviceId} agent=${target.wazuhAgentId} status=${status} totalMs=${timingsMs.total} alertsMs=${timingsMs.alerts} endpointContextMs=${timingsMs.endpointContext} vulnerabilitiesMs=${timingsMs.vulnerabilities}`,
    );

    return {
      deviceId: target.deviceId,
      hostname: target.hostname,
      wazuhAgentId: target.wazuhAgentId,
      status,
      startedAt,
      completedAt: new Date(),
      components,
      timingsMs,
    };
  }

  private async syncVulnerabilities(target: SyncTarget, trigger: string) {
    const totalStarted = Date.now();
    const sourceId = await this.findSourceId('WAZUH_VULNERABILITY_STATE');
    const run = await this.database.syncRun.create({
      data: {
        sourceId,
        deviceId: target.deviceId,
        sourceType: SyncSourceType.WAZUH_VULNERABILITIES,
        trigger,
        sourceManifest: {
          agentId: target.wazuhAgentId,
          indexPattern: 'wazuh-states-vulnerabilities-*',
        },
      },
    });

    try {
      const fetchStarted = Date.now();
      const collection = await this.wazuh.getVulnerabilityStates(
        target.wazuhAgentId,
      );
      const fetchMs = Date.now() - fetchStarted;
      const persistenceStarted = Date.now();
      const now = new Date();
      const normalized = collection.documents
        .map((document) => normalizeVulnerabilityDocument(document))
        .filter((item) => item !== null);
      const rejected = collection.documents.length - normalized.length;
      let createdCount = 0;
      let updatedCount = 0;

      for (const item of normalized) {
        const sourceDocumentHash = stableHash(item.rawPayload);

        await this.database.cve.upsert({
          where: { cveId: item.cveId },
          create: {
            cveId: item.cveId,
            description: item.description,
            publishedAt: item.publishedAt,
            modifiedAt: item.sourceUpdatedAt,
            source: 'WAZUH',
            sourceVersion: item.schemaVersion,
            sourceDocumentHash,
          },
          update: {
            ...(item.description ? { description: item.description } : {}),
            ...(item.publishedAt ? { publishedAt: item.publishedAt } : {}),
            ...(item.sourceUpdatedAt ? { modifiedAt: item.sourceUpdatedAt } : {}),
            ingestedAt: now,
          },
        });

        if (item.cvssBaseScore !== null || item.vectorString) {
          await this.database.cveCvssMetric.upsert({
            where: {
              cveId_source_metricType_cvssVersion: {
                cveId: item.cveId,
                source: 'WAZUH',
                metricType: 'WAZUH_STATE',
                cvssVersion: item.cvssVersion,
              },
            },
            create: {
              cveId: item.cveId,
              source: 'WAZUH',
              metricType: 'WAZUH_STATE',
              cvssVersion: item.cvssVersion,
              vectorString: item.vectorString,
              baseScore: item.cvssBaseScore,
              baseSeverity: item.severity,
              attackVector: item.attackVector,
              attackComplexity: item.attackComplexity,
              privilegesRequired: item.privilegesRequired,
              userInteraction: item.userInteraction,
              scope: item.scope,
              confidentialityImpact: item.confidentialityImpact,
              integrityImpact: item.integrityImpact,
              availabilityImpact: item.availabilityImpact,
              publishedAt: item.publishedAt,
            },
            update: {
              vectorString: item.vectorString,
              baseScore: item.cvssBaseScore,
              baseSeverity: item.severity,
              attackVector: item.attackVector,
              attackComplexity: item.attackComplexity,
              privilegesRequired: item.privilegesRequired,
              userInteraction: item.userInteraction,
              scope: item.scope,
              confidentialityImpact: item.confidentialityImpact,
              integrityImpact: item.integrityImpact,
              availabilityImpact: item.availabilityImpact,
              publishedAt: item.publishedAt,
              ingestedAt: now,
            },
          });
        }

        for (const url of item.references) {
          const urlHash = referenceHash(url);
          await this.database.cveReference.upsert({
            where: {
              cveId_urlHash: {
                cveId: item.cveId,
                urlHash,
              },
            },
            create: {
              cveId: item.cveId,
              url,
              urlHash,
              source: 'WAZUH',
            },
            update: {
              url,
              source: 'WAZUH',
            },
          });
        }

        const existing = await this.database.detectedVulnerability.findUnique({
          where: {
            sourceIndex_sourceDocumentId: {
              sourceIndex: item.sourceIndex,
              sourceDocumentId: item.sourceDocumentId,
            },
          },
          select: { id: true },
        });

        await this.database.detectedVulnerability.upsert({
          where: {
            sourceIndex_sourceDocumentId: {
              sourceIndex: item.sourceIndex,
              sourceDocumentId: item.sourceDocumentId,
            },
          },
          create: {
            deviceId: target.deviceId,
            cveId: item.cveId,
            syncRunId: run.id,
            wazuhAgentId: target.wazuhAgentId,
            packageName: item.packageName,
            packageVersion: item.packageVersion,
            packageArchitecture: item.packageArchitecture,
            packageVendor: item.packageVendor,
            packageType: item.packageType,
            status: item.status,
            sourceStatus: item.sourceStatus,
            severity: item.severity,
            cvssBaseScore: item.cvssBaseScore,
            detectedAt: item.detectedAt,
            publishedAt: item.publishedAt,
            lastSeenAt: now,
            resolvedAt:
              item.status === VulnerabilityLifecycleStatus.RESOLVED
                ? now
                : null,
            sourceIndex: item.sourceIndex,
            sourceDocumentId: item.sourceDocumentId,
            sourceUpdatedAt: item.sourceUpdatedAt,
            rawPayload: this.sanitizeJson(item.rawPayload) as Prisma.InputJsonValue,
          },
          update: {
            deviceId: target.deviceId,
            cveId: item.cveId,
            syncRunId: run.id,
            wazuhAgentId: target.wazuhAgentId,
            packageName: item.packageName,
            packageVersion: item.packageVersion,
            packageArchitecture: item.packageArchitecture,
            packageVendor: item.packageVendor,
            packageType: item.packageType,
            status: item.status,
            sourceStatus: item.sourceStatus,
            severity: item.severity,
            cvssBaseScore: item.cvssBaseScore,
            detectedAt: item.detectedAt,
            publishedAt: item.publishedAt,
            lastSeenAt: now,
            resolvedAt:
              item.status === VulnerabilityLifecycleStatus.RESOLVED
                ? now
                : null,
            sourceUpdatedAt: item.sourceUpdatedAt,
            rawPayload: this.sanitizeJson(item.rawPayload) as Prisma.InputJsonValue,
          },
        });

        if (existing) {
          updatedCount += 1;
        } else {
          createdCount += 1;
        }
      }

      const hasShardFailures = (collection.shards.failed ?? 0) > 0;
      let resolvedCount = 0;
      if (
        collection.indexAvailable &&
        !collection.truncated &&
        !hasShardFailures
      ) {
        const resolved = await this.database.detectedVulnerability.updateMany({
          where: {
            deviceId: target.deviceId,
            status: { not: VulnerabilityLifecycleStatus.RESOLVED },
            lastSeenAt: { lt: run.startedAt },
            sourceIndex: { startsWith: 'wazuh-states-vulnerabilities-' },
          },
          data: {
            status: VulnerabilityLifecycleStatus.RESOLVED,
            sourceStatus: 'not_present_in_latest_complete_snapshot',
            resolvedAt: now,
          },
        });
        resolvedCount = resolved.count;
      }

      const persistenceMs = Date.now() - persistenceStarted;
      const enrichment = await this.ctiCvssEnrichment.enrich(
        normalized.map((item) => item.cveId),
      );
      const predictionStarted = Date.now();
      const predictionStats = await this.refreshFeatureVectorsAndPredictions(
        target,
        now,
      );
      const predictionMs = Date.now() - predictionStarted;
      const totalMs = Date.now() - totalStarted;

      const partialReasons = [
        ...(!collection.indexAvailable
          ? ['Không tìm thấy Wazuh vulnerability state index']
          : []),
        ...(collection.truncated
          ? [
              `Kết quả bị giới hạn ở ${collection.documents.length}/${collection.total} bản ghi`,
            ]
          : []),
        ...(hasShardFailures
          ? [`Wazuh Indexer có ${collection.shards.failed} shard query thất bại`]
          : []),
        ...(rejected > 0
          ? [`${rejected} bản ghi không chuẩn hóa được`]
          : []),
        ...(enrichment.status === 'FAILED'
          ? [`CTI CVSS enrichment thất bại: ${enrichment.message}`]
          : []),
      ];
      const status =
        partialReasons.length > 0
          ? SyncRunStatus.PARTIAL
          : SyncRunStatus.COMPLETED;

      const completedAt = new Date();
      await this.database.syncRun.update({
        where: { id: run.id },
        data: {
          status,
          completedAt,
          sourceVersion:
            normalized.find((item) => item.schemaVersion)?.schemaVersion ?? null,
          recordsRead: collection.documents.length,
          recordsWritten: createdCount,
          recordsUpdated: updatedCount,
          recordsResolved: resolvedCount,
          recordsRejected: rejected,
          errorSummary:
            partialReasons.length > 0 ? partialReasons.join('; ') : null,
          checkpointAfter: {
            total: collection.total,
            fetched: collection.documents.length,
            created: createdCount,
            updated: updatedCount,
            resolved: resolvedCount,
            rejected,
            featureVectors: predictionStats.featureVectors,
            predictions: predictionStats.predictions,
            predictionHistory: predictionStats.historyRows,
            predictionsSkippedUnchanged: predictionStats.skippedPredictions,
            cvssEnrichment: enrichment as unknown as Prisma.InputJsonValue,
            timingsMs: {
              total: totalMs,
              indexFetch: fetchMs,
              persistence: persistenceMs,
              cvssEnrichment: enrichment.durationMs,
              predictions: predictionMs,
            },
            truncated: collection.truncated,
            indexAvailable: collection.indexAvailable,
            shards: collection.shards,
          },
        },
      });

      if (collection.indexAvailable) {
        await this.markSourceSuccess(sourceId, completedAt);
      } else {
        await this.markSourceFailure(
          sourceId,
          new Error('Wazuh vulnerability state index is unavailable'),
        );
      }

      this.logger.log(
        `Vulnerability sync timing device=${target.deviceId} agent=${target.wazuhAgentId} totalMs=${totalMs} indexFetchMs=${fetchMs} persistenceMs=${persistenceMs} cvssEnrichmentMs=${enrichment.durationMs} predictionsMs=${predictionMs} enriched=${enrichment.upserted} predictions=${predictionStats.predictions} skipped=${predictionStats.skippedPredictions}`,
      );

      return {
        syncRunId: run.id,
        status,
        total: collection.total,
        fetched: collection.documents.length,
        created: createdCount,
        updated: updatedCount,
        rejected,
        resolved: resolvedCount,
        featureVectors: predictionStats.featureVectors,
        predictions: predictionStats.predictions,
        predictionHistory: predictionStats.historyRows,
        predictionsSkippedUnchanged: predictionStats.skippedPredictions,
        cvssEnrichment: enrichment,
        timingsMs: {
          total: totalMs,
          indexFetch: fetchMs,
          persistence: persistenceMs,
          cvssEnrichment: enrichment.durationMs,
          predictions: predictionMs,
        },
        truncated: collection.truncated,
        indexAvailable: collection.indexAvailable,
        shards: collection.shards,
      };
    } catch (error: unknown) {
      await this.failRun(run.id, error);
      await this.markSourceFailure(sourceId, error);
      throw error;
    }
  }

  private async syncEndpointContext(target: SyncTarget, trigger: string) {
    const totalStarted = Date.now();
    const sourceId = await this.findSourceId('WAZUH_ENDPOINT_CONTEXT');
    const run = await this.database.syncRun.create({
      data: {
        sourceId,
        deviceId: target.deviceId,
        sourceType: SyncSourceType.WAZUH_ENDPOINT_CONTEXT,
        trigger,
        sourceManifest: {
          agentId: target.wazuhAgentId,
          categories: INVENTORY_CATEGORIES,
        },
      },
    });

    try {
      const agentStarted = Date.now();
      const agent = await this.wazuh.getAgent(target.wazuhAgentId);
      const agentMs = Date.now() - agentStarted;
      const collections = {} as Record<
        WazuhInventoryCategory,
        WazuhStateCollection<WazuhInventoryStateSource>
      >;
      const errors: Partial<Record<WazuhInventoryCategory, string>> = {};
      const categoryTimingsMs: Partial<Record<WazuhInventoryCategory, number>> = {};
      const inventoryStarted = Date.now();

      await this.runWithConcurrency(
        INVENTORY_CATEGORIES,
        this.inventoryCategoryConcurrency,
        async (category) => {
          const categoryStarted = Date.now();
          try {
            collections[category] = await this.wazuh.getInventoryState(
              target.wazuhAgentId,
              category,
            );

            if (!collections[category].indexAvailable) {
              errors[category] =
                `Không tìm thấy state index cho category ${category}`;
            } else if ((collections[category].shards.failed ?? 0) > 0) {
              errors[category] =
                `${collections[category].shards.failed} shard query thất bại cho category ${category}`;
            }
          } catch (error: unknown) {
            errors[category] = this.errorMessage(error);
            collections[category] = {
              total: 0,
              truncated: false,
              indexAvailable: false,
              shards: {
                total: null,
                successful: null,
                failed: null,
              },
              documents: [],
            };
          } finally {
            categoryTimingsMs[category] = Date.now() - categoryStarted;
          }
        },
      );
      const inventoryMs = Date.now() - inventoryStarted;

      const values = Object.fromEntries(
        INVENTORY_CATEGORIES.map((category) => [
          category,
          collections[category].documents.map((document) =>
            this.sanitizeJson(document.source),
          ),
        ]),
      ) as Record<WazuhInventoryCategory, WazuhInventoryStateSource[]>;
      const counts = Object.fromEntries(
        INVENTORY_CATEGORIES.map((category) => [
          category,
          collections[category].total,
        ]),
      ) as Record<WazuhInventoryCategory, number>;
      const fetchedCounts = Object.fromEntries(
        INVENTORY_CATEGORIES.map((category) => [
          category,
          collections[category].documents.length,
        ]),
      ) as Record<WazuhInventoryCategory, number>;
      const truncation = Object.fromEntries(
        INVENTORY_CATEGORIES.map((category) => [
          category,
          collections[category].truncated,
        ]),
      ) as Record<WazuhInventoryCategory, boolean>;

      const metadata = this.sanitizeJson(
        normalizeContextMetadata(
          collections.system.documents,
          agent,
        ),
      );
      const asOfTime = new Date();
      const contextHash = stableHash({
        agentId: target.wazuhAgentId,
        metadata,
        values,
      });
      const listeningPortCount = countListeningPorts(values.ports);
      const availableCategories = INVENTORY_CATEGORIES.filter(
        (category) => collections[category].indexAvailable,
      );
      const partialReasons = [
        ...Object.entries(errors).map(
          ([category, message]) => `${category}: ${message}`,
        ),
        ...INVENTORY_CATEGORIES.filter(
          (category) => truncation[category],
        ).map(
          (category) =>
            `${category}: dữ liệu bị giới hạn ở ${fetchedCounts[category]}/${counts[category]} bản ghi`,
        ),
      ];
      const status =
        partialReasons.length > 0
          ? SyncRunStatus.PARTIAL
          : SyncRunStatus.COMPLETED;
      const lastKeepAliveAt = safeDate(agent.lastKeepAlive);
      const completeness = {
        complete: status === SyncRunStatus.COMPLETED,
        contextHash,
        categories: Object.fromEntries(
          INVENTORY_CATEGORIES.map((category) => [
            category,
            {
              total: counts[category],
              fetched: fetchedCounts[category],
              truncated: truncation[category],
              indexAvailable: collections[category].indexAvailable,
              shards: collections[category].shards,
              error: errors[category] ?? null,
            },
          ]),
        ),
      };

      const persistenceStarted = Date.now();
      const snapshot = await this.database.endpointContextSnapshot.create({
        data: {
          deviceId: target.deviceId,
          syncRunId: run.id,
          wazuhAgentId: target.wazuhAgentId,
          observedAt: asOfTime,
          asOfTime,
          agentStatus: agent.status ?? null,
          agentIp: agent.ip ?? null,
          hostname: metadata.hostname,
          osName: metadata.osName,
          osVersion: metadata.osVersion,
          osFull: metadata.osFull,
          architecture: metadata.architecture,
          packageCount: counts.packages,
          hotfixCount: counts.hotfixes,
          portCount: counts.ports,
          listeningPortCount,
          processCount: counts.processes,
          serviceCount: counts.services,
          packages: values.packages as unknown as Prisma.InputJsonValue,
          hotfixes: values.hotfixes as unknown as Prisma.InputJsonValue,
          ports: values.ports as unknown as Prisma.InputJsonValue,
          processes: values.processes as unknown as Prisma.InputJsonValue,
          services: values.services as unknown as Prisma.InputJsonValue,
          ...(values.system[0]
            ? {
                systemInventory: values.system[0] as Prisma.InputJsonValue,
              }
            : {}),
          ...(values.hardware[0]
            ? { hardware: values.hardware[0] as Prisma.InputJsonValue }
            : {}),
          completeness: completeness as Prisma.InputJsonValue,
          sourceVersions: {
            agentVersion: agent.version ?? null,
            schemaVersion: metadata.schemaVersion,
          } as Prisma.InputJsonValue,
        },
      });

      const packageSync = await this.upsertDevicePackages(
        target,
        run.id,
        collections.packages.documents,
        asOfTime,
      );

      await this.database.$transaction([
        this.database.wazuhAgentBinding.update({
          where: { deviceId: target.deviceId },
          data: {
            wazuhAgentName: agent.name ?? target.wazuhAgentName,
            lastKnownStatus: agent.status ?? null,
            lastKeepAliveAt,
            lastSynchronizedAt: asOfTime,
            lastStatusCheckedAt: asOfTime,
            lastStatusError: null,
            consecutiveStatusFailures: 0,
          },
        }),
        this.database.device.update({
          where: { id: target.deviceId },
          data: {
            ...(metadata.hostname ? { hostname: metadata.hostname } : {}),
            ...(metadata.osFull || metadata.osName
              ? {
                  operatingSystem:
                    metadata.osFull ?? metadata.osName ?? 'Unknown',
                }
              : {}),
            ...(metadata.architecture
              ? { architecture: metadata.architecture }
              : {}),
            status:
              agent.status?.toLowerCase() === 'active'
                ? DeviceStatus.IDLE
                : DeviceStatus.OFFLINE,
            ...(lastKeepAliveAt ? { lastSeenAt: lastKeepAliveAt } : {}),
          },
        }),
        this.database.syncRun.update({
          where: { id: run.id },
          data: {
            status,
            completedAt: asOfTime,
            sourceVersion: metadata.schemaVersion,
            recordsRead: Object.values(fetchedCounts).reduce(
              (total, value) => total + value,
              0,
            ),
            recordsWritten: 1 + packageSync.created,
            recordsUpdated: packageSync.updated,
            recordsRejected: Object.keys(errors).length + packageSync.rejected,
            errorSummary:
              partialReasons.length > 0 ? partialReasons.join('; ') : null,
            checkpointAfter: {
              counts,
              fetchedCounts,
              truncation,
              indexAvailability: Object.fromEntries(
                INVENTORY_CATEGORIES.map((category) => [
                  category,
                  collections[category].indexAvailable,
                ]),
              ),
              shards: Object.fromEntries(
                INVENTORY_CATEGORIES.map((category) => [
                  category,
                  collections[category].shards,
                ]),
              ),
              errors,
              contextHash,
              packageSync,
              timingsMs: {
                agent: agentMs,
                inventory: inventoryMs,
                categories: categoryTimingsMs,
                categoryConcurrency: this.inventoryCategoryConcurrency,
              },
            },
          },
        }),
      ]);

      const persistenceMs = Date.now() - persistenceStarted;
      const totalMs = Date.now() - totalStarted;
      await this.database.syncRun.update({
        where: { id: run.id },
        data: {
          metadata: {
            timingsMs: {
              total: totalMs,
              agent: agentMs,
              inventory: inventoryMs,
              persistence: persistenceMs,
              categories: categoryTimingsMs,
              categoryConcurrency: this.inventoryCategoryConcurrency,
            },
          },
        },
      });

      this.logger.log(
        `Endpoint context timing device=${target.deviceId} agent=${target.wazuhAgentId} totalMs=${totalMs} agentMs=${agentMs} inventoryMs=${inventoryMs} persistenceMs=${persistenceMs} categoryConcurrency=${this.inventoryCategoryConcurrency} categories=${JSON.stringify(categoryTimingsMs)}`,
      );

      if (availableCategories.length > 0) {
        await this.markSourceSuccess(sourceId, asOfTime);
      } else {
        await this.markSourceFailure(
          sourceId,
          new Error('No Wazuh endpoint inventory state index is available'),
        );
      }

      return {
        syncRunId: run.id,
        snapshotId: snapshot.id,
        status,
        asOfTime,
        counts,
        fetchedCounts,
        listeningPortCount,
        truncation,
        availableCategories,
        errors,
        packageSync,
        timingsMs: {
          total: totalMs,
          agent: agentMs,
          inventory: inventoryMs,
          persistence: persistenceMs,
          categories: categoryTimingsMs,
          categoryConcurrency: this.inventoryCategoryConcurrency,
        },
      };
    } catch (error: unknown) {
      await this.failRun(run.id, error);
      await this.markSourceFailure(sourceId, error);
      throw error;
    }
  }


  private async upsertDevicePackages(
    target: SyncTarget,
    syncRunId: string,
    documents: Array<WazuhStateDocument<WazuhInventoryStateSource>>,
    scannedAt: Date,
  ): Promise<{
    read: number;
    created: number;
    updated: number;
    rejected: number;
  }> {
    let created = 0;
    let updated = 0;
    let rejected = 0;

    for (const document of documents) {
      const normalized = this.normalizePackageDocument(document.source);

      if (!normalized) {
        rejected += 1;
        continue;
      }

      const existing = await this.database.devicePackage.findUnique({
        where: {
          deviceId_packageKey: {
            deviceId: target.deviceId,
            packageKey: normalized.packageKey,
          },
        },
        select: { id: true },
      });

      await this.database.devicePackage.upsert({
        where: {
          deviceId_packageKey: {
            deviceId: target.deviceId,
            packageKey: normalized.packageKey,
          },
        },
        create: {
          deviceId: target.deviceId,
          syncRunId,
          wazuhAgentId: target.wazuhAgentId,
          packageKey: normalized.packageKey,
          name: normalized.name,
          version: normalized.version,
          vendor: normalized.vendor,
          architecture: normalized.architecture,
          packageType: normalized.packageType,
          description: normalized.description,
          sizeBytes: normalized.sizeBytes,
          sourceIndex: document.index,
          sourceDocumentId: document.id,
          firstSeenAt: scannedAt,
          lastSeenAt: scannedAt,
          lastScannedAt: scannedAt,
          rawPayload: this.sanitizeJson(document.source) as Prisma.InputJsonValue,
        },
        update: {
          syncRunId,
          wazuhAgentId: target.wazuhAgentId,
          name: normalized.name,
          version: normalized.version,
          vendor: normalized.vendor,
          architecture: normalized.architecture,
          packageType: normalized.packageType,
          description: normalized.description,
          sizeBytes: normalized.sizeBytes,
          sourceIndex: document.index,
          sourceDocumentId: document.id,
          lastSeenAt: scannedAt,
          lastScannedAt: scannedAt,
          rawPayload: this.sanitizeJson(document.source) as Prisma.InputJsonValue,
        },
      });

      if (existing) {
        updated += 1;
      } else {
        created += 1;
      }
    }

    return {
      read: documents.length,
      created,
      updated,
      rejected,
    };
  }

  private normalizePackageDocument(source: WazuhInventoryStateSource): {
    packageKey: string;
    name: string;
    version: string | null;
    vendor: string | null;
    architecture: string | null;
    packageType: string | null;
    description: string | null;
    sizeBytes: bigint | null;
  } | null {
    const name = this.firstString(source, [
      ['package', 'name'],
      ['name'],
      ['package_name'],
    ]);

    if (!name) {
      return null;
    }

    const version = this.firstString(source, [
      ['package', 'version'],
      ['version'],
      ['package_version'],
    ]);
    const vendor = this.firstString(source, [
      ['package', 'vendor'],
      ['vendor'],
    ]);
    const architecture = this.firstString(source, [
      ['package', 'architecture'],
      ['package', 'arch'],
      ['architecture'],
      ['arch'],
    ]);
    const packageType = this.firstString(source, [
      ['package', 'type'],
      ['type'],
    ]);
    const description = this.firstString(source, [
      ['package', 'description'],
      ['description'],
    ]);
    const size = this.firstNumber(source, [
      ['package', 'size'],
      ['size'],
    ]);
    const packageKey = stableHash({
      name: name.toLowerCase(),
      version,
      vendor,
      architecture,
      packageType,
    });

    return {
      packageKey,
      name,
      version,
      vendor,
      architecture,
      packageType,
      description,
      sizeBytes:
        size !== null && size >= 0
          ? BigInt(Math.trunc(size))
          : null,
    };
  }

  private async refreshFeatureVectorsAndPredictions(
    target: SyncTarget,
    predictedAt: Date,
  ): Promise<{
    featureVectors: number;
    predictions: number;
    historyRows: number;
    skippedPredictions: number;
  }> {
    const [detections, securitySnapshot, packageCount] = await Promise.all([
      this.database.detectedVulnerability.findMany({
        where: {
          deviceId: target.deviceId,
          status: { not: VulnerabilityLifecycleStatus.RESOLVED },
        },
        include: {
          featureVector: {
            select: {
              featureHash: true,
            },
          },
          aiPrediction: {
            select: {
              modelVersion: true,
              explanation: true,
            },
          },
          cve: {
            include: {
              cvssMetrics: { orderBy: { ingestedAt: 'desc' } },
              threatSignals: {
                take: 1,
                orderBy: { signalDate: 'desc' },
              },
              cveCwes: {
                take: 1,
                include: { cwe: true },
              },
            },
          },
        },
      }),
      this.database.deviceSecuritySnapshot.findUnique({
        where: { deviceId: target.deviceId },
        select: {
          alertCount: true,
          maxRuleLevel: true,
        },
      }),
      this.database.devicePackage.count({
        where: { deviceId: target.deviceId },
      }),
    ]);

    let featureVectors = 0;
    let predictions = 0;
    let historyRows = 0;
    let skippedPredictions = 0;
    const expectedModelVersion = this.aiModelRuntime.isEnabled()
      ? this.aiModelRuntime.configuredModelVersion()
      : BASELINE_MODEL_VERSION;

    for (const detection of detections) {
      const metric = this.preferredCvssMetric(detection.cve.cvssMetrics);
      const threatSignal = detection.cve.threatSignals[0] ?? null;
      const cwe = detection.cve.cveCwes[0]?.cwe ?? null;
      const baseScore = detection.cvssBaseScore ?? metric?.baseScore ?? null;
      const severity = detection.severity ?? metric?.baseSeverity ?? null;
      const features: CvePredictionFeatures = {
        detectionId: detection.id,
        deviceId: target.deviceId,
        cveId: detection.cveId,
        packageName: detection.packageName,
        packageVersion: detection.packageVersion,
        severity,
        baseScore,
        attackVector: metric?.attackVector ?? null,
        attackComplexity: metric?.attackComplexity ?? null,
        privilegesRequired: metric?.privilegesRequired ?? null,
        userInteraction: metric?.userInteraction ?? null,
        scope: metric?.scope ?? null,
        confidentialityImpact: metric?.confidentialityImpact ?? null,
        integrityImpact: metric?.integrityImpact ?? null,
        availabilityImpact: metric?.availabilityImpact ?? null,
        epssScore: threatSignal?.epssScore ?? null,
        epssPercentile: threatSignal?.epssPercentile ?? null,
        isKnownExploited: threatSignal?.isKnownExploited ?? false,
        cweIdGrouped: cwe?.cweId ?? null,
        cweIsGeneric: this.cweIsGeneric(cwe?.cweId ?? null),
        isCvss3OrHigher: this.isCvss3OrHigher(metric?.cvssVersion ?? null),
        alertCount24h: securitySnapshot?.alertCount ?? 0,
        maxRuleLevel24h: securitySnapshot?.maxRuleLevel ?? null,
        devicePackageCount: packageCount,
        modelInputVersion: FEATURE_MODEL_INPUT_VERSION,
      };
      const featureHash = stableHash(features);
      const featureUnchanged =
        detection.featureVector?.featureHash === featureHash;
      const modelUnchanged =
        detection.aiPrediction?.modelVersion === expectedModelVersion;

      if (featureUnchanged && modelUnchanged) {
        skippedPredictions += 1;
        continue;
      }

      const prediction = await this.aiPredictionForFeatures(
        features,
        metric,
        predictedAt,
      );

      let historyCreated = false;

      await this.database.$transaction(async (transaction) => {
        await transaction.vulnerabilityFeatureVector.upsert({
          where: { detectedVulnerabilityId: detection.id },
          create: {
            detectedVulnerabilityId: detection.id,
            deviceId: target.deviceId,
            cveId: detection.cveId,
            modelInputVersion: FEATURE_MODEL_INPUT_VERSION,
            attackVector: features.attackVector,
            attackComplexity: features.attackComplexity,
            privilegesRequired: features.privilegesRequired,
            userInteraction: features.userInteraction,
            scope: features.scope,
            confidentialityImpact: features.confidentialityImpact,
            integrityImpact: features.integrityImpact,
            availabilityImpact: features.availabilityImpact,
            baseScore,
            severity,
            epssScore: features.epssScore,
            epssPercentile: features.epssPercentile,
            isKnownExploited: features.isKnownExploited,
            cweIdGrouped: features.cweIdGrouped,
            cweIsGeneric: features.cweIsGeneric,
            isCvss3OrHigher: features.isCvss3OrHigher,
            alertCount24h: features.alertCount24h,
            maxRuleLevel24h: features.maxRuleLevel24h,
            devicePackageCount: features.devicePackageCount,
            featureHash,
            rawFeatures: features as unknown as Prisma.InputJsonValue,
          },
          update: {
            modelInputVersion: FEATURE_MODEL_INPUT_VERSION,
            attackVector: features.attackVector,
            attackComplexity: features.attackComplexity,
            privilegesRequired: features.privilegesRequired,
            userInteraction: features.userInteraction,
            scope: features.scope,
            confidentialityImpact: features.confidentialityImpact,
            integrityImpact: features.integrityImpact,
            availabilityImpact: features.availabilityImpact,
            baseScore,
            severity,
            epssScore: features.epssScore,
            epssPercentile: features.epssPercentile,
            isKnownExploited: features.isKnownExploited,
            cweIdGrouped: features.cweIdGrouped,
            cweIsGeneric: features.cweIsGeneric,
            isCvss3OrHigher: features.isCvss3OrHigher,
            alertCount24h: features.alertCount24h,
            maxRuleLevel24h: features.maxRuleLevel24h,
            devicePackageCount: features.devicePackageCount,
            featureHash,
            rawFeatures: features as unknown as Prisma.InputJsonValue,
          },
        });

        const existingAiPrediction = await transaction.aiPrediction.findUnique({
          where: { detectedVulnerabilityId: detection.id },
          select: { explanation: true },
        });

        const mergedExplanation = this.mergePredictionExplanation(
          prediction.explanation,
          existingAiPrediction?.explanation,
        );

        await transaction.aiPrediction.upsert({
          where: { detectedVulnerabilityId: detection.id },
          create: {
            detectedVulnerabilityId: detection.id,
            modelVersion: prediction.modelVersion,
            attackProbability: prediction.attackProbability,
            predictedPercentile: prediction.predictedPercentile,
            riskLevel: prediction.riskLevel,
            explanation: mergedExplanation as Prisma.InputJsonValue,
            predictedAt,
          },
          update: {
            modelVersion: prediction.modelVersion,
            attackProbability: prediction.attackProbability,
            predictedPercentile: prediction.predictedPercentile,
            riskLevel: prediction.riskLevel,
            explanation: mergedExplanation as Prisma.InputJsonValue,
            predictedAt,
          },
        });

        const latestHistory = await transaction.predictionHistory.findFirst({
          where: { detectedVulnerabilityId: detection.id },
          orderBy: { predictedAt: 'desc' },
          select: {
            featureHash: true,
            modelVersion: true,
            riskLevel: true,
          },
        });

        if (
          !latestHistory ||
          latestHistory.featureHash !== featureHash ||
          latestHistory.modelVersion !== prediction.modelVersion ||
          latestHistory.riskLevel !== prediction.riskLevel
        ) {
          await transaction.predictionHistory.create({
            data: {
              detectedVulnerabilityId: detection.id,
              deviceId: target.deviceId,
              cveId: detection.cveId,
              wazuhAgentId: target.wazuhAgentId,
              modelVersion: prediction.modelVersion,
              attackProbability: prediction.attackProbability,
              predictedPercentile: prediction.predictedPercentile,
              riskLevel: prediction.riskLevel,
              featureHash,
              predictedAt,
            },
          });
          historyCreated = true;
        }
      });

      featureVectors += 1;
      predictions += 1;
      if (historyCreated) {
        historyRows += 1;
      }

      // The model deliberately writes an audit artifact first. Delete it only
      // after the complete per-CVE database transaction has committed.
      await this.aiModelRuntime.cleanupArtifact(prediction.artifactPath);
    }

    return {
      featureVectors,
      predictions,
      historyRows,
      skippedPredictions,
    };
  }

  private async aiPredictionForFeatures(
    features: CvePredictionFeatures,
    metric: {
      cvssVersion: string | null;
    } | null,
    predictedAt: Date,
  ): Promise<PersistedPrediction> {
    const input = this.buildAiModelInput(features, metric);

    if (!this.aiModelRuntime.isEnabled()) {
      return this.baselinePrediction(features);
    }

    try {
      const result = await this.aiModelRuntime.predict(input);

      if (
        !result ||
        result.attackProbability === null ||
        result.attackProbability === undefined
      ) {
        return this.baselinePrediction(features);
      }

      return this.mapAiModelPrediction(
        result,
        features,
        input,
        predictedAt,
      );
    } catch (error: unknown) {
      this.logger.warn(
        `AI model prediction failed for ${features.cveId}; fallback to baseline: ${this.errorMessage(error)}`,
      );

      const fallback = this.baselinePrediction(features);
      fallback.explanation = {
        ...fallback.explanation,
        ai_model_error: this.errorMessage(error),
        attempted_model: this.aiModelRuntime.activeModel(),
      };

      return fallback;
    }
  }

  private buildAiModelInput(
    features: CvePredictionFeatures,
    metric: {
      cvssVersion: string | null;
    } | null,
  ): AiModelRuntimeInput {
    const attackVector = this.cvssLabel(features.attackVector, 'attackVector');
    const attackComplexity = this.cvssLabel(
      features.attackComplexity,
      'attackComplexity',
    );
    const privilegesRequired = this.cvssLabel(
      features.privilegesRequired,
      'privilegesRequired',
    );
    const userInteraction = this.cvssLabel(
      features.userInteraction,
      'userInteraction',
    );
    const scope = this.cvssLabel(features.scope, 'scope');
    const confidentiality = this.cvssLabel(
      features.confidentialityImpact,
      'impact',
    );
    const integrity = this.cvssLabel(features.integrityImpact, 'impact');
    const availability = this.cvssLabel(
      features.availabilityImpact,
      'impact',
    );

    return {
      cve_id: features.cveId,
      cwe_id: features.cweIdGrouped,
      cvss_version: metric?.cvssVersion ?? null,
      base_score: features.baseScore,
      av_label: attackVector,
      ac_label: attackComplexity,
      pr_label: privilegesRequired,
      ui_label: userInteraction,
      scope_label: scope,
      c_label: confidentiality,
      i_label: integrity,
      a_label: availability,
      exploitability_score: this.cvssExploitabilityScore({
        attackVector,
        attackComplexity,
        privilegesRequired,
        userInteraction,
        scope,
      }),
      impact_score: this.cvssImpactScore({
        scope,
        confidentiality,
        integrity,
        availability,
      }),
      severity_label: features.severity,
      epss_score: features.epssScore,
      kev_flag: features.isKnownExploited ? 1 : 0,
    };
  }

  private mapAiModelPrediction(
    result: AiModelRuntimeResult,
    features: CvePredictionFeatures,
    input: AiModelRuntimeInput,
    predictedAt: Date,
  ): PersistedPrediction {
    const attackProbability = this.roundProbability(
      result.attackProbability ?? 0,
    );
    const priority = this.finalPriority(
      features,
      attackProbability,
      result.finalPriority,
    );

    return {
      artifactPath: result.artifactPath,
      modelVersion:
        result.modelVersion ??
        'CYRP_XGBOOST_CVSS_PERCENTILE_V3',
      attackProbability,
      predictedPercentile: result.predictedPercentile ?? attackProbability,
      riskLevel: this.normalizedRiskLevel(result.riskLevel) ??
        this.riskLevel(attackProbability),
      explanation: this.sanitizeJson({
        model: result.modelVersion,
        modelName: result.modelName,
        source: 'PYTHON_AI_MODEL_RUNTIME',
        predictedAt: predictedAt.toISOString(),
        final_priority_level: priority.level,
        finalPriorityLevel: priority.level,
        final_priority_score: priority.score,
        finalPriorityScore: priority.score,
        official_epss_score: features.epssScore,
        officialEpssScore: features.epssScore,
        official_epss_percentile: features.epssPercentile,
        officialEpssPercentile: features.epssPercentile,
        kev_flag: features.isKnownExploited,
        model_final_priority: result.finalPriority,
        model_prediction: result.prediction,
        predicted_percentile: result.predictedPercentile,
        predictedPercentile: result.predictedPercentile,
        baseScore: features.baseScore,
        severity: features.severity,
        cweId: features.cweIdGrouped,
        reasons: this.cvssReasons(features, input),
        rawModelOutput: {
          Probability: attackProbability,
          Percentile: result.predictedPercentile,
          Reasons: this.cvssReasons(features, input),
        },
        input,
        modelDetails: result.details ?? null,
      }),
    };
  }



  private cvssReasons(
    features: CvePredictionFeatures,
    input?: AiModelRuntimeInput,
  ): Array<{ feature: string; value: string | number | boolean }> {
    const entries: Array<{ feature: string; value: string | number | boolean | null | undefined }> = [
      { feature: 'CVSS_cvss_version', value: input?.cvss_version ?? null },
      { feature: 'CVSS_base_score', value: features.baseScore },
      { feature: 'CVSS_attack_vector', value: features.attackVector },
      { feature: 'CVSS_attack_complexity', value: features.attackComplexity },
      { feature: 'CVSS_privileges_required', value: features.privilegesRequired },
      { feature: 'CVSS_user_interaction', value: features.userInteraction },
      { feature: 'CVSS_scope', value: features.scope },
      { feature: 'CVSS_confidentiality', value: features.confidentialityImpact },
      { feature: 'CVSS_integrity', value: features.integrityImpact },
      { feature: 'CVSS_availability', value: features.availabilityImpact },
      { feature: 'CVSS_exploitability_score', value: input?.exploitability_score ?? null },
      { feature: 'CVSS_impact_score', value: input?.impact_score ?? null },
    ];

    return entries.filter(
      (entry): entry is { feature: string; value: string | number | boolean } =>
        entry.value !== null && entry.value !== undefined && entry.value !== '',
    );
  }

  private cyrpIsRecord(value: unknown): value is Record<string, unknown> {
    return value !== null && typeof value === 'object' && !Array.isArray(value);
  }

  private mergePredictionExplanation(
    incoming: Record<string, unknown>,
    existingValue: unknown,
  ): Record<string, unknown> {
    const existing = this.cyrpIsRecord(existingValue) ? existingValue : {};
    const merged: Record<string, unknown> = {
      ...existing,
      ...incoming,
    };

    const incomingReasons = Array.isArray(incoming.reasons) ? incoming.reasons : [];
    const existingReasons = Array.isArray(existing.reasons) ? existing.reasons : [];

    const incomingRawModelOutput = this.cyrpIsRecord(incoming.rawModelOutput)
      ? incoming.rawModelOutput
      : null;
    const existingRawModelOutput = this.cyrpIsRecord(existing.rawModelOutput)
      ? existing.rawModelOutput
      : null;

    const incomingRawReasons =
      incomingRawModelOutput && Array.isArray(incomingRawModelOutput.Reasons)
        ? incomingRawModelOutput.Reasons
        : [];

    if (incomingReasons.length > 0) {
      merged.reasons = incomingReasons;
    } else if (incomingRawReasons.length > 0) {
      merged.reasons = incomingRawReasons;
    } else if (existingReasons.length > 0) {
      merged.reasons = existingReasons;
    }

    if (!incomingRawModelOutput && existingRawModelOutput) {
      merged.rawModelOutput = existingRawModelOutput;
    }

    const incomingRemediation = this.cyrpIsRecord(incoming.remediation)
      ? incoming.remediation
      : null;
    const existingRemediation = this.cyrpIsRecord(existing.remediation)
      ? existing.remediation
      : null;

    if (!incomingRemediation && existingRemediation) {
      merged.remediation = existingRemediation;
    }

    return merged;
  }

  private finalPriority(
    features: CvePredictionFeatures,
    attackProbability: number,
    modelPriority: string | null,
  ): {
    score: number;
    level: string;
  } {
    const cvss = Math.min(Math.max((features.baseScore ?? 0) / 10, 0), 1);
    const epss = Math.min(Math.max(features.epssScore ?? 0, 0), 1);
    const severity = this.severityWeight(features.severity);
    const kev = features.isKnownExploited ? 1 : 0;
    const alert = Math.min(Math.max((features.maxRuleLevel24h ?? 0) / 15, 0), 1);

    const score = Math.round(
      Math.min(
        Math.max(
          attackProbability * 55 +
            cvss * 20 +
            epss * 12 +
            severity * 6 +
            kev * 5 +
            alert * 2,
          0,
        ),
        100,
      ) * 100,
    ) / 100;

    const level = this.higherPriorityLevel(
      this.priorityLevel(score),
      this.normalizedRiskLevel(modelPriority),
    );

    return {
      score,
      level,
    };
  }

  private priorityLevel(score: number): string {
    if (score >= 85) {
      return 'CRITICAL';
    }
    if (score >= 65) {
      return 'HIGH';
    }
    if (score >= 40) {
      return 'MEDIUM';
    }
    if (score >= 15) {
      return 'LOW';
    }
    return 'INFORMATIONAL';
  }

  private higherPriorityLevel(
    left: string,
    right: string | null,
  ): string {
    if (!right) {
      return left;
    }

    return this.priorityRank(right) > this.priorityRank(left)
      ? right
      : left;
  }

  private priorityRank(level: string): number {
    switch (level.toUpperCase()) {
      case 'CRITICAL':
        return 4;
      case 'HIGH':
        return 3;
      case 'MEDIUM':
        return 2;
      case 'LOW':
        return 1;
      default:
        return 0;
    }
  }

  private normalizedRiskLevel(level: string | null): string | null {
    if (!level) {
      return null;
    }

    const normalized = level.trim().toUpperCase();

    return [
      'CRITICAL',
      'HIGH',
      'MEDIUM',
      'LOW',
      'INFORMATIONAL',
    ].includes(normalized)
      ? normalized
      : null;
  }

  private cvssExploitabilityScore(metrics: {
    attackVector: string | null;
    attackComplexity: string | null;
    privilegesRequired: string | null;
    userInteraction: string | null;
    scope: string | null;
  }): number | null {
    const av = this.cvssMetricWeight(metrics.attackVector, {
      NETWORK: 0.85,
      ADJACENT: 0.62,
      LOCAL: 0.55,
      PHYSICAL: 0.2,
    });
    const ac = this.cvssMetricWeight(metrics.attackComplexity, {
      LOW: 0.77,
      HIGH: 0.44,
    });
    const ui = this.cvssMetricWeight(metrics.userInteraction, {
      NONE: 0.85,
      REQUIRED: 0.62,
    });

    let pr: number | null = null;
    const scopeChanged = metrics.scope === 'CHANGED';

    switch (metrics.privilegesRequired) {
      case 'NONE':
        pr = 0.85;
        break;
      case 'LOW':
        pr = scopeChanged ? 0.68 : 0.62;
        break;
      case 'HIGH':
        pr = scopeChanged ? 0.5 : 0.27;
        break;
      default:
        pr = null;
    }

    if (av === null || ac === null || pr === null || ui === null) {
      return null;
    }

    return Math.round(8.22 * av * ac * pr * ui * 10) / 10;
  }

  private cvssImpactScore(metrics: {
    scope: string | null;
    confidentiality: string | null;
    integrity: string | null;
    availability: string | null;
  }): number | null {
    const c = this.cvssMetricWeight(metrics.confidentiality, {
      HIGH: 0.56,
      LOW: 0.22,
      NONE: 0,
    });
    const i = this.cvssMetricWeight(metrics.integrity, {
      HIGH: 0.56,
      LOW: 0.22,
      NONE: 0,
    });
    const a = this.cvssMetricWeight(metrics.availability, {
      HIGH: 0.56,
      LOW: 0.22,
      NONE: 0,
    });

    if (c === null || i === null || a === null) {
      return null;
    }

    const iscBase = 1 - (1 - c) * (1 - i) * (1 - a);

    if (iscBase <= 0) {
      return 0;
    }

    const rawImpact =
      metrics.scope === 'CHANGED'
        ? 7.52 * (iscBase - 0.029) -
          3.25 * Math.pow(iscBase - 0.02, 15)
        : 6.42 * iscBase;

    return Math.round(Math.max(rawImpact, 0) * 10) / 10;
  }

  private cvssMetricWeight(
    value: string | null,
    weights: Record<string, number>,
  ): number | null {
    if (!value) {
      return null;
    }

    return weights[value] ?? null;
  }

  private cvssLabel(
    value: string | null,
    kind:
      | 'attackVector'
      | 'attackComplexity'
      | 'privilegesRequired'
      | 'userInteraction'
      | 'scope'
      | 'impact',
  ): string | null {
    if (!value) {
      return null;
    }

    const normalized = value.trim().toUpperCase();

    const mappings: Record<string, string> = {
      N: 'NETWORK',
      NETWORK: 'NETWORK',
      A: kind === 'impact' ? 'HIGH' : 'ADJACENT',
      ADJACENT: 'ADJACENT',
      L: kind === 'impact' || kind === 'attackComplexity' || kind === 'privilegesRequired'
        ? 'LOW'
        : 'LOCAL',
      LOCAL: 'LOCAL',
      P: 'PHYSICAL',
      PHYSICAL: 'PHYSICAL',
      H: 'HIGH',
      HIGH: 'HIGH',
      LOW: 'LOW',
      NONE: 'NONE',
      R: 'REQUIRED',
      REQUIRED: 'REQUIRED',
      U: 'UNCHANGED',
      UNCHANGED: 'UNCHANGED',
      C: 'CHANGED',
      CHANGED: 'CHANGED',
    };

    if (kind === 'scope' && normalized === 'C') {
      return 'CHANGED';
    }

    if (kind === 'impact' && normalized === 'A') {
      return 'HIGH';
    }

    if (kind === 'attackVector' && normalized === 'A') {
      return 'ADJACENT';
    }

    if (kind === 'attackVector' && normalized === 'L') {
      return 'LOCAL';
    }

    if (kind === 'privilegesRequired' && normalized === 'L') {
      return 'LOW';
    }

    if (kind === 'attackComplexity' && normalized === 'L') {
      return 'LOW';
    }

    return mappings[normalized] ?? normalized;
  }

  private preferredCvssMetric<T extends {
    source: string;
    metricType: string;
    cvssVersion: string;
    vectorString: string | null;
    baseScore: number | null;
    baseSeverity: string | null;
    attackVector: string | null;
    attackComplexity: string | null;
    privilegesRequired: string | null;
    userInteraction: string | null;
    scope: string | null;
    confidentialityImpact: string | null;
    integrityImpact: string | null;
    availabilityImpact: string | null;
  }>(metrics: T[]): T | null {
    return [...metrics].sort((left, right) => {
      const sourceWeight = (source: string): number =>
        source === 'CYRP_CTI_CSV'
          ? 100
          : source === 'NVD'
            ? 90
            : source === 'WAZUH'
              ? 10
              : 0;
      const completeness = (metric: T): number =>
        [
          metric.vectorString,
          metric.attackVector,
          metric.attackComplexity,
          metric.privilegesRequired,
          metric.userInteraction,
          metric.scope,
          metric.confidentialityImpact,
          metric.integrityImpact,
          metric.availabilityImpact,
        ].filter(Boolean).length;

      return (
        completeness(right) * 1_000 +
        sourceWeight(right.source) -
        (completeness(left) * 1_000 + sourceWeight(left.source))
      );
    })[0] ?? null;
  }

  private baselinePrediction(features: CvePredictionFeatures): PersistedPrediction {
    return {
      artifactPath: null,
      modelVersion: BASELINE_MODEL_VERSION,
      attackProbability: 0,
      predictedPercentile: null,
      riskLevel: 'INFORMATIONAL',
      explanation: {
        model: BASELINE_MODEL_VERSION,
        note: 'Không dùng mô hình AI cũ. Dòng này chỉ cho biết model mới chưa trả được kết quả dự đoán.',
        modelRequired: 'CYRP_XGBOOST_CVSS_PERCENTILE_V3',
        severity: features.severity,
        baseScore: features.baseScore,
        epssScore: features.epssScore,
        epssPercentile: features.epssPercentile,
        isKnownExploited: features.isKnownExploited,
        maxRuleLevel24h: features.maxRuleLevel24h,
        reasons: this.cvssReasons(features),
      },
    };
  }

  private severityWeight(severity: string | null): number {
    switch (severity?.toUpperCase()) {
      case 'CRITICAL':
        return 1;
      case 'HIGH':
        return 0.75;
      case 'MEDIUM':
        return 0.45;
      case 'LOW':
        return 0.2;
      default:
        return 0;
    }
  }

  private riskLevel(probability: number): string {
    if (probability >= 0.85) {
      return 'CRITICAL';
    }
    if (probability >= 0.65) {
      return 'HIGH';
    }
    if (probability >= 0.4) {
      return 'MEDIUM';
    }
    if (probability >= 0.15) {
      return 'LOW';
    }
    return 'INFORMATIONAL';
  }

  private roundProbability(value: number): number {
    return Math.round(Math.min(Math.max(value, 0), 1) * 100_000) / 100_000;
  }

  private isCvss3OrHigher(version: string | null): boolean {
    const major = Number.parseInt(version ?? '', 10);
    return Number.isFinite(major) && major >= 3;
  }

  private cweIsGeneric(cweId: string | null): boolean {
    return !cweId || cweId === 'CWE-Other' || cweId === 'CWE-NVD-noinfo';
  }

  private sanitizeText(value: string): string {
    let sanitized = '';

    for (const character of value) {
      const code =
        character.charCodeAt(0);

      const isUnsupportedControlCharacter =
        code === 0 ||
        (code >= 1 && code <= 8) ||
        code === 11 ||
        code === 12 ||
        (code >= 14 && code <= 31) ||
        code === 127;

      if (!isUnsupportedControlCharacter) {
        sanitized += character;
      }
    }

    return sanitized;
  }

  private sanitizeJson<T>(value: T): T {
    if (typeof value === 'string') {
      return this.sanitizeText(value) as T;
    }

    if (Array.isArray(value)) {
      return value.map((item) =>
        this.sanitizeJson(item),
      ) as T;
    }

    if (
      value &&
      typeof value === 'object'
    ) {
      if (value instanceof Date) {
        return value as T;
      }

      return Object.fromEntries(
        Object.entries(value as Record<string, unknown>).map(
          ([key, item]) => [
            this.sanitizeText(key),
            this.sanitizeJson(item),
          ],
        ),
      ) as T;
    }

    return value;
  }
  private firstString(
    source: unknown,
    paths: string[][],
  ): string | null {
    const value = this.firstValue(source, paths);
    if (typeof value !== 'string') {
      return null;
    }

    const normalized = this.sanitizeText(value).trim();
    return normalized || null;
  }

  private firstNumber(
    source: unknown,
    paths: string[][],
  ): number | null {
    const value = this.firstValue(source, paths);

    if (typeof value === 'number' && Number.isFinite(value)) {
      return value;
    }

    if (typeof value === 'string' && value.trim()) {
      const parsed = Number(value);
      return Number.isFinite(parsed) ? parsed : null;
    }

    return null;
  }

  private firstValue(source: unknown, paths: string[][]): unknown {
    for (const path of paths) {
      let current: unknown = source;

      for (const segment of path) {
        if (!this.isRecord(current) || !(segment in current)) {
          current = undefined;
          break;
        }
        current = current[segment];
      }

      if (current !== undefined && current !== null) {
        return current;
      }
    }

    return null;
  }

  private isRecord(value: unknown): value is Record<string, unknown> {
    return typeof value === 'object' && value !== null && !Array.isArray(value);
  }

  private async resolveTarget(
    deviceId: string,
    userId?: string,
  ): Promise<SyncTarget> {
    const device = await this.database.device.findFirst({
      where: {
        id: deviceId,
        ...(userId ? { userId } : {}),
      },
      select: {
        id: true,
        userId: true,
        hostname: true,
        wazuhBinding: {
          select: {
            wazuhAgentId: true,
            wazuhAgentName: true,
          },
        },
      },
    });

    if (!device) {
      throw new NotFoundException({
        code: 'DEVICE_NOT_FOUND',
        message: 'Không tìm thấy thiết bị hoặc bạn không có quyền truy cập',
      });
    }

    if (!device.wazuhBinding) {
      throw new NotFoundException({
        code: 'WAZUH_AGENT_NOT_BOUND',
        message: 'Thiết bị chưa được liên kết với Wazuh Agent',
      });
    }

    return {
      deviceId: device.id,
      userId: device.userId,
      hostname: device.hostname,
      wazuhAgentId: device.wazuhBinding.wazuhAgentId,
      wazuhAgentName: device.wazuhBinding.wazuhAgentName,
    };
  }

  private async runScheduledSync(): Promise<void> {
    if (this.scheduledRunActive) {
      this.logger.warn('Skipped overlapping Phase 2 state synchronization');
      return;
    }

    this.scheduledRunActive = true;

    try {
      const devices = await this.database.device.findMany({
        where: { wazuhBinding: { isNot: null } },
        select: { id: true },
        orderBy: { createdAt: 'asc' },
      });

      await this.runWithConcurrency(
        devices,
        this.maxConcurrency,
        async (device) => {
          try {
            await this.syncLock.runWithLock(device.id, async () => {
              const target = await this.resolveTarget(device.id);
              await Promise.all([
                this.syncVulnerabilities(target, 'SCHEDULED'),
                this.syncEndpointContext(target, 'SCHEDULED'),
              ]);
            });
          } catch (error: unknown) {
            this.logger.warn(
              `Phase 2 state sync failed for device ${device.id}: ${this.errorMessage(error)}`,
            );
          }
        },
      );
    } finally {
      this.scheduledRunActive = false;
    }
  }

  private async recoverStaleRuns(): Promise<void> {
    const cutoff = new Date(Date.now() - this.staleRunMs);
    const recovered = await this.database.syncRun.updateMany({
      where: {
        status: SyncRunStatus.RUNNING,
        startedAt: { lt: cutoff },
      },
      data: {
        status: SyncRunStatus.FAILED,
        completedAt: new Date(),
        errorSummary:
          'Recovered at API startup because the synchronization run exceeded the configured stale-run threshold.',
      },
    });

    if (recovered.count > 0) {
      this.logger.warn(`Recovered ${recovered.count} stale SyncRun record(s)`);
    }
  }

  private async findSourceId(code: string): Promise<string | null> {
    const source = await this.database.ctiSource.findUnique({
      where: { code },
      select: { id: true },
    });
    return source?.id ?? null;
  }

  private async markSourceSuccess(
    sourceId: string | null,
    at: Date,
  ): Promise<void> {
    if (!sourceId) {
      return;
    }

    await this.database.ctiSource.update({
      where: { id: sourceId },
      data: {
        status: 'ACTIVE',
        lastAttemptAt: at,
        lastSuccessAt: at,
        lastError: null,
      },
    });
  }

  private async markSourceFailure(
    sourceId: string | null,
    error: unknown,
  ): Promise<void> {
    if (!sourceId) {
      return;
    }

    await this.database.ctiSource.update({
      where: { id: sourceId },
      data: {
        status: 'ERROR',
        lastAttemptAt: new Date(),
        lastError: this.errorMessage(error).slice(0, 2_000),
      },
    });
  }

  private async failRun(runId: string, error: unknown): Promise<void> {
    await this.database.syncRun.update({
      where: { id: runId },
      data: {
        status: SyncRunStatus.FAILED,
        completedAt: new Date(),
        errorSummary: this.errorMessage(error).slice(0, 2_000),
      },
    });
  }

  private async timedSettled<T>(
    promise: Promise<T>,
  ): Promise<{
    result: PromiseSettledResult<T>;
    durationMs: number;
  }> {
    const started = Date.now();
    const result = await this.settle(promise);
    return {
      result,
      durationMs: Date.now() - started,
    };
  }

  private async settle<T>(
    promise: Promise<T>,
  ): Promise<PromiseSettledResult<T>> {
    try {
      return {
        status: 'fulfilled',
        value: await promise,
      };
    } catch (reason: unknown) {
      return {
        status: 'rejected',
        reason,
      };
    }
  }

  private componentResult<T>(
    result: PromiseSettledResult<T>,
    successMessage: string,
  ): ComponentResult {
    if (result.status === 'fulfilled') {
      const value = result.value as { status?: string } | null;
      return {
        status: value?.status === 'PARTIAL' ? 'PARTIAL' : 'COMPLETED',
        message: successMessage,
        data: result.value,
      };
    }

    return this.failedComponent(result.reason);
  }

  private failedComponent(error: unknown): ComponentResult {
    return {
      status: 'FAILED',
      message: this.errorMessage(error),
    };
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
          'Tích hợp Wazuh đang tắt. Hãy cấu hình WAZUH_INTEGRATION_ENABLED=true trước khi đồng bộ.',
      });
    }
  }

  private errorMessage(error: unknown): string {
    if (error instanceof Error) {
      return error.message;
    }

    return 'Lỗi đồng bộ không xác định';
  }

  private booleanValue(value: unknown, fallback: boolean): boolean {
    if (typeof value === 'boolean') {
      return value;
    }

    if (typeof value === 'string') {
      const normalized = value.trim().toLowerCase();

      if (normalized === 'true') {
        return true;
      }

      if (normalized === 'false') {
        return false;
      }
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
}