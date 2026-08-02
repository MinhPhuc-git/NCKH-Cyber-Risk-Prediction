import { Injectable, NotFoundException } from '@nestjs/common';
import {
  Prisma,
  SyncRunStatus,
  VulnerabilityLifecycleStatus,
} from '@prisma/client';

import { DatabaseService } from '../../database/database.service';
import { AgentRuntimeService } from '../wazuh-bindings/agent-runtime.service';
import { WazuhService } from '../wazuh/wazuh.service';
import { SecurityDataSyncService } from './security-data-sync.service';
import type { ListAdminDevicesQueryDto } from './dto/list-admin-devices-query.dto';
import type { ListDevicePackagesQueryDto } from './dto/list-device-packages-query.dto';
import type { ListSyncRunsQueryDto } from './dto/list-sync-runs-query.dto';
import type { ListVulnerabilitiesQueryDto } from './dto/list-vulnerabilities-query.dto';

@Injectable()
export class SecurityDataService {
  constructor(
    private readonly database: DatabaseService,
    private readonly wazuh: WazuhService,
    private readonly syncService: SecurityDataSyncService,
    private readonly agentRuntime: AgentRuntimeService,
  ) {}

  async getUserDashboard(userId: string) {
    const [devices, topVulnerabilities, recentRuns, severity] =
      await Promise.all([
        this.database.device.findMany({
          where: { userId },
          orderBy: { createdAt: 'asc' },
          select: {
            id: true,
            hostname: true,
            operatingSystem: true,
            status: true,
            lastSeenAt: true,
            wazuhBinding: {
              select: {
                wazuhAgentId: true,
                lastKnownStatus: true,
                lastKeepAliveAt: true,
                lastSynchronizedAt: true,
              },
            },
            endpointContextSnapshots: {
              take: 1,
              orderBy: { asOfTime: 'desc' },
              select: this.contextSummarySelect(),
            },
            _count: {
              select: {
                detectedVulnerabilities: {
                  where: { status: VulnerabilityLifecycleStatus.ACTIVE },
                },
              },
            },
          },
        }),
        this.database.detectedVulnerability.findMany({
          where: {
            device: { userId },
            status: VulnerabilityLifecycleStatus.ACTIVE,
          },
          orderBy: [{ cvssBaseScore: 'desc' }, { lastSeenAt: 'desc' }],
          take: 10,
          include: this.vulnerabilityInclude(),
        }),
        this.database.syncRun.findMany({
          where: { device: { userId } },
          orderBy: { startedAt: 'desc' },
          take: 10,
          include: {
            device: { select: { id: true, hostname: true } },
            source: { select: { id: true, code: true, name: true } },
          },
        }),
        this.groupSeverity({
          device: { userId },
          status: VulnerabilityLifecycleStatus.ACTIVE,
        }),
      ]);

    return {
      calculatedAt: new Date().toISOString(),
      devices: {
        total: devices.length,
        active: devices.filter(
          (device) => device.wazuhBinding?.lastKnownStatus === 'active',
        ).length,
        stale: devices.filter((device) => {
          const asOfTime = device.endpointContextSnapshots[0]?.asOfTime;
          return !asOfTime || Date.now() - asOfTime.getTime() > 86_400_000;
        }).length,
        items: devices.map((device) => ({
          ...device,
          latestContext: device.endpointContextSnapshots[0] ?? null,
          endpointContextSnapshots: undefined,
          activeVulnerabilities: device._count.detectedVulnerabilities,
          _count: undefined,
        })),
      },
      vulnerabilities: {
        active: severity.total,
        severity: severity.counts,
        top: topVulnerabilities.map((item) =>
          this.mapVulnerability(item),
        ),
      },
      recentRuns: recentRuns.map((run) => this.mapSyncRun(run)),
      scopeNote:
        'Các chỉ số Phase 2 phản ánh dữ liệu Wazuh và CTI đã đồng bộ; chưa phải kết quả mô hình AI.',
    };
  }

  async getDeviceOverview(userId: string, deviceId: string) {
    const device = await this.database.device.findFirst({
      where: { id: deviceId, userId },
      include: {
        wazuhBinding: true,
        securitySnapshot: true,
        endpointContextSnapshots: {
          take: 1,
          orderBy: { asOfTime: 'desc' },
        },
        syncRuns: {
          take: 20,
          orderBy: { startedAt: 'desc' },
          include: {
            source: { select: { id: true, code: true, name: true } },
          },
        },
      },
    });

    if (!device) {
      throw this.deviceNotFound();
    }

    const [severity, resolved] = await Promise.all([
      this.groupSeverity({
        deviceId,
        status: VulnerabilityLifecycleStatus.ACTIVE,
      }),
      this.database.detectedVulnerability.count({
        where: {
          deviceId,
          status: VulnerabilityLifecycleStatus.RESOLVED,
        },
      }),
    ]);

    return {
      ...device,
      latestContext: this.mapContextSnapshot(
        device.endpointContextSnapshots[0] ?? null,
      ),
      endpointContextSnapshots: undefined,
      syncRuns: device.syncRuns.map((run) => this.mapSyncRun(run)),
      vulnerabilitySummary: {
        active: severity.total,
        resolved,
        severity: severity.counts,
      },
    };
  }

  async getLatestContext(userId: string, deviceId: string) {
    await this.assertUserDevice(userId, deviceId);

    const context = await this.database.endpointContextSnapshot.findFirst({
      where: { deviceId },
      orderBy: { asOfTime: 'desc' },
      include: {
        syncRun: {
          select: {
            id: true,
            status: true,
            completedAt: true,
            errorSummary: true,
          },
        },
      },
    });

    return this.mapContextSnapshot(context);
  }

  async listUserDevicePackages(
    userId: string,
    deviceId: string,
    query: ListDevicePackagesQueryDto,
  ) {
    await this.assertUserDevice(userId, deviceId);
    return this.listDevicePackages(deviceId, query);
  }

  async listAdminDevicePackages(
    deviceId: string,
    query: ListDevicePackagesQueryDto,
  ) {
    const device = await this.database.device.findUnique({
      where: { id: deviceId },
      select: { id: true },
    });

    if (!device) {
      throw this.deviceNotFound();
    }

    return this.listDevicePackages(deviceId, query);
  }

  async listUserVulnerabilities(
    userId: string,
    query: ListVulnerabilitiesQueryDto,
  ) {
    if (query.deviceId) {
      await this.assertUserDevice(userId, query.deviceId);
    }

    return this.listVulnerabilities(
      this.vulnerabilityWhere(query, userId),
      query.page,
      query.limit,
    );
  }

  getUserVulnerability(userId: string, id: string) {
    return this.getVulnerabilityDetail({ id, device: { userId } }, true);
  }

  getAdminVulnerability(id: string) {
    return this.getVulnerabilityDetail({ id }, false);
  }

  listUserSyncRuns(userId: string, query: ListSyncRunsQueryDto) {
    return this.listSyncRuns(
      {
        device: { userId },
        ...(query.deviceId ? { deviceId: query.deviceId } : {}),
        ...(query.status ? { status: query.status } : {}),
        ...(query.sourceType ? { sourceType: query.sourceType } : {}),
      },
      query.page,
      query.limit,
    );
  }

  async getAdminDashboard() {
    const [
      users,
      devices,
      bindings,
      failedRuns,
      runningRuns,
      recentRuns,
      sources,
      severity,
      cves,
      contexts,
      wazuhApi,
      indexer,
    ] = await Promise.all([
      this.database.user.count(),
      this.database.device.count(),
      this.database.wazuhAgentBinding.count(),
      this.database.syncRun.count({ where: { status: SyncRunStatus.FAILED } }),
      this.database.syncRun.count({ where: { status: SyncRunStatus.RUNNING } }),
      this.database.syncRun.findMany({
        take: 10,
        orderBy: { startedAt: 'desc' },
        include: {
          device: { select: { id: true, hostname: true } },
          source: { select: { id: true, code: true, name: true } },
        },
      }),
      this.database.ctiSource.findMany({ orderBy: { name: 'asc' } }),
      this.groupSeverity({ status: VulnerabilityLifecycleStatus.ACTIVE }),
      this.database.cve.count(),
      this.database.endpointContextSnapshot.count(),
      this.captureStatus(() => this.wazuh.getStatus()),
      this.captureStatus(() => this.wazuh.getIndexerStatus()),
    ]);

    return {
      calculatedAt: new Date().toISOString(),
      users,
      devices,
      bindings,
      vulnerabilities: {
        active: severity.total,
        severity: severity.counts,
      },
      dataFoundation: { cves, endpointContextSnapshots: contexts },
      sync: {
        failed: failedRuns,
        running: runningRuns,
        recent: recentRuns.map((run) => this.mapSyncRun(run)),
      },
      sources,
      services: {
        database: { connected: true },
        wazuhApi,
        indexer,
        synchronization: this.syncService.getSchedulerStatus(),
        agentRuntime: this.agentRuntime.getSchedulerStatus(),
        wazuhRuntime: this.wazuh.getRuntimeConfiguration(),
      },
    };
  }

  async listAdminDevices(query: ListAdminDevicesQueryDto) {
    const where: Prisma.DeviceWhereInput = query.query
      ? {
          OR: [
            { hostname: { contains: query.query, mode: 'insensitive' } },
            {
              operatingSystem: {
                contains: query.query,
                mode: 'insensitive',
              },
            },
            {
              user: {
                email: { contains: query.query, mode: 'insensitive' },
              },
            },
            {
              wazuhBinding: {
                is: { wazuhAgentId: { contains: query.query } },
              },
            },
          ],
        }
      : {};
    const skip = (query.page - 1) * query.limit;

    const [total, items] = await this.database.$transaction([
      this.database.device.count({ where }),
      this.database.device.findMany({
        where,
        skip,
        take: query.limit,
        orderBy: { createdAt: 'desc' },
        select: {
          id: true,
          hostname: true,
          operatingSystem: true,
          architecture: true,
          agentVersion: true,
          status: true,
          lastSeenAt: true,
          createdAt: true,
          user: {
            select: {
              id: true,
              email: true,
              fullName: true,
              status: true,
            },
          },
          wazuhBinding: true,
          endpointContextSnapshots: {
            take: 1,
            orderBy: { asOfTime: 'desc' },
            select: this.contextSummarySelect(),
          },
          _count: {
            select: {
              detectedVulnerabilities: {
                where: { status: VulnerabilityLifecycleStatus.ACTIVE },
              },
            },
          },
        },
      }),
    ]);

    return {
      page: query.page,
      limit: query.limit,
      total,
      totalPages: Math.max(1, Math.ceil(total / query.limit)),
      items: items.map((item) => ({
        ...item,
        latestContext: item.endpointContextSnapshots[0] ?? null,
        endpointContextSnapshots: undefined,
        activeVulnerabilities: item._count.detectedVulnerabilities,
        _count: undefined,
      })),
    };
  }

  async getAdminDevice(deviceId: string) {
    const [device, latestContext] = await Promise.all([
      this.database.device.findUnique({
        where: { id: deviceId },
        include: {
          user: {
            select: { id: true, email: true, fullName: true, status: true },
          },
          wazuhBinding: true,
          securitySnapshot: true,
          endpointContextSnapshots: {
            take: 5,
            orderBy: { asOfTime: 'desc' },
            select: this.contextHistorySelect(),
          },
          syncRuns: {
            take: 20,
            orderBy: { startedAt: 'desc' },
            include: {
              source: { select: { id: true, code: true, name: true } },
            },
          },
        },
      }),
      this.database.endpointContextSnapshot.findFirst({
        where: { deviceId },
        orderBy: { asOfTime: 'desc' },
      }),
    ]);

    if (!device) {
      throw this.deviceNotFound();
    }

    const severity = await this.groupSeverity({
      deviceId,
      status: VulnerabilityLifecycleStatus.ACTIVE,
    });

    return {
      ...device,
      latestContext: this.mapContextSnapshot(latestContext),
      activeVulnerabilities: severity.total,
      syncRuns: device.syncRuns.map((run) => this.mapSyncRun(run)),
      vulnerabilitySummary: {
        active: severity.total,
        severity: severity.counts,
      },
    };
  }

  listAdminBindings() {
    return this.database.wazuhAgentBinding.findMany({
      orderBy: { updatedAt: 'desc' },
      include: {
        device: {
          select: {
            id: true,
            hostname: true,
            operatingSystem: true,
            status: true,
            user: {
              select: { id: true, email: true, fullName: true },
            },
          },
        },
      },
    });
  }

  listAdminVulnerabilities(query: ListVulnerabilitiesQueryDto) {
    return this.listVulnerabilities(
      this.vulnerabilityWhere(query),
      query.page,
      query.limit,
    );
  }

  listAdminSyncRuns(query: ListSyncRunsQueryDto) {
    return this.listSyncRuns(
      {
        ...(query.deviceId ? { deviceId: query.deviceId } : {}),
        ...(query.status ? { status: query.status } : {}),
        ...(query.sourceType ? { sourceType: query.sourceType } : {}),
      },
      query.page,
      query.limit,
    );
  }

  async listCtiSources() {
    const [sources, cves, metrics, cwes, signals, products] =
      await Promise.all([
        this.database.ctiSource.findMany({
          orderBy: { name: 'asc' },
          include: {
            syncRuns: { take: 5, orderBy: { startedAt: 'desc' } },
          },
        }),
        this.database.cve.count(),
        this.database.cveCvssMetric.count(),
        this.database.cwe.count(),
        this.database.cveThreatSignal.count(),
        this.database.cveAffectedProduct.count(),
      ]);

    return {
      totals: { cves, metrics, cwes, signals, products },
      items: sources.map((source) => ({
        ...source,
        syncRuns: source.syncRuns.map((run) => this.mapSyncRun(run)),
      })),
    };
  }

  async getSystemHealth() {
    const startedAt = Date.now();
    const database = await this.captureStatus(async () => ({
      connected: true,
      latencyMs: await this.database.ping(),
    }));
    const [wazuhApi, indexer, latestRuns] = await Promise.all([
      this.captureStatus(() => this.wazuh.getStatus()),
      this.captureStatus(() => this.wazuh.getIndexerStatus()),
      this.database.syncRun.findMany({
        take: 12,
        orderBy: { startedAt: 'desc' },
        include: {
          device: { select: { id: true, hostname: true } },
          source: { select: { id: true, code: true, name: true } },
        },
      }),
    ]);

    const synchronization = this.syncService.getSchedulerStatus();

    return {
      checkedAt: new Date().toISOString(),
      responseTimeMs: Date.now() - startedAt,
      dataSyncEnabled: synchronization.enabled,
      synchronization,
      agentRuntime: this.agentRuntime.getSchedulerStatus(),
      wazuhRuntime: this.wazuh.getRuntimeConfiguration(),
      database,
      wazuhApi,
      indexer,
      latestRuns: latestRuns.map((run) => this.mapSyncRun(run)),
    };
  }


  private async getVulnerabilityDetail(
    where: Prisma.DetectedVulnerabilityWhereInput,
    userScoped: boolean,
  ) {
    const item = await this.database.detectedVulnerability.findFirst({
      where,
      include: {
        ...this.vulnerabilityInclude(),
        syncRun: true,
      },
    });

    if (!item) {
      throw new NotFoundException({
        code: 'VULNERABILITY_NOT_FOUND',
        message: userScoped
          ? 'Không tìm thấy lỗ hổng trên thiết bị của bạn'
          : 'Không tìm thấy lỗ hổng trong hệ thống',
      });
    }

    const latestContext =
      await this.database.endpointContextSnapshot.findFirst({
        where: { deviceId: item.deviceId },
        orderBy: { asOfTime: 'desc' },
      });

    return {
      ...this.mapVulnerability(item),
      references: item.cve.references,
      affectedProducts: item.cve.affectedProducts,
      cwes: item.cve.cveCwes.map((link) => link.cwe),
      latestContext: this.mapContextSnapshot(latestContext),
      source: {
        index: item.sourceIndex,
        documentId: item.sourceDocumentId,
        updatedAt: item.sourceUpdatedAt,
        syncRun: item.syncRun ? this.mapSyncRun(item.syncRun) : null,
      },
    };
  }

  private async listDevicePackages(
    deviceId: string,
    query: ListDevicePackagesQueryDto,
  ) {
    const search = query.query?.trim();
    const where: Prisma.DevicePackageWhereInput = {
      deviceId,
      ...(search
        ? {
            OR: [
              { name: { contains: search, mode: 'insensitive' } },
              { version: { contains: search, mode: 'insensitive' } },
              { vendor: { contains: search, mode: 'insensitive' } },
            ],
          }
        : {}),
    };
    const skip = (query.page - 1) * query.limit;
    const [total, items] = await this.database.$transaction([
      this.database.devicePackage.count({ where }),
      this.database.devicePackage.findMany({
        where,
        skip,
        take: query.limit,
        orderBy: [{ name: 'asc' }, { version: 'asc' }],
      }),
    ]);

    return {
      page: query.page,
      limit: query.limit,
      total,
      totalPages: Math.max(1, Math.ceil(total / query.limit)),
      items: items.map((item) => this.mapDevicePackage(item)),
    };
  }

  private mapDevicePackage(item: {
    id: string;
    deviceId: string;
    syncRunId: string | null;
    wazuhAgentId: string;
    packageKey: string;
    name: string;
    version: string | null;
    vendor: string | null;
    architecture: string | null;
    packageType: string | null;
    description: string | null;
    sizeBytes: bigint | null;
    sourceIndex: string | null;
    sourceDocumentId: string | null;
    firstSeenAt: Date;
    lastSeenAt: Date;
    lastScannedAt: Date;
    rawPayload: Prisma.JsonValue | null;
    createdAt: Date;
    updatedAt: Date;
  }) {
    return {
      ...item,
      sizeBytes: item.sizeBytes?.toString() ?? null,
    };
  }

  private async listVulnerabilities(
    where: Prisma.DetectedVulnerabilityWhereInput,
    page: number,
    limit: number,
  ) {
    const skip = (page - 1) * limit;
    const [total, items] = await this.database.$transaction([
      this.database.detectedVulnerability.count({ where }),
      this.database.detectedVulnerability.findMany({
        where,
        skip,
        take: limit,
        orderBy: [{ cvssBaseScore: 'desc' }, { lastSeenAt: 'desc' }],
        include: this.vulnerabilityInclude(),
      }),
    ]);

    return {
      page,
      limit,
      total,
      totalPages: Math.max(1, Math.ceil(total / limit)),
      items: items.map((item) => this.mapVulnerability(item)),
    };
  }

  private async listSyncRuns(
    where: Prisma.SyncRunWhereInput,
    page: number,
    limit: number,
  ) {
    const skip = (page - 1) * limit;
    const [total, items] = await this.database.$transaction([
      this.database.syncRun.count({ where }),
      this.database.syncRun.findMany({
        where,
        skip,
        take: limit,
        orderBy: { startedAt: 'desc' },
        include: {
          device: {
            select: {
              id: true,
              hostname: true,
              user: { select: { id: true, email: true, fullName: true } },
            },
          },
          source: { select: { id: true, code: true, name: true } },
        },
      }),
    ]);

    return {
      page,
      limit,
      total,
      totalPages: Math.max(1, Math.ceil(total / limit)),
      items: items.map((run) => this.mapSyncRun(run)),
    };
  }

  private vulnerabilityWhere(
    query: ListVulnerabilitiesQueryDto,
    userId?: string,
  ): Prisma.DetectedVulnerabilityWhereInput {
    const search = query.query?.trim();
    return {
      ...(userId ? { device: { userId } } : {}),
      ...(query.deviceId ? { deviceId: query.deviceId } : {}),
      ...(query.ownerId && !userId ? { device: { userId: query.ownerId } } : {}),
      ...(query.status ? { status: query.status } : {}),
      ...(query.severity ? { severity: query.severity } : {}),
      ...(search
        ? {
            OR: [
              { cveId: { contains: search.toUpperCase(), mode: 'insensitive' } },
              { packageName: { contains: search, mode: 'insensitive' } },
              {
                device: {
                  hostname: { contains: search, mode: 'insensitive' },
                },
              },
              {
                cve: {
                  description: { contains: search, mode: 'insensitive' },
                },
              },
            ],
          }
        : {}),
    };
  }

  private vulnerabilityInclude() {
    return {
      device: {
        select: {
          id: true,
          hostname: true,
          operatingSystem: true,
          architecture: true,
          status: true,
          user: { select: { id: true, fullName: true, email: true } },
          wazuhBinding: {
            select: { wazuhAgentId: true, lastKnownStatus: true },
          },
        },
      },
      featureVector: true,
      aiPrediction: true,
      predictionHistory: {
        take: 5,
        orderBy: { predictedAt: 'desc' as const },
      },
      cve: {
        include: {
          cvssMetrics: { take: 3, orderBy: { ingestedAt: 'desc' as const } },
          threatSignals: {
            take: 1,
            orderBy: { signalDate: 'desc' as const },
          },
          references: { take: 20 },
          affectedProducts: { take: 20 },
          cveCwes: { include: { cwe: true } },
        },
      },
    } as const;
  }

  private mapVulnerability(item: {
    id: string;
    cveId: string;
    packageName: string | null;
    packageVersion: string | null;
    packageArchitecture: string | null;
    packageVendor: string | null;
    packageType: string | null;
    status: VulnerabilityLifecycleStatus;
    sourceStatus: string | null;
    severity: string | null;
    cvssBaseScore: number | null;
    firstSeenAt: Date;
    lastSeenAt: Date;
    resolvedAt: Date | null;
    detectedAt: Date | null;
    publishedAt: Date | null;
    sourceIndex: string;
    sourceDocumentId: string;
    sourceUpdatedAt: Date | null;
    featureVector: {
      id: string;
      modelInputVersion: string;
      baseScore: number | null;
      severity: string | null;
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
      featureHash: string;
      rawFeatures: Prisma.JsonValue;
      createdAt: Date;
      updatedAt: Date;
    } | null;
    aiPrediction: {
      id: string;
      modelVersion: string;
      attackProbability: number;
      predictedPercentile: number | null;
      riskLevel: string;
      explanation: Prisma.JsonValue | null;
      predictedAt: Date;
      createdAt: Date;
      updatedAt: Date;
    } | null;
    predictionHistory: Array<{
      id: string;
      modelVersion: string;
      attackProbability: number;
      predictedPercentile: number | null;
      riskLevel: string;
      featureHash: string | null;
      predictedAt: Date;
      createdAt: Date;
      detectedVulnerabilityId: string;
      deviceId: string;
      cveId: string;
      wazuhAgentId: string;
    }>;
    device: {
      id: string;
      hostname: string;
      operatingSystem: string;
      architecture: string | null;
      status: string;
      user: { id: string; fullName: string; email: string };
      wazuhBinding: {
        wazuhAgentId: string;
        lastKnownStatus: string | null;
      } | null;
    };
    cve: {
      description: string | null;
      publishedAt: Date | null;
      modifiedAt: Date | null;
      cvssMetrics: Array<{
        id: string;
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
        publishedAt: Date | null;
        ingestedAt: Date;
        createdAt: Date;
        updatedAt: Date;
        cveId: string;
      }>;
      threatSignals: Array<{
        id: string;
        cveId: string;
        signalDate: Date;
        epssScore: number | null;
        epssPercentile: number | null;
        isKnownExploited: boolean;
        kevDateAdded: Date | null;
        exploitEvidence: Prisma.JsonValue | null;
        sourceVersions: Prisma.JsonValue | null;
        ingestedAt: Date;
        createdAt: Date;
        updatedAt: Date;
      }>;
      references: Array<{
        id: string;
        cveId: string;
        url: string;
        urlHash: string;
        source: string;
        tags: Prisma.JsonValue | null;
        createdAt: Date;
      }>;
      affectedProducts: Array<{
        id: string;
        cveId: string;
        fingerprint: string;
        vendor: string | null;
        product: string | null;
        cpeUri: string | null;
        versionStartIncluding: string | null;
        versionStartExcluding: string | null;
        versionEndIncluding: string | null;
        versionEndExcluding: string | null;
        versionCriteria: Prisma.JsonValue | null;
        source: string;
        createdAt: Date;
        updatedAt: Date;
      }>;
      cveCwes: Array<{
        cwe: {
          cweId: string;
          name: string | null;
          description: string | null;
          source: string;
          modifiedAt: Date | null;
          createdAt: Date;
          updatedAt: Date;
        };
      }>;
    };
  }) {
    const cvssMetrics = [...item.cve.cvssMetrics].sort((left, right) =>
      this.cvssMetricRank(right) - this.cvssMetricRank(left),
    );
    const preferredCvssMetric = cvssMetrics[0] ?? null;
    const cve = {
      ...item.cve,
      cvssMetrics,
    };

    return {
      id: item.id,
      cveId: item.cveId,
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
      firstSeenAt: item.firstSeenAt,
      lastSeenAt: item.lastSeenAt,
      syncSeenAt: item.lastSeenAt,
      sourceUpdatedAt: item.sourceUpdatedAt,
      wazuhRecordTime:
        item.detectedAt ??
        item.sourceUpdatedAt ??
        item.publishedAt ??
        item.lastSeenAt,
      resolvedAt: item.resolvedAt,
      publishedAt: item.publishedAt ?? item.cve.publishedAt,
      device: item.device,
      cve,
      cvssVector: {
        source: preferredCvssMetric?.source ?? null,
        metricType: preferredCvssMetric?.metricType ?? null,
        cvssVersion: preferredCvssMetric?.cvssVersion ?? null,
        vectorString: preferredCvssMetric?.vectorString ?? null,
        attackVector: item.featureVector?.attackVector ?? preferredCvssMetric?.attackVector ?? null,
        attackComplexity: item.featureVector?.attackComplexity ?? preferredCvssMetric?.attackComplexity ?? null,
        privilegesRequired: item.featureVector?.privilegesRequired ?? preferredCvssMetric?.privilegesRequired ?? null,
        userInteraction: item.featureVector?.userInteraction ?? preferredCvssMetric?.userInteraction ?? null,
        scope: item.featureVector?.scope ?? preferredCvssMetric?.scope ?? null,
        confidentialityImpact: item.featureVector?.confidentialityImpact ?? preferredCvssMetric?.confidentialityImpact ?? null,
        integrityImpact: item.featureVector?.integrityImpact ?? preferredCvssMetric?.integrityImpact ?? null,
        availabilityImpact: item.featureVector?.availabilityImpact ?? preferredCvssMetric?.availabilityImpact ?? null,
        available: this.cvssMetricCompleteness(preferredCvssMetric) > 0,
      },
      featureVector: item.featureVector,
      aiPrediction: item.aiPrediction,
      predictionHistory: item.predictionHistory,
      latestThreatSignal: item.cve.threatSignals[0] ?? null,
    };
  }

  private cvssMetricRank(metric: {
    source: string;
    vectorString: string | null;
    baseScore: number | null;
    attackVector: string | null;
    attackComplexity: string | null;
    privilegesRequired: string | null;
    userInteraction: string | null;
    scope: string | null;
    confidentialityImpact: string | null;
    integrityImpact: string | null;
    availabilityImpact: string | null;
    ingestedAt: Date;
  }): number {
    const sourceWeight = metric.source === 'CYRP_CTI_CSV'
      ? 1_000
      : metric.source === 'NVD'
        ? 900
        : metric.source === 'WAZUH'
          ? 100
          : 0;
    const completeness = this.cvssMetricCompleteness(metric);
    const baseScoreWeight = metric.baseScore !== null ? 10 : 0;
    const freshnessWeight = Math.trunc(metric.ingestedAt.getTime() / 86_400_000) / 1_000_000;
    return sourceWeight + completeness * 20 + baseScoreWeight + freshnessWeight;
  }

  private cvssMetricCompleteness(metric: {
    vectorString: string | null;
    attackVector: string | null;
    attackComplexity: string | null;
    privilegesRequired: string | null;
    userInteraction: string | null;
    scope: string | null;
    confidentialityImpact: string | null;
    integrityImpact: string | null;
    availabilityImpact: string | null;
  } | null): number {
    if (!metric) {
      return 0;
    }
    return [
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
  }

  private async groupSeverity(where: Prisma.DetectedVulnerabilityWhereInput) {
    const rows = await this.database.detectedVulnerability.groupBy({
      by: ['severity'],
      where,
      _count: { _all: true },
    });
    const counts: Record<string, number> = {
      CRITICAL: 0,
      HIGH: 0,
      MEDIUM: 0,
      LOW: 0,
      UNKNOWN: 0,
    };

    for (const row of rows) {
      const key = row.severity?.toUpperCase() || 'UNKNOWN';
      counts[key] = (counts[key] ?? 0) + row._count._all;
    }

    return {
      total: Object.values(counts).reduce((sum, value) => sum + value, 0),
      counts,
    };
  }

  private mapContextSnapshot<T extends {
    packages: Prisma.JsonValue | null;
    hotfixes: Prisma.JsonValue | null;
    ports: Prisma.JsonValue | null;
    processes: Prisma.JsonValue | null;
    services: Prisma.JsonValue | null;
  }>(snapshot: T | null, limit = 50) {
    if (!snapshot) {
      return null;
    }

    const values = {
      packages: this.jsonArray(snapshot.packages),
      hotfixes: this.jsonArray(snapshot.hotfixes),
      ports: this.jsonArray(snapshot.ports),
      processes: this.jsonArray(snapshot.processes),
      services: this.jsonArray(snapshot.services),
    };

    return {
      ...snapshot,
      packages: values.packages.slice(0, limit),
      hotfixes: values.hotfixes.slice(0, limit),
      ports: values.ports.slice(0, limit),
      processes: values.processes.slice(0, limit),
      services: values.services.slice(0, limit),
      preview: {
        limit,
        stored: Object.fromEntries(
          Object.entries(values).map(([key, items]) => [key, items.length]),
        ),
        returned: Object.fromEntries(
          Object.entries(values).map(([key, items]) => [
            key,
            Math.min(items.length, limit),
          ]),
        ),
        truncated: Object.fromEntries(
          Object.entries(values).map(([key, items]) => [
            key,
            items.length > limit,
          ]),
        ),
      },
    };
  }

  private jsonArray(value: Prisma.JsonValue | null): Prisma.JsonValue[] {
    return Array.isArray(value) ? value : [];
  }

  private contextHistorySelect() {
    return {
      id: true,
      observedAt: true,
      asOfTime: true,
      agentStatus: true,
      agentIp: true,
      hostname: true,
      osName: true,
      osVersion: true,
      osFull: true,
      architecture: true,
      packageCount: true,
      hotfixCount: true,
      portCount: true,
      listeningPortCount: true,
      processCount: true,
      serviceCount: true,
      completeness: true,
      sourceVersions: true,
    } as const;
  }

  private contextSummarySelect() {
    return {
      id: true,
      asOfTime: true,
      agentStatus: true,
      packageCount: true,
      hotfixCount: true,
      portCount: true,
      listeningPortCount: true,
      processCount: true,
      serviceCount: true,
      completeness: true,
    } as const;
  }

  private mapSyncRun(run: {
    id: string;
    deviceId: string | null;
    sourceType: string;
    status: string;
    trigger: string;
    sourceVersion: string | null;
    recordsRead: number;
    recordsWritten: number;
    recordsUpdated: number;
    recordsResolved: number;
    recordsRejected: number;
    startedAt: Date;
    completedAt: Date | null;
    errorSummary: string | null;
    checkpointAfter: Prisma.JsonValue | null;
    device?: {
      id: string;
      hostname: string;
      user?: { id: string; email: string; fullName: string };
    } | null;
    source?: { id: string; code: string; name: string } | null;
  }) {
    return {
      id: run.id,
      deviceId: run.deviceId,
      device: run.device ?? null,
      sourceType: run.sourceType,
      status: run.status,
      trigger: run.trigger,
      sourceVersion: run.sourceVersion,
      recordsRead: run.recordsRead,
      recordsWritten: run.recordsWritten,
      recordsUpdated: run.recordsUpdated,
      recordsResolved: run.recordsResolved,
      recordsRejected: run.recordsRejected,
      startedAt: run.startedAt,
      completedAt: run.completedAt,
      errorSummary: run.errorSummary,
      checkpointAfter: run.checkpointAfter,
      source: run.source ?? null,
    };
  }

  private async assertUserDevice(userId: string, deviceId: string) {
    const device = await this.database.device.findFirst({
      where: { id: deviceId, userId },
      select: { id: true },
    });
    if (!device) {
      throw this.deviceNotFound();
    }
  }

  private deviceNotFound() {
    return new NotFoundException({
      code: 'DEVICE_NOT_FOUND',
      message: 'Không tìm thấy thiết bị hoặc bạn không có quyền truy cập',
    });
  }

  private async captureStatus(operation: () => Promise<unknown>) {
    try {
      return await operation();
    } catch (error: unknown) {
      return {
        connected: false,
        checkedAt: new Date().toISOString(),
        error: error instanceof Error ? error.message : 'Không thể kiểm tra',
      };
    }
  }
}
