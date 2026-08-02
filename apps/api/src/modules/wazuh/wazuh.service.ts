import {
  Injectable,
  Logger,
  NotFoundException,
  ServiceUnavailableException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
  request as httpRequest,
  type IncomingMessage,
  type RequestOptions,
} from 'node:http';
import {
  request as httpsRequest,
} from 'node:https';

import type {
  WazuhAgentEnrollmentEnvelope,
  WazuhAgentProvisioning,
  WazuhAgentProtocol,
  WazuhAgentSummary,
  WazuhAlertAnalytics,
  WazuhApiEnvelope,
  WazuhIndexerHit,
  WazuhIndexerSearchResponse,
  WazuhHardwareInfo,
  WazuhInventoryCounts,
  WazuhInventoryCategory,
  WazuhInventoryStateSource,
  WazuhManagerInfo,
  WazuhStateCollection,
  WazuhStateSearchResponse,
  WazuhVulnerabilityStateSource,
} from './wazuh.types';

interface RawHttpResponse {
  statusCode: number;
  body: string;
}

interface EndpointSettings {
  baseUrl: string;
  username: string;
  password: string;
  rejectUnauthorized: boolean;
  timeoutMs: number;
}

@Injectable()
export class WazuhService {
  private readonly logger =
    new Logger(WazuhService.name);
  private readonly enabled: boolean;
  private readonly api: EndpointSettings;
  private readonly indexer: EndpointSettings;
  private readonly tokenTtlSeconds: number;
  private readonly alertSampleLimit: number;
  private readonly statePageSize: number;
  private readonly stateMaxItems: number;
  private readonly maxResponseBytes: number;
  private readonly retryAttempts: number;
  private readonly retryBaseDelayMs: number;
  private readonly managerAddress: string;
  private readonly managerPort: number;
  private readonly managerProtocol: WazuhAgentProtocol;
  private cachedToken: string | null = null;
  private tokenExpiresAtMs = 0;

  constructor(
    config: ConfigService,
  ) {
    this.enabled = this.booleanValue(
      config.get<unknown>('WAZUH_INTEGRATION_ENABLED'),
      false,
      'WAZUH_INTEGRATION_ENABLED',
    );

    this.api = this.enabled
      ? this.endpointSettings(
          config,
          'WAZUH_API',
          10_000,
        )
      : this.disabledEndpoint();

    this.indexer = this.enabled
      ? this.endpointSettings(
          config,
          'WAZUH_INDEXER',
          15_000,
        )
      : this.disabledEndpoint();

    this.tokenTtlSeconds =
      this.positiveInteger(
        config.get<unknown>(
          'WAZUH_API_TOKEN_TTL_SECONDS',
        ),
        900,
        'WAZUH_API_TOKEN_TTL_SECONDS',
      );

    this.alertSampleLimit =
      this.positiveInteger(
        config.get<unknown>(
          'WAZUH_ALERT_SAMPLE_LIMIT',
        ),
        10,
        'WAZUH_ALERT_SAMPLE_LIMIT',
      );

    this.statePageSize =
      this.positiveInteger(
        config.get<unknown>(
          'WAZUH_STATE_PAGE_SIZE',
        ),
        250,
        'WAZUH_STATE_PAGE_SIZE',
      );

    this.stateMaxItems =
      this.positiveInteger(
        config.get<unknown>(
          'WAZUH_STATE_MAX_ITEMS_PER_CATEGORY',
        ),
        5_000,
        'WAZUH_STATE_MAX_ITEMS_PER_CATEGORY',
      );

    this.maxResponseBytes =
      this.positiveInteger(
        config.get<unknown>(
          'WAZUH_MAX_RESPONSE_BYTES',
        ),
        10 * 1024 * 1024,
        'WAZUH_MAX_RESPONSE_BYTES',
      );

    this.retryAttempts =
      this.boundedInteger(
        config.get<unknown>('WAZUH_REQUEST_RETRY_ATTEMPTS'),
        3,
        1,
        5,
        'WAZUH_REQUEST_RETRY_ATTEMPTS',
      );

    this.retryBaseDelayMs =
      this.boundedInteger(
        config.get<unknown>('WAZUH_REQUEST_RETRY_BASE_DELAY_MS'),
        250,
        50,
        5_000,
        'WAZUH_REQUEST_RETRY_BASE_DELAY_MS',
      );

    this.managerAddress =
      config.get<string>(
        'WAZUH_AGENT_MANAGER_ADDRESS',
      )?.trim() ||
      new URL(this.api.baseUrl).hostname;

    this.managerPort =
      this.portNumber(
        config.get<unknown>(
          'WAZUH_AGENT_MANAGER_PORT',
        ),
        1514,
        'WAZUH_AGENT_MANAGER_PORT',
      );

    this.managerProtocol =
      this.agentProtocol(
        config.get<string>(
          'WAZUH_AGENT_MANAGER_PROTOCOL',
        ),
      );
  }

  async getStatus() {
    if (!this.enabled) {
      return {
        enabled: false as const,
        connected: false as const,
        checkedAt: new Date().toISOString(),
        manager: null,
      };
    }

    try {
      const response =
        await this.authorizedApiJson<
          WazuhApiEnvelope<WazuhManagerInfo>
        >(
          'GET',
          '/manager/info',
        );

      const manager =
        response.data
          ?.affected_items?.[0];

      return {
        enabled: true as const,
        connected: true as const,
        checkedAt:
          new Date().toISOString(),
        manager: {
          name:
            manager?.name ?? null,
          version:
            manager?.version ?? null,
          type:
            manager?.type ?? null,
          uuid:
            manager?.uuid ?? null,
        },
      };
    } catch (error: unknown) {
      throw this.unavailable(error);
    }
  }

  async listAgents(
    limit: number,
  ) {
    try {
      const query =
        new URLSearchParams({
          limit: String(limit),
          sort: '-lastKeepAlive',
        });

      const response =
        await this.authorizedApiJson<
          WazuhApiEnvelope<WazuhAgentSummary>
        >(
          'GET',
          `/agents?${query.toString()}`,
        );

      const items =
        response.data
          ?.affected_items ?? [];

      return {
        total:
          response.data
            ?.total_affected_items ??
          items.length,
        items,
      };
    } catch (error: unknown) {
      throw this.unavailable(error);
    }
  }

  async getAgent(
    agentId: string,
  ): Promise<WazuhAgentSummary> {
    try {
      const query =
        new URLSearchParams({
          agents_list: agentId,
          limit: '1',
        });

      const response =
        await this.authorizedApiJson<
          WazuhApiEnvelope<WazuhAgentSummary>
        >(
          'GET',
          `/agents?${query.toString()}`,
        );

      const agent =
        response.data
          ?.affected_items?.find(
            (item) =>
              item.id === agentId,
          );

      if (!agent) {
        throw new NotFoundException({
          code:
            'WAZUH_AGENT_NOT_FOUND',
          message:
            `Không tìm thấy Wazuh Agent ${agentId}`,
        });
      }

      return agent;
    } catch (error: unknown) {
      if (
        error instanceof
          NotFoundException
      ) {
        throw error;
      }

      throw this.unavailable(error);
    }
  }

  async createAgent(
    agentName: string,
  ): Promise<WazuhAgentProvisioning> {
    const normalizedName =
      agentName.trim();

    if (
      !/^[A-Za-z0-9._-]{1,128}$/.test(
        normalizedName,
      )
    ) {
      throw new Error(
        'Wazuh Agent name is invalid',
      );
    }

    try {
      const response =
        await this.authorizedApiJson<
          WazuhAgentEnrollmentEnvelope
        >(
          'POST',
          '/agents?pretty=true',
          {
            name: normalizedName,
          },
        );

      const agentId =
        response.data?.id?.trim();
      const clientKey =
        response.data?.key?.trim();

      if (!agentId || !clientKey) {
        throw new Error(
          'Wazuh Agent enrollment response has no ID or client key',
        );
      }

      return {
        agentId,
        agentName: normalizedName,
        clientKey,
        managerAddress:
          this.managerAddress,
        managerPort:
          this.managerPort,
        protocol:
          this.managerProtocol,
      };
    } catch (error: unknown) {
      throw this.unavailable(error);
    }
  }

  async deleteAgent(
    agentId: string,
  ): Promise<void> {
    const normalizedId =
      agentId.trim();

    if (!/^\d{3,}$/.test(normalizedId)) {
      throw new Error(
        'Wazuh Agent ID is invalid',
      );
    }

    const query =
      new URLSearchParams({
        agents_list: normalizedId,
        older_than: '0s',
        status: 'all',
      });

    await this.authorizedApiJson<
      WazuhApiEnvelope<string>
    >(
      'DELETE',
      `/agents?${query.toString()}`,
    );
  }


  async getHardware(
    agentId: string,
  ): Promise<WazuhHardwareInfo | null> {
    const normalizedId =
      this.normalizedAgentId(agentId);

    try {
      const response =
        await this.authorizedApiJson<
          WazuhApiEnvelope<WazuhHardwareInfo>
        >(
          'GET',
          `/syscollector/${normalizedId}/hardware`,
        );

      return (
        response.data
          ?.affected_items?.[0] ??
        null
      );
    } catch (error: unknown) {
      throw this.unavailable(error);
    }
  }

  async getInventoryCounts(
    agentId: string,
  ): Promise<WazuhInventoryCounts> {
    const normalizedId =
      this.normalizedAgentId(agentId);

    const [ports, packages] =
      await Promise.all([
        this.syscollectorCount(
          normalizedId,
          'ports',
        ),
        this.syscollectorCount(
          normalizedId,
          'packages',
        ),
      ]);

    return {
      ports,
      packages,
    };
  }

  private async syscollectorCount(
    agentId: string,
    property: 'ports' | 'packages',
  ): Promise<number> {
    try {
      const response =
        await this.authorizedApiJson<
          WazuhApiEnvelope<unknown>
        >(
          'GET',
          `/syscollector/${agentId}/${property}?limit=1`,
        );

      return (
        response.data
          ?.total_affected_items ?? 0
      );
    } catch (error: unknown) {
      this.loggerWarning(
        `Unable to read Wazuh syscollector ${property} for agent ${agentId}: ${this.errorText(error)}`,
      );
      return 0;
    }
  }

  private normalizedAgentId(
    agentId: string,
  ): string {
    const normalizedId = agentId.trim();

    if (!/^\d{3,}$/.test(normalizedId)) {
      throw new Error(
        'Wazuh Agent ID is invalid',
      );
    }

    return normalizedId;
  }

  private loggerWarning(
    message: string,
  ): void {
    // Keep inventory failures non-fatal for dashboard snapshots.
    this.logger.warn(message);
  }

  private errorText(
    error: unknown,
  ): string {
    return error instanceof Error
      ? error.message
      : 'Unknown Wazuh error';
  }

  isIntegrationEnabled(): boolean {
    return this.enabled;
  }

  getRuntimeConfiguration() {
    return {
      enabled: this.enabled,
      apiTimeoutMs: this.api.timeoutMs,
      indexerTimeoutMs: this.indexer.timeoutMs,
      retryAttempts: this.retryAttempts,
      retryBaseDelayMs: this.retryBaseDelayMs,
      statePageSize: this.statePageSize,
      stateMaxItems: this.stateMaxItems,
      maxResponseBytes: this.maxResponseBytes,
    };
  }

  async getIndexerStatus() {
    if (!this.enabled) {
      return {
        enabled: false as const,
        connected: false as const,
        checkedAt: new Date().toISOString(),
        cluster: null,
      };
    }

    try {
      const cluster = await this.indexerJson<{
        cluster_name?: string;
        status?: string;
        number_of_nodes?: number;
        active_primary_shards?: number;
        active_shards?: number;
      }>(
        'GET',
        '/_cluster/health?filter_path=cluster_name,status,number_of_nodes,active_primary_shards,active_shards',
      );

      return {
        enabled: true as const,
        connected: true as const,
        checkedAt: new Date().toISOString(),
        cluster: {
          name: cluster.cluster_name ?? null,
          status: cluster.status ?? null,
          nodes: cluster.number_of_nodes ?? null,
          primaryShards: cluster.active_primary_shards ?? null,
          activeShards: cluster.active_shards ?? null,
        },
      };
    } catch (error: unknown) {
      throw this.unavailable(error);
    }
  }

  async getVulnerabilityStates(
    agentId: string,
    limit = this.stateMaxItems,
  ): Promise<
    WazuhStateCollection<WazuhVulnerabilityStateSource>
  > {
    return this.collectStateDocuments(
      'wazuh-states-vulnerabilities-*',
      this.normalizedAgentId(agentId),
      limit,
    );
  }

  async getInventoryState(
    agentId: string,
    category: WazuhInventoryCategory,
    limit = this.stateMaxItems,
  ): Promise<
    WazuhStateCollection<WazuhInventoryStateSource>
  > {
    const patternByCategory: Record<
      WazuhInventoryCategory,
      string
    > = {
      hardware:
        'wazuh-states-inventory-hardware-*',
      hotfixes:
        'wazuh-states-inventory-hotfixes-*',
      packages:
        'wazuh-states-inventory-packages-*',
      ports:
        'wazuh-states-inventory-ports-*',
      processes:
        'wazuh-states-inventory-processes-*',
      system:
        'wazuh-states-inventory-system-*',
      services:
        'wazuh-states-inventory-services-*',
    };

    return this.collectStateDocuments(
      patternByCategory[category],
      this.normalizedAgentId(agentId),
      limit,
    );
  }

  private async collectStateDocuments<TSource>(
    indexPattern: string,
    agentId: string,
    requestedLimit: number,
  ): Promise<WazuhStateCollection<TSource>> {
    const limit = Math.min(
      Math.max(1, Math.trunc(requestedLimit)),
      this.stateMaxItems,
    );

    const documents: WazuhStateCollection<TSource>['documents'] = [];
    let from = 0;
    let total = 0;
    let shardMetadataSeen = false;
    let shardTotal: number | null = null;
    let shardSuccessful: number | null = null;
    let shardFailed: number | null = null;

    while (documents.length < limit) {
      const size = Math.min(
        this.statePageSize,
        limit - documents.length,
      );

      const response =
        await this.indexerJson<
          WazuhStateSearchResponse<TSource>
        >(
          'POST',
          `/${indexPattern}/_search?ignore_unavailable=true&allow_no_indices=true`,
          {
            from,
            size,
            track_total_hits: true,
            sort: ['_doc'],
            query: {
              term: {
                'agent.id': agentId,
              },
            },
          },
        );

      if (response._shards) {
        shardMetadataSeen = true;
        shardTotal = response._shards.total ?? shardTotal;
        shardSuccessful = response._shards.successful ?? shardSuccessful;
        shardFailed = response._shards.failed ?? shardFailed;
      }

      const totalValue =
        response.hits?.total;

      total =
        typeof totalValue === 'number'
          ? totalValue
          : totalValue?.value ?? total;

      const hits =
        response.hits?.hits ?? [];

      for (const hit of hits) {
        if (
          !hit._index ||
          !hit._id ||
          !hit._source
        ) {
          continue;
        }

        documents.push({
          index: hit._index,
          id: hit._id,
          source: hit._source,
        });
      }

      if (hits.length < size) {
        break;
      }

      from += hits.length;
    }

    const indexAvailable = shardMetadataSeen
      ? (shardTotal ?? 0) > 0
      : true;

    return {
      total,
      truncated: total > documents.length,
      indexAvailable,
      shards: {
        total: shardTotal,
        successful: shardSuccessful,
        failed: shardFailed,
      },
      documents,
    };
  }

  async getEndpointStateBundle(
    agentId: string,
  ): Promise<{
    vulnerabilities: WazuhStateCollection<WazuhVulnerabilityStateSource>;
    hardware: WazuhStateCollection<WazuhInventoryStateSource>;
    hotfixes: WazuhStateCollection<WazuhInventoryStateSource>;
    packages: WazuhStateCollection<WazuhInventoryStateSource>;
    ports: WazuhStateCollection<WazuhInventoryStateSource>;
    processes: WazuhStateCollection<WazuhInventoryStateSource>;
    system: WazuhStateCollection<WazuhInventoryStateSource>;
    services: WazuhStateCollection<WazuhInventoryStateSource>;
  }> {
    const normalizedId =
      this.normalizedAgentId(agentId);

    const [
      vulnerabilities,
      hardware,
      hotfixes,
      packages,
      ports,
      processes,
      system,
      services,
    ] = await Promise.all([
      this.getVulnerabilityStates(normalizedId),
      this.getInventoryState(normalizedId, 'hardware'),
      this.getInventoryState(normalizedId, 'hotfixes'),
      this.getInventoryState(normalizedId, 'packages'),
      this.getInventoryState(normalizedId, 'ports'),
      this.getInventoryState(normalizedId, 'processes'),
      this.getInventoryState(normalizedId, 'system'),
      this.getInventoryState(normalizedId, 'services'),
    ]);

    return {
      vulnerabilities,
      hardware,
      hotfixes,
      packages,
      ports,
      processes,
      system,
      services,
    };
  }

  async analyzeAlerts(
    agentId: string,
    windowStart: Date,
    windowEnd: Date,
  ): Promise<WazuhAlertAnalytics> {
    try {
      const response =
        await this.indexerJson<
          WazuhIndexerSearchResponse
        >(
          'POST',
          '/wazuh-alerts-*/_search',
          {
            size:
              this.alertSampleLimit,
            track_total_hits: true,
            sort: [
              {
                timestamp: {
                  order: 'desc',
                },
              },
            ],
            _source: [
              'timestamp',
              'agent',
              'rule',
              'decoder',
              'location',
            ],
            query: {
              bool: {
                filter: [
                  {
                    term: {
                      'agent.id':
                        agentId,
                    },
                  },
                  {
                    range: {
                      timestamp: {
                        gte:
                          windowStart
                            .toISOString(),
                        lte:
                          windowEnd
                            .toISOString(),
                      },
                    },
                  },
                ],
              },
            },
            aggs: {
              max_rule_level: {
                max: {
                  field: 'rule.level',
                },
              },
              severity: {
                filters: {
                  filters: {
                    low: {
                      range: {
                        'rule.level': {
                          lt: 4,
                        },
                      },
                    },
                    medium: {
                      range: {
                        'rule.level': {
                          gte: 4,
                          lt: 8,
                        },
                      },
                    },
                    high: {
                      range: {
                        'rule.level': {
                          gte: 8,
                          lt: 12,
                        },
                      },
                    },
                    critical: {
                      range: {
                        'rule.level': {
                          gte: 12,
                        },
                      },
                    },
                  },
                },
              },
              top_rules: {
                terms: {
                  field: 'rule.id',
                  size: 10,
                },
                aggs: {
                  max_level: {
                    max: {
                      field: 'rule.level',
                    },
                  },
                  latest: {
                    top_hits: {
                      size: 1,
                      _source: [
                        'rule.description',
                      ],
                    },
                  },
                },
              },
            },
          },
        );

      return this.mapAlertAnalytics(
        response,
      );
    } catch (error: unknown) {
      throw this.unavailable(error);
    }
  }

  private mapAlertAnalytics(
    response:
      WazuhIndexerSearchResponse,
  ): WazuhAlertAnalytics {
    const totalValue =
      response.hits?.total;

    const total =
      typeof totalValue === 'number'
        ? totalValue
        : totalValue?.value ?? 0;

    const severityBuckets =
      response.aggregations
        ?.severity?.buckets ?? {};

    const topRules =
      response.aggregations
        ?.top_rules?.buckets ?? [];

    return {
      total,
      maxRuleLevel:
        this.nullableInteger(
          response.aggregations
            ?.max_rule_level?.value,
        ),
      severity: {
        low:
          severityBuckets['low']
            ?.doc_count ?? 0,
        medium:
          severityBuckets['medium']
            ?.doc_count ?? 0,
        high:
          severityBuckets['high']
            ?.doc_count ?? 0,
        critical:
          severityBuckets['critical']
            ?.doc_count ?? 0,
      },
      topRules:
        topRules.map((bucket) => {
          const source =
            bucket.latest?.hits
              ?.hits?.[0]?._source;

          return {
            ruleId:
              String(
                bucket.key ??
                  'unknown',
              ),
            description:
              source?.rule
                ?.description ??
              'Không có mô tả',
            count:
              bucket.doc_count ?? 0,
            maxLevel:
              this.nullableInteger(
                bucket.max_level
                  ?.value,
              ) ?? 0,
          };
        }),
      latestAlerts:
        (response.hits?.hits ?? [])
          .map((hit) =>
            this.mapAlertHit(hit),
          ),
    };
  }

  private mapAlertHit(
    hit: WazuhIndexerHit,
  ) {
    const source = hit._source;

    return {
      timestamp:
        source?.timestamp ?? null,
      ruleId:
        source?.rule?.id ?? null,
      level:
        typeof source?.rule
          ?.level === 'number'
          ? source.rule.level
          : null,
      description:
        source?.rule
          ?.description ?? null,
      groups:
        source?.rule?.groups ?? [],
      decoder:
        source?.decoder?.name ?? null,
      location:
        source?.location ?? null,
    };
  }

  private async authorizedApiJson<T>(
    method: string,
    path: string,
    body?: unknown,
    retry = true,
  ): Promise<T> {
    this.assertEnabled();

    const token =
      await this.getApiToken();

    const response =
      await this.requestRaw(
        this.api,
        method,
        path,
        {
          Accept:
            'application/json',
          Authorization:
            `Bearer ${token}`,
        },
        body,
        method === 'GET',
      );

    if (
      response.statusCode === 401 &&
      retry
    ) {
      this.cachedToken = null;
      this.tokenExpiresAtMs = 0;

      return this.authorizedApiJson<T>(
        method,
        path,
        body,
        false,
      );
    }

    return this.parseJsonResponse<T>(
      response,
      'Wazuh API',
    );
  }

  private async indexerJson<T>(
    method: string,
    path: string,
    body?: unknown,
  ): Promise<T> {
    this.assertEnabled();

    const basic =
      Buffer.from(
        `${this.indexer.username}:${this.indexer.password}`,
        'utf8',
      ).toString('base64');

    const response =
      await this.requestRaw(
        this.indexer,
        method,
        path,
        {
          Accept:
            'application/json',
          Authorization:
            `Basic ${basic}`,
        },
        body,
        true,
      );

    return this.parseJsonResponse<T>(
      response,
      'Wazuh Indexer',
    );
  }

  private async getApiToken():
    Promise<string> {
    if (
      this.cachedToken &&
      Date.now() <
        this.tokenExpiresAtMs
    ) {
      return this.cachedToken;
    }

    const basic =
      Buffer.from(
        `${this.api.username}:${this.api.password}`,
        'utf8',
      ).toString('base64');

    const response =
      await this.requestRaw(
        this.api,
        'POST',
        '/security/user/authenticate?raw=true',
        {
          Accept:
            'application/json',
          Authorization:
            `Basic ${basic}`,
        },
        undefined,
        true,
      );

    if (
      response.statusCode < 200 ||
      response.statusCode >= 300
    ) {
      throw new Error(
        `Wazuh authentication failed with HTTP ${response.statusCode}`,
      );
    }

    const token =
      this.extractToken(
        response.body,
      );

    this.cachedToken = token;
    this.tokenExpiresAtMs =
      Date.now() +
      this.tokenTtlSeconds *
        1000 -
      30_000;

    return token;
  }

  private extractToken(
    body: string,
  ): string {
    const trimmed = body.trim();

    if (!trimmed) {
      throw new Error(
        'Wazuh authentication returned an empty token',
      );
    }

    if (!trimmed.startsWith('{')) {
      return trimmed.replace(
        /^"|"$/g,
        '',
      );
    }

    const parsed =
      JSON.parse(trimmed) as {
        token?: string;
        data?: {
          token?: string;
        };
      };

    const token =
      parsed.token ??
      parsed.data?.token;

    if (!token) {
      throw new Error(
        'Wazuh authentication response has no token',
      );
    }

    return token;
  }

  private async requestRaw(
    endpoint: EndpointSettings,
    method: string,
    path: string,
    headers: Record<string, string>,
    body?: unknown,
    retryable = false,
  ): Promise<RawHttpResponse> {
    const attempts = retryable ? this.retryAttempts : 1;
    let lastError: unknown = null;

    for (let attempt = 1; attempt <= attempts; attempt += 1) {
      try {
        const response = await this.requestRawOnce(
          endpoint,
          method,
          path,
          headers,
          body,
        );

        if (
          retryable &&
          attempt < attempts &&
          this.isRetryableStatus(response.statusCode)
        ) {
          const delayMs = this.retryDelay(attempt);
          this.logger.warn(
            `Retrying Wazuh ${method} ${path} after HTTP ${response.statusCode} (attempt ${attempt + 1}/${attempts})`,
          );
          await this.delay(delayMs);
          continue;
        }

        return response;
      } catch (error: unknown) {
        lastError = error;

        if (!retryable || attempt >= attempts) {
          throw error;
        }

        const delayMs = this.retryDelay(attempt);
        this.logger.warn(
          `Retrying Wazuh ${method} ${path} after ${this.errorText(error)} (attempt ${attempt + 1}/${attempts})`,
        );
        await this.delay(delayMs);
      }
    }

    throw lastError instanceof Error
      ? lastError
      : new Error('Wazuh request failed');
  }

  private requestRawOnce(
    endpoint: EndpointSettings,
    method: string,
    path: string,
    headers: Record<string, string>,
    body?: unknown,
  ): Promise<RawHttpResponse> {
    const url = new URL(
      `${endpoint.baseUrl}${path}`,
    );

    const encodedBody =
      body === undefined
        ? undefined
        : Buffer.from(
            JSON.stringify(body),
            'utf8',
          );

    const options: RequestOptions = {
      method,
      headers: {
        ...headers,
        ...(encodedBody
          ? {
              'Content-Type':
                'application/json',
              'Content-Length':
                String(
                  encodedBody.length,
                ),
            }
          : {}),
      },
    };

    if (url.protocol === 'https:') {
      Object.assign(options, {
        rejectUnauthorized:
          endpoint
            .rejectUnauthorized,
      });
    }

    return new Promise(
      (resolve, reject) => {
        let settled = false;

        const safeReject = (
          error: Error,
        ): void => {
          if (settled) {
            return;
          }

          settled = true;
          reject(error);
        };

        const onResponse = (
          response: IncomingMessage,
        ): void => {
          const chunks: Buffer[] = [];
          let responseBytes = 0;

          response.on(
            'data',
            (
              chunk:
                Buffer | string,
            ) => {
              const buffer =
                Buffer.isBuffer(chunk)
                  ? chunk
                  : Buffer.from(
                      chunk,
                      'utf8',
                    );

              responseBytes +=
                buffer.length;

              if (
                responseBytes >
                this.maxResponseBytes
              ) {
                response.destroy();
                safeReject(
                  new Error(
                    `Wazuh response exceeded ${this.maxResponseBytes} bytes`,
                  ),
                );
                return;
              }

              chunks.push(buffer);
            },
          );

          response.on(
            'error',
            (error: Error) => {
              safeReject(error);
            },
          );

          response.on(
            'end',
            () => {
              if (settled) {
                return;
              }

              settled = true;
              resolve({
                statusCode:
                  response.statusCode ??
                  0,
                body:
                  Buffer.concat(
                    chunks,
                  ).toString('utf8'),
              });
            },
          );
        };

        const request =
          url.protocol === 'https:'
            ? httpsRequest(
                url,
                options,
                onResponse,
              )
            : httpRequest(
                url,
                options,
                onResponse,
              );

        request.setTimeout(
          endpoint.timeoutMs,
          () => {
            request.destroy(
              new Error(
                'Wazuh request timed out',
              ),
            );
          },
        );

        request.on(
          'error',
          (error: Error) => {
            safeReject(error);
          },
        );

        if (encodedBody) {
          request.write(
            encodedBody,
          );
        }

        request.end();
      },
    );
  }

  private isRetryableStatus(statusCode: number): boolean {
    return [408, 425, 429, 500, 502, 503, 504].includes(statusCode);
  }

  private retryDelay(attempt: number): number {
    return Math.min(
      5_000,
      this.retryBaseDelayMs * 2 ** Math.max(0, attempt - 1),
    );
  }

  private delay(milliseconds: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, milliseconds));
  }

  private parseJsonResponse<T>(
    response: RawHttpResponse,
    source: string,
  ): T {
    if (
      response.statusCode < 200 ||
      response.statusCode >= 300
    ) {
      throw new Error(
        `${source} returned HTTP ${response.statusCode}`,
      );
    }

    try {
      return JSON.parse(
        response.body,
      ) as T;
    } catch {
      throw new Error(
        `${source} returned invalid JSON`,
      );
    }
  }

  private unavailable(
    error: unknown,
  ): ServiceUnavailableException {
    this.logger.error(
      'Wazuh integration request failed',
      error instanceof Error
        ? error.stack ?? error.message
        : String(error),
    );

    return new ServiceUnavailableException({
      code:
        'WAZUH_INTEGRATION_UNAVAILABLE',
      message:
        'CYRP không thể truy cập Wazuh. Vui lòng thử lại sau.',
    });
  }

  private assertEnabled(): void {
    if (!this.enabled) {
      throw new Error(
        'Wazuh integration is disabled',
      );
    }
  }

  private disabledEndpoint(): EndpointSettings {
    return {
      baseUrl: 'http://127.0.0.1',
      username: 'disabled',
      password: 'disabled',
      rejectUnauthorized: true,
      timeoutMs: 1_000,
    };
  }

  private endpointSettings(
    config: ConfigService,
    prefix: 'WAZUH_API' | 'WAZUH_INDEXER',
    defaultTimeout: number,
  ): EndpointSettings {
    const baseUrl =
      this.required(
        config,
        `${prefix}_BASE_URL`,
      ).replace(/\/+$/, '');

    const parsed = new URL(baseUrl);

    if (
      parsed.protocol !== 'https:' &&
      parsed.protocol !== 'http:'
    ) {
      throw new Error(
        `${prefix}_BASE_URL must use http or https`,
      );
    }

    return {
      baseUrl,
      username:
        this.required(
          config,
          `${prefix}_USERNAME`,
        ),
      password:
        this.required(
          config,
          `${prefix}_PASSWORD`,
        ),
      rejectUnauthorized:
        this.booleanValue(
          config.get<unknown>(
            `${prefix}_REJECT_UNAUTHORIZED`,
          ),
          true,
          `${prefix}_REJECT_UNAUTHORIZED`,
        ),
      timeoutMs:
        this.positiveInteger(
          config.get<unknown>(
            `${prefix}_TIMEOUT_MS`,
          ),
          defaultTimeout,
          `${prefix}_TIMEOUT_MS`,
        ),
    };
  }

  private required(
    config: ConfigService,
    name: string,
  ): string {
    const value =
      config.get<string>(name)
        ?.trim();

    if (!value) {
      throw new Error(
        `Missing required environment variable: ${name}`,
      );
    }

    return value;
  }

  private positiveInteger(
    value: unknown,
    fallback: number,
    name: string,
  ): number {
    if (
      value === undefined ||
      value === null ||
      value === ''
    ) {
      return fallback;
    }

    const parsed =
      typeof value === 'number'
        ? value
        : typeof value === 'string'
          ? Number.parseInt(value, 10)
          : Number.NaN;

    if (
      !Number.isInteger(parsed) ||
      parsed <= 0
    ) {
      throw new Error(
        `${name} must be a positive integer`,
      );
    }

    return parsed;
  }

  private boundedInteger(
    value: unknown,
    fallback: number,
    min: number,
    max: number,
    name: string,
  ): number {
    if (value === undefined || value === null || value === '') {
      return fallback;
    }

    const parsed =
      typeof value === 'number'
        ? value
        : typeof value === 'string'
          ? Number.parseInt(value, 10)
          : Number.NaN;

    if (!Number.isInteger(parsed) || parsed < min || parsed > max) {
      throw new Error(`${name} must be between ${min} and ${max}`);
    }

    return parsed;
  }

  private booleanValue(
    value: unknown,
    fallback: boolean,
    name: string,
  ): boolean {
    if (
      value === undefined ||
      value === null ||
      value === ''
    ) {
      return fallback;
    }

    if (typeof value === 'boolean') {
      return value;
    }

    if (typeof value === 'string') {
      const normalized =
        value.trim().toLowerCase();

      if (normalized === 'true') {
        return true;
      }

      if (normalized === 'false') {
        return false;
      }
    }

    throw new Error(
      `${name} must be true or false`,
    );
  }

  private portNumber(
    value: unknown,
    fallback: number,
    name: string,
  ): number {
    const port = this.positiveInteger(
      value,
      fallback,
      name,
    );

    if (port > 65_535) {
      throw new Error(
        `${name} must be between 1 and 65535`,
      );
    }

    return port;
  }

  private agentProtocol(
    value: string | undefined,
  ): WazuhAgentProtocol {
    const normalized =
      value?.trim().toLowerCase() ??
      'tcp';

    if (
      normalized !== 'tcp' &&
      normalized !== 'udp'
    ) {
      throw new Error(
        'WAZUH_AGENT_MANAGER_PROTOCOL must be tcp or udp',
      );
    }

    return normalized;
  }

  private nullableInteger(
    value: number | null | undefined,
  ): number | null {
    return typeof value === 'number' &&
      Number.isFinite(value)
      ? Math.trunc(value)
      : null;
  }
}
