export interface Pagination<T> {
  page: number;
  limit: number;
  total: number;
  totalPages: number;
  items: T[];
}

export interface EndpointContextSnapshot {
  id: string;
  asOfTime: string;
  observedAt?: string;
  agentStatus: string | null;
  agentIp?: string | null;
  hostname?: string | null;
  osName?: string | null;
  osVersion?: string | null;
  osFull?: string | null;
  architecture?: string | null;
  packageCount: number;
  hotfixCount: number;
  portCount: number;
  listeningPortCount: number;
  processCount: number;
  serviceCount: number;
  packages?: unknown[] | null;
  hotfixes?: unknown[] | null;
  ports?: unknown[] | null;
  processes?: unknown[] | null;
  services?: unknown[] | null;
  preview?: {
    limit: number;
    stored: Record<string, number>;
    returned: Record<string, number>;
    truncated: Record<string, boolean>;
  };
  completeness: Record<string, unknown> | null;
}


export interface AiPrediction {
  id: string;
  modelVersion: string;
  attackProbability: number;
  predictedPercentile: number | null;
  riskLevel: string;
  explanation: unknown;
  predictedAt: string;
  createdAt: string;
  updatedAt: string;
}

export interface PredictionHistoryItem {
  id: string;
  modelVersion: string;
  attackProbability: number;
  predictedPercentile: number | null;
  riskLevel: string;
  featureHash: string | null;
  predictedAt: string;
  createdAt: string;
}

export interface VulnerabilityItem {
  id: string;
  cveId: string;
  packageName: string | null;
  packageVersion: string | null;
  packageArchitecture: string | null;
  packageVendor: string | null;
  packageType: string | null;
  status: 'ACTIVE' | 'RESOLVED' | 'UNDER_EVALUATION' | 'UNKNOWN';
  sourceStatus: string | null;
  severity: string | null;
  cvssBaseScore: number | null;
  detectedAt: string | null;
  firstSeenAt: string;
  lastSeenAt: string;
  resolvedAt: string | null;
  publishedAt: string | null;
  device: {
    id: string;
    hostname: string;
    operatingSystem: string;
    status: string;
    user?: { id: string; fullName: string; email: string };
    wazuhBinding?: {
      wazuhAgentId: string;
      lastKnownStatus: string | null;
    } | null;
  };
  cve: {
    description: string | null;
    publishedAt: string | null;
    modifiedAt: string | null;
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
    }>;
    threatSignals: Array<{
      signalDate: string;
      epssScore: number | null;
      epssPercentile: number | null;
      isKnownExploited: boolean;
      kevDateAdded?: string | null;
    }>;
  };
  aiPrediction: AiPrediction | null;
  predictionHistory?: PredictionHistoryItem[];
  latestThreatSignal: {
    signalDate: string;
    epssScore: number | null;
    epssPercentile: number | null;
    isKnownExploited: boolean;
    kevDateAdded?: string | null;
  } | null;
}

export interface SyncRunItem {
  id: string;
  deviceId: string | null;
  sourceType: string;
  status: string;
  trigger: string;
  sourceVersion: string | null;
  startedAt: string;
  completedAt: string | null;
  recordsRead: number;
  recordsWritten: number;
  recordsUpdated: number;
  recordsResolved: number;
  recordsRejected: number;
  errorSummary: string | null;
  device: {
    id: string;
    hostname: string;
    user?: { id: string; email: string; fullName: string };
  } | null;
  source?: { id: string; code: string; name: string } | null;
}

export interface AdminDeviceItem {
  id: string;
  hostname: string;
  operatingSystem: string;
  architecture: string | null;
  agentVersion: string;
  status: string;
  lastSeenAt: string | null;
  createdAt: string;
  user: {
    id: string;
    email: string;
    fullName: string;
    status: string;
  };
  wazuhBinding: {
    wazuhAgentId: string;
    wazuhAgentName: string;
    lastKnownStatus: string | null;
    lastKeepAliveAt: string | null;
    lastSynchronizedAt: string;
    lastStatusCheckedAt?: string | null;
    lastStatusError?: string | null;
    consecutiveStatusFailures?: number;
  } | null;
  latestContext: EndpointContextSnapshot | null;
  activeVulnerabilities: number;
}

export interface AdminDeviceDetail extends AdminDeviceItem {
  endpointContextSnapshots: EndpointContextSnapshot[];
  syncRuns: SyncRunItem[];
  vulnerabilitySummary: {
    active: number;
    severity: Record<string, number>;
  };
  securitySnapshot: {
    alertCount: number;
    criticalCount: number;
    highCount: number;
    mediumCount: number;
    lowCount: number;
    riskScore: number;
    riskLabel: string;
    calculatedAt: string;
    syncError: string | null;
  } | null;
}

export interface AdminDashboardData {
  calculatedAt: string;
  users: number;
  devices: number;
  bindings: number;
  vulnerabilities: {
    active: number;
    severity: Record<string, number>;
  };
  dataFoundation: {
    cves: number;
    endpointContextSnapshots: number;
  };
  sync: {
    failed: number;
    running: number;
    recent: SyncRunItem[];
  };
  sources: Array<{
    id: string;
    code: string;
    name: string;
    status: string;
    enabled: boolean;
    lastSuccessAt: string | null;
    lastError: string | null;
  }>;
  services: {
    database: { connected: boolean };
    wazuhApi: Record<string, unknown>;
    indexer: Record<string, unknown>;
    synchronization?: SynchronizationStatus;
    agentRuntime?: AgentRuntimeStatus;
    wazuhRuntime?: WazuhRuntimeConfiguration;
  };
}

export interface SynchronizationStatus {
  integrationEnabled: boolean;
  configured: boolean;
  enabled: boolean;
  running: boolean;
  intervalSeconds: number;
  maxConcurrency: number;
  staleRunMinutes: number;
  syncLock: {
    strategy: string;
    ttlSeconds: number;
    localActiveLeases: number;
    instanceId: string;
  };
}

export interface AgentRuntimeStatus {
  integrationEnabled: boolean;
  configured: boolean;
  enabled: boolean;
  running: boolean;
  intervalSeconds: number;
  maxConcurrency: number;
}

export interface WazuhRuntimeConfiguration {
  enabled: boolean;
  apiTimeoutMs: number;
  indexerTimeoutMs: number;
  retryAttempts: number;
  retryBaseDelayMs: number;
  statePageSize: number;
  stateMaxItems: number;
  maxResponseBytes: number;
}

export interface CtiSourcesResponse {
  totals: {
    cves: number;
    metrics: number;
    cwes: number;
    signals: number;
    products: number;
  };
  items: Array<{
    id: string;
    code: string;
    name: string;
    sourceType: string;
    description: string | null;
    status: string;
    enabled: boolean;
    lastAttemptAt: string | null;
    lastSuccessAt: string | null;
    lastError: string | null;
    syncRuns: SyncRunItem[];
  }>;
}

export interface SystemHealthResponse {
  checkedAt: string;
  responseTimeMs: number;
  dataSyncEnabled: boolean;
  synchronization: SynchronizationStatus;
  agentRuntime: AgentRuntimeStatus;
  wazuhRuntime: WazuhRuntimeConfiguration;
  database: Record<string, unknown>;
  wazuhApi: Record<string, unknown>;
  indexer: Record<string, unknown>;
  latestRuns: SyncRunItem[];
}

export interface WazuhAgentItem {
  id?: string;
  name?: string;
  ip?: string;
  status?: string;
  version?: string;
  node_name?: string;
  dateAdd?: string;
  lastKeepAlive?: string;
  group?: string[];
  os?: {
    name?: string;
    platform?: string;
    version?: string;
    arch?: string;
    uname?: string;
  };
}

export interface WazuhAgentsResponse {
  total: number;
  items: WazuhAgentItem[];
}

export interface WazuhStatusResponse {
  enabled: boolean;
  connected: boolean;
  checkedAt: string;
  manager: {
    name: string | null;
    version: string | null;
    type: string | null;
    uuid: string | null;
  } | null;
}

export interface AdminVulnerabilityDetail extends VulnerabilityItem {
  references: Array<{ id: string; url: string; source: string }>;
  affectedProducts: Array<{
    id: string;
    vendor: string | null;
    product: string | null;
    cpeUri: string | null;
    source: string;
  }>;
  cwes: Array<{
    cweId: string;
    name: string | null;
    description: string | null;
  }>;
  latestContext: EndpointContextSnapshot | null;
  source: {
    index: string;
    documentId: string;
    updatedAt: string | null;
    syncRun: SyncRunItem | null;
  };
}
