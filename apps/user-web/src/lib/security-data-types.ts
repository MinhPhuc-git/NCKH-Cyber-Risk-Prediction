export interface Pagination<T> {
  page: number;
  limit: number;
  total: number;
  totalPages: number;
  items: T[];
}

export type VulnerabilityStatus =
  | 'ACTIVE'
  | 'RESOLVED'
  | 'UNDER_EVALUATION'
  | 'UNKNOWN';

export interface DevicePackageItem {
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
  sizeBytes: string | null;
  sourceIndex: string | null;
  sourceDocumentId: string | null;
  firstSeenAt: string;
  lastSeenAt: string;
  syncSeenAt?: string | null;
  sourceUpdatedAt?: string | null;
  wazuhRecordTime?: string | null;
  lastScannedAt: string;
  rawPayload?: unknown;
  createdAt: string;
  updatedAt: string;
}

export interface VulnerabilityFeatureVector {
  id: string;
  modelInputVersion: string;
  baseScore: number | null;
  severity: string | null;
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
  rawFeatures: unknown;
  createdAt: string;
  updatedAt: string;
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
  systemInventory?: unknown;
  hardware?: unknown;
  completeness: Record<string, unknown> | null;
  sourceVersions?: Record<string, unknown> | null;
}

export interface WazuhBindingSummary {
  wazuhAgentId: string;
  wazuhAgentName?: string;
  lastKnownStatus: string | null;
  lastKeepAliveAt: string | null;
  lastSynchronizedAt: string;
}

export interface VulnerabilityItem {
  id: string;
  cveId: string;
  packageName: string | null;
  packageVersion: string | null;
  packageArchitecture: string | null;
  packageVendor: string | null;
  packageType: string | null;
  status: VulnerabilityStatus;
  sourceStatus: string | null;
  severity: string | null;
  cvssBaseScore: number | null;
  detectedAt: string | null;
  firstSeenAt: string;
  lastSeenAt: string;
  syncSeenAt?: string | null;
  sourceUpdatedAt?: string | null;
  wazuhRecordTime?: string | null;
  resolvedAt: string | null;
  publishedAt: string | null;
  device: {
    id: string;
    hostname: string;
    operatingSystem: string;
    architecture: string | null;
    status: string;
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
    references?: Array<{
      id: string;
      url: string;
      source: string;
    }>;
    affectedProducts?: Array<{
      id: string;
      vendor: string | null;
      product: string | null;
      cpeUri: string | null;
      source: string;
    }>;
    cveCwes?: Array<{
      cwe: {
        cweId: string;
        name: string | null;
        description: string | null;
      };
    }>;
  };
  featureVector: VulnerabilityFeatureVector | null;
  aiPrediction: AiPrediction | null;
  predictionHistory: PredictionHistoryItem[];
  latestThreatSignal: {
    signalDate: string;
    epssScore: number | null;
    epssPercentile: number | null;
    isKnownExploited: boolean;
    kevDateAdded?: string | null;
  } | null;
}

export interface VulnerabilityDetail extends VulnerabilityItem {
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
  checkpointAfter?: unknown;
  device: {
    id: string;
    hostname: string;
  } | null;
  source?: {
    id: string;
    code: string;
    name: string;
  } | null;
}

export interface UserDataOverview {
  calculatedAt: string;
  devices: {
    total: number;
    active: number;
    stale: number;
    items: Array<{
      id: string;
      hostname: string;
      operatingSystem: string;
      status: string;
      lastSeenAt: string | null;
      activeVulnerabilities: number;
      latestContext: EndpointContextSnapshot | null;
      wazuhBinding: WazuhBindingSummary | null;
    }>;
  };
  vulnerabilities: {
    active: number;
    severity: Record<string, number>;
    top: VulnerabilityItem[];
  };
  recentRuns: SyncRunItem[];
  scopeNote: string;
}

export interface DeviceOverview {
  id: string;
  hostname: string;
  operatingSystem: string;
  architecture: string | null;
  agentVersion: string;
  status: string;
  lastSeenAt: string | null;
  createdAt: string;
  updatedAt: string;
  wazuhBinding: WazuhBindingSummary | null;
  latestContext: EndpointContextSnapshot | null;
  syncRuns: SyncRunItem[];
  vulnerabilitySummary: {
    active: number;
    resolved: number;
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

export interface FullSyncResult {
  deviceId: string;
  hostname: string;
  wazuhAgentId: string;
  status: 'COMPLETED' | 'PARTIAL' | 'FAILED';
  startedAt: string;
  completedAt: string;
  components: Record<
    string,
    {
      status: 'COMPLETED' | 'PARTIAL' | 'FAILED';
      message: string;
      data?: unknown;
    }
  >;
}
