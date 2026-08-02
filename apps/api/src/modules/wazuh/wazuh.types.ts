export interface WazuhApiData<T> {
  affected_items?: T[];
  total_affected_items?: number;
  total_failed_items?: number;
  failed_items?: unknown[];
}

export interface WazuhApiEnvelope<T> {
  data?: WazuhApiData<T>;
  message?: string;
  error?: number;
}

export interface WazuhAgentEnrollmentData {
  id?: string;
  key?: string;
}

export interface WazuhAgentEnrollmentEnvelope {
  data?: WazuhAgentEnrollmentData;
  message?: string;
  error?: number;
}

export type WazuhAgentProtocol = 'tcp' | 'udp';

export interface WazuhAgentProvisioning {
  agentId: string;
  agentName: string;
  clientKey: string;
  managerAddress: string;
  managerPort: number;
  protocol: WazuhAgentProtocol;
}

export interface WazuhManagerInfo {
  name?: string;
  version?: string;
  type?: string;
  path?: string;
  uuid?: string;
}

export interface WazuhAgentOs {
  name?: string;
  platform?: string;
  version?: string;
  arch?: string;
  uname?: string;
}

export interface WazuhAgentSummary {
  id?: string;
  name?: string;
  ip?: string;
  status?: string;
  version?: string;
  node_name?: string;
  dateAdd?: string;
  lastKeepAlive?: string;
  group?: string[];
  os?: WazuhAgentOs;
}

export interface WazuhHardwareInfo {
  cpu?: {
    cores?: number;
    mhz?: number;
    name?: string;
  };
  ram?: {
    free?: number;
    total?: number;
    usage?: number;
  };
  scan?: {
    id?: number;
    time?: string;
  };
  board_serial?: string;
  agent_id?: string;
}

export interface WazuhInventoryCounts {
  ports: number;
  packages: number;
}

export interface WazuhAlertHitSource {
  timestamp?: string;
  agent?: {
    id?: string;
    name?: string;
    ip?: string;
  };
  rule?: {
    id?: string;
    level?: number;
    description?: string;
    groups?: string[];
  };
  decoder?: {
    name?: string;
  };
  location?: string;
}

export interface WazuhIndexerHit {
  _index?: string;
  _id?: string;
  _source?: WazuhAlertHitSource;
}

interface WazuhBucket {
  key?: string | number;
  doc_count?: number;
}

interface WazuhTopRuleBucket extends WazuhBucket {
  max_level?: {
    value?: number | null;
  };
  latest?: {
    hits?: {
      hits?: WazuhIndexerHit[];
    };
  };
}

export interface WazuhIndexerSearchResponse {
  hits?: {
    total?:
      | number
      | {
          value?: number;
          relation?: string;
        };
    hits?: WazuhIndexerHit[];
  };
  aggregations?: {
    max_rule_level?: {
      value?: number | null;
    };
    severity?: {
      buckets?: Record<string, WazuhBucket>;
    };
    top_rules?: {
      buckets?: WazuhTopRuleBucket[];
    };
  };
}

export interface WazuhAlertAnalytics {
  total: number;
  maxRuleLevel: number | null;
  severity: {
    low: number;
    medium: number;
    high: number;
    critical: number;
  };
  topRules: Array<{
    ruleId: string;
    description: string;
    count: number;
    maxLevel: number;
  }>;
  latestAlerts: Array<{
    timestamp: string | null;
    ruleId: string | null;
    level: number | null;
    description: string | null;
    groups: string[];
    decoder: string | null;
    location: string | null;
  }>;
}

export type WazuhStateSource = Record<string, unknown>;

export interface WazuhVulnerabilityStateSource extends WazuhStateSource {
  agent?: {
    id?: string;
    name?: string;
    type?: string;
    version?: string;
  };
  package?: {
    architecture?: string;
    description?: string;
    name?: string;
    size?: number;
    type?: string;
    vendor?: string;
    version?: string;
  };
  vulnerability?: {
    category?: string;
    classification?: string;
    description?: string;
    detected_at?: string;
    enumeration?: string;
    id?: string;
    published_at?: string;
    reference?: string | string[];
    severity?: string;
    status?: string;
    under_evaluation?: boolean;
    scanner?: {
      source?: string;
      vendor?: string;
    };
    score?: {
      base?: number;
      version?: string;
      vector?: string;
    };
  };
  wazuh?: {
    cluster?: {
      name?: string;
      node?: string;
    };
    schema?: {
      version?: string;
    };
  };
}

export interface WazuhInventoryStateSource extends WazuhStateSource {
  agent?: {
    id?: string;
    name?: string;
    version?: string;
  };
  host?: Record<string, unknown>;
  package?: Record<string, unknown>;
  process?: Record<string, unknown>;
  service?: Record<string, unknown>;
  network?: Record<string, unknown>;
  system?: Record<string, unknown>;
  hardware?: Record<string, unknown>;
  hotfix?: Record<string, unknown>;
  wazuh?: {
    schema?: {
      version?: string;
    };
  };
}

export type WazuhInventoryCategory =
  | 'hardware'
  | 'hotfixes'
  | 'packages'
  | 'ports'
  | 'processes'
  | 'services'
  | 'system';

export interface WazuhStateHit<TSource> {
  _index?: string;
  _id?: string;
  _source?: TSource;
}

export interface WazuhStateSearchResponse<TSource> {
  _shards?: {
    total?: number;
    successful?: number;
    skipped?: number;
    failed?: number;
    failures?: unknown[];
  };
  hits?: {
    total?:
      | number
      | {
          value?: number;
          relation?: string;
        };
    hits?: Array<WazuhStateHit<TSource>>;
  };
}

export interface WazuhStateDocument<TSource> {
  index: string;
  id: string;
  source: TSource;
}

export interface WazuhStateCollection<TSource> {
  total: number;
  truncated: boolean;
  indexAvailable: boolean;
  shards: {
    total: number | null;
    successful: number | null;
    failed: number | null;
  };
  documents: Array<WazuhStateDocument<TSource>>;
}
