export interface SecurityTopRule {
  ruleId: string;
  description: string;
  count: number;
  maxLevel: number;
}

export interface SecurityAlert {
  timestamp: string | null;
  ruleId: string | null;
  level: number | null;
  description: string | null;
  groups: string[];
  decoder: string | null;
  location: string | null;
  deviceId?: string;
  hostname?: string;
}

export interface HardwareSnapshot {
  cpu: {
    cores?: number;
    mhz?: number;
    name?: string;
  } | null;
  ram: {
    free?: number;
    total?: number;
    usage?: number;
  } | null;
  scanTime: string | null;
}

export interface InventorySnapshot {
  ports: number;
  packages: number;
}

export interface DeviceSecuritySnapshot {
  id: string;
  deviceId: string;
  wazuhAgentId: string;
  agentName: string | null;
  agentStatus: string | null;
  agentIp: string | null;
  lastKeepAliveAt: string | null;
  windowMinutes: number;
  alertCount: number;
  maxRuleLevel: number | null;
  lowCount: number;
  mediumCount: number;
  highCount: number;
  criticalCount: number;
  riskScore: number;
  riskLabel: string;
  topRules: SecurityTopRule[];
  latestAlerts: SecurityAlert[];
  hardware: HardwareSnapshot | null;
  inventory: InventorySnapshot | null;
  calculatedAt: string;
  lastSuccessfulAt: string | null;
  syncError: string | null;
}

export interface OverviewDevice {
  deviceId: string;
  hostname: string;
  operatingSystem: string;
  architecture: string | null;
  deviceStatus: string;
  lastSeenAt: string | null;
  wazuhAgentId: string | null;
  wazuhAgentName: string | null;
  agentStatus: string | null;
  agentIp: string | null;
  lastKeepAliveAt: string | null;
  alertCount: number;
  maxRuleLevel: number | null;
  riskScore: number;
  riskLabel: string;
  low: number;
  medium: number;
  high: number;
  critical: number;
  calculatedAt: string | null;
  hardware: HardwareSnapshot | null;
  inventory: InventorySnapshot | null;
  topRules: SecurityTopRule[];
}

export interface SecurityOverview {
  calculatedAt: string | null;
  devices: {
    total: number;
    active: number;
    disconnected: number;
    pending: number;
  };
  alerts24h: {
    total: number;
    low: number;
    medium: number;
    high: number;
    critical: number;
    maxRuleLevel: number;
  };
  risk: {
    score: number;
    label: string;
    method: string;
    note: string;
  };
  primaryDevice: OverviewDevice | null;
  topDevices: OverviewDevice[];
  latestAlerts: SecurityAlert[];
}
