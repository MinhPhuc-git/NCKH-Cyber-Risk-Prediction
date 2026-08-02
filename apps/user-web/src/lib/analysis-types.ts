export type AnalysisRunStatus =
  | 'QUEUED'
  | 'COLLECTING_EVENTS'
  | 'ANALYZING'
  | 'COMPLETED'
  | 'FAILED';

export interface AnalysisRunSummary {
  windowMinutes: number;
  agent: {
    id: string;
    name: string | null;
    ip: string | null;
    status: string | null;
    version: string | null;
    lastKeepAlive: string | null;
    os: {
      name?: string;
      platform?: string;
      version?: string;
      arch?: string;
      uname?: string;
    } | null;
  };
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

export interface AnalysisRun {
  id: string;
  deviceId: string;
  status: AnalysisRunStatus;
  windowStart: string;
  windowEnd: string;
  requestedAt: string;
  completedAt: string | null;
  eventCount: number;
  maxRuleLevel: number | null;
  summary: AnalysisRunSummary | null;
  errorMessage: string | null;
}
