import { createHash } from 'node:crypto';
import { VulnerabilityLifecycleStatus } from '@prisma/client';

import type {
  WazuhAgentSummary,
  WazuhInventoryStateSource,
  WazuhStateDocument,
  WazuhVulnerabilityStateSource,
} from '../wazuh/wazuh.types';

export interface NormalizedVulnerabilityState {
  sourceIndex: string;
  sourceDocumentId: string;
  cveId: string;
  description: string | null;
  packageName: string | null;
  packageVersion: string | null;
  packageArchitecture: string | null;
  packageVendor: string | null;
  packageType: string | null;
  status: VulnerabilityLifecycleStatus;
  sourceStatus: string | null;
  severity: string | null;
  cvssBaseScore: number | null;
  cvssVersion: string;
  vectorString: string | null;
  attackVector: string | null;
  attackComplexity: string | null;
  privilegesRequired: string | null;
  userInteraction: string | null;
  scope: string | null;
  confidentialityImpact: string | null;
  integrityImpact: string | null;
  availabilityImpact: string | null;
  detectedAt: Date | null;
  publishedAt: Date | null;
  sourceUpdatedAt: Date | null;
  references: string[];
  schemaVersion: string | null;
  rawPayload: Record<string, unknown>;
}

export interface NormalizedContextMetadata {
  hostname: string | null;
  osName: string | null;
  osVersion: string | null;
  osFull: string | null;
  architecture: string | null;
  schemaVersion: string | null;
}

export function normalizeVulnerabilityDocument(
  document: WazuhStateDocument<WazuhVulnerabilityStateSource>,
): NormalizedVulnerabilityState | null {
  const source = document.source;
  const cveId = firstString(source, [
    ['vulnerability', 'id'],
    ['vulnerability', 'cve'],
    ['cve', 'id'],
    ['id'],
  ])?.toUpperCase();

  if (!cveId || !/^CVE-\d{4}-\d{4,}$/i.test(cveId)) {
    return null;
  }

  const underEvaluation = firstBoolean(source, [
    ['vulnerability', 'under_evaluation'],
    ['vulnerability', 'underEvaluation'],
  ]);
  const sourceStatus = firstString(source, [
    ['vulnerability', 'status'],
    ['status'],
  ]);
  const cvssVersion =
    firstString(source, [
      ['vulnerability', 'score', 'version'],
      ['vulnerability', 'cvss', 'version'],
      ['cvss', 'version'],
    ]) ?? 'UNKNOWN';
  const vectorString = firstString(source, [
    ['vulnerability', 'score', 'vector'],
    ['vulnerability', 'cvss', 'vector_string'],
    ['cvss', 'vector_string'],
    ['vectorString'],
  ]);
  const cvssComponents = parseCvssVector(vectorString);

  return {
    sourceIndex: document.index,
    sourceDocumentId: document.id,
    cveId,
    description: firstString(source, [
      ['vulnerability', 'description'],
      ['description'],
    ]),
    packageName: firstString(source, [
      ['package', 'name'],
      ['package_name'],
      ['vulnerability', 'package', 'name'],
      ['vulnerability', 'package_name'],
      ['data', 'package', 'name'],
      ['data', 'package_name'],
      ['data', 'vulnerability', 'package', 'name'],
      ['data', 'vulnerability', 'package_name'],
      ['software', 'name'],
    ]),
    packageVersion: firstString(source, [
      ['package', 'version'],
      ['package_version'],
      ['vulnerability', 'package', 'version'],
      ['vulnerability', 'package_version'],
      ['data', 'package', 'version'],
      ['data', 'package_version'],
      ['data', 'vulnerability', 'package', 'version'],
      ['data', 'vulnerability', 'package_version'],
      ['software', 'version'],
    ]),
    packageArchitecture: firstString(source, [
      ['package', 'architecture'],
      ['package', 'arch'],
      ['package_architecture'],
      ['package_arch'],
      ['vulnerability', 'package', 'architecture'],
      ['vulnerability', 'package', 'arch'],
      ['data', 'package', 'architecture'],
      ['data', 'package', 'arch'],
      ['software', 'architecture'],
    ]),
    packageVendor: firstString(source, [
      ['package', 'vendor'],
      ['package_vendor'],
      ['vulnerability', 'package', 'vendor'],
      ['data', 'package', 'vendor'],
      ['software', 'vendor'],
    ]),
    packageType: firstString(source, [
      ['package', 'type'],
      ['package_type'],
      ['vulnerability', 'package', 'type'],
      ['data', 'package', 'type'],
      ['software', 'type'],
    ]),
    status: mapVulnerabilityStatus(sourceStatus, underEvaluation),
    sourceStatus,
    severity: normalizeSeverity(
      firstString(source, [
        ['vulnerability', 'severity'],
        ['severity'],
      ]),
    ),
    cvssBaseScore: firstNumber(source, [
      ['vulnerability', 'score', 'base'],
      ['vulnerability', 'cvss', 'base_score'],
      ['cvss', 'base_score'],
      ['baseScore'],
    ]),
    cvssVersion,
    vectorString,
    ...cvssComponents,
    detectedAt: safeDate(
      firstValue(source, [
        ['vulnerability', 'detected_at'],
        ['detected_at'],
      ]),
    ),
    publishedAt: safeDate(
      firstValue(source, [
        ['vulnerability', 'published_at'],
        ['published_at'],
      ]),
    ),
    sourceUpdatedAt: safeDate(
      firstValue(source, [
        ['vulnerability', 'updated_at'],
        ['vulnerability', 'modified_at'],
        ['updated_at'],
        ['@timestamp'],
      ]),
    ),
    references: normalizeReferences(
      firstValue(source, [
        ['vulnerability', 'reference'],
        ['vulnerability', 'references'],
        ['references'],
      ]),
    ),
    schemaVersion: firstString(source, [
      ['wazuh', 'schema', 'version'],
      ['schema', 'version'],
    ]),
    rawPayload: source,
  };
}

export function normalizeContextMetadata(
  systemDocuments: Array<WazuhStateDocument<WazuhInventoryStateSource>>,
  agent: WazuhAgentSummary,
): NormalizedContextMetadata {
  const source = systemDocuments[0]?.source ?? {};

  return {
    hostname:
      firstString(source, [
        ['host', 'hostname'],
        ['system', 'hostname'],
        ['agent', 'name'],
      ]) ?? agent.name ?? null,
    osName:
      firstString(source, [
        ['host', 'os', 'name'],
        ['os', 'name'],
        ['system', 'os', 'name'],
      ]) ?? agent.os?.name ?? null,
    osVersion:
      firstString(source, [
        ['host', 'os', 'version'],
        ['os', 'version'],
        ['system', 'os', 'version'],
      ]) ?? agent.os?.version ?? null,
    osFull:
      firstString(source, [
        ['host', 'os', 'full'],
        ['host', 'os', 'pretty_name'],
        ['os', 'full'],
        ['system', 'os', 'full'],
      ]) ?? agent.os?.uname ?? null,
    architecture:
      firstString(source, [
        ['host', 'architecture'],
        ['host', 'os', 'architecture'],
        ['os', 'architecture'],
        ['system', 'architecture'],
      ]) ?? agent.os?.arch ?? null,
    schemaVersion: firstString(source, [
      ['wazuh', 'schema', 'version'],
      ['schema', 'version'],
    ]),
  };
}

export function parseCvssVector(vectorString: string | null): {
  attackVector: string | null;
  attackComplexity: string | null;
  privilegesRequired: string | null;
  userInteraction: string | null;
  scope: string | null;
  confidentialityImpact: string | null;
  integrityImpact: string | null;
  availabilityImpact: string | null;
} {
  const empty = {
    attackVector: null,
    attackComplexity: null,
    privilegesRequired: null,
    userInteraction: null,
    scope: null,
    confidentialityImpact: null,
    integrityImpact: null,
    availabilityImpact: null,
  };

  if (!vectorString) {
    return empty;
  }

  const metrics = new Map<string, string>();
  for (const token of vectorString.trim().split('/')) {
    const separator = token.indexOf(':');
    if (separator <= 0) {
      continue;
    }

    const key = token.slice(0, separator).trim().toUpperCase();
    const value = token.slice(separator + 1).trim().toUpperCase();
    if (key && value && key !== 'CVSS') {
      metrics.set(key, value);
    }
  }

  const mapValue = (
    metric: string,
    aliases: Record<string, string>,
  ): string | null => {
    const value = metrics.get(metric);
    return value ? aliases[value] ?? value : null;
  };

  return {
    attackVector: mapValue('AV', {
      N: 'NETWORK',
      A: 'ADJACENT',
      L: 'LOCAL',
      P: 'PHYSICAL',
    }),
    attackComplexity: mapValue('AC', {
      L: 'LOW',
      H: 'HIGH',
      M: 'MEDIUM',
    }),
    privilegesRequired: mapValue('PR', {
      N: 'NONE',
      L: 'LOW',
      H: 'HIGH',
    }),
    userInteraction: mapValue('UI', {
      N: 'NONE',
      R: 'REQUIRED',
    }),
    scope: mapValue('S', {
      U: 'UNCHANGED',
      C: 'CHANGED',
    }),
    confidentialityImpact: mapValue('C', {
      N: 'NONE',
      L: 'LOW',
      H: 'HIGH',
      P: 'PARTIAL',
      C: 'COMPLETE',
    }),
    integrityImpact: mapValue('I', {
      N: 'NONE',
      L: 'LOW',
      H: 'HIGH',
      P: 'PARTIAL',
      C: 'COMPLETE',
    }),
    availabilityImpact: mapValue('A', {
      N: 'NONE',
      L: 'LOW',
      H: 'HIGH',
      P: 'PARTIAL',
      C: 'COMPLETE',
    }),
  };
}

export function countListeningPorts(
  sources: WazuhInventoryStateSource[],
): number {
  return sources.filter((source) => {
    const state = firstString(source, [
      ['network', 'state'],
      ['port', 'state'],
      ['state'],
    ])?.toUpperCase();
    const localPort = firstNumber(source, [
      ['network', 'local', 'port'],
      ['local', 'port'],
      ['port', 'local'],
      ['local_port'],
    ]);

    return localPort !== null && (!state || state.includes('LISTEN'));
  }).length;
}

export function stableHash(value: unknown): string {
  return createHash('sha256').update(stableStringify(value)).digest('hex');
}

export function referenceHash(url: string): string {
  return createHash('sha256').update(url.trim()).digest('hex');
}

export function safeDate(value: unknown): Date | null {
  if (value instanceof Date && Number.isFinite(value.getTime())) {
    return value;
  }

  if (typeof value !== 'string' && typeof value !== 'number') {
    return null;
  }

  const date = new Date(value);
  return Number.isFinite(date.getTime()) ? date : null;
}

export function asJsonRecord(value: unknown): Record<string, unknown> {
  return isRecord(value) ? value : {};
}

function mapVulnerabilityStatus(
  rawStatus: string | null,
  underEvaluation: boolean | null,
): VulnerabilityLifecycleStatus {
  if (underEvaluation === true) {
    return VulnerabilityLifecycleStatus.UNDER_EVALUATION;
  }

  const normalized = rawStatus?.trim().toLowerCase() ?? '';

  if (
    normalized.includes('resolved') ||
    normalized.includes('solved') ||
    normalized.includes('fixed') ||
    normalized.includes('closed')
  ) {
    return VulnerabilityLifecycleStatus.RESOLVED;
  }

  if (
    normalized.includes('active') ||
    normalized.includes('affected') ||
    normalized.includes('open') ||
    normalized.includes('valid')
  ) {
    return VulnerabilityLifecycleStatus.ACTIVE;
  }

  return normalized
    ? VulnerabilityLifecycleStatus.UNKNOWN
    : VulnerabilityLifecycleStatus.ACTIVE;
}

function normalizeSeverity(value: string | null): string | null {
  if (!value) {
    return null;
  }

  const normalized = value.trim().toUpperCase();
  const aliases: Record<string, string> = {
    MODERATE: 'MEDIUM',
    IMPORTANT: 'HIGH',
  };

  return aliases[normalized] ?? normalized;
}

function normalizeReferences(value: unknown): string[] {
  const values = Array.isArray(value)
    ? value
    : typeof value === 'string'
      ? value.split(/[\n,]/)
      : [];

  return Array.from(
    new Set(
      values
        .filter((item): item is string => typeof item === 'string')
        .map((item) => item.trim())
        .filter((item) => /^https?:\/\//i.test(item)),
    ),
  );
}

function firstString(
  source: unknown,
  paths: string[][],
): string | null {
  const value = firstValue(source, paths);
  if (typeof value !== 'string') {
    return null;
  }

  const normalized = value.trim();
  return normalized || null;
}

function firstNumber(
  source: unknown,
  paths: string[][],
): number | null {
  const value = firstValue(source, paths);

  if (typeof value === 'number' && Number.isFinite(value)) {
    return value;
  }

  if (typeof value === 'string' && value.trim()) {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : null;
  }

  return null;
}

function firstBoolean(
  source: unknown,
  paths: string[][],
): boolean | null {
  const value = firstValue(source, paths);

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

  return null;
}

function firstValue(source: unknown, paths: string[][]): unknown {
  for (const path of paths) {
    let current: unknown = source;

    for (const segment of path) {
      if (!isRecord(current) || !(segment in current)) {
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

function stableStringify(value: unknown): string {
  if (Array.isArray(value)) {
    return `[${value.map((item) => stableStringify(item)).join(',')}]`;
  }

  if (isRecord(value)) {
    const entries = Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`);
    return `{${entries.join(',')}}`;
  }

  return JSON.stringify(value) ?? 'null';
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
