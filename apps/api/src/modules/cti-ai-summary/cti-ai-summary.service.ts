import { Injectable, NotFoundException } from '@nestjs/common';
import { accessSync, promises as fs } from 'fs';
import { dirname, isAbsolute, join, resolve } from 'path';

type RawRecommendation = Record<string, unknown>;
type RawSummary = {
  schema_version?: string;
  generated_from?: Record<string, unknown>;
  summary?: Record<string, unknown>;
  recommendations?: RawRecommendation[];
};
type Distribution = Record<string, number>;

@Injectable()
export class CtiAiSummaryService {
  private cachedMtimeMs = 0;
  private cachedData: RawSummary | null = null;

  async getLatest(options: { device?: string; limit?: number } = {}) {
    const data = await this.load();
    const recommendations = Array.isArray(data.recommendations) ? data.recommendations : [];
    const deviceFilter = options.device?.trim().toLowerCase();
    const filtered = deviceFilter
      ? recommendations.filter((item) => String(item.device ?? '').toLowerCase().includes(deviceFilter))
      : recommendations;
    const sorted = [...filtered].sort((left, right) =>
      this.numberValue(right.ai_risk_score) - this.numberValue(left.ai_risk_score) ||
      this.numberValue(right.cvss_score) - this.numberValue(left.cvss_score),
    );
    const limit = options.limit && options.limit > 0 ? Math.min(options.limit, 100) : 20;

    return {
      schemaVersion: data.schema_version ?? 'cti-device-recommendations-with-ai.v1',
      generatedFrom: data.generated_from ?? {},
      sourceFile: this.resolveSummaryPath(),
      summary: {
        ...(data.summary ?? {}),
        visibleRecommendations: filtered.length,
        selectedDevice: options.device ?? null,
        riskLevelDistribution: this.distribution(filtered, 'ai_risk_level'),
        finalPriorityDistribution: this.distribution(filtered, 'ai_final_priority'),
        severityDistribution: this.distribution(filtered, 'severity'),
      },
      topRecommendations: sorted.slice(0, limit).map((item) => this.toViewModel(item)),
    };
  }

  private async load(): Promise<RawSummary> {
    const targetPath = this.resolveSummaryPath();
    let stat;
    try {
      stat = await fs.stat(targetPath);
    } catch {
      throw new NotFoundException(`CTI AI summary file was not found: ${targetPath}`);
    }
    if (this.cachedData && this.cachedMtimeMs === stat.mtimeMs) return this.cachedData;
    const data = JSON.parse(await fs.readFile(targetPath, 'utf8')) as RawSummary;
    this.cachedMtimeMs = stat.mtimeMs;
    this.cachedData = data;
    return data;
  }

  private resolveSummaryPath(): string {
    const configured = process.env.CTI_AI_SUMMARY_PATH?.trim();
    if (configured) return isAbsolute(configured) ? configured : resolve(this.resolveProjectRoot(), configured);
    return join(this.resolveProjectRoot(), 'apps', 'ai-model', 'cti-collector', 'data', 'output', 'final_device_security_summary_xgboost.json');
  }

  private resolveProjectRoot(): string {
    const configured = process.env.CYRP_PROJECT_ROOT?.trim();
    if (configured) return configured;
    let current = process.cwd();
    for (let index = 0; index < 8; index += 1) {
      try {
        accessSync(join(current, 'apps', 'ai-model'));
        return current;
      } catch {
        const parent = dirname(current);
        if (parent === current) break;
        current = parent;
      }
    }
    return resolve(process.cwd(), '..', '..');
  }

  private toViewModel(item: RawRecommendation) {
    return {
      device: String(item.device ?? ''),
      agentId: String(item.agent_id ?? ''),
      cveId: String(item.cve_id ?? ''),
      packageName: String(item.package_name ?? ''),
      installedVersion: String(item.installed_version ?? ''),
      fixedVersion: String(item.fixed_version ?? ''),
      severity: String(item.severity ?? ''),
      cvssScore: this.nullableNumber(item.cvss_score),
      priority: String(item.priority ?? ''),
      aiRiskScore: this.nullableNumber(item.ai_risk_score),
      aiRiskLevel: String(item.ai_risk_level ?? ''),
      aiFinalPriority: String(item.ai_final_priority ?? ''),
      modelVersion: String(item.model_version ?? ''),
      description: String(item.description ?? ''),
      recommendation: String(item.recommendation ?? ''),
      references: Array.isArray(item.references) ? item.references.map(String) : [],
    };
  }

  private distribution(rows: RawRecommendation[], key: string): Distribution {
    return rows.reduce<Distribution>((acc, item) => {
      const value = String(item[key] ?? 'UNKNOWN').toUpperCase();
      acc[value] = (acc[value] ?? 0) + 1;
      return acc;
    }, {});
  }

  private numberValue(value: unknown): number {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : 0;
  }

  private nullableNumber(value: unknown): number | null {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : null;
  }
}
