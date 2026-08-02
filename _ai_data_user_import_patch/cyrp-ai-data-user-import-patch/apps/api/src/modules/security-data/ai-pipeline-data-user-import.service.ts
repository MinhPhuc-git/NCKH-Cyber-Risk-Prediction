import {
  Injectable,
  Logger,
  NotFoundException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
  Prisma,
  VulnerabilityLifecycleStatus,
} from '@prisma/client';
import { existsSync } from 'node:fs';
import {
  readdir,
  readFile,
  rm,
  stat,
} from 'node:fs/promises';
import {
  basename,
  extname,
  isAbsolute,
  join,
  resolve,
} from 'node:path';

import { DatabaseService } from '../../database/database.service';

interface DataUserImportOptions {
  userId?: string;
  deviceId?: string;
  deleteAfterImport?: boolean;
}

interface DataUserPredictionRecord {
  cveId: string;
  agentIds: string[];
  attackProbability: number;
  predictedPercentile: number | null;
  riskLevel: string;
  raw: Record<string, unknown>;
}

interface ImportSkip {
  file: string;
  cveId?: string;
  agentId?: string;
  reason: string;
}

interface ImportError {
  file: string;
  message: string;
}

export interface DataUserImportResult {
  dataUserDir: string;
  filesFound: number;
  filesDeleted: number;
  recordsRead: number;
  recordsImported: number;
  historyRowsCreated: number;
  skipped: ImportSkip[];
  errors: ImportError[];
}

@Injectable()
export class AiPipelineDataUserImportService {
  private readonly logger = new Logger(AiPipelineDataUserImportService.name);
  private readonly dataUserDir: string;
  private readonly modelVersion: string;

  constructor(
    private readonly database: DatabaseService,
    config: ConfigService,
  ) {
    this.dataUserDir = this.resolveProjectPath(
      this.stringValue(
        config.get<unknown>('AI_PIPELINE_DATA_USER_DIR'),
        'apps/ai-model/model-risk-prediction/Data User',
      ),
    );
    this.modelVersion = this.stringValue(
      config.get<unknown>('AI_MODEL_VERSION'),
      'CYRP_XGBOOST_CVSS_PERCENTILE_V3',
    );
  }

  async importForUserDevice(
    userId: string,
    deviceId: string,
  ): Promise<DataUserImportResult> {
    const device = await this.database.device.findFirst({
      where: {
        id: deviceId,
        userId,
      },
      select: { id: true },
    });

    if (!device) {
      throw new NotFoundException('Không tìm thấy thiết bị thuộc tài khoản hiện tại');
    }

    return this.importDataUserJson({
      userId,
      deviceId,
      deleteAfterImport: true,
    });
  }

  async importAllForAdmin(): Promise<DataUserImportResult> {
    return this.importDataUserJson({
      deleteAfterImport: true,
    });
  }

  async importDataUserJson(
    options: DataUserImportOptions = {},
  ): Promise<DataUserImportResult> {
    const files = await this.listJsonFiles(this.dataUserDir);
    const result: DataUserImportResult = {
      dataUserDir: this.dataUserDir,
      filesFound: files.length,
      filesDeleted: 0,
      recordsRead: 0,
      recordsImported: 0,
      historyRowsCreated: 0,
      skipped: [],
      errors: [],
    };
    const importedKeys = new Set<string>();

    for (const file of files) {
      let parsed: unknown;

      try {
        parsed = JSON.parse(await readFile(file, 'utf8'));
      } catch (error: unknown) {
        result.errors.push({
          file,
          message: this.errorMessage(error),
        });
        continue;
      }

      const records = this.extractRecords(parsed, file, result);
      let fileHadFatalError = false;

      for (const record of records) {
        result.recordsRead += 1;

        const agentIds = record.agentIds.length > 0
          ? record.agentIds
          : [''];

        for (const agentId of agentIds) {
          const dedupeKey = [
            record.cveId,
            agentId,
            record.attackProbability,
            record.predictedPercentile ?? '',
            record.riskLevel,
            options.deviceId ?? '',
          ].join('|');

          if (importedKeys.has(dedupeKey)) {
            continue;
          }
          importedKeys.add(dedupeKey);

          try {
            const imported = await this.importOneRecord(record, agentId, options);

            if (!imported.imported) {
              result.skipped.push({
                file,
                cveId: record.cveId,
                agentId: agentId || undefined,
                reason: imported.reason,
              });
              continue;
            }

            result.recordsImported += 1;
            if (imported.historyCreated) {
              result.historyRowsCreated += 1;
            }
          } catch (error: unknown) {
            fileHadFatalError = true;
            result.errors.push({
              file,
              message: `${record.cveId}${agentId ? `/${agentId}` : ''}: ${this.errorMessage(error)}`,
            });
          }
        }
      }

      if (options.deleteAfterImport !== false && !fileHadFatalError) {
        await rm(file, { force: true }).catch((error: unknown) => {
          result.errors.push({
            file,
            message: `Không xóa được file sau import: ${this.errorMessage(error)}`,
          });
        });

        if (!result.errors.some((item) => item.file === file && item.message.startsWith('Không xóa được'))) {
          result.filesDeleted += 1;
        }
      }
    }

    this.logger.log(
      `Imported Data User predictions: files=${result.filesFound}, records=${result.recordsImported}, history=${result.historyRowsCreated}, skipped=${result.skipped.length}, errors=${result.errors.length}`,
    );

    return result;
  }

  private async importOneRecord(
    record: DataUserPredictionRecord,
    agentId: string,
    options: DataUserImportOptions,
  ): Promise<{
    imported: boolean;
    historyCreated: boolean;
    reason: string;
  }> {
    const detection = await this.database.detectedVulnerability.findFirst({
      where: {
        cveId: record.cveId,
        ...(agentId ? { wazuhAgentId: agentId } : {}),
        ...(options.deviceId ? { deviceId: options.deviceId } : {}),
        ...(options.userId
          ? { device: { userId: options.userId } }
          : {}),
        status: { not: VulnerabilityLifecycleStatus.RESOLVED },
      },
      include: {
        featureVector: {
          select: { featureHash: true },
        },
      },
      orderBy: { lastSeenAt: 'desc' },
    });

    if (!detection) {
      return {
        imported: false,
        historyCreated: false,
        reason: agentId
          ? `Không tìm thấy detected_vulnerabilities ACTIVE/UNDER_EVALUATION cho ${record.cveId} và agent_id=${agentId}`
          : `Không tìm thấy detected_vulnerabilities ACTIVE/UNDER_EVALUATION cho ${record.cveId}`,
      };
    }

    const predictedAt = new Date();
    const explanation = this.buildExplanation(record, agentId, predictedAt);

    await this.database.aiPrediction.upsert({
      where: { detectedVulnerabilityId: detection.id },
      create: {
        detectedVulnerabilityId: detection.id,
        modelVersion: this.modelVersion,
        attackProbability: record.attackProbability,
        predictedPercentile: record.predictedPercentile,
        riskLevel: record.riskLevel,
        explanation: explanation as Prisma.InputJsonValue,
        predictedAt,
      },
      update: {
        modelVersion: this.modelVersion,
        attackProbability: record.attackProbability,
        predictedPercentile: record.predictedPercentile,
        riskLevel: record.riskLevel,
        explanation: explanation as Prisma.InputJsonValue,
        predictedAt,
      },
    });

    const latestHistory = await this.database.predictionHistory.findFirst({
      where: { detectedVulnerabilityId: detection.id },
      orderBy: { predictedAt: 'desc' },
      select: {
        modelVersion: true,
        riskLevel: true,
        attackProbability: true,
        predictedPercentile: true,
        featureHash: true,
      },
    });

    const featureHash = detection.featureVector?.featureHash ?? null;
    const shouldCreateHistory = !latestHistory ||
      latestHistory.modelVersion !== this.modelVersion ||
      latestHistory.riskLevel !== record.riskLevel ||
      !this.sameNumber(latestHistory.attackProbability, record.attackProbability) ||
      !this.sameNullableNumber(latestHistory.predictedPercentile, record.predictedPercentile) ||
      latestHistory.featureHash !== featureHash;

    if (shouldCreateHistory) {
      await this.database.predictionHistory.create({
        data: {
          detectedVulnerabilityId: detection.id,
          deviceId: detection.deviceId,
          cveId: detection.cveId,
          wazuhAgentId: detection.wazuhAgentId,
          modelVersion: this.modelVersion,
          attackProbability: record.attackProbability,
          predictedPercentile: record.predictedPercentile,
          riskLevel: record.riskLevel,
          featureHash,
          predictedAt,
        },
      });
    }

    return {
      imported: true,
      historyCreated: shouldCreateHistory,
      reason: 'IMPORTED',
    };
  }

  private buildExplanation(
    record: DataUserPredictionRecord,
    agentId: string,
    predictedAt: Date,
  ): Record<string, unknown> {
    const raw = { ...record.raw };
    delete raw._saved_path;

    return this.sanitizeJson({
      source: 'DATA_USER_JSON_PIPELINE',
      modelVersion: this.modelVersion,
      predictedAt: predictedAt.toISOString(),
      cveId: record.cveId,
      agentId: agentId || null,
      predicted_percentile: record.predictedPercentile,
      predictedPercentile: record.predictedPercentile,
      risk_level: record.riskLevel,
      riskLevel: record.riskLevel,
      probability: record.attackProbability,
      rawRiskLabel: this.optionalString(record.raw.Risk),
      prediction: record.raw.Prediction ?? null,
      thresholdUsed: record.raw.Threshold_Used ?? null,
      riskThresholdsUsed: record.raw.Risk_Thresholds_Used ?? null,
      reasons: Array.isArray(record.raw.Reasons) ? record.raw.Reasons : [],
      remediation: this.isRecord(record.raw.Remediation) ? record.raw.Remediation : null,
      rawModelOutput: raw,
    });
  }

  private extractRecords(
    parsed: unknown,
    file: string,
    result: DataUserImportResult,
  ): DataUserPredictionRecord[] {
    const values = Array.isArray(parsed) ? parsed : [parsed];
    const records: DataUserPredictionRecord[] = [];

    for (const value of values) {
      if (!this.isRecord(value)) {
        result.skipped.push({
          file,
          reason: 'JSON record không phải object',
        });
        continue;
      }

      const cveId = this.normalizeCve(
        this.optionalString(value.CVE_ID) ??
        this.optionalString(value.cveId) ??
        this.optionalString(value.cve_id),
      );
      const attackProbability = this.normalizeProbability(
        this.optionalNumber(value.Probability) ??
        this.optionalNumber(value.attackProbability) ??
        this.optionalNumber(value.attack_probability),
      );
      const predictedPercentile = this.normalizePercentile(
        this.optionalNumber(value.Percentile) ??
        this.optionalNumber(value.predictedPercentile) ??
        this.optionalNumber(value.predicted_percentile),
      );
      const riskLevel = this.normalizeRiskLevel(
        this.optionalString(value.Risk) ??
        this.optionalString(value.riskLevel) ??
        this.optionalString(value.risk_level),
      );

      if (!cveId) {
        result.skipped.push({
          file,
          reason: 'Thiếu CVE_ID',
        });
        continue;
      }

      if (attackProbability === null) {
        result.skipped.push({
          file,
          cveId,
          reason: 'Thiếu Probability/attackProbability',
        });
        continue;
      }

      records.push({
        cveId,
        agentIds: this.agentIds(value),
        attackProbability,
        predictedPercentile,
        riskLevel,
        raw: value,
      });
    }

    return records;
  }

  private agentIds(value: Record<string, unknown>): string[] {
    const raw = value.Agent_IDs ??
      value.agentIds ??
      value.agent_ids ??
      value.Agent_ID ??
      value.agent_id ??
      value.wazuhAgentId ??
      value.wazuh_agent_id;

    const candidates = Array.isArray(raw) ? raw : [raw];
    const normalized = candidates
      .map((item) => this.optionalString(item))
      .filter((item): item is string => Boolean(item))
      .map((item) => item.trim())
      .filter(Boolean);

    return [...new Set(normalized)];
  }

  private async listJsonFiles(directory: string): Promise<string[]> {
    try {
      const entries = await readdir(directory, { withFileTypes: true });
      const files: string[] = [];

      for (const entry of entries) {
        if (!entry.isFile()) {
          continue;
        }

        if (extname(entry.name).toLowerCase() !== '.json') {
          continue;
        }

        const path = join(directory, entry.name);
        const itemStat = await stat(path);

        if (itemStat.size <= 0) {
          continue;
        }

        files.push(path);
      }

      return files.sort((left, right) => {
        if (basename(left) === 'final_prediction_results.json') return 1;
        if (basename(right) === 'final_prediction_results.json') return -1;
        return left.localeCompare(right);
      });
    } catch (error: unknown) {
      this.logger.warn(
        `Cannot list AI Data User directory ${directory}: ${this.errorMessage(error)}`,
      );
      return [];
    }
  }

  private resolveProjectPath(value: string): string {
    if (isAbsolute(value)) {
      return value;
    }

    const candidates = [
      resolve(process.cwd(), value),
      resolve(process.cwd(), '..', '..', value),
      resolve(process.cwd(), '..', value),
    ];

    return candidates.find((candidate) => existsSync(candidate)) ?? candidates[0];
  }

  private stringValue(value: unknown, fallback: string): string {
    if (typeof value === 'string' && value.trim()) {
      return value.trim();
    }

    return fallback;
  }

  private optionalString(value: unknown): string | null {
    if (typeof value === 'string' && value.trim()) {
      return value.trim();
    }

    if (typeof value === 'number' && Number.isFinite(value)) {
      return String(value);
    }

    return null;
  }

  private optionalNumber(value: unknown): number | null {
    if (typeof value === 'number' && Number.isFinite(value)) {
      return value;
    }

    if (typeof value === 'string' && value.trim()) {
      const parsed = Number(value.trim());
      return Number.isFinite(parsed) ? parsed : null;
    }

    return null;
  }

  private normalizeProbability(value: number | null): number | null {
    if (value === null) {
      return null;
    }

    if (value > 1) {
      return this.clamp(value / 100, 0, 1);
    }

    return this.clamp(value, 0, 1);
  }

  private normalizePercentile(value: number | null): number | null {
    if (value === null) {
      return null;
    }

    return this.clamp(value, 0, 100);
  }

  private normalizeCve(value: string | null): string | null {
    if (!value) {
      return null;
    }

    const match = value.toUpperCase().match(/CVE-\d{4}-\d{4,}/);
    return match ? match[0] : null;
  }

  private normalizeRiskLevel(value: string | null): string {
    const normalized = this.removeVietnameseAccent(value ?? '')
      .trim()
      .toUpperCase();

    if (!normalized) {
      return 'UNKNOWN';
    }

    if (['CRITICAL', 'NGHIEM TRONG', 'RAT CAO'].includes(normalized)) {
      return 'CRITICAL';
    }

    if (['HIGH', 'CAO'].includes(normalized)) {
      return 'HIGH';
    }

    if (['MEDIUM', 'TRUNG BINH', 'TRUNG BINH'].includes(normalized)) {
      return 'MEDIUM';
    }

    if (['LOW', 'THAP'].includes(normalized)) {
      return 'LOW';
    }

    return normalized.slice(0, 20);
  }

  private removeVietnameseAccent(value: string): string {
    return value
      .normalize('NFD')
      .replace(/[\u0300-\u036f]/g, '')
      .replace(/Đ/g, 'D')
      .replace(/đ/g, 'd');
  }

  private sameNumber(left: number, right: number): boolean {
    return Math.abs(left - right) < 0.000001;
  }

  private sameNullableNumber(left: number | null, right: number | null): boolean {
    if (left === null && right === null) {
      return true;
    }

    if (left === null || right === null) {
      return false;
    }

    return this.sameNumber(left, right);
  }

  private clamp(value: number, min: number, max: number): number {
    return Math.min(Math.max(value, min), max);
  }

  private isRecord(value: unknown): value is Record<string, unknown> {
    return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
  }

  private sanitizeJson(value: unknown): Record<string, unknown> {
    return JSON.parse(JSON.stringify(value)) as Record<string, unknown>;
  }

  private errorMessage(error: unknown): string {
    return error instanceof Error ? error.message : String(error);
  }
}
