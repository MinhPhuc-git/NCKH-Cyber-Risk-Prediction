import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { CtiSourceStatus, SyncRunStatus, SyncSourceType } from '@prisma/client';
import { spawn } from 'node:child_process';
import { access } from 'node:fs/promises';
import { isAbsolute, resolve } from 'node:path';

import { DatabaseService } from '../../database/database.service';

interface DatasetCvssRecord {
  cveId: string;
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
  publishedAt: string | null;
  modifiedAt: string | null;
  description: string | null;
  cweId: string | null;
}

interface DatasetScriptOutput {
  requested: number;
  matched: number;
  missing: number;
  scannedRows: number;
  durationMs: number;
  records: DatasetCvssRecord[];
}

export interface CtiCvssEnrichmentResult {
  status: 'DISABLED' | 'SKIPPED' | 'COMPLETED' | 'PARTIAL' | 'FAILED';
  requested: number;
  pending: number;
  matched: number;
  upserted: number;
  missing: number;
  failed: number;
  scannedRows: number;
  durationMs: number;
  message: string;
}

@Injectable()
export class CtiCvssEnrichmentService {
  private readonly logger = new Logger(CtiCvssEnrichmentService.name);
  private readonly enabled: boolean;
  private readonly pythonPath: string;
  private readonly scriptPath: string;
  private readonly datasetPath: string;
  private readonly timeoutMs: number;

  constructor(
    private readonly database: DatabaseService,
    config: ConfigService,
  ) {
    this.enabled = this.booleanValue(
      config.get<unknown>('CTI_CVSS_ENRICHMENT_ENABLED'),
      true,
    );
    this.pythonPath = this.resolveProjectPath(
      this.stringValue(
        config.get<unknown>('CTI_CVSS_PYTHON_PATH'),
        'apps/ai-model/.venv/Scripts/python.exe',
      ),
    );
    this.scriptPath = this.resolveProjectPath(
      this.stringValue(
        config.get<unknown>('CTI_CVSS_ENRICHMENT_SCRIPT'),
        'apps/ai-model/model-risk-prediction/runtime/enrich_cvss_from_dataset.py',
      ),
    );
    this.datasetPath = this.resolveProjectPath(
      this.stringValue(
        config.get<unknown>('CTI_CVSS_DATASET_PATH'),
        'apps/ai-model/model-risk-prediction/Data Train/350k-Data_HasExploited.csv',
      ),
    );
    this.timeoutMs = this.integerValue(
      config.get<unknown>('CTI_CVSS_ENRICHMENT_TIMEOUT_MS'),
      30_000,
      5_000,
      300_000,
    );
  }

  isEnabled(): boolean {
    return this.enabled;
  }

  async enrich(cveIds: string[]): Promise<CtiCvssEnrichmentResult> {
    const startedAt = Date.now();
    const requestedIds = [...new Set(
      cveIds
        .map((value) => value.trim().toUpperCase())
        .filter((value) => /^CVE-\d{4}-\d{4,}$/.test(value)),
    )];

    if (!this.enabled) {
      return this.result('DISABLED', requestedIds.length, 0, 0, 0, 0, 0, 0, startedAt,
        'CTI CVSS enrichment is disabled');
    }

    if (requestedIds.length === 0) {
      return this.result('SKIPPED', 0, 0, 0, 0, 0, 0, 0, startedAt,
        'No CVE identifiers require enrichment');
    }

    const completeRows = await this.database.cveCvssMetric.findMany({
      where: {
        cveId: { in: requestedIds },
        source: 'CYRP_CTI_CSV',
        metricType: 'NVD_DATASET',
      },
      select: {
        cveId: true,
        vectorString: true,
        attackVector: true,
        attackComplexity: true,
        privilegesRequired: true,
        userInteraction: true,
        scope: true,
        confidentialityImpact: true,
        integrityImpact: true,
        availabilityImpact: true,
      },
    });
    const completeIds = new Set(
      completeRows
        .filter((row) => this.metricCompleteness(row) > 0)
        .map((row) => row.cveId),
    );
    const pendingIds = requestedIds.filter((cveId) => !completeIds.has(cveId));

    if (pendingIds.length === 0) {
      return this.result('SKIPPED', requestedIds.length, 0, 0, 0, 0, 0, 0, startedAt,
        'All requested CVEs already have enriched CVSS data');
    }

    const source = await this.database.ctiSource.upsert({
      where: { code: 'CYRP_CTI_CVSS_DATASET' },
      create: {
        code: 'CYRP_CTI_CVSS_DATASET',
        name: 'CYRP local NVD-derived CVSS dataset',
        sourceType: SyncSourceType.CTI_CSV,
        description:
          'Local CTI dataset used to enrich CVSS vectors without placing NVD API latency in the machine-check request path.',
        enabled: true,
        lastAttemptAt: new Date(),
      },
      update: {
        enabled: true,
        lastAttemptAt: new Date(),
        lastError: null,
      },
    });
    const run = await this.database.syncRun.create({
      data: {
        sourceId: source.id,
        sourceType: SyncSourceType.CTI_CSV,
        trigger: 'MACHINE_CHECK_CVSS_ENRICHMENT',
        sourceManifest: {
          datasetPath: this.datasetPath,
          requestedCveCount: pendingIds.length,
        },
      },
    });

    try {
      await Promise.all([
        access(this.pythonPath),
        access(this.scriptPath),
        access(this.datasetPath),
      ]);

      const output = await this.runDatasetScript(pendingIds);
      let upserted = 0;
      let failed = 0;
      const errors: string[] = [];

      for (const record of output.records) {
        try {
          await this.persistRecord(record);
          upserted += 1;
        } catch (error: unknown) {
          failed += 1;
          errors.push(`${record.cveId}: ${this.errorMessage(error)}`);
        }
      }

      const completedAt = new Date();
      const status = failed > 0 || output.missing > 0
        ? SyncRunStatus.PARTIAL
        : SyncRunStatus.COMPLETED;

      await this.database.$transaction([
        this.database.syncRun.update({
          where: { id: run.id },
          data: {
            status,
            completedAt,
            recordsRead: output.scannedRows,
            recordsWritten: upserted,
            recordsRejected: failed,
            errorSummary: errors.length > 0 ? errors.slice(0, 20).join('; ') : null,
            checkpointAfter: {
              requested: pendingIds.length,
              matched: output.matched,
              missing: output.missing,
              upserted,
              failed,
              scanDurationMs: output.durationMs,
              totalDurationMs: Date.now() - startedAt,
            },
          },
        }),
        this.database.ctiSource.update({
          where: { id: source.id },
          data: {
            status: failed > 0 ? CtiSourceStatus.ERROR : CtiSourceStatus.ACTIVE,
            lastSuccessAt: completedAt,
            lastError: errors.length > 0 ? errors.slice(0, 10).join('; ') : null,
          },
        }),
      ]);

      const result = this.result(
        status === SyncRunStatus.COMPLETED ? 'COMPLETED' : 'PARTIAL',
        requestedIds.length,
        pendingIds.length,
        output.matched,
        upserted,
        output.missing,
        failed,
        output.scannedRows,
        startedAt,
        `Enriched ${upserted}/${pendingIds.length} CVE records from the local CTI dataset`,
      );
      this.logger.log(
        `CTI CVSS enrichment status=${result.status} requested=${result.requested} pending=${result.pending} matched=${result.matched} upserted=${result.upserted} missing=${result.missing} failed=${result.failed} durationMs=${result.durationMs}`,
      );
      return result;
    } catch (error: unknown) {
      const message = this.errorMessage(error);
      const completedAt = new Date();
      await Promise.allSettled([
        this.database.syncRun.update({
          where: { id: run.id },
          data: {
            status: SyncRunStatus.FAILED,
            completedAt,
            errorSummary: message,
          },
        }),
        this.database.ctiSource.update({
          where: { id: source.id },
          data: {
            status: CtiSourceStatus.ERROR,
            lastError: message,
          },
        }),
      ]);
      this.logger.warn(`CTI CVSS enrichment failed: ${message}`);
      return this.result(
        'FAILED',
        requestedIds.length,
        pendingIds.length,
        0,
        0,
        pendingIds.length,
        pendingIds.length,
        0,
        startedAt,
        message,
      );
    }
  }

  private async persistRecord(record: DatasetCvssRecord): Promise<void> {
    const publishedAt = this.dateValue(record.publishedAt);
    const modifiedAt = this.dateValue(record.modifiedAt);
    const cvssVersion = record.cvssVersion || 'UNKNOWN';

    await this.database.$transaction(async (transaction) => {
      await transaction.cve.upsert({
        where: { cveId: record.cveId },
        create: {
          cveId: record.cveId,
          description: record.description,
          publishedAt,
          modifiedAt,
          source: 'CYRP_CTI_CSV',
          sourceVersion: '350K_DATASET',
        },
        update: {
          ...(record.description ? { description: record.description } : {}),
          ...(publishedAt ? { publishedAt } : {}),
          ...(modifiedAt ? { modifiedAt } : {}),
          ingestedAt: new Date(),
        },
      });

      await transaction.cveCvssMetric.upsert({
        where: {
          cveId_source_metricType_cvssVersion: {
            cveId: record.cveId,
            source: 'CYRP_CTI_CSV',
            metricType: 'NVD_DATASET',
            cvssVersion,
          },
        },
        create: {
          cveId: record.cveId,
          source: 'CYRP_CTI_CSV',
          metricType: 'NVD_DATASET',
          cvssVersion,
          vectorString: record.vectorString,
          baseScore: record.baseScore,
          baseSeverity: record.baseSeverity,
          attackVector: record.attackVector,
          attackComplexity: record.attackComplexity,
          privilegesRequired: record.privilegesRequired,
          userInteraction: record.userInteraction,
          scope: record.scope,
          confidentialityImpact: record.confidentialityImpact,
          integrityImpact: record.integrityImpact,
          availabilityImpact: record.availabilityImpact,
          publishedAt,
        },
        update: {
          vectorString: record.vectorString,
          baseScore: record.baseScore,
          baseSeverity: record.baseSeverity,
          attackVector: record.attackVector,
          attackComplexity: record.attackComplexity,
          privilegesRequired: record.privilegesRequired,
          userInteraction: record.userInteraction,
          scope: record.scope,
          confidentialityImpact: record.confidentialityImpact,
          integrityImpact: record.integrityImpact,
          availabilityImpact: record.availabilityImpact,
          publishedAt,
          ingestedAt: new Date(),
        },
      });

      if (record.cweId && /^CWE-\d+$/.test(record.cweId)) {
        await transaction.cwe.upsert({
          where: { cweId: record.cweId },
          create: {
            cweId: record.cweId,
            source: 'CYRP_CTI_CSV',
          },
          update: {
            source: 'CYRP_CTI_CSV',
          },
        });
        await transaction.cveCwe.upsert({
          where: {
            cveId_cweId_source: {
              cveId: record.cveId,
              cweId: record.cweId,
              source: 'CYRP_CTI_CSV',
            },
          },
          create: {
            cveId: record.cveId,
            cweId: record.cweId,
            source: 'CYRP_CTI_CSV',
          },
          update: {},
        });
      }
    }, { timeout: 30_000 });
  }

  private runDatasetScript(cveIds: string[]): Promise<DatasetScriptOutput> {
    return new Promise((resolvePromise, rejectPromise) => {
      const child = spawn(
        this.pythonPath,
        ['-u', this.scriptPath, '--dataset', this.datasetPath],
        {
          windowsHide: true,
          env: {
            ...process.env,
            PYTHONUTF8: '1',
            PYTHONIOENCODING: 'utf-8',
          },
          stdio: ['pipe', 'pipe', 'pipe'],
        },
      );
      let stdout = '';
      let stderr = '';
      let settled = false;

      const timer = setTimeout(() => {
        if (settled) {
          return;
        }
        settled = true;
        child.kill();
        rejectPromise(
          new Error(`CTI CVSS enrichment timed out after ${this.timeoutMs}ms`),
        );
      }, this.timeoutMs);

      child.stdout.setEncoding('utf8');
      child.stderr.setEncoding('utf8');
      child.stdout.on('data', (chunk: string) => {
        stdout += chunk;
      });
      child.stderr.on('data', (chunk: string) => {
        stderr += chunk;
      });
      child.once('error', (error) => {
        if (settled) {
          return;
        }
        settled = true;
        clearTimeout(timer);
        rejectPromise(error);
      });
      child.once('exit', (code) => {
        if (settled) {
          return;
        }
        settled = true;
        clearTimeout(timer);

        if (code !== 0) {
          rejectPromise(
            new Error(
              `CTI CVSS enrichment exited with code ${String(code)}: ${stderr.trim().slice(0, 2000)}`,
            ),
          );
          return;
        }

        try {
          const parsed = JSON.parse(stdout.trim()) as DatasetScriptOutput;
          if (!Array.isArray(parsed.records)) {
            throw new Error('CTI CVSS enrichment returned an invalid payload');
          }
          resolvePromise(parsed);
        } catch (error: unknown) {
          rejectPromise(
            new Error(
              `Unable to parse CTI CVSS enrichment output: ${this.errorMessage(error)}; stdout=${stdout.slice(0, 1000)}`,
            ),
          );
        }
      });

      child.stdin.end(JSON.stringify({ cveIds }), 'utf8');
    });
  }

  private metricCompleteness(metric: {
    vectorString: string | null;
    attackVector: string | null;
    attackComplexity: string | null;
    privilegesRequired: string | null;
    userInteraction: string | null;
    scope: string | null;
    confidentialityImpact: string | null;
    integrityImpact: string | null;
    availabilityImpact: string | null;
  }): number {
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

  private result(
    status: CtiCvssEnrichmentResult['status'],
    requested: number,
    pending: number,
    matched: number,
    upserted: number,
    missing: number,
    failed: number,
    scannedRows: number,
    startedAt: number,
    message: string,
  ): CtiCvssEnrichmentResult {
    return {
      status,
      requested,
      pending,
      matched,
      upserted,
      missing,
      failed,
      scannedRows,
      durationMs: Date.now() - startedAt,
      message,
    };
  }

  private resolveProjectPath(value: string): string {
    if (isAbsolute(value)) {
      return value;
    }
    return resolve(this.resolveProjectRoot(), value);
  }

  private resolveProjectRoot(): string {
    const configured = process.env.CYRP_PROJECT_ROOT?.trim();
    if (configured) {
      return configured;
    }
    return resolve(process.cwd(), '..', '..');
  }

  private stringValue(value: unknown, fallback: string): string {
    return typeof value === 'string' && value.trim() !== ''
      ? value.trim()
      : fallback;
  }

  private booleanValue(value: unknown, fallback: boolean): boolean {
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
    return fallback;
  }

  private integerValue(
    value: unknown,
    fallback: number,
    min: number,
    max: number,
  ): number {
    const parsed = typeof value === 'number'
      ? value
      : typeof value === 'string' && value.trim() !== ''
        ? Number.parseInt(value, 10)
        : fallback;
    return Number.isInteger(parsed)
      ? Math.min(max, Math.max(min, parsed))
      : fallback;
  }

  private dateValue(value: string | null): Date | null {
    if (!value) {
      return null;
    }
    const parsed = new Date(value);
    return Number.isNaN(parsed.getTime()) ? null : parsed;
  }

  private errorMessage(error: unknown): string {
    return error instanceof Error ? error.message : 'Unknown enrichment error';
  }
}
