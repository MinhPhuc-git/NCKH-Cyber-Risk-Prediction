import {
  ConflictException,
  Injectable,
  Logger,
  NotFoundException,
  ServiceUnavailableException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { VulnerabilityLifecycleStatus } from '@prisma/client';
import { execFile } from 'node:child_process';
import { existsSync } from 'node:fs';
import {
  mkdir,
  readdir,
  rm,
} from 'node:fs/promises';
import {
  isAbsolute,
  join,
  resolve,
} from 'node:path';
import { promisify } from 'node:util';

import { DatabaseService } from '../../database/database.service';
import {
  AiPipelineDataUserImportService,
  type DataUserImportResult,
} from './ai-pipeline-data-user-import.service';

const execFileAsync = promisify(execFile);

interface PipelineStepResult {
  step: string;
  command: string;
  skipped: boolean;
  durationMs: number;
  stdoutTail: string;
  stderrTail: string;
}

interface TopPredictionItem {
  cveId: string;
  riskLevel: string | null;
  attackProbability: number | null;
  predictedPercentile: number | null;
  predictedAt: Date | null;
}

export interface AiPipelineCheckResult {
  deviceId: string;
  wazuhAgentId: string;
  startedAt: string;
  completedAt: string;
  durationMs: number;
  steps: PipelineStepResult[];
  importResult: DataUserImportResult;
  activeVulnerabilities: number;
  topPredictions: TopPredictionItem[];
}

@Injectable()
export class AiPipelineCheckService {
  private readonly logger = new Logger(AiPipelineCheckService.name);
  private readonly activeChecks = new Map<string, Promise<AiPipelineCheckResult>>();

  private readonly modelRoot: string;
  private readonly dataUserDir: string;
  private readonly pythonPath: string;
  private readonly timeoutMs: number;
  private readonly indexerUrl: string;
  private readonly indexerUsername: string;
  private readonly indexerPassword: string;
  private readonly indexerRejectUnauthorized: boolean;

  constructor(
    private readonly database: DatabaseService,
    private readonly config: ConfigService,
    private readonly importer: AiPipelineDataUserImportService,
  ) {
    this.modelRoot = this.resolveProjectPath(
      this.stringValue(
        this.config.get<unknown>('AI_PIPELINE_MODEL_ROOT'),
        'apps/ai-model/model-risk-prediction',
      ),
    );
    this.dataUserDir = this.resolveProjectPath(
      this.stringValue(
        this.config.get<unknown>('AI_PIPELINE_DATA_USER_DIR'),
        'apps/ai-model/model-risk-prediction/Data User',
      ),
    );
    this.pythonPath = this.resolveProjectPath(
      this.stringValue(
        this.config.get<unknown>('AI_PIPELINE_PYTHON_PATH') ?? this.config.get<unknown>('AI_MODEL_PYTHON_PATH'),
        'apps/ai-model/.venv/Scripts/python.exe',
      ),
    );
    this.timeoutMs = this.integerValue(
      this.config.get<unknown>('AI_PIPELINE_TIMEOUT_MS'),
      900_000,
      30_000,
      3_600_000,
    );
    this.indexerUrl = this.stringValue(
      this.config.get<unknown>('WAZUH_INDEXER_BASE_URL'),
      'https://127.0.0.1:19201',
    );
    this.indexerUsername = this.stringValue(
      this.config.get<unknown>('WAZUH_INDEXER_USERNAME'),
      'admin',
    );
    this.indexerPassword = this.stringValue(
      this.config.get<unknown>('WAZUH_INDEXER_PASSWORD'),
      '',
    );
    this.indexerRejectUnauthorized = this.booleanValue(
      this.config.get<unknown>('WAZUH_INDEXER_REJECT_UNAUTHORIZED'),
      false,
    );
  }

  async runForUserDevice(
    userId: string,
    deviceId: string,
  ): Promise<AiPipelineCheckResult> {
    if (this.activeChecks.has(deviceId)) {
      throw new ConflictException({
        code: 'AI_PIPELINE_ALREADY_RUNNING',
        message: 'Thiết bị đang chạy kiểm tra AI pipeline. Chờ phiên hiện tại hoàn tất rồi bấm kiểm tra lại.',
      });
    }

    const promise = this.runInternal(userId, deviceId);
    this.activeChecks.set(deviceId, promise);

    try {
      return await promise;
    } finally {
      this.activeChecks.delete(deviceId);
    }
  }

  private async runInternal(
    userId: string,
    deviceId: string,
  ): Promise<AiPipelineCheckResult> {
    const startedAt = new Date();
    const steps: PipelineStepResult[] = [];

    const device = await this.database.device.findFirst({
      where: {
        id: deviceId,
        userId,
      },
      include: {
        wazuhBinding: true,
      },
    });

    if (!device) {
      throw new NotFoundException({
        code: 'DEVICE_NOT_FOUND',
        message: 'Không tìm thấy thiết bị thuộc tài khoản hiện tại',
      });
    }

    const wazuhAgentId = device.wazuhBinding?.wazuhAgentId;

    if (!wazuhAgentId) {
      throw new NotFoundException({
        code: 'WAZUH_AGENT_BINDING_NOT_FOUND',
        message: 'Thiết bị chưa có Wazuh Agent binding nên chưa thể chạy AI pipeline.',
      });
    }

    this.ensureFile(this.pythonPath, 'Không tìm thấy Python runtime cho AI pipeline');
    this.ensureFile(this.modelRoot, 'Không tìm thấy thư mục model-risk-prediction');

    await mkdir(this.dataUserDir, { recursive: true });
    await this.cleanDataUserJson();

    steps.push(await this.runExtractFromWazuh(wazuhAgentId));
    steps.push(await this.ensureXgboostModel());
    steps.push(await this.runPipeline());

    const importResult = await this.importer.importForUserDevice(userId, deviceId);
    const [activeVulnerabilities, topPredictions] = await Promise.all([
      this.database.detectedVulnerability.count({
        where: {
          deviceId,
          status: VulnerabilityLifecycleStatus.ACTIVE,
        },
      }),
      this.loadTopPredictions(deviceId),
    ]);
    const completedAt = new Date();

    const result: AiPipelineCheckResult = {
      deviceId,
      wazuhAgentId,
      startedAt: startedAt.toISOString(),
      completedAt: completedAt.toISOString(),
      durationMs: completedAt.getTime() - startedAt.getTime(),
      steps,
      importResult,
      activeVulnerabilities,
      topPredictions,
    };

    this.logger.log(
      `AI pipeline check completed for device=${deviceId} agent=${wazuhAgentId} imported=${importResult.recordsImported} active=${activeVulnerabilities}`,
    );

    return result;
  }

  private async runExtractFromWazuh(wazuhAgentId: string): Promise<PipelineStepResult> {
    const script = join(this.modelRoot, 'CTI Collector', 'Extract_Data_Wazuh.py');
    this.ensureFile(script, 'Không tìm thấy CTI Collector/Extract_Data_Wazuh.py');

    if (!this.indexerPassword) {
      throw new ServiceUnavailableException({
        code: 'WAZUH_INDEXER_PASSWORD_MISSING',
        message: 'Thiếu WAZUH_INDEXER_PASSWORD trong .env nên backend không thể gọi Extract_Data_Wazuh.py không tương tác.',
      });
    }

    const args = [
      script,
      '--indexer-url',
      this.indexerUrl,
      '--username',
      this.indexerUsername,
      '--password',
      this.indexerPassword,
      '--agent-id',
      wazuhAgentId,
    ];

    if (!this.indexerRejectUnauthorized) {
      args.push('--insecure');
    }

    return this.runPython('extract-wazuh-cve-list', args, true);
  }

  private async ensureXgboostModel(): Promise<PipelineStepResult> {
    const artifact = join(this.modelRoot, 'Model Result', 'xgboost', 'xgboost_model.pkl');

    if (existsSync(artifact)) {
      return {
        step: 'ensure-xgboost-model',
        command: 'xgboost artifact already exists',
        skipped: true,
        durationMs: 0,
        stdoutTail: '',
        stderrTail: '',
      };
    }

    const script = join(this.modelRoot, 'Model', 'xgboost_model.py');
    this.ensureFile(script, 'Không tìm thấy Model/xgboost_model.py');

    return this.runPython('train-xgboost-model', [script], false);
  }

  private async runPipeline(): Promise<PipelineStepResult> {
    const script = join(this.modelRoot, 'run_pipeline.py');
    this.ensureFile(script, 'Không tìm thấy run_pipeline.py');

    return this.runPython('run-pipeline-inference', [script], false);
  }

  private async runPython(
    step: string,
    args: string[],
    redactPassword: boolean,
  ): Promise<PipelineStepResult> {
    const startedAt = Date.now();
    const command = [this.pythonPath, ...args].join(' ');
    const safeCommand = redactPassword
      ? command.replace(this.indexerPassword, '***')
      : command;

    try {
      const { stdout, stderr } = await execFileAsync(
        this.pythonPath,
        args,
        {
          cwd: this.modelRoot,
          timeout: this.timeoutMs,
          maxBuffer: 64 * 1024 * 1024,
          windowsHide: true,
          env: {
            ...process.env,
            PYTHONIOENCODING: 'utf-8',
            PYTHONUTF8: '1',
          },
        },
      );

      return {
        step,
        command: safeCommand,
        skipped: false,
        durationMs: Date.now() - startedAt,
        stdoutTail: this.tail(stdout),
        stderrTail: this.tail(stderr),
      };
    } catch (error: unknown) {
      const err = error as {
        message?: string;
        stdout?: string | Buffer;
        stderr?: string | Buffer;
        signal?: string;
        code?: number | string;
      };
      const stdout = Buffer.isBuffer(err.stdout)
        ? err.stdout.toString('utf8')
        : err.stdout ?? '';
      const stderr = Buffer.isBuffer(err.stderr)
        ? err.stderr.toString('utf8')
        : err.stderr ?? '';

      throw new ServiceUnavailableException({
        code: 'AI_PIPELINE_STEP_FAILED',
        message: `AI pipeline step thất bại: ${step}`,
        step,
        command: safeCommand,
        exitCode: err.code ?? null,
        signal: err.signal ?? null,
        error: err.message ?? 'unknown error',
        stdoutTail: this.tail(stdout),
        stderrTail: this.tail(stderr),
      });
    }
  }

  private async cleanDataUserJson(): Promise<void> {
    const entries = await readdir(this.dataUserDir, { withFileTypes: true })
      .catch(() => []);

    await Promise.all(
      entries
        .filter((entry) => entry.isFile() && entry.name.toLowerCase().endsWith('.json'))
        .map((entry) => rm(join(this.dataUserDir, entry.name), { force: true })),
    );
  }

  private async loadTopPredictions(deviceId: string): Promise<TopPredictionItem[]> {
    const items = await this.database.detectedVulnerability.findMany({
      where: {
        deviceId,
        status: VulnerabilityLifecycleStatus.ACTIVE,
        aiPrediction: { isNot: null },
      },
      take: 500,
      include: {
        aiPrediction: true,
      },
      orderBy: {
        lastSeenAt: 'desc',
      },
    });

    return items
      .sort((left, right) => {
        const leftScore = left.aiPrediction?.predictedPercentile ??
          ((left.aiPrediction?.attackProbability ?? 0) * 100);
        const rightScore = right.aiPrediction?.predictedPercentile ??
          ((right.aiPrediction?.attackProbability ?? 0) * 100);
        return rightScore - leftScore;
      })
      .slice(0, 10)
      .map((item) => ({
        cveId: item.cveId,
        riskLevel: item.aiPrediction?.riskLevel ?? null,
        attackProbability: item.aiPrediction?.attackProbability ?? null,
        predictedPercentile: item.aiPrediction?.predictedPercentile ?? null,
        predictedAt: item.aiPrediction?.predictedAt ?? null,
      }));
  }

  private ensureFile(path: string, message: string): void {
    if (!existsSync(path)) {
      throw new ServiceUnavailableException({
        code: 'AI_PIPELINE_PATH_NOT_FOUND',
        message,
        path,
      });
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

  private integerValue(
    value: unknown,
    fallback: number,
    min: number,
    max: number,
  ): number {
    const parsed = typeof value === 'number'
      ? value
      : typeof value === 'string' && value.trim()
        ? Number(value)
        : Number.NaN;

    if (!Number.isFinite(parsed)) {
      return fallback;
    }

    return Math.min(Math.max(Math.trunc(parsed), min), max);
  }

  private booleanValue(value: unknown, fallback: boolean): boolean {
    if (typeof value === 'boolean') {
      return value;
    }

    if (typeof value === 'string') {
      const normalized = value.trim().toLowerCase();
      if (['true', '1', 'yes', 'y'].includes(normalized)) {
        return true;
      }
      if (['false', '0', 'no', 'n'].includes(normalized)) {
        return false;
      }
    }

    return fallback;
  }

  private tail(value: string, maxLength = 4000): string {
    return value.length > maxLength
      ? value.slice(value.length - maxLength)
      : value;
  }
}
