import {
  Injectable,
  Logger,
  OnApplicationShutdown,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
  type ChildProcessWithoutNullStreams,
  spawn,
} from 'node:child_process';
import { isAbsolute, relative, resolve, sep } from 'node:path';
import { unlink } from 'node:fs/promises';
import { createInterface } from 'node:readline';

export interface AiModelRuntimeInput {
  cve_id: string;
  cwe_id: string | null;
  cvss_version: string | null;
  base_score: number | null;
  av_label: string | null;
  ac_label: string | null;
  pr_label: string | null;
  ui_label: string | null;
  scope_label: string | null;
  c_label: string | null;
  i_label: string | null;
  a_label: string | null;
  exploitability_score: number | null;
  impact_score: number | null;
  severity_label: string | null;
  epss_score: number | null;
  kev_flag: 0 | 1;
}

export interface AiModelRuntimeResult {
  cveId: string | null;
  modelName: string | null;
  modelVersion: string | null;
  attackProbability: number | null;
  predictedPercentile: number | null;
  riskLevel: string | null;
  finalPriority: string | null;
  baseScore: number | null;
  baseSeverity: string | null;
  epssSupport: number | null;
  prediction: number | null;
  details?: Record<string, unknown>;
  artifactPath: string | null;
}

interface QueuedPrediction {
  id: string;
  input: AiModelRuntimeInput;
  resolve: (value: AiModelRuntimeResult | null) => void;
  reject: (reason?: unknown) => void;
}

interface ActivePrediction extends QueuedPrediction {
  timer: ReturnType<typeof setTimeout>;
}

interface WorkerEnvelope {
  type?: unknown;
  id?: unknown;
  result?: unknown;
  error?: unknown;
  traceback?: unknown;
  modelVersion?: unknown;
}

@Injectable()
export class AiModelRuntimeService implements OnApplicationShutdown {
  private readonly logger = new Logger(AiModelRuntimeService.name);
  private readonly enabled: boolean;
  private readonly model: string;
  private readonly modelVersion: string;
  private readonly pythonPath: string;
  private readonly workerScript: string;
  private readonly runtimeDir: string;
  private readonly dataUserDir: string;
  private readonly timeoutMs: number;

  private worker: ChildProcessWithoutNullStreams | null = null;
  private workerReady: Promise<void> | null = null;
  private predictionSequence = 0;
  private readonly queue: QueuedPrediction[] = [];
  private activePrediction: ActivePrediction | null = null;
  private draining = false;
  private shuttingDown = false;

  constructor(config: ConfigService) {
    this.enabled = this.booleanValue(
      config.get<unknown>('AI_MODEL_ENABLED'),
      true,
    );
    this.model = this.stringValue(
      config.get<unknown>('AI_MODEL_ACTIVE'),
      'xgboost',
    );
    this.modelVersion = this.stringValue(
      config.get<unknown>('AI_MODEL_VERSION'),
      'CYRP_XGBOOST_CVSS_PERCENTILE_V3',
    );
    this.pythonPath = this.resolveProjectPath(
      this.stringValue(
        config.get<unknown>('AI_MODEL_PYTHON_PATH'),
        'apps/ai-model/.venv/Scripts/python.exe',
      ),
    );
    this.workerScript = this.resolveProjectPath(
      this.stringValue(
        config.get<unknown>('AI_MODEL_WORKER_SCRIPT'),
        'apps/ai-model/model-risk-prediction/runtime/predict_worker.py',
      ),
    );
    this.runtimeDir = this.resolveProjectPath(
      this.stringValue(
        config.get<unknown>('AI_MODEL_RUNTIME_DIR'),
        'apps/ai-model/model-risk-prediction',
      ),
    );
    this.dataUserDir = resolve(this.runtimeDir, 'Data User');
    this.timeoutMs = this.integerValue(
      config.get<unknown>('AI_MODEL_TIMEOUT_MS'),
      60_000,
      5_000,
      300_000,
    );
  }

  isEnabled(): boolean {
    return this.enabled;
  }

  activeModel(): string {
    return this.model;
  }

  configuredModelVersion(): string {
    return this.modelVersion;
  }

  async cleanupArtifact(artifactPath: string | null): Promise<boolean> {
    if (!artifactPath) {
      return false;
    }

    const resolvedArtifact = resolve(artifactPath);
    const relativePath = relative(this.dataUserDir, resolvedArtifact);
    const outsideDataUser =
      relativePath === '..' ||
      relativePath.startsWith(`..${sep}`) ||
      isAbsolute(relativePath);

    if (outsideDataUser) {
      this.logger.warn(
        `Refusing to delete AI artifact outside Data User: ${resolvedArtifact}`,
      );
      return false;
    }

    try {
      await unlink(resolvedArtifact);
      return true;
    } catch (error: unknown) {
      const code =
        typeof error === 'object' && error !== null && 'code' in error
          ? String((error as { code?: unknown }).code ?? '')
          : '';

      if (code === 'ENOENT') {
        return false;
      }

      this.logger.warn(
        `Unable to delete committed AI artifact ${resolvedArtifact}: ${this.errorMessage(error)}`,
      );
      return false;
    }
  }

  async predict(
    input: AiModelRuntimeInput,
  ): Promise<AiModelRuntimeResult | null> {
    if (!this.enabled) {
      return null;
    }

    if (this.shuttingDown) {
      throw new Error('AI model runtime is shutting down');
    }

    return new Promise((resolvePromise, rejectPromise) => {
      const id = `prediction-${Date.now()}-${++this.predictionSequence}`;
      this.queue.push({
        id,
        input,
        resolve: resolvePromise,
        reject: rejectPromise,
      });
      void this.drainQueue();
    });
  }

  onApplicationShutdown(): void {
    this.shuttingDown = true;

    const shutdownError = new Error('AI model runtime stopped');
    this.rejectActive(shutdownError);

    while (this.queue.length > 0) {
      this.queue.shift()?.reject(shutdownError);
    }

    if (this.worker && !this.worker.killed) {
      this.worker.kill();
    }

    this.worker = null;
    this.workerReady = null;
  }

  private async drainQueue(): Promise<void> {
    if (
      this.draining ||
      this.activePrediction ||
      this.queue.length === 0 ||
      this.shuttingDown
    ) {
      return;
    }

    this.draining = true;

    try {
      const request = this.queue.shift();
      if (!request) {
        return;
      }

      try {
        await this.ensureWorker();
      } catch (error: unknown) {
        request.reject(error);
        return;
      }

      if (!this.worker || this.worker.killed) {
        request.reject(new Error('AI model worker is not available'));
        return;
      }

      const timer = setTimeout(() => {
        if (this.activePrediction?.id !== request.id) {
          return;
        }

        const timeoutError = new Error(
          `AI model worker timed out for ${request.input.cve_id} after ${this.timeoutMs}ms`,
        );
        this.rejectActive(timeoutError);
        this.restartWorker(timeoutError);
      }, this.timeoutMs);

      this.activePrediction = {
        ...request,
        timer,
      };

      const line = `${JSON.stringify({
        id: request.id,
        input: request.input,
      })}\n`;

      this.worker.stdin.write(line, 'utf8', (error) => {
        if (!error) {
          return;
        }

        this.rejectActive(error);
        this.restartWorker(error);
      });
    } finally {
      this.draining = false;

      if (
        !this.activePrediction &&
        this.queue.length > 0 &&
        !this.shuttingDown
      ) {
        void this.drainQueue();
      }
    }
  }

  private ensureWorker(): Promise<void> {
    if (this.worker && this.workerReady && !this.worker.killed) {
      return this.workerReady;
    }

    const child = spawn(
      this.pythonPath,
      [
        '-u',
        this.workerScript,
        '--model',
        this.model,
      ],
      {
        cwd: this.runtimeDir,
        windowsHide: true,
        env: {
          ...process.env,
          PYTHONUTF8: '1',
          PYTHONIOENCODING: 'utf-8',
        },
        stdio: ['pipe', 'pipe', 'pipe'],
      },
    );

    this.worker = child;
    let readySettled = false;

    this.workerReady = new Promise<void>((resolveReady, rejectReady) => {
      const output = createInterface({ input: child.stdout });

      output.on('line', (line) => {
        const envelope = this.parseEnvelope(line);
        if (!envelope) {
          this.logger.debug(
            `Ignoring non-JSON AI worker stdout: ${line.slice(0, 500)}`,
          );
          return;
        }

        if (envelope.type === 'ready') {
          if (!readySettled) {
            readySettled = true;
            resolveReady();
            this.logger.log(
              `AI model worker ready: model=${this.model} version=${this.optionalString(envelope.modelVersion) ?? this.modelVersion}`,
            );
          }
          return;
        }

        if (envelope.type === 'startup-error') {
          const error = new Error(
            this.workerErrorMessage(envelope),
          );
          if (!readySettled) {
            readySettled = true;
            rejectReady(error);
          }
          this.restartWorker(error, child);
          return;
        }

        this.handlePredictionEnvelope(envelope);
      });

      child.stderr.on('data', (chunk: Buffer | string) => {
        const text = String(chunk).trim();
        if (text) {
          this.logger.debug(`AI model worker stderr: ${text.slice(0, 1000)}`);
        }
      });

      child.once('error', (error) => {
        if (!readySettled) {
          readySettled = true;
          rejectReady(error);
        }
        this.restartWorker(error, child);
      });

      child.once('exit', (code, signal) => {
        const error = new Error(
          `AI model worker exited: code=${String(code)} signal=${String(signal)}`,
        );
        if (!readySettled) {
          readySettled = true;
          rejectReady(error);
        }
        this.restartWorker(error, child);
      });
    });

    return this.workerReady;
  }

  private handlePredictionEnvelope(envelope: WorkerEnvelope): void {
    const id = this.optionalString(envelope.id);
    const active = this.activePrediction;

    if (!id || !active || active.id !== id) {
      this.logger.warn(
        `Ignoring unexpected AI worker response id=${id ?? 'missing'}`,
      );
      return;
    }

    clearTimeout(active.timer);
    this.activePrediction = null;

    if (envelope.error !== undefined && envelope.error !== null) {
      active.reject(new Error(this.workerErrorMessage(envelope)));
    } else if (!this.isRecord(envelope.result)) {
      active.reject(new Error('AI model worker returned an invalid result'));
    } else {
      active.resolve(this.parseResultRecord(envelope.result));
    }

    void this.drainQueue();
  }

  private rejectActive(error: unknown): void {
    const active = this.activePrediction;
    if (!active) {
      return;
    }

    clearTimeout(active.timer);
    this.activePrediction = null;
    active.reject(error);
    void this.drainQueue();
  }

  private restartWorker(
    error: unknown,
    expectedWorker: ChildProcessWithoutNullStreams | null = this.worker,
  ): void {
    if (!expectedWorker || this.worker !== expectedWorker) {
      return;
    }

    this.logger.warn(
      `Restarting AI model worker: ${this.errorMessage(error)}`,
    );

    if (!expectedWorker.killed) {
      expectedWorker.kill();
    }

    this.worker = null;
    this.workerReady = null;
    this.rejectActive(error);
  }

  private parseEnvelope(line: string): WorkerEnvelope | null {
    try {
      const parsed = JSON.parse(line) as unknown;
      return this.isRecord(parsed) ? parsed : null;
    } catch {
      return null;
    }
  }

  private parseResultRecord(
    parsed: Record<string, unknown>,
  ): AiModelRuntimeResult {
    return {
      cveId: this.optionalString(parsed.cveId),
      modelName: this.optionalString(parsed.modelName),
      modelVersion: this.optionalString(parsed.modelVersion),
      attackProbability: this.optionalNumber(parsed.attackProbability),
      predictedPercentile: this.optionalNumber(parsed.predictedPercentile),
      riskLevel: this.optionalString(parsed.riskLevel),
      finalPriority: this.optionalString(parsed.finalPriority),
      baseScore: this.optionalNumber(parsed.baseScore),
      baseSeverity: this.optionalString(parsed.baseSeverity),
      epssSupport: this.optionalNumber(parsed.epssSupport),
      prediction: this.optionalNumber(parsed.prediction),
      details: this.isRecord(parsed.details)
        ? parsed.details
        : undefined,
      artifactPath: this.optionalString(parsed.artifactPath),
    };
  }

  private workerErrorMessage(envelope: WorkerEnvelope): string {
    const error = this.optionalString(envelope.error) ?? 'Unknown AI worker error';
    const traceback = this.optionalString(envelope.traceback);
    return traceback ? `${error}\n${traceback}` : error;
  }

  private resolveProjectPath(value: string): string {
    if (isAbsolute(value)) {
      return value;
    }

    return resolve(process.cwd(), value);
  }

  private booleanValue(value: unknown, fallback: boolean): boolean {
    if (typeof value === 'boolean') {
      return value;
    }

    if (typeof value === 'string') {
      const normalized = value.trim().toLowerCase();

      if (['1', 'true', 'yes', 'on'].includes(normalized)) {
        return true;
      }

      if (['0', 'false', 'no', 'off'].includes(normalized)) {
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
    const parsed =
      typeof value === 'number'
        ? value
        : typeof value === 'string'
          ? Number.parseInt(value, 10)
          : Number.NaN;

    if (!Number.isFinite(parsed)) {
      return fallback;
    }

    return Math.min(Math.max(parsed, min), max);
  }

  private stringValue(value: unknown, fallback: string): string {
    return typeof value === 'string' && value.trim()
      ? value.trim()
      : fallback;
  }

  private optionalString(value: unknown): string | null {
    return typeof value === 'string' && value.trim()
      ? value
      : null;
  }

  private optionalNumber(value: unknown): number | null {
    if (typeof value === 'boolean') {
      return value ? 1 : 0;
    }

    if (typeof value === 'number' && Number.isFinite(value)) {
      return value;
    }

    if (typeof value === 'string' && value.trim()) {
      const parsed = Number(value);
      return Number.isFinite(parsed) ? parsed : null;
    }

    return null;
  }

  private isRecord(value: unknown): value is Record<string, unknown> {
    return typeof value === 'object' && value !== null && !Array.isArray(value);
  }

  private errorMessage(error: unknown): string {
    return error instanceof Error ? error.message : String(error);
  }
}
