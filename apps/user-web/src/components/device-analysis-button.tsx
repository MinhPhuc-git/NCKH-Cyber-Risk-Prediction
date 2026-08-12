'use client';
import { CveRemediationLink } from '@/components/cve-remediation-link';
import {
  MouseEvent,
  useCallback,
  useEffect,
  useMemo,
  useState,
} from 'react';

import type {
  ApiErrorResponse,
} from '@/lib/api-types';
import type {
  Pagination,
  VulnerabilityItem,
} from '@/lib/security-data-types';
import type {
  DeviceSecuritySnapshot,
} from '@/lib/security-snapshot-types';

import styles from './device-analysis-button.module.css';



function normalizeAiRiskLevel(value: unknown): 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | 'UNKNOWN' {
  const level = String(value ?? '').trim().toUpperCase();

  if (level === 'LOW' || level === 'THẤP') {
    return 'LOW';
  }

  if (level === 'MEDIUM' || level === 'TRUNG BÌNH' || level === 'TRUNG_BINH') {
    return 'MEDIUM';
  }

  if (level === 'HIGH' || level === 'CAO') {
    return 'HIGH';
  }

  if (
    level === 'CRITICAL' ||
    level === 'VERY_HIGH' ||
    level === 'VERY HIGH' ||
    level === 'RẤT CAO' ||
    level === 'RAT CAO'
  ) {
    return 'CRITICAL';
  }

  return 'UNKNOWN';
}

function buildAiRiskDistribution(items: Array<{ riskLevel?: unknown }>) {
  const result = {
    low: 0,
    medium: 0,
    high: 0,
    critical: 0,
  };

  for (const item of items ?? []) {
    const level = normalizeAiRiskLevel(item.riskLevel);

    if (level === 'LOW') {
      result.low += 1;
    } else if (level === 'MEDIUM') {
      result.medium += 1;
    } else if (level === 'HIGH') {
      result.high += 1;
    } else if (level === 'CRITICAL') {
      result.critical += 1;
    }
  }

  return result;
}

function percentileBucketKey(
  value: number | null,
): 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | null {
  if (value === null || !Number.isFinite(value)) {
    return null;
  }

  const percent = value <= 1 ? value * 100 : value;

  if (percent >= 85) return 'CRITICAL';
  if (percent >= 65) return 'HIGH';
  if (percent >= 45) return 'MEDIUM';

  return 'LOW';
}

function toPercent(value: unknown, mode: 'probability' | 'percentile' = 'probability') {
  const numberValue = Number(value);

  if (!Number.isFinite(numberValue)) {
    return null;
  }

  if (mode === 'probability') {
    return numberValue <= 1 ? numberValue * 100 : numberValue;
  }

  return numberValue;
}


interface AiRiskSummaryResponse {
  total: number;
  loaded?: number;
  distribution: {
    LOW: number;
    MEDIUM: number;
    HIGH: number;
    CRITICAL: number;
  };
  highestAttackProbability: number | null;
  highestPercentile: number | null;
  calculatedAt: string;
}

interface MachineCheckStartResponse {
  runId: string;
  status: 'RUNNING';
  pollAfterMs?: number;
  message?: string;
}

interface MachineCheckStatusResponse {
  runId: string;
  status: 'RUNNING' | 'COMPLETED' | 'PARTIAL' | 'FAILED';
  phase?: string;
  message?: string;
  cached?: boolean;
  error?: string | null;
}

function wait(milliseconds: number): Promise<void> {
  return new Promise((resolvePromise) => {
    window.setTimeout(resolvePromise, milliseconds);
  });
}

interface DeviceAnalysisButtonProps {
  deviceId: string;
  variant?: 'default' | 'repairOrb';
  wazuhAgentId?: string | null;
  wazuhAgentName?: string | null;
}

type JsonRecord = Record<string, unknown>;

type DeviceHighestAiSummary = {
  total: number;
  highestPercentile: number | null;
  highestAttackProbability: number | null;
  topCveId: string | null;
  topPackageName: string | null;
  topRiskLevel: string | null;
  topPredictedAt: string | null;
  latestPredictedAt: string | null;
  topItems: VulnerabilityItem[];
};

function cyrpNumber(value: unknown): number | null {
  if (typeof value === 'number' && Number.isFinite(value)) {
    return value;
  }

  if (typeof value === 'string' && value.trim()) {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : null;
  }

  return null;
}

function cyrpRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === 'object'
    ? (value as Record<string, unknown>)
    : {};
}

function cyrpPredictionRecord(
  item: VulnerabilityItem | null | undefined,
): Record<string, unknown> {
  return cyrpRecord(item?.aiPrediction);
}

function cyrpExplanationRecord(
  item: VulnerabilityItem | null | undefined,
): Record<string, unknown> {
  return cyrpRecord(cyrpPredictionRecord(item).explanation);
}

function cyrpPredictedPercentile(
  item: VulnerabilityItem | null | undefined,
): number | null {
  const prediction = cyrpPredictionRecord(item);
  const explanation = cyrpExplanationRecord(item);

  return cyrpNumber(prediction.predictedPercentile)
    ?? cyrpNumber(prediction.predicted_percentile)
    ?? cyrpNumber(prediction.percentile)
    ?? cyrpNumber(explanation.predictedPercentile)
    ?? cyrpNumber(explanation.predicted_percentile)
    ?? cyrpNumber(explanation.Percentile)
    ?? null;
}

function cyrpAttackProbability(
  item: VulnerabilityItem | null | undefined,
): number | null {
  const prediction = cyrpPredictionRecord(item);
  const explanation = cyrpExplanationRecord(item);

  return cyrpNumber(prediction.attackProbability)
    ?? cyrpNumber(prediction.attack_probability)
    ?? cyrpNumber(prediction.probability)
    ?? cyrpNumber(explanation.attackProbability)
    ?? cyrpNumber(explanation.attack_probability)
    ?? cyrpNumber(explanation.Probability)
    ?? null;
}

function cyrpRiskLevel(
  item: VulnerabilityItem | null | undefined,
): string | null {
  const prediction = cyrpPredictionRecord(item);
  const explanation = cyrpExplanationRecord(item);

  const value =
    prediction.riskLevel
    ?? prediction.risk_level
    ?? explanation.riskLevel
    ?? explanation.risk_level
    ?? explanation.Risk;

  return typeof value === 'string' && value.trim()
    ? value.trim().toUpperCase()
    : null;
}

function cyrpPercentileSortValue(
  item: VulnerabilityItem | null | undefined,
): number {
  const percentile = cyrpPredictedPercentile(item);

  if (typeof percentile === 'number' && Number.isFinite(percentile)) {
    return percentile <= 1 ? percentile * 100 : percentile;
  }

  const probability = cyrpAttackProbability(item);

  if (typeof probability === 'number' && Number.isFinite(probability)) {
    return probability <= 1 ? probability * 100 : probability;
  }

  return -1;
}

function percentileAsRiskScale(value: number | null): number | null {
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    return null;
  }

  return value > 1 ? value / 100 : value;
}

function gaugeClass(value: number | null): string {
  if (value === null) {
    return styles.gaugeNeutral;
  }

  if (value >= 0.85) {
    return styles.gaugeCritical;
  }

  if (value >= 0.65) {
    return styles.gaugeHigh;
  }

  if (value >= 0.45) {
    return styles.gaugeMedium;
  }

  return styles.gaugeLow;
}

function riskBandLabel(value: number | null): string {
  if (value === null) {
    return 'Chưa đủ dữ liệu';
  }

  if (value >= 0.85) {
    return 'Nguy cơ nghiêm trọng';
  }

  if (value >= 0.65) {
    return 'Nguy cơ cao';
  }

  if (value >= 0.45) {
    return 'Nguy cơ trung bình';
  }

  return 'Nguy cơ thấp';
}

function formatPercentileDisplay(value: number | null | undefined): string {
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    return '—';
  }

  const percent = value <= 1 ? value * 100 : value;
  return `${Math.round(percent)}%`;
}

function percentileAsProbabilityScale(value: number | null | undefined): number | null {
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    return null;
  }

  return value <= 1 ? value : value / 100;
}

function cyrpPercentileGaugeClass(value: number | null | undefined): string {
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    return styles.gaugeNeutral;
  }

  const percent = value <= 1 ? value * 100 : value;

  if (percent >= 85) {
    return styles.gaugeCritical;
  }

  if (percent >= 65) {
    return styles.gaugeHigh;
  }

  if (percent >= 45) {
    return styles.gaugeMedium;
  }

  return styles.gaugeLow;
}


type RiskBucketKey =
  | 'LOW'
  | 'MEDIUM'
  | 'HIGH'
  | 'CRITICAL';

interface RiskBucketRow {
  key: RiskBucketKey;
  label: string;
  count: number;
}

function errorMessage(
  payload: ApiErrorResponse,
  fallback: string,
): string {
  if (Array.isArray(payload.message)) {
    return payload.message.join(', ');
  }

  return payload.message ?? fallback;
}

function asRecord(
  value: unknown,
): JsonRecord | null {
  return value !== null &&
    typeof value === 'object' &&
    !Array.isArray(value)
    ? value as JsonRecord
    : null;
}

function numberValue(
  value: unknown,
): number | null {
  if (typeof value === 'number' && Number.isFinite(value)) {
    return value;
  }

  if (typeof value === 'string' && value.trim()) {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : null;
  }

  return null;
}

function stringValue(
  value: unknown,
): string | null {
  return typeof value === 'string' && value.trim()
    ? value
    : null;
}

function formatDate(
  value: string | null,
): string {
  if (!value) {
    return 'Chưa đồng bộ';
  }

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return 'Không xác định';
  }

  return new Intl.DateTimeFormat(
    'vi-VN',
    {
      dateStyle: 'short',
      timeStyle: 'medium',
    },
  ).format(date);
}

function formatProbability(
  value: number | null | undefined,
): string {
  if (typeof value !== 'number' || Number.isNaN(value)) {
    return '—';
  }

  return `${Math.round(value * 100)}%`;
}


function normalizeProbabilityLikeValue(
  value: number | null | undefined,
): number | null {
  if (typeof value !== 'number' || Number.isNaN(value)) {
    return null;
  }

  if (value > 1) {
    return Math.max(0, Math.min(1, value / 100));
  }

  return Math.max(0, Math.min(1, value));
}

function modelAttackProbabilityValue(
  item: VulnerabilityItem | null | undefined,
): number | null {
  return normalizeProbabilityLikeValue(
    item?.aiPrediction?.attackProbability,
  );
}

function modelExploitRiskValue(
  item: VulnerabilityItem | null | undefined,
): number | null {
  const percentile = normalizeProbabilityLikeValue(
    item?.aiPrediction?.predictedPercentile,
  );

  if (percentile !== null) {
    return percentile;
  }

  return normalizeProbabilityLikeValue(
    item?.aiPrediction?.attackProbability,
  );
}

function formatScore(
  value: number | null | undefined,
  digits = 3,
): string {
  if (typeof value !== 'number' || Number.isNaN(value)) {
    return '—';
  }

  return value.toFixed(digits);
}

function formatShortScore(
  value: number | null | undefined,
): string {
  if (typeof value !== 'number' || Number.isNaN(value)) {
    return '—';
  }

  return value.toFixed(1);
}

function formatPercentBar(
  value: number,
): string {
  return `${Math.max(0, Math.min(100, value))}%`;
}

function modelLabel(
  modelVersion: string | null | undefined,
): string {
  if (!modelVersion) {
    return 'Chưa có AI model';
  }

  if (modelVersion === 'CYRP_XGBOOST_CVSS_PERCENTILE_V3') {
    return 'CYRP XGBoost CVSS Percentile';
  }

  if (modelVersion === 'CYRP_NO_AI_MODEL_RESULT_V1') {
    return 'Chưa có kết quả model mới';
  }

  return modelVersion.replaceAll('_', ' ');
}

function riskClass(
  level: string | null | undefined,
): string {
  switch (level?.toUpperCase()) {
    case 'CRITICAL':
      return styles.riskCritical;
    case 'HIGH':
      return styles.riskHigh;
    case 'MEDIUM':
      return styles.riskMedium;
    case 'LOW':
      return styles.riskLow;
    default:
      return styles.riskNeutral;
  }
}

function finalPriorityScore(
  item: VulnerabilityItem,
): number | null {
  const explanation = asRecord(
    item.aiPrediction?.explanation,
  );

  if (!explanation) {
    return null;
  }

  return numberValue(
    explanation.final_priority_score ??
      explanation.finalPriorityScore,
  );
}

function finalPriorityLevel(
  item: VulnerabilityItem,
): string | null {
  const explanation = asRecord(
    item.aiPrediction?.explanation,
  );

  if (!explanation) {
    return null;
  }

  return stringValue(
    explanation.final_priority_level ??
      explanation.finalPriorityLevel,
  );
}

function epssSupport(
  item: VulnerabilityItem,
): number | null {
  const explanation = asRecord(
    item.aiPrediction?.explanation,
  );

  if (!explanation) {
    return item.latestThreatSignal?.epssScore ?? null;
  }

  return numberValue(
    explanation.official_epss_score ??
      explanation.officialEpssScore,
  ) ?? item.latestThreatSignal?.epssScore ?? null;
}

function summaryMessage(
  probability: number | null,
  activeCount: number,
  alertCount: number,
): string {
  if (probability !== null && probability >= 0.8) {
    return 'Máy đang có một số lỗ hổng cần ưu tiên xử lý ngay. Hệ thống AI đánh giá nguy cơ khai thác ở mức cao.';
  }

  if (probability !== null && probability >= 0.5) {
    return 'Hệ thống đã phát hiện các lỗ hổng cần theo dõi sát. Nên xem các mục ưu tiên và thực hiện vá trước.';
  }

  if (activeCount > 0 || alertCount > 0) {
    return 'Thiết bị hiện có tín hiệu bảo mật cần theo dõi, nhưng chưa xuất hiện lỗ hổng có xác suất khai thác quá cao.';
  }

  return 'Chưa phát hiện tín hiệu bất thường nổi bật trong lần kiểm tra này.';
}

export function DeviceAnalysisButton({
  deviceId,
  variant = 'default',
  wazuhAgentId: propWazuhAgentId = null,
  wazuhAgentName: propWazuhAgentName = null,
}: DeviceAnalysisButtonProps) {
  const [snapshot, setSnapshot] =
    useState<DeviceSecuritySnapshot | null>(
      null,
    );
  const [vulnerabilities, setVulnerabilities] = useState<VulnerabilityItem[]>([]);
  const [aiRiskSummary, setAiRiskSummary] = useState<AiRiskSummaryResponse | null>(null);
  const [vulnerabilityTotal, setVulnerabilityTotal] =
    useState(0);
  const [isRunning, setIsRunning] =
    useState(false);
  const [isModalOpen, setIsModalOpen] =
    useState(false);
  useEffect(() => {
    const root = document.documentElement;
    const className = 'cyrp-machine-check-open';

    if (isModalOpen) {
      root.classList.add(className);
    } else {
      root.classList.remove(className);
    }

    return () => {
      root.classList.remove(className);
    };
  }, [isModalOpen]);
  const [error, setError] =
    useState('');
  const [progressMessage, setProgressMessage] =
    useState('Đang chuẩn bị kiểm tra máy.');
  const [expandedId, setExpandedId] =
    useState<string | null>(null);
  const hasCachedResult = snapshot !== null;

  async function openCachedResult(): Promise<void> {
    if (!snapshot || isRunning) {
      return;
    }

    setError('');
    setExpandedId(null);
    setIsModalOpen(true);

    try {
      await loadVulnerabilities();
      await loadDeviceHighestAiSummary();
    } catch (caught: unknown) {
      setError(
        caught instanceof Error
          ? caught.message
          : 'Không thể tải lại kết quả kiểm tra cũ',
      );
    }
  }
  const loadLatest = useCallback(
    async (
      signal?: AbortSignal,
    ): Promise<void> => {
      const response = await fetch(
        `/api/devices/${deviceId}/security-snapshot`,
        {
          method: 'GET',
          cache: 'no-store',
          credentials: 'same-origin',
          signal,
        },
      );
      const payload =
        (await response.json()) as
          | DeviceSecuritySnapshot
          | null
          | ApiErrorResponse;

      if (!response.ok) {
        throw new Error(
          errorMessage(
            payload as ApiErrorResponse,
            'Không thể tải snapshot bảo mật',
          ),
        );
      }

      setSnapshot(
        payload as DeviceSecuritySnapshot | null,
      );
    },
    [deviceId],
  );

  const loadVulnerabilities = useCallback(
    async (): Promise<void> => {
      const params = new URLSearchParams({
        deviceId,
        page: '1',
        limit: '8',
        status: 'ACTIVE',
      });

      const response = await fetch(
        `/api/vulnerabilities?${params.toString()}`,
        {
          method: 'GET',
          cache: 'no-store',
          credentials: 'same-origin',
        },
      );
      const payload =
        (await response.json()) as
          | Pagination<VulnerabilityItem>
          | ApiErrorResponse;

      if (!response.ok) {
        throw new Error(
          errorMessage(
            payload as ApiErrorResponse,
            'Không thể tải danh sách lỗ hổng',
          ),
        );
      }

      const page = payload as Pagination<VulnerabilityItem>;
      setVulnerabilities(page.items ?? []);
      setVulnerabilityTotal(page.total ?? 0);
    },
    [deviceId],
  );

  useEffect(() => {
    const controller =
      new AbortController();

    const initialTimer =
      window.setTimeout(
        () => {
          void loadLatest(
            controller.signal,
          ).catch(() => {
            // Snapshot may not exist before the first sync.
          });
        },
        0,
      );

    const refreshTimer =
      window.setInterval(
        () => {
          void loadLatest().catch(() => {
            // Keep the most recent snapshot during transient failures.
          });
        },
        60_000,
      );

    return () => {
      controller.abort();
      window.clearTimeout(
        initialTimer,
      );
      window.clearInterval(
        refreshTimer,
      );
    };
  }, [loadLatest]);

  useEffect(() => {
    if (!isModalOpen) {
      return undefined;
    }

    function closeOnEscape(
      event: KeyboardEvent,
    ): void {
      if (event.key === 'Escape') {
        setIsModalOpen(false);
      }
    }

    window.addEventListener(
      'keydown',
      closeOnEscape,
    );

    return () => window.removeEventListener(
      'keydown',
      closeOnEscape,
    );
  }, [isModalOpen]);

  async function loadAiRiskSummary() {
    const distribution = {
      LOW: 0,
      MEDIUM: 0,
      HIGH: 0,
      CRITICAL: 0,
    };

    let loaded = 0;
    let total = 0;
    let highestAttackProbability: number | null = null;
    let highestPercentile: number | null = null;

    function normalizeRiskLevel(value: unknown): keyof typeof distribution | null {
      const level = String(value ?? '').trim().toUpperCase();

      if (level === 'LOW' || level === 'THẤP') return 'LOW';
      if (level === 'MEDIUM' || level === 'TRUNG BÌNH' || level === 'TRUNG_BINH') return 'MEDIUM';
      if (level === 'HIGH' || level === 'CAO') return 'HIGH';

      if (
        level === 'CRITICAL' ||
        level === 'VERY_HIGH' ||
        level === 'VERY HIGH' ||
        level === 'RẤT CAO' ||
        level === 'RAT CAO'
      ) {
        return 'CRITICAL';
      }

      return null;
    }

    function toNumber(value: unknown): number | null {
      if (typeof value === 'number' && Number.isFinite(value)) return value;

      if (typeof value === 'string' && value.trim()) {
        const parsed = Number(value);
        return Number.isFinite(parsed) ? parsed : null;
      }

      return null;
    }

    function percentileRiskLevel(value: unknown): keyof typeof distribution | null {
      const numberValue = toNumber(value);

      if (numberValue === null) {
        return null;
      }

      const percent = numberValue <= 1 ? numberValue * 100 : numberValue;

      if (percent >= 85) return 'CRITICAL';
      if (percent >= 65) return 'HIGH';
      if (percent >= 45) return 'MEDIUM';
      return 'LOW';
    }

    function asRecord(value: unknown): Record<string, unknown> {
      return value && typeof value === 'object' && !Array.isArray(value)
        ? (value as Record<string, unknown>)
        : {};
    }

    for (let pageNumber = 1; pageNumber <= 20; pageNumber += 1) {
      const params = new URLSearchParams({
        deviceId,
        status: 'ACTIVE',
        limit: '100',
        page: String(pageNumber),
      });

      const response = await fetch(`/api/vulnerabilities?${params.toString()}`, {
        method: 'GET',
        cache: 'no-store',
        credentials: 'same-origin',
      });

      if (!response.ok) break;

      const payload = await response.json().catch(() => null);
      const payloadRecord = asRecord(payload);
      const items = Array.isArray(payloadRecord.items)
        ? payloadRecord.items.filter(
            (item): item is Record<string, unknown> =>
              item !== null && typeof item === 'object' && !Array.isArray(item),
          )
        : [];

      if (pageNumber === 1) {
        total = toNumber(payloadRecord.total) ?? items.length;
      }

      for (const item of items) {
        const prediction = asRecord(item.aiPrediction);

        if (Object.keys(prediction).length === 0) {
          continue;
        }

        const percentile = toNumber(
          prediction.predictedPercentile ??
          prediction.predicted_percentile ??
          prediction.percentile,
        );
        const level = percentileRiskLevel(percentile) ?? normalizeRiskLevel(prediction.riskLevel);

        if (level) {
          distribution[level] += 1;
        }

        const attackProbability = toNumber(
          prediction.attackProbability ??
          prediction.attack_probability ??
          prediction.probability,
        );
        if (attackProbability !== null) {
          highestAttackProbability =
            highestAttackProbability === null
              ? attackProbability
              : Math.max(highestAttackProbability, attackProbability);
        }

        if (percentile !== null) {
          highestPercentile =
            highestPercentile === null
              ? percentile
              : Math.max(highestPercentile, percentile);
        }
      }

      loaded += items.length;

      if (items.length === 0 || loaded >= total) {
        break;
      }
    }

    const aiTotal = distribution.LOW + distribution.MEDIUM + distribution.HIGH + distribution.CRITICAL;

    setAiRiskSummary({
      total: aiTotal,
      loaded,
      distribution,
      highestAttackProbability,
      highestPercentile,
      calculatedAt: new Date().toISOString(),
    });
  }

  useEffect(() => {
    if (!isModalOpen) {
      return;
    }

    // eslint-disable-next-line react-hooks/set-state-in-effect
    void loadAiRiskSummary().catch(() => {
      // Keep existing distribution if summary refresh fails.
    });
  }, [isModalOpen]);

  const [highestAiSummary, setHighestAiSummary] = useState<DeviceHighestAiSummary | null>(null);

  async function loadDeviceHighestAiSummary(): Promise<void> {
    const fetchLimit = 100;
    const allItems: VulnerabilityItem[] = [];

    let apiTotal = 0;
    let apiTotalPages = 1;

    for (let pageNumber = 1; pageNumber <= apiTotalPages && pageNumber <= 50; pageNumber += 1) {
      const params = new URLSearchParams({
        deviceId,
        page: String(pageNumber),
        limit: String(fetchLimit),
        status: 'ACTIVE',
      });

      const response = await fetch(`/api/vulnerabilities?${params.toString()}`, {
        method: 'GET',
        cache: 'no-store',
        credentials: 'same-origin',
      });

      const payload = (await response.json().catch(() => null)) as
        | (Pagination<VulnerabilityItem> & { message?: string })
        | null;

      if (!response.ok || !payload || typeof payload !== 'object') {
        return;
      }

      const pageItems = Array.isArray(payload.items) ? payload.items : [];
      allItems.push(...pageItems);

      if (pageNumber === 1) {
        apiTotal = typeof payload.total === 'number' ? payload.total : pageItems.length;
        apiTotalPages =
          typeof payload.totalPages === 'number' && payload.totalPages > 0
            ? payload.totalPages
            : Math.max(1, Math.ceil(apiTotal / fetchLimit));
      }

      if (pageItems.length === 0 || allItems.length >= apiTotal) {
        break;
      }
    }

    const sorted = [...allItems].sort(
      (left, right) => cyrpPercentileSortValue(right) - cyrpPercentileSortValue(left),
    );

    const top = sorted[0] ?? null;

    const latestPredictedAt =
      sorted
        .map((item) => item.aiPrediction?.predictedAt ?? null)
        .filter((value): value is string => typeof value === 'string' && value.trim().length > 0)
        .sort((left, right) => new Date(right).getTime() - new Date(left).getTime())[0] ?? null;

    setHighestAiSummary({
      total: sorted.length,
      highestPercentile: cyrpPredictedPercentile(top),
      highestAttackProbability: cyrpAttackProbability(top),
      topCveId: top?.cveId ?? null,
      topPackageName: top?.packageName ?? null,
      topRiskLevel: cyrpRiskLevel(top),
      topPredictedAt: top?.aiPrediction?.predictedAt ?? null,
      latestPredictedAt,
      topItems: sorted.slice(0, 8),
    });
  }

  useEffect(() => {
    if (!isModalOpen) {
      return;
    }

    void loadDeviceHighestAiSummary().catch(() => {
      // Keep the current summary if refresh fails.
    });
  }, [isModalOpen]);

  const sortedVulnerabilities = useMemo(
    () => {
      return [...vulnerabilities].sort(
        (left, right) =>
          (modelExploitRiskValue(right) ?? -1) -
          (modelExploitRiskValue(left) ?? -1),
      );
    },
    [vulnerabilities],
  );

  const highestAttackProbability = useMemo(
    () => {
      const values = vulnerabilities
        .map((item) => modelExploitRiskValue(item))
        .filter(
          (value): value is number =>
            typeof value === 'number' &&
            Number.isFinite(value),
        );

      return values.length
        ? Math.max(...values)
        : null;
    },
    [vulnerabilities],
  );

  const strongestPrediction = useMemo(
    () => {
      return sortedVulnerabilities[0] ?? null;
    },
    [sortedVulnerabilities],
  );

  const cyrpPriorityVulnerabilities = useMemo(
    () => {
      return highestAiSummary?.topItems?.length
        ? highestAiSummary.topItems
        : sortedVulnerabilities;
    },
    [highestAiSummary, sortedVulnerabilities],
  );

  const cyrpTopPrediction = cyrpPriorityVulnerabilities[0] ?? null;

  const aiDistribution = useMemo<RiskBucketRow[]>(
    () => {
      const counts = aiRiskSummary?.distribution ?? {
        LOW: 0,
        MEDIUM: 0,
        HIGH: 0,
        CRITICAL: 0,
      };

      return [
        { key: 'LOW', label: 'Thấp', count: counts.LOW },
        { key: 'MEDIUM', label: 'Trung bình', count: counts.MEDIUM },
        { key: 'HIGH', label: 'Cao', count: counts.HIGH },
        { key: 'CRITICAL', label: 'Rất cao', count: counts.CRITICAL },
      ];
    },
    [aiRiskSummary],
  );

  const maxDistributionCount = useMemo(
    () => Math.max(1, ...aiDistribution.map((item) => item.count)),
    [aiDistribution],
  );

  const quickActions = (() => {
    const actions: string[] = [];

    if (cyrpTopPrediction) {
      actions.push(
        `Ưu tiên xử lý ${cyrpTopPrediction.cveId} vì đang có percentile AI ${formatPercentileDisplay(cyrpPredictedPercentile(cyrpTopPrediction))} và xác suất khai thác ${formatProbability(cyrpAttackProbability(cyrpTopPrediction))}.`,
      );
    }

    if ((snapshot?.criticalCount ?? 0) > 0) {
      actions.push(
        `Wazuh ghi nhận ${snapshot?.criticalCount ?? 0} cảnh báo critical trong 24 giờ gần nhất, nên kiểm tra nhật ký và rule liên quan.`,
      );
    }

    if (vulnerabilityTotal > cyrpPriorityVulnerabilities.length) {
      actions.push(
        `Hiện chỉ đang hiển thị ${cyrpPriorityVulnerabilities.length}/${vulnerabilityTotal} lỗ hổng ưu tiên cao nhất, nhấn vào chi tiết để xem thêm khi cần.`,
      );
    } else if (vulnerabilityTotal > 0) {
      actions.push(
        `Thiết bị hiện có ${vulnerabilityTotal} lỗ hổng active cần được theo dõi và vá theo mức ưu tiên.`,
      );
    }

    if (!actions.length) {
      actions.push('Chưa có hành động khẩn cấp nổi bật. Có thể tiếp tục theo dõi ở lần kiểm tra tiếp theo.');
    }

    return actions;
  })();

  function closeModal(
    event?: MouseEvent<HTMLDivElement | HTMLButtonElement>,
  ): void {
    event?.preventDefault();
    setIsModalOpen(false);
  }

  function keepModalOpen(
    event: MouseEvent<HTMLElement>,
  ): void {
    event.stopPropagation();
  }

  async function syncNow(): Promise<void> {
    if (isRunning) {
      return;
    }

    setIsRunning(true);
    setError('');
    setProgressMessage('Đang gửi yêu cầu kiểm tra máy tới CYRP.');
    setExpandedId(null);
    setIsModalOpen(true);

    try {
      const startResponse = await fetch(
        `/api/devices/${deviceId}/ai-pipeline-check`,
        {
          method: 'POST',
          cache: 'no-store',
          credentials: 'same-origin',
        },
      );
      const startPayload = (await startResponse
        .json()
        .catch(() => null)) as
        | MachineCheckStartResponse
        | ApiErrorResponse
        | null;

      if (!startResponse.ok || !startPayload || !('runId' in startPayload)) {
        throw new Error(
          startPayload
            ? errorMessage(startPayload as ApiErrorResponse, 'Không thể khởi tạo kiểm tra máy')
            : 'Không thể khởi tạo kiểm tra máy',
        );
      }

      const runId = startPayload.runId;
      const pollAfterMs = Math.min(
        Math.max(Number(startPayload.pollAfterMs ?? 2000), 500),
        10000,
      );
      const deadline = Date.now() + 20 * 60 * 1000;
      let completed = false;
      setProgressMessage(
        startPayload.message ?? 'CYRP đang kiểm tra máy ở chế độ nền.',
      );

      while (Date.now() < deadline) {
        await wait(pollAfterMs);

        const statusResponse = await fetch(
          `/api/devices/${deviceId}/ai-pipeline-check/${runId}`,
          {
            method: 'GET',
            cache: 'no-store',
            credentials: 'same-origin',
          },
        );
        const statusPayload = (await statusResponse
          .json()
          .catch(() => null)) as
          | MachineCheckStatusResponse
          | ApiErrorResponse
          | null;

        if (!statusResponse.ok || !statusPayload || !('status' in statusPayload)) {
          throw new Error(
            statusPayload
              ? errorMessage(statusPayload as ApiErrorResponse, 'Không thể đọc tiến độ kiểm tra máy')
              : 'Không thể đọc tiến độ kiểm tra máy',
          );
        }

        setProgressMessage(
          statusPayload.message ?? 'CYRP đang xử lý dữ liệu bảo mật.',
        );

        if (statusPayload.status === 'FAILED') {
          throw new Error(
            statusPayload.error ??
              statusPayload.message ??
              'Lần kiểm tra máy đã thất bại.',
          );
        }

        if (
          statusPayload.status === 'COMPLETED' ||
          statusPayload.status === 'PARTIAL'
        ) {
          completed = true;
          break;
        }
      }

      if (!completed) {
        throw new Error(
          'Lần kiểm tra máy chưa hoàn tất sau 20 phút. Tiến trình nền vẫn có thể tiếp tục; hãy thử mở lại kết quả sau.',
        );
      }

      setProgressMessage('Đang tải kết quả mới nhất.');
      await Promise.all([
        loadLatest(),
        loadVulnerabilities(),
        loadAiRiskSummary(),
        loadDeviceHighestAiSummary(),
      ]);
    } catch (caught: unknown) {
      setError(
        caught instanceof Error
          ? caught.message
          : 'Không thể kiểm tra máy',
      );
    } finally {
      setIsRunning(false);
    }
  }
  const cyrpDisplayAgentId =
    snapshot?.wazuhAgentId ??
    propWazuhAgentId ??
    null;

  const cyrpTopRecord = cyrpTopPrediction as
    | (VulnerabilityItem & {
        device?: { hostname?: string | null } | null;
        deviceName?: string | null;
        hostname?: string | null;
      })
    | null;

  const cyrpTopDeviceName =
    cyrpTopRecord?.device?.hostname ??
    cyrpTopRecord?.deviceName ??
    cyrpTopRecord?.hostname ??
    null;

  const cyrpDisplayAgentName =
    snapshot?.agentName ??
    propWazuhAgentName ??
    cyrpTopDeviceName ??
    (cyrpDisplayAgentId ? `Agent ${cyrpDisplayAgentId}` : 'Thiết bị đã liên kết');

  const cyrpDisplayAgentMeta =
    cyrpDisplayAgentId
      ? `${cyrpDisplayAgentName} · ID ${cyrpDisplayAgentId}`
      : cyrpDisplayAgentName;

  const cyrpDisplayHighestPercentile =
    highestAiSummary?.highestPercentile ??
    cyrpPredictedPercentile(cyrpTopPrediction) ??
    cyrpPredictedPercentile(strongestPrediction) ??
    null;

  const cyrpDisplayHighestAttackProbability =
    highestAiSummary?.highestAttackProbability ??
    cyrpAttackProbability(cyrpTopPrediction) ??
    cyrpAttackProbability(strongestPrediction) ??
    null;

  return (
    <div className={styles.inlineWorkspace}>
      <div className={styles.controlRail}>
        <div className={styles.scanCard}>
          <button
            type="button"
            className={`${styles.button} ${variant === 'repairOrb' ? styles.repairOrbButton : ''}`}
            disabled={isRunning}
            onClick={() => void syncNow()}
          >
            {variant === 'repairOrb' ? (
              <span className={styles.repairOrbContent}>
                <span className={styles.repairOrbIcon} aria-hidden="true">
                  <img src="/cyrp-assets/gear.svg" alt="" />
                </span>
                <span>{isRunning ? 'Đang kiểm tra...' : 'Kiểm tra máy'}</span>
              </span>
            ) : (
              isRunning
                ? 'Đang kiểm tra máy...'
                : 'Kiểm tra tình trạng máy'
            )}
          </button>

          {snapshot ? (
            <small className={styles.empty}>
              Lần kiểm tra gần nhất: {formatDate(highestAiSummary?.latestPredictedAt ?? highestAiSummary?.topPredictedAt ?? snapshot?.calculatedAt ?? null)}
            </small>
          ) : (
            <small className={styles.empty}>
              Chưa có snapshot. Nhấn kiểm tra máy để lấy dữ liệu Wazuh.
            </small>
          )}
        </div>

        <div className={styles.recallCard}>
          <div className={styles.recallMeta}>
            <span>Kết quả gần nhất</span>
            <strong>
              {snapshot ? formatDate(snapshot.calculatedAt) : 'Chưa có dữ liệu'}
            </strong>
            <p>
              {snapshot
                ? 'Bạn có thể mở lại kết quả cũ mà không cần quét lại.'
                : 'Sau lần kiểm tra đầu tiên, nút xem lại sẽ dùng được.'}
            </p>
          </div>

          <button
            type="button"
            className={styles.recallButton}
            onClick={() => void openCachedResult()}
            disabled={!hasCachedResult || isRunning}
          >
            Xem lại kết quả cũ
          </button>
        </div>
      </div>

      <div className={styles.resultStage}>
        {!isModalOpen ? (
          <>
            {hasCachedResult ? (
              <button
                type="button"
                className={styles.reopenSideHandle}
                onClick={() => void openCachedResult()}
                aria-label="Mở lại kết quả cũ"
                title="Xem lại kết quả cũ"
              >
                <span>&lt;</span>
              </button>
            ) : null}

            <div className={styles.stagePlaceholder}>
              <span className={styles.stageEyebrow}>CYRP machine check</span>
              <h3>Chưa mở bảng kết quả</h3>
              <p>
                Nhấn <strong>Kiểm tra máy</strong> để lấy dữ liệu mới, hoặc mở lại
                kết quả cũ nếu bạn đã từng kiểm tra trước đó.
              </p>
            </div>
          </>
        ) : (
          <section
            className={`${styles.modalPanel} ${styles.inlinePanel}`}
            role="region"
            aria-labelledby={`machine-check-title-${deviceId}`}
          >
            <div className={styles.modalHeader}>
              <div>
                <p>CYRP machine check</p>
                <h2 id={`machine-check-title-${deviceId}`}>
                  Kết quả kiểm tra máy
                </h2>
                <span className={styles.headerHint}>
                  Tóm tắt nhanh trước, chi tiết kỹ thuật chỉ mở khi cần.
                </span>
              </div>

              <button
                type="button"
                className={styles.closeButton}
                aria-label="Đóng kết quả kiểm tra máy"
                onClick={closeModal}
              >
                ×
              </button>
            </div>

            {isRunning ? (
              <div className={styles.progressPanel}>
                <div className={styles.spinner} />
                <div>
                  <strong>Đang phân tích bằng AI</strong>
                  <span>{progressMessage}</span>
                </div>
              </div>
            ) : null}

            {error ? (
              <p className={styles.error} role="alert">
                {error}
              </p>
            ) : null}

            {snapshot ? (
              <>
                <section className={styles.heroSection}>
                  <div className={styles.heroText}>
                    <span className={styles.sectionEyebrow}>Tổng quan nhanh</span>
                    <h3>{summaryMessage(percentileAsProbabilityScale(cyrpDisplayHighestPercentile), vulnerabilityTotal, snapshot.alertCount)}</h3>

                    <div className={styles.heroPills}>
                      <span className={`${styles.riskPill} ${riskClass(cyrpTopPrediction ? (finalPriorityLevel(cyrpTopPrediction) ?? cyrpTopPrediction.aiPrediction?.riskLevel) : null)}`}>
                        {strongestPrediction
                          ? finalPriorityLevel(strongestPrediction) ?? strongestPrediction.aiPrediction?.riskLevel ?? '—'
                          : 'Chưa có dữ liệu'}
                      </span>
                      <span className={styles.heroSubtlePill}>
                        {modelLabel(cyrpTopPrediction?.aiPrediction?.modelVersion)}
                      </span>
                    </div>
                  </div>

                  <div className={styles.gaugeCard}>
                    <div className={`${styles.gauge} ${cyrpPercentileGaugeClass(cyrpDisplayHighestPercentile)}`}>
                      <div className={styles.gaugeInner}>
                        <span>Percentile cao nhất</span>
                        <strong>{formatPercentileDisplay(cyrpDisplayHighestPercentile)}</strong>
                        <small>{riskBandLabel(percentileAsRiskScale(cyrpDisplayHighestPercentile))}</small>
                      </div>
                    </div>
                    <p>
                      Đây là percentile AI cao nhất trong các lỗ hổng active chưa khắc phục của thiết bị ở lần kiểm tra hiện tại.
                    </p>
                  </div>
                </section>

                <div className={styles.summaryGrid}>
                  <article className={styles.summaryCard}>
                    <span>Tên thiết bị agent</span>
                    <strong>
                      {cyrpDisplayAgentName}
                    </strong>
                    <small>
                      {snapshot.agentStatus ?? 'unknown'} · IP {snapshot.agentIp ?? 'unknown'}
                    </small>
                  </article>

                  <article className={styles.summaryCard}>
                    <span>Cảnh báo 24h</span>
                    <strong>{snapshot.alertCount}</strong>
                    <small>
                      Max rule level {snapshot.maxRuleLevel ?? 0} · {snapshot.criticalCount} critical
                    </small>
                  </article>

                  <article className={styles.summaryCard}>
                    <span>Lỗ hổng active</span>
                    <strong>{vulnerabilityTotal}</strong>
                    <small>
                      {aiRiskSummary?.total ?? sortedVulnerabilities.length} lỗ hổng có AI prediction đang được tổng hợp
                    </small>
                  </article>

                  <article className={styles.summaryCard}>
                    <span>Percentile</span>
                    <strong>{formatPercentileDisplay(cyrpDisplayHighestPercentile)}</strong>
                    <small>
                      Percentile AI cao nhất · cập nhật {formatDate(highestAiSummary?.topPredictedAt ?? highestAiSummary?.latestPredictedAt ?? cyrpTopPrediction?.aiPrediction?.predictedAt ?? snapshot.calculatedAt)}
                    </small>
                  </article>
                </div>

                <div className={styles.insightGrid}>
                  <section className={styles.panelCard}>
                    <div className={styles.sectionHeader}>
                      <strong>Phân bố mức rủi ro AI</strong>
                      <span>Đây là phân bố theo toàn bộ AI prediction active, không phải theo CVSS.</span>
                    </div>

                    <div className={styles.chartRows}>
                      {aiDistribution.map((bucket) => {
                        const width = maxDistributionCount
                          ? (bucket.count / maxDistributionCount) * 100
                          : 0;

                        return (
                          <div className={styles.chartRow} key={bucket.key}>
                            <div className={styles.chartLabelWrap}>
                              <span>{bucket.label}</span>
                              <strong>{bucket.count}</strong>
                            </div>
                            <div className={styles.chartTrack}>
                              <div
                                className={`${styles.chartFill} ${riskClass(bucket.key)}`}
                                style={{ width: formatPercentBar(width) }}
                              />
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </section>

                  <section className={styles.panelCard}>
                    <div className={styles.sectionHeader}>
                      <strong>Điều cần làm ngay</strong>
                      <span>Tóm tắt hành động ưu tiên cho người dùng.</span>
                    </div>

                    <ul className={styles.actionList}>
                      {quickActions.map((action) => (
                        <li key={action}>{action}</li>
                      ))}
                    </ul>
                  </section>
                </div>

                <div className={styles.modalSection}>
                  <div className={styles.sectionHeader}>
                    <strong>Lỗ hổng ưu tiên</strong>
                    <span>
                      Chỉ hiển thị ngắn gọn các mục cần quan tâm nhất. Phân bố AI phía trên được tính từ danh sách active đã tải.
                    </span>
                  </div>

                  {cyrpPriorityVulnerabilities.length ? (
                    <div className={styles.vulnerabilityList}>
                      {cyrpPriorityVulnerabilities.slice(0, 5).map((item) => {
                        const isExpanded = expandedId === item.id;
                        const finalLevel =
                          finalPriorityLevel(item) ??
                          item.aiPrediction?.riskLevel ??
                          '—';
                        const finalScore = finalPriorityScore(item);

                        return (
                          <article className={styles.vulnerabilityCard} key={item.id}>
                            <div className={styles.vulnerabilityTop}>
                              <div className={styles.vulnerabilityMain}>
                                <strong>{item.cveId}</strong>
                                <span>{item.packageName ?? 'Không rõ package'}</span>
                                <small>
                                  CVSS {formatShortScore(item.cvssBaseScore)} · {item.severity ?? 'UNKNOWN'}
                                </small>
                              </div>

                              <div className={styles.vulnerabilityStats}>
                                <div className={styles.statChip}>
                                  <span>Percentile</span>
                                  <strong>{formatPercentileDisplay(cyrpPredictedPercentile(item))}</strong>
                                </div>
                                <div className={styles.statChip}>
                                  <span>Attack probability</span>
                                  <strong>{formatProbability(modelAttackProbabilityValue(item))}</strong>
                                </div>
                                <div className={styles.statChip}>
                                  <span>Mức ưu tiên</span>
                                  <strong>{finalLevel}</strong>
                                </div>
                              </div>
                            </div>

                            <div className={styles.vulnerabilityMetaRow}>
                              <span className={`${styles.riskPill} ${riskClass(item.aiPrediction?.riskLevel)}`}>
                                AI risk {item.aiPrediction?.riskLevel ?? '—'}
                              </span>
                              <span className={`${styles.riskPill} ${riskClass(finalLevel)}`}>
                                Final priority {finalLevel}
                              </span>
                              <span className={styles.metaBadge}>
                                  {item.status?.toUpperCase() === 'RESOLVED'
                                    ? 'Đã khắc phục'
                                    : 'Chưa khắc phục'}
                                </span>
                            </div>

                            <div className={styles.vulnerabilityActions}>
                              <button
                                type="button"
                                className={styles.detailButton}
                                onClick={() => setExpandedId(isExpanded ? null : item.id)}
                              >
                                {isExpanded ? 'Ẩn chi tiết' : 'Xem chi tiết'}
                              </button>
                              <CveRemediationLink cveId={item.cveId} />
                            </div>

                            {isExpanded ? (
                              <div className={styles.detailPanel}>
                                <div className={styles.detailGrid}>
                                  <div>
                                    <span>CVE</span>
                                    <strong>{item.cveId}</strong>
                                  </div>
                                  <div>
                                    <span>Package</span>
                                    <strong>{item.packageName ?? 'Không rõ'}</strong>
                                  </div>
                                  <div>
                                    <span>CVSS base score</span>
                                    <strong>{formatShortScore(item.cvssBaseScore)}</strong>
                                  </div>
                                  <div>
                                    <span>Severity</span>
                                    <strong>{item.severity ?? 'UNKNOWN'}</strong>
                                  </div>
                                  <div>
                                    <span>AI model</span>
                                    <strong>{modelLabel(item.aiPrediction?.modelVersion)}</strong>
                                  </div>
                                  <div>
                                    <span>Model version</span>
                                    <strong>{item.aiPrediction?.modelVersion ?? '—'}</strong>
                                  </div>
                                  <div>
                                    <span>Final priority score</span>
                                    <strong>{formatScore(finalScore)}</strong>
                                  </div>                                    <div>
                                      <span>Trạng thái khắc phục</span>
                                      <strong>{item.status?.toUpperCase() === 'RESOLVED' ? 'Đã khắc phục' : 'Chưa khắc phục'}</strong>
                                    </div>
                                </div>
                              </div>
                            ) : null}
                          </article>
                        );
                      })}
                    </div>
                  ) : (
                    <p className={styles.emptyState}>
                      Chưa có lỗ hổng active hoặc AI prediction cho thiết bị này.
                    </p>
                  )}
                </div>

                <details className={styles.technicalDetails}>
                  <summary>Chi tiết kỹ thuật và nguồn dữ liệu</summary>
                  <div className={styles.technicalBody}>
                    <div className={styles.metaLine}>
                      <span>Đồng bộ: {formatDate(snapshot.calculatedAt)}</span>
                      <span>Agent: {cyrpDisplayAgentMeta}</span>
                      <span>Window: {snapshot.windowMinutes} phút</span>
                    </div>

                    {(Array.isArray(snapshot?.topRules) ? snapshot?.topRules : []).length ? (
                      <div className={styles.ruleList}>
                        {(Array.isArray(snapshot?.topRules) ? snapshot?.topRules : []).slice(0, 5).map((rule) => (
                          <span key={rule.ruleId}>
                            #{rule.ruleId} · L{rule.maxLevel} · {rule.count} lần — {rule.description}
                          </span>
                        ))}
                      </div>
                    ) : (
                      <p className={styles.disclaimer}>
                        Chưa có top Wazuh rules nổi bật trong cửa sổ thời gian hiện tại.
                      </p>
                    )}

                    <p className={styles.disclaimer}>
                      CYRP hiện hiển thị lớp tóm tắt cho người dùng. Nhật ký và dữ liệu phân tích sâu được ẩn sau phần chi tiết để tránh gây quá tải thông tin.
                    </p>
                  </div>
                </details>
              </>
            ) : !isRunning ? (
              <p className={styles.emptyState}>
                Chưa có snapshot. Nhấn kiểm tra lại để CYRP lấy dữ liệu từ Wazuh.
              </p>
            ) : null}
          </section>
        )}
      </div>
    </div>
  );
}
