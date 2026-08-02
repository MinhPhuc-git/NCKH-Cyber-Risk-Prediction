'use client';

import Link from 'next/link';
import { FormEvent, useCallback, useEffect, useState } from 'react';

import { CveRemediationLink } from '@/components/cve-remediation-link';
import styles from '@/components/security-console.module.css';
import type { Pagination, VulnerabilityItem } from '@/lib/security-data-types';

type PredictionExplanation = Record<string, unknown>;

type AiPredictionRow = VulnerabilityItem & {
  device?: {
    id?: string | null;
    hostname?: string | null;
    operatingSystem?: string | null;
  } | null;
  deviceName?: string | null;
  hostname?: string | null;
  operatingSystem?: string | null;
};

function numberFromUnknown(value: unknown): number | null {
  if (typeof value === 'number' && Number.isFinite(value)) return value;

  if (typeof value === 'string' && value.trim()) {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : null;
  }

  return null;
}

function stringFromUnknown(value: unknown): string | null {
  return typeof value === 'string' && value.trim() ? value : null;
}

function predictionExplanation(value: unknown): PredictionExplanation {
  return value && typeof value === 'object'
    ? (value as PredictionExplanation)
    : {};
}

function predictionRecord(item: VulnerabilityItem): Record<string, unknown> {
  return item.aiPrediction && typeof item.aiPrediction === 'object'
    ? (item.aiPrediction as unknown as Record<string, unknown>)
    : {};
}

function predictionPercentile(item: VulnerabilityItem): number | null {
  const prediction = predictionRecord(item);
  const explanation = predictionExplanation(item.aiPrediction?.explanation);

  return numberFromUnknown(prediction.predictedPercentile)
    ?? numberFromUnknown(prediction.predicted_percentile)
    ?? numberFromUnknown(prediction.percentile)
    ?? numberFromUnknown(explanation.predicted_percentile)
    ?? numberFromUnknown(explanation.predictedPercentile)
    ?? null;
}

function attackProbability(item: VulnerabilityItem): number | null {
  const prediction = predictionRecord(item);
  const explanation = predictionExplanation(item.aiPrediction?.explanation);

  return numberFromUnknown(prediction.attackProbability)
    ?? numberFromUnknown(prediction.attack_probability)
    ?? numberFromUnknown(explanation.attackProbability)
    ?? numberFromUnknown(explanation.attack_probability)
    ?? numberFromUnknown(explanation.probability)
    ?? null;
}

function riskLevelFromPercentile(value: number | null): string | null {
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    return null;
  }

  const percent = value <= 1 ? value * 100 : value;

  if (percent >= 85) return 'CRITICAL';
  if (percent >= 65) return 'HIGH';
  if (percent >= 45) return 'MEDIUM';
  return 'LOW';
}

function riskLevel(item: VulnerabilityItem): string {
  return (
    riskLevelFromPercentile(predictionPercentile(item))
    ?? item.aiPrediction?.riskLevel
    ?? stringFromUnknown(predictionExplanation(item.aiPrediction?.explanation).risk_level)
    ?? stringFromUnknown(predictionExplanation(item.aiPrediction?.explanation).riskLevel)
    ?? 'UNKNOWN'
  ).toUpperCase();
}

function riskRank(level: string | null | undefined): number {
  switch (level?.toUpperCase()) {
    case 'CRITICAL':
      return 4;
    case 'HIGH':
      return 3;
    case 'MEDIUM':
      return 2;
    case 'LOW':
      return 1;
    default:
      return 0;
  }
}

function aiScoreForSort(item: VulnerabilityItem): number {
  const percentile = predictionPercentile(item);

  if (typeof percentile === 'number' && Number.isFinite(percentile)) {
    return percentile <= 1 ? percentile * 100 : percentile;
  }

  const probability = attackProbability(item);

  if (typeof probability === 'number' && Number.isFinite(probability)) {
    return probability <= 1 ? probability * 100 : probability;
  }

  return -1;
}

function sortAndFilterByAiRiskLevel(
  items: VulnerabilityItem[],
  selectedRiskLevel: string,
): VulnerabilityItem[] {
  const normalizedFilter = selectedRiskLevel.trim().toUpperCase();

  return [...items]
    .filter((item) => {
      const level = riskLevel(item);
      return !normalizedFilter || level === normalizedFilter;
    })
    .sort((left, right) => {
      const scoreDelta = aiScoreForSort(right) - aiScoreForSort(left);

      if (scoreDelta !== 0) {
        return scoreDelta;
      }

      return riskRank(riskLevel(right)) - riskRank(riskLevel(left));
    });
}

function formatDate(value: string | null | undefined): string {
  if (!value) return '—';

  const date = new Date(value);

  return Number.isNaN(date.getTime())
    ? '—'
    : new Intl.DateTimeFormat('vi-VN', {
        dateStyle: 'short',
        timeStyle: 'short',
      }).format(date);
}

function formatProbability(value: number | null | undefined): string {
  if (typeof value !== 'number' || Number.isNaN(value)) return '—';

  const percent = value <= 1 ? value * 100 : value;
  return `${Math.round(percent)}%`;
}

function formatPercentile(value: number | null): string {
  if (typeof value !== 'number' || Number.isNaN(value)) return '—';

  const percent = value <= 1 ? value * 100 : value;
  return `${Math.round(percent)}%`;
}

function severityClass(severity: string | null | undefined): string {
  switch (severity?.toUpperCase()) {
    case 'CRITICAL':
      return styles.severityCritical;
    case 'HIGH':
      return styles.severityHigh;
    case 'MEDIUM':
      return styles.severityMedium;
    case 'LOW':
      return styles.severityLow;
    default:
      return styles.severityUnknown;
  }
}


function percentileBandValue(value: number | null): number | null {
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    return null;
  }

  return value <= 1 ? value * 100 : value;
}

function percentileBandClass(value: number | null): string {
  const percent = percentileBandValue(value);

  if (percent === null) {
    return styles.severityUnknown;
  }

  if (percent >= 85) {
    return styles.percentileCritical;
  }

  if (percent >= 65) {
    return styles.percentileHigh;
  }

  if (percent >= 45) {
    return styles.percentileMedium;
  }

  return styles.percentileLow;
}

function percentileBandStyle(value: number | null) {
  const percent = percentileBandValue(value);

  if (percent === null) {
    return {};
  }

  if (percent >= 85) {
    return {
      color: '#f87171',
      backgroundColor: 'rgba(239, 68, 68, 0.16)',
      borderColor: 'rgba(239, 68, 68, 0.42)',
    };
  }

  if (percent >= 65) {
    return {
      color: '#fb923c',
      backgroundColor: 'rgba(251, 146, 60, 0.16)',
      borderColor: 'rgba(251, 146, 60, 0.38)',
    };
  }

  if (percent >= 45) {
    return {
      color: '#facc15',
      backgroundColor: 'rgba(250, 204, 21, 0.14)',
      borderColor: 'rgba(250, 204, 21, 0.34)',
    };
  }

  return {
    color: '#34d399',
    backgroundColor: 'rgba(52, 211, 153, 0.14)',
    borderColor: 'rgba(52, 211, 153, 0.34)',
  };
}

function statusClass(status: string | null | undefined): string {
  const normalized = status?.toUpperCase();

  if (normalized === 'CRITICAL' || normalized === 'HIGH') return styles.statusDanger;
  if (normalized === 'MEDIUM') return styles.statusWarning;
  if (normalized === 'LOW') return styles.statusSuccess;

  return styles.statusNeutral;
}

function pickFirstDateString(...values: Array<string | null | undefined>): string | null {
  for (const value of values) {
    if (typeof value === 'string' && value.trim()) {
      return value;
    }
  }

  return null;
}

function getAiScanTime(item: VulnerabilityItem): string | null {
  return pickFirstDateString(
    item.aiPrediction?.predictedAt,
    item.predictionHistory?.[0]?.predictedAt,
  );
}

function deviceHostname(item: AiPredictionRow): string {
  return (
    item.device?.hostname ??
    item.deviceName ??
    item.hostname ??
    'Không rõ thiết bị'
  );
}

function packageLabel(row: AiPredictionRow): string {
  const direct = row.packageName;

  if (typeof direct === 'string' && direct.trim()) {
    return direct;
  }

  return 'Không rõ package';
}

export function AiPredictionsClient() {
  const [data, setData] = useState<Pagination<VulnerabilityItem> | null>(null);
  const [queryInput, setQueryInput] = useState('');
  const [query, setQuery] = useState('');
  const [riskLevelFilter, setRiskLevelFilter] = useState('');
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const load = useCallback(async () => {
    setLoading(true);

    try {
      const pageSize = 25;
      const fetchLimit = 100;
      const allItems: VulnerabilityItem[] = [];

      let apiTotal = 0;
      let apiTotalPages = 1;

      for (let pageNumber = 1; pageNumber <= apiTotalPages && pageNumber <= 50; pageNumber += 1) {
        const params = new URLSearchParams({
          page: String(pageNumber),
          limit: String(fetchLimit),
          status: 'ACTIVE',
        });

        if (query) {
          params.set('query', query);
        }

        const response = await fetch(`/api/vulnerabilities?${params.toString()}`, {
          cache: 'no-store',
        });

        const payload = (await response.json()) as Pagination<VulnerabilityItem> & {
          message?: string;
        };

        if (!response.ok) {
          throw new Error(payload.message ?? 'Không thể tải kết quả AI');
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

      const sortedItems = sortAndFilterByAiRiskLevel(allItems, riskLevelFilter);
      const totalItems = sortedItems.length;
      const totalPages = Math.max(1, Math.ceil(totalItems / pageSize));
      const safePage = Math.min(page, totalPages);
      const startIndex = (safePage - 1) * pageSize;
      const visibleItems = sortedItems.slice(startIndex, startIndex + pageSize);

      if (safePage !== page) {
        setPage(safePage);
      }

      setData({
        page: safePage,
        limit: pageSize,
        total: totalItems,
        totalPages,
        items: visibleItems,
      });

      setError('');
    } catch (caught: unknown) {
      setError(caught instanceof Error ? caught.message : 'Không thể tải kết quả AI');
    } finally {
      setLoading(false);
    }
  }, [page, query, riskLevelFilter]);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      void load();
    }, 0);

    return () => window.clearTimeout(timer);
  }, [load]);

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setPage(1);
    setQuery(queryInput.trim());
  }

  return (
    <div className={`${styles.page} cyrp-table-main-only`}>
      <header
        className={styles.pageHeader}
        style={{
          display: 'grid',
          gridTemplateColumns: 'minmax(0, 1fr) auto',
          alignItems: 'start',
          columnGap: '24px',
          width: '100%',
        }}
      >
        <div style={{ minWidth: 0 }}>
          <p className={styles.eyebrow}>AI_CYRP prediction results</p>
          <h1>Kết quả AI dự đoán</h1>
          <p>
            Trang này hiển thị kết quả dự đoán của model AI_CYRP cho các CVE đang được Wazuh ghi nhận.
          </p>
        </div>

        <div
          style={{
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'flex-end',
            justifyContent: 'flex-start',
            gap: '10px',
            minWidth: '120px',
          }}
        >
          <button
            className={styles.secondaryButton}
            type="button"
            onClick={() => {
              setPage(1);
              void load();
            }}
            disabled={loading}
          >
            {loading ? 'Đang tải...' : 'Làm mới'}
          </button>

          <span className={`${styles.statusPill} ${styles.statusNeutral}`}>
            {data?.total ?? 0} bản ghi
          </span>
        </div>
      </header>
      <form className={styles.filterRow} onSubmit={submit}>
        <input
          className={styles.input}
          value={queryInput}
          onChange={(event) => setQueryInput(event.target.value)}
          placeholder="Tìm CVE, package hoặc hostname"
          aria-label="Tìm kết quả AI"
        />

        <select
          className={styles.select}
          value={riskLevelFilter}
          onChange={(event) => {
            setRiskLevelFilter(event.target.value);
            setPage(1);
          }}
          aria-label="Lọc theo risk level AI"
        >
          <option value="">Mọi risk level</option>
          <option value="CRITICAL">Critical</option>
          <option value="HIGH">High</option>
          <option value="MEDIUM">Medium</option>
          <option value="LOW">Low</option>
        </select>

        <button className={styles.primaryButton} type="submit">
          Tìm kiếm
        </button>
      </form>

      {error ? (
        <div className={styles.errorMessage} role="alert">
          {error}
        </div>
      ) : null}

      <section className={styles.panel}>
        <div className={styles.panelHeader}>
          <div>
            <h2>Kết quả chấm điểm AI_CYRP</h2>
            <p>Bảng này chỉ hiển thị các trường chính của kết quả dự đoán AI.</p>
          </div>
        </div>

        {loading && !data ? (
          <div className={styles.loadingSkeleton} />
        ) : (
          <div className={styles.tableWrap}>
            <table className={styles.table}>
              <thead>
                <tr>
                  <th>CVE</th>
                  <th>Thiết bị</th>
                  <th>Package</th>
                  <th>AI ScanTime</th>
                  <th>Risk level</th>
                  <th>Xác suất bị khai thác</th>
                  <th>Percentile</th>
                  <th>Cách khắc phục</th>
                </tr>
              </thead>

              <tbody>
                {(data?.items ?? []).map((item) => {
                  const row = item as AiPredictionRow;
                  const level = riskLevel(row);
                  const probability = attackProbability(row);
                  const percentile = predictionPercentile(row);

                  return (
                    <tr key={row.id}>
                      <td>
                        <Link href={`/ai-predictions/${row.id}`} className={styles.linkText}>
                          {row.cveId}
                        </Link>
                      </td>

                      <td>
                        <strong>{deviceHostname(row)}</strong>
                      </td>

                      <td>
                        <strong>{packageLabel(row)}</strong>
                      </td>

                      <td>
                        <strong>{formatDate(getAiScanTime(row))}</strong>
                      </td>

                      <td>
                        <span className={`${styles.statusPill} ${statusClass(level)}`}>
                          {level}
                        </span>
                      </td>

                      <td>
                        <strong>{formatProbability(probability)}</strong>
                      </td>

                      <td>
                        <span className={`${styles.statusPill} ${percentileBandClass(percentile)}`}
                          style={percentileBandStyle(percentile)}>
                          {formatPercentile(percentile)}
                        </span>
                      </td>

                      <td>
                        <CveRemediationLink cveId={row.cveId} />
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>

            {data && data.items.length === 0 ? (
              <p className={styles.emptyState}>
                Không có kết quả AI phù hợp với bộ lọc hiện tại.
              </p>
            ) : null}
          </div>
        )}
      </section>

      {data ? (
        <div className={styles.pagination}>
          <button
            className={styles.secondaryButton}
            type="button"
            disabled={page <= 1 || loading}
            onClick={() => setPage((value) => Math.max(1, value - 1))}
          >
            Trang trước
          </button>

          <span>
            Trang {page} / {Math.max(1, data.totalPages ?? 1)}
          </span>

          <button
            className={styles.secondaryButton}
            type="button"
            disabled={page >= (data.totalPages ?? 1) || loading}
            onClick={() => setPage((value) => value + 1)}
          >
            Trang sau
          </button>
        </div>
      ) : null}
    </div>
  );
}
