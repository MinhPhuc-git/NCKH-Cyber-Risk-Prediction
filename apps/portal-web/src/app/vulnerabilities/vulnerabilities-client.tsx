'use client';

import Link from 'next/link';
import { FormEvent, useCallback, useEffect, useState } from 'react';

import styles from '@/components/security-console.module.css';
import { formatDateTime } from '@/lib/security-format';
import type { Pagination, VulnerabilityItem } from '@/lib/security-data-types';
import type { ListUsersResponse, UserListItem } from '@/lib/api-types';

type PredictionExplanation = Record<string, unknown>;

function formatProbability(value: number | null | undefined): string {
  if (typeof value !== 'number' || Number.isNaN(value)) return '—';
  return `${Math.round(value * 100)}%`;
}

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

function finalPriorityLevel(item: VulnerabilityItem): string | null {
  const explanation = predictionExplanation(item.aiPrediction?.explanation);
  return stringFromUnknown(explanation.final_priority_level)
    ?? stringFromUnknown(explanation.finalPriorityLevel);
}

function finalPriorityScore(item: VulnerabilityItem): number | null {
  const explanation = predictionExplanation(item.aiPrediction?.explanation);
  return numberFromUnknown(explanation.final_priority_score)
    ?? numberFromUnknown(explanation.finalPriorityScore);
}

function officialEpssScore(item: VulnerabilityItem): number | null {
  const explanation = predictionExplanation(item.aiPrediction?.explanation);
  return numberFromUnknown(explanation.official_epss_score)
    ?? numberFromUnknown(explanation.officialEpssScore)
    ?? item.latestThreatSignal?.epssScore
    ?? null;
}

function officialEpssPercentile(item: VulnerabilityItem): number | null {
  const explanation = predictionExplanation(item.aiPrediction?.explanation);
  return numberFromUnknown(explanation.official_epss_percentile)
    ?? numberFromUnknown(explanation.officialEpssPercentile)
    ?? item.latestThreatSignal?.epssPercentile
    ?? null;
}

function modelDisplayName(modelVersion: string | null | undefined): string {
  if (!modelVersion) return '—';
  if (modelVersion === 'AI_CYRP_RANDOM_FOREST_V1') return 'AI_CYRP Random Forest';
  if (modelVersion === 'CYRP_BASELINE_V1') return 'CYRP Baseline';
  return modelVersion;
}

function severityClass(severity: string | null): string {
  switch (severity?.toUpperCase()) {
    case 'CRITICAL': return styles.severityCritical;
    case 'HIGH': return styles.severityHigh;
    case 'MEDIUM': return styles.severityMedium;
    case 'LOW': return styles.severityLow;
    default: return styles.severityUnknown;
  }
}

function statusClass(status: string): string {
  if (status === 'ACTIVE') return styles.statusDanger;
  if (status === 'RESOLVED') return styles.statusSuccess;
  if (status === 'UNDER_EVALUATION') return styles.statusWarning;
  if (status === 'CRITICAL' || status === 'HIGH') return styles.statusDanger;
  if (status === 'MEDIUM') return styles.statusWarning;
  if (status === 'LOW') return styles.statusSuccess;
  return styles.statusNeutral;
}

export function AdminVulnerabilitiesClient() {
  const [data, setData] = useState<Pagination<VulnerabilityItem> | null>(null);
  const [queryInput, setQueryInput] = useState('');
  const [query, setQuery] = useState('');
  const [severity, setSeverity] = useState('');
  const [status, setStatus] = useState('ACTIVE');
  const [ownerId, setOwnerId] = useState('');
  const [owners, setOwners] = useState<UserListItem[]>([]);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams({ page: String(page), limit: '25' });
      if (query) params.set('query', query);
      if (severity) params.set('severity', severity);
      if (status) params.set('status', status);
      if (ownerId) params.set('ownerId', ownerId);
      const response = await fetch(`/api/admin/vulnerabilities?${params}`, { cache: 'no-store' });
      const payload = (await response.json()) as Pagination<VulnerabilityItem> & { message?: string };
      if (!response.ok) throw new Error(payload.message ?? 'Không thể tải lỗ hổng');
      setData(payload);
      setError('');
    } catch (caught: unknown) {
      setError(caught instanceof Error ? caught.message : 'Không thể tải lỗ hổng');
    } finally {
      setLoading(false);
    }
  }, [ownerId, page, query, severity, status]);

  useEffect(() => {
    let cancelled = false;

    async function loadOwners(): Promise<void> {
      try {
        const response = await fetch('/api/users?page=1&limit=100&role=USER', {
          cache: 'no-store',
        });
        const payload = (await response.json()) as ListUsersResponse & { message?: string };
        if (!response.ok) {
          return;
        }
        if (!cancelled) {
          setOwners(payload.data ?? []);
        }
      } catch {
        // Owner filter is optional; keep the page usable if this request fails.
      }
    }

    void loadOwners();

    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    void load();
  }, [load]);

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setPage(1);
    setQuery(queryInput.trim());
  }

  return (
    <div className={styles.page}>
      <header className={styles.pageHeader}>
        <div>
          <p className={styles.eyebrow}>Enterprise vulnerability inventory + AI_CYRP prediction</p>
          <h1>Lỗ hổng toàn hệ thống</h1>
          <p className={styles.subtitle}>CVE được Wazuh phát hiện theo từng endpoint/package, làm giàu bằng CTI và chấm điểm bằng AI_CYRP.</p>
        </div>
        <span className={`${styles.statusPill} ${styles.statusNeutral}`}>{data?.total ?? 0} bản ghi</span>
      </header>

      <form className={styles.filterRow} onSubmit={submit}>
        <input className={styles.input} value={queryInput} onChange={(event) => setQueryInput(event.target.value)} placeholder="Tìm CVE, package, hostname" aria-label="Tìm lỗ hổng" />
        <select className={styles.select} value={severity} onChange={(event) => { setSeverity(event.target.value); setPage(1); }} aria-label="Severity"><option value="">Mọi severity</option><option value="CRITICAL">Critical</option><option value="HIGH">High</option><option value="MEDIUM">Medium</option><option value="LOW">Low</option></select>
        <select className={styles.select} value={status} onChange={(event) => { setStatus(event.target.value); setPage(1); }} aria-label="Status"><option value="">Mọi trạng thái</option><option value="ACTIVE">Active</option><option value="UNDER_EVALUATION">Under evaluation</option><option value="RESOLVED">Resolved</option><option value="UNKNOWN">Unknown</option></select>
        <select className={styles.select} value={ownerId} onChange={(event) => { setOwnerId(event.target.value); setPage(1); }} aria-label="Owner"><option value="">Tất cả người dùng</option>{owners.map((owner) => (<option key={owner.id} value={owner.id}>{owner.email}</option>))}</select>
        <button className={styles.primaryButton} type="submit">Tìm kiếm</button>
      </form>

      {error ? <div className={styles.errorPanel}>{error}</div> : null}
      <section className={styles.panel}>
        <div className={styles.panelHeader}>
          <div>
            <h2>Detected vulnerabilities and AI prediction</h2>
            <p>Một CVE có thể xuất hiện nhiều lần nếu ảnh hưởng nhiều endpoint/package. EPSS chỉ là dữ liệu hỗ trợ đầu ra.</p>
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
                  <th>Endpoint / owner</th>
                  <th>Package</th>
                  <th>Severity</th>
                  <th>CVSS</th>
                  <th>AI model</th>
                  <th>Risk level</th>
                  <th>AI xác suất</th>
                  <th>Final priority</th>
                  <th>EPSS hỗ trợ</th>
                  <th>Trạng thái</th>
                  <th>Last seen</th>
                </tr>
              </thead>
              <tbody>
                {(data?.items ?? []).map((item) => {
                  const prediction = item.aiPrediction;
                  const priorityLevel = finalPriorityLevel(item) ?? prediction?.riskLevel ?? null;
                  const priorityScore = finalPriorityScore(item);
                  const epssScore = officialEpssScore(item);
                  const epssPercentile = officialEpssPercentile(item);

                  return (
                    <tr key={item.id}>
                      <td><Link className={styles.linkInline} href={`/vulnerabilities/${item.id}`}><strong>{item.cveId}</strong></Link></td>
                      <td><Link className={styles.linkInline} href={`/endpoints/${item.device.id}`}>{item.device.hostname}</Link><span className={styles.secondaryText}>{item.device.user?.email ?? item.device.operatingSystem}</span></td>
                      <td><span className={styles.primaryText}>{item.packageName ?? 'Không xác định'}</span><span className={styles.secondaryText}>{item.packageVersion ?? '—'}</span></td>
                      <td><span className={`${styles.severityPill} ${severityClass(item.severity)}`}>{item.severity ?? 'UNKNOWN'}</span></td>
                      <td>{item.cvssBaseScore?.toFixed(1) ?? '—'}</td>
                      <td><span className={styles.primaryText}>{modelDisplayName(prediction?.modelVersion)}</span><span className={styles.secondaryText}>{prediction?.modelVersion ?? '—'}</span></td>
                      <td><span className={`${styles.statusPill} ${statusClass(prediction?.riskLevel ?? 'UNKNOWN')}`}>{prediction?.riskLevel ?? '—'}</span></td>
                      <td><span className={styles.primaryText}>{formatProbability(prediction?.attackProbability)}</span><span className={styles.secondaryText}>{prediction ? `score ${prediction.attackProbability.toFixed(3)}` : '—'}</span></td>
                      <td><span className={`${styles.statusPill} ${statusClass(priorityLevel ?? 'UNKNOWN')}`}>{priorityLevel ?? '—'}</span><span className={styles.secondaryText}>{formatProbability(priorityScore)}</span></td>
                      <td><span className={styles.primaryText}>{formatProbability(epssScore)}</span><span className={styles.secondaryText}>{epssPercentile === null ? 'support only' : `percentile ${formatProbability(epssPercentile)}`}</span></td>
                      <td><span className={`${styles.statusPill} ${statusClass(item.status)}`}>{item.status}</span></td>
                      <td>{formatDateTime(item.lastSeenAt)}</td>
                    </tr>
                  );
                })}
                {!data?.items.length ? <tr><td colSpan={12}>Không có bản ghi phù hợp.</td></tr> : null}
              </tbody>
            </table>
          </div>
        )}
      </section>
      <div className={styles.pagination}><span>Trang {data?.page ?? page}/{data?.totalPages ?? 1} · {data?.total ?? 0} kết quả</span><div className={styles.inlineActions}><button className={styles.secondaryButton} type="button" disabled={loading || page <= 1} onClick={() => setPage((value) => Math.max(1, value - 1))}>Trang trước</button><button className={styles.secondaryButton} type="button" disabled={loading || page >= (data?.totalPages ?? 1)} onClick={() => setPage((value) => value + 1)}>Trang sau</button></div></div>
      <div className={styles.notice}>AI_CYRP_RANDOM_FOREST_V1 là lớp dự đoán sau đồng bộ Wazuh. Nếu vừa bấm đồng bộ, cần chạy lại AI refresh để tránh quay về baseline.</div>
    </div>
  );
}
