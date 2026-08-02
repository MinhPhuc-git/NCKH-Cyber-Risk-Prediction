'use client';

import Link from 'next/link';
import { useCallback, useEffect, useMemo, useState } from 'react';

import styles from '@/components/security-console.module.css';
import type { UserDataOverview } from '@/lib/security-data-types';
import type { SecurityOverview } from '@/lib/security-snapshot-types';

const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'] as const;

function formatDate(value: string | null | undefined): string {
  if (!value) {
    return 'Chưa đồng bộ';
  }
  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? 'Không xác định'
    : new Intl.DateTimeFormat('vi-VN', {
        dateStyle: 'short',
        timeStyle: 'short',
      }).format(date);
}

function severityClass(severity: string | null): string {
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

function runStatusClass(status: string): string {
  if (status === 'COMPLETED') return styles.statusSuccess;
  if (status === 'PARTIAL' || status === 'RUNNING') return styles.statusWarning;
  if (status === 'FAILED') return styles.statusDanger;
  return styles.statusNeutral;
}

export function DashboardOverviewClient() {
  const [overview, setOverview] = useState<UserDataOverview | null>(null);
  const [alertOverview, setAlertOverview] = useState<SecurityOverview | null>(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);

  const load = useCallback(async (): Promise<void> => {
    setLoading(true);
    try {
      const [dataResponse, alertResponse] = await Promise.all([
        fetch('/api/dashboard/data-overview', { cache: 'no-store' }),
        fetch('/api/dashboard/security-overview', { cache: 'no-store' }),
      ]);

      const dataPayload = (await dataResponse.json()) as UserDataOverview & {
        message?: string;
      };
      if (!dataResponse.ok) {
        throw new Error(dataPayload.message ?? 'Không thể tải dữ liệu bảo mật');
      }
      setOverview(dataPayload);

      if (alertResponse.ok) {
        setAlertOverview((await alertResponse.json()) as SecurityOverview);
      } else {
        setAlertOverview(null);
      }
      setError('');
    } catch (caught: unknown) {
      setError(
        caught instanceof Error
          ? caught.message
          : 'Không thể tải tổng quan an ninh',
      );
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    const initialTimer = window.setTimeout(() => {
      void load();
    }, 0);
    const refreshTimer = window.setInterval(() => void load(), 60_000);

    return () => {
      window.clearTimeout(initialTimer);
      window.clearInterval(refreshTimer);
    };
  }, [load]);

  const severityTotal = overview?.vulnerabilities.active ?? 0;
  const criticalCount = overview?.vulnerabilities.severity.CRITICAL ?? 0;
  const highCount = overview?.vulnerabilities.severity.HIGH ?? 0;
  const maxSeverity = useMemo(
    () =>
      Math.max(
        1,
        ...SEVERITIES.map(
          (severity) => overview?.vulnerabilities.severity[severity] ?? 0,
        ),
      ),
    [overview],
  );

  if (loading && !overview) {
    return <div className={styles.loadingSkeleton} aria-label="Đang tải" />;
  }

  return (
    <div className={styles.page}>
      <header className={styles.pageHeader}>
        <div>
          <p className={styles.eyebrow}>Security dashboard</p>
          <h1>Tổng quan an ninh</h1>
        </div>
        <div className={styles.headerActions}>
          <button
            type="button"
            className={styles.secondaryButton}
            onClick={() => void load()}
            disabled={loading}
          >
            {loading ? 'Đang làm mới…' : 'Làm mới'}
          </button>
        </div>
      </header>

      {error ? <div className={styles.errorPanel}>{error}</div> : null}

      <section className={styles.metricGrid}>
        <article className={styles.metricCard}>
          <span className={styles.metricLabel}>Lỗ hổng đang mở</span>
          <strong className={styles.metricValue}>{severityTotal}</strong>
          <span className={styles.metricHint}>Được đồng bộ từ Wazuh vulnerability state</span>
        </article>
        <article className={styles.metricCard}>
          <span className={styles.metricLabel}>Critical</span>
          <strong className={styles.metricValue}>{criticalCount}</strong>
          <span className={styles.metricHint}>Ưu tiên xử lý trước</span>
        </article>
        <article className={styles.metricCard}>
          <span className={styles.metricLabel}>High</span>
          <strong className={styles.metricValue}>{highCount}</strong>
          <span className={styles.metricHint}>Cần rà soát và vá sớm</span>
        </article>
        <article className={styles.metricCard}>
          <span className={styles.metricLabel}>Context quá hạn</span>
          <strong className={styles.metricValue}>{overview?.devices.stale ?? 0}</strong>
          <span className={styles.metricHint}>Chưa có snapshot mới trong 24 giờ</span>
        </article>
      </section>

      <section className={styles.panelGrid}>
        <article className={styles.panel}>
          <div className={styles.panelHeader}>
            <div>
              <h2>Lỗ hổng cần chú ý</h2>
              <p>Xếp theo CVSS và thời điểm Wazuh ghi nhận gần nhất.</p>
            </div>
            <Link className={styles.linkButton} href="/vulnerabilities">
              Xem tất cả
            </Link>
          </div>
          <div className={styles.tableWrap}>
            <table className={styles.table}>
              <thead>
                <tr>
                  <th>CVE</th>
                  <th>Thiết bị</th>
                  <th>Package</th>
                  <th>Mức độ</th>
                  <th>CVSS</th>
                  <th>Wazuh last seen</th>
                </tr>
              </thead>
              <tbody>
                {(overview?.vulnerabilities.top ?? []).map((item) => (
                  <tr key={item.id}>
                    <td>
                      <Link className={styles.linkInline} href={`/vulnerabilities/${item.id}`}>
                        {item.cveId}
                      </Link>
                    </td>
                    <td>{item.device.hostname}</td>
                    <td>
                      <span className={styles.primaryText}>{item.packageName ?? 'Không rõ'}</span>
                      <span className={styles.secondaryText}>{item.packageVersion ?? '—'}</span>
                    </td>
                    <td>
                      <span className={`${styles.severityPill} ${severityClass(item.severity)}`}>
                        {item.severity ?? 'UNKNOWN'}
                      </span>
                    </td>
                    <td>{item.cvssBaseScore?.toFixed(1) ?? '—'}</td>
                    <td>{formatDate(item.lastSeenAt)}</td>
                  </tr>
                ))}
                {!overview?.vulnerabilities.top.length ? (
                  <tr>
                    <td colSpan={6}>Chưa có trạng thái lỗ hổng được đồng bộ.</td>
                  </tr>
                ) : null}
              </tbody>
            </table>
          </div>
        </article>

        <article className={styles.panel}>
          <div className={styles.panelHeader}>
            <div>
              <h2>Phân bố severity</h2>
              <p>{severityTotal} lỗ hổng đang ở trạng thái active.</p>
            </div>
          </div>
          <div className={styles.severityStack}>
            {SEVERITIES.map((severity) => {
              const count = overview?.vulnerabilities.severity[severity] ?? 0;
              return (
                <div className={styles.severityRow} key={severity}>
                  <span>{severity}</span>
                  <div className={styles.severityTrack}>
                    <div
                      className={styles.severityFill}
                      style={{ width: `${Math.max(2, (count / maxSeverity) * 100)}%` }}
                    />
                  </div>
                  <strong>{count}</strong>
                </div>
              );
            })}
          </div>
        </article>
      </section>

      <section className={styles.panelGridEqual}>
        <article className={styles.panel}>
          <div className={styles.panelHeader}>
            <div>
              <h2>Lịch sử đồng bộ</h2>
              <p>Vulnerability state và endpoint context gần đây.</p>
            </div>
            <Link className={styles.linkButton} href="/sync-history">Mở lịch sử</Link>
          </div>
          <div className={styles.timeline}>
            {(overview?.recentRuns ?? []).slice(0, 7).map((run) => (
              <div className={styles.timelineItem} key={run.id}>
                <div>
                  <strong>{run.sourceType.replaceAll('_', ' ')}</strong>
                  <span>{run.device?.hostname ?? 'Nguồn CTI'} · {formatDate(run.startedAt)}</span>
                </div>
                <span className={`${styles.statusPill} ${runStatusClass(run.status)}`}>
                  {run.status}
                </span>
              </div>
            ))}
            {!overview?.recentRuns.length ? (
              <div className={styles.emptyState}>Chưa có lần đồng bộ.</div>
            ) : null}
          </div>
        </article>

        <article className={styles.panel}>
          <div className={styles.panelHeader}>
            <div>
              <h2>Cảnh báo Wazuh 24 giờ</h2>
              <p>Heuristic vận hành độc lập với pipeline AI.</p>
            </div>
          </div>
          <div className={styles.detailGrid}>
            <div className={styles.detailItem}>
              <span className={styles.label}>Tổng cảnh báo</span>
              <strong>{alertOverview?.alerts24h.total ?? 0}</strong>
            </div>
            <div className={styles.detailItem}>
              <span className={styles.label}>Critical</span>
              <strong>{alertOverview?.alerts24h.critical ?? 0}</strong>
            </div>
            <div className={styles.detailItem}>
              <span className={styles.label}>High</span>
              <strong>{alertOverview?.alerts24h.high ?? 0}</strong>
            </div>
          </div>
        </article>
      </section>
    </div>
  );
}
