'use client';

import Link from 'next/link';
import { useCallback, useEffect, useMemo, useState } from 'react';

import styles from '@/components/security-console.module.css';
import type {
  Pagination,
  SyncRunItem,
} from '@/lib/security-data-types';
import { formatDateTime } from '@/lib/security-format';

function statusTone(status: string): string {
  if (status === 'COMPLETED') return styles.statusSuccess;
  if (status === 'FAILED') return styles.statusDanger;
  if (status === 'PARTIAL' || status === 'RUNNING') {
    return styles.statusWarning;
  }
  return styles.statusNeutral;
}

async function responseMessage(response: Response): Promise<string> {
  try {
    const payload = (await response.json()) as { message?: string };
    return payload.message ?? `HTTP ${response.status}`;
  } catch {
    return `HTTP ${response.status}`;
  }
}

export function SyncHistoryClient() {
  const [data, setData] = useState<Pagination<SyncRunItem>>({
    page: 1,
    limit: 50,
    total: 0,
    totalPages: 1,
    items: [],
  });
  const [status, setStatus] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const load = useCallback(async () => {
    setLoading(true);
    const parameters = new URLSearchParams({ limit: '50' });
    if (status) parameters.set('status', status);

    try {
      const response = await fetch(`/api/sync-runs?${parameters.toString()}`, {
        cache: 'no-store',
      });
      if (!response.ok) {
        throw new Error(await responseMessage(response));
      }
      setData((await response.json()) as Pagination<SyncRunItem>);
      setError('');
    } catch (caught: unknown) {
      setError(
        caught instanceof Error
          ? caught.message
          : 'Không thể tải lịch sử đồng bộ',
      );
    } finally {
      setLoading(false);
    }
  }, [status]);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      void load();
    }, 0);

    return () => window.clearTimeout(timer);
  }, [load]);

  const summary = useMemo(
    () => ({
      completed: data.items.filter((item) => item.status === 'COMPLETED').length,
      partial: data.items.filter((item) => item.status === 'PARTIAL').length,
      failed: data.items.filter((item) => item.status === 'FAILED').length,
    }),
    [data.items],
  );

  return (
    <div className={styles.page}>
      <header className={styles.pageHeader}>
        <div>
          <p className={styles.eyebrow}>Data freshness</p>
          <h1>Lịch sử đồng bộ</h1>
        </div>
        <button
          className={styles.secondaryButton}
          type="button"
          onClick={() => void load()}
          disabled={loading}
        >
          Làm mới
        </button>
      </header>

      {error ? <div className={styles.errorPanel}>{error}</div> : null}

      <section className={styles.metricGrid}>
        <article className={styles.metricCard}>
          <span className={styles.metricLabel}>Tổng SyncRun</span>
          <strong className={styles.metricValue}>{data.total}</strong>
          <span className={styles.metricHint}>Thuộc các Device của bạn</span>
        </article>
        <article className={styles.metricCard}>
          <span className={styles.metricLabel}>Hoàn tất</span>
          <strong className={styles.metricValue}>{summary.completed}</strong>
          <span className={styles.metricHint}>Trong trang dữ liệu hiện tại</span>
        </article>
        <article className={styles.metricCard}>
          <span className={styles.metricLabel}>Một phần</span>
          <strong className={styles.metricValue}>{summary.partial}</strong>
          <span className={styles.metricHint}>Một hoặc nhiều category thiếu</span>
        </article>
        <article className={styles.metricCard}>
          <span className={styles.metricLabel}>Thất bại</span>
          <strong className={styles.metricValue}>{summary.failed}</strong>
          <span className={styles.metricHint}>Cần kiểm tra Agent hoặc Wazuh</span>
        </article>
      </section>

      <section className={styles.filterRow}>
        <select
          className={styles.select}
          value={status}
          onChange={(event) => setStatus(event.target.value)}
        >
          <option value="">Mọi trạng thái</option>
          <option value="RUNNING">RUNNING</option>
          <option value="COMPLETED">COMPLETED</option>
          <option value="PARTIAL">PARTIAL</option>
          <option value="FAILED">FAILED</option>
        </select>
      </section>

      <section className={styles.panel}>
        <div className={styles.panelHeader}>
          <div>
            <h2>Pipeline history</h2>
            <p>
              Records read/write/rejected giúp phân biệt dữ liệu bằng 0 với đồng
              bộ chưa chạy hoặc đồng bộ lỗi.
            </p>
          </div>
        </div>
        {loading && !data.items.length ? (
          <div className={styles.loadingSkeleton} />
        ) : (
          <div className={styles.tableWrap}>
            <table className={styles.table}>
              <thead>
                <tr>
                  <th>Thời gian</th>
                  <th>Device</th>
                  <th>Nguồn</th>
                  <th>Trạng thái</th>
                  <th>Read / Write / Reject</th>
                  <th>Lỗi</th>
                </tr>
              </thead>
              <tbody>
                {data.items.map((run) => (
                  <tr key={run.id}>
                    <td>
                      <span className={styles.primaryText}>
                        {formatDateTime(run.startedAt)}
                      </span>
                      <span className={styles.secondaryText}>{run.trigger}</span>
                    </td>
                    <td>
                      {run.device ? (
                        <Link
                          className={styles.linkInline}
                          href={`/devices/${run.device.id}`}
                        >
                          {run.device.hostname}
                        </Link>
                      ) : (
                        '--'
                      )}
                    </td>
                    <td>
                      <span className={styles.codeText}>{run.sourceType}</span>
                    </td>
                    <td>
                      <span
                        className={`${styles.statusPill} ${statusTone(run.status)}`}
                      >
                        {run.status}
                      </span>
                    </td>
                    <td>
                      {run.recordsRead} / {run.recordsWritten} /{' '}
                      {run.recordsRejected}
                    </td>
                    <td>
                      <span className={styles.secondaryText}>
                        {run.errorSummary ?? '--'}
                      </span>
                    </td>
                  </tr>
                ))}
                {!data.items.length ? (
                  <tr>
                    <td colSpan={6}>Chưa có SyncRun phù hợp bộ lọc.</td>
                  </tr>
                ) : null}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}
