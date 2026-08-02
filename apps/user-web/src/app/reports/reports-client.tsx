'use client';

import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { useCallback, useEffect, useMemo, useState } from 'react';

import styles from '@/components/security-console.module.css';
import { formatDateTime, statusLabel } from '@/lib/security-format';
import type {
  Pagination,
  SyncRunItem,
  UserDataOverview,
} from '@/lib/security-data-types';

function statusTone(status: string): string {
  if (status === 'COMPLETED') return styles.statusSuccess;
  if (status === 'FAILED') return styles.statusDanger;
  if (status === 'PARTIAL' || status === 'RUNNING') return styles.statusWarning;
  return styles.statusNeutral;
}

export function ReportsClient() {
  const router = useRouter();
  const [overview, setOverview] = useState<UserDataOverview | null>(null);
  const [runs, setRuns] = useState<Pagination<SyncRunItem> | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [status, setStatus] = useState('');
  const [page, setPage] = useState(1);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams({ page: String(page), limit: '25' });
      if (status) params.set('status', status);
      const [overviewResponse, runsResponse] = await Promise.all([
        fetch('/api/dashboard/data-overview', { cache: 'no-store' }),
        fetch(`/api/sync-runs?${params}`, { cache: 'no-store' }),
      ]);
      if ([overviewResponse.status, runsResponse.status].some((value) => value === 401 || value === 403)) {
        router.replace('/login');
        return;
      }
      const overviewPayload = (await overviewResponse.json()) as UserDataOverview & { message?: string };
      const runsPayload = (await runsResponse.json()) as Pagination<SyncRunItem> & { message?: string };
      if (!overviewResponse.ok) throw new Error(overviewPayload.message ?? 'Không thể tải báo cáo');
      if (!runsResponse.ok) throw new Error(runsPayload.message ?? 'Không thể tải lịch sử đồng bộ');
      setOverview(overviewPayload);
      setRuns(runsPayload);
      setError('');
    } catch (caught: unknown) {
      setError(caught instanceof Error ? caught.message : 'Không thể tải báo cáo dữ liệu');
    } finally {
      setLoading(false);
    }
  }, [page, router, status]);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      void load();
    }, 0);

    return () => window.clearTimeout(timer);
  }, [load]);

  const runStats = useMemo(() => {
    const items = runs?.items ?? [];
    return {
      completed: items.filter((run) => run.status === 'COMPLETED').length,
      partial: items.filter((run) => run.status === 'PARTIAL').length,
      failed: items.filter((run) => run.status === 'FAILED').length,
      records: items.reduce((sum, run) => sum + run.recordsWritten + run.recordsUpdated, 0),
    };
  }, [runs]);

  return (
    <div className={styles.page}>
      <header className={styles.pageHeader}>
        <div>
          <p className={styles.eyebrow}>Data quality & provenance</p>
          <h1>Báo cáo dữ liệu</h1>
          <p className={styles.subtitle}>
            Theo dõi phạm vi dữ liệu đã thu thập, lịch sử đồng bộ và lỗi pipeline trước khi chuyển sang Feature Builder.
          </p>
        </div>
        <button className={styles.secondaryButton} type="button" onClick={() => void load()} disabled={loading}>Làm mới</button>
      </header>

      {error ? <div className={styles.errorPanel}>{error}</div> : null}

      <section className={styles.metricGrid}>
        <article className={styles.metricCard}><span className={styles.metricLabel}>Active CVE</span><strong className={styles.metricValue}>{overview?.vulnerabilities.active ?? '—'}</strong><span className={styles.metricHint}>{(overview?.vulnerabilities.severity.CRITICAL ?? 0) + (overview?.vulnerabilities.severity.HIGH ?? 0)} Critical/High</span></article>
        <article className={styles.metricCard}><span className={styles.metricLabel}>Sync thành công</span><strong className={styles.metricValue}>{runStats.completed}</strong><span className={styles.metricHint}>{runStats.partial} partial · {runStats.failed} failed trong trang hiện tại</span></article>
        <article className={styles.metricCard}><span className={styles.metricLabel}>Records thay đổi</span><strong className={styles.metricValue}>{runStats.records}</strong><span className={styles.metricHint}>Written + updated trong trang hiện tại</span></article>
      </section>

      <section className={styles.panel}>
        <div className={styles.panelHeader}><div><h2>Chất lượng dữ liệu</h2><p>Những điều cần kiểm tra trước khi dùng cho AI.</p></div></div>
          <div className={styles.keyValueList}>
            <div className={styles.keyValueRow}><span>Thiết bị thiếu hoặc stale context</span><strong>{overview?.devices.stale ?? '—'}</strong></div>
            <div className={styles.keyValueRow}><span>Critical CVE</span><strong>{overview?.vulnerabilities.severity.CRITICAL ?? 0}</strong></div>
            <div className={styles.keyValueRow}><span>Unknown severity</span><strong>{overview?.vulnerabilities.severity.UNKNOWN ?? 0}</strong></div>
            <div className={styles.keyValueRow}><span>Lần tính báo cáo</span><strong>{formatDateTime(overview?.calculatedAt)}</strong></div>
          </div>
          <div className={styles.notice} style={{ marginTop: 14 }}>
            Báo cáo này đánh giá tính sẵn sàng của dữ liệu. Nó chưa đánh giá chất lượng của label hoặc độ chính xác của model AI.
          </div>
      </section>

      <section className={styles.panel}>
        <div className={styles.panelHeader}>
          <div><h2>Lịch sử đồng bộ</h2><p>Mỗi run lưu source, số bản ghi, checkpoint và thông báo lỗi.</p></div>
          <select className={styles.select} value={status} onChange={(event) => { setStatus(event.target.value); setPage(1); }} aria-label="Lọc trạng thái đồng bộ">
            <option value="">Mọi trạng thái</option>
            <option value="COMPLETED">Completed</option>
            <option value="PARTIAL">Partial</option>
            <option value="FAILED">Failed</option>
            <option value="RUNNING">Running</option>
          </select>
        </div>
        {loading && !runs ? <div className={styles.loadingSkeleton} /> : (
          <div className={styles.tableWrap}>
            <table className={styles.table}>
              <thead><tr><th>Thời gian</th><th>Thiết bị</th><th>Nguồn</th><th>Records</th><th>Trạng thái</th><th>Lỗi</th></tr></thead>
              <tbody>
                {(runs?.items ?? []).map((run) => (
                  <tr key={run.id}>
                    <td>{formatDateTime(run.startedAt)}</td>
                    <td>{run.device ? <Link className={styles.linkInline} href={`/devices/${run.device.id}`}>{run.device.hostname}</Link> : 'Toàn hệ thống'}</td>
                    <td><span className={styles.primaryText}>{run.source?.name ?? run.sourceType}</span><span className={styles.secondaryText}>{run.trigger}</span></td>
                    <td>R {run.recordsRead} · W {run.recordsWritten} · U {run.recordsUpdated} · X {run.recordsRejected}</td>
                    <td><span className={`${styles.statusPill} ${statusTone(run.status)}`}>{statusLabel(run.status)}</span></td>
                    <td>{run.errorSummary ?? '—'}</td>
                  </tr>
                ))}
                {!runs?.items.length ? <tr><td colSpan={6}>Chưa có sync run phù hợp.</td></tr> : null}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <div className={styles.pagination}>
        <span>Trang {runs?.page ?? page}/{runs?.totalPages ?? 1} · {runs?.total ?? 0} run</span>
        <div className={styles.inlineActions}>
          <button className={styles.secondaryButton} type="button" disabled={loading || page <= 1} onClick={() => setPage((value) => Math.max(1, value - 1))}>Trang trước</button>
          <button className={styles.secondaryButton} type="button" disabled={loading || page >= (runs?.totalPages ?? 1)} onClick={() => setPage((value) => value + 1)}>Trang sau</button>
        </div>
      </div>
    </div>
  );
}
