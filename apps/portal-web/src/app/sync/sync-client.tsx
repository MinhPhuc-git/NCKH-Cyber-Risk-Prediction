'use client';

import Link from 'next/link';
import {
  useCallback,
  useEffect,
  useMemo,
  useState,
} from 'react';

import styles from '@/components/security-console.module.css';
import type {
  Pagination,
  SyncRunItem,
} from '@/lib/security-data-types';
import { formatDateTime } from '@/lib/security-format';

const SOURCE_OPTIONS = [
  '',
  'WAZUH_VULNERABILITIES',
  'WAZUH_ENDPOINT_CONTEXT',
  'CTI_CSV',
  'CTI_NVD',
  'CTI_EPSS',
  'CTI_CISA_KEV',
];

function statusTone(status: string): string {
  switch (status) {
    case 'COMPLETED':
      return styles.statusSuccess;
    case 'PARTIAL':
    case 'RUNNING':
      return styles.statusWarning;
    case 'FAILED':
      return styles.statusDanger;
    default:
      return styles.statusNeutral;
  }
}

function duration(run: SyncRunItem): string {
  if (!run.completedAt) {
    return 'Đang chạy';
  }

  const milliseconds =
    new Date(run.completedAt).getTime() - new Date(run.startedAt).getTime();

  if (!Number.isFinite(milliseconds) || milliseconds < 0) {
    return '--';
  }

  if (milliseconds < 1000) {
    return '< 1 giây';
  }

  const seconds = Math.round(milliseconds / 1000);

  if (seconds < 60) {
    return `${seconds} giây`;
  }

  const minutes = Math.floor(seconds / 60);
  const remainingSeconds = seconds % 60;

  if (minutes < 60) {
    return remainingSeconds > 0
      ? `${minutes} phút ${remainingSeconds} giây`
      : `${minutes} phút`;
  }

  const hours = Math.floor(minutes / 60);
  const remainingMinutes = minutes % 60;

  return remainingMinutes > 0
    ? `${hours} giờ ${remainingMinutes} phút`
    : `${hours} giờ`;
}

async function readMessage(response: Response): Promise<string> {
  try {
    const payload = (await response.json()) as {
      message?: string;
      detail?: string;
    };
    return payload.message ?? payload.detail ?? `HTTP ${response.status}`;
  } catch {
    return `HTTP ${response.status}`;
  }
}

export function SyncClient() {
  const [data, setData] = useState<Pagination<SyncRunItem>>({
    page: 1,
    limit: 50,
    total: 0,
    totalPages: 1,
    items: [],
  });
  const [status, setStatus] = useState('');
  const [sourceType, setSourceType] = useState('');
  const [loading, setLoading] = useState(true);
  const [syncing, setSyncing] = useState(false);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');

  const load = useCallback(async () => {
    setLoading(true);
    const parameters = new URLSearchParams({ limit: '50' });
    if (status) parameters.set('status', status);
    if (sourceType) parameters.set('sourceType', sourceType);

    try {
      const response = await fetch(
        `/api/admin/sync-runs?${parameters.toString()}`,
        { cache: 'no-store' },
      );
      if (!response.ok) {
        throw new Error(await readMessage(response));
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
  }, [sourceType, status]);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      void load();
    }, 0);

    return () => window.clearTimeout(timer);
  }, [load]);

  useEffect(() => {
    if (!data.items.some((item) => item.status === 'RUNNING')) {
      return;
    }

    const timer = window.setInterval(() => {
      void load();
    }, 10_000);

    return () => window.clearInterval(timer);
  }, [data.items, load]);

  const summary = useMemo(() => {
    const completed = data.items.filter(
      (item) => item.status === 'COMPLETED',
    ).length;
    const partial = data.items.filter(
      (item) => item.status === 'PARTIAL',
    ).length;
    const failed = data.items.filter((item) => item.status === 'FAILED').length;
    const running = data.items.filter(
      (item) => item.status === 'RUNNING',
    ).length;

    return { completed, partial, failed, running };
  }, [data.items]);

  async function syncAll(): Promise<void> {
    const confirmed = window.confirm(
      'Đồng bộ alerts, vulnerability state và endpoint inventory cho toàn bộ Device đã binding? Tác vụ có thể tạo tải lên Wazuh Indexer.',
    );

    if (!confirmed) {
      return;
    }

    setSyncing(true);
    setNotice('');

    try {
      const response = await fetch('/api/admin/data-sync/all', {
        method: 'POST',
      });
      if (!response.ok) {
        throw new Error(await readMessage(response));
      }
      const result = (await response.json()) as {
        requested?: number;
        completed?: number;
        partial?: number;
        failed?: number;
      };
      setNotice(
        `Đã xử lý ${result.requested ?? 0} thiết bị: ${
          result.completed ?? 0
        } hoàn tất, ${result.partial ?? 0} một phần, ${
          result.failed ?? 0
        } thất bại.`,
      );
      await load();
    } catch (caught: unknown) {
      setNotice(
        caught instanceof Error ? caught.message : 'Không thể đồng bộ dữ liệu',
      );
    } finally {
      setSyncing(false);
    }
  }

  return (
    <div className={styles.page}>
      <header className={styles.pageHeader}>
        <div>
          <p className={styles.eyebrow}>Pipeline observability</p>
          <h1>Đồng bộ dữ liệu</h1>
          <p className={styles.subtitle}>
            Theo dõi provenance, số bản ghi đọc/ghi/từ chối và trạng thái của
            pipeline Wazuh vulnerability, endpoint context và CTI.
          </p>
        </div>
        <div className={styles.headerActions}>
          <button
            className={styles.secondaryButton}
            type="button"
            onClick={() => void load()}
            disabled={loading || syncing}
          >
            Làm mới
          </button>
          <button
            className={styles.primaryButton}
            type="button"
            onClick={() => void syncAll()}
            disabled={syncing}
          >
            {syncing ? 'Đang đồng bộ...' : 'Đồng bộ mọi Device'}
          </button>
        </div>
      </header>

      {error ? <div className={styles.errorPanel}>{error}</div> : null}
      {notice ? <div className={styles.notice}>{notice}</div> : null}

      <section className={styles.metricGrid}>
        <article className={styles.metricCard}>
          <span className={styles.metricLabel}>Tổng lịch sử</span>
          <strong className={styles.metricValue}>{data.total}</strong>
          <span className={styles.metricHint}>Tất cả SyncRun phù hợp bộ lọc</span>
        </article>
        <article className={styles.metricCard}>
          <span className={styles.metricLabel}>Hoàn tất</span>
          <strong className={styles.metricValue}>{summary.completed}</strong>
          <span className={styles.metricHint}>Trong tối đa 50 lần hiển thị</span>
        </article>
        <article className={styles.metricCard}>
          <span className={styles.metricLabel}>Partial / Running</span>
          <strong className={styles.metricValue}>
            {summary.partial + summary.running}
          </strong>
          <span className={styles.metricHint}>
            {summary.running} đang chạy · {summary.partial} một phần
          </span>
        </article>
        <article className={styles.metricCard}>
          <span className={styles.metricLabel}>Thất bại</span>
          <strong className={styles.metricValue}>{summary.failed}</strong>
          <span className={styles.metricHint}>Cần kiểm tra error summary</span>
        </article>
      </section>

      <section className={styles.filterRow} aria-label="Bộ lọc đồng bộ">
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
        <select
          className={styles.select}
          value={sourceType}
          onChange={(event) => setSourceType(event.target.value)}
        >
          <option value="">Mọi nguồn dữ liệu</option>
          {SOURCE_OPTIONS.filter(Boolean).map((source) => (
            <option key={source} value={source}>
              {source}
            </option>
          ))}
        </select>
      </section>

      <section className={styles.panel}>
        <div className={styles.panelHeader}>
          <div>
            <h2>Sync run history</h2>
            <p>
              Dữ liệu append-only để truy vết nguồn, thời điểm và kết quả đồng
              bộ; không phải lịch sử dự đoán AI.
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
                  <th>Nguồn</th>
                  <th>Device</th>
                  <th>Trạng thái</th>
                  <th>Records</th>
                  <th>Thời lượng</th>
                  <th>Thông tin lỗi</th>
                </tr>
              </thead>
              <tbody>
                {data.items.map((run) => (
                  <tr key={run.id}>
                    <td>
                      <span className={styles.primaryText}>
                        {formatDateTime(run.startedAt)}
                      </span>
                      <span className={styles.secondaryText}>
                        {run.trigger}
                      </span>
                    </td>
                    <td>
                      <span className={styles.codeText}>{run.sourceType}</span>
                      <span className={styles.secondaryText}>
                        {run.source?.name ?? run.sourceVersion ?? '--'}
                      </span>
                    </td>
                    <td>
                      {run.device ? (
                        <Link
                          className={styles.linkInline}
                          href={`/endpoints/${run.device.id}`}
                        >
                          {run.device.hostname}
                        </Link>
                      ) : (
                        <span className={styles.secondaryText}>Global CTI</span>
                      )}
                    </td>
                    <td>
                      <span
                        className={`${styles.statusPill} ${statusTone(run.status)}`}
                      >
                        {run.status}
                      </span>
                    </td>
                    <td>
                      <span className={styles.primaryText}>
                        R {run.recordsRead} · W {run.recordsWritten}
                      </span>
                      <span className={styles.secondaryText}>
                        U {run.recordsUpdated} · Res {run.recordsResolved} · Rej{' '}
                        {run.recordsRejected}
                      </span>
                    </td>
                    <td>{duration(run)}</td>
                    <td>
                      {run.errorSummary ? (
                        <span className={styles.secondaryText}>
                          {run.errorSummary}
                        </span>
                      ) : (
                        '--'
                      )}
                    </td>
                  </tr>
                ))}
                {!data.items.length ? (
                  <tr>
                    <td colSpan={7}>Chưa có SyncRun phù hợp bộ lọc.</td>
                  </tr>
                ) : null}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <div className={styles.notice}>
        Đồng bộ tự động trong tiến trình API chỉ phù hợp bản luận văn một instance.
        Khi triển khai nhiều instance cần tách worker/queue và distributed lock.
      </div>
    </div>
  );
}
