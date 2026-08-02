'use client';

import Link from 'next/link';
import { useCallback, useEffect, useMemo, useState } from 'react';

import styles from '@/components/security-console.module.css';
import type {
  SyncRunItem,
  SystemHealthResponse,
} from '@/lib/security-data-types';
import { formatDateTime } from '@/lib/security-format';

function booleanField(value: Record<string, unknown>, name: string): boolean {
  return value[name] === true;
}

function textField(value: Record<string, unknown>, name: string): string | null {
  return typeof value[name] === 'string' ? (value[name] as string) : null;
}

function nestedRecord(
  value: Record<string, unknown>,
  name: string,
): Record<string, unknown> | null {
  const candidate = value[name];
  return typeof candidate === 'object' && candidate !== null
    ? (candidate as Record<string, unknown>)
    : null;
}

function runTone(status: string): string {
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

export function SystemHealthClient() {
  const grafanaUrl = process.env.NEXT_PUBLIC_GRAFANA_URL ?? '';
  const [data, setData] = useState<SystemHealthResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const response = await fetch('/api/admin/system-health', {
        cache: 'no-store',
      });
      if (!response.ok) {
        throw new Error(await responseMessage(response));
      }
      setData((await response.json()) as SystemHealthResponse);
      setError('');
    } catch (caught: unknown) {
      setError(
        caught instanceof Error
          ? caught.message
          : 'Không thể kiểm tra sức khỏe hệ thống',
      );
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      void load();
    }, 0);

    return () => window.clearTimeout(timer);
  }, [load]);

  const databaseConnected = data
    ? booleanField(data.database, 'connected')
    : false;
  const wazuhEnabled = data ? booleanField(data.wazuhApi, 'enabled') : false;
  const wazuhConnected = data
    ? booleanField(data.wazuhApi, 'connected')
    : false;
  const indexerConnected = data
    ? booleanField(data.indexer, 'connected')
    : false;
  const manager = data ? nestedRecord(data.wazuhApi, 'manager') : null;
  const cluster = data ? nestedRecord(data.indexer, 'cluster') : null;
  const failedRuns = useMemo(
    () => data?.latestRuns.filter((run) => run.status === 'FAILED').length ?? 0,
    [data],
  );

  return (
    <div className={styles.page}>
      <header className={styles.pageHeader}>
        <div>
          <p className={styles.eyebrow}>Operational diagnostics</p>
          <h1>Sức khỏe hệ thống</h1>
          <p className={styles.subtitle}>
            Kiểm tra độc lập PostgreSQL, Wazuh Server API, Wazuh Indexer và bộ
            lập lịch đồng bộ Phase 2. Trạng thái lỗi không được thay bằng dữ liệu
            giả.
          </p>
        </div>
        <button
          className={styles.secondaryButton}
          type="button"
          onClick={() => void load()}
          disabled={loading}
        >
          Chạy lại kiểm tra
        </button>
      </header>

      {error ? <div className={styles.errorPanel}>{error}</div> : null}

      <section className={styles.metricGrid}>
        <article className={styles.metricCard}>
          <span className={styles.metricLabel}>PostgreSQL</span>
          <strong className={styles.metricValue}>
            {databaseConnected ? 'Online' : 'Offline'}
          </strong>
          <span className={styles.metricHint}>
            Latency:{' '}
            {typeof data?.database.latencyMs === 'number'
              ? `${data.database.latencyMs} ms`
              : '--'}
          </span>
        </article>
        <article className={styles.metricCard}>
          <span className={styles.metricLabel}>Wazuh Server API</span>
          <strong className={styles.metricValue}>
            {wazuhConnected ? 'Online' : wazuhEnabled ? 'Offline' : 'Disabled'}
          </strong>
          <span className={styles.metricHint}>
            {manager
              ? `${textField(manager, 'name') ?? 'Manager'} · ${
                  textField(manager, 'version') ?? 'unknown version'
                }`
              : 'Chưa có manager metadata'}
          </span>
        </article>
        <article className={styles.metricCard}>
          <span className={styles.metricLabel}>Wazuh Indexer</span>
          <strong className={styles.metricValue}>
            {indexerConnected ? 'Online' : wazuhEnabled ? 'Offline' : 'Disabled'}
          </strong>
          <span className={styles.metricHint}>
            {cluster
              ? `${textField(cluster, 'name') ?? 'Cluster'} · ${
                  textField(cluster, 'status') ?? 'unknown'
                }`
              : 'Chưa có cluster metadata'}
          </span>
        </article>
        <article className={styles.metricCard}>
          <span className={styles.metricLabel}>Data scheduler</span>
          <strong className={styles.metricValue}>
            {data?.synchronization.enabled ? 'Enabled' : 'Disabled'}
          </strong>
          <span className={styles.metricHint}>
            {data
              ? `${data.synchronization.intervalSeconds}s · leases ${data.synchronization.syncLock.localActiveLeases}`
              : '--'}
          </span>
        </article>
      </section>

      <section className={styles.panel}>
        <div className={styles.panelHeader}>
          <div>
            <h2>Log thô và quan sát hệ thống</h2>
            <p>Mở Grafana/Loki để điều tra log thô khi endpoint có dấu hiệu bị tấn công. Link này chỉ dành cho quản trị viên.</p>
          </div>
          {grafanaUrl ? (
            <a className={styles.linkButton} href={grafanaUrl} target="_blank" rel="noreferrer">Mở Grafana Logs</a>
          ) : (
            <span className={`${styles.statusPill} ${styles.statusNeutral}`}>Chưa cấu hình Grafana URL</span>
          )}
        </div>
      </section>

      <section className={styles.panelGrid}>
        <article className={styles.panel}>
          <div className={styles.panelHeader}>
            <div>
              <h2>Dependency status</h2>
              <p>
                Wazuh integration và scheduler là hai công tắc riêng; bật API
                không có nghĩa scheduler đã chạy.
              </p>
            </div>
          </div>
          <div className={styles.keyValueList}>
            <div className={styles.keyValueRow}>
              <span>Checked at</span>
              <strong>{formatDateTime(data?.checkedAt ?? null)}</strong>
            </div>
            <div className={styles.keyValueRow}>
              <span>Health response</span>
              <strong>{data?.responseTimeMs ?? '--'} ms</strong>
            </div>
            <div className={styles.keyValueRow}>
              <span>Wazuh integration</span>
              <strong>
                {data?.synchronization.integrationEnabled
                  ? 'Đã bật'
                  : 'Đang tắt'}
              </strong>
            </div>
            <div className={styles.keyValueRow}>
              <span>Scheduler configured</span>
              <strong>
                {data?.synchronization.configured ? 'true' : 'false'}
              </strong>
            </div>
            <div className={styles.keyValueRow}>
              <span>Scheduler running</span>
              <strong>{data?.synchronization.running ? 'true' : 'false'}</strong>
            </div>
            <div className={styles.keyValueRow}>
              <span>Data sync concurrency</span>
              <strong>{data?.synchronization.maxConcurrency ?? '--'}</strong>
            </div>
            <div className={styles.keyValueRow}>
              <span>Persistent sync lock</span>
              <strong>
                {data
                  ? `${data.synchronization.syncLock.strategy} · TTL ${data.synchronization.syncLock.ttlSeconds}s`
                  : '--'}
              </strong>
            </div>
            <div className={styles.keyValueRow}>
              <span>Stale SyncRun recovery</span>
              <strong>
                {data ? `${data.synchronization.staleRunMinutes} phút` : '--'}
              </strong>
            </div>
            <div className={styles.keyValueRow}>
              <span>Agent status scheduler</span>
              <strong>
                {data?.agentRuntime.enabled
                  ? `Enabled · ${data.agentRuntime.intervalSeconds}s`
                  : 'Disabled'}
              </strong>
            </div>
            <div className={styles.keyValueRow}>
              <span>Wazuh request retry</span>
              <strong>
                {data
                  ? `${data.wazuhRuntime.retryAttempts} attempts · ${data.wazuhRuntime.retryBaseDelayMs}ms base`
                  : '--'}
              </strong>
            </div>
          </div>
        </article>

        <article className={styles.panel}>
          <div className={styles.panelHeader}>
            <div>
              <h2>Chẩn đoán nhanh</h2>
              <p>Các kiểm tra cần thực hiện khi Agent không lên dữ liệu.</p>
            </div>
          </div>
          <div className={styles.keyValueList}>
            <div className={styles.keyValueRow}>
              <span>1. Agent</span>
              <strong>Service chạy và Manager báo active</strong>
            </div>
            <div className={styles.keyValueRow}>
              <span>2. Binding</span>
              <strong>Agent ID ánh xạ đúng CYRP Device</strong>
            </div>
            <div className={styles.keyValueRow}>
              <span>3. Indexer role</span>
              <strong>Được read state indices và alerts</strong>
            </div>
            <div className={styles.keyValueRow}>
              <span>4. Data freshness</span>
              <strong>Syscollector/Vulnerability Detection đã hoàn tất</strong>
            </div>
            <div className={styles.keyValueRow}>
              <span>5. SyncRun</span>
              <strong>Đọc error summary và recordsRejected</strong>
            </div>
          </div>
        </article>
      </section>

      <section className={styles.panel}>
        <div className={styles.panelHeader}>
          <div>
            <h2>Recent pipeline health</h2>
            <p>
              {failedRuns} lần thất bại trong tối đa 12 SyncRun gần nhất. Mở
              trang Đồng bộ dữ liệu để lọc và xem đầy đủ.
            </p>
          </div>
          <Link className={styles.linkButton} href="/sync">
            Mở Sync history
          </Link>
        </div>
        {loading && !data ? (
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
                  <th>Read / Write / Reject</th>
                  <th>Lỗi</th>
                </tr>
              </thead>
              <tbody>
                {(data?.latestRuns ?? []).map((run: SyncRunItem) => (
                  <tr key={run.id}>
                    <td>{formatDateTime(run.startedAt)}</td>
                    <td>
                      <span className={styles.codeText}>{run.sourceType}</span>
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
                        'Global CTI'
                      )}
                    </td>
                    <td>
                      <span
                        className={`${styles.statusPill} ${runTone(run.status)}`}
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
                {!data?.latestRuns.length ? (
                  <tr>
                    <td colSpan={6}>Chưa có lịch sử đồng bộ.</td>
                  </tr>
                ) : null}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {!wazuhEnabled ? (
        <div className={styles.notice}>
          Wazuh đang tắt an toàn. Cấu hình credential service account, TLS và
          kiểm tra kết nối trước khi đặt WAZUH_INTEGRATION_ENABLED=true. Sau đó
          mới bật WAZUH_DATA_SYNC_ENABLED nếu muốn chạy định kỳ.
        </div>
      ) : null}
    </div>
  );
}
