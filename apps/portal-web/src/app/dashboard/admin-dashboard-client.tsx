'use client';

import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { useCallback, useEffect, useMemo, useState } from 'react';

import styles from '@/components/security-console.module.css';
import { formatDateTime, statusLabel } from '@/lib/security-format';
import type { AdminDashboardData } from '@/lib/security-data-types';

function isConnected(value: Record<string, unknown> | { connected: boolean }): boolean {
  if ('connected' in value && typeof value.connected === 'boolean') return value.connected;
  if ('status' in value && typeof value.status === 'string') return ['ok', 'up', 'active', 'connected'].includes(value.status.toLowerCase());
  return false;
}

function runTone(status: string): string {
  if (status === 'COMPLETED') return styles.statusSuccess;
  if (status === 'FAILED') return styles.statusDanger;
  if (status === 'PARTIAL' || status === 'RUNNING') return styles.statusWarning;
  return styles.statusNeutral;
}

export function AdminDashboardClient() {
  const router = useRouter();
  const [data, setData] = useState<AdminDashboardData | null>(null);
  const [loading, setLoading] = useState(true);
  const [syncing, setSyncing] = useState(false);
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const response = await fetch('/api/admin/dashboard', { cache: 'no-store' });
      if (response.status === 401 || response.status === 403) {
        router.replace('/login');
        return;
      }
      const payload = (await response.json()) as AdminDashboardData & { message?: string };
      if (!response.ok) throw new Error(payload.message ?? 'Không thể tải tổng quan Admin');
      setData(payload);
      setError('');
    } catch (caught: unknown) {
      setError(caught instanceof Error ? caught.message : 'Không thể tải tổng quan Admin');
    } finally {
      setLoading(false);
    }
  }, [router]);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      void load();
    }, 0);

    return () => window.clearTimeout(timer);
  }, [load]);

  async function syncAll(): Promise<void> {
    setSyncing(true);
    setError('');
    setMessage('');
    try {
      const response = await fetch('/api/admin/data-sync/all', { method: 'POST' });
      const payload = (await response.json()) as {
        message?: string;
        requested?: number;
        completed?: number;
        partial?: number;
        failed?: number;
      };
      if (!response.ok) {
        throw new Error(
          payload.message ?? 'Không thể chạy đồng bộ toàn hệ thống',
        );
      }
      setMessage(
        `Đã xử lý ${payload.requested ?? 0} thiết bị: ${
          payload.completed ?? 0
        } hoàn tất, ${payload.partial ?? 0} một phần, ${
          payload.failed ?? 0
        } thất bại.`,
      );
      await load();
    } catch (caught: unknown) {
      setError(caught instanceof Error ? caught.message : 'Không thể chạy đồng bộ toàn hệ thống');
    } finally {
      setSyncing(false);
    }
  }

  const maxSeverity = useMemo(() => Math.max(1, ...Object.values(data?.vulnerabilities.severity ?? {})), [data]);
  const databaseConnected = data ? isConnected(data.services.database) : false;
  const wazuhConnected = data ? isConnected(data.services.wazuhApi) : false;
  const indexerConnected = data ? isConnected(data.services.indexer) : false;

  return (
    <div className={styles.page}>
      <header className={styles.pageHeader}>
        <div>
          <p className={styles.eyebrow}>Security operations overview</p>
          <h1>Tổng quan hệ thống</h1>
          <p className={styles.subtitle}>Theo dõi người dùng, endpoint, Wazuh, CTI và tiến trình đồng bộ dữ liệu Phase 2.</p>
        </div>
        <div className={styles.headerActions}>
          <button className={styles.secondaryButton} type="button" onClick={() => void load()} disabled={loading || syncing}>Làm mới</button>
          <button className={styles.primaryButton} type="button" onClick={() => void syncAll()} disabled={syncing || !data?.bindings}>
            {syncing ? 'Đang đồng bộ...' : 'Đồng bộ tất cả'}
          </button>
        </div>
      </header>

      {error ? <div className={styles.errorPanel}>{error}</div> : null}
      {message ? <div className={styles.notice}>{message}</div> : null}
      {loading && !data ? <div className={styles.loadingSkeleton} /> : null}

      {data ? (
        <>
          <section className={styles.metricGrid}>
            <article className={styles.metricCard}><span className={styles.metricLabel}>Người dùng</span><strong className={styles.metricValue}>{data.users}</strong><span className={styles.metricHint}>Tài khoản trong PostgreSQL</span></article>
            <article className={styles.metricCard}><span className={styles.metricLabel}>Thiết bị / Agent</span><strong className={styles.metricValue}>{data.devices}</strong><span className={styles.metricHint}>{data.bindings} Wazuh binding</span></article>
            <article className={styles.metricCard}><span className={styles.metricLabel}>Active CVE</span><strong className={styles.metricValue}>{data.vulnerabilities.active}</strong><span className={styles.metricHint}>{(data.vulnerabilities.severity.CRITICAL ?? 0) + (data.vulnerabilities.severity.HIGH ?? 0)} Critical/High</span></article>
            <article className={styles.metricCard}><span className={styles.metricLabel}>CTI / Context</span><strong className={styles.metricValue}>{data.dataFoundation.cves}</strong><span className={styles.metricHint}>{data.dataFoundation.endpointContextSnapshots} context snapshots</span></article>
          </section>

          <section className={styles.panelGrid}>
            <article className={styles.panel}>
              <div className={styles.panelHeader}><div><h2>Phân bố vulnerability severity</h2><p>Dữ liệu active từ Wazuh vulnerability state index.</p></div><Link className={styles.linkButton} href="/vulnerabilities">Mở danh sách</Link></div>
              <div className={styles.severityStack}>
                {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'].map((severity) => {
                  const count = data.vulnerabilities.severity[severity] ?? 0;
                  return <div className={styles.severityRow} key={severity}><span>{severity}</span><div className={styles.severityTrack}><div className={styles.severityFill} style={{ width: `${(count / maxSeverity) * 100}%` }} /></div><strong>{count}</strong></div>;
                })}
              </div>
            </article>

            <article className={styles.panel}>
              <div className={styles.panelHeader}><div><h2>Sức khỏe dịch vụ</h2><p>Kiểm tra trực tiếp DB, Wazuh API và Indexer.</p></div><Link className={styles.linkButton} href="/system">Chi tiết</Link></div>
              <div className={styles.keyValueList}>
                <div className={styles.keyValueRow}><span>PostgreSQL</span><strong className={databaseConnected ? styles.statusSuccess : styles.statusDanger}>{databaseConnected ? 'Connected' : 'Unavailable'}</strong></div>
                <div className={styles.keyValueRow}><span>Wazuh Manager API</span><strong className={wazuhConnected ? styles.statusSuccess : styles.statusDanger}>{wazuhConnected ? 'Connected' : 'Disabled / unavailable'}</strong></div>
                <div className={styles.keyValueRow}><span>Wazuh Indexer</span><strong className={indexerConnected ? styles.statusSuccess : styles.statusDanger}>{indexerConnected ? 'Connected' : 'Disabled / unavailable'}</strong></div>
                <div className={styles.keyValueRow}><span>Sync running / failed</span><strong>{data.sync.running} / {data.sync.failed}</strong></div>
              </div>
            </article>
          </section>

          <section className={styles.panelGridEqual}>
            <article className={styles.panel}>
              <div className={styles.panelHeader}><div><h2>Nguồn dữ liệu</h2><p>Trạng thái các nguồn CTI và Wazuh đã đăng ký.</p></div><Link className={styles.linkButton} href="/cti">Nguồn CTI</Link></div>
              <div className={styles.cardList}>
                {data.sources.map((source) => (
                  <div className={styles.listCard} key={source.id}>
                    <div><strong>{source.name}</strong><p>{source.code} · success {formatDateTime(source.lastSuccessAt)}</p></div>
                    <span className={`${styles.statusPill} ${source.status === 'ERROR' ? styles.statusDanger : source.enabled ? styles.statusSuccess : styles.statusNeutral}`}>{source.enabled ? statusLabel(source.status) : 'Đã tắt'}</span>
                  </div>
                ))}
                {!data.sources.length ? <div className={styles.emptyState}>Chưa seed nguồn dữ liệu.</div> : null}
              </div>
            </article>

            <article className={styles.panel}>
              <div className={styles.panelHeader}><div><h2>Data foundation</h2><p>Phần đã triển khai, không bao gồm model AI.</p></div></div>
              <div className={styles.keyValueList}>
                <div className={styles.keyValueRow}><span>CVE records</span><strong>{data.dataFoundation.cves}</strong></div>
                <div className={styles.keyValueRow}><span>Endpoint context snapshots</span><strong>{data.dataFoundation.endpointContextSnapshots}</strong></div>
                <div className={styles.keyValueRow}><span>Active detected vulnerabilities</span><strong>{data.vulnerabilities.active}</strong></div>
                <div className={styles.keyValueRow}><span>Model AI</span><strong>Chưa tích hợp</strong></div>
              </div>
            </article>
          </section>

          <section className={styles.panel}>
            <div className={styles.panelHeader}><div><h2>Sync run gần đây</h2><p>Truy vết ETL và Wazuh state synchronization.</p></div><Link className={styles.linkButton} href="/sync">Xem tất cả</Link></div>
            <div className={styles.tableWrap}>
              <table className={styles.table}>
                <thead><tr><th>Thời gian</th><th>Thiết bị</th><th>Nguồn</th><th>Records</th><th>Trạng thái</th></tr></thead>
                <tbody>
                  {data.sync.recent.map((run) => (
                    <tr key={run.id}><td>{formatDateTime(run.startedAt)}</td><td>{run.device ? <Link className={styles.linkInline} href={`/endpoints/${run.device.id}`}>{run.device.hostname}</Link> : 'Toàn hệ thống'}</td><td>{run.source?.name ?? run.sourceType}</td><td>R {run.recordsRead} · W {run.recordsWritten} · U {run.recordsUpdated}</td><td><span className={`${styles.statusPill} ${runTone(run.status)}`}>{statusLabel(run.status)}</span></td></tr>
                  ))}
                  {!data.sync.recent.length ? <tr><td colSpan={5}>Chưa có sync run.</td></tr> : null}
                </tbody>
              </table>
            </div>
          </section>

          <div className={styles.notice}>Phase 2 hoàn thiện lớp dữ liệu và giao diện vận hành. Mọi điểm số từ security snapshot hiện tại chỉ là Wazuh heuristic, không phải kết quả model AI.</div>
        </>
      ) : null}
    </div>
  );
}
