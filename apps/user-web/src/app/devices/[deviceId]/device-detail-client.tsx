'use client';

import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { useCallback, useEffect, useMemo, useState } from 'react';

import styles from '@/components/security-console.module.css';
import { formatDateTime, statusLabel, stringifyJson } from '@/lib/security-format';
import type {
  DeviceOverview,
  FullSyncResult,
  Pagination,
  VulnerabilityItem,
} from '@/lib/security-data-types';

function severityClass(severity: string | null): string {
  switch (severity?.toUpperCase()) {
    case 'CRITICAL': return styles.severityCritical;
    case 'HIGH': return styles.severityHigh;
    case 'MEDIUM': return styles.severityMedium;
    case 'LOW': return styles.severityLow;
    default: return styles.severityUnknown;
  }
}

function statusTone(value: string | null | undefined): string {
  const status = value?.toUpperCase();
  if (['ACTIVE', 'IDLE', 'COMPLETED', 'ONLINE'].includes(status ?? '')) return styles.statusSuccess;
  if (['FAILED', 'ERROR', 'OFFLINE'].includes(status ?? '')) return styles.statusDanger;
  if (['PARTIAL', 'SCANNING', 'RUNNING', 'QUEUED'].includes(status ?? '')) return styles.statusWarning;
  return styles.statusNeutral;
}

function previewArray(value: unknown[] | null | undefined, limit = 10): unknown[] {
  return Array.isArray(value) ? value.slice(0, limit) : [];
}

export function DeviceDetailClient({ deviceId }: { deviceId: string }) {
  const router = useRouter();
  const [device, setDevice] = useState<DeviceOverview | null>(null);
  const [vulnerabilities, setVulnerabilities] = useState<Pagination<VulnerabilityItem> | null>(null);
  const [loading, setLoading] = useState(true);
  const [syncing, setSyncing] = useState(false);
  const [error, setError] = useState('');
  const [syncResult, setSyncResult] = useState<FullSyncResult | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [deviceResponse, vulnerabilityResponse] = await Promise.all([
        fetch(`/api/devices/${encodeURIComponent(deviceId)}/overview`, { cache: 'no-store' }),
        fetch(`/api/vulnerabilities?deviceId=${encodeURIComponent(deviceId)}&status=ACTIVE&page=1&limit=20`, { cache: 'no-store' }),
      ]);

      if ([deviceResponse.status, vulnerabilityResponse.status].some((status) => status === 401 || status === 403)) {
        router.replace('/login');
        return;
      }

      const devicePayload = (await deviceResponse.json()) as DeviceOverview & { message?: string };
      const vulnerabilityPayload = (await vulnerabilityResponse.json()) as Pagination<VulnerabilityItem> & { message?: string };

      if (!deviceResponse.ok) throw new Error(devicePayload.message ?? 'Không thể tải thiết bị');
      if (!vulnerabilityResponse.ok) throw new Error(vulnerabilityPayload.message ?? 'Không thể tải lỗ hổng');

      setDevice(devicePayload);
      setVulnerabilities(vulnerabilityPayload);
      setError('');
    } catch (caught: unknown) {
      setError(caught instanceof Error ? caught.message : 'Không thể tải dữ liệu thiết bị');
    } finally {
      setLoading(false);
    }
  }, [deviceId, router]);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      void load();
    }, 0);

    return () => window.clearTimeout(timer);
  }, [load]);

  async function synchronize(): Promise<void> {
    setSyncing(true);
    setError('');
    setSyncResult(null);
    try {
      const response = await fetch(`/api/devices/${encodeURIComponent(deviceId)}/data-sync`, {
        method: 'POST',
      });
      if (response.status === 401 || response.status === 403) {
        router.replace('/login');
        return;
      }
      const payload = (await response.json()) as FullSyncResult & { message?: string };
      if (!response.ok) throw new Error(payload.message ?? 'Không thể đồng bộ dữ liệu Wazuh');
      setSyncResult(payload);
      await load();
    } catch (caught: unknown) {
      setError(caught instanceof Error ? caught.message : 'Không thể đồng bộ dữ liệu Wazuh');
    } finally {
      setSyncing(false);
    }
  }

  const maximumSeverity = useMemo(() => {
    if (!device) return 0;
    return Math.max(1, ...Object.values(device.vulnerabilitySummary.severity));
  }, [device]);

  if (loading && !device) return <div className={styles.loadingSkeleton} />;

  if (!device) {
    return (
      <div className={styles.page}>
        <div className={styles.errorPanel}>{error || 'Không tìm thấy thiết bị.'}</div>
        <Link className={styles.linkButton} href="/devices">Quay lại danh sách</Link>
      </div>
    );
  }

  const context = device.latestContext;

  return (
    <div className={styles.page}>
      <header className={styles.pageHeader}>
        <div>
          <p className={styles.eyebrow}>Endpoint security context</p>
          <h1>{device.hostname}</h1>
          <p className={styles.subtitle}>{device.operatingSystem} · {device.architecture ?? 'Kiến trúc chưa xác định'}</p>
        </div>
        <div className={styles.headerActions}>
          <span className={`${styles.statusPill} ${statusTone(device.wazuhBinding?.lastKnownStatus ?? device.status)}`}>
            {device.wazuhBinding?.lastKnownStatus ?? device.status}
          </span>
          <button className={styles.secondaryButton} type="button" onClick={() => void load()} disabled={loading || syncing}>
            Làm mới
          </button>
          <button className={styles.primaryButton} type="button" onClick={() => void synchronize()} disabled={syncing || !device.wazuhBinding}>
            {syncing ? 'Đang đồng bộ...' : 'Đồng bộ Wazuh'}
          </button>
        </div>
      </header>

      {error ? <div className={styles.errorPanel}>{error}</div> : null}
      {!device.wazuhBinding ? (
        <div className={styles.notice}>Thiết bị chưa có Wazuh Agent binding nên chưa thể đồng bộ vulnerability và endpoint context.</div>
      ) : null}
      {syncResult ? (
        <div className={styles.notice}>
          Lần đồng bộ vừa hoàn tất với trạng thái <strong>{statusLabel(syncResult.status)}</strong>. Mỗi thành phần được ghi riêng trong lịch sử sync để truy vết.
        </div>
      ) : null}

      <section className={styles.metricGrid}>
        <article className={styles.metricCard}><span className={styles.metricLabel}>Active CVE</span><strong className={styles.metricValue}>{device.vulnerabilitySummary.active}</strong><span className={styles.metricHint}>{device.vulnerabilitySummary.resolved} bản ghi đã resolved</span></article>
        <article className={styles.metricCard}><span className={styles.metricLabel}>Listening ports</span><strong className={styles.metricValue}>{context?.listeningPortCount ?? '—'}</strong><span className={styles.metricHint}>Tổng port inventory: {context?.portCount ?? '—'}</span></article>
        <article className={styles.metricCard}><span className={styles.metricLabel}>Packages</span><strong className={styles.metricValue}>{context?.packageCount ?? '—'}</strong><span className={styles.metricHint}>Hotfixes: {context?.hotfixCount ?? '—'}</span></article>
        <article className={styles.metricCard}><span className={styles.metricLabel}>Processes</span><strong className={styles.metricValue}>{context?.processCount ?? '—'}</strong><span className={styles.metricHint}>Services: {context?.serviceCount ?? '—'}</span></article>
      </section>

      <section className={styles.panelGrid}>
        <article className={styles.panel}>
          <div className={styles.panelHeader}>
            <div><h2>Phân bố severity</h2><p>Các vulnerability đang active trên endpoint.</p></div>
            <Link className={styles.linkButton} href={`/vulnerabilities?deviceId=${device.id}`}>Xem tất cả</Link>
          </div>
          <div className={styles.severityStack}>
            {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'].map((severity) => {
              const count = device.vulnerabilitySummary.severity[severity] ?? 0;
              return (
                <div className={styles.severityRow} key={severity}>
                  <span>{severity}</span>
                  <div className={styles.severityTrack}><div className={styles.severityFill} style={{ width: `${(count / maximumSeverity) * 100}%` }} /></div>
                  <strong>{count}</strong>
                </div>
              );
            })}
          </div>
        </article>

        <article className={styles.panel}>
          <div className={styles.panelHeader}><div><h2>Wazuh Agent</h2><p>Binding giữa Device của CYRP và Agent ID.</p></div></div>
          <div className={styles.keyValueList}>
            <div className={styles.keyValueRow}><span>Agent ID</span><strong className={styles.codeText}>{device.wazuhBinding?.wazuhAgentId ?? 'Chưa binding'}</strong></div>
            <div className={styles.keyValueRow}><span>Agent name</span><strong>{device.wazuhBinding?.wazuhAgentName ?? '—'}</strong></div>
            <div className={styles.keyValueRow}><span>Status</span><strong>{device.wazuhBinding?.lastKnownStatus ?? '—'}</strong></div>
            <div className={styles.keyValueRow}><span>Last keep alive</span><strong>{formatDateTime(device.wazuhBinding?.lastKeepAliveAt)}</strong></div>
            <div className={styles.keyValueRow}><span>Last synchronized</span><strong>{formatDateTime(device.wazuhBinding?.lastSynchronizedAt)}</strong></div>
          </div>
        </article>
      </section>

      <section className={styles.panel}>
        <div className={styles.panelHeader}><div><h2>Lỗ hổng ưu tiên</h2><p>Các CVE đang active được sắp theo CVSS và lần nhìn thấy gần nhất.</p></div></div>
        <div className={styles.tableWrap}>
          <table className={styles.table}>
            <thead><tr><th>CVE</th><th>Package</th><th>Severity</th><th>CVSS</th><th>Last seen</th></tr></thead>
            <tbody>
              {(vulnerabilities?.items ?? []).map((item) => (
                <tr key={item.id}>
                  <td><Link className={styles.linkInline} href={`/vulnerabilities/${item.id}`}><strong>{item.cveId}</strong></Link></td>
                  <td><span className={styles.primaryText}>{item.packageName ?? 'Không xác định'}</span><span className={styles.secondaryText}>{item.packageVersion ?? '—'}</span></td>
                  <td><span className={`${styles.severityPill} ${severityClass(item.severity)}`}>{item.severity ?? 'UNKNOWN'}</span></td>
                  <td>{item.cvssBaseScore?.toFixed(1) ?? '—'}</td>
                  <td>{formatDateTime(item.lastSeenAt)}</td>
                </tr>
              ))}
              {!vulnerabilities?.items.length ? <tr><td colSpan={5}>Chưa có vulnerability state được đồng bộ.</td></tr> : null}
            </tbody>
          </table>
        </div>
      </section>

      <section className={styles.panelGridEqual}>
        <article className={styles.panel}>
          <div className={styles.panelHeader}><div><h2>Endpoint context mới nhất</h2><p>Snapshot bất biến theo as-of time.</p></div></div>
          {context ? (
            <div className={styles.keyValueList}>
              <div className={styles.keyValueRow}><span>As-of time</span><strong>{formatDateTime(context.asOfTime)}</strong></div>
              <div className={styles.keyValueRow}><span>Agent IP</span><strong>{context.agentIp ?? '—'}</strong></div>
              <div className={styles.keyValueRow}><span>OS</span><strong>{context.osFull ?? ([context.osName, context.osVersion].filter(Boolean).join(' ') || '—')}</strong></div>
              <div className={styles.keyValueRow}><span>Hardware / architecture</span><strong>{context.architecture ?? device.architecture ?? '—'}</strong></div>
              <div className={styles.keyValueRow}><span>Snapshot completeness</span><strong>{context.completeness ? 'Có metadata' : 'Chưa có'}</strong></div>
            </div>
          ) : <div className={styles.emptyState}>Chưa có endpoint context. Hãy chạy đồng bộ Wazuh.</div>}
        </article>
        <article className={styles.panel}>
          <div className={styles.panelHeader}><div><h2>Alert heuristic hiện tại</h2><p>Đây là snapshot alert cũ, không phải model AI.</p></div></div>
          {device.securitySnapshot ? (
            <div className={styles.keyValueList}>
              <div className={styles.keyValueRow}><span>Alert count</span><strong>{device.securitySnapshot.alertCount}</strong></div>
              <div className={styles.keyValueRow}><span>Critical / High</span><strong>{device.securitySnapshot.criticalCount} / {device.securitySnapshot.highCount}</strong></div>
              <div className={styles.keyValueRow}><span>Heuristic score</span><strong>{device.securitySnapshot.riskScore}</strong></div>
              <div className={styles.keyValueRow}><span>Label</span><strong>{device.securitySnapshot.riskLabel}</strong></div>
              <div className={styles.keyValueRow}><span>Calculated</span><strong>{formatDateTime(device.securitySnapshot.calculatedAt)}</strong></div>
            </div>
          ) : <div className={styles.emptyState}>Chưa có security snapshot.</div>}
        </article>
      </section>

      {context ? (
        <section className={styles.panelGridEqual}>
          <article className={styles.panel}><div className={styles.panelHeader}><div><h2>Port inventory mẫu</h2><p>Tối đa 10 record từ snapshot gần nhất.</p></div></div><pre className={styles.jsonList}>{stringifyJson(previewArray(context.ports))}</pre></article>
          <article className={styles.panel}><div className={styles.panelHeader}><div><h2>Process inventory mẫu</h2><p>Tối đa 10 record từ snapshot gần nhất.</p></div></div><pre className={styles.jsonList}>{stringifyJson(previewArray(context.processes))}</pre></article>
        </section>
      ) : null}

      <section className={styles.panel}>
        <div className={styles.panelHeader}><div><h2>Lịch sử đồng bộ</h2><p>Truy vết từng lần lấy dữ liệu Wazuh theo source type.</p></div></div>
        <div className={styles.timeline}>
          {device.syncRuns.map((run) => (
            <div className={styles.timelineItem} key={run.id}>
              <div><strong>{run.source?.name ?? run.sourceType}</strong><span>{formatDateTime(run.startedAt)} · đọc {run.recordsRead}, ghi {run.recordsWritten}, cập nhật {run.recordsUpdated}</span></div>
              <span className={`${styles.statusPill} ${statusTone(run.status)}`}>{statusLabel(run.status)}</span>
            </div>
          ))}
          {!device.syncRuns.length ? <div className={styles.emptyState}>Chưa có lịch sử đồng bộ dữ liệu Phase 2.</div> : null}
        </div>
      </section>

      <div className={styles.notice}>Endpoint context đang được lưu theo snapshot để giai đoạn sau có thể tạo feature theo device + CVE + as_of_time mà không làm sai dữ liệu lịch sử.</div>
    </div>
  );
}
