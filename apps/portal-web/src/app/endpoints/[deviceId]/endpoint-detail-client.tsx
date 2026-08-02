'use client';

import Link from 'next/link';
import { useCallback, useEffect, useMemo, useState } from 'react';

import styles from '@/components/security-console.module.css';
import { formatDateTime, statusLabel, stringifyJson } from '@/lib/security-format';
import type { AdminDeviceDetail } from '@/lib/security-data-types';

function tone(status: string | null | undefined): string {
  if (['active', 'idle', 'completed'].includes(status?.toLowerCase() ?? '')) return styles.statusSuccess;
  if (['failed', 'error', 'offline', 'disconnected'].includes(status?.toLowerCase() ?? '')) return styles.statusDanger;
  if (['partial', 'running', 'scanning'].includes(status?.toLowerCase() ?? '')) return styles.statusWarning;
  return styles.statusNeutral;
}

export function EndpointDetailClient({ deviceId }: { deviceId: string }) {
  const [device, setDevice] = useState<AdminDeviceDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [syncing, setSyncing] = useState(false);
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const response = await fetch(`/api/admin/devices/${encodeURIComponent(deviceId)}`, { cache: 'no-store' });
      const payload = (await response.json()) as AdminDeviceDetail & { message?: string };
      if (!response.ok) throw new Error(payload.message ?? 'Không thể tải thiết bị');
      setDevice(payload);
      setError('');
    } catch (caught: unknown) {
      setError(caught instanceof Error ? caught.message : 'Không thể tải thiết bị');
    } finally {
      setLoading(false);
    }
  }, [deviceId]);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      void load();
    }, 0);

    return () => window.clearTimeout(timer);
  }, [load]);

  async function sync(): Promise<void> {
    setSyncing(true);
    setError('');
    setMessage('');
    try {
      const response = await fetch(`/api/admin/devices/${encodeURIComponent(deviceId)}/data-sync`, { method: 'POST' });
      const payload = (await response.json()) as { status?: string; message?: string };
      if (!response.ok) throw new Error(payload.message ?? 'Không thể đồng bộ thiết bị');
      setMessage(`Đồng bộ thiết bị hoàn tất với trạng thái ${payload.status ?? 'COMPLETED'}.`);
      await load();
    } catch (caught: unknown) {
      setError(caught instanceof Error ? caught.message : 'Không thể đồng bộ thiết bị');
    } finally {
      setSyncing(false);
    }
  }

  const maxSeverity = useMemo(() => Math.max(1, ...Object.values(device?.vulnerabilitySummary.severity ?? {})), [device]);

  if (loading && !device) return <div className={styles.loadingSkeleton} />;
  if (!device) return <div className={styles.page}><div className={styles.errorPanel}>{error || 'Không tìm thấy thiết bị.'}</div><Link className={styles.linkButton} href="/endpoints">Quay lại</Link></div>;

  const context = device.latestContext;

  return (
    <div className={styles.page}>
      <header className={styles.pageHeader}>
        <div><p className={styles.eyebrow}>Administrative endpoint view</p><h1>{device.hostname}</h1><p className={styles.subtitle}>{device.user.fullName} · {device.user.email} · {device.operatingSystem}</p></div>
        <div className={styles.headerActions}><span className={`${styles.statusPill} ${tone(device.wazuhBinding?.lastKnownStatus ?? device.status)}`}>{device.wazuhBinding?.lastKnownStatus ?? device.status}</span><button className={styles.secondaryButton} type="button" onClick={() => void load()} disabled={loading || syncing}>Làm mới</button><button className={styles.primaryButton} type="button" onClick={() => void sync()} disabled={syncing || !device.wazuhBinding}>{syncing ? 'Đang đồng bộ...' : 'Đồng bộ Agent'}</button></div>
      </header>
      {error ? <div className={styles.errorPanel}>{error}</div> : null}
      {message ? <div className={styles.notice}>{message}</div> : null}
      {!device.wazuhBinding ? <div className={styles.notice}>Endpoint chưa có Wazuh Agent binding.</div> : null}

      <section className={styles.metricGrid}>
        <article className={styles.metricCard}><span className={styles.metricLabel}>Active CVE</span><strong className={styles.metricValue}>{device.vulnerabilitySummary.active}</strong><span className={styles.metricHint}>Theo Wazuh vulnerability state</span></article>
        <article className={styles.metricCard}><span className={styles.metricLabel}>Packages</span><strong className={styles.metricValue}>{context?.packageCount ?? '—'}</strong><span className={styles.metricHint}>{context?.hotfixCount ?? 0} hotfixes</span></article>
        <article className={styles.metricCard}><span className={styles.metricLabel}>Listening ports</span><strong className={styles.metricValue}>{context?.listeningPortCount ?? '—'}</strong><span className={styles.metricHint}>{context?.portCount ?? 0} port records</span></article>
        <article className={styles.metricCard}><span className={styles.metricLabel}>Context snapshots</span><strong className={styles.metricValue}>{device.endpointContextSnapshots.length}</strong><span className={styles.metricHint}>Hiển thị 5 snapshot gần nhất</span></article>
      </section>

      <section className={styles.panelGrid}>
        <article className={styles.panel}>
          <div className={styles.panelHeader}><div><h2>Severity distribution</h2><p>CVE active theo mức độ nghiêm trọng.</p></div><Link className={styles.linkButton} href={`/vulnerabilities?deviceId=${device.id}`}>Lọc CVE</Link></div>
          <div className={styles.severityStack}>{['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'].map((severity) => { const count = device.vulnerabilitySummary.severity[severity] ?? 0; return <div className={styles.severityRow} key={severity}><span>{severity}</span><div className={styles.severityTrack}><div className={styles.severityFill} style={{ width: `${(count / maxSeverity) * 100}%` }} /></div><strong>{count}</strong></div>; })}</div>
        </article>
        <article className={styles.panel}>
          <div className={styles.panelHeader}><div><h2>Agent binding</h2><p>Ánh xạ giữa thiết bị nghiệp vụ và Wazuh.</p></div></div>
          <div className={styles.keyValueList}>
            <div className={styles.keyValueRow}><span>Device ID</span><strong className={styles.codeText}>{device.id}</strong></div>
            <div className={styles.keyValueRow}><span>Agent ID</span><strong className={styles.codeText}>{device.wazuhBinding?.wazuhAgentId ?? '—'}</strong></div>
            <div className={styles.keyValueRow}><span>Agent name</span><strong>{device.wazuhBinding?.wazuhAgentName ?? '—'}</strong></div>
            <div className={styles.keyValueRow}><span>Keep alive</span><strong>{formatDateTime(device.wazuhBinding?.lastKeepAliveAt)}</strong></div>
            <div className={styles.keyValueRow}><span>Last synchronized</span><strong>{formatDateTime(device.wazuhBinding?.lastSynchronizedAt)}</strong></div>
          </div>
        </article>
      </section>

      <section className={styles.panel}>
        <div className={styles.panelHeader}><div><h2>Context snapshots</h2><p>Lịch sử gần nhất phục vụ truy vết theo as-of time.</p></div></div>
        <div className={styles.tableWrap}><table className={styles.table}><thead><tr><th>As-of time</th><th>Agent</th><th>Packages</th><th>Hotfixes</th><th>Ports</th><th>Processes</th><th>Services</th></tr></thead><tbody>{device.endpointContextSnapshots.map((snapshot) => <tr key={snapshot.id}><td>{formatDateTime(snapshot.asOfTime)}</td><td>{snapshot.agentStatus ?? '—'}</td><td>{snapshot.packageCount}</td><td>{snapshot.hotfixCount}</td><td>{snapshot.listeningPortCount}/{snapshot.portCount}</td><td>{snapshot.processCount}</td><td>{snapshot.serviceCount}</td></tr>)}{!device.endpointContextSnapshots.length ? <tr><td colSpan={7}>Chưa có snapshot.</td></tr> : null}</tbody></table></div>
      </section>

      <section className={styles.panelGridEqual}>
        <article className={styles.panel}><div className={styles.panelHeader}><div><h2>Inventory preview</h2><p>Trích mẫu dữ liệu từ snapshot mới nhất.</p></div></div><pre className={styles.jsonList}>{stringifyJson({ packages: context?.packages?.slice(0, 5), ports: context?.ports?.slice(0, 5), hotfixes: context?.hotfixes?.slice(0, 5) })}</pre></article>
        <article className={styles.panel}><div className={styles.panelHeader}><div><h2>Heuristic snapshot</h2><p>Alert summary cũ, chưa phải model AI.</p></div></div>{device.securitySnapshot ? <div className={styles.keyValueList}><div className={styles.keyValueRow}><span>Alerts</span><strong>{device.securitySnapshot.alertCount}</strong></div><div className={styles.keyValueRow}><span>Critical / High</span><strong>{device.securitySnapshot.criticalCount} / {device.securitySnapshot.highCount}</strong></div><div className={styles.keyValueRow}><span>Score / label</span><strong>{device.securitySnapshot.riskScore} · {device.securitySnapshot.riskLabel}</strong></div><div className={styles.keyValueRow}><span>Calculated</span><strong>{formatDateTime(device.securitySnapshot.calculatedAt)}</strong></div></div> : <div className={styles.emptyState}>Chưa có alert snapshot.</div>}</article>
      </section>

      <section className={styles.panel}>
        <div className={styles.panelHeader}><div><h2>Sync history</h2><p>Từng component được lưu thành một run riêng.</p></div></div>
        <div className={styles.timeline}>{device.syncRuns.map((run) => <div className={styles.timelineItem} key={run.id}><div><strong>{run.source?.name ?? run.sourceType}</strong><span>{formatDateTime(run.startedAt)} · R {run.recordsRead} · W {run.recordsWritten} · U {run.recordsUpdated} · X {run.recordsRejected}</span></div><span className={`${styles.statusPill} ${tone(run.status)}`}>{statusLabel(run.status)}</span></div>)}{!device.syncRuns.length ? <div className={styles.emptyState}>Chưa có sync run.</div> : null}</div>
      </section>
    </div>
  );
}
