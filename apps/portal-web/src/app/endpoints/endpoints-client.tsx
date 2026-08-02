'use client';

import Link from 'next/link';
import { FormEvent, useCallback, useEffect, useState } from 'react';

import styles from '@/components/security-console.module.css';
import { formatDateTime } from '@/lib/security-format';
import type { AdminDeviceItem, Pagination } from '@/lib/security-data-types';

function statusTone(status: string | null | undefined): string {
  const normalized = status?.toLowerCase();
  if (normalized === 'active' || normalized === 'idle') return styles.statusSuccess;
  if (normalized === 'disconnected' || normalized === 'offline' || normalized === 'error') return styles.statusDanger;
  return styles.statusNeutral;
}

export function EndpointsClient() {
  const [data, setData] = useState<Pagination<AdminDeviceItem> | null>(null);
  const [queryInput, setQueryInput] = useState('');
  const [query, setQuery] = useState('');
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams({ page: String(page), limit: '25' });
      if (query) params.set('query', query);
      const response = await fetch(`/api/admin/devices?${params}`, { cache: 'no-store' });
      const payload = (await response.json()) as Pagination<AdminDeviceItem> & { message?: string };
      if (!response.ok) throw new Error(payload.message ?? 'Không thể tải danh sách thiết bị');
      setData(payload);
      setError('');
    } catch (caught: unknown) {
      setError(caught instanceof Error ? caught.message : 'Không thể tải danh sách thiết bị');
    } finally {
      setLoading(false);
    }
  }, [page, query]);

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
    <div className={styles.page}>
      <header className={styles.pageHeader}>
        <div><p className={styles.eyebrow}>Endpoint inventory</p><h1>Thiết bị</h1><p className={styles.subtitle}>Quản lý Device, chủ sở hữu, Wazuh Agent binding và độ mới của endpoint context.</p></div>
        <span className={`${styles.statusPill} ${styles.statusNeutral}`}>{data?.total ?? 0} thiết bị</span>
      </header>

      <form className={styles.filterRow} onSubmit={submit}>
        <input className={styles.input} value={queryInput} onChange={(event) => setQueryInput(event.target.value)} placeholder="Tìm hostname, OS, email hoặc Agent ID" aria-label="Tìm thiết bị" />
        <button className={styles.primaryButton} type="submit">Tìm kiếm</button>
        <button className={styles.secondaryButton} type="button" onClick={() => void load()} disabled={loading}>Làm mới</button>
      </form>

      {error ? <div className={styles.errorPanel}>{error}</div> : null}

      <section className={styles.panel}>
        <div className={styles.panelHeader}><div><h2>Danh sách endpoint</h2><p>Chọn một endpoint để xem vulnerability, inventory và sync history.</p></div></div>
        {loading && !data ? <div className={styles.loadingSkeleton} /> : (
          <div className={styles.tableWrap}>
            <table className={styles.table}>
              <thead><tr><th>Thiết bị</th><th>Chủ sở hữu</th><th>Wazuh Agent</th><th>Active CVE</th><th>Context</th><th>Last seen</th><th>Trạng thái</th></tr></thead>
              <tbody>
                {(data?.items ?? []).map((device) => (
                  <tr key={device.id}>
                    <td><Link className={styles.linkInline} href={`/endpoints/${device.id}`}><strong>{device.hostname}</strong></Link><span className={styles.secondaryText}>{device.operatingSystem} · {device.architecture ?? '—'}</span></td>
                    <td><span className={styles.primaryText}>{device.user.fullName}</span><span className={styles.secondaryText}>{device.user.email}</span></td>
                    <td><span className={styles.codeText}>{device.wazuhBinding?.wazuhAgentId ?? 'Chưa binding'}</span><span className={styles.secondaryText}>{device.wazuhBinding?.wazuhAgentName ?? '—'}</span></td>
                    <td>{device.activeVulnerabilities}</td>
                    <td>{formatDateTime(device.latestContext?.asOfTime)}</td>
                    <td>{formatDateTime(device.lastSeenAt)}</td>
                    <td><span className={`${styles.statusPill} ${statusTone(device.wazuhBinding?.lastKnownStatus ?? device.status)}`}>{device.wazuhBinding?.lastKnownStatus ?? device.status}</span></td>
                  </tr>
                ))}
                {!data?.items.length ? <tr><td colSpan={7}>Chưa có thiết bị phù hợp.</td></tr> : null}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <div className={styles.pagination}>
        <span>Trang {data?.page ?? page}/{data?.totalPages ?? 1} · {data?.total ?? 0} thiết bị</span>
        <div className={styles.inlineActions}>
          <button className={styles.secondaryButton} type="button" disabled={loading || page <= 1} onClick={() => setPage((value) => Math.max(1, value - 1))}>Trang trước</button>
          <button className={styles.secondaryButton} type="button" disabled={loading || page >= (data?.totalPages ?? 1)} onClick={() => setPage((value) => value + 1)}>Trang sau</button>
        </div>
      </div>
    </div>
  );
}
