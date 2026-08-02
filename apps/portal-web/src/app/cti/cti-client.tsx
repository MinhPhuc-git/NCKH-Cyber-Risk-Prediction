'use client';

import { useCallback, useEffect, useMemo, useState } from 'react';

import styles from '@/components/security-console.module.css';
import type { CtiSourcesResponse } from '@/lib/security-data-types';
import { formatDateTime } from '@/lib/security-format';

function statusTone(status: string): string {
  switch (status) {
    case 'ACTIVE': return styles.statusSuccess;
    case 'READY': return styles.statusWarning;
    case 'ERROR': return styles.statusDanger;
    default: return styles.statusNeutral;
  }
}

async function messageFrom(response: Response): Promise<string> {
  try {
    const payload = (await response.json()) as { message?: string };
    return payload.message ?? `HTTP ${response.status}`;
  } catch {
    return `HTTP ${response.status}`;
  }
}

function sourceStatusLabel(status: string, enabled = true): string {
  if (!enabled) return 'Chưa bật';
  if (status === 'ACTIVE') return 'Đang dùng';
  if (status === 'READY') return 'Sẵn sàng';
  if (status === 'ERROR') return 'Lỗi';
  return status;
}

export function CtiClient() {
  const [data, setData] = useState<CtiSourcesResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [copied, setCopied] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const response = await fetch('/api/admin/cti-sources', { cache: 'no-store' });
      if (!response.ok) throw new Error(await messageFrom(response));
      setData((await response.json()) as CtiSourcesResponse);
      setError('');
    } catch (caught: unknown) {
      setError(caught instanceof Error ? caught.message : 'Không thể tải thống kê dữ liệu');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    const timer = window.setTimeout(() => { void load(); }, 0);
    return () => window.clearTimeout(timer);
  }, [load]);

  const importCommand = 'corepack pnpm@11.9.0 run cti:import:csv -- --file "D:\duong-dan\cve_intelligence_feed.csv"';

  const sourceRows = useMemo(() => {
    const registry = data?.items ?? [];
    const find = (keyword: string) => registry.find((item) => `${item.code} ${item.name} ${item.sourceType}`.toLowerCase().includes(keyword.toLowerCase()));

    return [
      { name: 'NVD', role: 'CVE / CVSS / CWE nền tảng', source: find('NVD') },
      { name: 'CISA KEV', role: 'Known exploited vulnerabilities', source: find('KEV') ?? find('CISA') },
      { name: 'EPSS', role: 'Điểm hỗ trợ xác suất khai thác', source: find('EPSS') },
      { name: 'Exploit-DB', role: 'Bằng chứng exploit / PoC nếu có trong dataset', source: find('EXPLOIT') ?? find('EXPLOITDB') },
      { name: 'Local CSV Feed', role: 'Dữ liệu đã import vào PostgreSQL CYRP', source: find('CSV') ?? find('CTI_CSV') },
      { name: 'Wazuh Vulnerability State', role: 'Lỗ hổng thực tế phát hiện trên endpoint', source: find('WAZUH') },
    ];
  }, [data]);

  async function copyCommand(): Promise<void> {
    try {
      await navigator.clipboard.writeText(importCommand);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1800);
    } catch {
      setCopied(false);
    }
  }

  return (
    <div className={styles.page}>
      <header className={styles.pageHeader}>
        <div>
          <p className={styles.eyebrow}>Threat intelligence foundation</p>
          <h1>Thống kê dữ liệu</h1>
          <p className={styles.subtitle}>Theo dõi dữ liệu CVE, CVSS, CWE và tín hiệu khai thác đang được dùng để làm giàu lỗ hổng và hỗ trợ AI_CYRP prediction.</p>
        </div>
        <button className={styles.secondaryButton} type="button" onClick={() => void load()} disabled={loading}>Làm mới thống kê</button>
      </header>

      {error ? <div className={styles.errorPanel}>{error}</div> : null}

      <section className={styles.metricGrid}>
        <article className={styles.metricCard}><span className={styles.metricLabel}>Tổng CVE</span><strong className={styles.metricValue}>{data?.totals.cves ?? 0}</strong><span className={styles.metricHint}>Bản ghi tri thức lỗ hổng</span></article>
        <article className={styles.metricCard}><span className={styles.metricLabel}>Tổng CVSS metrics</span><strong className={styles.metricValue}>{data?.totals.metrics ?? 0}</strong><span className={styles.metricHint}>Base score, vector và impact metrics</span></article>
        <article className={styles.metricCard}><span className={styles.metricLabel}>Tổng CWE</span><strong className={styles.metricValue}>{data?.totals.cwes ?? 0}</strong><span className={styles.metricHint}>Nhóm điểm yếu liên kết với CVE</span></article>
        <article className={styles.metricCard}><span className={styles.metricLabel}>Threat signals</span><strong className={styles.metricValue}>{data?.totals.signals ?? 0}</strong><span className={styles.metricHint}>EPSS / KEV / exploit evidence hỗ trợ</span></article>
      </section>

      <section className={styles.panelGrid}>
        <article className={styles.panel}>
          <div className={styles.panelHeader}><div><h2>Nguồn dữ liệu đang dùng</h2><p>Các nguồn dùng để xây dựng kho CTI, làm giàu CVE và hỗ trợ mức ưu tiên cuối cùng.</p></div></div>
          <div className={styles.keyValueList}>
            {sourceRows.map((row) => (
              <div className={styles.keyValueRow} key={row.name}>
                <span>{row.name}</span>
                <strong>{row.role} · {row.source ? sourceStatusLabel(row.source.status, row.source.enabled) : 'Chưa có registry'}</strong>
              </div>
            ))}
          </div>
        </article>

        <article className={styles.panel}>
          <div className={styles.panelHeader}><div><h2>Import dữ liệu CTI</h2><p>Import chạy phía server/CLI để tạo SyncRun có provenance và tránh đẩy file lớn qua trình duyệt.</p></div></div>
          <pre className={styles.jsonList}>{importCommand}</pre>
          <div className={styles.inlineActions}><button className={styles.secondaryButton} type="button" onClick={() => void copyCommand()}>{copied ? 'Đã sao chép' : 'Sao chép lệnh'}</button></div>
        </article>
      </section>

      <section className={styles.panel}>
        <div className={styles.panelHeader}><div><h2>Source registry</h2><p>Trạng thái nguồn, lần import thành công gần nhất và lỗi gần nhất.</p></div></div>
        {loading && !data ? <div className={styles.loadingSkeleton} /> : (
          <div className={styles.tableWrap}>
            <table className={styles.table}>
              <thead><tr><th>Nguồn</th><th>Loại</th><th>Trạng thái</th><th>Lần thành công</th><th>Sync gần nhất</th><th>Lỗi gần nhất</th></tr></thead>
              <tbody>
                {(data?.items ?? []).map((source) => {
                  const latestRun = source.syncRuns[0];
                  return (
                    <tr key={source.id}>
                      <td><span className={styles.primaryText}>{source.name}</span><span className={styles.secondaryText}>{source.code} · {source.description ?? 'Không có mô tả'}</span></td>
                      <td><span className={styles.codeText}>{source.sourceType}</span></td>
                      <td><span className={`${styles.statusPill} ${statusTone(source.enabled ? source.status : 'DISABLED')}`}>{sourceStatusLabel(source.status, source.enabled)}</span></td>
                      <td>{formatDateTime(source.lastSuccessAt)}</td>
                      <td>{latestRun ? (<><span className={styles.primaryText}>{latestRun.status}</span><span className={styles.secondaryText}>{formatDateTime(latestRun.startedAt)} · read {latestRun.recordsRead}</span></>) : '--'}</td>
                      <td><span className={styles.secondaryText}>{source.lastError ?? '--'}</span></td>
                    </tr>
                  );
                })}
                {!data?.items.length ? <tr><td colSpan={6}>Chưa có source registry. Hãy chạy db:seed hoặc import CTI.</td></tr> : null}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}
