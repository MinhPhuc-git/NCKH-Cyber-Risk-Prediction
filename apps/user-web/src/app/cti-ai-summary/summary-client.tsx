'use client';

import { useCallback, useEffect, useMemo, useState } from 'react';
import styles from './summary.module.css';

type SummaryResponse = { summary?: Record<string, unknown>; topRecommendations?: Recommendation[]; sourceFile?: string };
type Recommendation = { device: string; cveId: string; packageName: string; installedVersion: string; severity: string; cvssScore: number | null; priority: string; aiRiskScore: number | null; aiRiskLevel: string; aiFinalPriority: string; modelVersion: string; description: string; recommendation: string; references: string[] };


function formatPercent(value: number | null) {
  return value === null || Number.isNaN(value) ? 'N/A' : `${(value * 100).toFixed(2)}%`;
}

function formatDistribution(value: unknown) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return 'Không có dữ liệu';
  return Object.entries(value as Record<string, number>).map(([key, count]) => `${key}: ${count}`).join(' · ');
}

export function CtiAiSummaryClient() {
  const [device, setDevice] = useState('');
  const [data, setData] = useState<SummaryResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const endpoint = useMemo(() => {
    const params = new URLSearchParams();

    params.set('limit', '20');

    if (device.trim()) {
      params.set('device', device.trim());
    }

    return `/api/cti-ai-summary/latest?${params.toString()}`;
  }, [device]);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await fetch(endpoint, { headers: { Accept: 'application/json' } });
      if (!response.ok) throw new Error(`API returned HTTP ${response.status}`);
      setData((await response.json()) as SummaryResponse);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : 'Không tải được dữ liệu CTI AI.');
    } finally {
      setLoading(false);
    }
  }, [endpoint]);

  useEffect(() => { void load(); }, [load]);

  const summary = data?.summary ?? {};
  const rows = data?.topRecommendations ?? [];

  return (
    <main className={styles.page}>
      <section className={styles.header}>
        <div>
          <p className={styles.kicker}>CYRP CTI · XGBoost</p>
          <h1>Tổng quan lỗ hổng và rủi ro AI</h1>
          <p className={styles.description}>Dữ liệu đọc từ pipeline Wazuh Vulnerability Detection, CTI enrichment và model XGBoost đã train.</p>
        </div>
        <button className={styles.refreshButton} disabled={loading} onClick={() => { void load(); }} type="button">{loading ? 'Đang tải...' : 'Tải lại'}</button>
      </section>

      <section className={styles.filterBar}>
        <label>Lọc theo thiết bị<input value={device} onChange={(event) => setDevice(event.target.value)} placeholder="Ví dụ: DESKTOP-RCSLUG6" /></label>
      </section>

      {error ? <section className={styles.errorBox}>{error}</section> : null}

      <section className={styles.cards}>
        <article className={styles.card}><span>Tổng khuyến nghị</span><strong>{String(summary.visibleRecommendations ?? summary.recommendations ?? 0)}</strong></article>
        <article className={styles.card}><span>CVE duy nhất</span><strong>{String(summary.unique_cves ?? 0)}</strong></article>
        <article className={styles.card}><span>Đã chấm AI</span><strong>{String(summary.ai_enriched ?? 0)}</strong></article>
        <article className={styles.card}><span>Model</span><strong>{String(summary.model ?? 'xgboost')}</strong></article>
      </section>

      <section className={styles.distributions}>
        <p><b>AI risk:</b> {formatDistribution(summary.riskLevelDistribution)}</p>
        <p><b>Final priority:</b> {formatDistribution(summary.finalPriorityDistribution)}</p>
        <p><b>Severity:</b> {formatDistribution(summary.severityDistribution)}</p>
      </section>

      <section className={styles.tableSection}>
        <h2>Top CVE cần xử lý</h2>
        <div className={styles.tableWrap}>
          <table className={styles.table}>
            <thead><tr><th>CVE</th><th>Package</th><th>Severity</th><th>CVSS</th><th>AI Risk</th><th>Priority</th><th>Khuyến nghị</th></tr></thead>
            <tbody>
              {rows.map((row, index) => (
                <tr key={`${row.cveId}-${index}`}>
                  <td><strong>{row.cveId}</strong><span>{row.device}</span></td>
                  <td>{row.packageName}<span>{row.installedVersion}</span></td>
                  <td>{row.severity}</td><td>{row.cvssScore ?? 'N/A'}</td>
                  <td><strong>{formatPercent(row.aiRiskScore)}</strong><span>{row.aiRiskLevel}</span></td>
                  <td>{row.aiFinalPriority || row.priority}</td>
                  <td><p>{row.recommendation}</p>{row.references.length ? <a href={row.references[0]} target="_blank" rel="noreferrer">Mở advisory</a> : null}</td>
                </tr>
              ))}
              {!rows.length ? <tr><td colSpan={7}>Chưa có dữ liệu để hiển thị.</td></tr> : null}
            </tbody>
          </table>
        </div>
      </section>
    </main>
  );
}
