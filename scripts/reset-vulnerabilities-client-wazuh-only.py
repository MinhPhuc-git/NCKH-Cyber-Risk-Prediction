from pathlib import Path
import shutil
from datetime import datetime

path = Path(r"D:\LuanVan\test\cyrp-platform-phase2\apps\user-web\src\app\vulnerabilities\vulnerabilities-client.tsx")
backup = path.with_suffix(".tsx.bak-full-wazuh-reset-" + datetime.now().strftime("%Y%m%d-%H%M%S"))
shutil.copy2(path, backup)

content = r'''use client';

import { FormEvent, useCallback, useEffect, useState } from 'react';

import styles from '@/components/security-console.module.css';
import type {
  Pagination,
  VulnerabilityItem,
} from '@/lib/security-data-types';

type VulnerabilityRow = VulnerabilityItem & {
  id?: string | null;
  cveId?: string | null;
  cve?: {
    cveId?: string | null;
    description?: string | null;
  } | null;
  device?: {
    hostname?: string | null;
    name?: string | null;
  } | null;
  deviceName?: string | null;
  hostname?: string | null;
  packageName?: string | null;
  packageVersion?: string | null;
  severity?: string | null;
  cvssBaseScore?: number | null;
  status?: string | null;
  sourceStatus?: string | null;
  wazuhRecordTime?: string | null;
  sourceUpdatedAt?: string | null;
  syncSeenAt?: string | null;
  detectedAt?: string | null;
  publishedAt?: string | null;
  firstSeenAt?: string | null;
  lastSeenAt?: string | null;
};

function formatDate(value: string | null | undefined): string {
  if (!value) return '—';

  const date = new Date(value);

  return Number.isNaN(date.getTime())
    ? '—'
    : new Intl.DateTimeFormat('vi-VN', {
        dateStyle: 'short',
        timeStyle: 'short',
      }).format(date);
}

function formatScore(value: number | null | undefined): string {
  if (typeof value !== 'number' || Number.isNaN(value)) {
    return '—';
  }

  return value.toFixed(1);
}

function severityClass(severity: string | null | undefined): string {
  switch (severity?.toUpperCase()) {
    case 'CRITICAL':
      return styles.severityCritical;
    case 'HIGH':
      return styles.severityHigh;
    case 'MEDIUM':
      return styles.severityMedium;
    case 'LOW':
      return styles.severityLow;
    default:
      return styles.severityUnknown;
  }
}

function statusClass(status: string | null | undefined): string {
  const normalized = status?.toUpperCase();

  if (normalized === 'ACTIVE') return styles.statusDanger;
  if (normalized === 'RESOLVED') return styles.statusSuccess;
  if (normalized === 'UNDER_EVALUATION') return styles.statusWarning;

  return styles.statusNeutral;
}

function pickFirstDateString(
  ...values: Array<string | null | undefined>
): string | null {
  for (const value of values) {
    if (typeof value === 'string' && value.trim()) {
      return value;
    }
  }

  return null;
}

function getCveId(row: VulnerabilityRow): string {
  return row.cveId ?? row.cve?.cveId ?? 'UNKNOWN-CVE';
}

function getDeviceName(row: VulnerabilityRow): string {
  return (
    row.deviceName ??
    row.hostname ??
    row.device?.hostname ??
    row.device?.name ??
    'Không rõ thiết bị'
  );
}

function getPackageLabel(row: VulnerabilityRow): string {
  const name = row.packageName ?? 'Không rõ package';
  const version = row.packageVersion;

  return version ? `${name} ${version}` : name;
}

function getWazuhRecordTime(row: VulnerabilityRow): string | null {
  return pickFirstDateString(
    row.wazuhRecordTime,
    row.detectedAt,
    row.sourceUpdatedAt,
    row.publishedAt,
    row.syncSeenAt,
    row.lastSeenAt,
  );
}

export function VulnerabilitiesClient() {
  const [data, setData] = useState<Pagination<VulnerabilityItem> | null>(null);
  const [queryInput, setQueryInput] = useState('');
  const [query, setQuery] = useState('');
  const [severity, setSeverity] = useState('');
  const [status, setStatus] = useState('ACTIVE');
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const load = useCallback(async () => {
    setLoading(true);

    try {
      const params = new URLSearchParams({
        page: String(page),
        limit: '25',
      });

      if (query) params.set('query', query);
      if (severity) params.set('severity', severity);
      if (status) params.set('status', status);

      const response = await fetch(`/api/vulnerabilities?${params.toString()}`, {
        cache: 'no-store',
      });

      const payload = (await response.json()) as Pagination<VulnerabilityItem> & {
        message?: string;
      };

      if (!response.ok) {
        throw new Error(payload.message ?? 'Không thể tải lỗ hổng');
      }

      setData(payload);
      setError('');
    } catch (caught: unknown) {
      setError(
        caught instanceof Error
          ? caught.message
          : 'Không thể tải lỗ hổng',
      );
    } finally {
      setLoading(false);
    }
  }, [page, query, severity, status]);

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

  const items = (data?.items ?? []) as VulnerabilityRow[];
  const canGoNext = items.length >= 25;

  return (
    <div className={styles.page}>
      <header className={styles.pageHeader}>
        <div>
          <p className={styles.eyebrow}>Wazuh vulnerability state</p>
          <h1>Vulnerable detection</h1>
          <p className={styles.subtitle}>
            Danh sách CVE đang được Wazuh ghi nhận trên thiết bị. Trang này chỉ
            hiển thị trạng thái phát hiện lỗ hổng, severity và vòng đời khắc
            phục.
          </p>
        </div>

        <span className={`${styles.statusPill} ${styles.statusNeutral}`}>
          {data?.total ?? 0} bản ghi
        </span>
      </header>

      <form className={styles.filterRow} onSubmit={submit}>
        <input
          className={styles.input}
          value={queryInput}
          onChange={(event) => setQueryInput(event.target.value)}
          placeholder="Tìm theo CVE, package hoặc thiết bị"
          aria-label="Tìm lỗ hổng"
        />

        <select
          className={styles.select}
          value={severity}
          onChange={(event) => {
            setSeverity(event.target.value);
            setPage(1);
          }}
          aria-label="Lọc theo severity"
        >
          <option value="">Mọi severity</option>
          <option value="CRITICAL">Critical</option>
          <option value="HIGH">High</option>
          <option value="MEDIUM">Medium</option>
          <option value="LOW">Low</option>
        </select>

        <select
          className={styles.select}
          value={status}
          onChange={(event) => {
            setStatus(event.target.value);
            setPage(1);
          }}
          aria-label="Lọc theo trạng thái Wazuh"
        >
          <option value="ACTIVE">Active</option>
          <option value="RESOLVED">Resolved</option>
          <option value="UNDER_EVALUATION">Under evaluation</option>
          <option value="">Tất cả trạng thái</option>
        </select>

        <button className={styles.primaryButton} type="submit">
          Tìm kiếm
        </button>
      </form>

      {error ? <div className={styles.errorBanner}>{error}</div> : null}

      <section className={styles.panel}>
        <div className={styles.panelHeader}>
          <div>
            <h2>Kết quả phát hiện từ Wazuh</h2>
            <p>
              CVE active là lỗ hổng còn xuất hiện trong trạng thái Wazuh mới
              nhất. CVE resolved là lỗ hổng không còn xuất hiện sau lần đồng bộ
              hoàn chỉnh.
            </p>
          </div>
        </div>

        {loading && !data ? (
          <div className={styles.loadingSkeleton} />
        ) : (
          <div className={styles.tableWrap}>
            <table className={styles.table}>
              <thead>
                <tr>
                  <th>CVE</th>
                  <th>Thiết bị</th>
                  <th>Package</th>
                  <th>Severity</th>
                  <th>CVSS</th>
                  <th>Trạng thái Wazuh</th>
                  <th>Wazuh time</th>
                  <th>First seen</th>
                  <th>Last seen</th>
                </tr>
              </thead>

              <tbody>
                {items.map((row, index) => (
                  <tr key={row.id ?? `${getCveId(row)}-${index}`}>
                    <td>
                      <strong>{getCveId(row)}</strong>
                    </td>

                    <td>{getDeviceName(row)}</td>

                    <td>{getPackageLabel(row)}</td>

                    <td>
                      <span
                        className={`${styles.statusPill} ${severityClass(row.severity)}`}
                      >
                        {row.severity ?? 'UNKNOWN'}
                      </span>
                    </td>

                    <td>{formatScore(row.cvssBaseScore)}</td>

                    <td>
                      <span
                        className={`${styles.statusPill} ${statusClass(row.status)}`}
                      >
                        {row.status ?? 'UNKNOWN'}
                      </span>
                    </td>

                    <td>{formatDate(getWazuhRecordTime(row))}</td>
                    <td>{formatDate(row.firstSeenAt)}</td>
                    <td>{formatDate(row.lastSeenAt)}</td>
                  </tr>
                ))}

                {!items.length ? (
                  <tr>
                    <td colSpan={9}>Không có dữ liệu phù hợp.</td>
                  </tr>
                ) : null}
              </tbody>
            </table>
          </div>
        )}

        <div className={styles.paginationRow}>
          <button
            className={styles.secondaryButton}
            type="button"
            disabled={page <= 1}
            onClick={() => setPage((current) => Math.max(1, current - 1))}
          >
            Trang trước
          </button>

          <span>Trang {page}</span>

          <button
            className={styles.secondaryButton}
            type="button"
            disabled={!canGoNext}
            onClick={() => setPage((current) => current + 1)}
          >
            Trang sau
          </button>
        </div>
      </section>
    </div>
  );
}
'''

path.write_text(content, encoding="utf-8")

print(f"Reset file: {path}")
print(f"Backup:     {backup}")
