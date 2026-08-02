'use client';

import Link from 'next/link';
import { useEffect, useMemo, useState } from 'react';

import styles from '@/components/security-console.module.css';

type ApiErrorResponse = {
  message?: string | string[];
  error?: string;
};

type JsonRecord = Record<string, unknown>;

function asRecord(value: unknown): JsonRecord {
  return value !== null && typeof value === 'object' ? (value as JsonRecord) : {};
}

function asArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function getValue(source: unknown, path: string[]): unknown {
  let current: unknown = source;

  for (const key of path) {
    const record = asRecord(current);
    current = record[key];

    if (current === undefined || current === null) {
      return null;
    }
  }

  return current;
}

function getString(source: unknown, paths: string[][]): string | null {
  for (const path of paths) {
    const value = getValue(source, path);

    if (typeof value === 'string' && value.trim()) {
      return value.trim();
    }

    if (typeof value === 'number' && Number.isFinite(value)) {
      return String(value);
    }
  }

  return null;
}

function getNumber(source: unknown, paths: string[][]): number | null {
  for (const path of paths) {
    const value = getValue(source, path);

    if (typeof value === 'number' && Number.isFinite(value)) {
      return value;
    }

    if (typeof value === 'string' && value.trim()) {
      const parsed = Number(value);
      if (Number.isFinite(parsed)) {
        return parsed;
      }
    }
  }

  return null;
}

function getRawPredictionReasonValue(source: unknown, featureName: string): unknown {
  const reasons =
    getValue(source, ['rawPayload', 'rawPrediction', 'Reasons']) ??
    getValue(source, ['raw_payload', 'rawPrediction', 'Reasons']) ??
    getValue(source, ['rawPrediction', 'Reasons']) ??
    getValue(source, ['aiPrediction', 'explanation', 'Reasons']);

  if (!Array.isArray(reasons)) {
    return null;
  }

  const found = reasons.find((item) => {
    const record = asRecord(item);
    return record.feature === featureName;
  });

  return found ? asRecord(found).value : null;
}

function getRawPredictionReasonString(source: unknown, featureName: string): string | null {
  const value = getRawPredictionReasonValue(source, featureName);

  if (typeof value === 'string' && value.trim()) {
    return value.trim();
  }

  if (typeof value === 'number' && Number.isFinite(value)) {
    return String(value);
  }

  return null;
}

function getRawPredictionReasonNumber(source: unknown, featureName: string): number | null {
  const value = getRawPredictionReasonValue(source, featureName);

  if (typeof value === 'number' && Number.isFinite(value)) {
    return value;
  }

  if (typeof value === 'string' && value.trim()) {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : null;
  }

  return null;
}

function getAiCvssReasonValue(source: unknown, featureName: string): unknown {
  const candidates = [
    getValue(source, ['aiPrediction', 'explanation', 'reasons']),
    getValue(source, ['aiPrediction', 'explanation', 'Reasons']),
    getValue(source, ['aiPrediction', 'explanation', 'rawModelOutput', 'Reasons']),
    getValue(source, ['aiPrediction', 'explanation', 'rawModelOutput', 'reasons']),
    getValue(source, ['aiPrediction', 'explanation', 'modelDetails', 'reasons']),
    getValue(source, ['aiPrediction', 'explanation', 'modelDetails', 'rawPrediction', 'Reasons']),
    getValue(source, ['aiPrediction', 'explanation', 'rawPrediction', 'Reasons']),
    getValue(source, ['rawPayload', 'rawPrediction', 'Reasons']),
    getValue(source, ['raw_payload', 'rawPrediction', 'Reasons']),
  ];

  for (const candidate of candidates) {
    if (!Array.isArray(candidate)) {
      continue;
    }

    const found = candidate.find((entry) => {
      const record = asRecord(entry);
      return record.feature === featureName;
    });

    if (found) {
      return asRecord(found).value;
    }
  }

  return null;
}

function getAiCvssReasonString(source: unknown, featureName: string): string | null {
  const value = getAiCvssReasonValue(source, featureName);

  if (typeof value === 'string' && value.trim()) {
    return value.trim();
  }

  if (typeof value === 'number' && Number.isFinite(value)) {
    return String(value);
  }

  return null;
}

function getAiCvssReasonNumber(source: unknown, featureName: string): number | null {
  const value = getAiCvssReasonValue(source, featureName);

  if (typeof value === 'number' && Number.isFinite(value)) {
    return value;
  }

  if (typeof value === 'string' && value.trim()) {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : null;
  }

  return null;
}

function formatDateTime(value: unknown): string {
  if (typeof value !== 'string' || !value.trim()) {
    return '—';
  }

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return '—';
  }

  return new Intl.DateTimeFormat('vi-VN', {
    dateStyle: 'short',
    timeStyle: 'short',
  }).format(date);
}

function formatScore(value: number | null): string {
  if (value === null || Number.isNaN(value) || value < 0) {
    return 'N/A';
  }

  return value.toFixed(1);
}

function formatPercent(value: number | null): string {
  if (value === null || Number.isNaN(value)) {
    return '—';
  }

  const percent = value <= 1 ? value * 100 : value;
  return `${Math.round(percent)}%`;
}

function normalizeRiskLevel(value: string | null): string {
  const level = value?.trim().toUpperCase();

  if (!level) {
    return 'UNKNOWN';
  }

  if (level === 'CAO') {
    return 'HIGH';
  }

  if (level === 'TRUNG BÌNH' || level === 'TRUNG_BINH') {
    return 'MEDIUM';
  }

  if (level === 'THẤP') {
    return 'LOW';
  }

  return level;
}


function riskLevelFromPercentile(value: number | null): string | null {
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    return null;
  }

  const percent = value <= 1 ? value * 100 : value;

  if (percent >= 85) return 'CRITICAL';
  if (percent >= 65) return 'HIGH';
  if (percent >= 45) return 'MEDIUM';
  return 'LOW';
}

function cvssDisplayValue(value: string | null): string | null {
  if (!value) {
    return null;
  }
  const normalized = value.trim();
  if (!normalized || ['UNKNOWN', 'N/A', 'NA', '-1', 'NULL', 'NONE PROVIDED'].includes(normalized.toUpperCase())) {
    return null;
  }
  return normalized;
}

function cvssVectorMetricLabel(vector: string | null, key: string): string | null {
  if (!vector) {
    return null;
  }

  const token = vector.split('/').find((part) => part.startsWith(`${key}:`));
  const code = token?.split(':')[1]?.trim().toUpperCase();

  const maps: Record<string, Record<string, string>> = {
    AV: { N: 'NETWORK', A: 'ADJACENT', L: 'LOCAL', P: 'PHYSICAL' },
    AC: { L: 'LOW', H: 'HIGH' },
    PR: { N: 'NONE', L: 'LOW', H: 'HIGH' },
    UI: { N: 'NONE', R: 'REQUIRED' },
    S: { U: 'UNCHANGED', C: 'CHANGED' },
    C: { H: 'HIGH', L: 'LOW', N: 'NONE' },
    I: { H: 'HIGH', L: 'LOW', N: 'NONE' },
    A: { H: 'HIGH', L: 'LOW', N: 'NONE' },
  };

  return code ? maps[key]?.[code] ?? code : null;
}

function severityClass(value: string | null): string {
  switch (normalizeRiskLevel(value)) {
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

function statusClass(value: string | null): string {
  switch (normalizeRiskLevel(value)) {
    case 'CRITICAL':
    case 'HIGH':
      return styles.statusDanger;
    case 'MEDIUM':
      return styles.statusWarning;
    case 'LOW':
      return styles.statusSuccess;
    default:
      return styles.statusNeutral;
  }
}

function errorMessage(payload: ApiErrorResponse | null, fallback: string): string {
  if (!payload) {
    return fallback;
  }

  if (Array.isArray(payload.message)) {
    return payload.message.join(', ');
  }

  return payload.message ?? payload.error ?? fallback;
}

function getReasonValue(source: unknown, featureName: string): unknown {
  const candidates = [
    getValue(source, ['aiPrediction', 'explanation', 'Reasons']),
    getValue(source, ['aiPrediction', 'explanation', 'reasons']),
    getValue(source, ['rawPayload', 'rawPrediction', 'Reasons']),
    getValue(source, ['raw_payload', 'rawPrediction', 'Reasons']),
    getValue(source, ['rawPrediction', 'Reasons']),
  ];

  for (const candidate of candidates) {
    if (!Array.isArray(candidate)) {
      continue;
    }

    const found = candidate.find((entry) => {
      const record = asRecord(entry);
      return record.feature === featureName;
    });

    if (found) {
      return asRecord(found).value;
    }
  }

  return null;
}

function getReasonString(source: unknown, featureName: string): string | null {
  const value = getReasonValue(source, featureName);

  if (typeof value === 'string' && value.trim()) {
    return value.trim();
  }

  if (typeof value === 'number' && Number.isFinite(value)) {
    return String(value);
  }

  return null;
}

function getReasonNumber(source: unknown, featureName: string): number | null {
  const value = getReasonValue(source, featureName);

  if (typeof value === 'number' && Number.isFinite(value)) {
    return value;
  }

  if (typeof value === 'string' && value.trim()) {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : null;
  }

  return null;
}

function externalLinks(cveId: string, references: unknown[]): Array<{ label: string; url: string; note: string }> {
  const links: Array<{ label: string; url: string; note: string }> = [
    {
      label: 'NVD / Khắc phục',
      url: `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cveId)}`,
      note: 'Mở NVD để xem mô tả, CVSS, reference và hướng khắc phục nếu có.',
    },
    {
      label: 'CVE Record',
      url: `https://www.cve.org/CVERecord?id=${encodeURIComponent(cveId)}`,
      note: 'Bản ghi CVE chính thức để đối chiếu mô tả và nhà cung cấp.',
    },
  ];

  for (const reference of references) {
    const url = getString(reference, [['url'], ['href'], ['link']]);
    const source = getString(reference, [['source'], ['label'], ['name']]) ?? 'Reference';

    if (url && /^https?:\/\//i.test(url) && !links.some((item) => item.url === url)) {
      links.push({
        label: source,
        url,
        note: url,
      });
    }
  }

  return links.slice(0, 6);
}

function KeyValueRow({
  label,
  value,
}: {
  label: string;
  value: string;
}) {
  return (
    <div className={styles.keyValueRow}>
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function MetricCard({
  label,
  value,
  hint,
  className,
}: {
  label: string;
  value: string;
  hint: string;
  className?: string;
}) {
  return (
    <article className={styles.metricCard}>
      <span className={styles.metricLabel}>{label}</span>
      <strong className={`${styles.metricValue} ${className ?? ''}`}>{value}</strong>
      <span className={styles.metricHint}>{hint}</span>
    </article>
  );
}

export function AiPredictionDetailClient({
  vulnerabilityId,
}: {
  vulnerabilityId: string;
}) {
  const [item, setItem] = useState<JsonRecord | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    let cancelled = false;

    async function load() {
      setIsLoading(true);
      setError('');

      try {
        const response = await fetch(`/api/vulnerabilities/${vulnerabilityId}`, {
          cache: 'no-store',
          credentials: 'same-origin',
        });

        const payload = (await response.json().catch(() => null)) as JsonRecord | ApiErrorResponse | null;

        if (!response.ok) {
          throw new Error(errorMessage(payload as ApiErrorResponse | null, 'Không thể tải chi tiết dự đoán AI'));
        }

        if (!cancelled) {
          setItem(payload as JsonRecord);
        }
      } catch (caught: unknown) {
        if (!cancelled) {
          setError(caught instanceof Error ? caught.message : 'Không thể tải chi tiết dự đoán AI');
        }
      } finally {
        if (!cancelled) {
          setIsLoading(false);
        }
      }
    }

    void load();

    return () => {
      cancelled = true;
    };
  }, [vulnerabilityId]);

  const cveId = getString(item, [['cveId']]) ?? 'CVE';
  const hostname = getString(item, [['device', 'hostname']]) ?? 'Không rõ thiết bị';
  const operatingSystem = getString(item, [['device', 'operatingSystem']]) ?? '—';
  const wazuhAgentId =
    getString(item, [
      ['wazuhAgentId'],
      ['device', 'wazuhAgentId'],
      ['wazuhAgentBinding', 'wazuhAgentId'],
      ['device', 'wazuhBinding', 'wazuhAgentId'],
    ]) ?? null;

  const wazuhAgentName =
    getString(item, [
      ['wazuhAgentName'],
      ['device', 'wazuhAgentName'],
      ['wazuhAgentBinding', 'wazuhAgentName'],
      ['device', 'wazuhBinding', 'wazuhAgentName'],
    ]) ?? null;

  const wazuhAgentLabel =
    wazuhAgentName && wazuhAgentId
      ? `${wazuhAgentName} · ID ${wazuhAgentId}`
      : wazuhAgentName ?? wazuhAgentId ?? '—';
  const packageName = getString(item, [['packageName']]) ?? 'Không rõ package';
  const packageVersion = getString(item, [['packageVersion']]) ?? '—';
  const vendorType = getString(item, [['packageVendor'], ['packageType']]) ?? '—';
  const status = getString(item, [['status']]) ?? '—';

  const cvssBaseScore =
    getNumber(item, [
      ['cve', 'cvssMetrics', '0', 'baseScore'],
      ['cvssBaseScore'],
      ['featureVector', 'baseScore'],
      ['aiPrediction', 'explanation', 'rawModelOutput', 'CVSS_base_score'],
    ]) ?? getAiCvssReasonNumber(item, 'CVSS_base_score');

  const cvssVersion =
    getString(item, [
      ['cve', 'cvssMetrics', '0', 'cvssVersion'],
      ['cve', 'cvssMetrics', '0', 'version'],
      ['aiPrediction', 'explanation', 'rawModelOutput', 'CVSS_cvss_version'],
    ]) ?? getAiCvssReasonString(item, 'CVSS_cvss_version') ?? 'N/A';

  const cvssVersionLabel =
    cvssVersion === 'N/A'
      ? 'CVSS version: N/A'
      : `CVSS ${cvssVersion}`;

  const percentile =
    getNumber(item, [
      ['aiPrediction', 'predictedPercentile'],
      ['aiPrediction', 'explanation', 'predictedPercentile'],
      ['aiPrediction', 'explanation', 'predicted_percentile'],
      ['aiPrediction', 'explanation', 'rawModelOutput', 'Percentile'],
    ]);

  const probability =
    getNumber(item, [
      ['aiPrediction', 'attackProbability'],
      ['aiPrediction', 'explanation', 'probability'],
      ['aiPrediction', 'explanation', 'rawModelOutput', 'Probability'],
    ]);

  const riskLevel =
    riskLevelFromPercentile(percentile) ??
    normalizeRiskLevel(getString(item, [['aiPrediction', 'riskLevel']]));
  const modelVersion = getString(item, [['aiPrediction', 'modelVersion']]) ?? '—';
  const predictedAt = getString(item, [['aiPrediction', 'predictedAt']]);

  const description =
    getString(item, [
      ['cve', 'description'],
      ['description'],
      ['aiPrediction', 'explanation', 'remediation', 'cve_description'],
      ['aiPrediction', 'explanation', 'rawModelOutput', 'Remediation', 'cve_description'],
    ]) ?? 'Chưa có mô tả CVE.';

  const cvssVectorString =
    getString(item, [
      ['cvssVector', 'vectorString'],
      ['cve', 'cvssMetrics', '0', 'vectorString'],
    ]);

  const cvssAttackVector = cvssDisplayValue(
    getString(item, [
      ['cvssVector', 'attackVector'],
      ['cve', 'cvssMetrics', '0', 'attackVector'],
      ['featureVector', 'attackVector'],
      ['featureVector', 'rawFeatures', 'attackVector'],
    ]) ?? cvssVectorMetricLabel(cvssVectorString, 'AV') ?? getAiCvssReasonString(item, 'CVSS_attack_vector'),
  ) ?? 'N/A';

  const cvssAttackComplexity = cvssDisplayValue(
    getString(item, [
      ['cvssVector', 'attackComplexity'],
      ['cve', 'cvssMetrics', '0', 'attackComplexity'],
      ['featureVector', 'attackComplexity'],
      ['featureVector', 'rawFeatures', 'attackComplexity'],
    ]) ?? cvssVectorMetricLabel(cvssVectorString, 'AC') ?? getAiCvssReasonString(item, 'CVSS_attack_complexity'),
  ) ?? 'N/A';

  const cvssPrivilegesRequired = cvssDisplayValue(
    getString(item, [
      ['cvssVector', 'privilegesRequired'],
      ['cve', 'cvssMetrics', '0', 'privilegesRequired'],
      ['featureVector', 'privilegesRequired'],
      ['featureVector', 'rawFeatures', 'privilegesRequired'],
    ]) ?? cvssVectorMetricLabel(cvssVectorString, 'PR') ?? getAiCvssReasonString(item, 'CVSS_privileges_required'),
  ) ?? 'N/A';

  const cvssUserInteraction = cvssDisplayValue(
    getString(item, [
      ['cvssVector', 'userInteraction'],
      ['cve', 'cvssMetrics', '0', 'userInteraction'],
      ['featureVector', 'userInteraction'],
      ['featureVector', 'rawFeatures', 'userInteraction'],
    ]) ?? cvssVectorMetricLabel(cvssVectorString, 'UI') ?? getAiCvssReasonString(item, 'CVSS_user_interaction'),
  ) ?? 'N/A';

  const cvssConfidentiality = cvssDisplayValue(
    getString(item, [
      ['cvssVector', 'confidentialityImpact'],
      ['cve', 'cvssMetrics', '0', 'confidentialityImpact'],
      ['featureVector', 'confidentialityImpact'],
      ['featureVector', 'rawFeatures', 'confidentialityImpact'],
    ]) ?? cvssVectorMetricLabel(cvssVectorString, 'C') ?? getAiCvssReasonString(item, 'CVSS_confidentiality'),
  ) ?? 'N/A';

  const cvssIntegrity = cvssDisplayValue(
    getString(item, [
      ['cvssVector', 'integrityImpact'],
      ['cve', 'cvssMetrics', '0', 'integrityImpact'],
      ['featureVector', 'integrityImpact'],
      ['featureVector', 'rawFeatures', 'integrityImpact'],
    ]) ?? cvssVectorMetricLabel(cvssVectorString, 'I') ?? getAiCvssReasonString(item, 'CVSS_integrity'),
  ) ?? 'N/A';

  const cvssAvailability = cvssDisplayValue(
    getString(item, [
      ['cvssVector', 'availabilityImpact'],
      ['cve', 'cvssMetrics', '0', 'availabilityImpact'],
      ['featureVector', 'availabilityImpact'],
      ['featureVector', 'rawFeatures', 'availabilityImpact'],
    ]) ?? cvssVectorMetricLabel(cvssVectorString, 'A') ?? getAiCvssReasonString(item, 'CVSS_availability'),
  ) ?? 'N/A';

  const cvssCia = `${cvssConfidentiality} / ${cvssIntegrity} / ${cvssAvailability}`;

  const firstSeen = getString(item, [['firstSeenAt']]);
  const lastSeen = getString(item, [['lastSeenAt']]);

  const endpoint = asRecord(getValue(item, ['endpointContext']));
  const packagesTotal = getNumber(endpoint, [['packagesTotal'], ['packages']]);
  const hotfixesTotal = getNumber(endpoint, [['hotfixesTotal'], ['hotfixes']]);
  const portsOpen = getNumber(endpoint, [['openListeningPorts'], ['listeningPortsOpen']]);
  const portsTotal = getNumber(endpoint, [['listeningPortsTotal'], ['portsTotal']]);
  const processesTotal = getNumber(endpoint, [['processesTotal'], ['processes']]);
  const servicesTotal = getNumber(endpoint, [['servicesTotal'], ['services']]);
  const agentStatus = getString(endpoint, [['agentStatus']]) ?? '—';

  const references = asArray(getValue(item, ['references']));
  const links = useMemo(() => externalLinks(cveId, references), [cveId, references]);

  const predictionHistory = asArray(getValue(item, ['predictionHistory']));

  if (isLoading && !item) {
    return (
      <div className={styles.page}>
        <section className={styles.panel}>
          <div className={styles.loadingSkeleton} />
        </section>
      </div>
    );
  }

  return (
    <div className={styles.page}>
      <header className={styles.pageHeader}>
        <div>
          <p className={styles.eyebrow}>AI_CYRP prediction detail</p>
          <h1>{cveId}</h1>
          <p>
            Chi tiết dự đoán AI cho <strong>{hostname}</strong>, tách khỏi trang Vulnerable detection.
          </p>
        </div>

        <div className={styles.headerActions}>
          <Link className={styles.secondaryButton} href="/ai-predictions">
            Quay lại AI Predictions
          </Link>
          <a
            className={styles.linkButton}
            href={`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cveId)}`}
            target="_blank"
            rel="noreferrer"
          >
            NVD / Khắc phục
          </a>
          <span className={`${styles.severityPill} ${severityClass(riskLevel)}`}>
            {riskLevel}
          </span>
        </div>
      </header>

      {error ? (
        <div className={styles.errorMessage} role="alert">
          {error}
        </div>
      ) : null}

      <section className={styles.metricGrid}>
        <MetricCard
          label="CVSS base score"
          value={formatScore(cvssBaseScore)}
          hint={cvssVersionLabel}
        />

        <MetricCard
          label="Percentile"
          value={formatPercent(percentile)}
          hint="Percentile AI_CYRP của lỗ hổng này"
        />

        <MetricCard
          label="Attack probability"
          value={formatPercent(probability)}
          hint="Xác suất bị khai thác theo model AI"
        />

        <MetricCard
          label="AI risk level"
          value={riskLevel}
          hint={`Dự đoán lúc ${formatDateTime(predictedAt)}`}
          className={severityClass(riskLevel)}
        />

        <MetricCard
          label="Last seen"
          value={formatDateTime(lastSeen)}
          hint={`First seen: ${formatDateTime(firstSeen)}`}
        />
      </section>

      <section className={styles.panel}>
        <div className={styles.panelHeader}>
          <div>
            <h2>Mô tả CVE</h2>
            <p>Nội dung CTI đã được chuẩn hóa trong cơ sở dữ liệu CYRP.</p>
          </div>
        </div>
        <p className={styles.descriptionText}>{description}</p>
      </section>

      <section className={styles.panelGridEqual}>
        <article className={styles.panel}>
          <div className={styles.panelHeader}>
            <div>
              <h2>Thiết bị và package</h2>
              <p>Đơn vị đánh giá là thiết bị + CVE + package.</p>
            </div>
          </div>
          <div className={styles.keyValueList}>
            <KeyValueRow label="Hostname:" value={hostname} />
            <KeyValueRow label="Operating system:" value={operatingSystem} />
            <KeyValueRow label="Wazuh Agent:" value={wazuhAgentLabel} />
            <KeyValueRow label="Package:" value={packageName} />
            <KeyValueRow label="Version:" value={packageVersion} />
            <KeyValueRow label="Vendor / type:" value={vendorType} />
          </div>
        </article>

        <article className={styles.panel}>
          <div className={styles.panelHeader}>
            <div>
              <h2>Kết quả AI_CYRP</h2>
              <p>Thông số dự đoán chính của model AI.</p>
            </div>
          </div>
          <div className={styles.keyValueList}>
            <KeyValueRow label="Model version" value={modelVersion} />
            <KeyValueRow label="Risk level" value={riskLevel} />
            <KeyValueRow label="Percentile" value={formatPercent(percentile)} />
            <KeyValueRow label="Attack probability" value={formatPercent(probability)} />
            <KeyValueRow label="Predicted at" value={formatDateTime(predictedAt)} />
          </div>
        </article>
      </section>

      <section className={styles.panelGridEqual}>
        <article className={styles.panel}>
          <div className={styles.panelHeader}>
            <div>
              <h2>Đường link khắc phục</h2>
              <p>Các liên kết mở ở tab mới để không đè lên trang CYRP hiện tại.</p>
            </div>
          </div>

          <div className={styles.cardList}>
            {links.map((link) => (
              <article className={styles.referenceCard} key={link.url}>
                <div>
                  <strong>{link.label}</strong>
                  <span>{link.note}</span>
                </div>
                <a className={styles.linkButton} href={link.url} target="_blank" rel="noreferrer">
                  Mở nguồn
                </a>
              </article>
            ))}
          </div>
        </article>

        <article className={styles.panel}>
          <div className={styles.panelHeader}>
            <div>
              <h2>CVSS vector</h2>
              <p>{cvssVectorString || cvssAttackVector !== 'N/A' ? 'Thông số kỹ thuật của metric ưu tiên.' : 'N/A — nguồn hiện tại chưa cung cấp CVSS vector.'}</p>
            </div>
          </div>
          <div className={styles.keyValueList}>
            <KeyValueRow label="Attack vector" value={cvssAttackVector} />
            <KeyValueRow label="Attack complexity" value={cvssAttackComplexity} />
            <KeyValueRow label="Privileges required" value={cvssPrivilegesRequired} />
            <KeyValueRow label="User interaction" value={cvssUserInteraction} />
            <KeyValueRow
              label="C / I / A"
              value={cvssCia}
            />
          </div>
        </article>
      </section>

      <section className={styles.panel}>
        <div className={styles.panelHeader}>
          <div>
            <h2>Lịch sử dự đoán gần nhất</h2>
            <p>Đối chiếu các lần chấm điểm gần nhất của model AI_CYRP.</p>
          </div>
        </div>

        <div className={styles.tableWrap}>
          <table className={styles.table}>
            <thead>
              <tr>
                <th>Thời gian</th>
                <th>Risk level</th>
                <th>Attack probability</th>
                <th>Percentile</th>
                <th>Model</th>
              </tr>
            </thead>
            <tbody>
              {predictionHistory.length ? (
                predictionHistory.map((history, index) => {
                  const historyRisk = normalizeRiskLevel(getString(history, [['riskLevel']]));
                  return (
                    <tr key={`${getString(history, [['id']]) ?? 'history'}-${index}`}>
                      <td>{formatDateTime(getString(history, [['predictedAt']]))}</td>
                      <td>
                        <span className={`${styles.statusPill} ${statusClass(historyRisk)}`}>
                          {historyRisk}
                        </span>
                      </td>
                      <td>{formatPercent(getNumber(history, [['attackProbability']]))}</td>
                      <td>{formatPercent(getNumber(history, [['predictedPercentile']]))}</td>
                      <td>{getString(history, [['modelVersion']]) ?? '—'}</td>
                    </tr>
                  );
                })
              ) : (
                <tr>
                  <td colSpan={5}>Chưa có lịch sử dự đoán.</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
