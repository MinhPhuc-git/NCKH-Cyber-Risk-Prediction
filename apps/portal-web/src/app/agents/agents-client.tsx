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
  AdminDeviceItem,
  Pagination,
  WazuhAgentItem,
  WazuhAgentsResponse,
  WazuhStatusResponse,
} from '@/lib/security-data-types';
import { formatDateTime } from '@/lib/security-format';

interface BindingItem {
  id: string;
  deviceId: string;
  wazuhAgentId: string;
  wazuhAgentName: string;
  lastKnownStatus: string | null;
  lastKeepAliveAt: string | null;
  lastSynchronizedAt: string;
  lastStatusCheckedAt: string | null;
  lastStatusError: string | null;
  consecutiveStatusFailures: number;
  createdAt: string;
  updatedAt: string;
  device: {
    id: string;
    hostname: string;
    operatingSystem: string;
    status: string;
    user: { id: string; email: string; fullName: string };
  };
}

interface ErrorPayload {
  message?: string;
  detail?: string;
}

function statusTone(status: string | null | undefined): string {
  const normalized = status?.toLowerCase();

  if (normalized === 'active') {
    return styles.statusSuccess;
  }

  if (
    normalized &&
    ['disconnected', 'never_connected', 'pending'].includes(normalized)
  ) {
    return styles.statusDanger;
  }

  return styles.statusNeutral;
}

async function responseMessage(response: Response): Promise<string> {
  try {
    const payload = (await response.json()) as ErrorPayload;
    return payload.message ?? payload.detail ?? `HTTP ${response.status}`;
  } catch {
    return `HTTP ${response.status}`;
  }
}

export function AgentsClient() {
  const [bindings, setBindings] = useState<BindingItem[]>([]);
  const [agents, setAgents] = useState<WazuhAgentItem[]>([]);
  const [devices, setDevices] = useState<AdminDeviceItem[]>([]);
  const [wazuhStatus, setWazuhStatus] =
    useState<WazuhStatusResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [actionBusy, setActionBusy] = useState(false);
  const [error, setError] = useState('');
  const [liveError, setLiveError] = useState('');
  const [notice, setNotice] = useState('');
  const [selectedAgentId, setSelectedAgentId] = useState('');
  const [selectedDeviceId, setSelectedDeviceId] = useState('');

  const load = useCallback(async () => {
    setLoading(true);
    setError('');
    setLiveError('');

    const [bindingsResult, devicesResult, agentsResult, statusResult] =
      await Promise.allSettled([
        fetch('/api/admin/wazuh-bindings', { cache: 'no-store' }),
        fetch('/api/admin/devices?limit=100', { cache: 'no-store' }),
        fetch('/api/admin/wazuh-agents?limit=100', { cache: 'no-store' }),
        fetch('/api/admin/wazuh-status', { cache: 'no-store' }),
      ]);

    try {
      if (bindingsResult.status !== 'fulfilled') {
        throw bindingsResult.reason;
      }
      if (!bindingsResult.value.ok) {
        throw new Error(await responseMessage(bindingsResult.value));
      }
      const payload = (await bindingsResult.value.json()) as BindingItem[];
      setBindings(Array.isArray(payload) ? payload : []);
    } catch (caught: unknown) {
      setError(
        caught instanceof Error
          ? caught.message
          : 'Không thể tải Wazuh Agent bindings',
      );
    }

    try {
      if (devicesResult.status !== 'fulfilled') {
        throw devicesResult.reason;
      }
      if (!devicesResult.value.ok) {
        throw new Error(await responseMessage(devicesResult.value));
      }
      const payload =
        (await devicesResult.value.json()) as Pagination<AdminDeviceItem>;
      setDevices(payload.items ?? []);
    } catch (caught: unknown) {
      setError((current) =>
        current ||
        (caught instanceof Error
          ? caught.message
          : 'Không thể tải danh sách endpoint'),
      );
    }

    try {
      if (statusResult.status !== 'fulfilled') {
        throw statusResult.reason;
      }
      if (!statusResult.value.ok) {
        throw new Error(await responseMessage(statusResult.value));
      }
      setWazuhStatus(
        (await statusResult.value.json()) as WazuhStatusResponse,
      );
    } catch (caught: unknown) {
      setWazuhStatus(null);
      setLiveError(
        caught instanceof Error
          ? caught.message
          : 'Không thể kiểm tra Wazuh Manager',
      );
    }

    try {
      if (agentsResult.status !== 'fulfilled') {
        throw agentsResult.reason;
      }
      if (!agentsResult.value.ok) {
        throw new Error(await responseMessage(agentsResult.value));
      }
      const payload =
        (await agentsResult.value.json()) as WazuhAgentsResponse;
      setAgents(payload.items ?? []);
    } catch (caught: unknown) {
      setAgents([]);
      setLiveError((current) =>
        current ||
        (caught instanceof Error
          ? caught.message
          : 'Không thể đọc live Agent inventory'),
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

  const bindingByAgentId = useMemo(
    () => new Map(bindings.map((item) => [item.wazuhAgentId, item])),
    [bindings],
  );
  const bindingByDeviceId = useMemo(
    () => new Map(bindings.map((item) => [item.deviceId, item])),
    [bindings],
  );
  const endpointAgents = useMemo(
    () => agents.filter((agent) => agent.id && agent.id !== '000'),
    [agents],
  );
  const unboundAgents = useMemo(
    () =>
      endpointAgents.filter(
        (agent) => agent.id && !bindingByAgentId.has(agent.id),
      ),
    [bindingByAgentId, endpointAgents],
  );
  const unboundDevices = useMemo(
    () => devices.filter((device) => !bindingByDeviceId.has(device.id)),
    [bindingByDeviceId, devices],
  );
  const activeAgents = endpointAgents.filter(
    (agent) => agent.status?.toLowerCase() === 'active',
  ).length;
  const staleBindings = bindings.filter((item) => {
    const lastChecked = item.lastStatusCheckedAt ?? item.lastSynchronizedAt;
    return Date.now() - new Date(lastChecked).getTime() > 86_400_000;
  }).length;
  const failingBindings = bindings.filter(
    (item) => item.consecutiveStatusFailures > 0,
  ).length;

  async function refreshStatuses(deviceId?: string): Promise<void> {
    setActionBusy(true);
    setNotice('');

    try {
      const path = deviceId
        ? `/api/admin/wazuh-bindings/${encodeURIComponent(deviceId)}/status-refresh`
        : '/api/admin/wazuh-bindings/status-refresh';
      const response = await fetch(path, { method: 'POST' });

      if (!response.ok) {
        throw new Error(await responseMessage(response));
      }

      setNotice(
        deviceId
          ? 'Đã làm mới trạng thái Agent của endpoint.'
          : 'Đã làm mới trạng thái của các Agent đã binding.',
      );
      await load();
    } catch (caught: unknown) {
      setNotice(
        caught instanceof Error
          ? caught.message
          : 'Không thể làm mới trạng thái Wazuh Agent',
      );
    } finally {
      setActionBusy(false);
    }
  }

  async function createBinding(): Promise<void> {
    if (!selectedAgentId || !selectedDeviceId) {
      setNotice('Hãy chọn cả Wazuh Agent và CYRP Device.');
      return;
    }

    setActionBusy(true);
    setNotice('');

    try {
      const response = await fetch('/api/admin/wazuh-bindings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          wazuhAgentId: selectedAgentId,
          deviceId: selectedDeviceId,
        }),
      });

      if (!response.ok) {
        throw new Error(await responseMessage(response));
      }

      setSelectedAgentId('');
      setSelectedDeviceId('');
      setNotice('Đã liên kết Wazuh Agent với CYRP Device.');
      await load();
    } catch (caught: unknown) {
      setNotice(
        caught instanceof Error
          ? caught.message
          : 'Không thể tạo binding',
      );
    } finally {
      setActionBusy(false);
    }
  }

  async function removeBinding(binding: BindingItem): Promise<void> {
    const confirmed = window.confirm(
      `Gỡ liên kết Agent ${binding.wazuhAgentId} khỏi ${binding.device.hostname}? Agent vẫn được giữ trên Wazuh Manager.`,
    );

    if (!confirmed) {
      return;
    }

    setActionBusy(true);
    setNotice('');

    try {
      const response = await fetch(
        `/api/admin/wazuh-bindings/${encodeURIComponent(binding.deviceId)}`,
        { method: 'DELETE' },
      );

      if (!response.ok) {
        throw new Error(await responseMessage(response));
      }

      setNotice('Đã gỡ binding; Wazuh Agent không bị xóa.');
      await load();
    } catch (caught: unknown) {
      setNotice(
        caught instanceof Error
          ? caught.message
          : 'Không thể gỡ binding',
      );
    } finally {
      setActionBusy(false);
    }
  }

  return (
    <div className={styles.page}>
      <header className={styles.pageHeader}>
        <div>
          <p className={styles.eyebrow}>Wazuh Manager inventory</p>
          <h1>Wazuh Agents</h1>
          <p className={styles.subtitle}>
            Đối chiếu live Agent inventory từ Wazuh Manager với binding trong
            CYRP, theo dõi keep-alive và liên kết endpoint chưa được ánh xạ.
          </p>
        </div>
        <div className={styles.headerActions}>
          <button
            className={styles.primaryButton}
            type="button"
            onClick={() => void refreshStatuses()}
            disabled={loading || actionBusy || !bindings.length}
          >
            Đồng bộ trạng thái Agent
          </button>
          <button
            className={styles.secondaryButton}
            type="button"
            onClick={() => void load()}
            disabled={loading || actionBusy}
          >
            Tải lại dữ liệu
          </button>
        </div>
      </header>

      {error ? <div className={styles.errorPanel}>{error}</div> : null}
      {liveError ? (
        <div className={styles.notice}>
          Live Wazuh chưa sẵn sàng: {liveError}. Dữ liệu binding trong PostgreSQL
          vẫn được hiển thị để quản trị viên kiểm tra.
        </div>
      ) : null}
      {notice ? <div className={styles.notice}>{notice}</div> : null}

      <section className={styles.metricGrid}>
        <article className={styles.metricCard}>
          <span className={styles.metricLabel}>Wazuh Manager</span>
          <strong className={styles.metricValue}>
            {wazuhStatus?.connected ? 'Online' : 'Offline'}
          </strong>
          <span className={styles.metricHint}>
            {wazuhStatus?.manager?.name ?? 'Chưa xác định manager'}
            {wazuhStatus?.manager?.version
              ? ` · ${wazuhStatus.manager.version}`
              : ''}
          </span>
        </article>
        <article className={styles.metricCard}>
          <span className={styles.metricLabel}>Endpoint Agents</span>
          <strong className={styles.metricValue}>{endpointAgents.length}</strong>
          <span className={styles.metricHint}>{activeAgents} đang active</span>
        </article>
        <article className={styles.metricCard}>
          <span className={styles.metricLabel}>Bindings</span>
          <strong className={styles.metricValue}>{bindings.length}</strong>
          <span className={styles.metricHint}>
            {unboundAgents.length} Agent chưa ánh xạ
          </span>
        </article>
        <article className={styles.metricCard}>
          <span className={styles.metricLabel}>Stale binding</span>
          <strong className={styles.metricValue}>{staleBindings}</strong>
          <span className={styles.metricHint}>
            Quá 24 giờ chưa kiểm tra · {failingBindings} binding đang lỗi
          </span>
        </article>
      </section>

      <section className={styles.panelGrid}>
        <article className={styles.panel}>
          <div className={styles.panelHeader}>
            <div>
              <h2>Tạo Device ↔ Agent binding</h2>
              <p>
                Chỉ Agent không phải Manager 000 và Device chưa binding mới được
                liệt kê. Binding không truyền Wazuh credential xuống trình duyệt.
              </p>
            </div>
          </div>
          <div className={styles.filterRow}>
            <label>
              <span className={styles.label}>Wazuh Agent</span>
              <select
                className={styles.select}
                value={selectedAgentId}
                onChange={(event) => setSelectedAgentId(event.target.value)}
                disabled={actionBusy || !unboundAgents.length}
              >
                <option value="">Chọn Agent chưa binding</option>
                {unboundAgents.map((agent) => (
                  <option key={agent.id} value={agent.id}>
                    {agent.id} · {agent.name ?? 'Unnamed'} ·{' '}
                    {agent.status ?? 'unknown'}
                  </option>
                ))}
              </select>
            </label>
            <label>
              <span className={styles.label}>CYRP Device</span>
              <select
                className={styles.select}
                value={selectedDeviceId}
                onChange={(event) => setSelectedDeviceId(event.target.value)}
                disabled={actionBusy || !unboundDevices.length}
              >
                <option value="">Chọn Device chưa binding</option>
                {unboundDevices.map((device) => (
                  <option key={device.id} value={device.id}>
                    {device.hostname} · {device.user.email}
                  </option>
                ))}
              </select>
            </label>
            <button
              className={styles.primaryButton}
              type="button"
              disabled={
                actionBusy || !selectedAgentId || !selectedDeviceId
              }
              onClick={() => void createBinding()}
            >
              Tạo binding
            </button>
          </div>
        </article>

        <article className={styles.panel}>
          <div className={styles.panelHeader}>
            <div>
              <h2>Điều kiện Agent hoạt động đúng</h2>
              <p>Kiểm tra theo từng lớp thay vì chỉ nhìn một trạng thái.</p>
            </div>
          </div>
          <div className={styles.keyValueList}>
            <div className={styles.keyValueRow}>
              <span>Enrollment</span>
              <strong>Agent có ID và client key hợp lệ</strong>
            </div>
            <div className={styles.keyValueRow}>
              <span>Manager</span>
              <strong>Agent status = active, keep-alive còn mới</strong>
            </div>
            <div className={styles.keyValueRow}>
              <span>CYRP</span>
              <strong>Agent ID được binding đúng Device/owner</strong>
            </div>
            <div className={styles.keyValueRow}>
              <span>Indexer</span>
              <strong>Trả được vulnerability và inventory state</strong>
            </div>
          </div>
        </article>
      </section>

      <section className={styles.panel}>
        <div className={styles.panelHeader}>
          <div>
            <h2>Live Agent inventory</h2>
            <p>
              Trạng thái hiện tại từ Wazuh Manager; Agent 000 được loại khỏi chỉ
              số endpoint và không thể binding.
            </p>
          </div>
        </div>
        {loading && !agents.length ? (
          <div className={styles.loadingSkeleton} />
        ) : (
          <div className={styles.tableWrap}>
            <table className={styles.table}>
              <thead>
                <tr>
                  <th>Agent</th>
                  <th>Hệ điều hành</th>
                  <th>IP / Node</th>
                  <th>Trạng thái</th>
                  <th>Keep alive</th>
                  <th>CYRP binding</th>
                </tr>
              </thead>
              <tbody>
                {agents.map((agent, index) => {
                  const binding = agent.id
                    ? bindingByAgentId.get(agent.id)
                    : undefined;
                  return (
                    <tr key={agent.id ?? `${agent.name}-${index}`}>
                      <td>
                        <span className={styles.codeText}>
                          {agent.id ?? '--'}
                        </span>
                        <span className={styles.secondaryText}>
                          {agent.name ?? 'Không có tên'} ·{' '}
                          {agent.version ?? 'unknown version'}
                        </span>
                      </td>
                      <td>
                        <span className={styles.primaryText}>
                          {agent.os?.name ?? agent.os?.platform ?? 'Chưa xác định'}
                        </span>
                        <span className={styles.secondaryText}>
                          {[agent.os?.version, agent.os?.arch]
                            .filter(Boolean)
                            .join(' · ') || '--'}
                        </span>
                      </td>
                      <td>
                        <span className={styles.primaryText}>
                          {agent.ip ?? '--'}
                        </span>
                        <span className={styles.secondaryText}>
                          {agent.node_name ?? '--'}
                        </span>
                      </td>
                      <td>
                        <span
                          className={`${styles.statusPill} ${statusTone(agent.status)}`}
                        >
                          {agent.status ?? 'UNKNOWN'}
                        </span>
                      </td>
                      <td>{formatDateTime(agent.lastKeepAlive ?? null)}</td>
                      <td>
                        {agent.id === '000' ? (
                          <span className={styles.secondaryText}>Manager node</span>
                        ) : binding ? (
                          <>
                            <Link
                              className={styles.linkInline}
                              href={`/endpoints/${binding.device.id}`}
                            >
                              {binding.device.hostname}
                            </Link>
                            <span className={styles.secondaryText}>
                              {binding.device.user.email}
                            </span>
                          </>
                        ) : (
                          <span
                            className={`${styles.statusPill} ${styles.statusWarning}`}
                          >
                            CHƯA BINDING
                          </span>
                        )}
                      </td>
                    </tr>
                  );
                })}
                {!agents.length ? (
                  <tr>
                    <td colSpan={6}>Không có live Agent inventory.</td>
                  </tr>
                ) : null}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <section className={styles.panel}>
        <div className={styles.panelHeader}>
          <div>
            <h2>CYRP Agent bindings</h2>
            <p>
              Metadata PostgreSQL dùng để xác định dữ liệu Wazuh thuộc endpoint
              và người dùng nào.
            </p>
          </div>
        </div>
        {loading && !bindings.length ? (
          <div className={styles.loadingSkeleton} />
        ) : (
          <div className={styles.tableWrap}>
            <table className={styles.table}>
              <thead>
                <tr>
                  <th>Agent</th>
                  <th>Endpoint</th>
                  <th>Owner</th>
                  <th>Status lưu gần nhất</th>
                  <th>Runtime check</th>
                  <th>Last data sync</th>
                  <th>Thao tác</th>
                </tr>
              </thead>
              <tbody>
                {bindings.map((binding) => (
                  <tr key={binding.id}>
                    <td>
                      <span className={styles.codeText}>
                        {binding.wazuhAgentId}
                      </span>
                      <span className={styles.secondaryText}>
                        {binding.wazuhAgentName}
                      </span>
                    </td>
                    <td>
                      <Link
                        className={styles.linkInline}
                        href={`/endpoints/${binding.device.id}`}
                      >
                        <strong>{binding.device.hostname}</strong>
                      </Link>
                      <span className={styles.secondaryText}>
                        {binding.device.operatingSystem}
                      </span>
                    </td>
                    <td>
                      <span className={styles.primaryText}>
                        {binding.device.user.fullName}
                      </span>
                      <span className={styles.secondaryText}>
                        {binding.device.user.email}
                      </span>
                    </td>
                    <td>
                      <span
                        className={`${styles.statusPill} ${statusTone(
                          binding.lastKnownStatus,
                        )}`}
                      >
                        {binding.lastKnownStatus ?? 'UNKNOWN'}
                      </span>
                      <span className={styles.secondaryText}>
                        Keep-alive: {formatDateTime(binding.lastKeepAliveAt)}
                      </span>
                    </td>
                    <td>
                      <span className={styles.primaryText}>
                        {formatDateTime(binding.lastStatusCheckedAt)}
                      </span>
                      <span className={styles.secondaryText}>
                        {binding.consecutiveStatusFailures > 0
                          ? `${binding.consecutiveStatusFailures} lần lỗi liên tiếp`
                          : 'Không có lỗi runtime'}
                      </span>
                      {binding.lastStatusError ? (
                        <span className={styles.secondaryText}>
                          {binding.lastStatusError}
                        </span>
                      ) : null}
                    </td>
                    <td>{formatDateTime(binding.lastSynchronizedAt)}</td>
                    <td>
                      <div className={styles.inlineActions}>
                        <button
                          className={styles.secondaryButton}
                          type="button"
                          disabled={actionBusy}
                          onClick={() => void refreshStatuses(binding.deviceId)}
                        >
                          Kiểm tra
                        </button>
                        <button
                          className={styles.dangerButton}
                          type="button"
                          disabled={actionBusy}
                          onClick={() => void removeBinding(binding)}
                        >
                          Gỡ binding
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
                {!bindings.length ? (
                  <tr>
                    <td colSpan={7}>Chưa có Wazuh Agent binding.</td>
                  </tr>
                ) : null}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}
