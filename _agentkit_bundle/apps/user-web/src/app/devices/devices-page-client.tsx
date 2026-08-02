'use client';

import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { useEffect, useState } from 'react';

import { DeviceAnalysisButton } from '@/components/device-analysis-button';
import { UserShell } from '@/components/user-shell';
import type { ApiErrorResponse } from '@/lib/api-types';
import type {
  CreateEnrollmentCodeResponse,
  Device,
  DeviceStatus,
} from '@/lib/device-types';

import styles from './devices.module.css';

const statusLabel: Record<DeviceStatus, string> = {
  OFFLINE: 'Ngoại tuyến',
  IDLE: 'Sẵn sàng',
  SCANNING: 'Đang quét',
  ERROR: 'Lỗi',
};

function formatDate(value: string | null): string {
  if (!value) {
    return 'Chưa ghi nhận';
  }

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return 'Không xác định';
  }

  return new Intl.DateTimeFormat('vi-VN', {
    dateStyle: 'short',
    timeStyle: 'medium',
  }).format(date);
}

function getErrorMessage(
  payload: ApiErrorResponse,
  fallback: string,
): string {
  if (Array.isArray(payload.message)) {
    return payload.message.join(', ');
  }

  return payload.message ?? fallback;
}


function extractBackendBaseUrl(bootstrapCommand: string): string {
  const quotedMatch = bootstrapCommand.match(/-BackendBaseUrl\s+"([^"]+)"/i);

  if (quotedMatch?.[1]) {
    return quotedMatch[1];
  }

  const plainMatch = bootstrapCommand.match(/-BackendBaseUrl\s+([^\s`]+)/i);

  if (plainMatch?.[1]) {
    return plainMatch[1].replace(/^['"]|['"]$/g, '');
  }

  return 'http://<CYRP_API_HOST>:3001/api/v1';
}

function shellQuote(value: string): string {
  return "'" + value.replace(/'/g, "'\\''") + "'";
}

function buildLinuxBootstrapCommand(enrollment: CreateEnrollmentCodeResponse): string {
  const backendBaseUrl = extractBackendBaseUrl(enrollment.bootstrapCommand);

  return [
    'cd ~/Downloads',
    'tar -xzf cyrp-agent-kit-linux.tar.gz',
    'sudo bash ./cyrp-agent-kit-linux/Invoke-CyrpWazuhBootstrapper.sh \\',
    `  --backend-base-url ${shellQuote(backendBaseUrl)} \\`,
    `  --enrollment-code ${shellQuote(enrollment.code)}`,
  ].join('\n');
}


class AuthenticationRequiredError extends Error {
  constructor() {
    super('Authentication required');
    this.name = 'AuthenticationRequiredError';
  }
}

async function requestDevices(signal?: AbortSignal): Promise<Device[]> {
  const response = await fetch('/api/devices', {
    method: 'GET',
    cache: 'no-store',
    signal,
  });

  const payload = (await response.json()) as Device[] | ApiErrorResponse;

  if (response.status === 401) {
    throw new AuthenticationRequiredError();
  }

  if (!response.ok) {
    throw new Error(
      getErrorMessage(
        payload as ApiErrorResponse,
        'Không thể tải thiết bị',
      ),
    );
  }

  if (!Array.isArray(payload)) {
    throw new Error('Phản hồi thiết bị không hợp lệ');
  }

  return payload;
}

export function DevicesPageClient() {
  const router = useRouter();

  const [devices, setDevices] = useState<Device[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [isCreatingCode, setIsCreatingCode] = useState(false);
  const [errorMessage, setErrorMessage] = useState('');
  const [enrollment, setEnrollment] = useState<CreateEnrollmentCodeResponse | null>(null);
  const [copied, setCopied] = useState(false);
  const [copiedCommand, setCopiedCommand] = useState(false);
  const [copiedLinuxCommand, setCopiedLinuxCommand] = useState(false);

  useEffect(() => {
    const controller = new AbortController();

    requestDevices(controller.signal)
      .then((result) => {
        if (controller.signal.aborted) {
          return;
        }

        setDevices(result);
        setErrorMessage('');
      })
      .catch((error: unknown) => {
        if (controller.signal.aborted) {
          return;
        }

        if (error instanceof AuthenticationRequiredError) {
          router.replace('/login');
          return;
        }

        setErrorMessage(
          error instanceof Error ? error.message : 'Không thể tải thiết bị',
        );
      })
      .finally(() => {
        if (!controller.signal.aborted) {
          setIsLoading(false);
        }
      });

    return () => {
      controller.abort();
    };
  }, [router]);

  async function refreshDevices(): Promise<void> {
    setErrorMessage('');
    setIsLoading(true);

    try {
      const result = await requestDevices();
      setDevices(result);
    } catch (error: unknown) {
      if (error instanceof AuthenticationRequiredError) {
        router.replace('/login');
        return;
      }

      setErrorMessage(
        error instanceof Error ? error.message : 'Không thể tải thiết bị',
      );
    } finally {
      setIsLoading(false);
    }
  }

  async function createEnrollmentCode(): Promise<void> {
    setErrorMessage('');
    setCopied(false);
    setCopiedCommand(false);
    setCopiedLinuxCommand(false);
    setIsCreatingCode(true);

    try {
      const response = await fetch('/api/devices', {
        method: 'POST',
      });

      const payload = (await response.json()) as Partial<CreateEnrollmentCodeResponse> & ApiErrorResponse;

      if (response.status === 401) {
        router.replace('/login');
        return;
      }

      if (
        !response.ok ||
        typeof payload.code !== 'string' ||
        typeof payload.expiresAt !== 'string' ||
        typeof payload.expectedAgentName !== 'string' ||
        typeof payload.bootstrapCommand !== 'string'
      ) {
        throw new Error(
          getErrorMessage(payload, 'Không thể tạo mã liên kết thiết bị'),
        );
      }

      setEnrollment({
        code: payload.code,
        expectedAgentName: payload.expectedAgentName,
        bootstrapCommand: payload.bootstrapCommand,
        expiresAt: payload.expiresAt,
      });
    } catch (error: unknown) {
      setErrorMessage(
        error instanceof Error ? error.message : 'Không thể tạo mã liên kết',
      );
    } finally {
      setIsCreatingCode(false);
    }
  }

  async function copyBootstrapCommand(): Promise<void> {
    if (!enrollment) {
      return;
    }

    try {
      await navigator.clipboard.writeText(enrollment.bootstrapCommand);
      setCopiedCommand(true);
    } catch {
      setCopiedCommand(false);
    }
  }


  async function copyLinuxBootstrapCommand(): Promise<void> {
    if (!enrollment) {
      return;
    }

    try {
      await navigator.clipboard.writeText(buildLinuxBootstrapCommand(enrollment));
      setCopiedLinuxCommand(true);
    } catch {
      setCopiedLinuxCommand(false);
    }
  }

  async function copyEnrollmentCode(): Promise<void> {
    if (!enrollment) {
      return;
    }

    try {
      await navigator.clipboard.writeText(enrollment.code);
      setCopied(true);
    } catch {
      setCopied(false);
    }
  }

  const device = devices[0] ?? null;
  const hasLinkedDevice = devices.length > 0;

  return (
    <UserShell>
      <header className={styles.pageHeader}>
        <div>
          <p>Device management</p>
          <h1>Thiết bị của tôi</h1>
        </div>

        <div className={styles.headerActions}>
          <button
            type="button"
            className={styles.secondaryButton}
            onClick={() => void refreshDevices()}
            disabled={isLoading}
          >
            Làm mới
          </button>

          {!hasLinkedDevice ? (
            <button
              type="button"
              className={styles.primaryButton}
              onClick={() => void createEnrollmentCode()}
              disabled={isCreatingCode}
            >
              {isCreatingCode ? 'Đang tạo mã...' : 'Liên kết thiết bị'}
            </button>
          ) : null}
        </div>
      </header>

      {errorMessage ? (
        <div className={styles.errorMessage} role="alert">
          {errorMessage}
        </div>
      ) : null}

      {isLoading ? (
        <section className={styles.devicePanel}>
          <div className={styles.loader} />
          <h2>Đang tải thiết bị</h2>
          <p>User Portal đang lấy dữ liệu từ CYRP API.</p>
        </section>
      ) : !device ? (
        <section className={styles.devicePanel}>
          <div className={styles.emptyIcon}>PC</div>
          <h2>Chưa có thiết bị được liên kết</h2>
          <p>
            Tạo mã liên kết, sau đó chạy lệnh enrollment trong CYRP Windows Agent trên máy cần bảo vệ.
          </p>
          <button
            type="button"
            className={styles.primaryButton}
            onClick={() => void createEnrollmentCode()}
          >
            Tạo mã liên kết
          </button>
        </section>
            ) : (
        <section className={styles.deviceWorkspace}>
          <article className={styles.deviceHeroCard}>
            <div className={styles.deviceHeroTop}>
              <div className={styles.deviceIdentity}>
                <div className={styles.deviceIcon}>PC</div>
                <div>
                  <span>Endpoint được liên kết</span>
                  <h2>{device.hostname}</h2>
                  <p>{device.operatingSystem}</p>
                </div>
              </div>

              <span className={`${styles.statusBadge} ${styles[`status${device.status}`]}`}>
                {statusLabel[device.status]}
              </span>
            </div>

            <div className={styles.deviceInfoGrid}>
              <div>
                <span>Kiến trúc CPU</span>
                <strong>{device.architecture ?? '—'}</strong>
              </div>
              <div>
                <span>Wazuh Agent</span>
                <strong>
                  {(device as { wazuhBinding?: { wazuhAgentId?: string | null } | null }).wazuhBinding?.wazuhAgentId
                    ? `ID ${(device as { wazuhBinding?: { wazuhAgentId?: string | null } | null }).wazuhBinding?.wazuhAgentId}`
                    : device.agentVersion && !device.agentVersion.toLowerCase().includes('phase')
                      ? device.agentVersion
                      : 'CYRP Agent'}
                </strong>
              </div>
              <div>
                <span>Lần kết nối cuối</span>
                <strong>{formatDate(device.lastSeenAt)}</strong>
              </div>
              <div>
                <span>Trạng thái</span>
                <strong>{statusLabel[device.status]}</strong>
              </div>
            </div>

            <p className={styles.deviceHeroHint}>
              Thông số thiết bị và kết quả kiểm tra sẽ được giữ lại để bạn có thể
              xem lại nhanh mà không cần quét mới.
            </p>
          </article>

          <div className={styles.analysisWorkspace}>
            <DeviceAnalysisButton deviceId={device.id} variant="repairOrb" />
          </div>
        </section>
      )}

      {enrollment ? (
        <div className={styles.modalBackdrop} role="presentation">
          <section
            className={styles.modal}
            role="dialog"
            aria-modal="true"
            aria-labelledby="enrollment-title"
          >
            <div className={styles.modalHeader}>
              <div>
                <p>One-time enrollment</p>
                <h2 id="enrollment-title">Liên kết CYRP Agent</h2>
              </div>

              <button
                type="button"
                className={styles.closeButton}
                aria-label="Đóng"
                onClick={() => setEnrollment(null)}
              >
                ×
              </button>
            </div>

            <p className={styles.modalDescription}>
              Mã này dùng để thực nghiệm liên kết thiết bị trên máy khác. Không chia sẻ mã hoặc lệnh cài đặt cho người không thuộc tài khoản này.
            </p>

            <div className={styles.enrollmentSummary}>
              <div>
                <span>Mã liên kết</span>
                <strong>{enrollment.code}</strong>
              </div>
              <div>
                <span>Tên agent dự kiến</span>
                <strong>{enrollment.expectedAgentName}</strong>
              </div>
              <div>
                <span>Hết hạn</span>
                <strong>{formatDate(enrollment.expiresAt)}</strong>
              </div>
            </div>

            <div className={styles.codeBox}>
              <code>{enrollment.code}</code>
              <button type="button" onClick={() => void copyEnrollmentCode()}>
                {copied ? 'Đã sao chép mã' : 'Sao chép mã'}
              </button>
            </div>

            <div className={styles.commandBox}>
              <div>
                <span>Windows Agent Kit</span>
                <p>Download cyrp-agent-kit.zip và giải nén vào C:\CYRP\AgentKit trên endpoint Windows.</p>
              </div>

              <a className={styles.secondaryButton} href="/downloads/cyrp-agent-kit.zip" download>
                Download Windows Agent Kit
              </a>
            </div>

            <div className={styles.commandBox}>
              <div>
                <span>Lệnh liên kết Windows endpoint</span>
                <p>Chạy trong PowerShell bằng quyền Administrator trên máy Windows cần giám sát.</p>
              </div>

              <pre>{enrollment.bootstrapCommand}</pre>

              <button type="button" onClick={() => void copyBootstrapCommand()}>
                {copiedCommand ? 'Đã sao chép lệnh Windows' : 'Sao chép lệnh Windows'}
              </button>
            </div>

            <div className={styles.commandBox}>
              <div>
                <span>Linux Agent Kit</span>
                <p>Download cyrp-agent-kit-linux.tar.gz, giải nén trong ~/Downloads rồi chạy lệnh bằng sudo.</p>
              </div>

              <a className={styles.secondaryButton} href="/downloads/cyrp-agent-kit-linux.tar.gz" download>
                Download Linux Agent Kit
              </a>
            </div>

            <div className={styles.commandBox}>
              <div>
                <span>Lệnh liên kết Linux endpoint</span>
                <p>Chạy trong Terminal trên Linux bằng tài khoản có quyền sudo.</p>
              </div>

              <pre>{buildLinuxBootstrapCommand(enrollment)}</pre>

              <button type="button" onClick={() => void copyLinuxBootstrapCommand()}>
                {copiedLinuxCommand ? 'Đã sao chép lệnh Linux' : 'Sao chép lệnh Linux'}
              </button>
            </div>

            <div className={styles.modalActions}>
              <button
                type="button"
                className={styles.secondaryButton}
                onClick={() => setEnrollment(null)}
              >
                Đóng
              </button>

              <button
                type="button"
                className={styles.primaryButton}
                onClick={() => {
                  setEnrollment(null);
                  void refreshDevices();
                }}
              >
                Đã liên kết, làm mới
              </button>
            </div>
          </section>
        </div>
      ) : null}
    </UserShell>
  );
}
