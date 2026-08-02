'use client';

import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { useEffect, useMemo, useState } from 'react';

import styles from '@/components/security-console.module.css';
import type { AuthenticatedUser } from '@/lib/api-types';
import type { Device } from '@/lib/device-types';

export function SettingsClient() {
  const router = useRouter();
  const [user, setUser] = useState<AuthenticatedUser | null>(null);
  const [devices, setDevices] = useState<Device[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    const controller = new AbortController();
    Promise.all([
      fetch('/api/auth/me', { cache: 'no-store', signal: controller.signal }),
      fetch('/api/devices', { cache: 'no-store', signal: controller.signal }),
    ])
      .then(async ([userResponse, deviceResponse]) => {
        if ([userResponse.status, deviceResponse.status].some((status) => status === 401 || status === 403)) {
          router.replace('/login');
          return;
        }
        const userPayload = (await userResponse.json()) as AuthenticatedUser & { message?: string };
        const devicePayload = (await deviceResponse.json()) as Device[] & { message?: string };
        if (!userResponse.ok) throw new Error(userPayload.message ?? 'Không thể tải tài khoản');
        if (!deviceResponse.ok) throw new Error((devicePayload as unknown as { message?: string }).message ?? 'Không thể tải thiết bị');
        setUser(userPayload);
        setDevices(Array.isArray(devicePayload) ? devicePayload : []);
      })
      .catch((caught: unknown) => {
        if (controller.signal.aborted) return;
        setError(caught instanceof Error ? caught.message : 'Không thể tải cài đặt');
      })
      .finally(() => { if (!controller.signal.aborted) setLoading(false); });
    return () => controller.abort();
  }, [router]);

  const activeDevices = useMemo(() => devices.filter((device) => device.status !== 'ERROR' && device.status !== 'OFFLINE').length, [devices]);

  return (
    <div className={styles.page}>
      <header className={styles.pageHeader}>
        <div><p className={styles.eyebrow}>Account & security scope</p><h1>Cài đặt</h1><p className={styles.subtitle}>Thông tin tài khoản, phạm vi quyền và trạng thái các thiết bị đang được CYRP bảo vệ.</p></div>
      </header>
      {error ? <div className={styles.errorPanel}>{error}</div> : null}
      {loading ? <div className={styles.loadingSkeleton} /> : null}
      {!loading ? (
        <>
          <section className={styles.panelGridEqual}>
            <article className={styles.panel}><div className={styles.panelHeader}><div><h2>Tài khoản</h2><p>Thông tin từ phiên xác thực hiện tại.</p></div></div><div className={styles.keyValueList}><div className={styles.keyValueRow}><span>Họ tên</span><strong>{user?.fullName ?? '—'}</strong></div><div className={styles.keyValueRow}><span>Email</span><strong>{user?.email ?? '—'}</strong></div><div className={styles.keyValueRow}><span>Vai trò</span><strong>{user?.role ?? '—'}</strong></div><div className={styles.keyValueRow}><span>Thiết bị đang theo dõi</span><strong>{activeDevices}/{devices.length}</strong></div></div></article>
            <article className={styles.panel}><div className={styles.panelHeader}><div><h2>Phạm vi quyền</h2><p>CYRP chỉ cho người dùng xem dữ liệu thuộc thiết bị của chính tài khoản.</p></div></div><div className={styles.keyValueList}><div className={styles.keyValueRow}><span>Device ownership</span><strong>Bắt buộc</strong></div><div className={styles.keyValueRow}><span>Wazuh credential trên frontend</span><strong>Không lưu</strong></div><div className={styles.keyValueRow}><span>Session cookie</span><strong>HTTP-only</strong></div><div className={styles.keyValueRow}><span>Risk model AI</span><strong>Đã bật: AI_CYRP XGBoost</strong></div></div></article>
          </section>
          <section className={styles.panel}><div className={styles.panelHeader}><div><h2>Luồng kiểm tra bảo mật</h2><p>Cách CYRP lấy dữ liệu và hiển thị dự đoán AI khi người dùng bấm “Kiểm tra máy”.</p></div><Link className={styles.primaryButton} href="/devices">Quản lý thiết bị</Link></div><div className={styles.detailGrid}><div className={styles.detailItem}><span className={styles.label}>Bước 1</span><strong>Thiết bị được liên kết với Wazuh Agent</strong></div><div className={styles.detailItem}><span className={styles.label}>Bước 2</span><strong>Wazuh Agent gửi inventory và vulnerability state</strong></div><div className={styles.detailItem}><span className={styles.label}>Bước 3</span><strong>CYRP đồng bộ CVE, package và endpoint context</strong></div><div className={styles.detailItem}><span className={styles.label}>Bước 4</span><strong>Người dùng bấm “Kiểm tra máy”</strong></div><div className={styles.detailItem}><span className={styles.label}>Bước 5</span><strong>AI_CYRP XGBoost dự đoán nguy cơ khai thác</strong></div><div className={styles.detailItem}><span className={styles.label}>Bước 6</span><strong>Portal hiển thị mức ưu tiên và khuyến nghị ngắn gọn</strong></div></div></section>
          <section className={styles.panelGridEqual}>
            <article className={styles.panel}><div className={styles.panelHeader}><div><h2>Thiết bị đã đăng ký</h2><p>Trạng thái logic trong CYRP.</p></div></div><div className={styles.cardList}>{devices.map((device) => (<div className={styles.listCard} key={device.id}><div><Link className={styles.linkInline} href={`/devices/${device.id}`}><strong>{device.hostname}</strong></Link><p>{device.operatingSystem}</p></div><span className={`${styles.statusPill} ${device.status === 'ERROR' ? styles.statusDanger : styles.statusNeutral}`}>{device.status}</span></div>))}{!devices.length ? <div className={styles.emptyState}>Chưa có thiết bị.</div> : null}</div></article>
            <article className={styles.panel}><div className={styles.panelHeader}><div><h2>Lưu ý bảo mật</h2><p>Các nguyên tắc người dùng cần giữ khi vận hành endpoint.</p></div></div><div className={styles.keyValueList}><div className={styles.keyValueRow}><span>Token / mã enrollment</span><strong>Không chia sẻ</strong></div><div className={styles.keyValueRow}><span>Khi có cảnh báo HIGH/CRITICAL</span><strong>Ưu tiên cập nhật phần mềm và kiểm tra log</strong></div><div className={styles.keyValueRow}><span>Khi AI probability cao</span><strong>Nhấn chi tiết lỗ hổng để xem CVE và package liên quan</strong></div></div></article>
          </section>
        </>
      ) : null}
    </div>
  );
}
