import Link from 'next/link';
import type { ReactNode } from 'react';

import styles from './auth-shell.module.css';

interface AuthShellProps {
  active: 'login';
  title: string;
  description: string;
  children: ReactNode;
}

export function AuthShell({
  active,
  title,
  description,
  children,
}: AuthShellProps) {
  return (
    <main className={styles.page}>
      <section className={styles.brandPanel}>
        <div className={styles.brand}>
          <div className={styles.logo}>C</div>

          <div>
            <strong>CYRP</strong>
            <span>User Security Portal</span>
          </div>
        </div>

        <div className={styles.brandContent}>
          <p>Endpoint security</p>
          <h1>
            Theo dõi trạng thái bảo mật của thiết
            bị trong một giao diện thống nhất.
          </h1>
          <span>
            Tài khoản người dùng được quản trị viên
            cấp phát. Người dùng chỉ có quyền truy cập
            dữ liệu thuộc các thiết bị đã liên kết với
            chính tài khoản đó.
          </span>
        </div>

        <div className={styles.securityNote}>
          <span />
          Kết nối bảo mật với CYRP API
        </div>
      </section>

      <section className={styles.formPanel}>
        <div className={styles.formCard}>
          <div className={styles.tabs}>
            <Link
              href="/login"
              className={
                active === 'login'
                  ? styles.activeTab
                  : ''
              }
            >
              Đăng nhập
            </Link>

            <span className={styles.disabledTab}>
              Tài khoản do Admin cấp
            </span>
          </div>

          <header className={styles.formHeader}>
            <p>CYRP account</p>
            <h2>{title}</h2>
            <span>{description}</span>
          </header>

          {children}
        </div>
      </section>
    </main>
  );
}
