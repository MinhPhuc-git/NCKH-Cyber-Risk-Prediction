'use client';

import Link from 'next/link';
import { usePathname, useRouter } from 'next/navigation';
import {
  useEffect,
  useState,
  type ReactNode,
} from 'react';

import type { AuthenticatedUser } from '@/lib/api-types';

import styles from './user-shell.module.css';

type IconName =
  | 'dashboard'
  | 'devices'
  | 'report'
  | 'activity'
  | 'settings'
  | 'shield'
  | 'search'
  | 'bell'
  | 'menu'
  | 'logout';

interface UserShellProps {
  children: ReactNode;
}

interface NavigationItem {
  label: string;
  href: string;
  icon: IconName;
  enabled: boolean;
}

const navigationItems: NavigationItem[] = [
  { label: 'Dashboard', href: '/dashboard', icon: 'dashboard', enabled: true },
  { label: 'Thiết bị', href: '/devices', icon: 'devices', enabled: true },
  { label: 'Vulnerable detection', href: '/vulnerabilities', icon: 'shield', enabled: true },
  { label: 'Kết quả AI dự đoán', href: '/ai-predictions', icon: 'shield', enabled: true },
  { label: 'Lịch sử đồng bộ', href: '/sync-history', icon: 'activity', enabled: true },
  { label: 'Báo cáo dữ liệu', href: '/reports', icon: 'report', enabled: true },
  { label: 'Cài đặt', href: '/settings', icon: 'settings', enabled: true },
];

function Icon({ name }: { name: IconName }) {
  const common = {
    viewBox: '0 0 24 24',
    fill: 'none',
    stroke: 'currentColor',
    strokeWidth: 1.8,
    strokeLinecap: 'round' as const,
    strokeLinejoin: 'round' as const,
    'aria-hidden': true,
  };

  switch (name) {
    case 'dashboard':
      return (
        <svg {...common}>
          <rect x="3" y="3" width="7" height="7" rx="2" />
          <rect x="14" y="3" width="7" height="7" rx="2" />
          <rect x="3" y="14" width="7" height="7" rx="2" />
          <rect x="14" y="14" width="7" height="7" rx="2" />
        </svg>
      );
    case 'devices':
      return (
        <svg {...common}>
          <rect x="3" y="4" width="18" height="13" rx="2" />
          <path d="M8 21H16" />
          <path d="M12 17V21" />
        </svg>
      );
    case 'report':
      return (
        <svg {...common}>
          <path d="M5 3H19A2 2 0 0 1 21 5V19A2 2 0 0 1 19 21H5A2 2 0 0 1 3 19V5A2 2 0 0 1 5 3Z" />
          <path d="M7 16V12" />
          <path d="M12 16V8" />
          <path d="M17 16V10" />
        </svg>
      );
    case 'activity':
      return (
        <svg {...common}>
          <path d="M3 12H7L9 6L13 18L16 10L18 12H21" />
        </svg>
      );
    case 'settings':
      return (
        <svg {...common}>
          <circle cx="12" cy="12" r="3" />
          <path d="M19.4 15A1.7 1.7 0 0 0 19.7 16.9L19.8 17A2 2 0 1 1 17 19.8L16.9 19.7A1.7 1.7 0 0 0 15 19.4A1.7 1.7 0 0 0 14 21V21.2A2 2 0 0 1 10 21.2V21A1.7 1.7 0 0 0 9 19.4A1.7 1.7 0 0 0 7.1 19.7L7 19.8A2 2 0 1 1 4.2 17L4.3 16.9A1.7 1.7 0 0 0 4.6 15A1.7 1.7 0 0 0 3 14H2.8A2 2 0 0 1 2.8 10H3A1.7 1.7 0 0 0 4.6 9A1.7 1.7 0 0 0 4.3 7.1L4.2 7A2 2 0 1 1 7 4.2L7.1 4.3A1.7 1.7 0 0 0 9 4.6A1.7 1.7 0 0 0 10 3V2.8A2 2 0 0 1 14 2.8V3A1.7 1.7 0 0 0 15 4.6A1.7 1.7 0 0 0 16.9 4.3L17 4.2A2 2 0 1 1 19.8 7L19.7 7.1A1.7 1.7 0 0 0 19.4 9A1.7 1.7 0 0 0 21 10H21.2A2 2 0 0 1 21.2 14H21A1.7 1.7 0 0 0 19.4 15Z" />
        </svg>
      );
    case 'shield':
      return (
        <svg {...common}>
          <path d="M12 3L20 6V11C20 16 16.7 20.2 12 22C7.3 20.2 4 16 4 11V6L12 3Z" />
          <path d="M9 12L11 14L15 10" />
        </svg>
      );
    case 'search':
      return (
        <svg {...common}>
          <circle cx="11" cy="11" r="7" />
          <path d="M20 20L16.5 16.5" />
        </svg>
      );
    case 'bell':
      return (
        <svg {...common}>
          <path d="M18 8A6 6 0 0 0 6 8C6 15 3 15 3 17H21C21 15 18 15 18 8Z" />
          <path d="M10 21H14" />
        </svg>
      );
    case 'menu':
      return (
        <svg {...common}>
          <path d="M4 7H20" />
          <path d="M4 12H20" />
          <path d="M4 17H20" />
        </svg>
      );
    case 'logout':
      return (
        <svg {...common}>
          <path d="M10 17L15 12L10 7" />
          <path d="M15 12H3" />
          <path d="M15 4H19A2 2 0 0 1 21 6V18A2 2 0 0 1 19 20H15" />
        </svg>
      );
  }
}

function isActivePath(pathname: string, href: string): boolean {
  return pathname === href || pathname.startsWith(`${href}/`);
}

function isAuthenticatedUser(value: unknown): value is AuthenticatedUser {
  if (typeof value !== 'object' || value === null) {
    return false;
  }

  const candidate = value as Partial<AuthenticatedUser>;

  return (
    typeof candidate.id === 'string' &&
    typeof candidate.email === 'string' &&
    typeof candidate.fullName === 'string' &&
    candidate.role === 'USER'
  );
}

export function UserShell({ children }: UserShellProps) {
  const pathname = usePathname();
  const router = useRouter();

  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [currentUser, setCurrentUser] =
    useState<AuthenticatedUser | null>(null);
  const [authUnavailable, setAuthUnavailable] = useState(false);

  useEffect(() => {
    const controller = new AbortController();

    async function loadCurrentUser(): Promise<void> {
      try {
        const response = await fetch('/api/auth/me', {
          method: 'GET',
          cache: 'no-store',
          signal: controller.signal,
        });

        if (response.status === 401 || response.status === 403) {
          router.replace('/login');
          return;
        }

        if (!response.ok) {
          setAuthUnavailable(true);
          return;
        }

        const payload = (await response.json()) as unknown;

        if (!isAuthenticatedUser(payload)) {
          router.replace('/login');
          return;
        }

        setCurrentUser(payload);
        setAuthUnavailable(false);
      } catch (error: unknown) {
        if (
          error instanceof DOMException &&
          error.name === 'AbortError'
        ) {
          return;
        }

        setAuthUnavailable(true);
      }
    }

    void loadCurrentUser();

    return () => {
      controller.abort();
    };
  }, [router]);

  async function handleLogout(): Promise<void> {
    try {
      await fetch('/api/auth/logout', {
        method: 'POST',
      });
    } finally {
      router.replace('/login');
      router.refresh();
    }
  }

  const profileName = currentUser?.fullName ?? 'Đang xác thực';
  const profileMeta =
    currentUser?.email ??
    (authUnavailable ? 'Không thể kiểm tra phiên' : 'Đang tải phiên người dùng');
  const profileInitial =
    currentUser?.fullName.trim().charAt(0).toUpperCase() || 'U';

  return (
    <div className={styles.shell}>
      {sidebarOpen ? (
        <button
          type="button"
          className={styles.overlay}
          aria-label="Đóng menu"
          onClick={() => setSidebarOpen(false)}
        />
      ) : null}

      <aside
        className={`${styles.sidebar} ${
          sidebarOpen ? styles.sidebarOpen : ''
        }`}
      >
        <div className={styles.brand}>
          <div className={styles.brandIcon}>
            <Icon name="shield" />
          </div>
          <div>
            <strong>CYRP</strong>
            <span>User Security Portal</span>
          </div>
        </div>

        <div className={styles.consoleCard}>
          <div className={styles.consoleIcon}>
            <Icon name="shield" />
          </div>
          <div>
            <strong>Security Console</strong>
            <span>
              {authUnavailable
                ? 'Backend chưa sẵn sàng'
                : currentUser
                  ? 'Phiên đã xác thực'
                  : 'Đang xác thực phiên'}
            </span>
          </div>
        </div>

        <nav className={styles.navigation} aria-label="Điều hướng User Portal">
          {navigationItems.map((item) => {
            const active = isActivePath(pathname, item.href);

            if (!item.enabled) {
              return (
                <button
                  key={item.href}
                  type="button"
                  className={`${styles.navItem} ${styles.disabledItem}`}
                  disabled
                >
                  <span className={styles.navIcon}>
                    <Icon name={item.icon} />
                  </span>
                  <span>{item.label}</span>
                  <small>Sắp có</small>
                </button>
              );
            }

            return (
              <Link
                key={item.href}
                href={item.href}
                className={`${styles.navItem} ${
                  active ? styles.activeItem : ''
                }`}
                onClick={() => setSidebarOpen(false)}
              >
                <span className={styles.navIcon}>
                  <Icon name={item.icon} />
                </span>
                <span>{item.label}</span>
              </Link>
            );
          })}
        </nav>

        <div className={styles.sidebarFooter}>
          <div className={styles.profile}>
            <div className={styles.avatar}>{profileInitial}</div>
            <div className={styles.profileText}>
              <strong>{profileName}</strong>
              <span title={profileMeta}>{profileMeta}</span>
            </div>
          </div>

          <button
            type="button"
            className={styles.logoutButton}
            onClick={() => {
              void handleLogout();
            }}
          >
            <Icon name="logout" />
            <span>Đăng xuất</span>
          </button>

          <div className={styles.footerStatus}>
            <span />
            Portal đang hoạt động
          </div>
        </div>
      </aside>

      <div className={styles.workspace}>
        <header className={styles.topbar}>
          <div className={styles.topbarLeft}>
            <button
              type="button"
              className={styles.menuButton}
              aria-label="Mở menu"
              onClick={() => setSidebarOpen(true)}
            >
              <Icon name="menu" />
            </button>

            <div className={styles.topNav}>
              <Link
                href="/dashboard"
                className={
                  isActivePath(pathname, '/dashboard')
                    ? styles.topNavActive
                    : ''
                }
              >
                Tổng quan
              </Link>
              <Link
                href="/devices"
                className={
                  isActivePath(pathname, '/devices')
                    ? styles.topNavActive
                    : ''
                }
              >
                Thiết bị
              </Link>
              <Link
                href="/vulnerabilities"
                className={
                  isActivePath(pathname, '/vulnerabilities')
                    ? styles.topNavActive
                    : ''
                }
              >
                Vulnerable detection
              </Link>
              <Link
                href="/sync-history"
                className={
                  isActivePath(pathname, '/sync-history')
                    ? styles.topNavActive
                    : ''
                }
              >
                Lịch sử đồng bộ
              </Link>
              <Link
                href="/reports"
                className={
                  isActivePath(pathname, '/reports')
                    ? styles.topNavActive
                    : ''
                }
              >
                Báo cáo dữ liệu
              </Link>
            </div>
          </div>

          <div className={styles.topbarRight}>
            <div className={`${styles.search} ${styles.controlUnavailable}`}>
              <Icon name="search" />
              <input
                type="search"
                placeholder="Tìm kiếm — sắp có"
                disabled
                aria-label="Tìm kiếm chưa khả dụng"
              />
            </div>

            <button
              type="button"
              className={`${styles.iconButton} ${styles.controlUnavailable}`}
              aria-label="Thông báo chưa khả dụng"
              title="Thông báo sẽ được bổ sung ở giai đoạn tiếp theo"
              disabled
            >
              <Icon name="bell" />
            </button>

            <div className={styles.avatar} title={profileName}>
              {profileInitial}
            </div>
          </div>
        </header>

        <main className={styles.content}>{children}</main>
      </div>
    </div>
  );
}
