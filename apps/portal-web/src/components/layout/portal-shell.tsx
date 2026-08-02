'use client';

import Link from 'next/link';
import { usePathname, useRouter } from 'next/navigation';
import {
  useEffect,
  useState,
  type ReactNode,
} from 'react';
import type {
  AuthenticatedUser,
} from '@/lib/api-types';
import styles from './portal-shell.module.css';

type IconName =
  | 'dashboard'
  | 'users'
  | 'devices'
  | 'risk'
  | 'settings'
  | 'search'
  | 'bell'
  | 'menu'
  | 'logout'
  | 'shield'
  | 'agent'
  | 'database'
  | 'activity';

interface PortalShellProps {
  children: ReactNode;
}

interface NavigationItem {
  label: string;
  href: string;
  icon: IconName;
  enabled: boolean;
}

const navigationItems: NavigationItem[] = [
  { label: 'Tổng quan', href: '/dashboard', icon: 'dashboard', enabled: true },
  { label: 'Người dùng', href: '/users', icon: 'users', enabled: true },
  { label: 'Thiết bị', href: '/endpoints', icon: 'devices', enabled: true },
  { label: 'Wazuh Agents', href: '/agents', icon: 'agent', enabled: true },
  { label: 'Lỗ hổng', href: '/vulnerabilities', icon: 'risk', enabled: true },
  { label: 'Đồng bộ dữ liệu', href: '/sync', icon: 'activity', enabled: true },
  { label: 'Thống kê dữ liệu', href: '/cti', icon: 'database', enabled: true },
  { label: 'Sức khỏe hệ thống', href: '/system', icon: 'settings', enabled: true },
];

function Icon({ name }: { name: IconName }) {
  const commonProps = {
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
        <svg {...commonProps}>
          <rect x="3" y="3" width="7" height="7" rx="2" />
          <rect x="14" y="3" width="7" height="7" rx="2" />
          <rect x="3" y="14" width="7" height="7" rx="2" />
          <rect x="14" y="14" width="7" height="7" rx="2" />
        </svg>
      );

    case 'users':
      return (
        <svg {...commonProps}>
          <circle cx="9" cy="7" r="4" />
          <path d="M2 21V19A4 4 0 0 1 6 15H12A4 4 0 0 1 16 19V21" />
          <path d="M16 3.2A4 4 0 0 1 16 10.8" />
          <path d="M22 21V19A4 4 0 0 0 19 15.1" />
        </svg>
      );

    case 'devices':
      return (
        <svg {...commonProps}>
          <rect x="3" y="4" width="18" height="13" rx="2" />
          <path d="M8 21H16" />
          <path d="M12 17V21" />
        </svg>
      );

    case 'risk':
      return (
        <svg {...commonProps}>
          <path d="M12 3L21 19H3L12 3Z" />
          <path d="M12 9V13" />
          <path d="M12 17H12.01" />
        </svg>
      );

    case 'settings':
      return (
        <svg {...commonProps}>
          <circle cx="12" cy="12" r="3" />
          <path d="M19.4 15A1.7 1.7 0 0 0 19.7 16.9L19.8 17A2 2 0 1 1 17 19.8L16.9 19.7A1.7 1.7 0 0 0 15 19.4A1.7 1.7 0 0 0 14 21V21.2A2 2 0 0 1 10 21.2V21A1.7 1.7 0 0 0 9 19.4A1.7 1.7 0 0 0 7.1 19.7L7 19.8A2 2 0 1 1 4.2 17L4.3 16.9A1.7 1.7 0 0 0 4.6 15A1.7 1.7 0 0 0 3 14H2.8A2 2 0 0 1 2.8 10H3A1.7 1.7 0 0 0 4.6 9A1.7 1.7 0 0 0 4.3 7.1L4.2 7A2 2 0 1 1 7 4.2L7.1 4.3A1.7 1.7 0 0 0 9 4.6A1.7 1.7 0 0 0 10 3V2.8A2 2 0 0 1 14 2.8V3A1.7 1.7 0 0 0 15 4.6A1.7 1.7 0 0 0 16.9 4.3L17 4.2A2 2 0 1 1 19.8 7L19.7 7.1A1.7 1.7 0 0 0 19.4 9A1.7 1.7 0 0 0 21 10H21.2A2 2 0 0 1 21.2 14H21A1.7 1.7 0 0 0 19.4 15Z" />
        </svg>
      );

    case 'search':
      return (
        <svg {...commonProps}>
          <circle cx="11" cy="11" r="7" />
          <path d="M20 20L16.5 16.5" />
        </svg>
      );

    case 'bell':
      return (
        <svg {...commonProps}>
          <path d="M18 8A6 6 0 0 0 6 8C6 15 3 15 3 17H21C21 15 18 15 18 8Z" />
          <path d="M10 21H14" />
        </svg>
      );

    case 'menu':
      return (
        <svg {...commonProps}>
          <path d="M4 7H20" />
          <path d="M4 12H20" />
          <path d="M4 17H20" />
        </svg>
      );

    case 'logout':
      return (
        <svg {...commonProps}>
          <path d="M10 17L15 12L10 7" />
          <path d="M15 12H3" />
          <path d="M15 4H19A2 2 0 0 1 21 6V18A2 2 0 0 1 19 20H15" />
        </svg>
      );


    case 'agent':
      return (
        <svg {...commonProps}>
          <circle cx="12" cy="8" r="3" />
          <path d="M6 20V18A6 6 0 0 1 18 18V20" />
          <path d="M4 9H2M22 9H20M12 3V1" />
        </svg>
      );

    case 'database':
      return (
        <svg {...commonProps}>
          <ellipse cx="12" cy="5" rx="8" ry="3" />
          <path d="M4 5V12C4 13.7 7.6 15 12 15C16.4 15 20 13.7 20 12V5" />
          <path d="M4 12V19C4 20.7 7.6 22 12 22C16.4 22 20 20.7 20 19V12" />
        </svg>
      );

    case 'activity':
      return (
        <svg {...commonProps}>
          <path d="M3 12H7L9 6L13 18L16 10L18 12H21" />
        </svg>
      );

    case 'shield':
      return (
        <svg {...commonProps}>
          <path d="M12 3L20 6V11C20 16 16.7 20.2 12 22C7.3 20.2 4 16 4 11V6L12 3Z" />
          <path d="M9 12L11 14L15 10" />
        </svg>
      );
  }
}

export function PortalShell({ children }: PortalShellProps) {
  const pathname = usePathname();
  const router = useRouter();

  const [sidebarOpen, setSidebarOpen] =
    useState(false);

  const [currentUser, setCurrentUser] =
    useState<AuthenticatedUser | null>(null);

  useEffect(() => {
    const controller = new AbortController();

    async function loadCurrentUser(): Promise<void> {
      try {
        const response = await fetch('/api/auth/me', {
          method: 'GET',
          cache: 'no-store',
          signal: controller.signal,
        });

        if (
          response.status === 401 ||
          response.status === 403
        ) {
          router.replace('/login');
          return;
        }

        if (!response.ok) {
          console.error(
            'Không thể tải thông tin người dùng',
          );
          return;
        }

        const user =
          (await response.json()) as AuthenticatedUser;

        setCurrentUser(user);
      } catch (error: unknown) {
        if (
          error instanceof DOMException &&
          error.name === 'AbortError'
        ) {
          return;
        }

        console.error(
          'Không thể tải thông tin người dùng',
          error,
        );
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

  const profileName =
    currentUser?.fullName ?? 'Đang xác thực';

  const profileRole =
    currentUser?.role ?? '...';

  const profileInitial =
    currentUser?.fullName
      ?.trim()
      .charAt(0)
      .toUpperCase() || 'A';

  return (
    <div className={styles.shell}>
      {sidebarOpen && (
        <button
          type="button"
          className={styles.overlay}
          aria-label="Đóng menu"
          onClick={() => setSidebarOpen(false)}
        />
      )}

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
            <span>Security Platform</span>
          </div>
        </div>

        <div className={styles.sidebarContent}>
          <p className={styles.sectionLabel}>Quản trị hệ thống</p>

          <nav className={styles.navigation}>
            {navigationItems.map((item) => {
              const active =
                pathname === item.href ||
                pathname.startsWith(`${item.href}/`);

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
                    <span className={styles.comingSoon}>Sắp có</span>
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
        </div>

        <div className={styles.sidebarFooter}>
          <div className={styles.sidebarProfile}>
            <div className={styles.avatar}>
              {profileInitial}
            </div>

            <div>
              <strong>{profileName}</strong>
              <span>{profileRole}</span>
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

            <div className={styles.search}>
              <Icon name="search" />

              <input
                type="search"
                placeholder="Tìm kiếm — sắp có"
                aria-label="Tìm kiếm chưa khả dụng"
                disabled
              />

              <kbd>Ctrl K</kbd>
            </div>
          </div>

          <div className={styles.topbarRight}>
            <div className={styles.systemStatus}>
              <span />
              Hệ thống hoạt động
            </div>

            <button
              type="button"
              className={styles.iconButton}
              aria-label="Thông báo chưa khả dụng"
              title="Thông báo sẽ được bổ sung ở giai đoạn tiếp theo"
              disabled
            >
              <Icon name="bell" />
            </button>

            <div className={styles.topbarProfile}>
              <div className={styles.avatar}>
                {profileInitial}
              </div>

              <div>
                <strong>{profileName}</strong>
                <span>{profileRole}</span>
              </div>
            </div>
          </div>
        </header>

        <main className={styles.content}>{children}</main>
      </div>
    </div>
  );
}