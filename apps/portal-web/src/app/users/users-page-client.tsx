'use client';

import {
  useEffect,
  useState,
  type FormEvent,
} from 'react';
import { useRouter } from 'next/navigation';

import { PortalShell } from '@/components/layout/portal-shell';
import type {
  ApiErrorResponse,
  CreateUserResponse,
  ListUsersResponse,
  RoleCode,
  UserListItem,
  UserStatus,
} from '@/lib/api-types';

import styles from './users.module.css';

interface UserSummary {
  total: number;
  activeAccounts: number;
  disabledAccounts: number;
  usersWithActiveDevices: number;
  usersWithoutActiveDevices: number;
}

class PortalApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

async function fetchJson<T>(
  input: string,
  init?: RequestInit,
): Promise<T> {
  const response = await fetch(input, {
    method: init?.method ?? 'GET',
    cache: 'no-store',
    headers: init?.headers,
    body: init?.body,
  });

  const payload =
    (await response.json()) as
      T & ApiErrorResponse;

  if (!response.ok) {
    const message =
      Array.isArray(payload.message)
        ? payload.message.join(', ')
        : payload.message;

    throw new PortalApiError(
      response.status,
      message ??
        'Không thể tải dữ liệu',
    );
  }

  return payload;
}

function formatDate(
  value: string | null,
): string {
  if (!value) {
    return 'Chưa đăng nhập';
  }

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return 'Không xác định';
  }

  return new Intl.DateTimeFormat(
    'vi-VN',
    {
      dateStyle: 'short',
      timeStyle: 'short',
    },
  ).format(date);
}

function getInitials(
  fullName: string,
): string {
  const words = fullName
    .trim()
    .split(/\s+/)
    .filter(Boolean);

  if (words.length === 0) {
    return 'U';
  }

  if (words.length === 1) {
    return words[0]
      .slice(0, 1)
      .toUpperCase();
  }

  return (
    words[0].charAt(0) +
    words[words.length - 1].charAt(0)
  ).toUpperCase();
}

export function UsersPageClient() {
  const router = useRouter();

  const [users, setUsers] = useState<
    UserListItem[]
  >([]);

  const [summary, setSummary] =
    useState<UserSummary>({
      total: 0,
      activeAccounts: 0,
      disabledAccounts: 0,
      usersWithActiveDevices: 0,
      usersWithoutActiveDevices: 0,
    });

  const [page, setPage] = useState(1);
  const [limit] = useState(20);

  const [searchInput, setSearchInput] =
    useState('');

  const [search, setSearch] =
    useState('');

  const [role, setRole] =
    useState<RoleCode | ''>('');

  const [status, setStatus] =
    useState<UserStatus | ''>('');

  const [total, setTotal] = useState(0);

  const [totalPages, setTotalPages] =
    useState(0);

  const [isLoading, setIsLoading] =
    useState(true);

  const [errorMessage, setErrorMessage] =
    useState('');

  const [successMessage, setSuccessMessage] =
    useState('');

  const [isCreateOpen, setIsCreateOpen] =
    useState(false);

  const [isCreatingUser, setIsCreatingUser] =
    useState(false);

  const [createError, setCreateError] =
    useState('');

  const [reloadToken, setReloadToken] =
    useState(0);

  useEffect(() => {
    let cancelled = false;

    async function loadSummary():
      Promise<void> {
      try {
        const response =
          await fetchJson<ListUsersResponse>(
            '/api/users?page=1&limit=1',
          );

        if (cancelled) {
          return;
        }

        setSummary(
          response.summary ?? {
            total:
              response.pagination.total,
            activeAccounts:
              response.pagination.total,
            disabledAccounts: 0,
            usersWithActiveDevices: 0,
            usersWithoutActiveDevices:
              response.pagination.total,
          },
        );
      } catch (error: unknown) {
        if (
          error instanceof PortalApiError &&
          (
            error.status === 401 ||
            error.status === 403
          )
        ) {
          router.replace('/login');
        }
      }
    }

    void loadSummary();

    return () => {
      cancelled = true;
    };
  }, [router, reloadToken]);

  useEffect(() => {
    let cancelled = false;

    async function loadUsers():
      Promise<void> {
      setIsLoading(true);
      setErrorMessage('');

      const query = new URLSearchParams({
        page: String(page),
        limit: String(limit),
      });

      if (search) {
        query.set('search', search);
      }

      if (role) {
        query.set('role', role);
      }

      if (status) {
        query.set('status', status);
      }

      try {
        const response =
          await fetchJson<ListUsersResponse>(
            `/api/users?${query.toString()}`,
          );

        if (cancelled) {
          return;
        }

        setUsers(response.data);
        setTotal(
          response.pagination.total,
        );
        setTotalPages(
          response.pagination.totalPages,
        );
      } catch (error: unknown) {
        if (cancelled) {
          return;
        }

        if (
          error instanceof PortalApiError &&
          (
            error.status === 401 ||
            error.status === 403
          )
        ) {
          router.replace('/login');
          return;
        }

        setErrorMessage(
          error instanceof Error
            ? error.message
            : 'Không thể tải danh sách người dùng',
        );
      } finally {
        if (!cancelled) {
          setIsLoading(false);
        }
      }
    }

    void loadUsers();

    return () => {
      cancelled = true;
    };
  }, [
    limit,
    page,
    role,
    router,
    search,
    status,
    reloadToken,
  ]);

  function handleSearch(
    event: FormEvent<HTMLFormElement>,
  ): void {
    event.preventDefault();

    setPage(1);
    setSearch(searchInput.trim());
  }

  async function handleCreateUser(
    event: FormEvent<HTMLFormElement>,
  ): Promise<void> {
    event.preventDefault();

    setCreateError('');
    setSuccessMessage('');
    setIsCreatingUser(true);

    const formData = new FormData(
      event.currentTarget,
    );

    const fullName = String(
      formData.get('fullName') ?? '',
    ).trim();
    const email = String(
      formData.get('email') ?? '',
    ).trim();
    const password = String(
      formData.get('password') ?? '',
    );
    const confirmPassword = String(
      formData.get('confirmPassword') ?? '',
    );

    if (!fullName || !email || !password) {
      setCreateError(
        'Vui lòng nhập đầy đủ họ tên, email và mật khẩu tạm.',
      );
      setIsCreatingUser(false);
      return;
    }

    if (password !== confirmPassword) {
      setCreateError(
        'Mật khẩu xác nhận không khớp.',
      );
      setIsCreatingUser(false);
      return;
    }

    if (password.length < 12) {
      setCreateError(
        'Mật khẩu tạm cần tối thiểu 12 ký tự.',
      );
      setIsCreatingUser(false);
      return;
    }

    try {
      const response = await fetchJson<CreateUserResponse>(
        '/api/users',
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            fullName,
            email,
            password,
            confirmPassword,
          }),
        },
      );

      setSuccessMessage(
        `Đã tạo tài khoản USER ${response.email ?? email}. Người dùng có thể đăng nhập bằng mật khẩu tạm được cấp.`,
      );
      setIsCreateOpen(false);
      setReloadToken((current) => current + 1);
    } catch (error: unknown) {
      if (
        error instanceof PortalApiError &&
        (
          error.status === 401 ||
          error.status === 403
        )
      ) {
        router.replace('/login');
        return;
      }

      setCreateError(
        error instanceof Error
          ? error.message
          : 'Không thể tạo người dùng',
      );
    } finally {
      setIsCreatingUser(false);
    }
  }


  return (
    <PortalShell>
      <header className={styles.pageHeader}>
        <div>
          <p className={styles.eyebrow}>
            Identity management
          </p>

          <h1>Quản lý người dùng</h1>

          <p className={styles.description}>
            Quản lý tài khoản, vai trò truy cập và trạng thái thiết bị đang hoạt động trong CYRP Platform.
          </p>
        </div>

        <button
          type="button"
          className={styles.createButton}
          onClick={() => {
            setCreateError('');
            setIsCreateOpen(true);
          }}
        >
          + Tạo người dùng
        </button>
      </header>

      <section className={styles.summaryGrid}>
        <article className={styles.summaryCard}>
          <div className={styles.summaryHeading}>
            <span>Tổng tài khoản</span>
            <span className={styles.purpleDot} />
          </div>

          <strong>{summary.total}</strong>
          <p>Tài khoản trong hệ thống</p>
        </article>

        <article className={styles.summaryCard}>
          <div className={styles.summaryHeading}>
            <span>Có thiết bị active</span>
            <span className={styles.greenDot} />
          </div>

          <strong>{summary.usersWithActiveDevices}</strong>
          <p>Có Wazuh Agent active hoặc thiết bị liên kết hoạt động</p>
        </article>

        <article className={styles.summaryCard}>
          <div className={styles.summaryHeading}>
            <span>Đã vô hiệu hóa</span>
            <span className={styles.redDot} />
          </div>

          <strong>{summary.disabledAccounts}</strong>
          <p>Tài khoản bị khóa truy cập</p>
        </article>
      </section>

      {successMessage ? (
        <div className={styles.successBanner}>
          {successMessage}
        </div>
      ) : null}

      <section className={styles.userPanel}>
        <div className={styles.toolbar}>
          <form
            className={styles.searchBox}
            onSubmit={handleSearch}
          >
            <input
              type="search"
              value={searchInput}
              placeholder="Tìm kiếm theo tên hoặc email..."
              aria-label="Tìm kiếm người dùng"
              onChange={(event) => {
                setSearchInput(
                  event.target.value,
                );
              }}
            />
          </form>

          <div className={styles.filters}>
            <select
              aria-label="Lọc theo vai trò"
              value={role}
              onChange={(event) => {
                setPage(1);

                setRole(
                  event.target.value as
                    | RoleCode
                    | '',
                );
              }}
            >
              <option value="">
                Tất cả vai trò
              </option>
              <option value="ADMIN">
                ADMIN
              </option>
              <option value="USER">
                USER
              </option>
            </select>

            <select
              aria-label="Lọc theo trạng thái"
              value={status}
              onChange={(event) => {
                setPage(1);

                setStatus(
                  event.target.value as
                    | UserStatus
                    | '',
                );
              }}
            >
              <option value="">
                Tất cả trạng thái
              </option>
              <option value="ACTIVE">
                Đang hoạt động
              </option>
              <option value="DISABLED">
                Đã vô hiệu hóa
              </option>
            </select>
          </div>
        </div>

        {errorMessage ? (
          <div
            className={styles.errorBanner}
            role="alert"
          >
            {errorMessage}
          </div>
        ) : null}

        <div className={styles.tableWrapper}>
          <table className={styles.userTable}>
            <thead>
              <tr>
                <th>Tài khoản</th>
                <th>Vai trò</th>
                <th>Trạng thái tài khoản</th>
                <th>Thiết bị active</th>
                <th>Lần đăng nhập cuối</th>
                <th>Ngày tạo</th>
              </tr>
            </thead>

            <tbody>
              {isLoading ? (
                <tr>
                  <td
                    colSpan={6}
                    className={
                      styles.tableMessage
                    }
                  >
                    Đang tải dữ liệu...
                  </td>
                </tr>
              ) : null}

              {!isLoading &&
              users.length === 0 ? (
                <tr>
                  <td
                    colSpan={6}
                    className={
                      styles.tableMessage
                    }
                  >
                    Không tìm thấy người dùng phù
                    hợp.
                  </td>
                </tr>
              ) : null}

              {!isLoading
                ? users.map((user) => (
                    <tr key={user.id}>
                      <td>
                        <div
                          className={
                            styles.accountCell
                          }
                        >
                          <div
                            className={
                              styles.userAvatar
                            }
                          >
                            {getInitials(
                              user.fullName,
                            )}
                          </div>

                          <div>
                            <strong>
                              {user.fullName}
                            </strong>
                            <span>
                              {user.email}
                            </span>
                          </div>
                        </div>
                      </td>

                      <td>
                        <span
                          className={
                            user.role ===
                            'ADMIN'
                              ? styles.adminRole
                              : styles.userRole
                          }
                        >
                          {user.role}
                        </span>
                      </td>

                      <td>
                        <span
                          className={
                            user.status ===
                            'ACTIVE'
                              ? styles.activeStatus
                              : styles.disabledStatus
                          }
                        >
                          {user.status ===
                          'ACTIVE'
                            ? 'Tài khoản đang mở'
                            : 'Đã vô hiệu hóa'}
                        </span>
                      </td>

                      <td>
                        <span
                          className={
                            user.hasActiveDevice
                              ? styles.activeStatus
                              : styles.disabledStatus
                          }
                        >
                          {user.hasActiveDevice
                            ? `${user.activeDeviceCount ?? 0}/${user.deviceCount ?? 0} active`
                            : `0/${user.deviceCount ?? 0} active`}
                        </span>
                      </td>

                      <td>
                        {formatDate(
                          user.lastLoginAt,
                        )}
                      </td>

                      <td>
                        {formatDate(
                          user.createdAt,
                        )}
                      </td>
                    </tr>
                  ))
                : null}
            </tbody>
          </table>
        </div>

        <footer className={styles.panelFooter}>
          <span>
            Hiển thị {users.length} trên {total}{' '}
            tài khoản
          </span>

          <div className={styles.pagination}>
            <button
              type="button"
              disabled={
                page <= 1 || isLoading
              }
              onClick={() => {
                setPage((current) =>
                  Math.max(1, current - 1),
                );
              }}
            >
              Trước
            </button>

            <span>
              {page}/
              {Math.max(totalPages, 1)}
            </span>

            <button
              type="button"
              disabled={
                isLoading ||
                totalPages === 0 ||
                page >= totalPages
              }
              onClick={() => {
                setPage((current) =>
                  current + 1,
                );
              }}
            >
              Sau
            </button>
          </div>
        </footer>
      </section>


      {isCreateOpen ? (
        <div className={styles.modalBackdrop} role="presentation">
          <section
            className={styles.createModal}
            role="dialog"
            aria-modal="true"
            aria-labelledby="create-user-title"
          >
            <div className={styles.createModalHeader}>
              <div>
                <p>Account provisioning</p>
                <h2 id="create-user-title">
                  Tạo tài khoản USER
                </h2>
                <span>
                  User không tự đăng ký. Admin cấp tài khoản, sau đó người dùng đăng nhập và liên kết thiết bị của mình.
                </span>
              </div>

              <button
                type="button"
                className={styles.closeButton}
                onClick={() => setIsCreateOpen(false)}
                aria-label="Đóng form tạo người dùng"
              >
                ×
              </button>
            </div>

            {createError ? (
              <div className={styles.errorBanner} role="alert">
                {createError}
              </div>
            ) : null}

            <form className={styles.createForm} onSubmit={handleCreateUser}>
              <label>
                <span>Họ tên</span>
                <input
                  name="fullName"
                  type="text"
                  minLength={2}
                  maxLength={100}
                  required
                  placeholder="Nguyễn Văn A"
                />
              </label>

              <label>
                <span>Email đăng nhập</span>
                <input
                  name="email"
                  type="email"
                  maxLength={254}
                  required
                  placeholder="user@example.com"
                />
              </label>

              <label>
                <span>Mật khẩu tạm</span>
                <input
                  name="password"
                  type="password"
                  minLength={12}
                  maxLength={128}
                  required
                  placeholder="Tối thiểu 12 ký tự"
                />
              </label>

              <label>
                <span>Xác nhận mật khẩu tạm</span>
                <input
                  name="confirmPassword"
                  type="password"
                  minLength={12}
                  maxLength={128}
                  required
                  placeholder="Nhập lại mật khẩu"
                />
              </label>

              <p className={styles.createHint}>
                Tài khoản được tạo tại đây luôn có vai trò USER. Không cấp tài khoản ADMIN qua form này.
              </p>

              <div className={styles.modalActions}>
                <button
                  type="button"
                  className={styles.cancelButton}
                  onClick={() => setIsCreateOpen(false)}
                  disabled={isCreatingUser}
                >
                  Hủy
                </button>

                <button
                  type="submit"
                  className={styles.createSubmitButton}
                  disabled={isCreatingUser}
                >
                  {isCreatingUser
                    ? 'Đang tạo...'
                    : 'Tạo tài khoản'}
                </button>
              </div>
            </form>
          </section>
        </div>
      ) : null}
    </PortalShell>
  );
}