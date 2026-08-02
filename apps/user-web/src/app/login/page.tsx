'use client';

import {
  useRouter,
  useSearchParams,
} from 'next/navigation';
import {
  Suspense,
  useState,
  type FormEvent,
} from 'react';

import { AuthShell } from '@/components/auth-shell';
import styles from '@/components/auth-shell.module.css';
import type { ApiErrorResponse } from '@/lib/api-types';

function LoginForm() {
  const router = useRouter();
  const searchParams = useSearchParams();

  const [isSubmitting, setIsSubmitting] =
    useState(false);

  const [errorMessage, setErrorMessage] =
    useState('');

  const registered =
    searchParams.get('registered') === '1';

  const adminOnlyRegistration =
    searchParams.get('registration') === 'admin-only';

  async function handleSubmit(
    event: FormEvent<HTMLFormElement>,
  ): Promise<void> {
    event.preventDefault();

    setErrorMessage('');
    setIsSubmitting(true);

    const formData = new FormData(
      event.currentTarget,
    );

    try {
      const response = await fetch(
        '/api/auth/login',
        {
          method: 'POST',
          headers: {
            'Content-Type':
              'application/json',
          },
          body: JSON.stringify({
            email: String(
              formData.get('email') ?? '',
            ),
            password: String(
              formData.get('password') ?? '',
            ),
            remember:
              formData.get('remember') ===
              'on',
          }),
        },
      );

      const payload =
        (await response.json()) as
          ApiErrorResponse;

      if (!response.ok) {
        const message =
          Array.isArray(payload.message)
            ? payload.message.join(', ')
            : payload.message;

        throw new Error(
          message ?? 'Không thể đăng nhập',
        );
      }

      router.replace('/dashboard');
      router.refresh();
    } catch (error: unknown) {
      setErrorMessage(
        error instanceof Error
          ? error.message
          : 'Không thể kết nối máy chủ',
      );
    } finally {
      setIsSubmitting(false);
    }
  }

  return (
    <AuthShell
      active="login"
      title="Đăng nhập User Portal"
      description="Sử dụng tài khoản USER đã đăng ký để truy cập dữ liệu thiết bị của bạn."
    >
      <form
        className={styles.form}
        onSubmit={handleSubmit}
      >
        {registered ? (
          <div className={styles.success}>
            Đăng ký thành công. Bạn có thể đăng
            nhập bằng tài khoản vừa tạo.
          </div>
        ) : null}

        {adminOnlyRegistration ? (
          <div className={styles.success}>
            Tài khoản User hiện được quản trị viên cấp phát.
            Vui lòng đăng nhập bằng tài khoản đã được cấp.
          </div>
        ) : null}

        {errorMessage ? (
          <div
            className={styles.error}
            role="alert"
          >
            {errorMessage}
          </div>
        ) : null}

        <div className={styles.field}>
          <label htmlFor="email">
            Email
          </label>

          <input
            id="email"
            name="email"
            type="email"
            autoComplete="email"
            placeholder="user@example.com"
            required
          />
        </div>

        <div className={styles.field}>
          <label htmlFor="password">
            Mật khẩu
          </label>

          <input
            id="password"
            name="password"
            type="password"
            autoComplete="current-password"
            placeholder="Nhập mật khẩu"
            required
          />
        </div>

        <div className={styles.formOptions}>
          <label className={styles.remember}>
            <input
              name="remember"
              type="checkbox"
            />

            Ghi nhớ phiên đăng nhập
          </label>
        </div>

        <button
          type="submit"
          className={styles.submitButton}
          disabled={isSubmitting}
        >
          {isSubmitting
            ? 'Đang đăng nhập...'
            : 'Đăng nhập'}
        </button>
      </form>
    </AuthShell>
  );
}

function LoginFallback() {
  return (
    <AuthShell
      active="login"
      title="Đăng nhập User Portal"
      description="Đang chuẩn bị biểu mẫu đăng nhập."
    >
      <p className={styles.helper}>
        Đang tải biểu mẫu đăng nhập...
      </p>
    </AuthShell>
  );
}

export default function LoginPage() {
  return (
    <Suspense fallback={<LoginFallback />}>
      <LoginForm />
    </Suspense>
  );
}