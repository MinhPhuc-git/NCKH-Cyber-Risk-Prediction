'use client';

import {
  useState,
  type FormEvent,
} from 'react';
import { useRouter } from 'next/navigation';

import type {
  PortalLoginResponse,
} from '@/lib/api-types';
function ShieldLogo() {
  return (
    <div className="brand-logo" aria-hidden="true">
      <svg
        viewBox="0 0 48 48"
        fill="none"
        xmlns="http://www.w3.org/2000/svg"
      >
        <path
          d="M24 4L39 10V21C39 31.5 32.7 40.2 24 44C15.3 40.2 9 31.5 9 21V10L24 4Z"
          stroke="currentColor"
          strokeWidth="2.5"
        />
        <path
          d="M17 24L22 29L32 18"
          stroke="currentColor"
          strokeWidth="2.5"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
      </svg>
    </div>
  );
}

function EyeIcon({ visible }: { visible: boolean }) {
  return visible ? (
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <path d="M3 3L21 21" />
      <path d="M10.6 10.7A2 2 0 0 0 13.3 13.4" />
      <path d="M9.9 4.2A10.8 10.8 0 0 1 12 4C17.5 4 21 12 21 12A18.4 18.4 0 0 1 18.8 15.5" />
      <path d="M6.6 6.6C4.2 8.2 3 12 3 12S6.5 20 12 20C13.3 20 14.5 19.6 15.5 19" />
    </svg>
  ) : (
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <path d="M3 12S6.5 4 12 4S21 12 21 12S17.5 20 12 20S3 12 3 12Z" />
      <circle cx="12" cy="12" r="3" />
    </svg>
  );
}

export default function LoginPage() {
    const router = useRouter();
  const [showPassword, setShowPassword] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [errorMessage, setErrorMessage] =
  useState('');

  async function handleSubmit(
  event: FormEvent<HTMLFormElement>,
): Promise<void> {
  event.preventDefault();

  setErrorMessage('');
  setIsSubmitting(true);

  const formData = new FormData(
    event.currentTarget,
  );

  const email = String(
    formData.get('email') ?? '',
  );

  const password = String(
    formData.get('password') ?? '',
  );

  const remember =
    formData.get('remember') === 'on';

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
          email,
          password,
          remember,
        }),
      },
    );

    const payload =
      (await response.json()) as
        PortalLoginResponse & {
          message?: string | string[];
        };

    if (!response.ok) {
      const message =
        Array.isArray(payload.message)
          ? payload.message.join(', ')
          : payload.message;

      throw new Error(
        message ??
          'Không thể đăng nhập',
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
    <main className="login-page">
      <div className="login-background" aria-hidden="true">
        <div className="grid-overlay" />
        <div className="glow glow-one" />
        <div className="glow glow-two" />
      </div>

      <section className="login-shell">
        <div className="login-brand-panel">
          <div>
            <div className="brand-heading">
              <ShieldLogo />

              <div>
                <p className="brand-name">CYRP</p>
                <p className="brand-label">Security Platform</p>
              </div>
            </div>

            <div className="brand-content">
              <p className="eyebrow">Cybersecurity Risk Profiling</p>

              <h1>
                Cảnh báo sớm rủi ro.
                <br />
                <span>Ưu tiên xử lý chủ động.</span>
              </h1>

              <p className="brand-description">
                Nền tảng giám sát, phân tích và quản trị rủi ro an
                ninh mạng dành cho doanh nghiệp.
              </p>
            </div>
          </div>

          <div className="security-features">
            <div className="security-feature">
              <span className="feature-dot" />
              <div>
                <strong>Giám sát tập trung</strong>
                <p>Theo dõi trạng thái endpoint và hệ thống.</p>
              </div>
            </div>

            <div className="security-feature">
              <span className="feature-dot" />
              <div>
                <strong>Đánh giá rủi ro</strong>
                <p>Phân loại và ưu tiên các vấn đề bảo mật.</p>
              </div>
            </div>

            <div className="security-feature">
              <span className="feature-dot" />
              <div>
                <strong>Quản trị an toàn</strong>
                <p>Kiểm soát tài khoản và quyền truy cập.</p>
              </div>
            </div>
          </div>

          <p className="brand-footer">
            CYRP Platform · Internal Security Portal
          </p>
        </div>

        <div className="login-form-panel">
          <div className="login-card">
            <div className="mobile-brand">
              <ShieldLogo />
              <span>CYRP</span>
            </div>

            <div className="login-header">
              <p className="eyebrow">Secure access</p>
              <h2>Đăng nhập hệ thống</h2>
              <p>
                Nhập thông tin tài khoản được cấp để truy cập
                CYRP Platform.
              </p>
            </div>

            <form className="login-form" onSubmit={handleSubmit}>
              <div className="form-field">
                <label htmlFor="email">Email</label>

                <div className="input-wrapper">
                  <svg viewBox="0 0 24 24" aria-hidden="true">
                    <rect x="3" y="5" width="18" height="14" rx="2" />
                    <path d="M3 7L12 13L21 7" />
                  </svg>

                  <input
                    id="email"
                    name="email"
                    type="email"
                    placeholder="admin@cyrp.local"
                    autoComplete="email"
                    required
                  />
                </div>
              </div>

              <div className="form-field">
                <div className="field-heading">
                  <label htmlFor="password">Mật khẩu</label>
                </div>

                <div className="input-wrapper">
                  <svg viewBox="0 0 24 24" aria-hidden="true">
                    <rect x="5" y="10" width="14" height="10" rx="2" />
                    <path d="M8 10V7A4 4 0 0 1 16 7V10" />
                  </svg>

                  <input
                    id="password"
                    name="password"
                    type={showPassword ? 'text' : 'password'}
                    placeholder="Nhập mật khẩu"
                    autoComplete="current-password"
                    required
                  />

                  <button
                    className="password-toggle"
                    type="button"
                    aria-label={
                      showPassword
                        ? 'Ẩn mật khẩu'
                        : 'Hiện mật khẩu'
                    }
                    onClick={() => {
                      setShowPassword((current) => !current);
                    }}
                  >
                    <EyeIcon visible={showPassword} />
                  </button>
                </div>
              </div>

              <label className="remember-option">
                <input type="checkbox" name="remember" />
                <span>Ghi nhớ phiên đăng nhập</span>
              </label>

              {errorMessage ? (
                <div
                  className="login-error"
                  role="alert"
                >
                  {errorMessage}
                </div>
              ) : null}

              <button
                className="login-button"
                type="submit"
                disabled={isSubmitting}
              >
                {isSubmitting ? (
                  <>
                    <span className="button-spinner" />
                    Đang kiểm tra...
                  </>
                ) : (
                  <>
                    Đăng nhập
                    <svg viewBox="0 0 24 24" aria-hidden="true">
                      <path d="M5 12H19" />
                      <path d="M13 6L19 12L13 18" />
                    </svg>
                  </>
                )}
              </button>

              
            </form>

            <div className="login-security-note">
              <svg viewBox="0 0 24 24" aria-hidden="true">
                <path d="M12 3L19 6V11C19 15.9 16.1 20 12 22C7.9 20 5 15.9 5 11V6L12 3Z" />
                <path d="M9 12L11 14L15 10" />
              </svg>

              <p>
                Kết nối được bảo vệ. Hoạt động đăng nhập sẽ được
                ghi nhận nhằm bảo đảm an toàn hệ thống.
              </p>
            </div>
          </div>

          <p className="portal-footer">
            © 2026 CYRP Platform. Authorized access only.
          </p>
        </div>
      </section>
    </main>
  );
}