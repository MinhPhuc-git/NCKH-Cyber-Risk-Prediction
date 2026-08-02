export function formatDateTime(value: string | null | undefined): string {
  if (!value) return 'Chưa ghi nhận';
  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? 'Không xác định'
    : new Intl.DateTimeFormat('vi-VN', {
        dateStyle: 'short',
        timeStyle: 'short',
      }).format(date);
}

export function formatPercent(value: number | null | undefined): string {
  if (value === null || value === undefined || Number.isNaN(value)) return '—';
  return `${(value * 100).toFixed(value < 0.01 ? 2 : 1)}%`;
}

export function severityLabel(value: string | null | undefined): string {
  return value?.toUpperCase() || 'UNKNOWN';
}

export function statusLabel(value: string | null | undefined): string {
  if (!value) return 'Không xác định';
  const labels: Record<string, string> = {
    ACTIVE: 'Đang tồn tại',
    RESOLVED: 'Đã xử lý',
    UNDER_EVALUATION: 'Đang đánh giá',
    UNKNOWN: 'Không xác định',
    COMPLETED: 'Hoàn tất',
    PARTIAL: 'Một phần',
    FAILED: 'Thất bại',
    RUNNING: 'Đang chạy',
    READY: 'Sẵn sàng',
    ERROR: 'Lỗi',
    DISABLED: 'Đã tắt',
  };
  return labels[value.toUpperCase()] ?? value;
}

export function stringifyJson(value: unknown): string {
  if (value === null || value === undefined) return 'Không có dữ liệu';
  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return String(value);
  }
}
