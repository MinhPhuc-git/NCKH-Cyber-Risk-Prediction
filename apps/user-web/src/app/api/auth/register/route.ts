import { NextResponse } from 'next/server';

export async function POST(): Promise<NextResponse> {
  return NextResponse.json(
    {
      code: 'PUBLIC_REGISTRATION_DISABLED',
      message:
        'Hệ thống doanh nghiệp không cho phép người dùng tự đăng ký. Vui lòng liên hệ quản trị viên để được cấp tài khoản.',
    },
    {
      status: 403,
    },
  );
}
