import {
  createParamDecorator,
  UnauthorizedException,
} from '@nestjs/common';
import type { ExecutionContext } from '@nestjs/common';

import type {
  AuthenticatedRequest,
  AuthenticatedUser,
} from '../auth.types';

export const CurrentUser = createParamDecorator(
  (
    _data: unknown,
    context: ExecutionContext,
  ): AuthenticatedUser => {
    const request = context
      .switchToHttp()
      .getRequest<AuthenticatedRequest>();

    if (!request.user) {
      throw new UnauthorizedException({
        code: 'AUTH_CONTEXT_MISSING',
        message: 'Không tìm thấy ngữ cảnh xác thực',
      });
    }

    return request.user;
  },
);