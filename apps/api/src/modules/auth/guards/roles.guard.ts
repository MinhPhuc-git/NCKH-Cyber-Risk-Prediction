import {
  ForbiddenException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import type {
  CanActivate,
  ExecutionContext,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import type { RoleCode } from '@prisma/client';

import type { AuthenticatedRequest } from '../auth.types';
import {
  IS_PUBLIC_KEY,
} from '../decorators/public.decorator';
import {
  ROLES_KEY,
} from '../decorators/roles.decorator';

@Injectable()
export class RolesGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
  ) {}

  canActivate(
    context: ExecutionContext,
  ): boolean {
    const isPublic =
      this.reflector.getAllAndOverride<boolean>(
        IS_PUBLIC_KEY,
        [
          context.getHandler(),
          context.getClass(),
        ],
      );

    if (isPublic) {
      return true;
    }

    const requiredRoles =
      this.reflector.getAllAndOverride<RoleCode[]>(
        ROLES_KEY,
        [
          context.getHandler(),
          context.getClass(),
        ],
      );

    if (
      !requiredRoles ||
      requiredRoles.length === 0
    ) {
      return true;
    }

    const request = context
      .switchToHttp()
      .getRequest<AuthenticatedRequest>();

    if (!request.user) {
      throw new UnauthorizedException({
        code: 'AUTH_CONTEXT_MISSING',
        message:
          'Không tìm thấy ngữ cảnh xác thực',
      });
    }

    const hasRequiredRole =
      requiredRoles.includes(
        request.user.role,
      );

    if (!hasRequiredRole) {
      throw new ForbiddenException({
        code: 'ROLE_FORBIDDEN',
        message:
          'Bạn không có quyền truy cập tài nguyên này',
      });
    }

    return true;
  }
}