import {
  ForbiddenException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import type {
  CanActivate,
  ExecutionContext,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Reflector } from '@nestjs/core';
import { UserStatus } from '@prisma/client';

import { UsersService } from '../../users/users.service';
import type {
  AccessTokenPayload,
  AuthenticatedRequest,
} from '../auth.types';
import {
  IS_PUBLIC_KEY,
} from '../decorators/public.decorator';

@Injectable()
export class JwtAuthGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    private readonly jwtService: JwtService,
    private readonly usersService: UsersService,
  ) {}

  async canActivate(
    context: ExecutionContext,
  ): Promise<boolean> {
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

    const request = context
      .switchToHttp()
      .getRequest<AuthenticatedRequest>();

    const accessToken =
      this.extractBearerToken(
        request.headers.authorization,
      );

    if (!accessToken) {
      throw new UnauthorizedException({
        code: 'AUTH_TOKEN_MISSING',
        message: 'Thiếu access token',
      });
    }

    let payload: AccessTokenPayload;

    try {
      payload =
        await this.jwtService.verifyAsync<AccessTokenPayload>(
          accessToken,
        );
    } catch {
      throw this.createInvalidTokenException();
    }

    if (
      typeof payload.sub !== 'string' ||
      payload.sub.length === 0
    ) {
      throw this.createInvalidTokenException();
    }

    const user =
      await this.usersService.findForAuthorization(
        payload.sub,
      );

    if (!user) {
      throw this.createInvalidTokenException();
    }

    if (user.status !== UserStatus.ACTIVE) {
      throw new ForbiddenException({
        code: 'ACCOUNT_DISABLED',
        message:
          'Tài khoản đã bị vô hiệu hóa',
      });
    }

    request.user = {
      id: user.id,
      email: user.email,
      fullName: user.fullName,
      role: user.role.code,
    };

    return true;
  }

  private extractBearerToken(
    authorizationHeader:
      | string
      | undefined,
  ): string | undefined {
    if (!authorizationHeader) {
      return undefined;
    }

    const [tokenType, token] =
      authorizationHeader
        .trim()
        .split(/\s+/);

    if (
      tokenType !== 'Bearer' ||
      !token
    ) {
      return undefined;
    }

    return token;
  }

  private createInvalidTokenException():
    UnauthorizedException {
    return new UnauthorizedException({
      code: 'AUTH_TOKEN_INVALID',
      message:
        'Access token không hợp lệ hoặc đã hết hạn',
    });
  }
}