import {
  ForbiddenException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import {
  RoleCode,
  UserStatus,
} from '@prisma/client';
import { compare } from 'bcryptjs';

import { UsersService } from '../users/users.service';
import type { LoginDto } from './dto/login.dto';
import type { LoginResponseDto } from './dto/login-response.dto';

interface AccessTokenPayload {
  sub: string;
  email: string;
  role: RoleCode;
}

@Injectable()
export class AuthService {
  constructor(
    private readonly usersService: UsersService,
    private readonly jwtService: JwtService,
  ) {}

  async login(
    loginDto: LoginDto,
  ): Promise<LoginResponseDto> {
    const user =
      await this.usersService.findForAuthentication(
        loginDto.email,
      );

    if (!user) {
      throw this.createInvalidCredentialsException();
    }

    const passwordMatches = await compare(
      loginDto.password,
      user.passwordHash,
    );

    if (!passwordMatches) {
      throw this.createInvalidCredentialsException();
    }

    if (user.status !== UserStatus.ACTIVE) {
      throw new ForbiddenException({
        code: 'ACCOUNT_DISABLED',
        message: 'Tài khoản đã bị vô hiệu hóa',
      });
    }

    const payload: AccessTokenPayload = {
      sub: user.id,
      email: user.email,
      role: user.role.code,
    };

    const accessToken =
      await this.jwtService.signAsync(payload);

    await this.usersService.markAuthenticated(
      user.id,
    );

    return {
      accessToken,
      tokenType: 'Bearer',
      user: {
        id: user.id,
        email: user.email,
        fullName: user.fullName,
        role: user.role.code,
      },
    };
  }

  private createInvalidCredentialsException():
    UnauthorizedException {
    return new UnauthorizedException({
      code: 'INVALID_CREDENTIALS',
      message: 'Email hoặc mật khẩu không đúng',
    });
  }
}