import {
  ConflictException,
  Injectable,
  InternalServerErrorException,
} from '@nestjs/common';
import {
  Prisma,
  RoleCode,
  UserStatus,
} from '@prisma/client';
import { hash } from 'bcryptjs';

import { DatabaseService } from '../../database/database.service';
import type { RegisterUserDto } from './dto/register-user.dto';
import type { RegisterUserResponseDto } from './dto/register-user-response.dto';

@Injectable()
export class RegistrationService {
  constructor(
    private readonly database: DatabaseService,
  ) {}

  async register(
    dto: RegisterUserDto,
  ): Promise<RegisterUserResponseDto> {
    const email = dto.email
      .trim()
      .toLowerCase();

    const existingUser =
      await this.database.user.findUnique({
        where: {
          email,
        },
        select: {
          id: true,
        },
      });

    if (existingUser) {
      throw this.createEmailConflict();
    }

    const userRole =
      await this.database.role.findUnique({
        where: {
          code: RoleCode.USER,
        },
        select: {
          id: true,
        },
      });

    if (!userRole) {
      throw new InternalServerErrorException({
        code: 'USER_ROLE_NOT_CONFIGURED',
        message:
          'Vai trò USER chưa được cấu hình',
      });
    }

    const passwordHash = await hash(
      dto.password,
      12,
    );

    try {
      const user =
        await this.database.user.create({
          data: {
            email,
            fullName: dto.fullName.trim(),
            passwordHash,
            roleId: userRole.id,
            status: UserStatus.ACTIVE,
          },
          select: {
            id: true,
            email: true,
            fullName: true,
            status: true,
            createdAt: true,
            role: {
              select: {
                code: true,
              },
            },
          },
        });

      return {
        id: user.id,
        email: user.email,
        fullName: user.fullName,
        role: user.role.code,
        status: user.status,
        createdAt: user.createdAt,
      };
    } catch (error: unknown) {
      if (
        error instanceof
          Prisma.PrismaClientKnownRequestError &&
        error.code === 'P2002'
      ) {
        throw this.createEmailConflict();
      }

      throw error;
    }
  }

  private createEmailConflict():
    ConflictException {
    return new ConflictException({
      code: 'EMAIL_ALREADY_EXISTS',
      message:
        'Email này đã được sử dụng',
    });
  }
}
