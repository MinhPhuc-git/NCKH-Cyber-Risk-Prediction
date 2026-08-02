import {
  ConflictException,
  Injectable,
} from '@nestjs/common';
import {
  RoleCode,
} from '@prisma/client';
import { hash } from 'bcryptjs';

import type {
  CreateUserDto,
} from './dto/create-user.dto';
import type {
  CreateUserResponseDto,
} from './dto/create-user-response.dto';
import type {
  ListUsersQueryDto,
} from './dto/list-users-query.dto';
import type {
  ListUsersResponseDto,
} from './dto/list-users-response.dto';
import { UsersRepository } from './users.repository';
import type {
  UserWithRole,
} from './users.types';

@Injectable()
export class UsersService {
  constructor(
    private readonly usersRepository:
      UsersRepository,
  ) {}

  findForAuthentication(
    email: string,
  ): Promise<UserWithRole | null> {
    const normalizedEmail = email
      .trim()
      .toLowerCase();

    return this.usersRepository.findByEmail(
      normalizedEmail,
    );
  }

  findForAuthorization(
    userId: string,
  ): Promise<UserWithRole | null> {
    return this.usersRepository.findById(
      userId,
    );
  }

  async list(
    query: ListUsersQueryDto,
  ): Promise<ListUsersResponseDto> {
    const page = query.page ?? 1;
    const limit = query.limit ?? 20;

    const search =
      query.search?.trim() || undefined;

    const [result, summary] =
      await Promise.all([
        this.usersRepository.findMany({
          page,
          limit,
          search,
          role: query.role,
          status: query.status,
        }),
        this.usersRepository.getSummary(),
      ]);

    return {
      data: result.users.map((user) => {
        const activeDeviceCount =
          user.devices.filter(
            (device) =>
              device.wazuhBinding
                ?.lastKnownStatus === 'active',
          ).length;

        return {
          id: user.id,
          email: user.email,
          fullName: user.fullName,
          role: user.role.code,
          status: user.status,
          lastLoginAt: user.lastLoginAt,
          createdAt: user.createdAt,
          deviceCount: user.devices.length,
          activeDeviceCount,
          hasActiveDevice:
            activeDeviceCount > 0,
        };
      }),
      summary,
      pagination: {
        page,
        limit,
        total: result.total,
        totalPages:
          result.total === 0
            ? 0
            : Math.ceil(
                result.total / limit,
              ),
      },
    };
  }

  async createByAdmin(
    createUserDto: CreateUserDto,
  ): Promise<CreateUserResponseDto> {
    const email = createUserDto.email
      .trim()
      .toLowerCase();
    const fullName =
      createUserDto.fullName.trim();

    const existing =
      await this.usersRepository.findByEmail(
        email,
      );

    if (existing) {
      throw new ConflictException({
        code: 'USER_EMAIL_ALREADY_EXISTS',
        message:
          'Email này đã tồn tại trong hệ thống',
      });
    }

    const passwordHash = await hash(
      createUserDto.password,
      12,
    );

    const user =
      await this.usersRepository.createUser({
        email,
        fullName,
        passwordHash,
        roleCode: RoleCode.USER,
      });

    return {
      id: user.id,
      email: user.email,
      fullName: user.fullName,
      role: user.role.code,
      status: user.status,
      createdAt: user.createdAt,
    };
  }

  markAuthenticated(
    userId: string,
  ): Promise<void> {
    return this.usersRepository
      .updateLastLoginAt(userId);
  }
}
