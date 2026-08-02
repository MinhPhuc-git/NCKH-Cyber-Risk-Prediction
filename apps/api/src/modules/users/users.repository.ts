import { Injectable } from '@nestjs/common';
import {
  Prisma,
  RoleCode,
  UserStatus,
} from '@prisma/client';

import { DatabaseService } from '../../database/database.service';
import type {
  UserListRecord,
  UserWithRole,
} from './users.types';
import {
  userListSelect,
} from './users.types';

export interface ListUsersRepositoryParams {
  page: number;
  limit: number;
  search?: string;
  role?: RoleCode;
  status?: UserStatus;
}

export interface ListUsersRepositoryResult {
  users: UserListRecord[];
  total: number;
}

export interface CreateUserRepositoryParams {
  email: string;
  fullName: string;
  passwordHash: string;
  roleCode: RoleCode;
}

@Injectable()
export class UsersRepository {
  constructor(
    private readonly database: DatabaseService,
  ) {}

  findByEmail(
    email: string,
  ): Promise<UserWithRole | null> {
    return this.database.user.findUnique({
      where: {
        email,
      },
      include: {
        role: true,
      },
    });
  }

  findById(
    userId: string,
  ): Promise<UserWithRole | null> {
    return this.database.user.findUnique({
      where: {
        id: userId,
      },
      include: {
        role: true,
      },
    });
  }

  async findMany(
    params: ListUsersRepositoryParams,
  ): Promise<ListUsersRepositoryResult> {
    const where: Prisma.UserWhereInput = {};

    if (params.search) {
      where.OR = [
        {
          email: {
            contains: params.search,
            mode: 'insensitive',
          },
        },
        {
          fullName: {
            contains: params.search,
            mode: 'insensitive',
          },
        },
      ];
    }

    if (params.status) {
      where.status = params.status;
    }

    if (params.role) {
      where.role = {
        is: {
          code: params.role,
        },
      };
    }

    const skip =
      (params.page - 1) * params.limit;

    const [users, total] =
      await this.database.$transaction([
        this.database.user.findMany({
          where,
          select: userListSelect,
          orderBy: [
            {
              createdAt: 'desc',
            },
            {
              id: 'asc',
            },
          ],
          skip,
          take: params.limit,
        }),
        this.database.user.count({
          where,
        }),
      ]);

    return {
      users,
      total,
    };
  }

  async getSummary() {
    const [
      total,
      activeAccounts,
      disabledAccounts,
      activeDeviceUsers,
    ] = await this.database.$transaction([
      this.database.user.count(),
      this.database.user.count({
        where: {
          status: UserStatus.ACTIVE,
        },
      }),
      this.database.user.count({
        where: {
          status: UserStatus.DISABLED,
        },
      }),
      this.database.user.count({
        where: {
          devices: {
            some: {
              wazuhBinding: {
                is: {
                  lastKnownStatus: 'active',
                },
              },
            },
          },
        },
      }),
    ]);

    return {
      total,
      activeAccounts,
      disabledAccounts,
      usersWithActiveDevices:
        activeDeviceUsers,
      usersWithoutActiveDevices:
        Math.max(total - activeDeviceUsers, 0),
    };
  }

  async createUser(
    params: CreateUserRepositoryParams,
  ): Promise<UserWithRole> {
    const role =
      await this.database.role.findUnique({
        where: {
          code: params.roleCode,
        },
      });

    if (!role) {
      throw new Error(
        `Role ${params.roleCode} was not found`,
      );
    }

    return this.database.user.create({
      data: {
        email: params.email,
        fullName: params.fullName,
        passwordHash: params.passwordHash,
        status: UserStatus.ACTIVE,
        roleId: role.id,
      },
      include: {
        role: true,
      },
    });
  }

  async updateLastLoginAt(
    userId: string,
  ): Promise<void> {
    await this.database.user.update({
      where: {
        id: userId,
      },
      data: {
        lastLoginAt: new Date(),
      },
    });
  }
}
