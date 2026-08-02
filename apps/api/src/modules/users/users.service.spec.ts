import {
  RoleCode,
  UserStatus,
} from '@prisma/client';

import { UsersRepository } from './users.repository';
import { UsersService } from './users.service';

describe('UsersService', () => {
  const usersRepositoryMock = {
    findByEmail: jest.fn(),
    findById: jest.fn(),
    findMany: jest.fn(),
    updateLastLoginAt: jest.fn(),
  };

  const service = new UsersService(
    usersRepositoryMock as unknown as
      UsersRepository,
  );

  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('returns a paginated user list', async () => {
    usersRepositoryMock.findMany
      .mockResolvedValue({
        users: [
          {
            id: 'admin-id',
            email: 'admin@cyrp.local',
            fullName:
              'System Administrator',
            role: {
              code: RoleCode.ADMIN,
            },
            status: UserStatus.ACTIVE,
            lastLoginAt: null,
            createdAt:
              new Date(
                '2026-06-26T00:00:00.000Z',
              ),
          },
        ],
        total: 1,
      });

    const result = await service.list({
      page: 1,
      limit: 20,
    });

    expect(result.pagination).toEqual({
      page: 1,
      limit: 20,
      total: 1,
      totalPages: 1,
    });

    expect(result.data).toHaveLength(1);

    expect(result.data[0]).toEqual({
      id: 'admin-id',
      email: 'admin@cyrp.local',
      fullName: 'System Administrator',
      role: RoleCode.ADMIN,
      status: UserStatus.ACTIVE,
      lastLoginAt: null,
      createdAt:
        new Date(
          '2026-06-26T00:00:00.000Z',
        ),
    });
  });

  it('returns zero total pages for an empty list', async () => {
    usersRepositoryMock.findMany
      .mockResolvedValue({
        users: [],
        total: 0,
      });

    const result = await service.list({
      page: 1,
      limit: 20,
    });

    expect(result).toEqual({
      data: [],
      pagination: {
        page: 1,
        limit: 20,
        total: 0,
        totalPages: 0,
      },
    });
  });
});