import type {
  INestApplication,
} from '@nestjs/common';
import {
  RoleCode,
  UserStatus,
} from '@prisma/client';
import { Test } from '@nestjs/testing';
import { hashSync } from 'bcryptjs';
import request from 'supertest';

import { AppModule } from '../src/app.module';
import {
  setupApp,
} from '../src/bootstrap/application.setup';
import {
  DatabaseService,
} from '../src/database/database.service';

describe('UsersController (e2e)', () => {
  let app: INestApplication;

  const password = 'TestPassword123!';

  const adminUser = {
    id: '11111111-1111-4111-8111-111111111111',
    email: 'admin@cyrp.local',
    fullName: 'System Administrator',
    passwordHash: hashSync(password, 4),
    status: UserStatus.ACTIVE,
    roleId:
      'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
    lastLoginAt: null,
    createdAt: new Date(),
    updatedAt: new Date(),
    role: {
      id:
        'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
      code: RoleCode.ADMIN,
      name: 'Administrator',
      description: null,
      createdAt: new Date(),
      updatedAt: new Date(),
    },
  };

  const normalUser = {
    ...adminUser,
    id: '22222222-2222-4222-8222-222222222222',
    email: 'user@cyrp.local',
    fullName: 'Test User',
    roleId:
      'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
    role: {
      ...adminUser.role,
      id:
        'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
      code: RoleCode.USER,
      name: 'User',
    },
  };

  const findUnique = jest.fn(
    ({
      where,
    }: {
      where: {
        id?: string;
        email?: string;
      };
    }) => {
      if (
        where.id === adminUser.id ||
        where.email === adminUser.email
      ) {
        return Promise.resolve(adminUser);
      }

      if (
        where.id === normalUser.id ||
        where.email === normalUser.email
      ) {
        return Promise.resolve(normalUser);
      }

      return Promise.resolve(null);
    },
  );

  const mockDatabaseService = {
    ping: jest.fn().mockResolvedValue(1),
    deviceSyncLease: {
      deleteMany: jest.fn().mockResolvedValue({ count: 0 }),
    },
    syncRun: {
      updateMany: jest.fn().mockResolvedValue({ count: 0 }),
    },

    user: {
      findUnique,

      findMany: jest
        .fn()
        .mockResolvedValue([
          {
            id: adminUser.id,
            email: adminUser.email,
            fullName: adminUser.fullName,
            status: adminUser.status,
            lastLoginAt:
              adminUser.lastLoginAt,
            createdAt:
              adminUser.createdAt,
            role: {
              code:
                RoleCode.ADMIN,
            },
          },
          {
            id: normalUser.id,
            email: normalUser.email,
            fullName:
              normalUser.fullName,
            status:
              normalUser.status,
            lastLoginAt:
              normalUser.lastLoginAt,
            createdAt:
              normalUser.createdAt,
            role: {
              code: RoleCode.USER,
            },
          },
        ]),

      count: jest
        .fn()
        .mockResolvedValue(2),

      update: jest
        .fn()
        .mockResolvedValue(adminUser),
    },

    $transaction: jest.fn(
      async (
        operations: Promise<unknown>[],
      ) => Promise.all(operations),
    ),
  };

  beforeAll(async () => {
    process.env.NODE_ENV = 'test';
    process.env.DATABASE_URL =
      'postgresql://test:test@localhost:5432/test';
    process.env.SWAGGER_ENABLED = 'false';
    process.env.JWT_SECRET =
      'test-jwt-secret-at-least-32-characters-long';
    process.env.JWT_EXPIRES_IN = '15m';

    const moduleRef =
      await Test.createTestingModule({
        imports: [
          AppModule,
        ],
      })
        .overrideProvider(DatabaseService)
        .useValue(mockDatabaseService)
        .compile();

    app = moduleRef.createNestApplication();

    setupApp(app);

    await app.init();
  });

  afterAll(async () => {
    await app.close();
  });

  async function login(
    email: string,
  ): Promise<string> {
    const response = await request(
      app.getHttpServer(),
    )
      .post('/api/v1/auth/login')
      .send({
        email,
        password,
      })
      .expect(200);

    return response.body.accessToken as string;
  }

  it('allows ADMIN to list users', async () => {
    const accessToken =
      await login(adminUser.email);

    const response = await request(
      app.getHttpServer(),
    )
      .get('/api/v1/users')
      .set(
        'Authorization',
        `Bearer ${accessToken}`,
      )
      .expect(200);

    expect(response.body.pagination).toEqual({
      page: 1,
      limit: 20,
      total: 2,
      totalPages: 1,
    });

    expect(response.body.data).toHaveLength(2);

    expect(
      response.body.data[0],
    ).not.toHaveProperty('passwordHash');
  });

  it('rejects USER role', async () => {
    const accessToken =
      await login(normalUser.email);

    const response = await request(
      app.getHttpServer(),
    )
      .get('/api/v1/users')
      .set(
        'Authorization',
        `Bearer ${accessToken}`,
      )
      .expect(403);

    expect(response.body.code).toBe(
      'ROLE_FORBIDDEN',
    );
  });

  it('rejects requests without a token', async () => {
    const response = await request(
      app.getHttpServer(),
    )
      .get('/api/v1/users')
      .expect(401);

    expect(response.body.code).toBe(
      'AUTH_TOKEN_MISSING',
    );
  });
});