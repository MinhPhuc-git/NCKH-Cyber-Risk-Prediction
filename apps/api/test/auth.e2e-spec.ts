import type { INestApplication } from '@nestjs/common';
import {
  RoleCode,
  UserStatus,
} from '@prisma/client';
import { Test } from '@nestjs/testing';
import { hashSync } from 'bcryptjs';
import request from 'supertest';

import { AppModule } from '../src/app.module';
import { setupApp } from '../src/bootstrap/application.setup';
import { DatabaseService } from '../src/database/database.service';

describe('AuthController (e2e)', () => {
  let app: INestApplication;

  const password = 'AdminPassword123!';

  const testUser = {
    id: '2df130c6-7c35-4462-bc6d-4487b453eeb0',
    email: 'admin@cyrp.local',
    fullName: 'System Administrator',
    passwordHash: hashSync(password, 4),
    status: UserStatus.ACTIVE,
    roleId: '7b358110-9261-41f8-b7da-36aac2a30826',
    lastLoginAt: null,
    createdAt: new Date(),
    updatedAt: new Date(),
    role: {
      id: '7b358110-9261-41f8-b7da-36aac2a30826',
      code: RoleCode.ADMIN,
      name: 'Administrator',
      description: null,
      createdAt: new Date(),
      updatedAt: new Date(),
    },
  };

  const mockDatabaseService = {
    ping: jest.fn().mockResolvedValue(1),
    deviceSyncLease: {
      deleteMany: jest.fn().mockResolvedValue({ count: 0 }),
    },
    syncRun: {
      updateMany: jest.fn().mockResolvedValue({ count: 0 }),
    },

    user: {
      findUnique: jest.fn().mockImplementation(
        ({
          where,
        }: {
          where: {
            id?: string;
            email?: string;
          };
        }) => {
          if (
            where.id === testUser.id ||
            where.email === testUser.email
          ) {
            return Promise.resolve(testUser);
          }

          return Promise.resolve(null);
        },
      ),

      update: jest.fn().mockResolvedValue(testUser),
    },
  };

  beforeAll(async () => {
    process.env.NODE_ENV = 'test';
    process.env.DATABASE_URL =
      'postgresql://test:test@localhost:5432/test';
    process.env.SWAGGER_ENABLED = 'false';
    process.env.JWT_SECRET =
      'test-jwt-secret-at-least-32-characters-long';
    process.env.JWT_EXPIRES_IN = '15m';

    const moduleRef = await Test.createTestingModule({
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

  it('logs in and returns the current user', async () => {
    const loginResponse = await request(
      app.getHttpServer(),
    )
      .post('/api/v1/auth/login')
      .send({
        email: testUser.email,
        password,
      })
      .expect(200);

    expect(
      loginResponse.body.accessToken,
    ).toEqual(expect.any(String));

    const accessToken =
      loginResponse.body.accessToken as string;

    const meResponse = await request(
      app.getHttpServer(),
    )
      .get('/api/v1/auth/me')
      .set(
        'Authorization',
        `Bearer ${accessToken}`,
      )
      .expect(200);

    expect(meResponse.body).toEqual({
      id: testUser.id,
      email: testUser.email,
      fullName: testUser.fullName,
      role: RoleCode.ADMIN,
    });
  });

  it('rejects requests without an access token', async () => {
    const response = await request(
      app.getHttpServer(),
    )
      .get('/api/v1/auth/me')
      .expect(401);

    expect(response.body.code).toBe(
      'AUTH_TOKEN_MISSING',
    );
  });

  it('rejects an invalid access token', async () => {
    const response = await request(
      app.getHttpServer(),
    )
      .get('/api/v1/auth/me')
      .set(
        'Authorization',
        'Bearer invalid-token',
      )
      .expect(401);

    expect(response.body.code).toBe(
      'AUTH_TOKEN_INVALID',
    );
  });
});