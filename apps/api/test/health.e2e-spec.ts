import { INestApplication } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import request from 'supertest';
import { AppModule } from '../src/app.module';
import { setupApp } from '../src/bootstrap/application.setup';
import { DatabaseService } from '../src/database/database.service';

const mockDatabaseService = {
  ping: jest.fn().mockResolvedValue(1),
  deviceSyncLease: {
    deleteMany: jest.fn().mockResolvedValue({ count: 0 }),
  },
  syncRun: {
    updateMany: jest.fn().mockResolvedValue({ count: 0 }),
  },
};

describe('HealthController (e2e)', () => {
  let app: INestApplication;

  beforeAll(async () => {
  process.env.NODE_ENV = 'test';
  process.env.DATABASE_URL =
    'postgresql://test:test@localhost:5432/test';
  process.env.SWAGGER_ENABLED = 'false';
  process.env.JWT_SECRET =
    'test-jwt-secret-at-least-32-characters-long';
  process.env.JWT_EXPIRES_IN = '15m';

  const moduleRef = await Test.createTestingModule({
    imports: [AppModule],
  })
    .overrideProvider(DatabaseService)
    .useValue(mockDatabaseService)
    .compile();

  app = moduleRef.createNestApplication();

  setupApp(app);

  await app.init();
});

  afterAll(async () => {
    if (app) {
      await app.close();
    }
  });

  it('/api/v1/health (GET) returns 200', async () => {
    const response = await request(app.getHttpServer())
      .get('/api/v1/health');

    expect(response.status).toBe(200);

    expect(response.body).toMatchObject({
      status: 'ok',
      service: 'cyrp-api',
      version: '0.1.0',
      environment: 'test',
      database: {
        status: 'up',
      },
    });
  });
});