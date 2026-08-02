import { ConfigService } from '@nestjs/config';
import { DatabaseService } from '../../database/database.service';
import { HealthService } from './health.service';

describe('HealthService', () => {
  let healthService: HealthService;
  let databaseService: Partial<DatabaseService>;
  let configService: Partial<ConfigService>;

  beforeEach(() => {
    databaseService = {
      ping: jest.fn()
    };

    configService = {
      get: jest.fn((key: string) => {
        if (key === 'app.name') return 'cyrp-api';
        if (key === 'app.version') return '0.1.0';
        if (key === 'app.env') return 'development';
        return undefined;
      })
    };

    healthService = new HealthService(databaseService as DatabaseService, configService as ConfigService);
  });

  it('returns healthy status when database is reachable', async () => {
    (databaseService.ping as jest.Mock).mockResolvedValue(1);
    const health = await healthService.getHealth();

    expect(health.status).toBe('ok');
    expect(health.database.status).toBe('up');
    expect(health.database.latencyMs).toBeGreaterThanOrEqual(0);
    expect(health.service).toBe('cyrp-api');
  });

  it('returns error status when database is not reachable', async () => {
    (databaseService.ping as jest.Mock).mockRejectedValue(new Error('connection failed'));

    const health = await healthService.getHealth();

    expect(health.status).toBe('error');
    expect(health.database.status).toBe('down');
    expect(health.database.latencyMs).toBeNull();
  });
});
