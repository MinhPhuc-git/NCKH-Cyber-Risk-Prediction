import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { DatabaseService } from '../../database/database.service';

export interface HealthResponse {
  status: 'ok' | 'error';
  service: string;
  version: string;
  environment: string;
  timestamp: string;
  uptimeSeconds: number;
  database: {
    status: 'up' | 'down';
    latencyMs: number | null;
  };
}

@Injectable()
export class HealthService {
    constructor(
  private readonly database: DatabaseService,
  private readonly configService: ConfigService,
) {}

  async getHealth(): Promise<HealthResponse> {
    let databaseStatus: 'up' | 'down' = 'up';
    let latencyMs: number | null = null;

    try {
  latencyMs = await this.database.ping();
} catch {
  databaseStatus = 'down';
  latencyMs = null;
}

    return {
      status: databaseStatus === 'up' ? 'ok' : 'error',
      service: this.configService.get<string>('app.name') ?? 'cyrp-api',
      version: this.configService.get<string>('app.version') ?? '0.1.0',
      environment: this.configService.get<string>('app.env') ?? 'development',
      timestamp: new Date().toISOString(),
      uptimeSeconds: Math.floor(process.uptime()),
      database: {
        status: databaseStatus,
        latencyMs
      }
    };
  }
}
