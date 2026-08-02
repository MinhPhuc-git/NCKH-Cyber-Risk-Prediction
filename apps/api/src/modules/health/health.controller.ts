import { Controller, Get, HttpCode, Res } from '@nestjs/common';
import { Response } from 'express';
import { HealthService } from './health.service';
import {
  Public,
} from '../auth/decorators/public.decorator';
@Public()
@Controller('health')
export class HealthController {
  constructor(private readonly healthService: HealthService) {}

  @Get()
  @HttpCode(200)
  async getHealth(@Res({ passthrough: true }) response: Response) {
    const health = await this.healthService.getHealth();

    if (health.database.status !== 'up') {
      response.status(503);
    }

    return health;
  }
}
