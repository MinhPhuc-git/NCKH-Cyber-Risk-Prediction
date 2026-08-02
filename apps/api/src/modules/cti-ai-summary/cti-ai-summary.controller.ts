import { Controller, Get, Query } from '@nestjs/common';
import { CtiAiSummaryService } from './cti-ai-summary.service';

@Controller('cti-ai-summary')
export class CtiAiSummaryController {
  constructor(private readonly service: CtiAiSummaryService) {}

  @Get('latest')
  latest(@Query('device') device?: string, @Query('limit') limitRaw?: string) {
    const limit = Number(limitRaw);
    return this.service.getLatest({
      device,
      limit: Number.isFinite(limit) ? limit : undefined,
    });
  }
}
