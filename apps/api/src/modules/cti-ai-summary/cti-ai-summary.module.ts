import { Module } from '@nestjs/common';
import { CtiAiSummaryController } from './cti-ai-summary.controller';
import { CtiAiSummaryService } from './cti-ai-summary.service';

@Module({
  controllers: [CtiAiSummaryController],
  providers: [CtiAiSummaryService],
  exports: [CtiAiSummaryService],
})
export class CtiAiSummaryModule {}
