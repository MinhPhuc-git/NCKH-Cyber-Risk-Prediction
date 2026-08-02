import { Module } from '@nestjs/common';

import { DatabaseModule } from '../../database/database.module';
import { WazuhModule } from '../wazuh/wazuh.module';
import { AnalysisRunsController } from './analysis-runs.controller';
import { AnalysisRunsService } from './analysis-runs.service';

@Module({
  imports: [
    DatabaseModule,
    WazuhModule,
  ],
  controllers: [
    AnalysisRunsController,
  ],
  providers: [
    AnalysisRunsService,
  ],
})
export class AnalysisRunsModule {}
