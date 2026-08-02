import { Module } from '@nestjs/common';

import { DatabaseModule } from '../../database/database.module';
import { SecuritySnapshotsModule } from '../security-snapshots/security-snapshots.module';
import { WazuhBindingsModule } from '../wazuh-bindings/wazuh-bindings.module';
import { WazuhModule } from '../wazuh/wazuh.module';
import { AdminSecurityDataController } from './admin-security-data.controller';
import { AiPipelineCheckController } from './ai-pipeline-check.controller';
import { AiModelRuntimeService } from './ai-model-runtime.service';
import { AiPipelineCheckService } from './ai-pipeline-check.service';
import { AiPipelineDataUserImportService } from './ai-pipeline-data-user-import.service';
import { DeviceSyncLockService } from './device-sync-lock.service';
import { CveLifecycleDeltaService } from './cve-lifecycle-delta.service';
import { CtiCvssEnrichmentService } from './cti-cvss-enrichment.service';
import { SecurityDataController } from './security-data.controller';
import { SecurityDataSyncService } from './security-data-sync.service';
import { SecurityDataService } from './security-data.service';

@Module({
  imports: [
    DatabaseModule,
    WazuhModule,
    WazuhBindingsModule,
    SecuritySnapshotsModule,
  ],
  controllers: [SecurityDataController, AdminSecurityDataController, AiPipelineCheckController],
  providers: [
    SecurityDataService,
    SecurityDataSyncService,
    DeviceSyncLockService,
    AiModelRuntimeService,
    AiPipelineDataUserImportService,
    AiPipelineCheckService,
    CveLifecycleDeltaService,
    CtiCvssEnrichmentService,
  ],
  exports: [
    SecurityDataService,
    SecurityDataSyncService,
    DeviceSyncLockService,
    AiModelRuntimeService,
    AiPipelineDataUserImportService,
    AiPipelineCheckService,
    CveLifecycleDeltaService,
    CtiCvssEnrichmentService,
  ],
})
export class SecurityDataModule {}
