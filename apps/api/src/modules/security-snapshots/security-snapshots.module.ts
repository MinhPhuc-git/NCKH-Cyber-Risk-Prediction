import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';

import { DatabaseModule } from '../../database/database.module';
import { WazuhModule } from '../wazuh/wazuh.module';
import { SecuritySnapshotsController } from './security-snapshots.controller';
import { SecuritySnapshotsService } from './security-snapshots.service';

@Module({
  imports: [
    ConfigModule,
    DatabaseModule,
    WazuhModule,
  ],
  controllers: [
    SecuritySnapshotsController,
  ],
  providers: [
    SecuritySnapshotsService,
  ],
  exports: [
    SecuritySnapshotsService,
  ],
})
export class SecuritySnapshotsModule {}
