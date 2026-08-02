import { Module } from '@nestjs/common';

import { DatabaseModule } from '../../database/database.module';
import { WazuhModule } from '../wazuh/wazuh.module';
import { AgentRuntimeService } from './agent-runtime.service';
import { WazuhBindingsController } from './wazuh-bindings.controller';
import { WazuhBindingsService } from './wazuh-bindings.service';

@Module({
  imports: [
    DatabaseModule,
    WazuhModule,
  ],
  controllers: [
    WazuhBindingsController,
  ],
  providers: [
    WazuhBindingsService,
    AgentRuntimeService,
  ],
  exports: [
    WazuhBindingsService,
    AgentRuntimeService,
  ],
})
export class WazuhBindingsModule {}
