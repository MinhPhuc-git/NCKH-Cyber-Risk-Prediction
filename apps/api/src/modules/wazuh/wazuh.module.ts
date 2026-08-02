import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';

import { WazuhController } from './wazuh.controller';
import { WazuhService } from './wazuh.service';

@Module({
  imports: [
    ConfigModule,
  ],
  controllers: [
    WazuhController,
  ],
  providers: [
    WazuhService,
  ],
  exports: [
    WazuhService,
  ],
})
export class WazuhModule {}
