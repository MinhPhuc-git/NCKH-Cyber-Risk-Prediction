import { CtiAiSummaryModule } from './modules/cti-ai-summary/cti-ai-summary.module';
import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { resolve } from 'node:path';

import authConfig from './config/auth.config';
import { appConfig } from './config/app.config';
import { databaseConfig } from './config/database.config';
import { swaggerConfig } from './config/swagger.config';
import { validationSchema } from './config/validation.schema';
import { DatabaseModule } from './database/database.module';
import { AgentsModule } from './modules/agents/agents.module';
import { AnalysisRunsModule } from './modules/analysis-runs/analysis-runs.module';
import { AuthModule } from './modules/auth/auth.module';
import { DevicesModule } from './modules/devices/devices.module';
import { HealthModule } from './modules/health/health.module';
import { RegistrationModule } from './modules/registration/registration.module';
import { SecurityDataModule } from './modules/security-data/security-data.module';
import { SecuritySnapshotsModule } from './modules/security-snapshots/security-snapshots.module';
import { WazuhBindingsModule } from './modules/wazuh-bindings/wazuh-bindings.module';
import { WazuhModule } from './modules/wazuh/wazuh.module';

@Module({
  imports: [
    CtiAiSummaryModule,
    ConfigModule.forRoot({
      isGlobal: true,
      envFilePath: [
        resolve(__dirname, '../../../.env'),
        resolve(__dirname, '../.env'),
      ],
      load: [appConfig, databaseConfig, authConfig, swaggerConfig],
      validationSchema,
      expandVariables: true,
    }),
    DatabaseModule,
    HealthModule,
    AuthModule,
    RegistrationModule,
    DevicesModule,
    AgentsModule,
    WazuhModule,
    WazuhBindingsModule,
    AnalysisRunsModule,
    SecuritySnapshotsModule,
    SecurityDataModule,
  ],
})
export class AppModule {}
