import { Module } from '@nestjs/common';

import { DatabaseModule } from '../../database/database.module';
import { RegistrationController } from './registration.controller';
import { RegistrationService } from './registration.service';

@Module({
  imports: [
    DatabaseModule,
  ],
  controllers: [
    RegistrationController,
  ],
  providers: [
    RegistrationService,
  ],
})
export class RegistrationModule {}
