import { Module } from '@nestjs/common';
import {
  ConfigModule,
  ConfigService,
} from '@nestjs/config';
import {
  JwtModule,
  type JwtSignOptions,
} from '@nestjs/jwt';
import { APP_GUARD } from '@nestjs/core';

import { UsersModule } from '../users/users.module';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import {
  JwtAuthGuard,
} from './guards/jwt-auth.guard';
import {
  RolesGuard,
} from './guards/roles.guard';

@Module({
  imports: [
    ConfigModule,
    UsersModule,
    JwtModule.registerAsync({
      imports: [
        ConfigModule,
      ],
      inject: [
        ConfigService,
      ],
      useFactory: (
        configService: ConfigService,
      ) => ({
        secret:
          configService.getOrThrow<string>(
            'auth.jwtSecret',
          ),
        signOptions: {
          expiresIn:
            configService.getOrThrow<string>(
              'auth.jwtExpiresIn',
            ) as JwtSignOptions['expiresIn'],
        },
      }),
    }),
  ],
  controllers: [
    AuthController,
  ],
  providers: [
    AuthService,
    {
      provide: APP_GUARD,
      useClass: JwtAuthGuard,
    },
    {
      provide: APP_GUARD,
      useClass: RolesGuard,
    },
  ],
})
export class AuthModule {}