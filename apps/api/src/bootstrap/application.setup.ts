import {
  INestApplication,
  ValidationPipe,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
  DocumentBuilder,
  SwaggerModule,
} from '@nestjs/swagger';
import helmet from 'helmet';

export function setupApp(app: INestApplication): void {
  const configService = app.get(ConfigService);

  const appConfig = configService.get('app');
  const swaggerConfig = configService.get('swagger');

  app.use(helmet());

  app.enableCors({
    origin: appConfig?.corsOrigins ?? [],
    credentials: true,
  });

  app.setGlobalPrefix('api/v1');

  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      transform: true,
      forbidNonWhitelisted: true,
    }),
  );

  app.enableShutdownHooks();

  if (swaggerConfig?.enabled !== false) {
    const swaggerDocument = SwaggerModule.createDocument(
      app,
      new DocumentBuilder()
        .setTitle(swaggerConfig?.title ?? 'CYRP API')
        .setDescription(
          swaggerConfig?.description ?? 'CYRP Platform API',
        )
        .setVersion(swaggerConfig?.version ?? '0.1.0')
        .addBearerAuth(
          {
            type: 'http',
            scheme: 'bearer',
            bearerFormat: 'JWT',
            description: 'Nhập JWT access token',
          },
          'access-token',
        )
        .build(),
    );

    SwaggerModule.setup(
      swaggerConfig?.path ?? 'api/docs',
      app,
      swaggerDocument,
    );
  }
}
