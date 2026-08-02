import { NestFactory } from '@nestjs/core';
import { ConfigService } from '@nestjs/config';
import { AppModule } from './app.module';
import { setupApp } from './bootstrap/application.setup';

async function bootstrap(): Promise<void> {
  const app = await NestFactory.create(AppModule);

  await setupApp(app);

  const configService = app.get(ConfigService);

  const port =
    configService.get<number>('app.port') ?? 3001;

  const host =
    configService.get<string>('app.host') ?? '0.0.0.0';

  await app.listen(port, host);
   const url = await app.getUrl();
  console.log(`CYRP API listening at ${url}`);
}

void bootstrap();
