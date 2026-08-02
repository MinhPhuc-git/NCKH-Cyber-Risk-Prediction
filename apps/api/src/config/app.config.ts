export const appConfig = () => ({
  app: {
    name: 'cyrp-api',
    version: '0.1.0',
    env: process.env.NODE_ENV ?? 'development',
    host: process.env.API_HOST ?? '0.0.0.0',
    port: Number(process.env.API_PORT ?? 3001),
    corsOrigins:
      process.env.CORS_ORIGINS
        ?.split(',')
        .map((origin) => origin.trim())
        .filter(Boolean) ?? [
        'http://localhost:3000',
        'http://localhost:3002',
      ],
  },
});
